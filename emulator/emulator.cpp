#include <windows.h>
#include "logging.h"
#include "hwk_buffers.h"

typedef unsigned int FT_STATUS;
typedef void* FT_HANDLE;

enum ReadRequestType
{
	ReadLongBoxAuthData,
	ReadShortBoxAuthData1,
	ReadShortBoxAuthData2,
	EmulateAfterReadCall,
	SoftwareLicenceRead,
	HwkChecksSetupStart,
	HwkChecksSetupEnd,
	ReadBoxDataWithBitsEmulation,
	EmulateShortHwkResponseBits,
	ReadFirstByte,
	ReadNextByte,
	FullHwkResponseEmulation,
	Unknown
};

enum ResetGetQueueStatusType
{
	None,
	Init,
	End,
};

static const bool g_EnableHwkEmulation = true;

static bool g_GetQueueStatuHookEnabled = false;
static int g_GetQueueStatuReturnDelay = 0;
static ResetGetQueueStatusType g_ResetGetQueueStatus = None;

static bool g_IsHwkCheckInProcess = false;
static bool g_IsHwkCheckSetupCompleted = false;
static bool g_EmulateBoxDataHwkBits = false;
static bool g_ShouldSetModemDCDBit = true;

static ReadRequestType g_ReadRequestType = Unknown;
static ReadRequestType g_PrevReadRequestType = Unknown;

static BYTE g_ResponseBuffer[512];
static unsigned int g_ResponseBufferLength = 0;

unsigned long byteswap_ulong(unsigned long x)
{
    return ((x & 0x000000FF) << 24) |
        ((x & 0x0000FF00) << 8) |
        ((x & 0x00FF0000) >> 8) |
        ((x & 0xFF000000) >> 24);
}

unsigned int CalculateChecksumUsingXorTable(int processBytesLength, const BYTE* xorTable)
{
    unsigned int result = -1;
    do
    {
        BYTE currByte = *xorTable++;
        unsigned int xorResult = (unsigned __int8)(result ^ ~currByte);
        int cycleCount = 8;
        do
        {
            if ((xorResult & 1) != 0)
                xorResult = (xorResult >> 1) ^ 0xEDB88320;
            else
                xorResult >>= 1;
        } while (--cycleCount);
        result = xorResult ^ (result >> 8);
    } while (processBytesLength-- != 1);
    return byteswap_ulong(result);
}

WORD CalculateChecksumUsingLookupTable(int iterationsCount, BYTE* storageBuffer)
{
  WORD result = 0;
  int lookupTableIndex = 0;

  do
  {
	lookupTableIndex = (result ^ *storageBuffer++) & 0xFF;
	result = HWK_LOOKUP_TABLE[lookupTableIndex] ^ ((result >> 8) & 0xFF);
  }
  while (--iterationsCount);
  return result;
}

void AppendHwkResponseEnd()
{
	g_ResponseBuffer[g_ResponseBufferLength] = 0xA5;
	g_ResponseBuffer[g_ResponseBufferLength + 1] = 0x54;
	g_ResponseBufferLength += 2;
}

typedef FT_STATUS (__stdcall *FT_GetModemStatus_t)(FT_HANDLE, unsigned int*);
FT_GetModemStatus_t FT_GetModemStatusOrigFunc = NULL;

FT_STATUS __stdcall FT_GetModemStatus_Hook(
	FT_HANDLE ftHandle,
	unsigned int* lpdwModemStatus)
{
	FT_STATUS ret = FT_GetModemStatusOrigFunc(ftHandle, lpdwModemStatus);

	if (lpdwModemStatus)
	{
		if (g_ShouldSetModemDCDBit)
			*lpdwModemStatus |= 0x80;
		else
			*lpdwModemStatus &= ~0x80;
	}

	LogToFile("FT_GetModemStatus: 0x%X", *lpdwModemStatus);

	return ret;
}

typedef FT_STATUS (__stdcall *FT_ListDevices_t)(void*, void*, DWORD);
FT_ListDevices_t FT_ListDevicesOrigFunc = NULL;

FT_STATUS __stdcall FT_ListDevices_Hook(
	void* pvArg1,
	void* pvArg2,
	DWORD dwFlags)
{
	FT_STATUS result = FT_ListDevicesOrigFunc(pvArg1, pvArg2, dwFlags);
	
	if (dwFlags == 0x40000001) // FT_LIST_BY_INDEX | FT_OPEN_BY_SERIAL_NUMBER
	{
		LogToFile("FT_ListDevices: Emulating SN %s", EMULATED_BOX_SN);
		strcpy((char*)pvArg2, EMULATED_BOX_SN);
	}

	return result;
}

typedef FT_STATUS (__stdcall *FT_GetDeviceInfo_t)(FT_HANDLE, unsigned long*, unsigned long*, char*, char*, void*);
FT_GetDeviceInfo_t FT_GetDeviceInfoOrigFunc = NULL;

FT_STATUS __stdcall FT_GetDeviceInfo_Hook(
	FT_HANDLE ftHandle,
	unsigned long* pftType,
	unsigned long* lpdwID,
	char* pcSerialNumber,
	char* pcDescription,
	void* pvDummy)
{
	FT_STATUS result = FT_GetDeviceInfoOrigFunc(ftHandle, pftType, lpdwID, pcSerialNumber, pcDescription, pvDummy);

	if (pcSerialNumber)
	{
		LogToFile("FT_GetDeviceInfo: Original SN: %s , Emulating: %s", pcSerialNumber, EMULATED_BOX_SN);
		strcpy(ORIGINAL_SN, pcSerialNumber);
		strcpy(pcSerialNumber, EMULATED_BOX_SN);
	}

	return result;
}

typedef FT_STATUS (__stdcall *FT_OpenEx_t)(void*, DWORD, FT_HANDLE*);
FT_OpenEx_t FT_OpenExOrigFunc = NULL;

FT_STATUS __stdcall FT_OpenEx_Hook(
	void* pvArg1,
	DWORD dwFlags,
	FT_HANDLE* ftHandle)
{
	if (dwFlags == 1) // FT_OPEN_BY_SERIAL_NUMBER
	{
		LogToFile("FT_OpenEx: Emulating SN: %s , Connecting to: %s", (char*)pvArg1, ORIGINAL_SN);
		strcpy((char*)pvArg1, ORIGINAL_SN);
	}

	FT_STATUS result = FT_OpenExOrigFunc(pvArg1, dwFlags, ftHandle);
	return result;
}

typedef FT_STATUS (__stdcall *FT_GetQueueStatus_t)(FT_HANDLE, unsigned int*);
FT_GetQueueStatus_t FT_GetQueueStatusOrigFunc = NULL;

FT_STATUS __stdcall FT_GetQueueStatus_Hook(
	FT_HANDLE ftHandle,
	unsigned int* lpdwAmountInRxQueue)
{
	FT_STATUS ret = FT_GetQueueStatusOrigFunc(ftHandle, lpdwAmountInRxQueue);
	
	if (g_EnableHwkEmulation && g_GetQueueStatuHookEnabled)
	{
		*lpdwAmountInRxQueue = g_ResponseBufferLength;	
		if (g_GetQueueStatuReturnDelay > 0)
		{
			g_GetQueueStatuReturnDelay--;
			*lpdwAmountInRxQueue = 0;
		}
		else if (g_ResetGetQueueStatus == Init)
		{
			g_ResetGetQueueStatus = End;
		}
		else if (g_ResetGetQueueStatus == End)
		{
			g_GetQueueStatuHookEnabled = false;
			g_ResetGetQueueStatus = None;
		}
	}

	if (lpdwAmountInRxQueue)
		LogToFile("FT_GetQueueStatus: %d", *lpdwAmountInRxQueue);

	return ret;
}

typedef FT_STATUS (__stdcall *FT_Purge_t)(FT_HANDLE, unsigned long);
FT_Purge_t FT_PurgeOrigFunc = NULL;

FT_STATUS __stdcall FT_Purge_Hook(
	FT_HANDLE ftHandle,
	unsigned long uMask)
{
	FT_STATUS ret = FT_PurgeOrigFunc(ftHandle, uMask);
	LogToFile("FT_Purge: 0x%X", (unsigned int)uMask);
	return ret;
}

typedef FT_STATUS (__stdcall *FT_Read_t)(FT_HANDLE, void*, DWORD, unsigned int*);
FT_Read_t FT_ReadOrigFunc = NULL;

FT_STATUS __stdcall FT_Read_Hook(
	FT_HANDLE ftHandle,
	void* lpBuffer,
	DWORD dwBytesToRead,
	unsigned int* lpdwBytesReturned)
{
	if (!g_EnableHwkEmulation)
	{
		return FT_ReadOrigFunc(ftHandle, lpBuffer, dwBytesToRead, lpdwBytesReturned);
	}
	
	BYTE* buffer = (BYTE*)lpBuffer;
	
	if (g_ReadRequestType != Unknown)
	{
		g_PrevReadRequestType = g_ReadRequestType;
	}

	if (g_ReadRequestType == ReadNextByte)
	{
		g_EmulateBoxDataHwkBits = true;
		buffer[0] = g_ResponseBuffer[0];

		if (dwBytesToRead) dwBytesToRead = 1;
		*lpdwBytesReturned = dwBytesToRead;
		memcpy(g_ResponseBuffer, g_ResponseBuffer + 1, 0x1FF);
		g_ResponseBufferLength--;

FT_READ_EMU_READ_EXIT:
		LogBufferToFile("[EMU] FT_Read", lpBuffer, *lpdwBytesReturned);
		g_ReadRequestType = Unknown;
		g_GetQueueStatuHookEnabled = false;
		g_ResponseBufferLength = 0;
		return 0;
	}
	else if (g_ReadRequestType == ReadFirstByte)
	{
		g_EmulateBoxDataHwkBits = true;
		buffer[0] = g_ResponseBuffer[0];
		if (dwBytesToRead) dwBytesToRead = 1;
		*lpdwBytesReturned = dwBytesToRead;
		g_ResponseBufferLength--;
		goto FT_READ_EMU_READ_EXIT;
	}
	else if (g_ReadRequestType == FullHwkResponseEmulation)
	{
		g_EmulateBoxDataHwkBits = true;
		*lpdwBytesReturned = dwBytesToRead;
		memcpy(lpBuffer, g_ResponseBuffer, dwBytesToRead);
		goto FT_READ_EMU_READ_EXIT;
	}

	FT_STATUS ret = FT_ReadOrigFunc(ftHandle, lpBuffer, dwBytesToRead, lpdwBytesReturned);

	if (g_ReadRequestType == EmulateAfterReadCall)
	{
		*lpdwBytesReturned = g_ResponseBufferLength;
		memcpy(lpBuffer, g_ResponseBuffer, g_ResponseBufferLength);
		goto FT_READ_EMU_READ_EXIT;
	}
	else if (g_ReadRequestType == HwkChecksSetupStart)
	{
		*lpdwBytesReturned = dwBytesToRead;
		if (dwBytesToRead == 1 && buffer[0] == 0x54)
		{
			g_IsHwkCheckInProcess = true;
			g_IsHwkCheckSetupCompleted = false;
		}
		else
		{
			g_ShouldSetModemDCDBit = true;
			g_IsHwkCheckInProcess = false;
		}
		
		g_EmulateBoxDataHwkBits = false;
	}
	else if (g_ReadRequestType == HwkChecksSetupEnd)
	{
		*lpdwBytesReturned = dwBytesToRead;
		if (dwBytesToRead == 1 || buffer[0] == 0x54)
		{
			g_ShouldSetModemDCDBit = false;
			g_IsHwkCheckSetupCompleted = true;
		}
		else
		{
			g_ShouldSetModemDCDBit = true;
			g_IsHwkCheckSetupCompleted = false;
			g_IsHwkCheckInProcess = false;
		}
		
		g_EmulateBoxDataHwkBits = false;
	}
	else if (g_ReadRequestType == ReadBoxDataWithBitsEmulation)
	{
		*lpdwBytesReturned = dwBytesToRead;
		g_ShouldSetModemDCDBit = true;
		if (*lpdwBytesReturned == 65)
		{
			if (g_EmulateBoxDataHwkBits)
				buffer[0x38] |= 0x20;
			else
				buffer[0x38] &= ~0x20;

			BYTE checksum = 0;
			for (int i = 0; i < 64; i++)
			{
				checksum -= buffer[i];
			}
			
			buffer[64] = checksum;
		}
	}
	else if (g_ReadRequestType == EmulateShortHwkResponseBits)
	{
		buffer[3] |= 0x20;
		buffer[6] = 0xF3;
	}
	else if (g_ReadRequestType == ReadLongBoxAuthData)
	{
		g_EmulateBoxDataHwkBits = true;
	}
	else if (g_PrevReadRequestType == ReadLongBoxAuthData && dwBytesToRead == 193)
	{
		g_EmulateBoxDataHwkBits = true;
		memcpy(lpBuffer, BOX_AUTH_DATA, sizeof(BOX_AUTH_DATA));
		*lpdwBytesReturned = 193;
		goto FT_READ_EMU_READ_EXIT;
	}
	else if (g_PrevReadRequestType == ReadShortBoxAuthData1 && dwBytesToRead == 4)
	{
		buffer[0] = 0x2E;
		buffer[1] = 0xCC;
		buffer[2] = 0xC8;
		buffer[3] = 0x3E;
		*lpdwBytesReturned = 4;
		goto FT_READ_EMU_READ_EXIT;
	}
	else if (g_ReadRequestType == ReadShortBoxAuthData2 && dwBytesToRead == 3)
	{
		buffer[0] = 0xCC;
		buffer[1] = 0x2E;
		buffer[2] = 0xC8;
		*lpdwBytesReturned = 3;
		goto FT_READ_EMU_READ_EXIT;
	}

	g_ReadRequestType = Unknown;
	g_GetQueueStatuHookEnabled = false;

	if (lpdwBytesReturned)
		LogBufferToFile("FT_Read", lpBuffer, *lpdwBytesReturned);

	return ret;
}

typedef FT_STATUS (__stdcall *FT_Write_t)(FT_HANDLE, void*, DWORD, unsigned int*);
FT_Write_t FT_WriteOrigFunc = NULL;

FT_STATUS __stdcall FT_Write_Hook(
	FT_HANDLE ftHandle,
	void* lpBuffer,
	DWORD dwBytesToWrite,
	unsigned int* lpdwBytesWritten)
{
	if (!g_EnableHwkEmulation)
	{
		return FT_WriteOrigFunc(ftHandle, lpBuffer, dwBytesToWrite, lpdwBytesWritten);
	}
	
	g_GetQueueStatuReturnDelay = 0;

	BYTE* buffer = (BYTE*)lpBuffer;

	// box auth emulation start
	if (dwBytesToWrite == 1 && buffer[0] == 0x39)
	{
		g_ReadRequestType = ReadLongBoxAuthData;
		goto CALL_FT_WRITE;
	}
	else if (dwBytesToWrite == 1 && buffer[0] == 0x38)
	{
		g_ReadRequestType = ReadShortBoxAuthData1;
		goto CALL_FT_WRITE;
	}
	else if (dwBytesToWrite == 1 && buffer[0] == 0x53)
	{
		g_ReadRequestType = ReadShortBoxAuthData2;
		goto CALL_FT_WRITE;
	}
	else if (dwBytesToWrite == 3 && buffer[0] == 0x3B && buffer[1] == 0x01 && buffer[2] == 0x80)
	{
		g_ReadRequestType = EmulateAfterReadCall;
		g_ResponseBuffer[0] = 0x06;
		g_ResponseBuffer[1] = 0x9B;
		g_ResponseBuffer[2] = 0xE5;
		g_ResponseBuffer[3] = 0xAB; 
		*lpdwBytesWritten = 3;
		g_ResponseBufferLength = 4;
		goto CALL_FT_WRITE;
	}
	else if (buffer[0] == 0x3C && buffer[1] == 0x3A && buffer[2] == 0xC9)
	{
		g_ReadRequestType = EmulateAfterReadCall;
		g_ResponseBuffer[0] = 0x0C;
		g_ResponseBuffer[1] = 0xA7;
		g_ResponseBuffer[2] = 0x3C;
		g_ResponseBuffer[3] = 0xAD; 
		*lpdwBytesWritten = dwBytesToWrite;
		g_ResponseBufferLength = 4;
		goto CALL_FT_WRITE;
	}
	else if (buffer[0] == 0x44 && buffer[3] == 0x17)
	{
		g_ReadRequestType = EmulateAfterReadCall;
		g_ResponseBuffer[0] = 0xF0;
		g_ResponseBuffer[1] = 0x75;
		g_ResponseBuffer[2] = 0xA4;
		g_ResponseBuffer[3] = 0x61; 
		g_ResponseBuffer[4] = 0x96; 
		*lpdwBytesWritten = dwBytesToWrite;
		g_ResponseBufferLength = 5;
		goto CALL_FT_WRITE;
	}
	else if (buffer[0] == 0x44 && buffer[1] == 0x18 && buffer[3] == 0x08)
	{
		g_ReadRequestType = EmulateAfterReadCall;
		g_ResponseBuffer[0] = 0xF6;
		g_ResponseBuffer[1] = 0xE1;
		g_ResponseBuffer[2] = 0x89;
		g_ResponseBuffer[3] = 0x55;
		g_ResponseBuffer[4] = 0x4B; 
		*lpdwBytesWritten = dwBytesToWrite;
		g_ResponseBufferLength = 5;
		goto CALL_FT_WRITE;
	}
	else if (buffer[0] == 0x44 && buffer[3] == 0x08)
	{
		g_ReadRequestType = EmulateAfterReadCall;
		g_ResponseBuffer[0] = 0x7A;
		g_ResponseBuffer[1] = 0xD0;
		g_ResponseBuffer[2] = 0x2B;
		g_ResponseBuffer[3] = 0xAF;
		g_ResponseBuffer[4] = 0xDC; 
		*lpdwBytesWritten = dwBytesToWrite;
		g_ResponseBufferLength = 5;
		goto CALL_FT_WRITE;
	}
	else if (buffer[0] == 0x55 && buffer[1] == 0x14)
	{
		g_ReadRequestType = EmulateAfterReadCall;
		g_ResponseBuffer[0] = 0x58;
		g_ResponseBuffer[1] = 0x70;
		g_ResponseBuffer[2] = 0x38;
		*lpdwBytesWritten = dwBytesToWrite;
		g_ResponseBufferLength = 3;
		goto CALL_FT_WRITE;
	}
	else if (buffer[0] == 0x55 && buffer[1] == 0x15)
	{
		g_ReadRequestType = EmulateAfterReadCall;
		g_ResponseBuffer[0] = 0x00;
		g_ResponseBuffer[1] = 0xA2;
		g_ResponseBuffer[2] = 0x5E;
		*lpdwBytesWritten = dwBytesToWrite;
		g_ResponseBufferLength = 3;
		goto CALL_FT_WRITE;
	}
	else if (buffer[0] == 0x55 && buffer[1] == 0x05)
	{
		g_ReadRequestType = EmulateAfterReadCall;
		g_ResponseBuffer[0] = 0x01;
		g_ResponseBuffer[1] = 0xAB;
		g_ResponseBuffer[2] = 0x54;
		*lpdwBytesWritten = dwBytesToWrite;
		g_ResponseBufferLength = 3;
		goto CALL_FT_WRITE;
	}
	// box auth emulation end
	else if (dwBytesToWrite == 1 && buffer[0] == 0x54) // box SN
	{
		g_ReadRequestType = EmulateAfterReadCall;
		g_ResponseBuffer[0] = 0x33;
		g_ResponseBuffer[1] = 0xC5;
		g_ResponseBuffer[2] = 0x08;
		g_ResponseBufferLength = 3;
		goto CALL_FT_WRITE;
	}
	else if (dwBytesToWrite == 7 && buffer[0] == 0x4C) // software licence
	{
		g_ReadRequestType = SoftwareLicenceRead;
		if (g_PrevReadRequestType != SoftwareLicenceRead)
		{
			buffer[1] = 0x4D;
			buffer[2] = 0x54;
			buffer[3] = 0x31;
			buffer[4] = 0x39;
			buffer[5] = 0x06;
			buffer[6] = 0xEF;
		}
		else
		{
			buffer[1] = 0x1D;
			buffer[2] = 0x1D;
			buffer[3] = 0x1F;
			buffer[4] = 0x02;
			buffer[5] = 0x0D;
			buffer[6] = 0x98;
		}

		goto CALL_FT_WRITE;
	}

	if (dwBytesToWrite == 1 && buffer[0] == 0x45)
	{
		g_ReadRequestType = ReadBoxDataWithBitsEmulation;
		goto CALL_FT_WRITE;
	}
	
	if (!g_IsHwkCheckInProcess)
	{
		if (dwBytesToWrite == 1 && (buffer[0] == 0x36 || buffer[0] == 0x61))
		{
			g_ReadRequestType = HwkChecksSetupStart;
			goto CALL_FT_WRITE;
		}
		else if (dwBytesToWrite == 2 && buffer[0] == 0x3A && buffer[1] == 0x32)
		{
			*(DWORD*)(g_ResponseBuffer) = 0x6A;
			*(DWORD*)(g_ResponseBuffer + 4) = 0xF3000000;
			*(DWORD*)(g_ResponseBuffer + 8) = 0x100;
			FT_WriteOrigFunc(ftHandle, g_ResponseBuffer, 0xC, lpdwBytesWritten);
			FT_Read_Hook(ftHandle, g_ResponseBuffer, 4, lpdwBytesWritten);
			FT_Purge_Hook(ftHandle, 3);

			*(DWORD*)(g_ResponseBuffer) = 0x393061;
			FT_WriteOrigFunc(ftHandle, g_ResponseBuffer, 3, lpdwBytesWritten);
			FT_Read_Hook(ftHandle, g_ResponseBuffer, 3, lpdwBytesWritten);
			FT_Purge_Hook(ftHandle, 3);
			
			g_ResponseBuffer[0] = 0xA1;
			g_ResponseBuffer[1] = 0x04;
			g_ResponseBuffer[2] = 0xA5;
			
			g_ReadRequestType = FullHwkResponseEmulation;

			g_ResponseBufferLength = 3;
			*lpdwBytesWritten = 2;
			g_GetQueueStatuReturnDelay = 3;

FT_WRITE_EMU_EXIT:
			g_GetQueueStatuHookEnabled = true;
			LogBufferToFile("[EMU] FT_Write", lpBuffer, *lpdwBytesWritten);
			return 0;
		}
		else if (dwBytesToWrite == 3 && buffer[0] == 0x3A && buffer[1] == 0x36)
		{
			g_ReadRequestType = FullHwkResponseEmulation;
			
			DWORD invertTableIndex = buffer[2];
			for (int i = 0; i < 128; i++)
			{
				g_ResponseBuffer[i] = ~INVERT_HWK_TABLE[invertTableIndex++];
			}

			g_ResponseBuffer[128] = 0xA5;
			g_ResponseBufferLength = 129;
			*lpdwBytesWritten = 3;
			g_GetQueueStatuReturnDelay = 5;
			goto FT_WRITE_EMU_EXIT;
		}
		else if (dwBytesToWrite == 2 && buffer[0] == 0x3A && buffer[1] == 0x34)
		{
			g_ReadRequestType = FullHwkResponseEmulation;
			memcpy(g_ResponseBuffer, HWK_CHECKS_BUFFER, 8);
			g_ResponseBuffer[8] = 0xA5;
			g_ResponseBufferLength = 9;
			*lpdwBytesWritten = 2;
			g_GetQueueStatuReturnDelay = 3;
			goto FT_WRITE_EMU_EXIT;
		}
		else
		{
			if (dwBytesToWrite == 2 && buffer[0] == 0x3A && buffer[1] == 0x30)
			{
				g_ReadRequestType = EmulateShortHwkResponseBits;
				goto CALL_FT_WRITE;
			}
			else if (dwBytesToWrite == 2 && buffer[0] == 0x3A && buffer[1] == 0x35)
			{
				goto CALL_FT_WRITE;
			}
			else if (dwBytesToWrite == 2 && buffer[0] == 0x3A && buffer[1] == 0x31)
			{
				g_ReadRequestType = FullHwkResponseEmulation;
				g_ResponseBuffer[0] = 0xF0;
				g_ResponseBufferLength = 1;
				*lpdwBytesWritten = 2;
				g_GetQueueStatuReturnDelay = 2;
				goto FT_WRITE_EMU_EXIT;
			}
			else
			{
				if (dwBytesToWrite == 2 && buffer[0] == 0x3A && buffer[1] == 0x40)
				{
					goto CALL_FT_WRITE;
				}
				if (dwBytesToWrite == 2 && buffer[0] == 0x3A && buffer[1] == 0x38)
				{
					g_ReadRequestType = EmulateAfterReadCall;
					g_ResponseBuffer[0] = 0xD8;
					g_ResponseBufferLength = 1;
					*lpdwBytesWritten = 2;
					g_GetQueueStatuReturnDelay = 2;
					goto CALL_FT_WRITE;
				}
				else if (dwBytesToWrite != 5 || (buffer[0] != 0x3A && buffer[1] != 0x33))
				{
					goto CALL_FT_WRITE;
				}
				
				buffer[1] = 0x62;
				lpBuffer = &buffer[1];
				LogBufferToFile("[MOD] FT_Write", lpBuffer, 4);
				FT_STATUS writeStatus = FT_WriteOrigFunc(ftHandle, lpBuffer, 4, lpdwBytesWritten);
				*lpdwBytesWritten = dwBytesToWrite;
				g_GetQueueStatuHookEnabled = false;
				g_ReadRequestType = Unknown;
				return writeStatus;
			}
		}
	}
	
	if (!g_IsHwkCheckSetupCompleted)
	{
		if (buffer[0] != 0x30)
		{
			if (buffer[0] == 0x31)
			{
				g_ResponseBuffer[0] = 0xA5;
			}
			else if (
				buffer[0] != 0x32 &&
				buffer[0] != 0x33 &&
				buffer[0] != 0x34 &&
				buffer[0] != 0x35 &&
				buffer[0] != 0x36
			)
			{
				g_ShouldSetModemDCDBit = true;
				g_IsHwkCheckInProcess = false;
				g_IsHwkCheckSetupCompleted = false;
			}
			
			goto CALL_FT_WRITE;
		}
		
		goto CASE_HWK_SETUP_END;
	}

	if (buffer[0] == 0x30)
	{
CASE_HWK_SETUP_END:
		g_ResponseBuffer[0] = 0xA5;
		g_ReadRequestType = HwkChecksSetupEnd;

		memset(HWK_CHECKS_BUFFER, 0, 0x200);
		memcpy(HWK_CHECKS_BUFFER, HWK_HID, 8);
		
		HWK_CHECKS_BUFFER[0] ^= HWK_CHECKS_BUFFER[7];
		HWK_CHECKS_BUFFER[162] = HWK_CHECKS_BUFFER[0];
		HWK_CHECKS_BUFFER[5] ^= 0x27;
		
		memcpy(HWK_CHECKS_BUFFER + 0xF1, HWK_ADDITIONAL_DATA, sizeof(HWK_ADDITIONAL_DATA));
		
		goto CALL_FT_WRITE;
	}
	else if (buffer[0] == 0x31)
	{
		g_ResponseBuffer[0] = 0xA5;
		goto CALL_FT_WRITE;
	}
	else if (buffer[0] == 0x32)
	{
		g_GetQueueStatuReturnDelay = 1;
		g_ResponseBufferLength = 1;
		g_ReadRequestType = ReadNextByte;
		*lpdwBytesWritten = dwBytesToWrite;

		goto FT_WRITE_EMU_EXIT;
	}
	// TODO
	/*else if (buffer[0] == 0x33) // seems unused, or maybe used in very old versions
	{

	}*/
	else if (buffer[0] == 0x34)		// seems unused, or maybe used in very old versions
	{
		g_GetQueueStatuReturnDelay = 2;
		g_ReadRequestType = FullHwkResponseEmulation;
		*lpdwBytesWritten = dwBytesToWrite;

		int hwkDataOffset = buffer[2];
		int hwkDataLength = buffer[3];
		if ( !hwkDataLength ) hwkDataLength = 256;

		memcpy(g_ResponseBuffer, HWK_CHECKS_BUFFER + hwkDataOffset, hwkDataLength);

		g_ResponseBuffer[hwkDataLength] = 0xA5;
		g_ResponseBufferLength = hwkDataLength + 1;

		goto FT_WRITE_EMU_EXIT;
	}
	else if (buffer[0] == 0x35)		// seems unused, or maybe used in very old versions
	{
		g_GetQueueStatuReturnDelay = 2;
		g_ReadRequestType = ReadFirstByte;
		*lpdwBytesWritten = dwBytesToWrite;

		int hwkDataOffset = buffer[2];
		int hwkDataLength = buffer[3];
		if ( !hwkDataLength ) hwkDataLength = 0;

		memcpy(HWK_CHECKS_BUFFER + hwkDataOffset, buffer + 4, hwkDataLength);

		g_ResponseBuffer[0] = 0xA5;
		g_ResponseBufferLength = 1;

		goto FT_WRITE_EMU_EXIT;
	}
	else if (buffer[0] == 0x36) // hwk read-write
	{
		LogBufferToFile("[EMU] FT_Write", lpBuffer, *lpdwBytesWritten);

		g_GetQueueStatuHookEnabled = true;
		g_ReadRequestType = FullHwkResponseEmulation;
		g_GetQueueStatuReturnDelay = 3;
		g_ResponseBufferLength = buffer[1];
		BYTE hwkReadType = buffer[3];
		if (!g_ResponseBufferLength) g_ResponseBufferLength = 256;
		g_ResponseBuffer[0] = 0x54; // response start
		// BYTE bytesInWriteRequest = buffer[2];
		
		*lpdwBytesWritten = dwBytesToWrite;

		if (!hwkReadType)
		{
			g_ResponseBuffer[1] = 0xA5;
			g_ResponseBuffer[2] = 0x54;
			return 0;
		}
		if (hwkReadType == 1) // read hwk version
		{
			g_ResponseBuffer[1] = 0xA1;
			g_ResponseBuffer[2] = 0x04;
			g_GetQueueStatuReturnDelay = 2;
			AppendHwkResponseEnd();
			return 0;
		}
		else if (hwkReadType == 2) // read hwk buffer from offset
		{
			g_GetQueueStatuReturnDelay = 1;
			g_ResetGetQueueStatus = Init;

			int dataOffset = buffer[4];
			int dataLength = buffer[5];
			memcpy(g_ResponseBuffer + 1, HWK_CHECKS_BUFFER + dataOffset, dataLength);
			AppendHwkResponseEnd();
			return 0;
		}
		else if (hwkReadType == 3)	// write to hwk buffer
		{
			BYTE* hwkDataToWrite = buffer + 6;
			int hwkDataLength = buffer[5];
			int hwkDataOffset = buffer[4];

			memcpy(HWK_CHECKS_BUFFER + hwkDataOffset, hwkDataToWrite, hwkDataLength);
			AppendHwkResponseEnd();
			return 0;
		}
		else if (hwkReadType == 4) // re-initialize hwk buffer
		{
			g_GetQueueStatuReturnDelay = 2;
			memcpy(HWK_CHECKS_BUFFER + 8, HWK_INIT_TABLE, 0x98);
			AppendHwkResponseEnd();
			return 0;
		}
		else if (hwkReadType == 5) // fill buffer data with some checksums
		{
			STORAGE_BUFFER[0] = 0xAA;
			*(WORD*)(STORAGE_BUFFER + 1) = STORAGE_BUFFER2[0] & 0xFFF8;
			STORAGE_BUFFER[3] = 0x5F;
			
			memcpy(STORAGE_BUFFER + 4, &STORAGE_BUFFER2[1], 8);
			memcpy(HWK_CHECKS_BUFFER + 160, STORAGE_BUFFER + 1, 0xD);
			*(WORD*)(HWK_CHECKS_BUFFER + 171) = ~CalculateChecksumUsingLookupTable(12, STORAGE_BUFFER);

			AppendHwkResponseEnd();
			return 0;
		}
		else if (hwkReadType == 6)	// calculate some checksums
		{
			STORAGE_BUFFER[0] = 0xF;
			if ( *((WORD*)HWK_CHECKS_BUFFER + 80) <= 0x90 )
			{
				memcpy(STORAGE_BUFFER + 1, HWK_CHECKS_BUFFER + 160, 0xA);
				*((WORD*)HWK_CHECKS_BUFFER + 85) = ~CalculateChecksumUsingLookupTable(11, STORAGE_BUFFER);
				memcpy(STORAGE_BUFFER2, HWK_CHECKS_BUFFER + 160, 0xC);
			}
			else
			{
				memset(STORAGE_BUFFER2, 0, 0xA);
				STORAGE_BUFFER2[5] = -1;
				*((WORD*)HWK_CHECKS_BUFFER + 85) = -1;
			}

			AppendHwkResponseEnd();
			return 0;
		}
		else if (hwkReadType == 0xA) // calculate some checksums
		{
			STORAGE_BUFFER[0] = 0xA5;
			
			WORD hwkValue = *((WORD*)HWK_CHECKS_BUFFER + 80);
			
			*(WORD*)(STORAGE_BUFFER + 1) = hwkValue;
			memcpy(STORAGE_BUFFER + 3, HWK_INIT_TABLE + hwkValue, 0x20);
			
			STORAGE_BUFFER[35] = -1;
			*(WORD*)(STORAGE_BUFFER + 36) = ~CalculateChecksumUsingLookupTable(36, STORAGE_BUFFER);

			static BYTE responseChunk[] = {0x86,0x45,0x4C,0xDF,0x3D,0xFA,0x6D,0x0C,0x5E,0xBE,0x5C,0x46,0xBF,0x1A,0x3A,0x84,0xC7,0x2D,0x9C,0x05};
			memcpy(STORAGE_BUFFER + 38, responseChunk, 0x14);
			*((WORD*)STORAGE_BUFFER + 29) = ~CalculateChecksumUsingLookupTable(20, STORAGE_BUFFER + 38);
			*((WORD*)STORAGE_BUFFER + 30) = 0xAAAA;
			memcpy(HWK_CHECKS_BUFFER + 160, STORAGE_BUFFER + 1, 0x3D);

			AppendHwkResponseEnd();
			return 0;
		}
		else if (hwkReadType == 0xB) // write invert table to hwk buffer
		{
			g_GetQueueStatuReturnDelay = 1;
			int invertTableIndex = buffer[4];
			int writeAtOffset = buffer[5];
			unsigned int writeLength = buffer[6];
			unsigned int i;
			for (i = 0; i < g_ResponseBufferLength - 1; i++)
			{
				g_ResponseBuffer[i + 1] = i % 2 == 0 ? 0xA5 : 0;
			}
			
			for (i = 0; i < writeLength; i++)
			{
				HWK_CHECKS_BUFFER[writeAtOffset++] = ~INVERT_HWK_TABLE[invertTableIndex++];
			}
			
			AppendHwkResponseEnd();
			return 0;
		}
		else if (hwkReadType == 0x7 ||
				hwkReadType == 0x8 ||
				hwkReadType == 0x9 ||
				hwkReadType == 0xC ||
				hwkReadType == 0xD ||
				hwkReadType == 0xF)
        {
			AppendHwkResponseEnd();
			g_ResponseBuffer[1] = 0xA5;
			return 0;
        }
		else if (hwkReadType == 0xE)
        {
			AppendHwkResponseEnd();
			g_ResponseBuffer[1] = 0xA5;
			memcpy(HWK_INIT_TABLE, HWK_CHECKS_BUFFER + 160, 0xA);
			return 0;
        }
		else if (hwkReadType == 0x10 || hwkReadType == 0x13)
		{
			AppendHwkResponseEnd();
			g_ResponseBuffer[1] = 0x3C;
			g_ResponseBuffer[2] = 0xA5;
			return 0;
		}
		else if (hwkReadType == 0x11) // calculate checksum using xor tables
		{
			g_GetQueueStatuReturnDelay = 1;
			WORD someCount = buffer[5] | (buffer[4] << 8);
			int processBytesLength = 16 * buffer[6];
						
			WORD responseValue = processBytesLength + someCount;

			const BYTE* dataPtr;
			if (someCount >= 0xF000)
				dataPtr = &HWK_XOR_TABLE[someCount - 0xF000];
			else
				dataPtr = HWK_E_RANGE_XOR_TABLE;

			unsigned int encryptResult = CalculateChecksumUsingXorTable(processBytesLength, dataPtr);
			memcpy(g_ResponseBuffer + 1, &encryptResult, sizeof(int));
			
			g_ResponseBuffer[5] = (responseValue >> 8) & 0xFF;
			g_ResponseBuffer[6] = responseValue & 0xFF;
			
			AppendHwkResponseEnd();
			return 0;
		}
		else
		{
			if (hwkReadType == 0x12)
			{
				AppendHwkResponseEnd();
				g_ResponseBuffer[1] = 0x3C;
				return 0;
			}

			AppendHwkResponseEnd();
			g_ResponseBuffer[1] = 0x5A;
			return 0;
		}
	}
	else
	{
		g_ReadRequestType = Unknown;
		g_ShouldSetModemDCDBit = true;
		g_IsHwkCheckInProcess = false;
		g_IsHwkCheckSetupCompleted = false;
	}

CALL_FT_WRITE:

	g_GetQueueStatuHookEnabled = false;

	FT_STATUS ret = FT_WriteOrigFunc(ftHandle, lpBuffer, dwBytesToWrite, lpdwBytesWritten);

	if (lpdwBytesWritten)
		LogBufferToFile("FT_Write", lpBuffer, *lpdwBytesWritten);

	return ret;
}

static const BYTE DISK_INFO[] = {
	0x28,0x00,0x00,0x00,0x9C,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4C,0x00,0x00,0x00,
	0x6A,0x00,0x00,0x00,0x88,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x24,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x56,0x4D,0x77,0x61,0x72,0x65,0x20,0x56,0x69,0x72,0x74,0x75,
	0x61,0x6C,0x20,0x49,0x44,0x45,0x20,0x48,0x20,0x20,0x20,0x20,0x30,0x30,0x30,0x30,0x56,0x4D,0x77,0x61,
	0x72,0x65,0x20,0x56,0x69,0x72,0x74,0x75,0x61,0x6C,0x20,0x49,0x44,0x45,0x20,0x48,0x61,0x72,0x64,0x20,
	0x44,0x72,0x69,0x76,0x65,0x00,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x31,0x00,0x33,0x31,0x33,0x31,0x33,
	0x30,0x33,0x30,0x33,0x30,0x33,0x30,0x33,0x30,0x33,0x30,0x33,0x30,0x33,0x30,0x00,0x33,0x31,0x33,0x31,
	0x33,0x30,0x33,0x30,0x33,0x30,0x33,0x30,0x33,0x30,0x33,0x30,0x33,0x30,0x33,0x30,0x33,0x30,0x33,0x30,
	0x33,0x30,0x33,0x30,0x33,0x30,0x33,0x30,0x33,0x30,0x33,0x30,0x33,0x31,0x33,0x30,0x0
};

typedef HANDLE (WINAPI *CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
CreateFileA_t CreateFileAOrigFuncKBase = NULL;
CreateFileA_t CreateFileAOrigFuncK32 = NULL;

HANDLE WINAPI CreateFileA_KBaseHook(
    LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
)
{
	if (lstrcmp(lpFileName, "\\\\.\\PhysicalDrive1") == 0 ||
	    lstrcmp(lpFileName, "\\\\.\\PhysicalDrive2") == 0)
	{
		LogToFile("CreateFileA: Emulating only 1 PhysicalDrive");
		return INVALID_HANDLE_VALUE;
	}

    HANDLE result = CreateFileAOrigFuncKBase(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

	return result;
}

HANDLE WINAPI CreateFileA_K32Hook(
    LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
)
{
	if (lstrcmp(lpFileName, "\\\\.\\PhysicalDrive1") == 0 ||
	    lstrcmp(lpFileName, "\\\\.\\PhysicalDrive2") == 0)
	{
		LogToFile("CreateFileA: Emulating only 1 PhysicalDrive");
		return INVALID_HANDLE_VALUE;
	}

    HANDLE result = CreateFileAOrigFuncK32(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

	return result;
}

void ProcessDeviceIoControlResponse(
	DWORD IoControlCode,
    LPVOID InBuffer,
    DWORD InBufferSize,
    LPVOID OutBuffer,
    DWORD OutBufferSize,
    LPDWORD BytesReturned)
{
	if (IoControlCode == 0x2D1400 && sizeof(DISK_INFO) < OutBufferSize) // IOCTL_STORAGE_QUERY_PROPERTY
    {
		LogBufferToFile("Device IO Control InBuffer", InBuffer, InBufferSize);
		LogBufferToFile("Device IO Control Original OutBuffer", OutBuffer, OutBufferSize);
		LogToFile("Device IO Control BytesReturned: %d", (unsigned int)*BytesReturned);

		memcpy(OutBuffer, DISK_INFO, sizeof(DISK_INFO));
		*BytesReturned = sizeof(DISK_INFO);
    }
}

typedef BOOL (WINAPI *DeviceIoControl_t)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DeviceIoControl_t DeviceIoControlOrigFuncKBase = NULL;
DeviceIoControl_t DeviceIoControlOrigFuncK32 = NULL;

BOOL WINAPI DeviceIoControl_KBaseHook(
    HANDLE hDevice,
    DWORD IoControlCode,
    LPVOID InBuffer,
    DWORD InBufferSize,
    LPVOID OutBuffer,
    DWORD OutBufferSize,
    LPDWORD BytesReturned,
    LPOVERLAPPED Overlapped
)
{
    BOOL result = DeviceIoControlOrigFuncKBase(hDevice, IoControlCode, InBuffer, InBufferSize, OutBuffer,
        OutBufferSize, BytesReturned, Overlapped);

    if (!result)
        return result;

	ProcessDeviceIoControlResponse(IoControlCode, InBuffer, InBufferSize, OutBuffer, OutBufferSize, BytesReturned);

    return result;
}

BOOL WINAPI DeviceIoControl_K32Hook(
    HANDLE hDevice,
    DWORD IoControlCode,
    LPVOID InBuffer,
    DWORD InBufferSize,
    LPVOID OutBuffer,
    DWORD OutBufferSize,
    LPDWORD BytesReturned,
    LPOVERLAPPED Overlapped
)
{
    BOOL result = DeviceIoControlOrigFuncK32(hDevice, IoControlCode, InBuffer, InBufferSize, OutBuffer,
        OutBufferSize, BytesReturned, Overlapped);

    if (!result)
        return result;

	ProcessDeviceIoControlResponse(IoControlCode, InBuffer, InBufferSize, OutBuffer, OutBufferSize, BytesReturned);

    return result;
}

void ShowErrorMessageAndTerminate(const char* format, const char* funcName)
{
    char buffer[256];
    wsprintfA(buffer, format, funcName);
    MessageBoxA(NULL, buffer, "Error", MB_OK | MB_ICONERROR);
	TerminateProcess(GetCurrentProcess(), 1);
}

BOOL HookFunction(
	HMODULE hModule,
	const char* funcName,
	BYTE* origFuncEntryBytes,
	SIZE_T origFuncBufferLength,
	void** origFuncPtr,
	void* destHookFuncPtr,
	BOOL terminateOnFail = true
)
{
	DWORD oldProtect;
	const DWORD jmpLength = 5;
	
	BYTE* targetFunc = (BYTE*)GetProcAddress(hModule, funcName);
	if (!targetFunc)
	{
		LogToConsole("Bad driver. GetProcAddress failed for function %s", funcName);
		if (terminateOnFail)
		{
			ShowErrorMessageAndTerminate("Bad driver. GetProcAddress failed for function %s", funcName);
		}

		return false;
	}

	LogToConsole("%s found at %p", funcName, targetFunc);

	VirtualProtect(targetFunc, origFuncBufferLength, PAGE_EXECUTE_READWRITE, &oldProtect);

	for (SIZE_T i = 0; i < origFuncBufferLength; i++)
	{
		if (origFuncEntryBytes[i] != 0xFF && origFuncEntryBytes[i] != targetFunc[i])
		{
			LogToConsole("Bad driver. %s signature mismatch", funcName);
			if (terminateOnFail)
			{
				ShowErrorMessageAndTerminate("Bad driver. %s signature mismatch", funcName);
			}

			return false;
		}
	}

	BYTE* trampoline = (BYTE*)VirtualAlloc(
		NULL,
		origFuncBufferLength + jmpLength,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	*origFuncPtr = (void*)trampoline;
	memcpy(trampoline, targetFunc, origFuncBufferLength);
	
	DWORD jmpBackToOrigFuncAddr = (DWORD)(targetFunc + origFuncBufferLength);
	DWORD relativeJmpBack = jmpBackToOrigFuncAddr - ((DWORD)(trampoline + origFuncBufferLength) + 5);
	
	trampoline[origFuncBufferLength] = 0xE9; // JMP
	*(DWORD*)(trampoline + origFuncBufferLength + 1) = relativeJmpBack;

	DWORD tmpProtect;
	
	VirtualProtect(trampoline, origFuncBufferLength + jmpLength, PAGE_EXECUTE_READWRITE, &tmpProtect);

	LogToConsole("Hooked %s at %p", funcName, trampoline);
	
	DWORD relativeJmpToHookFunc = (DWORD)destHookFuncPtr - ((DWORD)targetFunc + 5);
	
	targetFunc[0] = 0xE9; // JMP
    *(DWORD*)(targetFunc + 1) = relativeJmpToHookFunc;

	for (i = 5; i < origFuncBufferLength; i++)
	{
		targetFunc[i] = 0x90; // nop
	}

	VirtualProtect(targetFunc, origFuncBufferLength, oldProtect, &oldProtect);

	LogToConsole("Hook for %s installed successfully", funcName);
	return true;
}

void InstallHooks()
{
    HMODULE hModule = NULL;
	BYTE waitCount = 0;

    LogToConsole("Waiting for UFS2XX.dll...");

    while (!hModule && waitCount < 200) // wait 20 secs
    {
        hModule = GetModuleHandleA("UFS2XX.dll");
		waitCount++;
        Sleep(100);
    }

	if (!hModule)
	{
		ShowErrorMessageAndTerminate("Timeout waiting for %s", "UFS2XX.dll");
		return;
	}

    LogToConsole("DLL loaded at %p", hModule);

	BYTE readEntryBytes[] = {0x57, 0x8B, 0x7C, 0x24, 0x08};
	HookFunction(hModule, "FT_Read", readEntryBytes, sizeof(readEntryBytes),
		(void**)&FT_ReadOrigFunc, (void*)FT_Read_Hook);

	BYTE writeEntryBytes[] = {0x57, 0x8B, 0x7C, 0x24, 0x08};
	HookFunction(hModule, "FT_Write", writeEntryBytes, sizeof(writeEntryBytes),
		(void**)&FT_WriteOrigFunc, (void*)FT_Write_Hook);

	BYTE getModemStatusEntryBytes[] = {0x8B, 0x4C, 0x24, 0x04, 0x6A, 0};
	HookFunction(hModule, "FT_GetModemStatus", getModemStatusEntryBytes, sizeof(getModemStatusEntryBytes),
		(void**)&FT_GetModemStatusOrigFunc, (void*)FT_GetModemStatus_Hook);

	BYTE getQueueStatusEntryBytes[] = {0x8B, 0x4C, 0x24, 0x04, 0x6A, 0};
	HookFunction(hModule, "FT_GetQueueStatus", getQueueStatusEntryBytes, sizeof(getQueueStatusEntryBytes),
		(void**)&FT_GetQueueStatusOrigFunc, (void*)FT_GetQueueStatus_Hook);

	BYTE purgeEntryBytes[] = {0x8B, 0x54, 0x24, 0x04, 0x6A, 0};
	HookFunction(hModule, "FT_Purge", purgeEntryBytes, sizeof(purgeEntryBytes),
		(void**)&FT_PurgeOrigFunc, (void*)FT_Purge_Hook);

	BYTE getDeviceInfoEntryBytes[] = {0x83, 0xEC, 0x70, 0xA1, 0xFF, 0xFF, 0xFF, 0xFF};
	HookFunction(hModule, "FT_GetDeviceInfo", getDeviceInfoEntryBytes, sizeof(getDeviceInfoEntryBytes),
		(void**)&FT_GetDeviceInfoOrigFunc, (void*)FT_GetDeviceInfo_Hook);

	BYTE listDevicesEntryBytes[] = {0x81, 0xEC, 0x84, 0x0, 0x0, 0x0};
	HookFunction(hModule, "FT_ListDevices", listDevicesEntryBytes, sizeof(listDevicesEntryBytes),
		(void**)&FT_ListDevicesOrigFunc, (void*)FT_ListDevices_Hook);

	BYTE openExEntryBytes[] = {0x83, 0xEC, 0x70, 0xA1, 0xFF, 0xFF, 0xFF, 0xFF};
	HookFunction(hModule, "FT_OpenEx", openExEntryBytes, sizeof(openExEntryBytes),
		(void**)&FT_OpenExOrigFunc, (void*)FT_OpenEx_Hook);


	BYTE DeviceIoControlBytes[] = {0x6A, 0xFF, 0x68, 0xFF, 0xFF, 0xFF, 0xFF};
	BYTE DeviceIoControlBytesFallback[] = {0x8B, 0xFF, 0x55, 0x8B, 0xFF};
	BYTE CreateFileABytes[] = {0x8B, 0xFF, 0x55, 0x8B, 0xFF};

	BOOL hookedDeviceIoControl = false;
	BOOL hookedCreateFileA = false;

	hModule = GetModuleHandleA("kernelbase.dll");
	if (hModule)
	{
		hookedDeviceIoControl = HookFunction(hModule, "DeviceIoControl", DeviceIoControlBytes, sizeof(DeviceIoControlBytes),
			(void**)&DeviceIoControlOrigFuncKBase, (void*)DeviceIoControl_KBaseHook, false);

		if (!hookedDeviceIoControl)
		{
			hookedDeviceIoControl = HookFunction(hModule, "DeviceIoControl", DeviceIoControlBytesFallback, sizeof(DeviceIoControlBytesFallback),
				(void**)&DeviceIoControlOrigFuncKBase, (void*)DeviceIoControl_KBaseHook, false);
		}

		hookedCreateFileA = HookFunction(hModule, "CreateFileA", CreateFileABytes, sizeof(CreateFileABytes),
			(void**)&CreateFileAOrigFuncKBase, (void*)CreateFileA_KBaseHook, false);
	}

	hModule = GetModuleHandleA("kernel32.dll");
	if (hModule)
	{
		BOOL success = HookFunction(hModule, "DeviceIoControl", DeviceIoControlBytes, sizeof(DeviceIoControlBytes),
			(void**)&DeviceIoControlOrigFuncK32, (void*)DeviceIoControl_K32Hook, false);

		if (!success)
		{
			success = HookFunction(hModule, "DeviceIoControl", DeviceIoControlBytesFallback, sizeof(DeviceIoControlBytesFallback),
				(void**)&DeviceIoControlOrigFuncK32, (void*)DeviceIoControl_K32Hook, false);
			
			if (!success && !hookedDeviceIoControl)
			{
				ShowErrorMessageAndTerminate("Bad system. Failed to hook %s", "DeviceIoControl");
			}
		}

		success = HookFunction(hModule, "CreateFileA", CreateFileABytes, sizeof(CreateFileABytes),
			(void**)&CreateFileAOrigFuncK32, (void*)CreateFileA_K32Hook, false);
		
		if (!success && !hookedCreateFileA)
		{
			ShowErrorMessageAndTerminate("Bad system. Failed to hook %s", "CreateFileA");
		}
	}

	LogToConsole("InstallHook finished successfully");
}

DWORD WINAPI ThreadProc(LPVOID lp)
{
	InitConsole();
	LogToConsole("DLL injected successfully");

	memset(HWK_E_RANGE_XOR_TABLE, 0x80, sizeof(HWK_E_RANGE_XOR_TABLE));
	memset(STORAGE_BUFFER2, 0, sizeof(STORAGE_BUFFER2));

	InstallHooks();

	return 0;
}

BOOL APIENTRY DllMain(
	HINSTANCE hinstDLL,
	DWORD fdwReason,
	LPVOID lpReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hinstDLL);
		CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
	}

	return TRUE;
}