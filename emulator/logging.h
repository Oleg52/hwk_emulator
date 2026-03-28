#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

// #define ENABLE_LOGS

const unsigned int MAX_BYTES_PER_LINE = 20;
const char* DUMP_FILE_NAME = "C:\\dump_info.txt";

void LogBufferAsHex(FILE* f, unsigned char* data, unsigned int dataIndex, int bytesWritten)
{
	unsigned int i;
	unsigned int counter = bytesWritten;
	for (i = dataIndex; counter < MAX_BYTES_PER_LINE; i++)
	{
		if (i != 0 && i % 4 == 0)
		{
			fputc(' ', f);
		}

		fputc(' ', f);
		fputc(' ', f);
		fputc(' ', f);
		counter++;
	}
	
	fputc(' ', f);
	fputc(' ', f);
	
	for (i = dataIndex - bytesWritten; i < dataIndex; i++)
	{
		unsigned char item = data[i];
		if (isprint(item))
		{
			fputc(item, f);
			continue;
		}
		
		fputc('.', f);
	}

	fputc('\n', f);
}

void LogBufferToFile(const char* opType, void* buffer, unsigned int length)
{
#ifdef ENABLE_LOGS
    FILE* f = fopen(DUMP_FILE_NAME, "a");
    if (!f) return;

    fprintf(f, "%s: %d\n", opType, length);

	int bytesWritten = 0;
	unsigned char* data = (unsigned char*)buffer;
	unsigned int i = 0;
	for (; i < length; i++)
	{
		if (bytesWritten == MAX_BYTES_PER_LINE)
		{
			LogBufferAsHex(f, data, i, bytesWritten);
			bytesWritten = 0;
		}
		
		if (bytesWritten != 0 && bytesWritten % 4 == 0)
		{
			fputc(' ', f);
		}
		
		fprintf(f, "%02X ", data[i]);
		bytesWritten++;
	}
	
	LogBufferAsHex(f, data, i, bytesWritten);
	
	fputc('\n', f);
    fclose(f);
#endif
}

void LogToFile(const char* format, ...)
{
#ifdef ENABLE_LOGS
    FILE* f = fopen(DUMP_FILE_NAME, "a");
    if (!f) return;

	va_list args;
    va_start(args, format);
	vfprintf(f, format, args);
	va_end(args);

	fputc('\n', f);
	fputc('\n', f);

    fclose(f);
#endif
}

void LogToConsole(const char* format, ...)
{
#ifdef ENABLE_LOGS
	va_list args;
    va_start(args, format);
	vprintf(format, args);
	va_end(args);

	printf("\n");
#endif
}

void InitConsole()
{
#ifdef ENABLE_LOGS
	AllocConsole();
	freopen("CONOUT$", "w", stdout);
	SetConsoleTitleA("UFS Hook Debug Console");
#endif
}