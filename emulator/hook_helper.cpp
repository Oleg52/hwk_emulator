#include <windows.h>
#include "hook_helper.h"
#include "logging.h"

void ShowErrorMessageAndTerminate(const char* format, const char* funcName)
{
    char buffer[256];
    wsprintfA(buffer, format, funcName);
    MessageBoxA(NULL, buffer, "Error", MB_OK | MB_ICONERROR);
    TerminateProcess(GetCurrentProcess(), 1);
}

void ShowBadDriverErrorAndTerminateIfTrue(BOOL enabled, const char* funcName)
{
    if (!enabled) return;
    ShowErrorMessageAndTerminate("Bad driver. GetProcAddress failed for function %s", funcName);
}

BOOL IatHookFunction(const char* moduleName, const char* funcName, void** origFuncPtr, void* destHookFuncPtr, BOOL terminateOnFail)
{
    BYTE* base = (BYTE*)GetModuleHandleA(NULL);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        ShowBadDriverErrorAndTerminateIfTrue(terminateOnFail, funcName);
        return FALSE;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        ShowBadDriverErrorAndTerminateIfTrue(terminateOnFail, funcName);
        return FALSE;
    }

    IMAGE_DATA_DIRECTORY importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size == 0)
    {
        ShowBadDriverErrorAndTerminateIfTrue(terminateOnFail, funcName);
        return FALSE;
    }

    PIMAGE_IMPORT_DESCRIPTOR import = (PIMAGE_IMPORT_DESCRIPTOR)(base + importDir.VirtualAddress);
    for(;import->Name; import++)
    {
        if (stricmp((const char*)(base + import->Name), moduleName) != 0)
        {
            continue;
        }

        PIMAGE_THUNK_DATA origFirstThunk = (PIMAGE_THUNK_DATA)(base + import->OriginalFirstThunk);
        PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(base + import->FirstThunk);
        BOOL lookupByAddress = import->OriginalFirstThunk == 0;
        if (lookupByAddress)
        {
            origFirstThunk = firstThunk;
        }

        for (;origFirstThunk->u1.AddressOfData != 0; origFirstThunk++, firstThunk++)
        {
            if (!lookupByAddress && origFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                continue;
            }

            if (!lookupByAddress)
            {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(base + (DWORD)origFirstThunk->u1.AddressOfData);
                if (strcmp((const char*)importByName->Name, funcName) != 0)
                {
                    continue;
                }
            }
            else
            {
                HMODULE hModule = LoadLibraryA(moduleName);
                DWORD* proc = (DWORD*)GetProcAddress(hModule, funcName);
                if (proc == NULL || firstThunk->u1.Function != proc)
                {
                    continue;
                }
            }

            LogToFile("Found IAT thunk of %s in %s", funcName, moduleName);
            DWORD oldProtect;
            if (!VirtualProtect(&firstThunk->u1.Function, sizeof(LPVOID), PAGE_READWRITE, &oldProtect))
            {
                ShowBadDriverErrorAndTerminateIfTrue(terminateOnFail, funcName);
                return FALSE;
            }

            if (origFuncPtr)
            {
                *origFuncPtr = (void*)firstThunk->u1.Function;
            }

            firstThunk->u1.Function = (DWORD*)destHookFuncPtr;
            VirtualProtect(&firstThunk->u1.Function, sizeof(LPVOID), oldProtect, &oldProtect);
            return TRUE;
        }
    }

    ShowBadDriverErrorAndTerminateIfTrue(terminateOnFail, funcName);
    return FALSE;
}

BOOL EatHookFunction(HMODULE hModule, const char* funcName, void** origFuncPtr, void* destHookFuncPtr, BOOL terminateOnFail)
{
    BYTE* base = (BYTE*)hModule;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        ShowBadDriverErrorAndTerminateIfTrue(terminateOnFail, funcName);
        return FALSE;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        ShowBadDriverErrorAndTerminateIfTrue(terminateOnFail, funcName);
        return FALSE;
    }

    IMAGE_DATA_DIRECTORY expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.VirtualAddress == 0)
    {
        ShowBadDriverErrorAndTerminateIfTrue(terminateOnFail, funcName);
        return FALSE;
    }

    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(base + expDir.VirtualAddress);

    DWORD* nameRVAs = (DWORD*)(base + exports->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
    DWORD* funcRVAs = (DWORD*)(base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++)
    {
        const char* name = (const char*)(base + nameRVAs[i]);
        if (strcmp(name, funcName) != 0)
        {
            continue;
        }

        WORD ordinal = ordinals[i];
        DWORD funcRVA = funcRVAs[ordinal];
        BYTE* origFuncAddr = base + funcRVA;

        if (funcRVA >= expDir.VirtualAddress &&
            funcRVA <  expDir.VirtualAddress + expDir.Size) {
            return NULL;
        }

        DWORD oldProtect;
        if (!VirtualProtect(&funcRVAs[ordinal], sizeof(DWORD), PAGE_READWRITE, &oldProtect))
        {
            ShowBadDriverErrorAndTerminateIfTrue(terminateOnFail, funcName);
            return FALSE;
        }

        if (origFuncPtr)
        {
            *origFuncPtr = (void*)origFuncAddr;
        }

        funcRVAs[ordinal] = (DWORD)destHookFuncPtr - (DWORD)hModule;
        VirtualProtect(&funcRVAs[ordinal], sizeof(DWORD), oldProtect, &oldProtect);
        return TRUE;
    }

    ShowBadDriverErrorAndTerminateIfTrue(terminateOnFail, funcName);
    return FALSE;
}

BOOL HookFunction(HMODULE hModule, const char* funcName, BYTE* origFuncEntryBytes,
    SIZE_T origFuncBufferLength, void** origFuncPtr, void* destHookFuncPtr, BOOL terminateOnFail)
{
    DWORD oldProtect;
    const DWORD jmpLength = 5;

    BYTE* targetFunc = (BYTE*)GetProcAddress(hModule, funcName);
    if (!targetFunc)
    {
        ShowBadDriverErrorAndTerminateIfTrue(terminateOnFail, funcName);
        return FALSE;
    }

    VirtualProtect(targetFunc, origFuncBufferLength, PAGE_EXECUTE_READWRITE, &oldProtect);

    LogToFile("Function %s signature:", funcName);
    LogBufferToFile("Buffer:", (void*)targetFunc, 10);

    SIZE_T i;
    for (i = 0; i < origFuncBufferLength; i++)
    {
        if (origFuncEntryBytes[i] != 0xFF && origFuncEntryBytes[i] != targetFunc[i])
        {
            if (terminateOnFail)
                ShowErrorMessageAndTerminate("Bad driver. %s signature mismatch", funcName);
            return FALSE;
        }
    }

    BYTE* trampoline = (BYTE*)VirtualAlloc(NULL, origFuncBufferLength + jmpLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (origFuncPtr) *origFuncPtr = (void*)trampoline;
    memcpy(trampoline, targetFunc, origFuncBufferLength);

    if ((trampoline[0] == 0xE9 || trampoline[0] == 0xE8) && origFuncBufferLength >= 5)
    {
        DWORD origRel = *(DWORD*)(trampoline + 1);
        BYTE* origTarget = targetFunc + 5 + (LONG)origRel;
        DWORD newRel = origTarget - (trampoline + 5);
        *(DWORD*)(trampoline + 1) = newRel;
    }

    DWORD jmpBackAddr = (DWORD)(targetFunc + origFuncBufferLength);
    DWORD relJmpBack = jmpBackAddr - ((DWORD)(trampoline + origFuncBufferLength) + 5);
    trampoline[origFuncBufferLength] = 0xE9;
    *(DWORD*)(trampoline + origFuncBufferLength + 1) = relJmpBack;

    DWORD tmpProtect;
    VirtualProtect(trampoline, origFuncBufferLength + jmpLength, PAGE_EXECUTE_READWRITE, &tmpProtect);

    DWORD relJmpHook = (DWORD)destHookFuncPtr - ((DWORD)targetFunc + 5);
    targetFunc[0] = 0xE9;
    *(DWORD*)(targetFunc + 1) = relJmpHook;
    for (i = 5; i < origFuncBufferLength; i++) targetFunc[i] = 0x90;

    VirtualProtect(targetFunc, origFuncBufferLength, oldProtect, &oldProtect);
    return TRUE;
}

void HookFunctionWithFallback(HMODULE hModule, const char* funcName, FuncEntrySignature funcSigs[],
    SIZE_T totalSigsSize, void** origFuncPtr, void* destHookFuncPtr)
{
    int sigsCount = totalSigsSize / sizeof(funcSigs[0]);
    for (int i = 0; i < sigsCount; i++)
    {
        BOOL success = HookFunction(hModule, funcName, funcSigs[i].bytes, funcSigs[i].size, origFuncPtr, destHookFuncPtr, i == sigsCount - 1);
        if (success) break;
    }
}

BOOL HookFunctionWithFallbackSafe(HMODULE hModule, const char* funcName, FuncEntrySignature funcSigs[],
    SIZE_T totalSigsSize, void** origFuncPtr, void* destHookFuncPtr, BOOL errorOnFail)
{
    int sigsCount = totalSigsSize / sizeof(funcSigs[0]);
    for (int i = 0; i < sigsCount; i++)
    {
        BOOL success = HookFunction(hModule, funcName, funcSigs[i].bytes, funcSigs[i].size, origFuncPtr, destHookFuncPtr, errorOnFail && i == sigsCount - 1);
        if (success) return TRUE;
    }

    return FALSE;
}