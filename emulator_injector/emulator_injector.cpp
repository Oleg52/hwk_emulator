#include <windows.h>
#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")

typedef long* ULONG_PTR;

static const char* g_CheckList[] = {
    "DCTxBB5.exe",
    "Acer.exe",
    "ATRz.exe",
    "SeDbx.exe",
    "KZF.exe",
    "LG_GSM.exe",
    "RTP.exe",
    "SAMs.exe",
};
static const int g_CheckListCount = sizeof(g_CheckList) / sizeof(g_CheckList[0]);

static const char* g_DllName = "emulator.dll";

/* ============================================================================
 * IAT FIX TABLES
 * ----------------------------------------------------------------------------
 * For each target EXE, list the by-ordinal imports whose ordinals were
 * "captured" against an older Windows version and no longer match today's
 * system DLLs.  At launch we look up each function NAME (stable forever) in
 * the user's current DLL, get its CURRENT ordinal, and rewrite the IAT slot
 * of the suspended child process before the Windows loader runs imports.
 * ============================================================================ */
typedef struct {
    const char* dll;
    int         slot;       /* 0-based index into that DLL's import table */
    const char* funcName;
} ImportFix;

static const ImportFix g_Fixes_DCTxBB5[] = {
    { "wininet.dll",  0, "InternetReadFile"       },
    { "wininet.dll",  1, "InternetOpenUrlA"       },
    { "wininet.dll",  2, "InternetOpenA"          },
    { "wininet.dll",  3, "InternetCloseHandle"    },
    { "winspool.drv", 0, "OpenPrinterA"           },
    { "winspool.drv", 1, "EnumPrintersA"          },
    { "winspool.drv", 2, "DocumentPropertiesA"    },
    { "winspool.drv", 3, "ClosePrinter"           },
    { "winscard.dll", 0, "SCardIsValidContext"    },
    { "winscard.dll", 1, "SCardGetAttrib"         },
    { "winscard.dll", 2, "SCardTransmit"          },
    { "winscard.dll", 3, "SCardDisconnect"        },
    { "winscard.dll", 4, "SCardConnectA"          },
    { "winscard.dll", 5, "SCardCancel"            },
    { "winscard.dll", 6, "SCardGetStatusChangeA"  },
    { "winscard.dll", 7, "SCardListReadersA"      },
    { "winscard.dll", 8, "SCardReleaseContext"    },
    { "winscard.dll", 9, "SCardEstablishContext"  },
    { NULL, 0, NULL }
};

typedef struct {
    const char*       exeName;
    const ImportFix*  fixes;
} AppFixes;

static const AppFixes g_AllFixes[] = {
    { "DCTxBB5.exe", g_Fixes_DCTxBB5 },
    { NULL, NULL }
};

static const ImportFix* FindFixesForApp(const char* exeName)
{
    for (int i = 0; g_AllFixes[i].exeName; i++) {
        if (lstrcmpiA(g_AllFixes[i].exeName, exeName) == 0) {
            return g_AllFixes[i].fixes;
        }
    }
    return NULL;
}

/* ============================================================================
 * Helpers for suspended-child memory access and PE parsing
 * ============================================================================ */
static BOOL SafeRead(HANDLE hProc, LPCVOID addr, LPVOID buf, SIZE_T n)
{
    SIZE_T got = 0;
    if (!ReadProcessMemory(hProc, addr, buf, n, &got)) return FALSE;
    return (got == n);
}

static BOOL SafeWrite(HANDLE hProc, LPVOID addr, LPCVOID buf, SIZE_T n)
{
    SIZE_T wrote = 0;
    DWORD oldProt = 0;
    BOOL ok;
    if (!VirtualProtectEx(hProc, addr, n, PAGE_READWRITE, &oldProt)) return FALSE;
    ok = WriteProcessMemory(hProc, addr, (LPVOID)buf, n, &wrote) && (wrote == n);
    VirtualProtectEx(hProc, addr, n, oldProt, &oldProt);
    return ok;
}

/* Get the main image base of a just-CREATE_SUSPENDED 32-bit child.  The
 * primary thread's EBX register points to the child's PEB; PEB.ImageBaseAddress
 * lives at offset 0x08 inside PEB.  Works for 32-bit injector + 32-bit child. */
static LPVOID GetChildImageBase(HANDLE hProc, HANDLE hThread)
{
    CONTEXT ctx;
    LPVOID peb;
    LPVOID imageBase = NULL;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(hThread, &ctx)) return NULL;
    peb = (LPVOID)(ULONG_PTR)ctx.Ebx;
    if (!peb) return NULL;
    if (!SafeRead(hProc, (BYTE*)peb + 8, &imageBase, sizeof(imageBase))) return NULL;
    return imageBase;
}

/* Look up a function's ordinal by NAME in a DLL loaded in our own process.
 * Returns -1 if not found. */
static int GetCurrentOrdinalForName(const char* dllName, const char* funcName)
{
    HMODULE hMod;
    PIMAGE_DOS_HEADER        dos;
    PIMAGE_NT_HEADERS        nt;
    PIMAGE_EXPORT_DIRECTORY  exp;
    DWORD                    expRva, expSize;
    DWORD*                   nameRvas;
    WORD*                    nameOrds;
    DWORD                    i;

    hMod = LoadLibraryA(dllName);
    if (!hMod) return -1;

    dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return -1;
    nt  = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return -1;

    expRva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    expSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!expRva || !expSize) return -1;
    exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + expRva);

    nameRvas = (DWORD*)((BYTE*)hMod + exp->AddressOfNames);
    nameOrds = (WORD*) ((BYTE*)hMod + exp->AddressOfNameOrdinals);

    for (i = 0; i < exp->NumberOfNames; i++) {
        const char* nm = (const char*)((BYTE*)hMod + nameRvas[i]);
        if (lstrcmpA(nm, funcName) == 0) {
            return (int)exp->Base + (int)nameOrds[i];
        }
    }
    return -1;
}

/* Walk the suspended child's import directory.  For each DLL whose imports
 * need fixing, rewrite the on-disk-captured ordinal to the ordinal valid on
 * the CURRENT Windows system.  Must be called before ResumeThread. */
static int ApplyIATFixes(HANDLE hProc, LPVOID imageBase, const ImportFix* fixes)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS nt;
    DWORD impRva;
    DWORD idx, f;
    int   patched = 0;

    if (!fixes) return 0;
    if (!SafeRead(hProc, imageBase, &dos, sizeof(dos))) return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if (!SafeRead(hProc, (BYTE*)imageBase + dos.e_lfanew, &nt, sizeof(nt))) return 0;
    if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;

    impRva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!impRva) return 0;

    for (idx = 0; ; idx++) {
        IMAGE_IMPORT_DESCRIPTOR desc;
        char dllName[64];
        if (!SafeRead(hProc, (BYTE*)imageBase + impRva + idx * sizeof(desc),
                      &desc, sizeof(desc))) break;
        if (desc.Name == 0 && desc.FirstThunk == 0) break;

        ZeroMemory(dllName, sizeof(dllName));
        SafeRead(hProc, (BYTE*)imageBase + desc.Name, dllName, sizeof(dllName) - 1);

        for (f = 0; fixes[f].dll; f++) {
            int newOrd;
            DWORD newThunk;
            LPVOID slotVA;

            if (lstrcmpiA(fixes[f].dll, dllName) != 0) continue;

            newOrd = GetCurrentOrdinalForName(fixes[f].dll, fixes[f].funcName);
            if (newOrd < 0) continue;   /* function missing in this Windows -- skip */

            newThunk = 0x80000000UL | (DWORD)newOrd;

            /* Patch IAT (FirstThunk) */
            slotVA = (BYTE*)imageBase + desc.FirstThunk + (DWORD)fixes[f].slot * 4;
            if (SafeWrite(hProc, slotVA, &newThunk, sizeof(newThunk))) patched++;

            /* Patch OFT (OriginalFirstThunk / Import Lookup Table) if present and
             * physically distinct from IAT -- some loaders consult it for name/ord. */
            if (desc.OriginalFirstThunk && desc.OriginalFirstThunk != desc.FirstThunk) {
                LPVOID oftVA = (BYTE*)imageBase + desc.OriginalFirstThunk
                               + (DWORD)fixes[f].slot * 4;
                SafeWrite(hProc, oftVA, &newThunk, sizeof(newThunk));
            }
        }
    }
    return patched;
}

static void BuildPath(char* out, int outSize, const char* folder, const char* file)
{
    int len;
    lstrcpynA(out, folder, outSize);
    len = lstrlenA(out);
    if (len > 0 && out[len - 1] != '\\') {
        lstrcatA(out, "\\");
    }
    lstrcatA(out, file);
}

static BOOL FileExists(const char* path)
{
    DWORD attr = GetFileAttributesA(path);
    return (attr != 0xFFFFFFFF && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

static const char* FindTargetExe(const char* folder)
{
    char fullPath[MAX_PATH];
    int i;
    for (i = 0; i < g_CheckListCount; i++) {
        BuildPath(fullPath, MAX_PATH, folder, g_CheckList[i]);
        if (FileExists(fullPath)) {
            return g_CheckList[i];
        }
    }
    return NULL;
}

static BOOL InjectDll(HANDLE hProcess, const char* dllFullPath)
{
    DWORD pathLen = lstrlenA(dllFullPath) + 1;
    LPVOID remoteBuf;
    HANDLE hThread;
    LPTHREAD_START_ROUTINE pLoadLibrary;

    remoteBuf = VirtualAllocEx(hProcess, NULL, pathLen,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuf) {
        MessageBoxA(NULL, "VirtualAllocEx failed", "Injector Error", MB_OK | MB_ICONERROR);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, remoteBuf, (LPVOID)dllFullPath, pathLen, NULL)) {
        MessageBoxA(NULL, "WriteProcessMemory failed", "Injector Error", MB_OK | MB_ICONERROR);
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        return FALSE;
    }

    pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(
                        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!pLoadLibrary) {
        MessageBoxA(NULL, "GetProcAddress(LoadLibraryA) failed", "Injector Error", MB_OK | MB_ICONERROR);
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        return FALSE;
    }

    hThread = CreateRemoteThread(hProcess, NULL, 0,
                                 pLoadLibrary, remoteBuf, 0, NULL);
    if (!hThread) {
        MessageBoxA(NULL, "CreateRemoteThread failed", "Injector Error", MB_OK | MB_ICONERROR);
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        return FALSE;
    }

    CloseHandle(hThread);
    return TRUE;
}

static BOOL g_HasCheckedIs64Bit = FALSE;
static BOOL g_Is64Bit = FALSE;

BOOL IsRunningOn64Bit()
{
    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS isWow64Process;

    if (g_HasCheckedIs64Bit) return g_Is64Bit;

    isWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "IsWow64Process");

    if (isWow64Process) {
        isWow64Process(GetCurrentProcess(), &g_Is64Bit);
    }

    g_HasCheckedIs64Bit = TRUE;
    return g_Is64Bit;
}

void SetRegistryProgramFilesPathValue(HKEY hKey, const char* keyName, const char* subPath)
{
    static char buffer[100];

    if (IsRunningOn64Bit()) lstrcpy(buffer, "C:\\Program Files (x86)\\");
    else lstrcpy(buffer, "C:\\Program Files\\");

    lstrcat(buffer, subPath);

    RegSetValueEx(hKey, keyName, 0, REG_SZ, (BYTE*)buffer, lstrlen(buffer) + 1);
}

void UpdateRegistryValues()
{
    HKEY hKey;

    RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\SarasSoft", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    RegCloseKey(hKey);

    RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\SarasSoft\\UFS3", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    RegCloseKey(hKey);

    RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\SarasSoft\\UFS3\\1_16455879416000A5", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);

    {
        const char* IV="4D45564EB20F8C526B27D3D92390BB920D9D811D8601BA547DD0A830D910E669FC9AC882E23D65989BE09E656151E7AC7260FAEE4F0EDE25DB3133313AB9518B74D0EAA9466450B2B17050BC3D57F306749F1E42B778F63D820CC00B26EF05C2F1FFF6B1306D64EC133942E8681800ECACAD574C4C66DB9A59A2419B20910055";
        const char* ID = "AA1B02806B681CC8AE3FAC6B4B297CBBA8D6BE14C034EC597A9154EC862BD459927A8F03F92F66EE568CE013D0C55359D22F650BA08391AF01E47CC32B121F87525E90DD3B44DBFAA08A0E7218CA4441D21DD9504781A85606CABE3C616DFF2E299D3EB729C84937CAAA4EABA2FDABDA2900A3E23FAC30FE";
        const char* IH = "80773171";
        const char* IM = "1F53DB28A7AFA2191AC4E0DDA0AD7E6D";
        const char* IL="D9C170978D1EB6D99D79A7BD6EAAEAFF56B9C9960955257927B2C54A70F540BB6DFE9B73DFD8C7331B9E50AE423BEB78C9C28A28990B83A468F550D19EBAE38712";
        RegSetValueEx(hKey, "IV", 0, REG_SZ, (BYTE*)IV, lstrlen(IV) + 1);
        RegSetValueEx(hKey, "ID", 0, REG_SZ, (BYTE*)ID, lstrlen(ID) + 1);
        RegSetValueEx(hKey, "IH", 0, REG_SZ, (BYTE*)IH, lstrlen(IH) + 1);
        RegSetValueEx(hKey, "IM", 0, REG_SZ, (BYTE*)IM, lstrlen(IM) + 1);
        RegSetValueEx(hKey, "IL", 0, REG_SZ, (BYTE*)IL, lstrlen(IL) + 1);
    }

    RegCloseKey(hKey);

    RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\SarasSoft\\UFS3\\DCTxBB5",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);

    SetRegistryProgramFilesPathValue(hKey, "Base Path", "Nokia\\Phoenix\\");
    SetRegistryProgramFilesPathValue(hKey, "FG Path",   "Nokia\\Phoenix\\Flash\\");
    SetRegistryProgramFilesPathValue(hKey, "FIA Path",  "Nokia\\Phoenix\\Flash\\");
    SetRegistryProgramFilesPathValue(hKey, "TIA Path",  "Nokia\\Phoenix\\Flash3\\");
    SetRegistryProgramFilesPathValue(hKey, "Tesla Path","Nokia\\Phoenix\\");

    {
        const char* teslaPath  = "C:\\Wintesla\\";
        RegSetValueEx(hKey, "Tesla Path", 0, REG_SZ, (BYTE*)teslaPath, lstrlen(teslaPath) + 1);
    }

    RegCloseKey(hKey);

    RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\SarasSoft\\UFS3\\GlobalOptions", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);

    SetRegistryProgramFilesPathValue(hKey, "APLPATH", "");
    SetRegistryProgramFilesPathValue(hKey, "NOKPATH", "Nokia\\Phoenix\\");

    {
        const char* IMEE = "E079E4CCAC1C269E014A722A91D2B5EA65FE3EF5";
        DWORD one = 1;
        RegSetValueEx(hKey, "IMEE", 0, REG_SZ, (BYTE*)IMEE, lstrlen(IMEE) + 1);
        RegSetValueEx(hKey, "ClientRunTimes", 0, REG_DWORD, (BYTE*)&one, sizeof(one));
        RegSetValueEx(hKey, "ClientRun",      0, REG_DWORD, (BYTE*)&one, sizeof(one));
    }

    RegCloseKey(hKey);
}

int main(int argc, char* argv[])
{
    char searchFolder[MAX_PATH];
    char exePath[MAX_PATH];
    char dllPath[MAX_PATH];
    const char* foundExe;
    const ImportFix* fixes;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    LPVOID childImageBase;
    int patchedCount;

    GetCurrentDirectoryA(MAX_PATH, searchFolder);

    foundExe = FindTargetExe(searchFolder);
    if (!foundExe) {
        MessageBoxA(NULL, "Executable not found. Check file name of the app. Example: DCTxBB5.exe", "Injector Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    BuildPath(exePath, MAX_PATH, searchFolder, foundExe);
    BuildPath(dllPath, MAX_PATH, searchFolder, g_DllName);

    if (!FileExists(dllPath)) {
        MessageBoxA(NULL, "DLL not found.", "Injector Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    UpdateRegistryValues();

    /* Look up a per-app IAT fix table (may be NULL for apps without fixes). */
    fixes = FindFixesForApp(foundExe);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    /* Create SUSPENDED so we can rewrite the IAT before the loader runs. */
    if (!CreateProcessA(exePath,
                        NULL,
                        NULL, NULL,
                        FALSE,
                        CREATE_SUSPENDED,
                        NULL,
                        searchFolder,
                        &si, &pi))
    {
        MessageBoxA(NULL, "CreateProcess failed.", "Injector Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    /* Apply dynamic IAT fixes for this app on this Windows version. */
    if (fixes) {
        childImageBase = GetChildImageBase(pi.hProcess, pi.hThread);
        if (childImageBase) {
            patchedCount = ApplyIATFixes(pi.hProcess, childImageBase, fixes);
        } else {
            MessageBoxA(NULL, "Could not locate child image base (IAT fix skipped).",
                        "Injector Warning", MB_OK | MB_ICONWARNING);
        }
    }

    /* Let the loader + startup code run with the corrected imports. */
    ResumeThread(pi.hThread);

    WaitForInputIdle(pi.hProcess, 5000);

    if (!InjectDll(pi.hProcess, dllPath)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
