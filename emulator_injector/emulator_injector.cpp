#include <windows.h>
#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")

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

static void BuildPath(char* out, int outSize, const char* folder, const char* file)
{
    lstrcpynA(out, folder, outSize);
    int len = lstrlenA(out);
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

static BOOL g_HasCheckedIs64Bit = false;
static BOOL g_Is64Bit = false;

BOOL IsRunningOn64Bit()
{
    if (g_HasCheckedIs64Bit) return g_Is64Bit;

    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);

    LPFN_ISWOW64PROCESS isWow64Process =
		(LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");

    if (isWow64Process)
    {
        isWow64Process(GetCurrentProcess(), &g_Is64Bit);
    }

	g_HasCheckedIs64Bit = true;
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

    const char* IV="4D45564EB20F8C526B27D3D92390BB920D9D811D8601BA547DD0A830D910E669FC9AC882E23D65989BE09E656151E7AC7260FAEE4F0EDE25DB3133313AB9518B74D0EAA9466450B2B17050BC3D57F306749F1E42B778F63D820CC00B26EF05C2F1FFF6B1306D64EC133942E8681800ECACAD574C4C66DB9A59A2419B20910055";
    RegSetValueEx(hKey, "IV", 0, REG_SZ, (BYTE*)IV, lstrlen(IV) + 1);

	const char* ID = "AA1B02806B681CC8AE3FAC6B4B297CBBA8D6BE14C034EC597A9154EC862BD459927A8F03F92F66EE568CE013D0C55359D22F650BA08391AF01E47CC32B121F87525E90DD3B44DBFAA08A0E7218CA4441D21DD9504781A85606CABE3C616DFF2E299D3EB729C84937CAAA4EABA2FDABDA2900A3E23FAC30FE";
    RegSetValueEx(hKey, "ID", 0, REG_SZ, (BYTE*)ID, lstrlen(ID) + 1);

	const char* IH = "80773171";
    RegSetValueEx(hKey, "IH", 0, REG_SZ, (BYTE*)IH, lstrlen(IH) + 1);
	
	const char* IM = "1F53DB28A7AFA2191AC4E0DDA0AD7E6D";
    RegSetValueEx(hKey, "IM", 0, REG_SZ, (BYTE*)IM, lstrlen(IM) + 1);
	
	const char* IL="D9C170978D1EB6D99D79A7BD6EAAEAFF56B9C9960955257927B2C54A70F540BB6DFE9B73DFD8C7331B9E50AE423BEB78C9C28A28990B83A468F550D19EBAE38712";
    RegSetValueEx(hKey, "IL", 0, REG_SZ, (BYTE*)IL, lstrlen(IL) + 1);

    RegCloseKey(hKey);

    RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\SarasSoft\\UFS3\\DCTxBB5",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);

	SetRegistryProgramFilesPathValue(hKey, "Base Path", "Nokia\\Phoenix\\");
	SetRegistryProgramFilesPathValue(hKey, "FG Path", "Nokia\\Phoenix\\Flash\\");
	SetRegistryProgramFilesPathValue(hKey, "FIA Path", "Nokia\\Phoenix\\Flash\\");
	SetRegistryProgramFilesPathValue(hKey, "TIA Path", "Nokia\\Phoenix\\Flash3\\");
	SetRegistryProgramFilesPathValue(hKey, "Tesla Path", "Nokia\\Phoenix\\");

	const char* teslaPath  = "C:\\Wintesla\\";
    RegSetValueEx(hKey, "Tesla Path", 0, REG_SZ, (BYTE*)teslaPath, lstrlen(teslaPath) + 1);

    RegCloseKey(hKey);

    RegCreateKeyEx(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\SarasSoft\\UFS3\\GlobalOptions", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);

	SetRegistryProgramFilesPathValue(hKey, "APLPATH", "");
	SetRegistryProgramFilesPathValue(hKey, "NOKPATH", "Nokia\\Phoenix\\");
    
	const char* IMEE = "E079E4CCAC1C269E014A722A91D2B5EA65FE3EF5";
    RegSetValueEx(hKey, "IMEE", 0, REG_SZ, (BYTE*)IMEE, lstrlen(IMEE) + 1);
	
	DWORD one = 1;
    RegSetValueEx(hKey, "ClientRunTimes", 0, REG_DWORD, (BYTE*)&one, sizeof(one));
    RegSetValueEx(hKey, "ClientRun", 0, REG_DWORD, (BYTE*)&one, sizeof(one));

    RegCloseKey(hKey);
}

int main(int argc, char* argv[])
{
    char searchFolder[MAX_PATH];
    char exePath[MAX_PATH];
    char dllPath[MAX_PATH];
    const char* foundExe;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

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

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(exePath,
                        NULL,
                        NULL, NULL,
                        FALSE,
                        0,
                        NULL,
                        searchFolder,
                        &si, &pi))
    {
        MessageBoxA(NULL, "CreateProcess failed.", "Injector Error", MB_OK | MB_ICONERROR);
        return 1;
    }

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
