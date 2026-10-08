#include <windows.h>

BOOL IsRunningOn64Bit()
{
    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS isWow64Process;
    BOOL is64Bit;

    isWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");
    if (isWow64Process)
    {
        isWow64Process(GetCurrentProcess(), &is64Bit);
    }

    return is64Bit;
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