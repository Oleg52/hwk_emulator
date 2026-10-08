#include <windows.h>
#include "winmm_hook.h"

struct winmm_dll {
	HMODULE dll;
	FARPROC waveInOpen;
} winmm;

extern "C" {
	__declspec(naked) void fwaveInOpen() { __asm { jmp winmm.waveInOpen } }
}

void SetupWinmmFunctions() {
	char path[MAX_PATH];
	GetWindowsDirectoryA(path, sizeof(path));

	strcat(path, "\\System32\\winmm.dll");
	winmm.dll = LoadLibraryA(path);

	winmm.waveInOpen = GetProcAddress(winmm.dll, "waveInOpen");
}