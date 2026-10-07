#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

void LogBufferToFile(const char* opType, void* buffer, unsigned int length);
void LogToFile(const char* format, ...);
void LogToFileW(const wchar_t* format, ...);