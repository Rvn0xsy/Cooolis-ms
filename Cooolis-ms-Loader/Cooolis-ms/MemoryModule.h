#pragma once


#ifndef __MEMORY_MODULE_HEADER
#define __MEMORY_MODULE_HEADER

#include <Windows.h>

#include "Kernel32-Import.h"

extern ImportCreateThread CooolisCreateThread;
extern ImportVirtualProtect CooolisVirtualProtect;
extern ImportVirtualProtectEx CooolisVirtualProtectEx;
extern ImportVirtualAlloc CooolisVirtualAlloc;
typedef void* HMEMORYMODULE;


#ifdef __cplusplus
extern "C" {
#endif

	HMEMORYMODULE MemoryLoadLibrary(const void*);

	FARPROC MemoryGetProcAddress(HMEMORYMODULE, const char*);

	void MemoryFreeLibrary(HMEMORYMODULE);

#ifdef __cplusplus
}
#endif

#endif  // __MEMORY_MODULE_HEADER