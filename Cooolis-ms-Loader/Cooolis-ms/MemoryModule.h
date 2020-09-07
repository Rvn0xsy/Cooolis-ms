#pragma once


#ifndef __MEMORY_MODULE_HEADER
#define __MEMORY_MODULE_HEADER

#include <Windows.h>

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