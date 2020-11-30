#pragma once
#ifndef KERNEL32_IMPORT
#define KERNEL32_IMPORT
#include <Windows.h>


typedef HANDLE(WINAPI* ImportCreateThread)(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId);


typedef BOOL(WINAPI* ImportVirtualProtect)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
	);

typedef BOOL(WINAPI* ImportVirtualProtectEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
	);

typedef LPVOID(WINAPI* ImportVirtualAlloc)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);

typedef LPVOID (WINAPI* ImportVirtualAllocEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);

typedef HANDLE (WINAPI* ImportCreateRemoteThread)(
	__in HANDLE hProcess,
	__in LPSECURITY_ATTRIBUTES lpThreadAttributes,
	__in SIZE_T dwStackSize,
	__in LPTHREAD_START_ROUTINE lpStartAddress,
	__in LPVOID lpParameter,
	__in DWORD dwCreationFlags,
	__out LPDWORD lpThreadId
);

typedef BOOL (WINAPI * ImportAdjustTokenPrivileges)(
	HANDLE            TokenHandle,
	BOOL              DisableAllPrivileges,
	PTOKEN_PRIVILEGES NewState,
	DWORD             BufferLength,
	PTOKEN_PRIVILEGES PreviousState,
	PDWORD            ReturnLength
);

typedef HANDLE (WINAPI * ImportHeapCreate)(
	 DWORD flOptions,
	 SIZE_T dwInitialSize,
	 SIZE_T dwMaximumSize
);

typedef LPVOID (WINAPI * ImportHeapAlloc)(
	HANDLE hHeap,
	DWORD  dwFlags,
	SIZE_T dwBytes
);

extern ImportCreateThread CooolisCreateThread;
extern ImportVirtualProtect CooolisVirtualProtect;
extern ImportVirtualProtectEx CooolisVirtualProtectEx;
extern ImportVirtualAlloc CooolisVirtualAlloc;
extern ImportVirtualAllocEx CooolisVirtualAllocEx;
extern ImportCreateRemoteThread CooolisCreateRemoteThread;
extern ImportAdjustTokenPrivileges CooolisAdjustTokenPrivileges;


#endif // !KERNEL32_IMPORT

