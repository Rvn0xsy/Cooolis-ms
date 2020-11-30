#include "Kernel32-Import.h"
#include "Cooolis-String.h"

ImportCreateThread CooolisCreateThread = (ImportCreateThread)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreateThread");
ImportVirtualProtect CooolisVirtualProtect = (ImportVirtualProtect)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualProtect");
ImportVirtualProtectEx CooolisVirtualProtectEx = (ImportVirtualProtectEx)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualProtectEx");
ImportVirtualAlloc CooolisVirtualAlloc = (ImportVirtualAlloc)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualAlloc");
ImportVirtualAllocEx CooolisVirtualAllocEx = (ImportVirtualAllocEx)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualAllocEx");
ImportCreateRemoteThread CooolisCreateRemoteThread = (ImportCreateRemoteThread)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreateRemoteThread");
ImportAdjustTokenPrivileges CooolisAdjustTokenPrivileges = (ImportAdjustTokenPrivileges)GetProcAddress(GetModuleHandleW(L"Advapi32.dll"), "AdjustTokenPrivileges");
ImportHeapCreate CooolisHeapCreate = (ImportHeapCreate)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "HeapCreate");
ImportHeapAlloc CooolisHeapAlloc = (ImportHeapAlloc)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "HeapAlloc");