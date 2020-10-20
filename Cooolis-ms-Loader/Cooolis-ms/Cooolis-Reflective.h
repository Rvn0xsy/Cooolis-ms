#pragma once
//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#ifndef _REFLECTIVEDLLINJECTION_REFLECTIVEDLLINJECTION_H
#define _REFLECTIVEDLLINJECTION_REFLECTIVEDLLINJECTION_H
//===============================================================================================//
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include "Kernel32-Import.h"

extern ImportCreateThread CooolisCreateThread;
extern ImportVirtualProtect CooolisVirtualProtect;
extern ImportVirtualProtectEx CooolisVirtualProtectEx;
extern ImportVirtualAlloc CooolisVirtualAlloc;
extern ImportVirtualAllocEx CooolisVirtualAllocEx;
extern ImportCreateRemoteThread CooolisCreateRemoteThread;
extern ImportAdjustTokenPrivileges CooolisAdjustTokenPrivileges;
// we declare some common stuff in here...


#define DLL_METASPLOIT_ATTACH	4
#define DLL_METASPLOIT_DETACH	5
#define DLL_QUERY_HMODULE		6
#define REFLECTIVED_EXPORT_NAME "ReflectiveLoader"
#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef ULONG_PTR(WINAPI* REFLECTIVELOADER)(VOID);
typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);

#define DLLEXPORT   __declspec( dllexport ) 


class CCooolisReflective
{
public:
	CCooolisReflective();
	~CCooolisReflective();
	BOOL ReflectiveInject(DWORD dwProcessId, std::string sReflectiveDllName);
	BOOL ReflectiveInject(DWORD dwProcessId, LPVOID lpBuffer, DWORD dwLength);
private:
	DWORD dwProcessId = NULL; // 进程ID

	DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer); // 获取反射DLL入口
	DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress);
	HMODULE WINAPI LoadLibraryR(LPVOID lpBuffer, DWORD dwLength); // 加载本地反射DLL
	FARPROC WINAPI GetProcAddressR(HANDLE hModule, LPCSTR lpProcName);
	HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter); // 远程注入反射DLL
};





//===============================================================================================//
#endif
//===============================================================================================//
