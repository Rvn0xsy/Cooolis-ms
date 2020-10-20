#include "Cooolis-String.h"

CooolisString::CooolisString(std::string szBase64String)
{
    this->dwStringSize = szBase64String.length();
    szOutStr = this->Base64decode(szBase64String, &dwStringSize);
}



CooolisString::~CooolisString()
{

}

DWORD CooolisString::length()
{
    return this->dwStringSize;
}

CooolisString::operator std::string()
{
    return this->szOutStr;
}



std::string CooolisString::Base64decode(std::string szBase64String, LPDWORD lpdwLen)
{
    DWORD dwLen;
    DWORD dwNeed;
    PBYTE lpBuffer;
    dwLen = szBase64String.length();
    dwNeed = 0;
    CryptStringToBinaryA(szBase64String.c_str(), 0, CRYPT_STRING_BASE64, NULL, &dwNeed, NULL, NULL);
    if (dwNeed)
    {
        lpBuffer = new BYTE[dwNeed + 1];
        ZeroMemory(lpBuffer, dwNeed + 1);
        CryptStringToBinaryA(szBase64String.c_str(), 0, CRYPT_STRING_BASE64, lpBuffer, &dwNeed, NULL, NULL);
        *lpdwLen = dwNeed;
    }
    return std::string((PCHAR)lpBuffer);
}
