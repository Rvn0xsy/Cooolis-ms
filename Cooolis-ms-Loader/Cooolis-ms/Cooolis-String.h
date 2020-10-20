#pragma once
#ifndef COOOLIS_STRING
#define COOOLIS_STRING


#include <iostream>
#include <Windows.h>
#include <wincrypt.h>

class CooolisString
{
public:
    CooolisString(std::string szBase64String);
    ~CooolisString();
    DWORD length();
    operator std::string();
private:
    std::string szOutStr;
    DWORD dwStringSize = 0;
    std::string Base64decode(std::string szBase64String, LPDWORD lpdwLen);
};


#endif // !COOOLIS_STRING
