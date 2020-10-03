#pragma once
#include <Windows.h>
#include <Winhttp.h>
#include <iostream>
#include <vector>

#define LIB_HTTP_USER_AGENT L"Mozilla/5.02 (Linux; Android 4.1.1; Nexus 7 Build/JRO03D) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Safari"


class CCooolisHttp {
public:
	CCooolisHttp();
	virtual BOOL ConnectServer(LPCWSTR pswzServerName, INTERNET_PORT nServerPort);
	virtual BOOL HttpAddHeaders(LPCWSTR szHeader); // 添加HTTP头
	virtual BOOL HttpAddHeaders(std::vector<std::wstring> szHeaders); // 添加多个HTTP头
	// 发送GET请求
	virtual DWORD HttpGet(
		LPCWSTR pszServerURI,
		std::vector<BYTE>& wszResponse
	);
	// 发送POST请求
	virtual DWORD HttpPost(
		LPCWSTR pszServerURI,
		LPVOID pszSendData,
		DWORD dwSendDataLen,
		std::vector<BYTE>& wszResponse
	);
	// 从Http Server读取文件到内存
	virtual LPVOID ReadHttpFile(LPCWSTR pszServerURI, DWORD & dwResponseLength);

private:
	HINTERNET   hSession = NULL;
	HINTERNET	hConnect = NULL;
	HINTERNET	hRequest = NULL;
	std::vector<std::wstring> szHeaders; // 请求头
	VOID SetHeaders(); // 设置请求头
	DWORD GetResponseContentLength(); // 获取响应内容长度
	BOOL SendRequest(); // 发送请求
	BOOL SendRequest(LPVOID pswzSendData, DWORD dwSendDataLen); // 发送带参数的请求

};