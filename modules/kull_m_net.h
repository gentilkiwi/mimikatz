/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <DsGetDC.h>

extern DWORD WINAPI NetApiBufferFree (IN LPVOID Buffer);

BOOL kull_m_net_getCurrentDomainInfo(PPOLICY_DNS_DOMAIN_INFO * pDomainInfo);
BOOL kull_m_net_CreateWellKnownSid(WELL_KNOWN_SID_TYPE WellKnownSidType, PSID DomainSid, PSID * pSid);
BOOL kull_m_net_getDC(LPCWSTR fullDomainName, DWORD altFlags, LPWSTR * fullDCName);

#define NET_API_STATUS          DWORD
#define NET_API_FUNCTION    __stdcall
#define LMSTR   LPWSTR
#define MAX_PREFERRED_LENGTH    ((DWORD) -1)

NET_API_STATUS NET_API_FUNCTION NetSessionEnum(IN LMSTR servername, IN LMSTR UncClientName, IN LMSTR username, IN DWORD level, OUT LPBYTE *bufptr, IN DWORD prefmaxlen, OUT LPDWORD entriesread, OUT LPDWORD totalentries, IN OUT LPDWORD resume_handle);
NET_API_STATUS NET_API_FUNCTION NetWkstaUserEnum(IN LMSTR servername, IN DWORD level, OUT LPBYTE *bufptr, IN DWORD prefmaxlen, OUT LPDWORD entriesread, OUT LPDWORD totalentries, IN OUT LPDWORD resumehandle);

typedef struct _SESSION_INFO_10 {
	LMSTR sesi10_cname;
	LMSTR sesi10_username;
	DWORD sesi10_time;
	DWORD sesi10_idle_time;
} SESSION_INFO_10, *PSESSION_INFO_10, *LPSESSION_INFO_10;

typedef struct _WKSTA_USER_INFO_1 {
	LMSTR wkui1_username;
	LMSTR wkui1_logon_domain;
	LMSTR wkui1_oth_domains;
	LMSTR wkui1_logon_server;
}WKSTA_USER_INFO_1, *PWKSTA_USER_INFO_1, *LPWKSTA_USER_INFO_1;