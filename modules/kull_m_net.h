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

#define NERR_Success 0 

NET_API_STATUS NET_API_FUNCTION NetSessionEnum(IN LMSTR servername, IN LMSTR UncClientName, IN LMSTR username, IN DWORD level, OUT LPBYTE *bufptr, IN DWORD prefmaxlen, OUT LPDWORD entriesread, OUT LPDWORD totalentries, IN OUT LPDWORD resume_handle);
NET_API_STATUS NET_API_FUNCTION NetWkstaUserEnum(IN LMSTR servername, IN DWORD level, OUT LPBYTE *bufptr, IN DWORD prefmaxlen, OUT LPDWORD entriesread, OUT LPDWORD totalentries, IN OUT LPDWORD resumehandle);

typedef struct _TIME_OF_DAY_INFO {
  DWORD tod_elapsedt;
  DWORD tod_msecs;
  DWORD tod_hours;
  DWORD tod_mins;
  DWORD tod_secs;
  DWORD tod_hunds;
  LONG  tod_timezone;
  DWORD tod_tinterval;
  DWORD tod_day;
  DWORD tod_month;
  DWORD tod_year;
  DWORD tod_weekday;
} TIME_OF_DAY_INFO, *PTIME_OF_DAY_INFO, *LPTIME_OF_DAY_INFO;

NET_API_STATUS NET_API_FUNCTION NetRemoteTOD(IN LPCWSTR UncServerName, OUT PTIME_OF_DAY_INFO *pToD);

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

#define SERVICE_WORKSTATION       TEXT("LanmanWorkstation")
#define SERVICE_SERVER            TEXT("LanmanServer")

NET_API_STATUS NET_API_FUNCTION NetStatisticsGet(IN LPWSTR server, IN LPWSTR service, IN DWORD  level, IN DWORD  options, OUT LPBYTE *bufptr);

typedef struct _STAT_WORKSTATION_0 {
  LARGE_INTEGER StatisticsStartTime;
  LARGE_INTEGER BytesReceived;
  LARGE_INTEGER SmbsReceived;
  LARGE_INTEGER PagingReadBytesRequested;
  LARGE_INTEGER NonPagingReadBytesRequested;
  LARGE_INTEGER CacheReadBytesRequested;
  LARGE_INTEGER NetworkReadBytesRequested;
  LARGE_INTEGER BytesTransmitted;
  LARGE_INTEGER SmbsTransmitted;
  LARGE_INTEGER PagingWriteBytesRequested;
  LARGE_INTEGER NonPagingWriteBytesRequested;
  LARGE_INTEGER CacheWriteBytesRequested;
  LARGE_INTEGER NetworkWriteBytesRequested;
  DWORD         InitiallyFailedOperations;
  DWORD         FailedCompletionOperations;
  DWORD         ReadOperations;
  DWORD         RandomReadOperations;
  DWORD         ReadSmbs;
  DWORD         LargeReadSmbs;
  DWORD         SmallReadSmbs;
  DWORD         WriteOperations;
  DWORD         RandomWriteOperations;
  DWORD         WriteSmbs;
  DWORD         LargeWriteSmbs;
  DWORD         SmallWriteSmbs;
  DWORD         RawReadsDenied;
  DWORD         RawWritesDenied;
  DWORD         NetworkErrors;
  DWORD         Sessions;
  DWORD         FailedSessions;
  DWORD         Reconnects;
  DWORD         CoreConnects;
  DWORD         Lanman20Connects;
  DWORD         Lanman21Connects;
  DWORD         LanmanNtConnects;
  DWORD         ServerDisconnects;
  DWORD         HungSessions;
  DWORD         UseCount;
  DWORD         FailedUseCount;
  DWORD         CurrentCommands;
} STAT_WORKSTATION_0, *PSTAT_WORKSTATION_0, *LPSTAT_WORKSTATION_0;

typedef struct _STAT_SERVER_0 {
  DWORD sts0_start;
  DWORD sts0_fopens;
  DWORD sts0_devopens;
  DWORD sts0_jobsqueued;
  DWORD sts0_sopens;
  DWORD sts0_stimedout;
  DWORD sts0_serrorout;
  DWORD sts0_pwerrors;
  DWORD sts0_permerrors;
  DWORD sts0_syserrors;
  DWORD sts0_bytessent_low;
  DWORD sts0_bytessent_high;
  DWORD sts0_bytesrcvd_low;
  DWORD sts0_bytesrcvd_high;
  DWORD sts0_avresponse;
  DWORD sts0_reqbufneed;
  DWORD sts0_bigbufneed;
} STAT_SERVER_0, *PSTAT_SERVER_0, *LPSTAT_SERVER_0;