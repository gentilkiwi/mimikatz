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
BOOL kull_m_net_getComputerName(BOOL isFull, LPWSTR *name);

#define NET_API_STATUS          DWORD
#define NET_API_FUNCTION    __stdcall
#define LMSTR   LPWSTR
#define MAX_PREFERRED_LENGTH    ((DWORD) -1)

#define NERR_Success 0 

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

#define STYPE_DISKTREE          0
#define STYPE_PRINTQ            1
#define STYPE_DEVICE            2
#define STYPE_IPC               3

#define STYPE_MASK              0x000000FF              // AND with shi_type to

#define STYPE_RESERVED1         0x01000000              // Reserved for internal processing
#define STYPE_RESERVED2         0x02000000            
#define STYPE_RESERVED3         0x04000000
#define STYPE_RESERVED4         0x08000000
#define STYPE_RESERVED_ALL      0x3FFFFF00

#define STYPE_TEMPORARY         0x40000000
#define STYPE_SPECIAL           0x80000000

typedef struct _SHARE_INFO_502 {
	LMSTR     shi502_netname;
	DWORD     shi502_type;
	LMSTR     shi502_remark;
	DWORD     shi502_permissions;
	DWORD     shi502_max_uses;
	DWORD     shi502_current_uses;
	LMSTR     shi502_path;
	LMSTR     shi502_passwd;
	DWORD     shi502_reserved;
	PSECURITY_DESCRIPTOR  shi502_security_descriptor;
} SHARE_INFO_502, *PSHARE_INFO_502, *LPSHARE_INFO_502;

typedef struct _SERVER_INFO_102 {
	DWORD          sv102_platform_id;
	LMSTR          sv102_name;
	DWORD          sv102_version_major;
	DWORD          sv102_version_minor;
	DWORD          sv102_type;
	LMSTR          sv102_comment;
	DWORD          sv102_users;
	LONG           sv102_disc;
	BOOL           sv102_hidden;
	DWORD          sv102_announce;
	DWORD          sv102_anndelta;
	DWORD          sv102_licenses;
	LMSTR          sv102_userpath;
} SERVER_INFO_102, *PSERVER_INFO_102, *LPSERVER_INFO_102;

typedef struct _SHARE_INFO_2 {
	LMSTR shi2_netname;
	DWORD shi2_type;
	LMSTR shi2_remark;
	DWORD shi2_permissions;
	DWORD shi2_max_uses;
	DWORD shi2_current_uses;
	LMSTR shi2_path;
	LMSTR shi2_passwd;
} SHARE_INFO_2, *PSHARE_INFO_2, *LPSHARE_INFO_2;

#define SV_TYPE_WORKSTATION         0x00000001
#define SV_TYPE_SERVER              0x00000002
#define SV_TYPE_SQLSERVER           0x00000004
#define SV_TYPE_DOMAIN_CTRL         0x00000008
#define SV_TYPE_DOMAIN_BAKCTRL      0x00000010
#define SV_TYPE_TIME_SOURCE         0x00000020
#define SV_TYPE_AFP                 0x00000040
#define SV_TYPE_NOVELL              0x00000080
#define SV_TYPE_DOMAIN_MEMBER       0x00000100
#define SV_TYPE_PRINTQ_SERVER       0x00000200
#define SV_TYPE_DIALIN_SERVER       0x00000400
#define SV_TYPE_XENIX_SERVER        0x00000800
#define SV_TYPE_SERVER_UNIX         SV_TYPE_XENIX_SERVER
#define SV_TYPE_NT                  0x00001000
#define SV_TYPE_WFW                 0x00002000
#define SV_TYPE_SERVER_MFPN         0x00004000
#define SV_TYPE_SERVER_NT           0x00008000
#define SV_TYPE_POTENTIAL_BROWSER   0x00010000
#define SV_TYPE_BACKUP_BROWSER      0x00020000
#define SV_TYPE_MASTER_BROWSER      0x00040000
#define SV_TYPE_DOMAIN_MASTER       0x00080000
#define SV_TYPE_SERVER_OSF          0x00100000
#define SV_TYPE_SERVER_VMS          0x00200000
#define SV_TYPE_WINDOWS             0x00400000  /* Windows95 and above */
#define SV_TYPE_DFS                 0x00800000  /* Root of a DFS tree */
#define SV_TYPE_CLUSTER_NT          0x01000000  /* NT Cluster */
#define SV_TYPE_TERMINALSERVER      0x02000000  /* Terminal Server(Hydra) */
#define SV_TYPE_CLUSTER_VS_NT       0x04000000  /* NT Cluster Virtual Server Name */
#define SV_TYPE_DCE                 0x10000000  /* IBM DSS (Directory and Security Services) or equivalent */
#define SV_TYPE_ALTERNATE_XPORT     0x20000000  /* return list for alternate transport */
#define SV_TYPE_LOCAL_LIST_ONLY     0x40000000  /* Return local list only */
#define SV_TYPE_DOMAIN_ENUM         0x80000000
#define SV_TYPE_ALL                 0xFFFFFFFF  /* handy for NetServerEnum2 */

NET_API_STATUS NET_API_FUNCTION NetSessionEnum(IN LMSTR servername, IN LMSTR UncClientName, IN LMSTR username, IN DWORD level, OUT LPBYTE *bufptr, IN DWORD prefmaxlen, OUT LPDWORD entriesread, OUT LPDWORD totalentries, IN OUT LPDWORD resume_handle);
NET_API_STATUS NET_API_FUNCTION NetWkstaUserEnum(IN LMSTR servername, IN DWORD level, OUT LPBYTE *bufptr, IN DWORD prefmaxlen, OUT LPDWORD entriesread, OUT LPDWORD totalentries, IN OUT LPDWORD resumehandle);
NET_API_STATUS NET_API_FUNCTION NetShareEnum(IN LMSTR servername, IN DWORD level, OUT LPBYTE *bufptr, IN DWORD prefmaxlen, OUT LPDWORD entriesread, OUT LPDWORD totalentries, IN OUT LPDWORD resume_handle);
NET_API_STATUS NET_API_FUNCTION NetStatisticsGet(IN LPWSTR server, IN LPWSTR service, IN DWORD  level, IN DWORD  options, OUT LPBYTE *bufptr);
NET_API_STATUS NET_API_FUNCTION NetRemoteTOD(IN LPCWSTR UncServerName, OUT PTIME_OF_DAY_INFO *pToD);
NET_API_STATUS NET_API_FUNCTION NetServerGetInfo(IN LPWSTR servername, IN DWORD level, OUT LPBYTE *bufptr);
NET_API_STATUS NET_API_FUNCTION NetShareAdd(IN LMSTR servername, IN DWORD level, IN LPBYTE buf, OUT LPDWORD parm_err);