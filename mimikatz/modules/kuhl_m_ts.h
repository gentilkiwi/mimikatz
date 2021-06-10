/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../../modules/kull_m_patch.h"
#include "../../modules/kull_m_service.h"
#include "../../modules/kull_m_process.h"
#include "../../modules/kull_m_memory.h"
#include "../../modules/kull_m_crypto_remote.h"

const KUHL_M kuhl_m_ts;

NTSTATUS kuhl_m_ts_multirdp(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_ts_sessions(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_ts_remote(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_ts_logonpasswords(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_ts_mstsc(int argc, wchar_t * argv[]);

typedef struct _KUHL_M_TS_MSTSC_ARG {
	PKULL_M_MEMORY_HANDLE hMemory;
	BOOL bIsVerbose;
} KUHL_M_TS_MSTSC_ARG, *PKUHL_M_TS_MSTSC_ARG;

BOOL CALLBACK kuhl_m_ts_logonpasswords_MemoryAnalysis(PMEMORY_BASIC_INFORMATION pMemoryBasicInformation, PVOID pvArg);
void kuhl_m_ts_logonpasswords_MemoryAnalysis_candidate(PKULL_M_MEMORY_HANDLE hProcess, PVOID Addr);

BOOL CALLBACK kuhl_m_ts_mstsc_enumProcess(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
BOOL CALLBACK kuhl_m_ts_mstsc_MemoryAnalysis(PMEMORY_BASIC_INFORMATION pMemoryBasicInformation, PVOID pvArg);
void kuhl_m_ts_mstsc_MemoryAnalysis_property(PKULL_M_MEMORY_HANDLE hMemory, PVOID pvProperties, DWORD cbProperties, BOOL bIsVerbose);

#define LOGONID_CURRENT			((ULONG) -1)
#define SERVERHANDLE_CURRENT	((HANDLE) NULL)
#define MAX_THINWIRECACHE		4
#define WINSTATIONNAME_LENGTH	32
#define DOMAIN_LENGTH			17
#define USERNAME_LENGTH			20
typedef WCHAR WINSTATIONNAME[WINSTATIONNAME_LENGTH + 1];

typedef enum _WINSTATIONSTATECLASS {
	State_Active = 0,
	State_Connected = 1,
	State_ConnectQuery = 2,
	State_Shadow = 3,
	State_Disconnected = 4,
	State_Idle = 5,
	State_Listen = 6,
	State_Reset = 7,
	State_Down = 8,
	State_Init = 9
} WINSTATIONSTATECLASS;

typedef enum _WINSTATIONINFOCLASS {
	WinStationCreateData,
	WinStationConfiguration,
	WinStationPdParams,
	WinStationWd,
	WinStationPd,
	WinStationPrinter,
	WinStationClient,
	WinStationModules,
	WinStationInformation,
	WinStationTrace,
	WinStationBeep,
	WinStationEncryptionOff,
	WinStationEncryptionPerm,
	WinStationNtSecurity,
	WinStationUserToken,
	WinStationUnused1,
	WinStationVideoData,
	WinStationInitialProgram,
	WinStationCd,
	WinStationSystemTrace,
	WinStationVirtualData,
	WinStationClientData,
	WinStationSecureDesktopEnter,
	WinStationSecureDesktopExit,
	WinStationLoadBalanceSessionTarget,
	WinStationLoadIndicator,
	WinStationShadowInfo,
	WinStationDigProductId,
	WinStationLockedState,
	WinStationRemoteAddress,
	WinStationIdleTime,
	WinStationLastReconnectType,
	WinStationDisallowAutoReconnect,
	WinStationUnused2,
	WinStationUnused3,
	WinStationUnused4,
	WinStationUnused5,
	WinStationReconnectedFromId,
	WinStationEffectsPolicy,
	WinStationType,
	WinStationInformationEx
} WINSTATIONINFOCLASS;

typedef struct _SESSIONIDW {
	union {
		ULONG SessionId;
		ULONG LogonId;
	};
	WINSTATIONNAME WinStationName;
	WINSTATIONSTATECLASS State;
} SESSIONIDW, *PSESSIONIDW;

typedef struct _TSHARE_COUNTERS {
	ULONG Reserved;
} TSHARE_COUNTERS, *PTSHARE_COUNTERS;

typedef struct _PROTOCOLCOUNTERS {
	ULONG WdBytes;
	ULONG WdFrames;
	ULONG WaitForOutBuf;
	ULONG Frames;
	ULONG Bytes;
	ULONG CompressedBytes;
	ULONG CompressFlushes;
	ULONG Errors;
	ULONG Timeouts;
	ULONG AsyncFramingError;
	ULONG AsyncOverrunError;
	ULONG AsyncOverflowError;
	ULONG AsyncParityError;
	ULONG TdErrors;
	USHORT ProtocolType;
	USHORT Length;
	union {
		TSHARE_COUNTERS TShareCounters;
		ULONG Reserved[100];
	} Specific;
} PROTOCOLCOUNTERS, *PPROTOCOLCOUNTERS;

typedef struct _THINWIRECACHE {
	ULONG CacheReads;
	ULONG CacheHits;
} THINWIRECACHE, *PTHINWIRECACHE;

typedef struct _RESERVED_CACHE {
	THINWIRECACHE ThinWireCache[MAX_THINWIRECACHE];
} RESERVED_CACHE, *PRESERVED_CACHE;

typedef struct _TSHARE_CACHE {
	ULONG Reserved;
} TSHARE_CACHE, * PTSHARE_CACHE;

typedef struct CACHE_STATISTICS {
	USHORT ProtocolType;
	USHORT Length;
	union {
		RESERVED_CACHE ReservedCacheStats;
		TSHARE_CACHE TShareCacheStats;
		ULONG Reserved[20];
	} Specific;
} CACHE_STATISTICS, *PCACHE_STATISTICS;

typedef struct _PROTOCOLSTATUS {
	PROTOCOLCOUNTERS Output;
	PROTOCOLCOUNTERS Input;
	CACHE_STATISTICS Cache;
	ULONG AsyncSignal;
	ULONG AsyncSignalMask;
} PROTOCOLSTATUS, * PPROTOCOLSTATUS;

typedef struct _WINSTATIONINFORMATION {
	WINSTATIONSTATECLASS ConnectState;
	WINSTATIONNAME WinStationName;
	ULONG LogonId;
	LARGE_INTEGER ConnectTime;
	LARGE_INTEGER DisconnectTime;
	LARGE_INTEGER LastInputTime;
	LARGE_INTEGER LogonTime;
	PROTOCOLSTATUS Status;
	WCHAR Domain[DOMAIN_LENGTH + 1];
	WCHAR UserName[USERNAME_LENGTH + 1];
	LARGE_INTEGER CurrentTime;
} WINSTATIONINFORMATION, *PWINSTATIONINFORMATION;

typedef struct _WINSTATIONVIDEODATA {
	USHORT HResolution;
	USHORT VResolution;
	USHORT fColorDepth;
} WINSTATIONVIDEODATA, *PWINSTATIONVIDEODATA;

typedef struct _WINSTATIONREMOTEADDRESS {
	unsigned short sin_family;
	union {
		struct {
			USHORT sin_port;
			ULONG in_addr;
			UCHAR sin_zero[8];
		} ipv4;
		struct {
			USHORT sin6_port;
			ULONG sin6_flowinfo;
			USHORT sin6_addr[8];
			ULONG sin6_scope_id;
		} ipv6;
	};
} WINSTATIONREMOTEADDRESS, *PWINSTATIONREMOTEADDRESS;

extern HANDLE WINAPI WinStationOpenServerW(IN PWSTR ServerName);
extern BOOLEAN WINAPI WinStationCloseServer(IN HANDLE hServer);
extern BOOLEAN WINAPI WinStationConnectW(IN HANDLE hServer, IN DWORD SessionId, IN DWORD TargetSessionID, IN LPWSTR Password, IN BOOLEAN bWait);
extern BOOLEAN WINAPI WinStationFreeMemory(IN PVOID Buffer);
extern BOOLEAN WINAPI WinStationEnumerateW(IN HANDLE hServer, OUT PSESSIONIDW *SessionIds, OUT PULONG Count);
extern BOOLEAN WINAPI WinStationQueryInformationW(IN HANDLE hServer, IN ULONG SessionId,IN WINSTATIONINFOCLASS WinStationInformationClass, OUT PVOID pWinStationInformation, IN ULONG WinStationInformationLength, OUT PULONG pReturnLength);
extern BOOLEAN WINAPI WinStationSetInformationW(IN HANDLE hServer, IN ULONG SessionId, IN WINSTATIONINFOCLASS WinStationInformationClass, IN PVOID pWinStationInformation, IN ULONG WinStationInformationLength);

extern LPWSTR NTAPI RtlIpv4AddressToStringW(IN const IN_ADDR *Addr, OUT LPWSTR S);
extern LPWSTR NTAPI RtlIpv6AddressToStringW(IN const PVOID /*IN6_ADDR **/Addr, OUT LPWSTR S);

#define WTS_DOMAIN_LENGTH            255
#define WTS_USERNAME_LENGTH          255
#define WTS_PASSWORD_LENGTH          255
#pragma pack(push, 2)
typedef struct _WTS_KIWI {
	DWORD unk0;
	DWORD unk1;
	WORD cbDomain;
	WORD cbUsername;
	WORD cbPassword;
	DWORD unk2;
	WCHAR Domain[WTS_DOMAIN_LENGTH + 1];
	WCHAR UserName[WTS_USERNAME_LENGTH + 1];
	WCHAR Password[WTS_PASSWORD_LENGTH + 1];
} WTS_KIWI, *PWTS_KIWI;
#pragma pack(pop)

typedef struct _TS_PROPERTY_KIWI {
	PCWSTR szProperty;
	DWORD dwType;
	PVOID pvData;
	PVOID unkp0;
	DWORD unkd0;
	DWORD dwFlags;
	DWORD unkd1;
	DWORD unkd2;
	PVOID pValidator;
	PVOID unkp2; // password size or ?, maybe a DWORD then align
	PVOID unkp3;
} TS_PROPERTY_KIWI, *PTS_PROPERTY_KIWI;

typedef struct _TS_PROPERTIES_KIWI {
	PVOID unkp0; // const CTSPropertySet::`vftable'{for `CTSObject'}
	PVOID unkp1; // "CTSPropertySet"
	DWORD unkh0; // 0xdbcaabcd
	DWORD unkd0; // 3
	PVOID unkp2;
	DWORD unkd1; // 45
	PVOID unkp3; // tagPROPERTY_ENTRY near * `CTSCoreApi::internalGetPropMap_CoreProps(void)'::`2'::_PropSet
	PTS_PROPERTY_KIWI pProperties;
	DWORD cbProperties; // 198
} TS_PROPERTIES_KIWI, *PTS_PROPERTIES_KIWI;