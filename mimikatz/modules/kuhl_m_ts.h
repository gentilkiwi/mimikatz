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

BOOL CALLBACK kuhl_m_ts_logonpasswords_MemoryAnalysis(PMEMORY_BASIC_INFORMATION pMemoryBasicInformation, PVOID pvArg);
void kuhl_m_ts_logonpasswords_MemoryAnalysis_candidate(PKULL_M_MEMORY_HANDLE hProcess, PVOID Addr);

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

typedef struct _STRUCT_DATASEARCH {
	PKULL_M_MEMORY_HANDLE hMemory;
	KULL_M_MEMORY_ADDRESS aPattern;
} STRUCT_DATASEARCH, *PSTRUCT_DATASEARCH;

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

/*
typedef struct _STRUCT_MYSEARCH {
	LPCSTR pCRDPWDUMXStack; // "CRDPWDUMXStack"
	DWORD unk0; // 0xdbcaabcd
	DWORD unk1; // 0x00000001
} STRUCT_MYSEARCH, *PSTRUCT_MYSEARCH;

typedef struct _UNK_STRUCT0 { // 0x2f8
	PVOID unkp0; // &CTSAsyncResultImpl::`vftable'{for `INonDelegatingUnknown'};
	PVOID unkp1; // &CTSUnknownCrossModule::`vftable'{for `CTSObject'};
	LPCSTR pCRDPWDUMXStack; // "CRDPWDUMXStack"
	DWORD unk0; // 0xdbcaabcd
	DWORD unk1; // 0x00000001
	PVOID unkThis0; // this
	DWORD unk2; // 0, 2 ?
	PVOID unkp2; // &CTSUnknownCrossModule::`vftable'
	PVOID ImageBase; //
	PVOID unkp3; // &CRDPWDUMXStack::`vftable'{for `IRDPWDUMX_StackEx'};
	PVOID unkp4; // &CRDPWDUMXStack::`vftable'{for `IRDPENCNetStreamEvents'};
	PVOID unkp5; // &CRDPWDUMXStack::`vftable'{for `IRDPNetworkDetectTransport'};
	DWORD unk3; // 1 ?
	DWORD unk4; // ?
	DWORD unk5; // 1 ?
	DWORD unk6; // 59 ? 
	DWORD unk7; //
	// align
	PVOID unkp6; //
	PVOID unkp7; //
	PVOID unkp8;
	PVOID unkp9;
	PVOID unkp10; /// :)
	PVOID unkp11;
	PVOID unkp12;
} UNK_STRUCT0, *PUNK_STRUCT0;
*/