/*	Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com / http://blog.gentilkiwi.com )
	Vincent LE TOUX ( vincent.letoux@gmail.com / http://www.mysmartlogon.com )
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "../kull_m_crypto_system.h"
#include "../kull_m_crypto.h"
#include "../kull_m_string.h"
#include "../kull_m_asn1.h"
#include "../kull_m_token.h"
#include "kull_m_rpc_ms-drsr.h"

typedef struct _DRS_EXTENSIONS_INT {
	DWORD cb;
	DWORD dwFlags;
	GUID SiteObjGuid;
	DWORD Pid;
	DWORD dwReplEpoch;
	DWORD dwFlagsExt;
	GUID ConfigObjGUID;
	DWORD dwExtCaps;
} DRS_EXTENSIONS_INT, *PDRS_EXTENSIONS_INT;

typedef struct _ENCRYPTED_PAYLOAD {
	UCHAR Salt[16];
	ULONG CheckSum;
	UCHAR EncryptedData[ANYSIZE_ARRAY];
} ENCRYPTED_PAYLOAD, *PENCRYPTED_PAYLOAD;

#define DRS_EXT_BASE								0x00000001
#define DRS_EXT_ASYNCREPL							0x00000002
#define DRS_EXT_REMOVEAPI							0x00000004
#define DRS_EXT_MOVEREQ_V2							0x00000008
#define DRS_EXT_GETCHG_DEFLATE						0x00000010
#define DRS_EXT_DCINFO_V1							0x00000020
#define DRS_EXT_RESTORE_USN_OPTIMIZATION			0x00000040
#define DRS_EXT_ADDENTRY							0x00000080
#define DRS_EXT_KCC_EXECUTE							0x00000100
#define DRS_EXT_ADDENTRY_V2							0x00000200
#define DRS_EXT_LINKED_VALUE_REPLICATION			0x00000400
#define DRS_EXT_DCINFO_V2							0x00000800
#define DRS_EXT_INSTANCE_TYPE_NOT_REQ_ON_MOD		0x00001000
#define DRS_EXT_CRYPTO_BIND							0x00002000
#define DRS_EXT_GET_REPL_INFO						0x00004000
#define DRS_EXT_STRONG_ENCRYPTION					0x00008000
#define DRS_EXT_DCINFO_VFFFFFFFF					0x00010000
#define DRS_EXT_TRANSITIVE_MEMBERSHIP				0x00020000
#define DRS_EXT_ADD_SID_HISTORY						0x00040000
#define DRS_EXT_POST_BETA3							0x00080000
#define DRS_EXT_GETCHGREQ_V5						0x00100000
#define DRS_EXT_GETMEMBERSHIPS2						0x00200000
#define DRS_EXT_GETCHGREQ_V6						0x00400000
#define DRS_EXT_NONDOMAIN_NCS						0x00800000
#define DRS_EXT_GETCHGREQ_V8						0x01000000
#define DRS_EXT_GETCHGREPLY_V5						0x02000000
#define DRS_EXT_GETCHGREPLY_V6						0x04000000
#define DRS_EXT_WHISTLER_BETA3						0x08000000
#define DRS_EXT_W2K3_DEFLATE						0x10000000
#define DRS_EXT_GETCHGREQ_V10						0x20000000
#define DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART2	0x40000000
#define DRS_EXT_RESERVED_FOR_WIN2K_OR_DOTNET_PART3	0x80000000

#define	DRS_EXT_ADAM								0x00000001
#define	DRS_EXT_LH_BETA2							0x00000002
#define	DRS_EXT_RECYCLE_BIN							0x00000004
#define DRS_EXT_GETCHGREPLY_V9						0x00000100
#define DRS_EXT_PAM									0x00000200

#define DRS_ASYNC_OP								0x00000001
#define DRS_GETCHG_CHECK							0x00000002
#define DRS_UPDATE_NOTIFICATION						0x00000002
#define DRS_ADD_REF									0x00000004
#define DRS_SYNC_ALL								0x00000008
#define DRS_DEL_REF									0x00000008
#define DRS_WRIT_REP								0x00000010
#define DRS_INIT_SYNC								0x00000020
#define DRS_PER_SYNC								0x00000040
#define DRS_MAIL_REP								0x00000080
#define DRS_ASYNC_REP								0x00000100
#define DRS_IGNORE_ERROR							0x00000100
#define DRS_TWOWAY_SYNC								0x00000200
#define DRS_CRITICAL_ONLY							0x00000400
#define DRS_GET_ANC									0x00000800
#define DRS_GET_NC_SIZE								0x00001000
#define DRS_LOCAL_ONLY								0x00001000
#define DRS_NONGC_RO_REP							0x00002000
#define DRS_SYNC_BYNAME								0x00004000
#define DRS_REF_OK									0x00004000
#define DRS_FULL_SYNC_NOW							0x00008000
#define DRS_NO_SOURCE								0x00008000
#define DRS_FULL_SYNC_IN_PROGRESS					0x00010000
#define DRS_FULL_SYNC_PACKET						0x00020000
#define DRS_SYNC_REQUEUE							0x00040000
#define DRS_SYNC_URGENT								0x00080000
#define DRS_REF_GCSPN								0x00100000
#define DRS_NO_DISCARD								0x00100000
#define DRS_NEVER_SYNCED							0x00200000
#define DRS_SPECIAL_SECRET_PROCESSING				0x00400000
#define DRS_INIT_SYNC_NOW							0x00800000
#define DRS_PREEMPTED								0x01000000
#define DRS_SYNC_FORCED								0x02000000
#define DRS_DISABLE_AUTO_SYNC						0x04000000
#define DRS_DISABLE_PERIODIC_SYNC					0x08000000
#define DRS_USE_COMPRESSION							0x10000000
#define DRS_NEVER_NOTIFY							0x20000000
#define DRS_SYNC_PAS								0x40000000
#define DRS_GET_ALL_GROUP_MEMBERSHIP				0x80000000

#define ENTINF_FROM_MASTER							0x00000001
#define ENTINF_DYNAMIC_OBJECT						0x00000002
#define ENTINF_REMOTE_MODIFY						0x00010000

typedef enum {
	DS_UNKNOWN_NAME = 0,
	DS_FQDN_1779_NAME = 1,
	DS_NT4_ACCOUNT_NAME = 2,
	DS_DISPLAY_NAME = 3,
	DS_UNIQUE_ID_NAME = 6,
	DS_CANONICAL_NAME = 7,
	DS_USER_PRINCIPAL_NAME = 8,
	DS_CANONICAL_NAME_EX = 9,
	DS_SERVICE_PRINCIPAL_NAME = 10,
	DS_SID_OR_SID_HISTORY_NAME = 11,
	DS_DNS_DOMAIN_NAME = 12,

	DS_LIST_SITES = -1,
	DS_LIST_SERVERS_IN_SITE = -2,
	DS_LIST_DOMAINS_IN_SITE = -3,
	DS_LIST_SERVERS_FOR_DOMAIN_IN_SITE = -4,
	DS_LIST_INFO_FOR_SERVER = -5,
	DS_LIST_ROLES = -6,
	DS_NT4_ACCOUNT_NAME_SANS_DOMAIN = -7,
	DS_MAP_SCHEMA_GUID = -8,
	DS_LIST_DOMAINS = -9,
	DS_LIST_NCS = -10,
	DS_ALT_SECURITY_IDENTITIES_NAME = -11,
	DS_STRING_SID_NAME = -12,
	DS_LIST_SERVERS_WITH_DCS_IN_SITE = -13,
	DS_USER_PRINCIPAL_NAME_FOR_LOGON = -14,
	DS_LIST_GLOBAL_CATALOG_SERVERS = -15,
	DS_NT4_ACCOUNT_NAME_SANS_DOMAIN_EX = -16,
	DS_USER_PRINCIPAL_NAME_AND_ALTSECID = -17,
} DS_NAME_FORMAT;

typedef enum  { 
	DS_NAME_NO_ERROR = 0,
	DS_NAME_ERROR_RESOLVING = 1,
	DS_NAME_ERROR_NOT_FOUND = 2,
	DS_NAME_ERROR_NOT_UNIQUE = 3,
	DS_NAME_ERROR_NO_MAPPING = 4,
	DS_NAME_ERROR_DOMAIN_ONLY = 5,
	DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING = 6,
	DS_NAME_ERROR_TRUST_REFERRAL = 7
} DS_NAME_ERROR;

typedef enum {
	EXOP_FSMO_REQ_ROLE = 1,
	EXOP_FSMO_REQ_RID_ALLOC = 2,
	EXOP_FSMO_RID_REQ_ROLE = 3,
	EXOP_FSMO_REQ_PDC = 4,
	EXOP_FSMO_ABANDON_ROLE = 5,
	EXOP_REPL_OBJ = 6,
	EXOP_REPL_SECRETS = 7
} EXOP_REQ;

#define szOID_objectclass					"2.5.4.0"
#define szOID_hasMasterNCs					"1.2.840.113556.1.2.14"
#define szOID_dMDLocation					"1.2.840.113556.1.2.36"
#define szOID_invocationId					"1.2.840.113556.1.2.115"

#define szOID_ANSI_name						"1.2.840.113556.1.4.1"
#define szOID_objectGUID					"1.2.840.113556.1.4.2"

#define szOID_ANSI_sAMAccountName			"1.2.840.113556.1.4.221"
#define szOID_ANSI_userPrincipalName		"1.2.840.113556.1.4.656"
#define szOID_ANSI_servicePrincipalName		"1.2.840.113556.1.4.771"
#define szOID_ANSI_sAMAccountType			"1.2.840.113556.1.4.302"
#define szOID_ANSI_userAccountControl		"1.2.840.113556.1.4.8"
#define szOID_ANSI_accountExpires			"1.2.840.113556.1.4.159"
#define szOID_ANSI_pwdLastSet				"1.2.840.113556.1.4.96"
#define szOID_ANSI_objectSid				"1.2.840.113556.1.4.146"
#define szOID_ANSI_sIDHistory				"1.2.840.113556.1.4.609"
#define szOID_ANSI_unicodePwd				"1.2.840.113556.1.4.90"
#define szOID_ANSI_ntPwdHistory				"1.2.840.113556.1.4.94"
#define szOID_ANSI_dBCSPwd					"1.2.840.113556.1.4.55"
#define szOID_ANSI_lmPwdHistory				"1.2.840.113556.1.4.160"
#define szOID_ANSI_supplementalCredentials	"1.2.840.113556.1.4.125"

#define szOID_ANSI_trustPartner				"1.2.840.113556.1.4.133"
#define szOID_ANSI_trustAuthIncoming		"1.2.840.113556.1.4.129"
#define szOID_ANSI_trustAuthOutgoing		"1.2.840.113556.1.4.135"

#define szOID_ANSI_currentValue				"1.2.840.113556.1.4.27"

#define szOID_options						"1.2.840.113556.1.4.307"
#define szOID_systemFlags					"1.2.840.113556.1.4.375"
#define szOID_ldapServer_show_deleted		"1.2.840.113556.1.4.417"
#define szOID_serverReference				"1.2.840.113556.1.4.515"
#define szOID_msDS_Behavior_Version			"1.2.840.113556.1.4.1459"
#define szOID_msDS_ReplicationEpoch			"1.2.840.113556.1.4.1720"
#define szOID_msDS_HasDomainNCs				"1.2.840.113556.1.4.1820"
#define szOID_msDS_hasMasterNCs				"1.2.840.113556.1.4.1836"

#define szOID_ANSI_nTDSDSA					"1.2.840.113556.1.5.7000.47"

#define ATT_WHEN_CREATED				MAKELONG(  2, 2)
#define ATT_WHEN_CHANGED				MAKELONG(  3, 2)

#define ATT_RDN							MAKELONG(  1, 9)
#define ATT_OBJECT_SID					MAKELONG(146, 9)
#define ATT_SAM_ACCOUNT_NAME			MAKELONG(221, 9)
#define ATT_USER_PRINCIPAL_NAME			MAKELONG(656, 9)
#define ATT_SERVICE_PRINCIPAL_NAME		MAKELONG(771, 9)
#define ATT_SID_HISTORY					MAKELONG(609, 9)
#define ATT_USER_ACCOUNT_CONTROL		MAKELONG(  8, 9)
#define ATT_SAM_ACCOUNT_TYPE			MAKELONG(302, 9)
#define ATT_LOGON_HOURS					MAKELONG( 64, 9)
#define ATT_LOGON_WORKSTATION			MAKELONG( 65, 9)
#define ATT_LAST_LOGON					MAKELONG( 52, 9)
#define ATT_PWD_LAST_SET				MAKELONG( 96, 9)
#define ATT_ACCOUNT_EXPIRES				MAKELONG(159, 9)
#define ATT_LOCKOUT_TIME				MAKELONG(662, 9)

#define ATT_UNICODE_PWD					MAKELONG( 90, 9)
#define ATT_NT_PWD_HISTORY				MAKELONG( 94, 9)
#define ATT_DBCS_PWD					MAKELONG( 55, 9)
#define ATT_LM_PWD_HISTORY				MAKELONG(160, 9)
#define ATT_SUPPLEMENTAL_CREDENTIALS	MAKELONG(125, 9)

#define ATT_CURRENT_VALUE				MAKELONG( 27, 9)

#define ATT_TRUST_ATTRIBUTES			MAKELONG(470, 9)
#define ATT_TRUST_AUTH_INCOMING			MAKELONG(129, 9)
#define ATT_TRUST_AUTH_OUTGOING			MAKELONG(135, 9)
#define ATT_TRUST_DIRECTION				MAKELONG(132, 9)
#define ATT_TRUST_PARENT				MAKELONG(471, 9)
#define ATT_TRUST_PARTNER				MAKELONG(133, 9)
#define ATT_TRUST_TYPE					MAKELONG(136, 9)

void RPC_ENTRY kull_m_rpc_drsr_RpcSecurityCallback(void *Context);

BOOL kull_m_rpc_drsr_getDomainAndUserInfos(RPC_BINDING_HANDLE *hBinding, LPCWSTR ServerName, LPCWSTR Domain, GUID *DomainGUID, LPCWSTR User, LPCWSTR Guid, GUID *UserGuid, DRS_EXTENSIONS_INT *pDrsExtensionsInt);
BOOL kull_m_rpc_drsr_getDCBind(RPC_BINDING_HANDLE *hBinding, GUID *NtdsDsaObjectGuid, DRS_HANDLE *hDrs, DRS_EXTENSIONS_INT *pDrsExtensionsInt);
BOOL kull_m_rpc_drsr_CrackName(DRS_HANDLE hDrs, DS_NAME_FORMAT NameFormat, LPCWSTR Name, DS_NAME_FORMAT FormatWanted, LPWSTR *CrackedName, LPWSTR *CrackedDomain);
BOOL kull_m_rpc_drsr_ProcessGetNCChangesReply(SCHEMA_PREFIX_TABLE *prefixTable, REPLENTINFLIST *objects);
BOOL kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt(ATTRVAL *val, SecPkgContext_SessionKey *SessionKey);
BOOL kull_m_rpc_drsr_CreateGetNCChangesReply_encrypt(ATTRVAL *val, SecPkgContext_SessionKey *SessionKey);

void kull_m_rpc_drsr_free_DRS_MSG_DCINFOREPLY_data(DWORD dcOutVersion, DRS_MSG_DCINFOREPLY * reply);
void kull_m_rpc_drsr_free_DRS_MSG_CRACKREPLY_data(DWORD nameCrackOutVersion, DRS_MSG_CRACKREPLY * reply);
void kull_m_rpc_drsr_free_DRS_MSG_GETCHGREPLY_data(DWORD dwOutVersion, DRS_MSG_GETCHGREPLY * reply);
void kull_m_rpc_drsr_free_SCHEMA_PREFIX_TABLE_data(SCHEMA_PREFIX_TABLE *prefixTable);

LPSTR kull_m_rpc_drsr_OidFromAttid(SCHEMA_PREFIX_TABLE *prefixTable, ATTRTYP type);
BOOL kull_m_rpc_drsr_MakeAttid(SCHEMA_PREFIX_TABLE *prefixTable, LPCSTR szOid, ATTRTYP *att, BOOL toAdd);

ATTRVALBLOCK * kull_m_rpc_drsr_findAttr(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, LPCSTR szOid);
PVOID kull_m_rpc_drsr_findMonoAttr(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, LPCSTR szOid, PVOID data, DWORD *size);
void kull_m_rpc_drsr_findPrintMonoAttr(LPCWSTR prefix, SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, LPCSTR szOid, BOOL newLine);

LPWSTR kull_m_rpc_drsr_MakeSpnWithGUID(LPCGUID ServClass, LPCWSTR ServName, LPCGUID InstName);
NTSTATUS kull_m_rpc_drsr_start_server(LPCWSTR ServName, LPCGUID InstName);
NTSTATUS kull_m_rpc_drsr_stop_server();

// cf https://technet.microsoft.com/en-us/library/cc961740.aspx
#define SYNTAX_UNDEFINED				0x550500
#define SYNTAX_DN						0x550501
#define SYNTAX_OID						0x550502
#define SYNTAX_CASE_SENSITIVE_STRING	0x550503
#define SYNTAX_CASE_IGNORE_STRING		0x550504
#define SYNTAX_STRING_IA5				0x550505
#define SYNTAX_STRING_NUMERIC			0x550506
#define SYNTAX_OBJECT_DN_BINARY			0x550507
#define SYNTAX_BOOLEAN					0x550508
#define SYNTAX_INTEGER					0x550509
#define SYNTAX_OCTET_STRING				0x55050a
#define SYNTAX_GENERALIZED_TIME			0x55050b
#define SYNTAX_UNICODE_STRING			0x55050c
#define SYNTAX_OBJECT_PRESENTATION_ADDR	0x55050d
#define SYNTAX_OBJECT_DN				0x55050e
#define SYNTAX_NTSECURITYDESCRIPTOR		0x55050f
#define SYNTAX_LARGE_INTEGER			0x550510
#define SYNTAX_SID						0x550511

const SCHEMA_PREFIX_TABLE SCHEMA_DEFAULT_PREFIX_TABLE;