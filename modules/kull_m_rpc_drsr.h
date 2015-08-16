/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globals.h"
#include "../modules/kull_m_crypto_system.h"
#include "../modules/kull_m_crypto.h"
#include "kull_m_rpc_ms-drsr.h"
#include "kull_m_string.h"

typedef struct _DRS_EXTENSIONS_INT {
	DWORD cb;
	DWORD dwFlags;
	GUID SiteObjGuid;
	DWORD Pid;
	DWORD dwReplEpoch;
	DWORD dwFlagsExt;
	GUID ConfigObjGUID;
} DRS_EXTENSIONS_INT, *PDRS_EXTENSIONS_INT;

typedef struct _ENCRYPTED_PAYLOAD {
	UCHAR Salt[16];
	ULONG CheckSum;
	UCHAR EncryptedData[ANYSIZE_ARRAY];
} ENCRYPTED_PAYLOAD, *PENCRYPTED_PAYLOAD;

void __RPC_FAR * __RPC_USER midl_user_allocate(size_t cBytes);
void __RPC_USER midl_user_free(void __RPC_FAR * p);

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

#define ATT_RDN							589825
#define ATT_OBJECT_SID					589970
#define ATT_WHEN_CREATED				131074
#define ATT_WHEN_CHANGED				131075

#define ATT_SAM_ACCOUNT_NAME			590045
#define ATT_USER_PRINCIPAL_NAME			590480
#define ATT_SERVICE_PRINCIPAL_NAME		590595
#define ATT_SID_HISTORY					590433
#define ATT_USER_ACCOUNT_CONTROL		589832
#define ATT_SAM_ACCOUNT_TYPE			590126
#define ATT_LOGON_HOURS					589888
#define ATT_LOGON_WORKSTATION			589889
#define ATT_LAST_LOGON					589876
#define ATT_PWD_LAST_SET				589920
#define ATT_ACCOUNT_EXPIRES				589983
#define ATT_LOCKOUT_TIME				590486

#define ATT_UNICODE_PWD					589914
#define ATT_NT_PWD_HISTORY				589918
#define ATT_DBCS_PWD					589879
#define ATT_LM_PWD_HISTORY				589984
#define ATT_SUPPLEMENTAL_CREDENTIALS	589949

#define ATT_CURRENT_VALUE				589851

#define ATT_TRUST_ATTRIBUTES			590294
#define ATT_TRUST_AUTH_INCOMING			589953
#define ATT_TRUST_AUTH_OUTGOING			589959
#define ATT_TRUST_DIRECTION				589956
#define ATT_TRUST_PARENT				590295
#define ATT_TRUST_PARTNER				589957
#define ATT_TRUST_TYPE					589960

void RPC_ENTRY  kull_m_rpc_drsr_RpcSecurityCallback(void *Context);
BOOL kull_m_rpc_drsr_createBinding(LPCWSTR server, RPC_BINDING_HANDLE *hBinding);
BOOL kull_m_rpc_drsr_deleteBinding(RPC_BINDING_HANDLE *hBinding);

BOOL kull_m_rpc_drsr_getDomainAndUserInfos(RPC_BINDING_HANDLE *hBinding, LPCWSTR ServerName, LPCWSTR Domain, GUID *DomainGUID, LPCWSTR User, LPCWSTR Guid, GUID *UserGuid);
BOOL kull_m_rpc_drsr_getDCBind(RPC_BINDING_HANDLE *hBinding, GUID *NtdsDsaObjectGuid, DRS_HANDLE *hDrs);
BOOL kull_m_rpc_drsr_CrackName(DRS_HANDLE hDrs, DS_NAME_FORMAT NameFormat, LPCWSTR Name, DS_NAME_FORMAT FormatWanted, LPWSTR *CrackedName, LPWSTR *CrackedDomain);
BOOL kull_m_rpc_drsr_ProcessGetNCChangesReply(REPLENTINFLIST *objects);
BOOL kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt(ATTRVAL *val);

#define DRS_EXCEPTION (RpcExceptionCode() != STATUS_ACCESS_VIOLATION) && \
	(RpcExceptionCode() != STATUS_DATATYPE_MISALIGNMENT) && \
	(RpcExceptionCode() != STATUS_PRIVILEGED_INSTRUCTION) && \
	(RpcExceptionCode() != STATUS_ILLEGAL_INSTRUCTION) && \
	(RpcExceptionCode() != STATUS_BREAKPOINT) && \
	(RpcExceptionCode() != STATUS_STACK_OVERFLOW) && \
	(RpcExceptionCode() != STATUS_IN_PAGE_ERROR) && \
	(RpcExceptionCode() != STATUS_ASSERTION_FAILURE) && \
	(RpcExceptionCode() != STATUS_STACK_BUFFER_OVERRUN) && \
	(RpcExceptionCode() != STATUS_GUARD_PAGE_VIOLATION)

void kull_m_rpc_drsr_free_DRS_MSG_DCINFOREPLY_data(DWORD dcOutVersion, DRS_MSG_DCINFOREPLY * reply);
void kull_m_rpc_drsr_free_DRS_MSG_CRACKREPLY_data(DWORD nameCrackOutVersion, DRS_MSG_CRACKREPLY * reply);
void kull_m_rpc_drsr_free_DRS_MSG_GETCHGREPLY_data(DWORD dwOutVersion, DRS_MSG_GETCHGREPLY * reply);