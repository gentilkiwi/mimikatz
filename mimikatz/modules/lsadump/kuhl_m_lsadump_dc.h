/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com

	Vincent LE TOUX
	http://pingcastle.com / http://mysmartlogon.com
	vincent.letoux@gmail.com

	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../modules/rpc/kull_m_rpc_drsr.h"
#include "../kuhl_m.h"
#include "../kuhl_m_lsadump.h" // to move

NTSTATUS kuhl_m_lsadump_dcsync(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_dcshadow(int argc, wchar_t * argv[]);

#pragma pack(push, 1) 
typedef struct _USER_PROPERTY {
	USHORT NameLength;
	USHORT ValueLength;
	USHORT Reserved;
	wchar_t PropertyName[ANYSIZE_ARRAY];
	// PropertyValue in HEX !
} USER_PROPERTY, *PUSER_PROPERTY;

typedef struct _USER_PROPERTIES {
	DWORD Reserved1;
	DWORD Length;
	USHORT Reserved2;
	USHORT Reserved3;
	BYTE Reserved4[96];
	wchar_t PropertySignature;
	USHORT PropertyCount;
	USER_PROPERTY UserProperties[ANYSIZE_ARRAY];
} USER_PROPERTIES, *PUSER_PROPERTIES;
#pragma pack(pop)

BOOL kuhl_m_lsadump_dcsync_decrypt(PBYTE encodedData, DWORD encodedDataSize, DWORD rid, LPCWSTR prefix, BOOL isHistory);
void kuhl_m_lsadump_dcsync_descrObject(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, LPCWSTR szSrcDomain, BOOL someExport);
void kuhl_m_lsadump_dcsync_descrUser(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes);
void kuhl_m_lsadump_dcsync_descrUserProperties(PUSER_PROPERTIES properties);
void kuhl_m_lsadump_dcsync_descrTrust(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, LPCWSTR szSrcDomain);
void kuhl_m_lsadump_dcsync_descrTrustAuthentication(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, PCUNICODE_STRING domain, PCUNICODE_STRING partner, BOOL isIn);
void kuhl_m_lsadump_dcsync_descrSecret(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, BOOL someExport);
void kuhl_m_lsadump_dcsync_descrObject_csv(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes);

typedef BOOL (*DCSHADOW_SYNTAX_ENCODER) (ATTRVAL* pVal, PWSTR szValue);

typedef struct _DS_REPL_ATTRTYP_META_DATA {
	ATTRTYP attrType;
	DWORD dwVersion;
	FILETIME ftimeLastOriginatingChange;
	UUID uuidLastOriginatingDsaInvocationID;
	USN usnOriginatingChange;
	USN usnLocalChange;
} DS_REPL_ATTRTYP_META_DATA, *PDS_REPL_ATTRTYP_META_DATA;

typedef struct _DS_REPL_OBJ_TYPE_META_DATA {
	DWORD cNumEntries;
	DWORD dwReserved;
	DS_REPL_ATTRTYP_META_DATA rgMetaData[ANYSIZE_ARRAY];
} DS_REPL_OBJ_TYPE_META_DATA, *PDS_REPL_OBJ_TYPE_META_DATA;

typedef struct _DS_REPL_OBJ_TYPE_META_DATA_BLOB {
	DWORD dwVersion;
	DWORD dwReserved;
	DS_REPL_OBJ_TYPE_META_DATA ctr;
} DS_REPL_OBJ_TYPE_META_DATA_BLOB, *PDS_REPL_OBJ_TYPE_META_DATA_BLOB;

typedef struct _DCSHADOW_OBJECT_ATTRIBUTE {
	PWSTR szAttributeName;
	PSTR Oid;
	DWORD dwSyntax;
	BOOL fIsSensitive;
} DCSHADOW_OBJECT_ATTRIBUTE, *PDCSHADOW_OBJECT_ATTRIBUTE;

#define REPLICATION_UID_SET		(1)
#define REPLICATION_USN_SET		(1 << 1)
#define REPLICATION_TIME_SET	(1 << 2)
#define OBJECT_TO_ADD			(1)
#define OBJECT_DYNAMIC			(1 << 1)

typedef struct _DCSHADOW_OBJECT_ATTRIBUTE_METADATA {
	DWORD dwFlag;
	GUID uidOriginatingDsa;
	DWORD usnOriginating;
	FILETIME usnTimeChanged;
	DWORD curRevision;
	FILETIME curTimeChanged;
} DCSHADOW_OBJECT_ATTRIBUTE_METADATA, *PDCSHADOW_OBJECT_ATTRIBUTE_METADATA;

typedef struct _DCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE {
	PDCSHADOW_OBJECT_ATTRIBUTE pAttribute;
	DCSHADOW_OBJECT_ATTRIBUTE_METADATA MetaData;
	ATTRVALBLOCK AttrVal;
	PWSTR * pszValue;
} DCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE, *PDCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE;

typedef struct _DCSHADOW_PUSH_REQUEST_OBJECT {
	PWSTR szObjectDN;
	// mandatory for object creation and/or password encoding
	NT4SID pSid;
	// mandatory for object creation
	GUID ObjectGUID;
	GUID ParentGuid;
	ULONG cbAttributes;
	PDCSHADOW_PUSH_REQUEST_OBJECT_ATTRIBUTE pAttributes;
	DWORD dwFlag;
} DCSHADOW_PUSH_REQUEST_OBJECT, *PDCSHADOW_PUSH_REQUEST_OBJECT;

typedef struct _DCSHADOW_PUSH_REQUEST {
	ULONG cNumObjects;
	PDCSHADOW_PUSH_REQUEST_OBJECT pObjects;
	ULONG cNumAttributes;
	PDCSHADOW_OBJECT_ATTRIBUTE pAttributes;
} DCSHADOW_PUSH_REQUEST, *PDCSHADOW_PUSH_REQUEST;

typedef struct _DCSHADOW_DOMAIN_DC_INFO {
	BOOL isInstanceId;
	GUID InstanceId;
	BOOL isInvocationId;
	GUID InvocationId;
} DCSHADOW_DOMAIN_DC_INFO, *PDCSHADOW_DOMAIN_DC_INFO;

#define DOMAIN_INFO_PUSH_FLAGS_ROOT		1
#define DOMAIN_INFO_PUSH_FLAGS_CONFIG	2
#define DOMAIN_INFO_PUSH_FLAGS_SCHEMA	4
#define DOMAIN_INFO_PUSH_REMOTE_MODIFY  8

typedef struct _DCSHADOW_DOMAIN_INFO {
	// dns name - arg or local assigned var freed
	PWSTR szDomainName;
	PWSTR szDCFQDN;
	// not to be freed - arg or static var
	PWSTR szFakeDCNetBIOS;
	PWSTR szFakeFQDN;
	PWSTR szFakeDN;
	// naming context of the AD
	PWSTR szDomainNamingContext;
	PWSTR szConfigurationNamingContext;
	PWSTR szSchemaNamingContext;
	// The site (first-or-default in general)
	PWSTR szDsServiceName;
	PWSTR szDCDsServiceName;
	DWORD dwDomainControllerFunctionality;
	DWORD dwReplEpoch;
	DWORD maxDCUsn;
	BOOL fUseSchemaSignature;
	BYTE pbSchemaSignature[21];
	DWORD dwPushFlags;
	DCSHADOW_DOMAIN_DC_INFO realDc;
	DCSHADOW_DOMAIN_DC_INFO mimiDc;
	LDAP* ld;
	HANDLE hGetNCChangeCalled;
	// the only attribute which can be there in a next call
	PDCSHADOW_PUSH_REQUEST request;
} DCSHADOW_DOMAIN_INFO, *PDCSHADOW_DOMAIN_INFO;