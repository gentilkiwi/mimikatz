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
//NTSTATUS kuhl_m_lsadump_dc...(int argc, wchar_t * argv[]);

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