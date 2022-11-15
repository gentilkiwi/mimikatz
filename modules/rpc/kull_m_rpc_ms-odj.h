#pragma once
#include "kull_m_rpc.h"
#include <dsgetdc.h>

extern const GUID GUID_JOIN_PROVIDER, GUID_JOIN_PROVIDER2, GUID_JOIN_PROVIDER3, GUID_CERT_PROVIDER, GUID_POLICY_PROVIDER;

#define	ODJ_WIN7_FORMAT	0x00000001 // The bytes contained in pBlob must contain a serialized ODJ_WIN7_BLOB structure
#define ODJ_WIN8_FORMAT 0x00000002 // The bytes contained in pBlob must contain a serialized OP_PACKAGE structure

typedef struct _ODJ_BLOB {
	ULONG ulODJFormat;
	ULONG cbBlob;
	PBYTE pBlob;
} ODJ_BLOB, * PODJ_BLOB;

typedef struct _ODJ_PROVISION_DATA {
	ULONG ulVersion; // 1
	ULONG ulcBlobs;
	PODJ_BLOB pBlobs;
} ODJ_PROVISION_DATA, * PODJ_PROVISION_DATA;

typedef struct _OP_BLOB {
	ULONG cbBlob;
	PBYTE pBlob;
} OP_BLOB, * POP_BLOB;

/* PartType
GUID_JOIN_PROVIDER		{631c7621-5289-4321-bc9e-80f843f868c3}	Contains a serialized ODJ_WIN7_BLOB structure.
GUID_JOIN_PROVIDER2		{57bfc56b-52f9-480c-adcb-91b3f8a82317}	Contains a serialized OP_JOIN_PROV2_PART structure.
GUID_JOIN_PROVIDER3		{fc0ccf25-7ffa-474a-8611-69ffe269645f}	Contains a serialized OP_JOIN_PROV3_PART structure.
GUID_CERT_PROVIDER		{9c0971e9-832f-4873-8e87-ef1419d4781e}	Contains a serialized OP_CERT_PART structure.
GUID_POLICY_PROVIDER	{68fb602a-0c09-48ce-b75f-07b7bd58f7ec}	Contains a serialized OP_POLICY_PART structure.
*/

#define OPSPI_PACKAGE_PART_ESSENTIAL	0x00000001 // This package part is considered essential. If the consumer does not recognize this package part or fails to successfully process it, the overall operation must fail.

typedef struct _OP_PACKAGE_PART {
	GUID PartType;
	ULONG ulFlags;
	OP_BLOB Part;
	OP_BLOB Extension; // Reserved for future use and MUST be set to all zeros.
} OP_PACKAGE_PART, * POP_PACKAGE_PART;

typedef struct _OP_PACKAGE_PART_COLLECTION {
	ULONG cParts;
	POP_PACKAGE_PART pParts;
	OP_BLOB Extension;
} OP_PACKAGE_PART_COLLECTION, * POP_PACKAGE_PART_COLLECTION;

typedef struct _OP_PACKAGE {
	GUID EncryptionType;				// Reserved for future use and MUST be set to GUID_NULL.
	OP_BLOB EncryptionContext;			// Reserved for future use and MUST be set to all zeros.
	OP_BLOB WrappedPartCollection;		// An OP_BLOB structure that contains a serialized OP_PACKAGE_COLLECTION structure.
	ULONG cbDecryptedPartCollection;	// Reserved for future use and MUST be set to zero.
	OP_BLOB Extension;					// Reserved for future use and MUST be set to all zeros.
} OP_PACKAGE, * POP_PACKAGE;

typedef struct _ODJ_SID {
	UCHAR Revision;
	UCHAR SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
	ULONG SubAuthority[ANYSIZE_ARRAY];
} ODJ_SID, * PODJ_SID;

typedef struct _ODJ_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} ODJ_UNICODE_STRING, * PODJ_UNICODE_STRING;

typedef struct _ODJ_POLICY_DNS_DOMAIN_INFO {
	ODJ_UNICODE_STRING Name;
	ODJ_UNICODE_STRING DnsDomainName;
	ODJ_UNICODE_STRING DnsForestName;
	GUID DomainGuid;
	PODJ_SID Sid;
} ODJ_POLICY_DNS_DOMAIN_INFO;

typedef struct _ODJ_WIN7BLOB {
	wchar_t* lpDomain;
	wchar_t* lpMachineName;
	wchar_t* lpMachinePassword;
	ODJ_POLICY_DNS_DOMAIN_INFO DnsDomainInfo;
	DOMAIN_CONTROLLER_INFOW DcInfo;
	DWORD Options;
} ODJ_WIN7BLOB, * PODJ_WIN7BLOB;

#define OP_JP2_FLAG_PERSISTENTSITE	0x00000001	// The site specified in lpSiteName MUST be considered the permanent site for the client.
typedef struct _OP_JOINPROV2_PART {
	DWORD dwFlags;
	wchar_t* lpNetbiosName;
	wchar_t* lpSiteName;
	wchar_t* lpPrimaryDNSDomain;
	DWORD dwReserved;
	wchar_t* lpReserved;
} OP_JOINPROV2_PART, * POP_JOINPROV2_PART;

typedef struct _OP_JOINPROV3_PART {
	DWORD Rid;
	wchar_t* lpSid;
} OP_JOINPROV3_PART, * POP_JOINPROV3_PART;

typedef struct _OP_POLICY_ELEMENT {
	wchar_t* pKeyPath;
	wchar_t* pValueName;
	ULONG ulValueType;
	ULONG cbValueData;
	PBYTE pValueData;
} OP_POLICY_ELEMENT, * POP_POLICY_ELEMENT;

typedef struct _OP_POLICY_ELEMENT_LIST {
	wchar_t* pSource;
	ULONG ulRootKeyId; // Contains the identifier of the root registry key; currently must be set to HKEY_LOCAL_MACHINE.
	ULONG cElements;
	POP_POLICY_ELEMENT pElements;
} OP_POLICY_ELEMENT_LIST, * POP_POLICY_ELEMENT_LIST;

typedef struct _OP_POLICY_PART {
	ULONG cElementLists;
	POP_POLICY_ELEMENT_LIST pElementLists;
	OP_BLOB Extension;	// Reserved for future use and must contain all zeros
} OP_POLICY_PART, * POP_POLICY_PART;

typedef struct _OP_CERT_PFX_STORE {
	wchar_t* pTemplateName;
	ULONG ulPrivateKeyExportPolicy;
	wchar_t* pPolicyServerUrl;
	ULONG ulPolicyServerUrlFlags;
	wchar_t* pPolicyServerId;
	ULONG cbPfx;
	PBYTE pPfx;
} OP_CERT_PFX_STORE, * POP_CERT_PFX_STORE;

typedef struct _OP_CERT_SST_STORE {
	ULONG StoreLocation;
	wchar_t* pStoreName;
	ULONG cbSst;
	PBYTE pSst;
} OP_CERT_SST_STORE, * POP_CERT_SST_STORE;

typedef struct _OP_CERT_PART {
	ULONG cPfxStores;
	POP_CERT_PFX_STORE pPfxStores;
	ULONG cSstStores;
	POP_CERT_SST_STORE pSstStores;
	OP_BLOB Extension;
} OP_CERT_PART, * POP_CERT_PART;

size_t POP_PACKAGE_AlignSize(handle_t _MidlEsHandle, POP_PACKAGE * _pType);
size_t PODJ_WIN7BLOB_AlignSize(handle_t _MidlEsHandle, PODJ_WIN7BLOB * _pType);
size_t POP_JOINPROV2_PART_AlignSize(handle_t _MidlEsHandle, POP_JOINPROV2_PART * _pType);
size_t POP_JOINPROV3_PART_AlignSize(handle_t _MidlEsHandle, POP_JOINPROV3_PART * _pType);
size_t PODJ_PROVISION_DATA_AlignSize(handle_t _MidlEsHandle, PODJ_PROVISION_DATA * _pType);
size_t POP_PACKAGE_PART_COLLECTION_AlignSize(handle_t _MidlEsHandle, POP_PACKAGE_PART_COLLECTION * _pType);
size_t POP_PACKAGE_PART_AlignSize(handle_t _MidlEsHandle, POP_PACKAGE_PART * _pType);
size_t POP_CERT_PART_AlignSize(handle_t _MidlEsHandle, POP_CERT_PART * _pType);
size_t POP_POLICY_PART_AlignSize(handle_t _MidlEsHandle, POP_POLICY_PART * _pType);

void POP_PACKAGE_Encode(handle_t _MidlEsHandle, POP_PACKAGE * _pType);
void POP_JOINPROV3_PART_Encode(handle_t _MidlEsHandle, POP_JOINPROV3_PART * _pType);
void POP_JOINPROV2_PART_Encode(handle_t _MidlEsHandle, POP_JOINPROV2_PART * _pType);
void PODJ_WIN7BLOB_Encode(handle_t _MidlEsHandle, PODJ_WIN7BLOB * _pType);
void PODJ_PROVISION_DATA_Encode(handle_t _MidlEsHandle, PODJ_PROVISION_DATA * _pType);
void POP_PACKAGE_PART_COLLECTION_Encode(handle_t _MidlEsHandle, POP_PACKAGE_PART_COLLECTION * _pType);
void POP_PACKAGE_PART_Encode(handle_t _MidlEsHandle, POP_PACKAGE_PART * _pType);
void POP_CERT_PART_Encode(handle_t _MidlEsHandle, POP_CERT_PART * _pType);
void POP_POLICY_PART_Encode(handle_t _MidlEsHandle, POP_POLICY_PART * _pType);

void POP_PACKAGE_Decode(handle_t _MidlEsHandle, POP_PACKAGE * _pType);
void POP_JOINPROV3_PART_Decode(handle_t _MidlEsHandle, POP_JOINPROV3_PART * _pType);
void PODJ_WIN7BLOB_Decode(handle_t _MidlEsHandle, PODJ_WIN7BLOB * _pType);
void POP_JOINPROV2_PART_Decode(handle_t _MidlEsHandle, POP_JOINPROV2_PART * _pType);
void PODJ_PROVISION_DATA_Decode(handle_t _MidlEsHandle, PODJ_PROVISION_DATA * _pType);
void POP_PACKAGE_PART_Decode(handle_t _MidlEsHandle, POP_PACKAGE_PART * _pType);
void POP_PACKAGE_PART_COLLECTION_Decode(handle_t _MidlEsHandle, POP_PACKAGE_PART_COLLECTION * _pType);
void POP_CERT_PART_Decode(handle_t _MidlEsHandle, POP_CERT_PART * _pType);
void POP_POLICY_PART_Decode(handle_t _MidlEsHandle, POP_POLICY_PART * _pType);

void POP_PACKAGE_Free(handle_t _MidlEsHandle, POP_PACKAGE * _pType);
void POP_JOINPROV2_PART_Free(handle_t _MidlEsHandle, POP_JOINPROV2_PART * _pType);
void PODJ_WIN7BLOB_Free(handle_t _MidlEsHandle, PODJ_WIN7BLOB * _pType);
void POP_JOINPROV3_PART_Free(handle_t _MidlEsHandle, POP_JOINPROV3_PART * _pType);
void PODJ_PROVISION_DATA_Free(handle_t _MidlEsHandle, PODJ_PROVISION_DATA * _pType);
void POP_PACKAGE_PART_Free(handle_t _MidlEsHandle, POP_PACKAGE_PART * _pType);
void POP_PACKAGE_PART_COLLECTION_Free(handle_t _MidlEsHandle, POP_PACKAGE_PART_COLLECTION * _pType);
void POP_CERT_PART_Free(handle_t _MidlEsHandle, POP_CERT_PART * _pType);
void POP_POLICY_PART_Free(handle_t _MidlEsHandle, POP_POLICY_PART * _pType);

#define kull_m_rpc_DecodeODJ_PROVISION_DATA(/*PVOID */data, /*DWORD */size, /*PODJ_PROVISION_DATA **/pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) PODJ_PROVISION_DATA_Decode)
#define kull_m_rpc_FreeODJ_PROVISION_DATA(/*PODJ_PROVISION_DATA **/pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) PODJ_PROVISION_DATA_Free)

#define kull_m_rpc_DecodeODJ_WIN7BLOB(/*PVOID */data, /*DWORD */size, /*PODJ_WIN7BLOB **/pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) PODJ_WIN7BLOB_Decode)
#define kull_m_rpc_FreeODJ_WIN7BLOB(/*PODJ_WIN7BLOB **/pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) PODJ_WIN7BLOB_Free)

#define kull_m_rpc_DecodeOP_PACKAGE(/*PVOID */data, /*DWORD */size, /*POP_PACKAGE **/pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) POP_PACKAGE_Decode)
#define kull_m_rpc_FreeOP_PACKAGE(/*POP_PACKAGE **/pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) POP_PACKAGE_Free)

#define kull_m_rpc_DecodeOP_PACKAGE_PART_COLLECTION(/*PVOID */data, /*DWORD */size, /*POP_PACKAGE_PART_COLLECTION **/pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) POP_PACKAGE_PART_COLLECTION_Decode)
#define kull_m_rpc_FreeOP_PACKAGE_PART_COLLECTION(/*POP_PACKAGE_PART_COLLECTION **/pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) POP_PACKAGE_PART_COLLECTION_Free)

#define kull_m_rpc_DecodeOP_JOINPROV2_PART(/*PVOID */data, /*DWORD */size, /*POP_JOINPROV2_PART **/pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) POP_JOINPROV2_PART_Decode)
#define kull_m_rpc_FreeOP_JOINPROV2_PART(/*POP_JOINPROV2_PART **/pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) POP_JOINPROV2_PART_Free)

#define kull_m_rpc_DecodeOP_JOINPROV3_PART(/*PVOID */data, /*DWORD */size, /*POP_JOINPROV3_PART **/pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) POP_JOINPROV3_PART_Decode)
#define kull_m_rpc_FreeOP_JOINPROV3_PART(/*POP_JOINPROV3_PART **/pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) POP_JOINPROV3_PART_Free)

#define kull_m_rpc_DecodeOP_CERT_PART(/*PVOID */data, /*DWORD */size, /*POP_CERT_PART **/pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) POP_CERT_PART_Decode)
#define kull_m_rpc_FreeOP_CERT_PART(/*POP_CERT_PART **/pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) POP_CERT_PART_Free)

#define kull_m_rpc_DecodeOP_POLICY_PART(/*PVOID */data, /*DWORD */size, /*POP_POLICY_PART **/pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) POP_POLICY_PART_Decode)
#define kull_m_rpc_FreeOP_POLICY_PART(/*POP_POLICY_PART **/pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) POP_POLICY_PART_Free)