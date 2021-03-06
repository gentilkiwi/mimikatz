#pragma once
#include "kull_m_rpc.h"
#include "../kull_m_samlib.h"

#define PACINFO_TYPE_LOGON_INFO				0x00000001
#define PACINFO_TYPE_CREDENTIALS_INFO		0x00000002
#define PACINFO_TYPE_CHECKSUM_SRV			0x00000006
#define PACINFO_TYPE_CHECKSUM_KDC			0x00000007
#define PACINFO_TYPE_CNAME_TINFO			0x0000000a
#define PACINFO_TYPE_DELEGATION_INFO		0x0000000b
#define PACINFO_TYPE_UPN_DNS				0x0000000c
#define PACINFO_TYPE_CLIENT_CLAIMS			0x0000000d
#define PACINFO_TYPE_DEVICE_INFO			0x0000000e
#define PACINFO_TYPE_DEVICE_CLAIMS			0x0000000f

typedef struct _PAC_INFO_BUFFER {
	ULONG ulType;
	ULONG cbBufferSize;
	ULONG64 Offset;
} PAC_INFO_BUFFER, *PPAC_INFO_BUFFER;

typedef struct _PACTYPE {
	ULONG cBuffers;
	ULONG Version;
	PAC_INFO_BUFFER Buffers[ANYSIZE_ARRAY];
} PACTYPE, *PPACTYPE;

typedef struct _PAC_CLIENT_INFO {
	FILETIME ClientId;
	USHORT NameLength;
	WCHAR Name[ANYSIZE_ARRAY];
} PAC_CLIENT_INFO, *PPAC_CLIENT_INFO;

typedef struct _PAC_CREDENTIAL_INFO {
	ULONG Version;
	ULONG EncryptionType;
	UCHAR SerializedData[ANYSIZE_ARRAY];
} PAC_CREDENTIAL_INFO, *PPAC_CREDENTIAL_INFO;

#if !defined(_NTSECPKG_)
typedef struct _SECPKG_SUPPLEMENTAL_CRED {
	RPC_UNICODE_STRING PackageName;
	ULONG CredentialSize;
	PUCHAR Credentials;
} SECPKG_SUPPLEMENTAL_CRED, *PSECPKG_SUPPLEMENTAL_CRED;
#endif

typedef struct _PAC_CREDENTIAL_DATA {
	ULONG CredentialCount;
	SECPKG_SUPPLEMENTAL_CRED Credentials[ANYSIZE_ARRAY];
} PAC_CREDENTIAL_DATA, *PPAC_CREDENTIAL_DATA;

typedef struct _NTLM_SUPPLEMENTAL_CREDENTIAL {
	ULONG Version;
	ULONG Flags;
	UCHAR LmPassword[LM_NTLM_HASH_LENGTH];
	UCHAR NtPassword[LM_NTLM_HASH_LENGTH];
} NTLM_SUPPLEMENTAL_CREDENTIAL, *PNTLM_SUPPLEMENTAL_CREDENTIAL;

typedef struct _UPN_DNS_INFO {
	USHORT UpnLength;
	USHORT UpnOffset;
	USHORT DnsDomainNameLength;
	USHORT DnsDomainNameOffset;
	ULONG Flags;
} UPN_DNS_INFO, *PUPN_DNS_INFO;

typedef struct _S4U_DELEGATION_INFO {
	RPC_UNICODE_STRING S4U2proxyTarget;
	ULONG TransitedListSize;
	RPC_UNICODE_STRING S4UTransitedServices[ANYSIZE_ARRAY];
} S4U_DELEGATION_INFO, *PS4U_DELEGATION_INFO;

typedef struct _KERB_SID_AND_ATTRIBUTES {
	PISID Sid;
	ULONG Attributes;
} KERB_SID_AND_ATTRIBUTES, *PKERB_SID_AND_ATTRIBUTES;

typedef struct _KERB_VALIDATION_INFO {
	FILETIME LogonTime;
	FILETIME LogoffTime;
	FILETIME KickOffTime;
	FILETIME PasswordLastSet;
	FILETIME PasswordCanChange;
	FILETIME PasswordMustChange;
	RPC_UNICODE_STRING EffectiveName;
	RPC_UNICODE_STRING FullName;
	RPC_UNICODE_STRING LogonScript;
	RPC_UNICODE_STRING ProfilePath;
	RPC_UNICODE_STRING HomeDirectory;
	RPC_UNICODE_STRING HomeDirectoryDrive;
	USHORT LogonCount;
	USHORT BadPasswordCount;
	ULONG UserId;
	ULONG PrimaryGroupId;
	ULONG GroupCount;
	/* [size_is] */ PGROUP_MEMBERSHIP GroupIds;
	ULONG UserFlags;
	USER_SESSION_KEY UserSessionKey;
	RPC_UNICODE_STRING LogonServer;
	RPC_UNICODE_STRING LogonDomainName;
	PISID LogonDomainId;
	ULONG Reserved1[ 2 ];
	ULONG UserAccountControl;
	ULONG SubAuthStatus;
	FILETIME LastSuccessfulILogon;
	FILETIME LastFailedILogon;
	ULONG FailedILogonCount;
	ULONG Reserved3;
	ULONG SidCount;
	/* [size_is] */ PKERB_SID_AND_ATTRIBUTES ExtraSids;
	PISID ResourceGroupDomainSid;
	ULONG ResourceGroupCount;
	/* [size_is] */ PGROUP_MEMBERSHIP ResourceGroupIds;
} KERB_VALIDATION_INFO, *PKERB_VALIDATION_INFO;

void PPAC_CREDENTIAL_DATA_Decode(handle_t _MidlEsHandle, PPAC_CREDENTIAL_DATA * _pType);
void PPAC_CREDENTIAL_DATA_Free(handle_t _MidlEsHandle, PPAC_CREDENTIAL_DATA * _pType);

size_t PKERB_VALIDATION_INFO_AlignSize(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType);
void PKERB_VALIDATION_INFO_Encode(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType);
void PKERB_VALIDATION_INFO_Decode(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType);
void PKERB_VALIDATION_INFO_Free(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType);

#define kull_m_pac_DecodeCredential(/*PVOID */data, /*DWORD */size, /*PPAC_CREDENTIAL_DATA **/pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) PPAC_CREDENTIAL_DATA_Decode)
#define kull_m_pac_FreeCredential(/*PPAC_CREDENTIAL_DATA **/pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) PPAC_CREDENTIAL_DATA_Free)

#define kull_m_pac_DecodeValidationInformation(/*PVOID */data, /*DWORD */size, /*PKERB_VALIDATION_INFO **/pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) PKERB_VALIDATION_INFO_Decode)
#define kull_m_pac_FreeValidationInformation(/*PKERB_VALIDATION_INFO **/pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) PKERB_VALIDATION_INFO_Free)
#define kull_m_pac_EncodeValidationInformation(/*PKERB_VALIDATION_INFO **/pObject, /*PVOID **/data, /*DWORD **/size) kull_m_rpc_Generic_Encode(pObject, data, size, (PGENERIC_RPC_ENCODE) PKERB_VALIDATION_INFO_Encode, (PGENERIC_RPC_ALIGNSIZE) PKERB_VALIDATION_INFO_AlignSize)