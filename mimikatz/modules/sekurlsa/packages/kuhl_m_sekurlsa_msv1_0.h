/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../kuhl_m_sekurlsa.h"
#include "../kuhl_m_sekurlsa_utils.h"
#include "../modules/kull_m_crypto_system.h"

typedef struct _MSV1_0_PRIMARY_CREDENTIAL { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName; 
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	DWORD unknow_01000100;
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL, *PMSV1_0_PRIMARY_CREDENTIAL; 

typedef struct _MARSHALL_KEY {
	DWORD unkId;
	USHORT unk0;
	USHORT length;
	RPCEID ElementId;
} MARSHALL_KEY, *PMARSHALL_KEY;

typedef struct _RPCE_CREDENTIAL_KEYCREDENTIAL {
	RPCE_COMMON_TYPE_HEADER	typeHeader;
	RPCE_PRIVATE_HEADER	privateHeader;
	RPCEID RootElementId;
	DWORD unk0;
	DWORD unk1;
	MARSHALL_KEY key[ANYSIZE_ARRAY];
} RPCE_CREDENTIAL_KEYCREDENTIAL, *PRPCE_CREDENTIAL_KEYCREDENTIAL;

typedef struct _MSV1_0_PTH_DATA { 
	PLUID		LogonId;
	PCWCHAR		UserName;
	PCWCHAR		LogonDomain;
	LPBYTE		NtlmHash;
	BOOL		isReplaceOk;
} MSV1_0_PTH_DATA, *PMSV1_0_PTH_DATA;

typedef struct _MSV1_0_PTH_DATA_CRED { 
	PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pSecData;
	PMSV1_0_PTH_DATA pthData;
} MSV1_0_PTH_DATA_CRED, *PMSV1_0_PTH_DATA_CRED;

typedef struct _MSV1_0_STD_DATA {
	PLUID						LogonId;
} MSV1_0_STD_DATA, *PMSV1_0_STD_DATA;

typedef BOOL (CALLBACK * PKUHL_M_SEKURLSA_MSV_CRED_CALLBACK) (IN struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS * pCredentials, IN DWORD AuthenticationPackageId, IN PKULL_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData);

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_msv_package;
NTSTATUS kuhl_m_sekurlsa_msv(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sekurlsa_msv_pth(int argc, wchar_t * argv[]);

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_msv(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_msv_pth(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData);

VOID kuhl_m_sekurlsa_msv_enum_cred(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN PVOID pCredentials, IN PKUHL_M_SEKURLSA_MSV_CRED_CALLBACK credCallback, IN PVOID optionalData);
BOOL CALLBACK kuhl_m_sekurlsa_msv_enum_cred_callback_std(IN struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS * pCredentials, IN DWORD AuthenticationPackageId, IN PKULL_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData);
BOOL CALLBACK kuhl_m_sekurlsa_msv_enum_cred_callback_pth(IN struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS * pCredentials, IN DWORD AuthenticationPackageId, IN PKULL_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData);