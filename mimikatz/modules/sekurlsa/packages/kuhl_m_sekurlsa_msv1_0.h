/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_sekurlsa.h"
#include "../kuhl_m_sekurlsa_utils.h"
#include "../modules/kull_m_crypto_system.h"
#include "../modules/rpc/kull_m_rpc_ms-credentialkeys.h"

typedef struct _MSV1_0_PRIMARY_CREDENTIAL { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName;
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	BOOLEAN isShaOwPassword;
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL, *PMSV1_0_PRIMARY_CREDENTIAL;

typedef struct _MSV1_0_PRIMARY_CREDENTIAL_10_OLD { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName;
	BOOLEAN isIso;
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	BOOLEAN isShaOwPassword;
	BYTE align0;
	BYTE align1;
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL_10_OLD, *PMSV1_0_PRIMARY_CREDENTIAL_10_OLD;

typedef struct _MSV1_0_PRIMARY_CREDENTIAL_10 { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName;
	BOOLEAN isIso;
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	BOOLEAN isShaOwPassword;
	BYTE align0;
	BYTE align1;
	BYTE align2;
	BYTE align3;
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL_10, *PMSV1_0_PRIMARY_CREDENTIAL_10;

typedef struct _MSV1_0_PRIMARY_CREDENTIAL_10_1607 { 
	LSA_UNICODE_STRING LogonDomainName; 
	LSA_UNICODE_STRING UserName;
	PVOID pNtlmCredIsoInProc;
	BOOLEAN isIso;
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	BOOLEAN isShaOwPassword;
	BOOLEAN isDPAPIProtected;
	BYTE align0;
	BYTE align1;
	BYTE align2;
	DWORD unkD; // 1/2
	#pragma pack(push, 2)
	WORD isoSize;  // 0000
	BYTE DPAPIProtected[LM_NTLM_HASH_LENGTH];
	DWORD align3; // 00000000
	#pragma pack(pop) 
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL_10_1607, *PMSV1_0_PRIMARY_CREDENTIAL_10_1607;

typedef struct _MSV1_0_PRIMARY_HELPER {
	LONG offsetToLogonDomain;
	LONG offsetToUserName;
	LONG offsetToisIso;
	LONG offsetToisNtOwfPassword;
	LONG offsetToisLmOwfPassword;
	LONG offsetToisShaOwPassword;
	LONG offsetToisDPAPIProtected;
	LONG offsetToNtOwfPassword;
	LONG offsetToLmOwfPassword;
	LONG offsetToShaOwPassword;
	LONG offsetToDPAPIProtected;
	LONG offsetToIso;
} MSV1_0_PRIMARY_HELPER, *PMSV1_0_PRIMARY_HELPER;

typedef struct _MSV1_0_PTH_DATA_CRED { 
	PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pSecData;
	PSEKURLSA_PTH_DATA pthData;
} MSV1_0_PTH_DATA_CRED, *PMSV1_0_PTH_DATA_CRED;

typedef struct _MSV1_0_STD_DATA {
	PLUID						LogonId;
} MSV1_0_STD_DATA, *PMSV1_0_STD_DATA;

typedef BOOL (CALLBACK * PKUHL_M_SEKURLSA_MSV_CRED_CALLBACK) (IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS * pCredentials, IN DWORD AuthenticationPackageId, IN PKULL_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData);

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_msv_package;
NTSTATUS kuhl_m_sekurlsa_msv(int argc, wchar_t * argv[]);

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_msv(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_msv_pth(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData);

VOID kuhl_m_sekurlsa_msv_enum_cred(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN PVOID pCredentials, IN PKUHL_M_SEKURLSA_MSV_CRED_CALLBACK credCallback, IN PVOID optionalData);
BOOL CALLBACK kuhl_m_sekurlsa_msv_enum_cred_callback_std(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS * pCredentials, IN DWORD AuthenticationPackageId, IN PKULL_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData);
BOOL CALLBACK kuhl_m_sekurlsa_msv_enum_cred_callback_pth(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN struct _KIWI_MSV1_0_PRIMARY_CREDENTIALS * pCredentials, IN DWORD AuthenticationPackageId, IN PKULL_M_MEMORY_ADDRESS origBufferAddress, IN OPTIONAL LPVOID pOptionalData);

const MSV1_0_PRIMARY_HELPER * kuhl_m_sekurlsa_msv_helper(PKUHL_M_SEKURLSA_CONTEXT context);