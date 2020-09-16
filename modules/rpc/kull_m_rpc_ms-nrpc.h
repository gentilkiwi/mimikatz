#pragma once
#include "kull_m_rpc.h"
#include "../kull_m_samlib.h"

typedef wchar_t * LOGONSRV_HANDLE;
typedef struct _NETLOGON_CREDENTIAL {
	CHAR data[8]; 
} NETLOGON_CREDENTIAL, *PNETLOGON_CREDENTIAL;

typedef  enum _NETLOGON_SECURE_CHANNEL_TYPE {
	NullSecureChannel = 0,
	MsvApSecureChannel = 1,
	WorkstationSecureChannel = 2,
	TrustedDnsDomainSecureChannel = 3,
	TrustedDomainSecureChannel = 4,
	UasServerSecureChannel = 5,
	ServerSecureChannel = 6,
	CdcServerSecureChannel = 7
} NETLOGON_SECURE_CHANNEL_TYPE;

typedef struct _NETLOGON_AUTHENTICATOR {
	NETLOGON_CREDENTIAL Credential;
	DWORD Timestamp;
} NETLOGON_AUTHENTICATOR, *PNETLOGON_AUTHENTICATOR;

typedef struct _NL_TRUST_PASSWORD {
	WCHAR Buffer[256];
	ULONG Length;
} NL_TRUST_PASSWORD, *PNL_TRUST_PASSWORD;

NTSTATUS NetrServerReqChallenge(IN LOGONSRV_HANDLE PrimaryName, IN wchar_t *ComputerName, IN PNETLOGON_CREDENTIAL ClientChallenge, OUT PNETLOGON_CREDENTIAL ServerChallenge);
NTSTATUS NetrServerAuthenticate2(IN LOGONSRV_HANDLE PrimaryName, IN wchar_t *AccountName, IN NETLOGON_SECURE_CHANNEL_TYPE SecureChannelType, IN wchar_t *ComputerName, IN PNETLOGON_CREDENTIAL ClientCredential, OUT PNETLOGON_CREDENTIAL ServerCredential, IN OUT ULONG *NegotiateFlags);
NTSTATUS NetrServerPasswordSet2(IN LOGONSRV_HANDLE PrimaryName, IN wchar_t *AccountName, IN NETLOGON_SECURE_CHANNEL_TYPE SecureChannelType, IN wchar_t *ComputerName, IN PNETLOGON_AUTHENTICATOR Authenticator, OUT PNETLOGON_AUTHENTICATOR ReturnAuthenticator, IN PNL_TRUST_PASSWORD ClearNewPassword);
NTSTATUS NetrServerTrustPasswordsGet(IN LOGONSRV_HANDLE TrustedDcName, IN wchar_t *AccountName, IN NETLOGON_SECURE_CHANNEL_TYPE SecureChannelType, IN wchar_t *ComputerName, IN PNETLOGON_AUTHENTICATOR Authenticator, OUT PNETLOGON_AUTHENTICATOR ReturnAuthenticator, OUT PENCRYPTED_NT_OWF_PASSWORD EncryptedNewOwfPassword, OUT PENCRYPTED_NT_OWF_PASSWORD EncryptedOldOwfPassword);

extern handle_t hLogon;
extern RPC_IF_HANDLE logon_v1_0_c_ifspec;

handle_t __RPC_USER LOGONSRV_HANDLE_bind(IN LOGONSRV_HANDLE Name);
void __RPC_USER LOGONSRV_HANDLE_unbind(IN LOGONSRV_HANDLE Name, handle_t hLogon);