#pragma once
#include "kull_m_rpc.h"
#include "kull_m_samlib.h"

typedef struct _KERB_SID_AND_ATTRIBUTES
{
	PISID Sid;
	ULONG Attributes;
} 	KERB_SID_AND_ATTRIBUTES, *PKERB_SID_AND_ATTRIBUTES;

typedef struct _KERB_VALIDATION_INFO
{
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
} 	KERB_VALIDATION_INFO, *PKERB_VALIDATION_INFO;

size_t PKERB_VALIDATION_INFO_AlignSize(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType);
void PKERB_VALIDATION_INFO_Encode(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType);
//void PKERB_VALIDATION_INFO_Decode(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType);
//void PKERB_VALIDATION_INFO_Free(handle_t _MidlEsHandle, PKERB_VALIDATION_INFO * _pType);