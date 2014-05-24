/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../utils.h"

typedef PVOID SAMPR_HANDLE;

typedef enum _USER_INFORMATION_CLASS {
	UserInternal1Information = 18,
	UserAllInformation = 21,
} USER_INFORMATION_CLASS, *PUSER_INFORMATION_CLASS;

typedef struct _SAMPR_USER_INTERNAL1_INFORMATION {
	BYTE NTHash[LM_NTLM_HASH_LENGTH];
	BYTE LMHash[LM_NTLM_HASH_LENGTH];
	BYTE NtPasswordPresent;
	BYTE LmPasswordPresent;
	BYTE PasswordExpired;
	BYTE PrivateDataSensitive;
} SAMPR_USER_INTERNAL1_INFORMATION, *PSAMPR_USER_INTERNAL1_INFORMATION;

typedef union _SAMPR_USER_INFO_BUFFER {
	SAMPR_USER_INTERNAL1_INFORMATION Internal1;
} SAMPR_USER_INFO_BUFFER, *PSAMPR_USER_INFO_BUFFER;

typedef struct _LSA_SUPCREDENTIAL {
	DWORD	type;
	DWORD	size;
	DWORD	offset;
	DWORD	Reserved;
} LSA_SUPCREDENTIAL, *PLSA_SUPCREDENTIAL;

typedef struct _LSA_SUPCREDENTIALS {
	DWORD	count;
	DWORD	Reserved;
} LSA_SUPCREDENTIALS, *PLSA_SUPCREDENTIALS;

typedef struct _LSA_SUPCREDENTIALS_BUFFERS {
	LSA_SUPCREDENTIAL credential;
	NTSTATUS status;
	PVOID Buffer;
} LSA_SUPCREDENTIALS_BUFFERS, *PLSA_SUPCREDENTIALS_BUFFERS;

extern NTSTATUS WINAPI SamIConnect(IN PUNICODE_STRING ServerName, OUT SAMPR_HANDLE * ServerHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN Trusted);
extern NTSTATUS WINAPI SamrCloseHandle(IN SAMPR_HANDLE SamHandle);

extern NTSTATUS WINAPI LsaIQueryInformationPolicyTrusted(IN POLICY_INFORMATION_CLASS InformationClass, OUT PVOID *Buffer);
extern VOID WINAPI LsaIFree_LSAPR_POLICY_INFORMATION(IN POLICY_INFORMATION_CLASS InformationClass, IN PVOID Buffer);

extern NTSTATUS WINAPI SamIRetrievePrimaryCredentials(IN SAMPR_HANDLE UserHandle, IN LSA_UNICODE_STRING *Name, OUT LPVOID *Buffer, OUT DWORD *BufferSize);

extern NTSTATUS WINAPI SamrOpenDomain(IN SAMPR_HANDLE SamHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT SAMPR_HANDLE *DomainHandle);
extern NTSTATUS WINAPI SamrOpenUser(IN SAMPR_HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN DWORD UserId, OUT SAMPR_HANDLE *UserHandle);
extern NTSTATUS WINAPI SamrQueryInformationUser(IN SAMPR_HANDLE UserHandle, IN USER_INFORMATION_CLASS UserInformationClass, OUT PSAMPR_USER_INFO_BUFFER *Buffer);
extern VOID WINAPI SamIFree_SAMPR_USER_INFO_BUFFER(IN PSAMPR_USER_INFO_BUFFER, IN USER_INFORMATION_CLASS UserInformationClass);

extern VOID WINAPI RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString);

DWORD WINAPI kuhl_sekurlsa_samsrv_thread(PREMOTE_LIB_FUNC lpParameter);