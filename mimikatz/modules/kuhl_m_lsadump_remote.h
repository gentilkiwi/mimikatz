/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m_lsadump.h"
#include "../modules/kull_m_remotelib.h"

typedef struct _KIWI_SAMPR_USER_INTERNAL42_INFORMATION {
	SAMPR_USER_INTERNAL1_INFORMATION Internal1;
	DWORD cbPrivate;
	BYTE Private[ANYSIZE_ARRAY];
} KIWI_SAMPR_USER_INTERNAL42_INFORMATION, *PKIWI_SAMPR_USER_INTERNAL42_INFORMATION;

typedef NTSTATUS	(WINAPI * PLSAIQUERYINFORMATIONPOLICYTRUSTED) (IN POLICY_INFORMATION_CLASS InformationClass, OUT PVOID *Buffer);
typedef VOID		(WINAPI * PLSAIFREE_LSAPR_POLICY_INFORMATION) (IN POLICY_INFORMATION_CLASS InformationClass, IN PVOID Buffer);

typedef NTSTATUS	(WINAPI * PSAMICONNECT) (IN PUNICODE_STRING ServerName, OUT SAMPR_HANDLE * ServerHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN Trusted);
typedef NTSTATUS	(WINAPI * PSAMRCLOSEHANDLE) (IN SAMPR_HANDLE SamHandle);
typedef NTSTATUS	(WINAPI * PSAMIRETRIEVEPRIMARYCREDENTIALS) (IN SAMPR_HANDLE UserHandle, IN LSA_UNICODE_STRING *Name, OUT LPVOID *Buffer, OUT DWORD *BufferSize);
typedef NTSTATUS	(WINAPI * PSAMIGETPRIVATEDATA) (IN SAMPR_HANDLE UserHandle, IN PDWORD DataType, OUT DWORD *unk, OUT DWORD *BufferSize, OUT struct _KIWI_LSA_PRIVATE_DATA **Buffer);

typedef NTSTATUS	(WINAPI * PSAMROPENDOMAIN) (IN SAMPR_HANDLE SamHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT SAMPR_HANDLE *DomainHandle);
typedef NTSTATUS	(WINAPI * PSAMROPENUSER) (IN SAMPR_HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN DWORD UserId, OUT SAMPR_HANDLE *UserHandle);
typedef NTSTATUS	(WINAPI * PSAMRQUERYINFORMATIONUSER) (IN SAMPR_HANDLE UserHandle, IN USER_INFORMATION_CLASS UserInformationClass, OUT PSAMPR_USER_INFO_BUFFER *Buffer);
typedef VOID		(WINAPI * PSAMIFREE_SAMPR_USER_INFO_BUFFER) (IN PSAMPR_USER_INFO_BUFFER, IN USER_INFORMATION_CLASS UserInformationClass);

typedef LPVOID		(WINAPI * PVIRTUALALLOC) (__in_opt LPVOID lpAddress, __in     SIZE_T dwSize, __in     DWORD flAllocationType, __in     DWORD flProtect);
typedef HLOCAL		(WINAPI * PLOCALALLOC) (__in UINT uFlags, __in SIZE_T uBytes);
typedef HLOCAL		(WINAPI * PLOCALFREE) (__deref HLOCAL hMem);
typedef PVOID		(__cdecl * PMEMCPY) (__out_bcount_full_opt(_MaxCount) void * _Dst, __in_bcount_opt(_MaxCount) const void * _Src, __in size_t _MaxCount);

typedef NTSTATUS	(NTAPI * PLSAOPENPOLICY) (__in_opt PLSA_UNICODE_STRING SystemName, __in PLSA_OBJECT_ATTRIBUTES ObjectAttributes, __in ACCESS_MASK DesiredAccess, __out PLSA_HANDLE PolicyHandle);
typedef NTSTATUS	(NTAPI * PLSACLOSE) (__in LSA_HANDLE ObjectHandle);
typedef NTSTATUS	(NTAPI * PLSAFREEMEMORY) (__in_opt PVOID Buffer);
typedef NTSTATUS	(NTAPI * PLSARETRIEVEPRIVATEDATA) (__in LSA_HANDLE PolicyHandle, __in PLSA_UNICODE_STRING KeyName, __out PLSA_UNICODE_STRING * PrivateData);

DWORD WINAPI kuhl_sekurlsa_samsrv_thread(PREMOTE_LIB_DATA lpParameter);
DWORD kuhl_sekurlsa_samsrv_thread_end();