/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_string.h"

const KUHL_M kuhl_m_sysenv;

NTSTATUS kuhl_m_sysenv_list(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sysenv_get(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sysenv_set(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sysenv_del(int argc, wchar_t * argv[]);

void kuhl_m_sysenv_display_attributes(DWORD attributes);
void kuhl_m_sysenv_display_vendorGuid(LPCGUID guid);

typedef struct _KUHL_M_SYSENV_GUID_STORE {
	const GUID guid;
	LPCWSTR name;
} KUHL_M_SYSENV_GUID_STORE, *PKUHL_M_SYSENV_GUID_STORE;

#define VARIABLE_ATTRIBUTE_NON_VOLATILE 0x00000001

#define VARIABLE_INFORMATION_NAMES  1
#define VARIABLE_INFORMATION_VALUES 2

typedef struct _VARIABLE_NAME {
    ULONG NextEntryOffset;
    GUID VendorGuid;
    WCHAR Name[ANYSIZE_ARRAY];
} VARIABLE_NAME, *PVARIABLE_NAME;

typedef struct _VARIABLE_NAME_AND_VALUE {
    ULONG NextEntryOffset;
    ULONG ValueOffset;
    ULONG ValueLength;
    ULONG Attributes;
    GUID VendorGuid;
    WCHAR Name[ANYSIZE_ARRAY];
    //UCHAR Value[ANYSIZE_ARRAY];
} VARIABLE_NAME_AND_VALUE, *PVARIABLE_NAME_AND_VALUE;

NTSYSCALLAPI NTSTATUS NTAPI NtQuerySystemEnvironmentValue (__in PUNICODE_STRING VariableName, __out_bcount(ValueLength) PWSTR VariableValue, __in USHORT ValueLength, __out_opt PUSHORT ReturnLength);
NTSYSCALLAPI NTSTATUS NTAPI NtSetSystemEnvironmentValue (__in PUNICODE_STRING VariableName, __in PUNICODE_STRING VariableValue);
NTSYSCALLAPI NTSTATUS NTAPI NtQuerySystemEnvironmentValueEx (__in PUNICODE_STRING VariableName, __in LPGUID VendorGuid, __out_bcount_opt(*ValueLength) PVOID Value, __inout PULONG ValueLength, __out_opt PULONG Attributes);
NTSYSCALLAPI NTSTATUS NTAPI NtSetSystemEnvironmentValueEx (__in PUNICODE_STRING VariableName, __in LPGUID VendorGuid, __in_bcount_opt(ValueLength) PVOID Value, __in ULONG ValueLength, __in ULONG Attributes);
NTSYSCALLAPI NTSTATUS NTAPI NtEnumerateSystemEnvironmentValuesEx (__in ULONG InformationClass, __out PVOID Buffer, __inout PULONG BufferLength);