/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_process.h"

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllInformation,
	ObjectDataInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	// ...
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG Reserved [22];    // reserved for internal use
} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_BASIC_INFORMATION
{
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG Reserved[3];
	ULONG NameInfoSize;
	ULONG TypeInfoSize;
	ULONG SecurityDescriptorSize;
	LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _PUBLIC_OBJECT_BASIC_INFORMATION
{
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG Reserved[10];    // reserved for internal use
 } PUBLIC_OBJECT_BASIC_INFORMATION, *PPUBLIC_OBJECT_BASIC_INFORMATION;

extern NTSTATUS WINAPI NtQueryObject(IN OPTIONAL HANDLE Handle, IN OBJECT_INFORMATION_CLASS ObjectInformationClass, OUT OPTIONAL PVOID ObjectInformation, IN ULONG ObjectInformationLength, OUT OPTIONAL PULONG ReturnLength);

typedef struct _SYSTEM_HANDLE
{
	DWORD ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	DWORD HandleCount;
	SYSTEM_HANDLE Handles[ANYSIZE_ARRAY];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef BOOL (CALLBACK * PKULL_M_SYSTEM_HANDLE_ENUM_CALLBACK) (PSYSTEM_HANDLE pSystemHandle, PVOID pvArg);
typedef BOOL (CALLBACK * PKULL_M_HANDLE_ENUM_CALLBACK) (HANDLE handle, PSYSTEM_HANDLE pSystemHandle, PVOID pvArg);

typedef struct _HANDLE_ENUM_DATA
{
	PCUNICODE_STRING type;
	DWORD dwDesiredAccess;
	DWORD dwOptions;
	PKULL_M_HANDLE_ENUM_CALLBACK callBack;
	PVOID pvArg;
} HANDLE_ENUM_DATA, *PHANDLE_ENUM_DATA;

NTSTATUS kull_m_handle_getHandles(PKULL_M_SYSTEM_HANDLE_ENUM_CALLBACK callBack, PVOID pvArg);
NTSTATUS kull_m_handle_getHandlesOfType(PKULL_M_HANDLE_ENUM_CALLBACK callBack, LPCTSTR type, DWORD dwDesiredAccess, DWORD dwOptions, PVOID pvArg);

BOOL CALLBACK kull_m_handle_getHandlesOfType_callback(PSYSTEM_HANDLE pSystemHandle, PVOID pvArg);

BOOL kull_m_handle_GetUserObjectInformation(HANDLE hObj, int nIndex, PVOID *pvInfo, PDWORD nLength);