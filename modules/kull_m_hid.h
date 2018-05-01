/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"

#include <pshpack4.h>
typedef struct _HIDP_PREPARSED_DATA * PHIDP_PREPARSED_DATA;

typedef USHORT USAGE, *PUSAGE;
typedef struct _HIDP_CAPS
{
	USAGE    Usage;
	USAGE    UsagePage;
	USHORT   InputReportByteLength;
	USHORT   OutputReportByteLength;
	USHORT   FeatureReportByteLength;
	USHORT   Reserved[17];

	USHORT   NumberLinkCollectionNodes;

	USHORT   NumberInputButtonCaps;
	USHORT   NumberInputValueCaps;
	USHORT   NumberInputDataIndices;

	USHORT   NumberOutputButtonCaps;
	USHORT   NumberOutputValueCaps;
	USHORT   NumberOutputDataIndices;

	USHORT   NumberFeatureButtonCaps;
	USHORT   NumberFeatureValueCaps;
	USHORT   NumberFeatureDataIndices;
} HIDP_CAPS, *PHIDP_CAPS;

typedef struct _HIDD_ATTRIBUTES {
	ULONG   Size;
	USHORT  VendorID;
	USHORT  ProductID;
	USHORT  VersionNumber;
} HIDD_ATTRIBUTES, *PHIDD_ATTRIBUTES;

extern void __stdcall HidD_GetHidGuid(__out LPGUID HidGuid);
extern NTSTATUS __stdcall HidP_GetCaps(__in PHIDP_PREPARSED_DATA PreparsedData, __out PHIDP_CAPS Capabilities);
extern BOOLEAN __stdcall HidD_GetAttributes(__in HANDLE HidDeviceObject, __out PHIDD_ATTRIBUTES Attributes);
extern BOOLEAN __stdcall HidD_GetPreparsedData(__in HANDLE HidDeviceObject, __out PHIDP_PREPARSED_DATA * PreparsedData);
extern BOOLEAN __stdcall HidD_FreePreparsedData(__in PHIDP_PREPARSED_DATA PreparsedData);
extern BOOLEAN __stdcall HidD_SetFeature(__in HANDLE HidDeviceObject, __in PVOID ReportBuffer, __in ULONG ReportBufferLength);
extern BOOLEAN __stdcall HidD_GetFeature(__in HANDLE HidDeviceObject, __out PVOID ReportBuffer, __in ULONG ReportBufferLength);
#include <poppack.h>

#ifdef _WIN64
#include <pshpack8.h>   // Assume 8-byte (64-bit) packing throughout
#else
#include <pshpack1.h>   // Assume byte packing throughout (32-bit processor)
#endif
#define DIGCF_DEFAULT           0x00000001  // only valid with DIGCF_DEVICEINTERFACE
#define DIGCF_PRESENT           0x00000002
#define DIGCF_ALLCLASSES        0x00000004
#define DIGCF_PROFILE           0x00000008
#define DIGCF_DEVICEINTERFACE   0x00000010

#define WINSETUPAPI DECLSPEC_IMPORT
typedef PVOID HDEVINFO;

typedef struct _SP_DEVINFO_DATA {
	DWORD cbSize;
	GUID  ClassGuid;
	DWORD DevInst;    // DEVINST handle
	ULONG_PTR Reserved;
} SP_DEVINFO_DATA, *PSP_DEVINFO_DATA;

typedef struct _SP_DEVICE_INTERFACE_DATA {
	DWORD cbSize;
	GUID  InterfaceClassGuid;
	DWORD Flags;
	ULONG_PTR Reserved;
} SP_DEVICE_INTERFACE_DATA, *PSP_DEVICE_INTERFACE_DATA;

typedef struct _SP_DEVICE_INTERFACE_DETAIL_DATA_W {
	DWORD  cbSize;
	WCHAR  DevicePath[ANYSIZE_ARRAY];
} SP_DEVICE_INTERFACE_DETAIL_DATA_W, *PSP_DEVICE_INTERFACE_DETAIL_DATA_W, SP_DEVICE_INTERFACE_DETAIL_DATA, *PSP_DEVICE_INTERFACE_DETAIL_DATA;

extern WINSETUPAPI HDEVINFO WINAPI SetupDiGetClassDevsW(__in_opt CONST GUID *ClassGuid, __in_opt PCWSTR Enumerator, __in_opt HWND hwndParent, __in DWORD Flags);
extern WINSETUPAPI BOOL WINAPI SetupDiEnumDeviceInterfaces(__in HDEVINFO DeviceInfoSet, __in_opt PSP_DEVINFO_DATA DeviceInfoData, __in CONST GUID *InterfaceClassGuid, __in DWORD MemberIndex, __out PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData);
extern WINSETUPAPI BOOL WINAPI SetupDiGetDeviceInterfaceDetailW( __in HDEVINFO DeviceInfoSet, __in PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData, __out_bcount_opt(DeviceInterfaceDetailDataSize) PSP_DEVICE_INTERFACE_DETAIL_DATA_W DeviceInterfaceDetailData, __in DWORD DeviceInterfaceDetailDataSize, __out_opt PDWORD RequiredSize,  __out_opt PSP_DEVINFO_DATA DeviceInfoData);
extern WINSETUPAPI BOOL WINAPI SetupDiDestroyDeviceInfoList(__in HDEVINFO DeviceInfoSet);
extern WINSETUPAPI BOOL SetupDiGetDeviceRegistryPropertyW(__in HDEVINFO DeviceInfoSet, __in PSP_DEVINFO_DATA DeviceInfoData, __in DWORD Property, __out_opt PDWORD PropertyRegDataType, __out_opt PBYTE PropertyBuffer, __in DWORD PropertyBufferSize, __out_opt PDWORD RequiredSize);
extern WINSETUPAPI BOOL SetupDiEnumDeviceInfo(__in HDEVINFO DeviceInfoSet, __in DWORD MemberIndex, __out PSP_DEVINFO_DATA DeviceInfoData);

#define SetupDiGetClassDevs SetupDiGetClassDevsW
#define SetupDiGetDeviceInterfaceDetail SetupDiGetDeviceInterfaceDetailW
#define SetupDiGetDeviceRegistryProperty SetupDiGetDeviceRegistryPropertyW
#include <poppack.h>