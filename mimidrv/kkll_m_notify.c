/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kkll_m_notify.h"

PVOID *PspCreateThreadNotifyRoutine = NULL, *PspCreateProcessNotifyRoutine = NULL, *PspLoadImageNotifyRoutine = NULL;
ULONG PspCreateThreadNotifyRoutineMax = 0, PspCreateProcessNotifyRoutineMax = 0, PspLoadImageNotifyRoutineMax = 0;

PVOID *CallbackListHeadOrCmpCallBackVector = NULL;
PKKLL_M_MEMORY_OFFSETS pCmpCallBackOffsets = NULL;
POBJECT_DIRECTORY *ObpTypeDirectoryObject = NULL;
PKKLL_M_MEMORY_OFFSETS pObpTypeDirectoryObjectOffsets = NULL;

#ifdef _M_X64
UCHAR PTRN_W23_Thread[] =	{0x66, 0x90, 0x66, 0x90, 0x48, 0x8b, 0xce, 0xe8};
UCHAR PTRN_WVI_Thread[] =	{0x49, 0x8b, 0x8c, 0x24, 0xf8, 0x01, 0x00, 0x00, 0x41, 0xb0, 0x01, 0x49, 0x8b, 0x94, 0x24, 0x88, 0x03, 0x00, 0x00};
UCHAR PTRN_WI7_Thread[] =	{0x41, 0xbf, 0x40, 0x00, 0x00, 0x00, 0x48, 0x8b, 0xcb, 0xe8};
UCHAR PTRN_WI8_Thread[] =	{0xbf, 0x40, 0x00, 0x00, 0x00, 0x48, 0x8b, 0xcb, 0xe8};
UCHAR PTRN_W81_Thread[] =	{0x41, 0xbf, 0x40, 0x00, 0x00, 0x00, 0x48, 0x8b, 0xcb, 0xe8};
KKLL_M_MEMORY_GENERIC ThreadReferences[] = {
	{KiwiOsIndex_2K3,	{sizeof(PTRN_W23_Thread), PTRN_W23_Thread},		L"PsReferencePrimaryToken",				L"CcSetBcbOwnerPointer",			{ -4,  8}},
	{KiwiOsIndex_VISTA,	{sizeof(PTRN_WVI_Thread), PTRN_WVI_Thread},		L"PsDereferenceKernelStack",			L"ExRaiseAccessViolation",			{-20, 64}},
	{KiwiOsIndex_7,		{sizeof(PTRN_WI7_Thread), PTRN_WI7_Thread},		L"PsDereferenceKernelStack",			L"MmIsVerifierEnabled",				{ -4, 64}},
	{KiwiOsIndex_8,		{sizeof(PTRN_WI8_Thread), PTRN_WI8_Thread},		L"PsAcquireProcessExitSynchronization",	L"FsRtlAddToTunnelCache",			{ -4, 64}},
	{KiwiOsIndex_BLUE,	{sizeof(PTRN_W81_Thread), PTRN_W81_Thread},		L"NtFindAtom",							L"RtlLookupAtomInAtomTable",		{ -4, 64}},
};
UCHAR PTRN_W23_Process[] =	{0x41, 0xbf, 0x08, 0x00, 0x00, 0x00, 0x49, 0x8b, 0xdf, 0x48, 0x8b, 0xce, 0xe8};
UCHAR PTRN_WVI_Process[] =	{0x48, 0x89, 0x4c, 0x24, 0x40, 0x41, 0xbe, 0x40, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x0c, 0xc1, 0xe8};
UCHAR PTRN_WI7_Process[] =	{0x4c, 0x8b, 0xf9, 0x48, 0x8d, 0x0c, 0xc1, 0xe8};
UCHAR PTRN_WI8_Process[] =	{0x8b, 0xc3, 0x48, 0x8d, 0x34, 0xc1, 0x48, 0x8b, 0xce, 0xe8};
UCHAR PTRN_W81_Process[] =	{0x48, 0x8d, 0x04, 0xc1, 0x48, 0x89, 0x45, 0x70, 0x48, 0x8b, 0xc8, 0xe8};
KKLL_M_MEMORY_GENERIC ProcessReferences[] = {
	{KiwiOsIndex_2K3,	{sizeof(PTRN_W23_Process), PTRN_W23_Process},	L"PsReferencePrimaryToken",				L"CcSetBcbOwnerPointer",			{ -4,  8}},
	{KiwiOsIndex_VISTA,	{sizeof(PTRN_WVI_Process), PTRN_WVI_Process},	L"SeCreateAccessStateEx",				L"PsReferenceImpersonationToken",	{ -4, 64}},
	{KiwiOsIndex_7,		{sizeof(PTRN_WI7_Process), PTRN_WI7_Process},	L"RtlAreAllAccessesGranted",			L"RtlGetIntegerAtom",				{ -4, 64}},
	{KiwiOsIndex_8,		{sizeof(PTRN_WI8_Process), PTRN_WI8_Process},	L"PsAcquireProcessExitSynchronization",	L"FsRtlAddToTunnelCache",			{ -4, 64}},
	{KiwiOsIndex_BLUE,	{sizeof(PTRN_W81_Process), PTRN_W81_Process},	L"NtFindAtom",							L"RtlLookupAtomInAtomTable",		{ -4, 64}},
};
UCHAR PTRN_W23_Image[] =	{0x4c, 0x8b, 0xf1, 0x48, 0x89, 0x78, 0x20, 0x4d, 0x8b, 0xe0, 0x4c, 0x8b, 0xea, 0xbd, 0x08, 0x00, 0x00, 0x00};
UCHAR PTRN_WVI_Image[] =	{0x4c, 0x8b, 0xf2, 0x41, 0x0f, 0xba, 0x6d, 0x00, 0x0a, 0x4c, 0x8b, 0xf9, 0x49, 0xc7, 0x00, 0x38, 0x00, 0x00, 0x00};
UCHAR PTRN_WI7_Image[] =	{0x41, 0x0f, 0xba, 0x6d, 0x00, 0x0a, 0xbb, 0x01, 0x00, 0x00, 0x00, 0x4c, 0x8b, 0xf2, 0x4c, 0x8b, 0xf9};
UCHAR PTRN_WI8_Image[] =	{0xbf, 0x08, 0x00, 0x00, 0x00, 0x41, 0x89, 0x06, 0x0f, 0x1f, 0x04, 0x00, 0x48, 0x8b, 0xcb, 0xe8};
UCHAR PTRN_W81_Image[] =	{0x41, 0xbe, 0x08, 0x00, 0x00, 0x00, 0x89, 0x06, 0x48, 0x8b, 0xcf, 0xe8};
KKLL_M_MEMORY_GENERIC ImageReferences[] = {
	{KiwiOsIndex_2K3,	{sizeof(PTRN_W23_Image), PTRN_W23_Image},		L"PsRemoveLoadImageNotifyRoutine",			L"PsSetLegoNotifyRoutine",			{ -4,  8}},
	{KiwiOsIndex_VISTA,	{sizeof(PTRN_WVI_Image), PTRN_WVI_Image},		L"NtRequestPort",							L"RtlQueryTimeZoneInformation",		{ -4,  8}},
	{KiwiOsIndex_7,		{sizeof(PTRN_WI7_Image), PTRN_WI7_Image},		L"FsRtlReleaseFile",						L"IoSetPartitionInformationEx",		{ -4,  8}},
	{KiwiOsIndex_8,		{sizeof(PTRN_WI8_Image), PTRN_WI8_Image},		L"ExSizeOfRundownProtectionCacheAware",		L"MmProbeAndLockProcessPages",		{ -4,  8}},
	{KiwiOsIndex_BLUE,	{sizeof(PTRN_W81_Image), PTRN_W81_Image},		L"NtFindAtom",								L"RtlLookupAtomInAtomTable",		{ -4,  8}},
};
UCHAR PTRN_W23_Object[] =	{0x40, 0x32, 0xf6, 0x4c, 0x89, 0x7c, 0x24, 0x78, 0x45, 0x33, 0xff, 0x4d, 0x85, 0xe4};
UCHAR PTRN_WVI_Object[] =	{0x41, 0x8a, 0xdf, 0x4c, 0x89, 0x7c, 0x24, 0x58, 0x4d, 0x3b, 0xe7, 0x88, 0x5c, 0x24, 0x66, 0x4c, 0x89, 0x7c, 0x24, 0x50, 0x49, 0x8b, 0xef, 0xc7, 0x44, 0x24, 0x68};
UCHAR PTRN_WI7_Object[] =	{0x41, 0x8a, 0xde, 0x44, 0x88, 0x74, 0x24, 0x47, 0x88, 0x5c, 0x24, 0x46, 0x4c, 0x89, 0x74, 0x24, 0x38, 0x4c, 0x89, 0x74, 0x24, 0x30, 0x49, 0x8b, 0xee, 0xc7, 0x44, 0x24, 0x48};
UCHAR PTRN_WI8_Object[] =	{0x41, 0x8a, 0xd8, 0x44, 0x88, 0x44, 0x24, 0x4f, 0x88, 0x5c, 0x24, 0x4e, 0x4c, 0x89, 0x44, 0x24, 0x38, 0x4d, 0x8b, 0xf0, 0x4c, 0x89, 0x44, 0x24, 0x30, 0xc7, 0x44, 0x24, 0x50};
UCHAR PTRN_W81_Object[] =	{0x41, 0x8a, 0xd8, 0x44, 0x88, 0x44, 0x24, 0x4f, 0x88, 0x5c, 0x24, 0x4e, 0x4c, 0x89, 0x44, 0x24, 0x38, 0x4d, 0x8b, 0xf0, 0x4c, 0x89, 0x44, 0x24, 0x30, 0xc7, 0x44, 0x24, 0x50};
KKLL_M_MEMORY_GENERIC ObjectReferences[] = {
	{KiwiOsIndex_2K3,	{sizeof(PTRN_W23_Object), PTRN_W23_Object},		L"ObCreateObjectType",						L"ObReferenceSecurityDescriptor",	{ -4, 0x078, 0x0d8}},
	{KiwiOsIndex_VISTA,	{sizeof(PTRN_WVI_Object), PTRN_WVI_Object},		L"ObRegisterCallbacks",						L"ObCreateObjectType",				{ -4, 0x010, 0x070, 0x228}},
	{KiwiOsIndex_7,		{sizeof(PTRN_WI7_Object), PTRN_WI7_Object},		L"ObUnRegisterCallbacks",					L"ObCreateObjectType",				{ -4, 0x010, 0x070, 0x0c0}},
	{KiwiOsIndex_8,		{sizeof(PTRN_WI8_Object), PTRN_WI8_Object},		L"ObCreateObjectType",						L"IoCreateController",				{ -4, 0x010, 0x070, 0x0c8}},
	{KiwiOsIndex_BLUE,	{sizeof(PTRN_W81_Object), PTRN_W81_Object},		L"ObCreateObjectType",						L"RtlRunOnceInitialize",			{ -4, 0x010, 0x070, 0x0c8}},
};
UCHAR PTRN_W23_Reg[] =	{0x49, 0x8d, 0x0c, 0xdc, 0x45, 0x33, 0xc0, 0x48, 0x8b, 0xd7, 0xe8};
UCHAR PTRN_WVI_Reg[] =	{0x48, 0x8b, 0xf0, 0x48, 0x89, 0x44, 0x24, 0x38, 0x48, 0x85, 0xc0, 0x0f, 0x84};
UCHAR PTRN_WI7_Reg[] =	{0x48, 0x8b, 0xf8, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0x3b, 0xc3, 0x0f, 0x84};
UCHAR PTRN_WI8_Reg[] =	{0x49, 0x8b, 0x04, 0x24, 0x48, 0x3b, 0x43, 0x18, 0x74};
UCHAR PTRN_W81_Reg[] =	{0x49, 0x8b, 0x04, 0x24, 0x48, 0x3b, 0x43, 0x18, 0x74};
KKLL_M_MEMORY_GENERIC RegReferences[] = {
	{KiwiOsIndex_2K3,	{sizeof(PTRN_W23_Reg), PTRN_W23_Reg},			L"CmRegisterCallback",						L"CmUnRegisterCallback",			{ -6}},
	{KiwiOsIndex_VISTA,	{sizeof(PTRN_WVI_Reg), PTRN_WVI_Reg},			L"CmUnRegisterCallback",					L"SeSetAuthorizationCallbacks",		{ -9, 0x030}},
	{KiwiOsIndex_7,		{sizeof(PTRN_WI7_Reg), PTRN_WI7_Reg},			L"CmUnRegisterCallback",					L"CmRegisterCallback",				{ -9, 0x028}},
	{KiwiOsIndex_8,		{sizeof(PTRN_WI8_Reg), PTRN_WI8_Reg},			L"CmSetCallbackObjectContext",				L"CmGetCallbackVersion",			{ -9, 0x028}},
	{KiwiOsIndex_BLUE,	{sizeof(PTRN_W81_Reg), PTRN_W81_Reg},			L"CmSetCallbackObjectContext",				L"DbgkLkmdUnregisterCallback",		{ -9, 0x028}},
};
#elif defined _M_IX86
UCHAR PTRN_WXP_Thread[] =	{0xc7, 0x45, 0xa4, 0x08, 0x00, 0x00, 0x00, 0xff, 0x75, 0xbc, 0xe8};
UCHAR PTRN_W23_Thread[] =	{0xc7, 0x45, 0xac, 0x08, 0x00, 0x00, 0x00, 0xff, 0x75, 0xd0, 0xe8};
UCHAR PTRN_WVI_Thread[] =	{0xc7, 0x45, 0x0c, 0x40, 0x00, 0x00, 0x00, 0x53, 0xe8};
UCHAR PTRN_WI7_Thread[] =	{0xc7, 0x45, 0x0c, 0x40, 0x00, 0x00, 0x00, 0x56, 0xe8};
UCHAR PTRN_WI8_Thread[] =	{0xbb, 0x40, 0x00, 0x00, 0x00, 0x8d, 0x1b, 0xe8};
UCHAR PTRN_W81_Thread[] =	{0xc7, 0x45, 0xa8, 0x40, 0x00, 0x00, 0x00, 0x8b, 0xcf, 0xe8};
KKLL_M_MEMORY_GENERIC ThreadReferences[] = {
	{KiwiOsIndex_XP,	{sizeof(PTRN_WXP_Thread), PTRN_WXP_Thread},		L"NtSetInformationProcess",					L"LdrEnumResources",				{ -4,  8}},
	{KiwiOsIndex_2K3,	{sizeof(PTRN_W23_Thread), PTRN_W23_Thread},		L"NtSetInformationProcess",					L"LdrEnumResources",				{ -4,  8}},
	{KiwiOsIndex_VISTA,	{sizeof(PTRN_WVI_Thread), PTRN_WVI_Thread},		L"RtlValidSid",								L"NtOpenThreadTokenEx",				{ -4, 64}},
	{KiwiOsIndex_7,		{sizeof(PTRN_WI7_Thread), PTRN_WI7_Thread},		L"RtlCompareUnicodeStrings",				L"ObQueryNameString",				{ -4, 64}},
	{KiwiOsIndex_8,		{sizeof(PTRN_WI8_Thread), PTRN_WI8_Thread},		L"PsAssignImpersonationToken",				L"NtFindAtom",						{ -4, 64}},
	{KiwiOsIndex_BLUE,	{sizeof(PTRN_W81_Thread), PTRN_W81_Thread},		L"RtlGetIntegerAtom",						L"PsGetThreadSessionId",			{ -4, 64}},
};
UCHAR PTRN_WXP_Process[] =	{0xc7, 0x45, 0xb0, 0x08, 0x00, 0x00, 0x00, 0xff, 0x75, 0xcc, 0xe8};
UCHAR PTRN_W23_Process[] =	{0xc7, 0x45, 0xb0, 0x08, 0x00, 0x00, 0x00, 0xff, 0x75, 0xc8, 0xe8};
UCHAR PTRN_WVI_Process[] =	{0x89, 0x4d, 0x20, 0xff, 0x75, 0x18, 0xe8};
UCHAR PTRN_WI7_Process[] =	{0x83, 0x65, 0x30, 0x00, 0xff, 0x75, 0x20, 0xe8};
UCHAR PTRN_WI8_Process[] =	{0x83, 0xc0, 0x40, 0x89, 0x85, 0x58, 0xff, 0xff, 0xff, 0x8d, 0x85, 0x3c, 0xff, 0xff, 0xff, 0x89, 0x45, 0x9c, 0xbe};
UCHAR PTRN_W81_Process[] =	{0x89, 0x45, 0x9c, 0x83, 0x65, 0x8c, 0x00, 0x8b, 0xc8, 0xe8};
KKLL_M_MEMORY_GENERIC ProcessReferences[] = {
	{KiwiOsIndex_XP,	{sizeof(PTRN_WXP_Process), PTRN_WXP_Process},	L"NtSetInformationProcess",					L"LdrEnumResources",				{ -4,  8}},
	{KiwiOsIndex_2K3,	{sizeof(PTRN_W23_Process), PTRN_W23_Process},	L"NtSetInformationProcess",					L"LdrEnumResources",				{ -4,  8}},
	{KiwiOsIndex_VISTA,	{sizeof(PTRN_WVI_Process), PTRN_WVI_Process},	L"RtlValidSid",								L"NtOpenThreadTokenEx",				{ -4, 64}},
	{KiwiOsIndex_7,		{sizeof(PTRN_WI7_Process), PTRN_WI7_Process},	L"RtlCompareUnicodeStrings",				L"ObQueryNameString",				{ -4, 64}},
	{KiwiOsIndex_8,		{sizeof(PTRN_WI8_Process), PTRN_WI8_Process},	L"PsAssignImpersonationToken",				L"NtFindAtom",						{ 19, 64}},
	{KiwiOsIndex_BLUE,	{sizeof(PTRN_W81_Process), PTRN_W81_Process},	L"RtlGetIntegerAtom",						L"PsGetThreadSessionId",			{ -4, 64}},
};
UCHAR PTRN_WXP_Image[] =	{0x53, 0x56, 0x57, 0x6a, 0x08, 0xbf};
UCHAR PTRN_W23_Image[] =	{0x53, 0x56, 0x57, 0x6a, 0x08, 0xbf};
UCHAR PTRN_WVI_Image[] =	{0xc7, 0x45, 0xfc, 0x08, 0x00, 0x00, 0x00, 0xff, 0x75, 0x10, 0xe8};
UCHAR PTRN_WI7_Image[] =	{0xc7, 0x45, 0xfc, 0x08, 0x00, 0x00, 0x00, 0xff, 0x75, 0x10, 0xe8};
UCHAR PTRN_WI8_Image[] =	{0xbb, 0x08, 0x00, 0x00, 0x00, 0x8b, 0xff, 0xe8};
UCHAR PTRN_W81_Image[] =	{0xc7, 0x45, 0x0c, 0x08, 0x00, 0x00, 0x00, 0x8b, 0xcf, 0xe8};
KKLL_M_MEMORY_GENERIC ImageReferences[] = {
	{KiwiOsIndex_XP,	{sizeof(PTRN_WXP_Image), PTRN_WXP_Image},		L"PsRemoveLoadImageNotifyRoutine",			L"PsCreateSystemProcess",			{  6,  8}},
	{KiwiOsIndex_2K3,	{sizeof(PTRN_W23_Image), PTRN_W23_Image},		L"PsRemoveLoadImageNotifyRoutine",			L"PsCreateSystemThread",			{  6,  8}},
	{KiwiOsIndex_VISTA,	{sizeof(PTRN_WVI_Image), PTRN_WVI_Image},		L"RtlUpcaseUnicodeStringToCountedOemString",L"IoCheckShareAccessEx",			{ -4,  8}},
	{KiwiOsIndex_7,		{sizeof(PTRN_WI7_Image), PTRN_WI7_Image},		L"RtlCopySidAndAttributesArray",			L"SeImpersonateClientEx",			{ -4,  8}},
	{KiwiOsIndex_8,		{sizeof(PTRN_WI8_Image), PTRN_WI8_Image},		L"PsAssignImpersonationToken",				L"NtFindAtom",						{ -4,  8}},
	{KiwiOsIndex_BLUE,	{sizeof(PTRN_W81_Image), PTRN_W81_Image},		L"RtlGetIntegerAtom",						L"PsGetThreadSessionId",			{ -4,  8}},
};
UCHAR PTRN_WXP_Object[] =	{0x3b, 0xfb, 0xc6, 0x45, 0xe6, 0x00, 0x89, 0x5d, 0xe0, 0x89, 0x5d, 0xdc, 0xc7, 0x45, 0xe8};
UCHAR PTRN_W23_Object[] =	{0x3b, 0xfb, 0xc6, 0x45, 0xe6, 0x00, 0x89, 0x5d, 0xdc, 0x89, 0x5d, 0xd8, 0xc7, 0x45, 0xe8};
UCHAR PTRN_WVI_Object[] =	{0x3b, 0xc3, 0x88, 0x5c, 0x24, 0x3a, 0x89, 0x5c, 0x24, 0x30, 0x89, 0x5c, 0x24, 0x2c, 0xc7, 0x44, 0x24, 0x3c};
UCHAR PTRN_WI7_Object[] =	{0xc6, 0x44, 0x24, 0x22, 0x00, 0xc6, 0x44, 0x24, 0x23, 0x00, 0x89, 0x74, 0x24, 0x18, 0x89, 0x74, 0x24, 0x14, 0xc7, 0x44, 0x24, 0x24};
UCHAR PTRN_WI8_Object[] =	{0x33, 0xc0, 0x8b, 0xf8, 0x66, 0x89, 0x44, 0x24, 0x2a, 0x89, 0x44, 0x24, 0x1c, 0x89, 0x7c, 0x24, 0x18, 0xc7, 0x44, 0x24, 0x2c};
UCHAR PTRN_W81_Object[] =	{0x8d, 0x44, 0x24, 0x14, 0x50, 0x33, 0xc0, 0x89, 0x7c, 0x24, 0x18, 0x50, 0x6a, 0x40};
KKLL_M_MEMORY_GENERIC ObjectReferences[] = {
	{KiwiOsIndex_XP,	{sizeof(PTRN_WXP_Object), PTRN_WXP_Object},		L"ObCreateObjectType",						L"NtOpenThread",					{ -4, 0x040, 0x08c}},
	{KiwiOsIndex_2K3,	{sizeof(PTRN_W23_Object), PTRN_W23_Object},		L"ObCreateObjectType",						L"NtOpenThread",					{ -4, 0x040, 0x08c}},
	{KiwiOsIndex_VISTA,	{sizeof(PTRN_WVI_Object), PTRN_WVI_Object},		L"ObCreateObjectType",						L"RtlInvertRangeList",				{ -4, 0x008, 0x058, 0x138}},
	{KiwiOsIndex_7,		{sizeof(PTRN_WI7_Object), PTRN_WI7_Object},		L"ObCreateObjectType",						L"RtlInvertRangeList",				{ -4, 0x008, 0x058, 0x080}},
	{KiwiOsIndex_8,		{sizeof(PTRN_WI8_Object), PTRN_WI8_Object},		L"ObCreateObjectType",						L"SeTokenIsAdmin",					{ -4, 0x008, 0x058, 0x088}},
	{KiwiOsIndex_BLUE,	{sizeof(PTRN_W81_Object), PTRN_W81_Object},		L"ObCreateObjectType",						L"KseRegisterShim",					{ -4, 0x008, 0x058, 0x088}},
};
UCHAR PTRN_WXP_Reg[] =	{0x89, 0x7d, 0x10, 0x57, 0xff, 0x75, 0xfc, 0xff, 0x75, 0x08, 0xe8};
UCHAR PTRN_W23_Reg[] =	{0x89, 0x5d, 0x08, 0x53, 0xff, 0x75, 0xfc, 0x57, 0xe8};
UCHAR PTRN_WVI_Reg[] =	{0x8b, 0x03, 0x8b, 0x4b, 0x04, 0x3b, 0x46, 0x10, 0x75};
UCHAR PTRN_WI7_Reg[] =	{0x8b, 0x03, 0x8b, 0x4b, 0x04, 0x3b, 0x46, 0x10, 0x75};
UCHAR PTRN_WI8_Reg[] =	{0x53, 0x8d, 0x55, 0xd0, 0x8b, 0xce, 0xe8};
UCHAR PTRN_W81_Reg[] =	{0x8b, 0x08, 0x8b, 0x40, 0x04, 0x3b, 0x4e, 0x10, 0x75};
KKLL_M_MEMORY_GENERIC RegReferences[] = {
	{KiwiOsIndex_XP,	{sizeof(PTRN_WXP_Reg), PTRN_WXP_Reg},			L"CmRegisterCallback",						L"FsRtlMdlReadDev",					{ -4}},
	{KiwiOsIndex_2K3,	{sizeof(PTRN_W23_Reg), PTRN_W23_Reg},			L"CmRegisterCallback",						L"FsRtlCopyRead",					{ -4}},
	{KiwiOsIndex_VISTA,	{sizeof(PTRN_WVI_Reg), PTRN_WVI_Reg},			L"CmSetCallbackObjectContext",				L"EmClientRuleRegisterNotification",{ -8, 0x01c}},
	{KiwiOsIndex_7,		{sizeof(PTRN_WI7_Reg), PTRN_WI7_Reg},			L"CmSetCallbackObjectContext",				L"DbgkLkmdUnregisterCallback",		{ -8, 0x01c}},
	{KiwiOsIndex_8,		{sizeof(PTRN_WI8_Reg), PTRN_WI8_Reg},			L"CmUnRegisterCallback",					L"FsRtlIsFatDbcsLegal",				{ -4, 0x01c}},
	{KiwiOsIndex_BLUE,	{sizeof(PTRN_W81_Reg), PTRN_W81_Reg},			L"CmSetCallbackObjectContext",				L"DbgkLkmdUnregisterCallback",		{ -8, 0x01c}},
};
#endif

NTSTATUS kkll_m_notify_list(PKIWI_BUFFER outBuffer, PKKLL_M_MEMORY_GENERIC generics, SIZE_T cbGenerics, PUCHAR * ptr, PULONG pRoutineMax)
{
	NTSTATUS status = STATUS_SUCCESS;
	PKKLL_M_NOTIFY_CALLBACK pNotifyCallback;
	ULONG i;

	if(!*ptr)
		status = kkll_m_notify_search(generics, cbGenerics, ptr, pRoutineMax, NULL);

	if(*ptr)
	{
		for(i = 0; NT_SUCCESS(status) && (i < *pRoutineMax); i++)
		{
			if(pNotifyCallback = (PKKLL_M_NOTIFY_CALLBACK) KIWI_mask3bits(((PVOID *) *ptr)[i]))
			{
				status = kprintf(outBuffer, L"[%.2u] ", i);
				if(NT_SUCCESS(status))
					status = kkll_m_modules_fromAddr(outBuffer, pNotifyCallback->callback);
			}
		}
	}
	return status;
}

NTSTATUS kkll_m_notify_search(PKKLL_M_MEMORY_GENERIC generics, SIZE_T cbGenerics, PUCHAR * ptr, PULONG pRoutineMax, PKKLL_M_MEMORY_OFFSETS * pOffsets)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	PKKLL_M_MEMORY_GENERIC pGeneric;
	UNICODE_STRING stringStart, stringEnd;
	PUCHAR start, end;
	
	if(pGeneric = kkll_m_memory_getGenericFromBuild(generics, cbGenerics))
	{
		RtlInitUnicodeString(&stringStart, pGeneric->start);
		RtlInitUnicodeString(&stringEnd, pGeneric->end);
		start = (PUCHAR) MmGetSystemRoutineAddress(&stringStart);
		end = (PUCHAR) MmGetSystemRoutineAddress(&stringEnd);

		if(start && end)
		{
			status = kkll_m_memory_genericPointerSearch(ptr, start, end, pGeneric->Search.Pattern, pGeneric->Search.Length, pGeneric->Offsets.off0);
			if(NT_SUCCESS(status))
			{
				if(pRoutineMax)
					*pRoutineMax = pGeneric->Offsets.off1;
				if(pOffsets)
					*pOffsets = &pGeneric->Offsets;
			}
		}
	}
	return status;
}

NTSTATUS kkll_m_notify_list_thread(PKIWI_BUFFER outBuffer)
{
	return kkll_m_notify_list(outBuffer, ThreadReferences, ARRAYSIZE(ThreadReferences), (PUCHAR *) &PspCreateThreadNotifyRoutine, &PspCreateThreadNotifyRoutineMax);
}

NTSTATUS kkll_m_notify_list_process(PKIWI_BUFFER outBuffer)
{
	return kkll_m_notify_list(outBuffer, ProcessReferences, ARRAYSIZE(ProcessReferences), (PUCHAR *) &PspCreateProcessNotifyRoutine, &PspCreateProcessNotifyRoutineMax);
}

NTSTATUS kkll_m_notify_list_image(PKIWI_BUFFER outBuffer)
{
	return kkll_m_notify_list(outBuffer, ImageReferences, ARRAYSIZE(ImageReferences), (PUCHAR *) &PspLoadImageNotifyRoutine, &PspLoadImageNotifyRoutineMax);
}

NTSTATUS kkll_m_notify_list_reg(PKIWI_BUFFER outBuffer)
{
	NTSTATUS status = STATUS_SUCCESS;
	PKKLL_M_NOTIFY_CALLBACK pNotifyCallback;
	PLIST_ENTRY pEntry;
	ULONG i;

	if(!CallbackListHeadOrCmpCallBackVector)
		status = kkll_m_notify_search(RegReferences, ARRAYSIZE(RegReferences), (PUCHAR *) &CallbackListHeadOrCmpCallBackVector, NULL, &pCmpCallBackOffsets);
	
	if(CallbackListHeadOrCmpCallBackVector)
	{
		if(KiwiOsIndex < KiwiOsIndex_VISTA)
		{
			for(i = 0; NT_SUCCESS(status) && (i < CM_REG_MAX_CALLBACKS); i++)
			{
				if(pNotifyCallback = (PKKLL_M_NOTIFY_CALLBACK) KIWI_mask3bits(CallbackListHeadOrCmpCallBackVector[i]))
				{
					status = kprintf(outBuffer, L"[%.2u] ", i);
					if(NT_SUCCESS(status))
						status = kkll_m_modules_fromAddr(outBuffer, pNotifyCallback->callback);
				}
			}
		}
		else
		{
			for(pEntry = (PLIST_ENTRY) *CallbackListHeadOrCmpCallBackVector, i = 0 ; NT_SUCCESS(status) && (pEntry != (PLIST_ENTRY) CallbackListHeadOrCmpCallBackVector); pEntry = (PLIST_ENTRY) (pEntry->Flink), i++)
			{
				status = kprintf(outBuffer, L"[%.2u] ", i);
				if(NT_SUCCESS(status))
					status = kkll_m_modules_fromAddr(outBuffer, *(PVOID *) ((ULONG_PTR) pEntry + pCmpCallBackOffsets->off1));
			}
		}
	}
	return status;
}

const WCHAR *procCallToName[] = {
	L"Dump       ",
	L"Open       ",
	L"Close      ",
	L"Delete     ",
	L"Parse      ",
	L"Security   ",
	L"QueryName  ",
	L"OkayToClose",
};
NTSTATUS kkll_m_notify_list_object(PKIWI_BUFFER outBuffer)
{
	NTSTATUS status = STATUS_SUCCESS;
	POBJECT_DIRECTORY_ENTRY pEntry;
	ULONG_PTR pType;
	POBJECT_CALLBACK_ENTRY pCallbackEntry;
	ULONG i, j;
	PVOID miniProc;

	if(!ObpTypeDirectoryObject)
		status = kkll_m_notify_search(ObjectReferences, ARRAYSIZE(ObjectReferences), (PUCHAR *) &ObpTypeDirectoryObject, NULL, &pObpTypeDirectoryObjectOffsets);
	
	if(ObpTypeDirectoryObject)
	{
		for(i = 0; NT_SUCCESS(status) && (i < OBJECT_HASH_TABLE_SIZE); i++)
		{
			for(pEntry = (*ObpTypeDirectoryObject)->HashBuckets[i]; NT_SUCCESS(status) && pEntry; pEntry = pEntry->ChainLink)
			{
				if(pType = (ULONG_PTR) pEntry->Object)
				{
					status = kprintf(outBuffer, L"\n * %wZ\n", pType + pObpTypeDirectoryObjectOffsets->off1);
					if(KiwiOsIndex >= KiwiOsIndex_VISTA)
					{
						for(pCallbackEntry = *(POBJECT_CALLBACK_ENTRY *) (pType + pObpTypeDirectoryObjectOffsets->off3) ; NT_SUCCESS(status) && (pCallbackEntry != (POBJECT_CALLBACK_ENTRY) (pType + pObpTypeDirectoryObjectOffsets->off3)) ; pCallbackEntry = (POBJECT_CALLBACK_ENTRY) pCallbackEntry->CallbackList.Flink)
						{
							if(pCallbackEntry->PreOperation || pCallbackEntry->PostOperation)
							{
								status = kprintf(outBuffer, L"\t* Callback [type %u]\n", pCallbackEntry->Operations);
								if(NT_SUCCESS(status) && pCallbackEntry->PreOperation)
								{
									status = kprintf(outBuffer, L"\t\tPreOperation  : ");
									if(NT_SUCCESS(status))
										status = kkll_m_modules_fromAddr(outBuffer, pCallbackEntry->PreOperation);
								}
								if(NT_SUCCESS(status) && pCallbackEntry->PostOperation)
								{
									status = kprintf(outBuffer, L"\t\tPreOperation  : ");
									if(NT_SUCCESS(status))
										status = kkll_m_modules_fromAddr(outBuffer, pCallbackEntry->PostOperation);
								}
							}
						}
					}
					for(j = 0; NT_SUCCESS(status) && (j < 8) ; j++)
					{
						if(miniProc = *(PVOID *) (pType + pObpTypeDirectoryObjectOffsets->off2 + (sizeof(PVOID) * j)))
						{
							status = kprintf(outBuffer, L"\t%s - ", procCallToName[j]);
							if(NT_SUCCESS(status))
								status = kkll_m_modules_fromAddr(outBuffer, miniProc);
						}
					}
				}
			}
		}
	}
	return status;
}