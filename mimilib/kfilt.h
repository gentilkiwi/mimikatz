/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "utils.h"

//typedef enum _DELTA_OPERATION_TYPE {
//	DeltaOperationCreateInDomain	= 1,
//	DeltaOperationSetInformation_a	= 2,
//	DeltaOperationDelete			= 3,
//	DeltaOperationAddMemberTo		= 4,
//	DeltaOperation_unknown5			= 5,
//	DeltaOperationRemoveMemberFrom	= 6,
//	DeltaOperationSetInformation_b	= 7,
//	DeltaOperationPassword			= 8,
//} DELTA_OPERATION_TYPE, *PDELTA_OPERATION_TYPE;
//
//typedef enum _DELTA_CATEGORY_TYPE {
//	DeltaCategoryDomain	= 1,
//	DeltaCategoryUser	= 2,
//	DeltaCategoryGroup	= 3,
//	DeltaCategoryAlias	= 4,
//} DELTA_CATEGORY_TYPE, *PDELTA_CATEGORY_TYPE;
//
//typedef struct _DELTA_OPERATION_PASSWORD {
//	DWORD unk0;
//	UNICODE_STRING UserName;
//	UNICODE_STRING description;
//	UNICODE_STRING FullName;
//	DWORD unk1;
//	DWORD PrimaryGroupId;
//	DWORD unk3;
//	UNICODE_STRING Password;
//	DWORD RelativeId;
//	DWORD unk4;
//	DWORD unk5;
//	DWORD unk6;	// 10002h
//} DELTA_OPERATION_PASSWORD, *PDELTA_OPERATION_PASSWORD;
//
//typedef struct _DELTA_OPERATION_DELETE {
//	UNICODE_STRING Name;
//	PVOID unk0;
//	PVOID unk1;
//	DWORD RelativeId;
//} DELTA_OPERATION_DELETE, *PDELTA_OPERATION_DELETE;
//
//typedef struct _DELTA_OPERATION_ADD_REMOVE_MEMBER {
//	PSID pSid;
//	DWORD RelativeId;
//	/**/
//} DELTA_OPERATION_ADD_REMOVE_MEMBER, *PDELTA_OPERATION_ADD_REMOVE_MEMBER;
//
//typedef struct _DELTA_OPERATION_DATA {
//	union {
//		DELTA_OPERATION_PASSWORD opPassword;
//		DELTA_OPERATION_ADD_REMOVE_MEMBER opMember;
//		DELTA_OPERATION_DELETE opDelete;
//	};
//} DELTA_OPERATION_DATA, *PDELTA_OPERATION_DATA;

BOOLEAN NTAPI kfilt_InitializeChangeNotify(void);
NTSTATUS NTAPI kfilt_PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword);
//NTSTATUS NTAPI kfilt_DeltaNotify(PSID pSid, DELTA_OPERATION_TYPE operation, DELTA_CATEGORY_TYPE category, ULONG RelativeId, PVOID data5, PDWORD a6, PDELTA_OPERATION_DATA data7);