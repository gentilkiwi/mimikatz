/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_string.h"
#include "../modules/kull_m_token.h"
#include "../modules/kull_m_patch.h"
#include "../modules/kull_m_cred.h"
#include "../modules/kull_m_crypto_ngc.h"

const KUHL_M kuhl_m_vault;

NTSTATUS kuhl_m_vault_init();
NTSTATUS kuhl_m_vault_clean();

NTSTATUS kuhl_m_vault_list(int argc, wchar_t * argv[]);
void kuhl_m_vault_list_descVault(HANDLE hVault);
void kuhl_m_vault_list_descItemData(struct _VAULT_ITEM_DATA * pData);
NTSTATUS kuhl_m_vault_cred(int argc, wchar_t * argv[]);
void kuhl_m_vault_cred_tryEncrypted(PCREDENTIAL pCredential);

typedef struct _VAULT_GUID_STRING {
	const GUID guid;
	const wchar_t * text;
} VAULT_GUID_STRING, *PVAULT_GUID_STRING;

void CALLBACK kuhl_m_vault_list_descItem_PINLogonOrPicturePasswordOrBiometric(const VAULT_GUID_STRING * pGuidString, PVOID enumItem, PVOID getItem, BOOL is8); 
void CALLBACK kuhl_m_vault_list_descItem_ngc(const VAULT_GUID_STRING * pGuidString, PVOID enumItem, PVOID getItem, BOOL is8);
typedef void (CALLBACK * PSCHEMA_HELPER_FUNC) (const VAULT_GUID_STRING * pGuidString, PVOID enumItem, PVOID getItem, BOOL is8);

typedef struct _VAULT_SCHEMA_HELPER {
	VAULT_GUID_STRING guidString;
	PSCHEMA_HELPER_FUNC helper;
} VAULT_SCHEMA_HELPER, *PVAULT_SCHEMA_HELPER;

typedef enum _VAULT_PICTURE_PASSWORD_TYPE {
	PP_Point	= 0,
	PP_Line		= 1,
	PP_Circle	= 2,
} VAULT_PICTURE_PASSWORD_TYPE, *PVAULT_PICTURE_PASSWORD_TYPE;

typedef struct _VAULT_PICTURE_PASSWORD_POINT {
	POINT coord;
} VAULT_PICTURE_PASSWORD_POINT, *PVAULT_PICTURE_PASSWORD_POINT;

typedef struct _VAULT_PICTURE_PASSWORD_LINE {
	POINT start;
	POINT end;
} VAULT_PICTURE_PASSWORD_LINE, *PVAULT_PICTURE_PASSWORD_LINE;

typedef struct _VAULT_PICTURE_PASSWORD_CIRCLE {
	POINT coord;
	LONG size;
	BOOL clockwise;
} VAULT_PICTURE_PASSWORD_CIRCLE, *PVAULT_PICTURE_PASSWORD_CIRCLE;

typedef struct _VAULT_PICTURE_PASSWORD_ELEMENT {
	VAULT_PICTURE_PASSWORD_TYPE Type;
	union {
		VAULT_PICTURE_PASSWORD_POINT point;
		VAULT_PICTURE_PASSWORD_LINE line;
		VAULT_PICTURE_PASSWORD_CIRCLE circle;
	};
} VAULT_PICTURE_PASSWORD_ELEMENT, *PVAULT_PICTURE_PASSWORD_ELEMENT;

typedef struct _VAULT_BIOMETRIC_ELEMENT {
	ULONG headersize; //data offset
	ULONG usernameLength;
	ULONG domainnameLength;
} VAULT_BIOMETRIC_ELEMENT, *PVAULT_BIOMETRIC_ELEMENT;

typedef enum _VAULT_INFORMATION_TYPE {
	VaultInformation_Name		= 1,
	VaultInformation_Path_7		= 8,
	VaultInformation_Path_8		= 4,
} VAULT_INFORMATION_TYPE, *PVAULT_INFORMATION_TYPE;

typedef struct _VAULT_INFORMATION {
	VAULT_INFORMATION_TYPE type;
	union {
		PWSTR string;
		GUID guid;
		BOOL status;
		DWORD time;
		struct {
			DWORD nbGuid;
			GUID * guids;
		};
	};
} VAULT_INFORMATION, *PVAULT_INFORMATION;

typedef enum _VAULT_ELEMENT_TYPE {
	ElementType_Boolean			= 0x00,
	ElementType_Short			= 0x01,
	ElementType_UnsignedShort	= 0x02,
	ElementType_Integer			= 0x03,
	ElementType_UnsignedInteger	= 0x04,
	ElementType_Double			= 0x05,
	ElementType_Guid			= 0x06,
	ElementType_String			= 0x07,
	ElementType_ByteArray		= 0x08,
	ElementType_TimeStamp		= 0x09,
	ElementType_ProtectedArray	= 0x0a,
	ElementType_Attribute		= 0x0b,
	ElementType_Sid				= 0x0c,
	ElementType_Max				= 0x0d,
} VAULT_ELEMENT_TYPE, *PVAULT_ELEMENT_TYPE;

typedef struct _VAULT_BYTE_BUFFER {
	DWORD Length;
	PBYTE Value;
} VAULT_BYTE_BUFFER, *PVAULT_BYTE_BUFFER;

typedef struct _VAULT_CREDENTIAL_ATTRIBUTEW {
    LPWSTR  Keyword;
    DWORD Flags;
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
	DWORD badAlign;
#endif
    DWORD ValueSize;
    LPBYTE Value;
} VAULT_CREDENTIAL_ATTRIBUTEW, *PVAULT_CREDENTIAL_ATTRIBUTEW;

typedef struct _VAULT_ITEM_DATA {
	DWORD SchemaElementId;
	DWORD unk0;
	VAULT_ELEMENT_TYPE Type;
	DWORD unk1;
	union {
		BOOL Boolean;
		SHORT Short;
		WORD UnsignedShort;
		LONG Int;
		ULONG UnsignedInt;
		DOUBLE Double;
		GUID Guid;
		LPWSTR String;
		VAULT_BYTE_BUFFER ByteArray;
		VAULT_BYTE_BUFFER ProtectedArray;
		PVAULT_CREDENTIAL_ATTRIBUTEW Attribute;
		PSID Sid;
	} data;
} VAULT_ITEM_DATA, *PVAULT_ITEM_DATA;

typedef struct _VAULT_ITEM_7 {
	GUID SchemaId;
	PWSTR FriendlyName;
	PVAULT_ITEM_DATA Ressource;
	PVAULT_ITEM_DATA Identity;
	PVAULT_ITEM_DATA Authenticator;
	FILETIME LastWritten;
	DWORD Flags;
	DWORD cbProperties;
	PVAULT_ITEM_DATA Properties;
} VAULT_ITEM_7, *PVAULT_ITEM_7;

typedef struct _VAULT_ITEM_8 {
	GUID SchemaId;
	PWSTR FriendlyName;
	PVAULT_ITEM_DATA Ressource;
	PVAULT_ITEM_DATA Identity;
	PVAULT_ITEM_DATA Authenticator;
	PVAULT_ITEM_DATA PackageSid;
	FILETIME LastWritten;
	DWORD Flags;
	DWORD cbProperties;
	PVAULT_ITEM_DATA Properties;
} VAULT_ITEM_8, *PVAULT_ITEM_8;

typedef struct _VAULT_ITEM_TYPE {
	GUID ItemType;
	PVOID FriendlyName;
	PVOID unk1;
	PVOID unk2;
	PVOID unk3;
	DWORD cbUnk;
	PVOID Unk;
} VAULT_ITEM_TYPE, *PVAULT_ITEM_TYPE;

typedef NTSTATUS	(WINAPI * PVAULTENUMERATEVAULTS) (DWORD unk0, PDWORD cbVault, LPGUID *);
typedef NTSTATUS	(WINAPI * PVAULTFREE) (PVOID memory);
typedef NTSTATUS	(WINAPI * PVAULTOPENVAULT) (GUID * vaultGUID, DWORD unk0, PHANDLE vault);
typedef NTSTATUS	(WINAPI * PVAULTCLOSEVAULT) (PHANDLE vault);
typedef NTSTATUS	(WINAPI * PVAULTGETINFORMATION) (HANDLE vault, DWORD unk0, PVAULT_INFORMATION informations);
typedef NTSTATUS	(WINAPI * PVAULTENUMERATEITEMS) (HANDLE vault, DWORD unk0, PDWORD cbItems, PVOID * items);
typedef NTSTATUS	(WINAPI * PVAULTENUMERATEITEMTYPES) (HANDLE vault, DWORD unk0, PDWORD cbItemTypes, PVAULT_ITEM_TYPE * itemTypes);
typedef NTSTATUS	(WINAPI * PVAULTGETITEM7) (HANDLE vault, LPGUID SchemaId, PVAULT_ITEM_DATA Resource, PVAULT_ITEM_DATA Identity, HWND hWnd, DWORD Flags, PVAULT_ITEM_7 * pItem);
typedef NTSTATUS	(WINAPI * PVAULTGETITEM8) (HANDLE vault, LPGUID SchemaId, PVAULT_ITEM_DATA Resource, PVAULT_ITEM_DATA Identity, PVAULT_ITEM_DATA PackageSid, HWND hWnd, DWORD Flags, PVAULT_ITEM_8 * pItem);