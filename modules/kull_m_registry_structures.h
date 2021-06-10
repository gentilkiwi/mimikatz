/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"

#define KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_VOLATILE	0x0001
#define KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_MOUNT_POINT	0x0002
#define KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_ROOT		0x0004
#define KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_LOCKED		0x0008
#define KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_SYMLINK		0x0010
#define KULL_M_REGISTRY_HIVE_KEY_NAMED_FLAG_ASCII_NAME	0x0020

#define KULL_M_REGISTRY_HIVE_VALUE_KEY_FLAG_ASCII_NAME	0x0001

typedef struct _KULL_M_REGISTRY_HIVE_HEADER
{
	DWORD tag;
	DWORD seqPri;
	DWORD seqSec;
	FILETIME lastModification;
	DWORD versionMajor;
	DWORD versionMinor;
	DWORD fileType;
	DWORD unk0;
	LONG offsetRootKey;
	DWORD szData;
	DWORD unk1;
	BYTE unk2[64];
	BYTE unk3[396];
	DWORD checksum;
	BYTE padding[3584];
} KULL_M_REGISTRY_HIVE_HEADER, *PKULL_M_REGISTRY_HIVE_HEADER;

typedef struct _KULL_M_REGISTRY_HIVE_BIN_HEADER
{
	DWORD tag;
	LONG offsetHiveBin;
	DWORD szHiveBin;
	DWORD unk0;
	DWORD unk1;
	FILETIME timestamp;
	DWORD unk2;
} KULL_M_REGISTRY_HIVE_BIN_HEADER, *PKULL_M_REGISTRY_HIVE_BIN_HEADER;

typedef struct _KULL_M_REGISTRY_HIVE_BIN_CELL
{
	LONG szCell;
	union{
		WORD tag;
		BYTE data[ANYSIZE_ARRAY];
	};
} KULL_M_REGISTRY_HIVE_BIN_CELL, *PKULL_M_REGISTRY_HIVE_BIN_CELL;

typedef struct _KULL_M_REGISTRY_HIVE_KEY_NAMED
{
	LONG szCell;
	WORD tag;
	WORD flags;
	FILETIME lastModification;
	DWORD unk0;
	LONG offsetParentKey;
	DWORD nbSubKeys;
	DWORD nbVolatileSubKeys;
	LONG offsetSubKeys;
	LONG offsetVolatileSubkeys;
	DWORD nbValues;
	LONG offsetValues;
	LONG offsetSecurityKey;
	LONG offsetClassName;
	DWORD szMaxSubKeyName;
	DWORD szMaxSubKeyClassName;
	DWORD szMaxValueName;
	DWORD szMaxValueData;
	DWORD unk1;
	WORD szKeyName;
	WORD szClassName;
	BYTE keyName[ANYSIZE_ARRAY];
} KULL_M_REGISTRY_HIVE_KEY_NAMED, *PKULL_M_REGISTRY_HIVE_KEY_NAMED;

typedef struct _KULL_M_REGISTRY_HIVE_VALUE_KEY
{
	LONG szCell;
	WORD tag;
	WORD szValueName;
	DWORD szData;
	LONG offsetData;
	DWORD typeData;
	WORD flags;
	WORD __align;
	BYTE valueName[ANYSIZE_ARRAY];
} KULL_M_REGISTRY_HIVE_VALUE_KEY, *PKULL_M_REGISTRY_HIVE_VALUE_KEY;

typedef struct _KULL_M_REGISTRY_HIVE_LF_LH_ELEMENT
{
	LONG offsetNamedKey;
	DWORD hash;
} KULL_M_REGISTRY_HIVE_LF_LH_ELEMENT, *PKULL_M_REGISTRY_HIVE_LF_LH_ELEMENT;

typedef struct _KULL_M_REGISTRY_HIVE_LF_LH
{
	LONG szCell;
	WORD tag;
	WORD nbElements;
	KULL_M_REGISTRY_HIVE_LF_LH_ELEMENT elements[ANYSIZE_ARRAY];
} KULL_M_REGISTRY_HIVE_LF_LH, *PKULL_M_REGISTRY_HIVE_LF_LH;

typedef struct _KULL_M_REGISTRY_HIVE_VALUE_LIST
{
	LONG szCell;
	LONG offsetValue[ANYSIZE_ARRAY];
} KULL_M_REGISTRY_HIVE_VALUE_LIST, *PKULL_M_REGISTRY_HIVE_VALUE_LIST;