/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m.h"
#include "../../../modules/kull_m_string.h"
#include "../../../modules/kull_m_service.h"
#include "../../../modules/kull_m_remotelib.h"
#include "../../../modules/kull_m_file.h"
#include "../../../modules/kull_m_crypto_ngc.h"
#include "../../../modules/kull_m_token.h"

const KUHL_M kuhl_m_ngc;

NTSTATUS kuhl_m_ngc_logondata(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_ngc_pin(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_ngc_sign(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_ngc_decrypt(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_ngc_enum(int argc, wchar_t * argv[]);

typedef struct _Node {
	struct _Node *Left;
	struct _Node *Parent;
	struct _Node *Right;
	BYTE Color;
	BYTE IsNil;
} Node, *PNode;

typedef struct _ValueGuidPtr {
	GUID guid;
	PVOID ptr;
} ValueGuidPtr, *PValueGuidPtr;

typedef struct _ValueUnkPtr {
	BYTE unkData[8];
	PVOID ptr;
} ValueUnkPtr, *PValueUnkPtr;

typedef struct _ValueProvider {
	PCWSTR Provider;
	PVOID unk0;
	DWORD cbProvider;
	DWORD unk1;
} ValueProvider, *PValueProvider;

typedef struct _ContainerManager {
	PWSTR Path;
	SIZE_T unk1;
	SIZE_T unk2;
	SIZE_T unk3;
	PVOID unk4;
	RTL_SRWLOCK SRWLock;
	PVOID unk7;
	DWORD unk8;
} ContainerManager, *PContainerManager;

typedef struct _unkF {
	PVOID unkVFTable;
	DWORD unk0;
	DWORD unk1;
	PVOID unk2;
	
	PVOID unkF0_0; // ff
	PVOID unkF0_1; // ff
	PVOID unkF0_2; // 0
	PVOID unkF0_3; // 0
	PVOID unkF0_4; // 20007D0

	PVOID unkF1_0; // ff
	PVOID unkF1_1; // ff
	PVOID unkF1_2; // 0
	PVOID unkF1_3; // 0
	PVOID unkF1_4; // 20007D0


	PVOID unk3;
	PVOID unk4;
	PVOID unk5;
	PWSTR ProfilePath;
	PBYTE unk6; // 16, 10 ?
	DWORD cbProfilePath; // ?
	DWORD unk7;
	DWORD unk8;
	DWORD unk9;
	PVOID t;
	BYTE z[0x88];
	PVOID u;
} unkF, *PunkF;

typedef struct _structToDecode {
	PBYTE toDecode;
	PVOID unk0;
	PVOID unk1;
	DWORD cb;
} structToDecode, *PstructToDecode;

typedef struct _structL {
	DWORD unk0;
	structToDecode d0; // ?
	structToDecode d1; // wut ?
	structToDecode d2; // pin here ?
} structL, *PstructL;

typedef struct _UNK_RAW_PIN {
	DWORD cbPin0;
	DWORD cbPin1;
	DWORD cbPin2;
	BYTE data[ANYSIZE_ARRAY];
} UNK_RAW_PIN, *PUNK_RAW_PIN;

typedef void (CALLBACK * PKUHL_M_NGC_ENUM_NODE_DATA) (IN PVOID pvData, IN DWORD szObject, IN PKULL_M_MEMORY_HANDLE hMemory, IN OPTIONAL PVOID pvOptionalData);

void kuhl_m_ngc_dealWithNode(PKULL_M_MEMORY_ADDRESS aNode, PVOID OrigMapAddress, PKUHL_M_NGC_ENUM_NODE_DATA Callback, DWORD szObject, PVOID CallbackData);