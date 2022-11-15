/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_misc.h"
#include "../../../modules/kull_m_memory.h"
#include "../../../modules/kull_m_process.h"

extern const KUHL_M kuhl_m_misc_citrix;

#pragma pack(push, 4)
typedef struct _CITRIX_CREDENTIALS {
	wchar_t username[0x100];
	wchar_t domain[0x100];
	DWORD cbPassword;
	wchar_t password[0x100];
	DWORD dwFlags; // type ?
} CITRIX_CREDENTIALS, * PCITRIX_CREDENTIALS;

typedef struct _CITRIX_PACKED_CREDENTIALS {
	DWORD cbStruct;
	DWORD cbData;
	DWORD dwFlags;
	BYTE Data[SIZE_ALIGN(sizeof(CITRIX_CREDENTIALS), CRYPTPROTECTMEMORY_BLOCK_SIZE)];
} CITRIX_PACKED_CREDENTIALS, * PCITRIX_PACKED_CREDENTIALS;
#pragma pack(pop)

void kuhl_m_misc_citrix_logonpasswords(int argc, wchar_t* argv[]);

BOOL CALLBACK Citrix_Each_SSO_Program(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
void Citrix_SSO_Program_args(HANDLE hRemoteProcess, PCUNICODE_STRING puCommandLine);
void Citrix_SSO_Program_FileMapping(HANDLE hRemoteProcess, HANDLE hRemoteFileMapping);

void CitrixPasswordObfuscate(PBYTE pbData, DWORD cbData);
void CitrixPasswordDesobfuscate(PBYTE pbData, DWORD cbData);