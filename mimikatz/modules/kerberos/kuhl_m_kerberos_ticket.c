/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_kerberos_ticket.h"

void kuhl_m_kerberos_ticket_display(PKIWI_KERBEROS_TICKET ticket, BOOL encodedTicketToo)
{
	kprintf(L"\n\t   Start/End/MaxRenew: ");
	kull_m_string_displayLocalFileTime(&ticket->StartTime); kprintf(L" ; ");
	kull_m_string_displayLocalFileTime(&ticket->EndTime); kprintf(L" ; ");
	kull_m_string_displayLocalFileTime(&ticket->RenewUntil);

	kuhl_m_kerberos_ticket_displayExternalName(L"\n\t   Service Name ", ticket->ServiceName, &ticket->DomainName);
	kuhl_m_kerberos_ticket_displayExternalName(L"\n\t   Target Name  ", ticket->TargetName, &ticket->TargetDomainName);
	kuhl_m_kerberos_ticket_displayExternalName(L"\n\t   Client Name  ", ticket->ClientName, &ticket->AltTargetDomainName);
	if(ticket->Description.Buffer)
		kprintf(L" ( %wZ )", &ticket->Description);
	kprintf(L"\n\t   Flags %08x    : ", ticket->TicketFlags);
	kuhl_m_kerberos_ticket_displayFlags(ticket->TicketFlags);
	kprintf(L"\n\t   Session Key       : 0x%08x - %s", ticket->KeyType, kuhl_m_kerberos_ticket_etype(ticket->KeyType));
	if(ticket->Key.Value)
	{
		kprintf(L"\n\t     ");
		kull_m_string_wprintf_hex(ticket->Key.Value, ticket->Key.Length, 0);
	}
	kprintf(L"\n\t   Ticket            : 0x%08x - %s ; kvno = %u", ticket->TicketEncType, kuhl_m_kerberos_ticket_etype(ticket->TicketEncType), ticket->TicketKvno);
	
	if(encodedTicketToo)
	{
		kprintf(L"\n\t     ");
		if(ticket->Ticket.Value)
			kull_m_string_wprintf_hex(ticket->Ticket.Value, ticket->Ticket.Length, 1);
		else PRINT_ERROR_AUTO(L"NULL Ticket Value !");
	}
	else kprintf(L"\t[...]");
}

const PCWCHAR TicketFlagsToStrings[] = {
	L"name_canonicalize", L"?", L"ok_as_delegate", L"?",
	L"hw_authent", L"pre_authent", L"initial", L"renewable",
	L"invalid", L"postdated", L"may_postdate", L"proxy",
	L"proxiable", L"forwarded", L"forwardable", L"reserved",
};
void kuhl_m_kerberos_ticket_displayFlags(ULONG flags)
{
	DWORD i;
	for(i = 0; i < 16; i++)
		if((flags >> (i + 16)) & 1)
			kprintf(L"%s ; ", TicketFlagsToStrings[i]);
}

void kuhl_m_kerberos_ticket_displayExternalName(IN LPCWSTR prefix, IN PKERB_EXTERNAL_NAME pExternalName, IN PUNICODE_STRING pDomain)
{
	USHORT i;
	if(prefix)
		kprintf(L"%s", prefix);
	if(pExternalName)
	{
		kprintf(L"(%02hu) : ", pExternalName->NameType);
		for(i = 0; i < pExternalName->NameCount; i++)
			kprintf(L"%wZ ; ", &pExternalName->Names[i]);
	}
	else kprintf(L"(--) : ");
	if(pDomain)
		kprintf(L"@ %wZ", pDomain);
}

PCWCHAR kuhl_m_kerberos_ticket_etype(LONG eType)
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

PDIRTY_ASN1_SEQUENCE_EASY kuhl_m_kerberos_ticket_createAppTicket(PKIWI_KERBEROS_TICKET ticket)
{
	PDIRTY_ASN1_SEQUENCE_EASY App_Ticket, Seq_Ticket, Ctx_Ticket;
	UCHAR integer1;
	
	if(App_Ticket = KULL_M_ASN1_CREATE_APP(ID_APP_TICKET))
	{
		if(Seq_Ticket = KULL_M_ASN1_CREATE_SEQ())
		{
			if(Ctx_Ticket = KULL_M_ASN1_CREATE_CTX(ID_CTX_TICKET_TKT_VNO))
			{
				integer1 = KERBEROS_VERSION;
				kull_m_asn1_create(DIRTY_ASN1_ID_INTEGER, &integer1, sizeof(UCHAR), &Ctx_Ticket);
				kull_m_asn1_append(&Seq_Ticket, Ctx_Ticket);
			}
			if(Ctx_Ticket = KULL_M_ASN1_CREATE_CTX(ID_CTX_TICKET_REALM))
			{
				kull_m_asn1_append(&Ctx_Ticket, kull_m_asn1_GenString(&ticket->DomainName));
				kull_m_asn1_append(&Seq_Ticket, Ctx_Ticket);
			}
			if(Ctx_Ticket = KULL_M_ASN1_CREATE_CTX(ID_CTX_TICKET_SNAME))
			{
				kull_m_asn1_append(&Ctx_Ticket, kuhl_m_kerberos_ticket_createSequencePrimaryName(ticket->ServiceName));
				kull_m_asn1_append(&Seq_Ticket, Ctx_Ticket);
			}
			if(Ctx_Ticket = KULL_M_ASN1_CREATE_CTX(ID_CTX_TICKET_ENC_PART))
			{
				kull_m_asn1_append(&Ctx_Ticket, kuhl_m_kerberos_ticket_createSequenceEncryptedData((UCHAR) ticket->TicketEncType, (UCHAR) ticket->TicketKvno, ticket->Ticket.Value, ticket->Ticket.Length));
				kull_m_asn1_append(&Seq_Ticket, Ctx_Ticket);
			}

			kull_m_asn1_append(&App_Ticket, Seq_Ticket);
		}
	}
	return App_Ticket;
}

PDIRTY_ASN1_SEQUENCE_EASY kuhl_m_kerberos_ticket_createAppKrbCred(PKIWI_KERBEROS_TICKET ticket)
{
	PDIRTY_ASN1_SEQUENCE_EASY App_KrbCred, Seq_KrbCred, Ctx_KrbCred, Seq_Root, App_EncKrbCredPart;
	UCHAR integer1;
	
	if(App_KrbCred = KULL_M_ASN1_CREATE_APP(ID_APP_KRB_CRED))
	{
		if(Seq_KrbCred = KULL_M_ASN1_CREATE_SEQ())
		{
			if(Ctx_KrbCred = KULL_M_ASN1_CREATE_CTX(ID_CTX_KRB_CRED_PVNO))
			{
				integer1 = KERBEROS_VERSION;
				kull_m_asn1_create(DIRTY_ASN1_ID_INTEGER, &integer1, sizeof(UCHAR), &Ctx_KrbCred);
				kull_m_asn1_append(&Seq_KrbCred, Ctx_KrbCred);
			}
			if(Ctx_KrbCred = KULL_M_ASN1_CREATE_CTX(ID_CTX_KRB_CRED_MSG_TYPE))
			{
				integer1 = ID_APP_KRB_CRED;
				kull_m_asn1_create(DIRTY_ASN1_ID_INTEGER, &integer1, sizeof(UCHAR), &Ctx_KrbCred);
				kull_m_asn1_append(&Seq_KrbCred, Ctx_KrbCred);
			}
			if(Ctx_KrbCred = KULL_M_ASN1_CREATE_CTX(ID_CTX_KRB_CRED_TICKETS))
			{
				if(Seq_Root = KULL_M_ASN1_CREATE_SEQ())
				{
					kull_m_asn1_append(&Seq_Root, kuhl_m_kerberos_ticket_createAppTicket(ticket));
					kull_m_asn1_append(&Ctx_KrbCred, Seq_Root);
				}
				kull_m_asn1_append(&Seq_KrbCred, Ctx_KrbCred);
			}
			if(Ctx_KrbCred = KULL_M_ASN1_CREATE_CTX(ID_CTX_KRB_CRED_ENC_PART))
			{
				if(App_EncKrbCredPart = kuhl_m_kerberos_ticket_createAppEncKrbCredPart(ticket))
				{
					kull_m_asn1_append(&Ctx_KrbCred, kuhl_m_kerberos_ticket_createSequenceEncryptedData(KERB_ETYPE_NULL, 0, App_EncKrbCredPart, kull_m_asn1_getSize(App_EncKrbCredPart)));
					LocalFree(App_EncKrbCredPart);
				}
				kull_m_asn1_append(&Seq_KrbCred, Ctx_KrbCred);
			}

			kull_m_asn1_append(&App_KrbCred, Seq_KrbCred);
		}
	}
	return App_KrbCred;
}

PDIRTY_ASN1_SEQUENCE_EASY kuhl_m_kerberos_ticket_createAppEncKrbCredPart(PKIWI_KERBEROS_TICKET ticket)
{
	PDIRTY_ASN1_SEQUENCE_EASY App_EncKrbCredPart, Seq_EncKrbCredPart, Ctx_TicketInfo, Seq_TicketInfo, Seq_KrbCredInfo, Ctx_Root;
	
	if(App_EncKrbCredPart = KULL_M_ASN1_CREATE_APP(ID_APP_ENCKRBCREDPART))
	{
		if(Seq_EncKrbCredPart = KULL_M_ASN1_CREATE_SEQ())
		{
			if(Ctx_TicketInfo = KULL_M_ASN1_CREATE_CTX(ID_CTX_ENCKRBCREDPART_TICKET_INFO))
			{
				if(Seq_TicketInfo = KULL_M_ASN1_CREATE_SEQ())
				{
					if(Seq_KrbCredInfo = KULL_M_ASN1_CREATE_SEQ())
					{
						if(Ctx_Root = KULL_M_ASN1_CREATE_CTX(ID_CTX_KRBCREDINFO_KEY))
						{
							kull_m_asn1_append(&Ctx_Root, kuhl_m_kerberos_ticket_createSequenceEncryptionKey((UCHAR) ticket->KeyType, ticket->Key.Value, ticket->Key.Length));
							kull_m_asn1_append(&Seq_KrbCredInfo, Ctx_Root);
						}
						if(Ctx_Root = KULL_M_ASN1_CREATE_CTX(ID_CTX_KRBCREDINFO_PREALM))
						{
							kull_m_asn1_append(&Ctx_Root, kull_m_asn1_GenString(&ticket->AltTargetDomainName));
							kull_m_asn1_append(&Seq_KrbCredInfo, Ctx_Root);
						}
						if(Ctx_Root = KULL_M_ASN1_CREATE_CTX(ID_CTX_KRBCREDINFO_PNAME))
						{
							kull_m_asn1_append(&Ctx_Root, kuhl_m_kerberos_ticket_createSequencePrimaryName(ticket->ClientName));
							kull_m_asn1_append(&Seq_KrbCredInfo, Ctx_Root);
						}
						if(Ctx_Root = KULL_M_ASN1_CREATE_CTX(ID_CTX_KRBCREDINFO_FLAGS))
						{
							kull_m_asn1_append(&Ctx_Root, kull_m_asn1_BitStringFromULONG(ticket->TicketFlags));
							kull_m_asn1_append(&Seq_KrbCredInfo, Ctx_Root);
						}
						/* ID_CTX_KRBCREDINFO_AUTHTIME not present */
						if(Ctx_Root = KULL_M_ASN1_CREATE_CTX(ID_CTX_KRBCREDINFO_STARTTIME))
						{
							kull_m_asn1_append(&Ctx_Root, kull_m_asn1_GenTime(&ticket->StartTime));
							kull_m_asn1_append(&Seq_KrbCredInfo, Ctx_Root);
						}
						if(Ctx_Root = KULL_M_ASN1_CREATE_CTX(ID_CTX_KRBCREDINFO_ENDTIME))
						{
							kull_m_asn1_append(&Ctx_Root, kull_m_asn1_GenTime(&ticket->EndTime));
							kull_m_asn1_append(&Seq_KrbCredInfo, Ctx_Root);
						}
						if(Ctx_Root = KULL_M_ASN1_CREATE_CTX(ID_CTX_KRBCREDINFO_RENEW_TILL))
						{
							kull_m_asn1_append(&Ctx_Root, kull_m_asn1_GenTime(&ticket->RenewUntil));
							kull_m_asn1_append(&Seq_KrbCredInfo, Ctx_Root);
						}
						if(Ctx_Root = KULL_M_ASN1_CREATE_CTX(ID_CTX_KRBCREDINFO_SREAL))
						{
							kull_m_asn1_append(&Ctx_Root, kull_m_asn1_GenString(&ticket->DomainName));
							kull_m_asn1_append(&Seq_KrbCredInfo, Ctx_Root);
						}
						if(Ctx_Root = KULL_M_ASN1_CREATE_CTX(ID_CTX_KRBCREDINFO_SNAME))
						{
							kull_m_asn1_append(&Ctx_Root, kuhl_m_kerberos_ticket_createSequencePrimaryName(ticket->ServiceName));
							kull_m_asn1_append(&Seq_KrbCredInfo, Ctx_Root);
						}

						kull_m_asn1_append(&Seq_TicketInfo, Seq_KrbCredInfo);
					}
					kull_m_asn1_append(&Ctx_TicketInfo, Seq_TicketInfo);
				}
				kull_m_asn1_append(&Seq_EncKrbCredPart, Ctx_TicketInfo);
			}
			kull_m_asn1_append(&App_EncKrbCredPart, Seq_EncKrbCredPart);
		}
	}
	return App_EncKrbCredPart;
}

PDIRTY_ASN1_SEQUENCE_EASY kuhl_m_kerberos_ticket_createAppEncTicketPart(PKIWI_KERBEROS_TICKET ticket, LPCVOID PacAuthData, DWORD PacAuthDataSize)
{
	PDIRTY_ASN1_SEQUENCE_EASY App_EncTicketPart, Seq_EncTicketPart, Ctx_EncTicketPart, Ctx_Root, Seq_1, Seq_2, Ctx_Child, Seq_3, Seq_4, OctetString;
	UCHAR integer1;	USHORT integer2;

	if(App_EncTicketPart = KULL_M_ASN1_CREATE_APP(ID_APP_ENCTICKETPART))
	{
		if(Seq_EncTicketPart = KULL_M_ASN1_CREATE_SEQ())
		{
			if(Ctx_EncTicketPart = KULL_M_ASN1_CREATE_CTX(ID_CTX_ENCTICKETPART_FLAGS))
			{
				kull_m_asn1_append(&Ctx_EncTicketPart, kull_m_asn1_BitStringFromULONG(ticket->TicketFlags));
				kull_m_asn1_append(&Seq_EncTicketPart, Ctx_EncTicketPart);
			}
			if(Ctx_EncTicketPart = KULL_M_ASN1_CREATE_CTX(ID_CTX_ENCTICKETPART_KEY))
			{
				kull_m_asn1_append(&Ctx_EncTicketPart, kuhl_m_kerberos_ticket_createSequenceEncryptionKey((UCHAR) ticket->KeyType, ticket->Key.Value, ticket->Key.Length));
				kull_m_asn1_append(&Seq_EncTicketPart, Ctx_EncTicketPart);
			}
			if(Ctx_EncTicketPart = KULL_M_ASN1_CREATE_CTX(ID_CTX_ENCTICKETPART_CREALM))
			{
				kull_m_asn1_append(&Ctx_EncTicketPart, kull_m_asn1_GenString(&ticket->AltTargetDomainName));
				kull_m_asn1_append(&Seq_EncTicketPart, Ctx_EncTicketPart);
			}
			if(Ctx_EncTicketPart = KULL_M_ASN1_CREATE_CTX(ID_CTX_ENCTICKETPART_CNAME))
			{
				kull_m_asn1_append(&Ctx_EncTicketPart, kuhl_m_kerberos_ticket_createSequencePrimaryName(ticket->ClientName));
				kull_m_asn1_append(&Seq_EncTicketPart, Ctx_EncTicketPart);
			}
			if(Ctx_EncTicketPart = KULL_M_ASN1_CREATE_CTX(ID_CTX_ENCTICKETPART_TRANSITED))
			{
				if(Seq_1 = KULL_M_ASN1_CREATE_SEQ())
				{
					if(Ctx_Root = KULL_M_ASN1_CREATE_CTX(ID_CTX_TRANSITEDENCODING_TR_TYPE))
					{
						integer1 = 0;
						kull_m_asn1_create(DIRTY_ASN1_ID_INTEGER, &integer1, sizeof(UCHAR), &Ctx_Root);
						kull_m_asn1_append(&Seq_1, Ctx_Root);
					}
					if(Ctx_Root = KULL_M_ASN1_CREATE_CTX(ID_CTX_TRANSITEDENCODING_CONTENTS))
					{
						kull_m_asn1_create(DIRTY_ASN1_ID_OCTET_STRING, NULL, 0, &Ctx_Root);
						kull_m_asn1_append(&Seq_1, Ctx_Root);
					}
					kull_m_asn1_append(&Ctx_EncTicketPart, Seq_1);
				}
				kull_m_asn1_append(&Seq_EncTicketPart, Ctx_EncTicketPart);
			}
			if(Ctx_EncTicketPart = KULL_M_ASN1_CREATE_CTX(ID_CTX_ENCTICKETPART_AUTHTIME))
			{
				kull_m_asn1_append(&Ctx_EncTicketPart, kull_m_asn1_GenTime(&ticket->StartTime)); // AuthTime = StartTime
				kull_m_asn1_append(&Seq_EncTicketPart, Ctx_EncTicketPart);
			}
			if(Ctx_EncTicketPart = KULL_M_ASN1_CREATE_CTX(ID_CTX_ENCTICKETPART_STARTTIME))
			{
				kull_m_asn1_append(&Ctx_EncTicketPart, kull_m_asn1_GenTime(&ticket->StartTime));
				kull_m_asn1_append(&Seq_EncTicketPart, Ctx_EncTicketPart);
			}
			if(Ctx_EncTicketPart = KULL_M_ASN1_CREATE_CTX(ID_CTX_ENCTICKETPART_ENDTIME))
			{
				kull_m_asn1_append(&Ctx_EncTicketPart, kull_m_asn1_GenTime(&ticket->EndTime));
				kull_m_asn1_append(&Seq_EncTicketPart, Ctx_EncTicketPart);
			}
			if(Ctx_EncTicketPart = KULL_M_ASN1_CREATE_CTX(ID_CTX_ENCTICKETPART_RENEW_TILL))
			{
				kull_m_asn1_append(&Ctx_EncTicketPart, kull_m_asn1_GenTime(&ticket->RenewUntil));
				kull_m_asn1_append(&Seq_EncTicketPart, Ctx_EncTicketPart);
			}
			/* ID_CTX_ENCTICKETPART_CADDR not present */
			if(Ctx_EncTicketPart = KULL_M_ASN1_CREATE_CTX(ID_CTX_ENCTICKETPART_AUTHORIZATION_DATA))
			{
				if(Seq_1 = KULL_M_ASN1_CREATE_SEQ())
				{
					if(Seq_2 = KULL_M_ASN1_CREATE_SEQ())
					{
						if(Ctx_Root = KULL_M_ASN1_CREATE_CTX(ID_CTX_AUTHORIZATIONDATA_AD_TYPE))
						{
							integer1 = ID_AUTHDATA_AD_IF_RELEVANT;
							kull_m_asn1_create(DIRTY_ASN1_ID_INTEGER, &integer1, sizeof(UCHAR), &Ctx_Root);
							kull_m_asn1_append(&Seq_2, Ctx_Root);
						}
						if(Ctx_Root = KULL_M_ASN1_CREATE_CTX(ID_CTX_AUTHORIZATIONDATA_AD_DATA))
						{
							if(OctetString = kull_m_asn1_create(DIRTY_ASN1_ID_OCTET_STRING, NULL, 0, NULL))
							{
								if(Seq_3 = KULL_M_ASN1_CREATE_SEQ())
								{
									if(Seq_4 = KULL_M_ASN1_CREATE_SEQ())
									{
										if(Ctx_Child = KULL_M_ASN1_CREATE_CTX(ID_CTX_AUTHORIZATIONDATA_AD_TYPE))
										{
											integer2 = _byteswap_ushort(ID_AUTHDATA_AD_WIN2K_PAC);
											kull_m_asn1_create(DIRTY_ASN1_ID_INTEGER, &integer2, sizeof(USHORT), &Ctx_Child);
											kull_m_asn1_append(&Seq_4, Ctx_Child);
										}
										if(Ctx_Child = KULL_M_ASN1_CREATE_CTX(ID_CTX_AUTHORIZATIONDATA_AD_DATA))
										{
											kull_m_asn1_create(DIRTY_ASN1_ID_OCTET_STRING, PacAuthData, PacAuthDataSize, &Ctx_Child);
											kull_m_asn1_append(&Seq_4, Ctx_Child);
										}
										kull_m_asn1_append(&Seq_3, Seq_4);
									}
									kull_m_asn1_append(&OctetString, Seq_3);
								}
								kull_m_asn1_append(&Ctx_Root, OctetString);
							}
							kull_m_asn1_append(&Seq_2, Ctx_Root);
						}
						kull_m_asn1_append(&Seq_1, Seq_2);
					}
					kull_m_asn1_append(&Ctx_EncTicketPart, Seq_1);
				}
				kull_m_asn1_append(&Seq_EncTicketPart, Ctx_EncTicketPart);
			}
			
			kull_m_asn1_append(&App_EncTicketPart, Seq_EncTicketPart);
		}
	}
	return App_EncTicketPart;
}

PDIRTY_ASN1_SEQUENCE_EASY kuhl_m_kerberos_ticket_createSequencePrimaryName(PKERB_EXTERNAL_NAME name)
{
	PDIRTY_ASN1_SEQUENCE_EASY Seq_ExternalName, Ctx_root, Seq_Names;
	UCHAR integer1;
	USHORT i;
	ANSI_STRING aString;

	if(Seq_ExternalName = KULL_M_ASN1_CREATE_SEQ())
	{
		if(Ctx_root = KULL_M_ASN1_CREATE_CTX(ID_CTX_PRINCIPALNAME_NAME_TYPE))
		{
			integer1 = (UCHAR) name->NameType;
			kull_m_asn1_create(DIRTY_ASN1_ID_INTEGER, &integer1, sizeof(UCHAR), &Ctx_root);
			kull_m_asn1_append(&Seq_ExternalName, Ctx_root);
		}
		if(Ctx_root = KULL_M_ASN1_CREATE_CTX(ID_CTX_PRINCIPALNAME_NAME_STRING))
		{
			if(Seq_Names = KULL_M_ASN1_CREATE_SEQ())
			{
				for(i = 0; i < name->NameCount; i++)
				{
					if(NT_SUCCESS(RtlUnicodeStringToAnsiString(&aString, &name->Names[i], TRUE)))
					{
						kull_m_asn1_create(DIRTY_ASN1_ID_GENERAL_STRING, aString.Buffer, aString.Length, &Seq_Names);
						RtlFreeAnsiString(&aString);
					}
				}
				kull_m_asn1_append(&Ctx_root, Seq_Names);
			}		
			kull_m_asn1_append(&Seq_ExternalName, Ctx_root);
		}
	}
	return Seq_ExternalName;
}

PDIRTY_ASN1_SEQUENCE_EASY kuhl_m_kerberos_ticket_createSequenceEncryptedData(UCHAR eType, UCHAR kvNo, LPCVOID data, DWORD size)
{
	PDIRTY_ASN1_SEQUENCE_EASY Seq_EncryptedData, Ctx_root;

	if(Seq_EncryptedData = KULL_M_ASN1_CREATE_SEQ())
	{
		if(Ctx_root = KULL_M_ASN1_CREATE_CTX(ID_CTX_ENCRYPTEDDATA_ETYPE))
		{
			kull_m_asn1_create(DIRTY_ASN1_ID_INTEGER, &eType, sizeof(UCHAR), &Ctx_root);
			kull_m_asn1_append(&Seq_EncryptedData, Ctx_root);
		}
		if(eType)
		{
			if(Ctx_root = KULL_M_ASN1_CREATE_CTX(ID_CTX_ENCRYPTEDDATA_KVNO))
			{
				kull_m_asn1_create(DIRTY_ASN1_ID_INTEGER, &kvNo, sizeof(UCHAR), &Ctx_root);
				kull_m_asn1_append(&Seq_EncryptedData, Ctx_root);
			}
		}
		if(Ctx_root = KULL_M_ASN1_CREATE_CTX(ID_CTX_ENCRYPTEDDATA_CIPHER))
		{
			kull_m_asn1_create(DIRTY_ASN1_ID_OCTET_STRING, data, size, &Ctx_root);
			kull_m_asn1_append(&Seq_EncryptedData, Ctx_root);
		}
	}
	return Seq_EncryptedData;
}

PDIRTY_ASN1_SEQUENCE_EASY kuhl_m_kerberos_ticket_createSequenceEncryptionKey(UCHAR eType, LPCVOID data, DWORD size)
{
	PDIRTY_ASN1_SEQUENCE_EASY Seq_EncryptionKey, Ctx_root;

	if(Seq_EncryptionKey = KULL_M_ASN1_CREATE_SEQ())
	{
		if(Ctx_root = KULL_M_ASN1_CREATE_CTX(ID_CTX_ENCRYPTIONKEY_KEYTYPE))
		{
			kull_m_asn1_create(DIRTY_ASN1_ID_INTEGER, &eType, sizeof(UCHAR), &Ctx_root);
			kull_m_asn1_append(&Seq_EncryptionKey, Ctx_root);
		}
		if(Ctx_root = KULL_M_ASN1_CREATE_CTX(ID_CTX_ENCRYPTIONKEY_KEYVALUE))
		{
			kull_m_asn1_create(DIRTY_ASN1_ID_OCTET_STRING, data, size, &Ctx_root);
			kull_m_asn1_append(&Seq_EncryptionKey, Ctx_root);
		}
	}
	return Seq_EncryptionKey;
}