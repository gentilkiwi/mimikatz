/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_kerberos_ticket.h"

void kuhl_m_kerberos_ticket_display(PKIWI_KERBEROS_TICKET ticket, BOOL withKey, BOOL encodedTicketToo)
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
	if(withKey)
	{
		kprintf(L"\n\t   Session Key       : 0x%08x - %s", ticket->KeyType, kuhl_m_kerberos_ticket_etype(ticket->KeyType));
		if(ticket->Key.Value)
		{
			kprintf(L"\n\t     ");
			kull_m_string_wprintf_hex(ticket->Key.Value, ticket->Key.Length, 0);
		}
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
	for(i = 0; i < ARRAYSIZE(TicketFlagsToStrings); i++)
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

BOOL kuhl_m_kerberos_ticket_isLongFilename(PKIWI_KERBEROS_TICKET ticket)
{
	return ticket && (ticket->ClientName) && (ticket->ClientName->NameType == KRB_NT_PRINCIPAL) && (ticket->ClientName->NameCount == 1) && (ticket->ServiceName) && ((ticket->ServiceName->NameType >= KRB_NT_PRINCIPAL) && (ticket->ServiceName->NameType <= KRB_NT_SRV_HST)) && (ticket->ServiceName->NameCount > 1);
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

PCWCHAR kuhl_m_kerberos_ticket_ctype(LONG cType)
{
	PCWCHAR type;
	switch(cType)
	{
	case KERB_CHECKSUM_NONE:					type = L"none               "; break;
	case KERB_CHECKSUM_CRC32:					type = L"crc32              "; break;
	case KERB_CHECKSUM_MD4:						type = L"md4                "; break;
	case KERB_CHECKSUM_KRB_DES_MAC:				type = L"krb_des_mac        "; break;
	case KERB_CHECKSUM_KRB_DES_MAC_K:			type = L"krb_des_mac_k      "; break;
	case KERB_CHECKSUM_MD5:						type = L"md5                "; break;
	case KERB_CHECKSUM_MD5_DES:					type = L"md5_des            "; break;
	case KERB_CHECKSUM_SHA1_NEW:				type = L"sha1_new           "; break;
	case KERB_CHECKSUM_HMAC_SHA1_96_AES128:		type = L"hmac_sha1_aes128   "; break;
	case KERB_CHECKSUM_HMAC_SHA1_96_AES256:		type = L"hmac_sha1_aes256   "; break;
	case KERB_CHECKSUM_LM:						type = L"lm                 "; break;
	case KERB_CHECKSUM_SHA1:					type = L"sha1               "; break;
	case KERB_CHECKSUM_REAL_CRC32:				type = L"real_crc32         "; break;
	case KERB_CHECKSUM_DES_MAC:					type = L"dec_mac            "; break;
	case KERB_CHECKSUM_DES_MAC_MD5:				type = L"dec_mac_md5        "; break;
	case KERB_CHECKSUM_MD25:					type = L"md25               "; break;
	case KERB_CHECKSUM_RC4_MD5:					type = L"rc4_md5            "; break;
	case KERB_CHECKSUM_MD5_HMAC:				type = L"md5_hmac           "; break;
	case KERB_CHECKSUM_HMAC_MD5:				type = L"hmac_md5           "; break;
	case KERB_CHECKSUM_HMAC_SHA1_96_AES128_Ki:	type = L"hmac_sha1_aes128_ki"; break;
	case KERB_CHECKSUM_HMAC_SHA1_96_AES256_Ki:	type = L"hmac_sha1_aes256_ki"; break;
	default:									type = L"unknow             "; break;
	}
	return type;
}

void kuhl_m_kerberos_ticket_freeTicket(PKIWI_KERBEROS_TICKET ticket)
{
	if(ticket)
	{
		kuhl_m_kerberos_ticket_freeExternalName(ticket->ServiceName);
		kull_m_string_freeUnicodeStringBuffer(&ticket->DomainName);
		kuhl_m_kerberos_ticket_freeExternalName(ticket->TargetName);
		kull_m_string_freeUnicodeStringBuffer(&ticket->TargetDomainName);
		kuhl_m_kerberos_ticket_freeExternalName(ticket->ClientName);
		kull_m_string_freeUnicodeStringBuffer(&ticket->AltTargetDomainName);
		kull_m_string_freeUnicodeStringBuffer(&ticket->Description);
		kuhl_m_kerberos_ticket_freeKiwiKerberosBuffer(&ticket->Key);
		kuhl_m_kerberos_ticket_freeKiwiKerberosBuffer(&ticket->Ticket);
		LocalFree(ticket);
	}
}

PKERB_EXTERNAL_NAME kuhl_m_kerberos_ticket_copyExternalName(PKERB_EXTERNAL_NAME pName)
{
	PKERB_EXTERNAL_NAME dest = NULL;
	DWORD i;
	BOOL status = TRUE;
	if(pName)
	{
		if(dest = (PKERB_EXTERNAL_NAME) LocalAlloc(LPTR, sizeof(KERB_EXTERNAL_NAME) + ((pName->NameCount - 1) * sizeof(UNICODE_STRING))))
		{
			dest->NameType = pName->NameType;
			dest->NameCount = pName->NameCount;
			for(i = 0; i < pName->NameCount; i++)
				status &= kull_m_string_copyUnicodeStringBuffer(&pName->Names[i], &dest->Names[i]);

			if(!status)
				dest = (PKERB_EXTERNAL_NAME) LocalFree(dest);
		}
	}
	return dest;
}

void kuhl_m_kerberos_ticket_freeExternalName(PKERB_EXTERNAL_NAME pName)
{
	DWORD i;
	if(pName)
	{
		for(i = 0; i < pName->NameCount; i++)
			kull_m_string_freeUnicodeStringBuffer(&pName->Names[i]);
		pName = (PKERB_EXTERNAL_NAME) LocalFree(pName);
	}
}

void kuhl_m_kerberos_ticket_freeKiwiKerberosBuffer(PKIWI_KERBEROS_BUFFER pBuffer)
{
	if(pBuffer->Value)
		pBuffer->Value = (PUCHAR) LocalFree(pBuffer->Value);
}

PBERVAL kuhl_m_kerberos_ticket_createAppKrbCred(PKIWI_KERBEROS_TICKET ticket, BOOL valueIsTicket)
{
	BerElement *pBer, *pBerApp;
	PBERVAL pBerVal = NULL, pBerVallApp = NULL;
	if(pBer = ber_alloc_t(LBER_USE_DER))
	{
		ber_printf(pBer, "t{{t{i}t{i}t{", MAKE_APP_TAG(ID_APP_KRB_CRED), MAKE_CTX_TAG(ID_CTX_KRB_CRED_PVNO), KERBEROS_VERSION, MAKE_CTX_TAG(ID_CTX_KRB_CRED_MSG_TYPE), ID_APP_KRB_CRED, MAKE_CTX_TAG(ID_CTX_KRB_CRED_TICKETS));
		if(!valueIsTicket)
		{
			ber_printf(pBer, "{t{{t{i}t{", MAKE_APP_TAG(ID_APP_TICKET), MAKE_CTX_TAG(ID_CTX_TICKET_TKT_VNO), KERBEROS_VERSION, MAKE_CTX_TAG(ID_CTX_TICKET_REALM));
			kull_m_asn1_GenString(pBer, &ticket->DomainName);
			ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_TICKET_SNAME));
			kuhl_m_kerberos_ticket_createSequencePrimaryName(pBer, ticket->ServiceName);
			ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_TICKET_ENC_PART));
			kuhl_m_kerberos_ticket_createSequenceEncryptedData(pBer, ticket->TicketEncType, ticket->TicketKvno, ticket->Ticket.Value, ticket->Ticket.Length);
			ber_printf(pBer, "}}}}");
		}
		else ber_printf(pBer, "to", DIRTY_ASN1_ID_SEQUENCE, ticket->Ticket.Value, ticket->Ticket.Length);
		ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_KRB_CRED_ENC_PART));
		if(pBerApp = ber_alloc_t(LBER_USE_DER))
		{
			ber_printf(pBerApp, "t{{t{{{t{", MAKE_APP_TAG(ID_APP_ENCKRBCREDPART), MAKE_CTX_TAG(ID_CTX_ENCKRBCREDPART_TICKET_INFO), MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_KEY));
			kuhl_m_kerberos_ticket_createSequenceEncryptionKey(pBerApp, ticket->KeyType, ticket->Key.Value, ticket->Key.Length);
			ber_printf(pBerApp, "}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_PREALM));
			kull_m_asn1_GenString(pBerApp, &ticket->AltTargetDomainName);
			ber_printf(pBerApp, "}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_PNAME));
			kuhl_m_kerberos_ticket_createSequencePrimaryName(pBerApp, ticket->ClientName);
			ber_printf(pBerApp, "}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_FLAGS));
			kull_m_asn1_BitStringFromULONG(pBerApp, ticket->TicketFlags);	/* ID_CTX_KRBCREDINFO_AUTHTIME not present */
			ber_printf(pBerApp, "}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_STARTTIME));
			kull_m_asn1_GenTime(pBerApp, &ticket->StartTime);
			ber_printf(pBerApp, "}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_ENDTIME));
			kull_m_asn1_GenTime(pBerApp, &ticket->EndTime);
			ber_printf(pBerApp, "}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_RENEW_TILL));
			kull_m_asn1_GenTime(pBerApp, &ticket->RenewUntil);
			ber_printf(pBerApp, "}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_SREAL));
			kull_m_asn1_GenString(pBerApp, &ticket->DomainName);
			ber_printf(pBerApp, "}t{", MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_SNAME));
			kuhl_m_kerberos_ticket_createSequencePrimaryName(pBerApp, ticket->ServiceName);
			ber_printf(pBerApp, "}}}}}}");

			if(ber_flatten(pBerApp, &pBerVallApp) >= 0)
				kuhl_m_kerberos_ticket_createSequenceEncryptedData(pBer, KERB_ETYPE_NULL, 0, pBerVallApp->bv_val, pBerVallApp->bv_len);
			ber_free(pBerApp, 1);
		}
		ber_printf(pBer, "}}}");
		ber_flatten(pBer, &pBerVal);
		if(pBerVallApp)
			ber_bvfree(pBerVallApp);
		ber_free(pBer, 1);
	}
	return pBerVal;
}

PBERVAL kuhl_m_kerberos_ticket_createAppEncTicketPart(PKIWI_KERBEROS_TICKET ticket, LPCVOID PacAuthData, DWORD PacAuthDataSize)
{
	BerElement *pBer, *pBerPac;
	PBERVAL pBerVal = NULL, pBerValPac = NULL;
	if(pBer = ber_alloc_t(LBER_USE_DER))
	{
		ber_printf(pBer, "t{{t{", MAKE_APP_TAG(ID_APP_ENCTICKETPART), MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_FLAGS));
		kull_m_asn1_BitStringFromULONG(pBer, ticket->TicketFlags);
		ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_KEY));
		kuhl_m_kerberos_ticket_createSequenceEncryptionKey(pBer, ticket->KeyType, ticket->Key.Value, ticket->Key.Length);
		ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_CREALM));
		kull_m_asn1_GenString(pBer, &ticket->AltTargetDomainName);
		ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_CNAME));
		kuhl_m_kerberos_ticket_createSequencePrimaryName(pBer, ticket->ClientName);
		ber_printf(pBer, "}t{{t{i}t{o}}}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_TRANSITED), MAKE_CTX_TAG(ID_CTX_TRANSITEDENCODING_TR_TYPE), 0, MAKE_CTX_TAG(ID_CTX_TRANSITEDENCODING_CONTENTS), NULL, 0, MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_AUTHTIME));
		kull_m_asn1_GenTime(pBer, &ticket->StartTime);
		ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_STARTTIME));
		kull_m_asn1_GenTime(pBer, &ticket->StartTime);
		ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_ENDTIME));
		kull_m_asn1_GenTime(pBer, &ticket->EndTime);
		ber_printf(pBer, "}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_RENEW_TILL));
		kull_m_asn1_GenTime(pBer, &ticket->RenewUntil);
		ber_printf(pBer, "}"); /* ID_CTX_ENCTICKETPART_CADDR not present */
		if(PacAuthData && PacAuthDataSize)
		{
			ber_printf(pBer, "t{{{t{i}t{", MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_AUTHORIZATION_DATA), MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_TYPE), ID_AUTHDATA_AD_IF_RELEVANT, MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_DATA));
			if(pBerPac = ber_alloc_t(LBER_USE_DER))
			{
				ber_printf(pBerPac, "{{t{i}t{o}}}", MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_TYPE), ID_AUTHDATA_AD_WIN2K_PAC, MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_DATA), PacAuthData, PacAuthDataSize);
				if(ber_flatten(pBerPac, &pBerValPac) >= 0)
					ber_printf(pBer, "o", pBerValPac->bv_val, pBerValPac->bv_len);
				ber_free(pBerPac, 1);
			}
			ber_printf(pBer, "}}}}");
		}
		ber_printf(pBer, "}}");
		ber_flatten(pBer, &pBerVal);
		if(pBerValPac)
			ber_bvfree(pBerValPac);
		ber_free(pBer, 1);
	}
	return pBerVal;
}

void kuhl_m_kerberos_ticket_createSequencePrimaryName(BerElement * pBer, PKERB_EXTERNAL_NAME name)
{
	ber_int_t nameType = name->NameType;
	USHORT i;
	ber_printf(pBer, "{t{i}t{{", MAKE_CTX_TAG(ID_CTX_PRINCIPALNAME_NAME_TYPE), nameType, MAKE_CTX_TAG(ID_CTX_PRINCIPALNAME_NAME_STRING));
	for(i = 0; i < name->NameCount; i++)
		kull_m_asn1_GenString(pBer, &name->Names[i]);
	ber_printf(pBer, "}}}");
}

void kuhl_m_kerberos_ticket_createSequenceEncryptedData(BerElement * pBer, LONG eType, ULONG kvNo, LPCVOID data, DWORD size)
{
	ber_printf(pBer, "{t{i}", MAKE_CTX_TAG(ID_CTX_ENCRYPTEDDATA_ETYPE), eType);
	if(eType)
		ber_printf(pBer, "t{i}", MAKE_CTX_TAG(ID_CTX_ENCRYPTEDDATA_KVNO), kvNo);
	ber_printf(pBer, "t{o}}", MAKE_CTX_TAG(ID_CTX_ENCRYPTEDDATA_CIPHER), data, size);
}

void kuhl_m_kerberos_ticket_createSequenceEncryptionKey(BerElement * pBer, LONG eType, LPCVOID data, DWORD size)
{
	ber_printf(pBer, "{t{i}t{o}}", MAKE_CTX_TAG(ID_CTX_ENCRYPTIONKEY_KEYTYPE), eType, MAKE_CTX_TAG(ID_CTX_ENCRYPTIONKEY_KEYVALUE), data, size);
}