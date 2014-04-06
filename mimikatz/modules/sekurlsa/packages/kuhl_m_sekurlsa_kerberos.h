/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../kuhl_m_sekurlsa.h"
#include "../../kerberos/kuhl_m_kerberos_ticket.h"
#include "../modules/kull_m_file.h"

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_kerberos_package;

NTSTATUS kuhl_m_sekurlsa_kerberos(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sekurlsa_kerberos_tickets(int argc, wchar_t * argv[]);

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_kerberos(IN PKUHL_M_SEKURLSA_CONTEXT cLsass, IN PLUID logId, IN PVOID pCredentials, IN OPTIONAL PKUHL_M_SEKURLSA_EXTERNAL externalCallback, IN OPTIONAL LPVOID externalCallbackData);
BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_kerberos_tickets(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData);
void kuhl_m_sekurlsa_kerberos_enum_tickets(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN DWORD grp, IN PVOID tickets, IN BOOL isFile);

wchar_t * kuhl_m_sekurlsa_kerberos_generateFileName(PLUID LogonId, const DWORD grp, const DWORD index, PKIWI_KERBEROS_TICKET ticket, LPCWSTR ext);

PKIWI_KERBEROS_TICKET kuhl_m_sekurlsa_kerberos_createTicket(PBYTE pTicket, PKULL_M_MEMORY_HANDLE hLSASS);
void kuhl_m_sekurlsa_kerberos_createExternalName(PKERB_EXTERNAL_NAME *pExternalName, PKULL_M_MEMORY_HANDLE hLSASS);
void kuhl_m_sekurlsa_kerberos_createKiwiKerberosBuffer(PKIWI_KERBEROS_BUFFER pBuffer, PKULL_M_MEMORY_HANDLE hLSASS);

void kuhl_m_sekurlsa_kerberos_freeTicket(PKIWI_KERBEROS_TICKET ticket);
void kuhl_m_sekurlsa_kerberos_freeExternalName(PKERB_EXTERNAL_NAME pName);
void kuhl_m_sekurlsa_kerberos_freeKiwiKerberosBuffer(PKIWI_KERBEROS_BUFFER pBuffer);

typedef struct _KERB_INFOS {
	LONG	offsetLuid;
	LONG	offsetCreds;
	LONG	offsetTickets[3];
	LONG	offsetPin;
	SIZE_T	structSize;
	LONG	offsetServiceName;
	LONG	offsetTargetName;
	LONG	offsetDomainName;
	LONG	offsetTargetDomainName;
	LONG	offsetDescription;
	LONG	offsetAltTargetDomainName;
	LONG	offsetClientName;
	LONG	offsetTicketFlags;
	LONG	offsetKeyType;
	LONG	offsetKey;
	LONG	offsetStartTime;
	LONG	offsetEndTime;
	LONG	offsetRenewUntil;
	LONG	offsetTicketEncType;
	LONG	offsetTicket;
	LONG	offsetTicketKvno;
	SIZE_T	structTicketSize;
} KERB_INFOS, *PKERB_INFOS;

typedef struct _KIWI_KERBEROS_LOGON_SESSION_51 {
	ULONG		UsageCount;
	LIST_ENTRY	unk0;
	LIST_ENTRY	unk1;
	PVOID		unk2;
	ULONG		unk3;	// filetime.1 ?
	ULONG		unk4;	// filetime.2 ?
	PVOID		unk5;
	PVOID		unk6;
	PVOID		unk7;
	LUID		LocallyUniqueIdentifier;
#ifdef _M_IX86
	ULONG		unkAlign;
#endif
	FILETIME	unk8;
	PVOID		unk9;
	ULONG		unk10;	// filetime.1 ?
	ULONG		unk11;	// filetime.2 ?
	PVOID		unk12;
	PVOID		unk13;
	PVOID		unk14;
	KIWI_GENERIC_PRIMARY_CREDENTIAL	credentials;
	ULONG		unk15;
	ULONG		unk16;
	ULONG		unk17;
	ULONG		unk18;
	PVOID		unk19;
	PVOID		unk20;
	PVOID		unk21;
	PVOID		unk22;
	PVOID		unk23;
	PVOID		unk24;
	LIST_ENTRY	Tickets_1;
	LIST_ENTRY	Tickets_2;
	LIST_ENTRY	Tickets_3;
	PUNICODE_STRING pinCode;	// not only PIN (CSP Info)
} KIWI_KERBEROS_LOGON_SESSION_51, *PKIWI_KERBEROS_LOGON_SESSION_51;

typedef struct _KIWI_KERBEROS_LOGON_SESSION {
	ULONG		UsageCount;
	LIST_ENTRY	unk0;
	PVOID		unk1;
	ULONG		unk2;	// filetime.1 ?
	ULONG		unk3;	// filetime.2 ?
	PVOID		unk4;
	PVOID		unk5;
	PVOID		unk6;
	LUID		LocallyUniqueIdentifier;
#ifdef _M_IX86
	ULONG		unkAlign;
#endif
	FILETIME	unk7;
	PVOID		unk8;
	ULONG		unk9;	// filetime.1 ?
	ULONG		unk10;	// filetime.2 ?
	PVOID		unk11;
	PVOID		unk12;
	PVOID		unk13;
	KIWI_GENERIC_PRIMARY_CREDENTIAL	credentials;
	ULONG		unk14;
	ULONG		unk15;
	ULONG		unk16;
	ULONG		unk17;
	PVOID		unk18;
	PVOID		unk19;
	PVOID		unk20;
	PVOID		unk21;
	PVOID		unk22;
	PVOID		unk23;
	LIST_ENTRY	Tickets_1;
	FILETIME	unk24;
	LIST_ENTRY	Tickets_2;
	FILETIME	unk25;
	LIST_ENTRY	Tickets_3;
	FILETIME	unk26;
	PUNICODE_STRING pinCode;	// not only PIN (CSP Info)
} KIWI_KERBEROS_LOGON_SESSION, *PKIWI_KERBEROS_LOGON_SESSION;

typedef struct _KIWI_KERBEROS_INTERNAL_TICKET_51 {
	LIST_ENTRY	This;
	PVOID		unk0;
	PVOID		unk1;
	PKERB_EXTERNAL_NAME	ServiceName;
	PKERB_EXTERNAL_NAME	TargetName;
	LSA_UNICODE_STRING	DomainName;
	LSA_UNICODE_STRING	TargetDomainName;
	LSA_UNICODE_STRING	Description;
	LSA_UNICODE_STRING	AltTargetDomainName;
	PKERB_EXTERNAL_NAME	ClientName;
	ULONG		TicketFlags;
	ULONG		unk2;
	ULONG		KeyType;
	KIWI_KERBEROS_BUFFER	Key;
	PVOID		unk3;
	PVOID		unk4;
	PVOID		unk5;
	PVOID		unk6;
	PVOID		unk7;
	PVOID		unk8;
	FILETIME	StartTime;
	FILETIME	EndTime;
	FILETIME	RenewUntil;
	ULONG		unk9;
	ULONG		unk10;
	PCWSTR		domain;
	ULONG		unk11;
	PVOID		strangeNames;
	ULONG		unk12;
	ULONG		TicketEncType;
	ULONG		TicketKvno;
	KIWI_KERBEROS_BUFFER	Ticket;
} KIWI_KERBEROS_INTERNAL_TICKET_51, *PKIWI_KERBEROS_INTERNAL_TICKET_51;

typedef struct _KIWI_KERBEROS_INTERNAL_TICKET_52 {
	LIST_ENTRY	This;
	PVOID		unk0;
	PVOID		unk1;
	PKERB_EXTERNAL_NAME	ServiceName;
	PKERB_EXTERNAL_NAME	TargetName;
	LSA_UNICODE_STRING	DomainName;
	LSA_UNICODE_STRING	TargetDomainName;
	LSA_UNICODE_STRING	Description;
	LSA_UNICODE_STRING	AltTargetDomainName;
	PKERB_EXTERNAL_NAME	ClientName;
	PVOID		name0;
	ULONG		TicketFlags;
	ULONG		unk2;
	ULONG		KeyType;
	KIWI_KERBEROS_BUFFER	Key;
	PVOID		unk3;
	PVOID		unk4;
	PVOID		unk5;
	FILETIME	StartTime;
	FILETIME	EndTime;
	FILETIME	RenewUntil;
	ULONG		unk6;
	ULONG		unk7;
	PCWSTR		domain;
	ULONG		unk8;
	PVOID		strangeNames;
	ULONG		unk9;
	ULONG		TicketEncType;
	ULONG		TicketKvno;
	KIWI_KERBEROS_BUFFER	Ticket;
} KIWI_KERBEROS_INTERNAL_TICKET_52, *PKIWI_KERBEROS_INTERNAL_TICKET_52;
    
typedef struct _KIWI_KERBEROS_INTERNAL_TICKET_6 {
	LIST_ENTRY	This;
	PVOID		unk0;
	PVOID		unk1;
	PKERB_EXTERNAL_NAME	ServiceName;
	PKERB_EXTERNAL_NAME	TargetName;
	LSA_UNICODE_STRING	DomainName;
	LSA_UNICODE_STRING	TargetDomainName;
	LSA_UNICODE_STRING	Description;
	LSA_UNICODE_STRING	AltTargetDomainName;
	LSA_UNICODE_STRING	KDCServer;	//?
	PKERB_EXTERNAL_NAME	ClientName;
	PVOID		name0;
	ULONG		TicketFlags;
	ULONG		unk2;
	ULONG		KeyType;
	KIWI_KERBEROS_BUFFER	Key;
	PVOID		unk3;
	PVOID		unk4;
	PVOID		unk5;
	FILETIME	StartTime;
	FILETIME	EndTime;
	FILETIME	RenewUntil;
	ULONG		unk6;
	ULONG		unk7;
	PCWSTR		domain;
	ULONG		unk8;
	PVOID		strangeNames;
	ULONG		unk9;
	ULONG		TicketEncType;
	ULONG		TicketKvno;
	KIWI_KERBEROS_BUFFER	Ticket;
} KIWI_KERBEROS_INTERNAL_TICKET_6, *PKIWI_KERBEROS_INTERNAL_TICKET_6;