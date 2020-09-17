/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m.h"
#include "../modules/kull_m_asn1.h"

#define ID_APP_TICKET								1
#define ID_CTX_TICKET_TKT_VNO						0
#define ID_CTX_TICKET_REALM							1
#define ID_CTX_TICKET_SNAME							2
#define ID_CTX_TICKET_ENC_PART						3

#define ID_APP_ENCTICKETPART						3
#define ID_CTX_ENCTICKETPART_FLAGS					0
#define ID_CTX_ENCTICKETPART_KEY					1
#define ID_CTX_ENCTICKETPART_CREALM					2
#define ID_CTX_ENCTICKETPART_CNAME					3
#define ID_CTX_ENCTICKETPART_TRANSITED				4
#define ID_CTX_ENCTICKETPART_AUTHTIME				5
#define ID_CTX_ENCTICKETPART_STARTTIME				6
#define ID_CTX_ENCTICKETPART_ENDTIME				7
#define ID_CTX_ENCTICKETPART_RENEW_TILL				8
#define ID_CTX_ENCTICKETPART_CADDR					9
#define ID_CTX_ENCTICKETPART_AUTHORIZATION_DATA		10

#define ID_APP_KRB_CRED								22
#define ID_CTX_KRB_CRED_PVNO						0
#define ID_CTX_KRB_CRED_MSG_TYPE					1
#define ID_CTX_KRB_CRED_TICKETS						2
#define ID_CTX_KRB_CRED_ENC_PART					3

#define ID_APP_ENCKRBCREDPART						29
#define ID_CTX_ENCKRBCREDPART_TICKET_INFO			0
#define ID_CTX_ENCKRBCREDPART_NONCE					1
#define ID_CTX_ENCKRBCREDPART_TIMESTAMP				2
#define ID_CTX_ENCKRBCREDPART_USEC					3
#define ID_CTX_ENCKRBCREDPART_S_ADDRESS				4
#define ID_CTX_ENCKRBCREDPART_R_ADDRESS				5

#define ID_CTX_KRBCREDINFO_KEY						0
#define ID_CTX_KRBCREDINFO_PREALM					1
#define ID_CTX_KRBCREDINFO_PNAME					2
#define ID_CTX_KRBCREDINFO_FLAGS					3
#define ID_CTX_KRBCREDINFO_AUTHTIME					4
#define ID_CTX_KRBCREDINFO_STARTTIME				5
#define ID_CTX_KRBCREDINFO_ENDTIME					6
#define ID_CTX_KRBCREDINFO_RENEW_TILL				7
#define ID_CTX_KRBCREDINFO_SREAL					8
#define ID_CTX_KRBCREDINFO_SNAME					9
#define ID_CTX_KRBCREDINFO_CADDR					10

#define ID_CTX_PRINCIPALNAME_NAME_TYPE				0
#define ID_CTX_PRINCIPALNAME_NAME_STRING			1

#define ID_CTX_ENCRYPTIONKEY_KEYTYPE				0
#define ID_CTX_ENCRYPTIONKEY_KEYVALUE				1

#define ID_CTX_ENCRYPTEDDATA_ETYPE					0
#define ID_CTX_ENCRYPTEDDATA_KVNO					1
#define ID_CTX_ENCRYPTEDDATA_CIPHER					2

#define ID_CTX_TRANSITEDENCODING_TR_TYPE			0
#define ID_CTX_TRANSITEDENCODING_CONTENTS			1

#define ID_CTX_AUTHORIZATIONDATA_AD_TYPE			0
#define ID_CTX_AUTHORIZATIONDATA_AD_DATA			1

#define ID_AUTHDATA_AD_IF_RELEVANT					1
#define ID_AUTHDATA_AD_WIN2K_PAC					128

typedef struct _KIWI_KERBEROS_BUFFER {
	ULONG Length;
	PUCHAR Value;
} KIWI_KERBEROS_BUFFER, *PKIWI_KERBEROS_BUFFER;

typedef struct _KIWI_KERBEROS_TICKET {
	PKERB_EXTERNAL_NAME	ServiceName;
	LSA_UNICODE_STRING	DomainName;
	PKERB_EXTERNAL_NAME	TargetName;
	LSA_UNICODE_STRING	TargetDomainName;
	PKERB_EXTERNAL_NAME	ClientName;
	LSA_UNICODE_STRING	AltTargetDomainName;

	LSA_UNICODE_STRING	Description;

	FILETIME	StartTime;
	FILETIME	EndTime;
	FILETIME	RenewUntil;

	LONG		KeyType;
	KIWI_KERBEROS_BUFFER	Key;

	ULONG		TicketFlags;
	LONG		TicketEncType;
	ULONG		TicketKvno;
	KIWI_KERBEROS_BUFFER	Ticket;
} KIWI_KERBEROS_TICKET, *PKIWI_KERBEROS_TICKET;

void kuhl_m_kerberos_ticket_display(PKIWI_KERBEROS_TICKET ticket, BOOL withKey, BOOL encodedTicketToo);
void kuhl_m_kerberos_ticket_displayFlags(ULONG flags);
void kuhl_m_kerberos_ticket_displayExternalName(IN LPCWSTR prefix, IN PKERB_EXTERNAL_NAME pExternalName, IN PUNICODE_STRING pDomain);
BOOL kuhl_m_kerberos_ticket_isLongFilename(PKIWI_KERBEROS_TICKET ticket);
PCWCHAR kuhl_m_kerberos_ticket_etype(LONG eType);
PCWCHAR kuhl_m_kerberos_ticket_ctype(LONG cType);

void kuhl_m_kerberos_ticket_freeTicket(PKIWI_KERBEROS_TICKET ticket);
PKERB_EXTERNAL_NAME kuhl_m_kerberos_ticket_copyExternalName(PKERB_EXTERNAL_NAME pName);
void kuhl_m_kerberos_ticket_freeExternalName(PKERB_EXTERNAL_NAME pName);
void kuhl_m_kerberos_ticket_freeKiwiKerberosBuffer(PKIWI_KERBEROS_BUFFER pBuffer);

PBERVAL kuhl_m_kerberos_ticket_createAppKrbCred(PKIWI_KERBEROS_TICKET ticket, BOOL valueIsTicket);
PBERVAL kuhl_m_kerberos_ticket_createAppEncTicketPart(PKIWI_KERBEROS_TICKET ticket, LPCVOID PacAuthData, DWORD PacAuthDataSize);

void kuhl_m_kerberos_ticket_createSequenceEncryptedData(BerElement * pBer, LONG eType, ULONG kvNo, LPCVOID data, DWORD size);
void kuhl_m_kerberos_ticket_createSequenceEncryptionKey(BerElement * pBer, LONG eType, LPCVOID data, DWORD size);
void kuhl_m_kerberos_ticket_createSequencePrimaryName(BerElement * pBer, PKERB_EXTERNAL_NAME name);