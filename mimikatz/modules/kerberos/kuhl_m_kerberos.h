/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m.h"
#include "../modules/kull_m_file.h"
#include "../modules/kull_m_crypto_system.h"
#include "kuhl_m_kerberos_ticket.h"
#include "kuhl_m_kerberos_pac.h"
#include "kuhl_m_kerberos_ccache.h"

#define USER_NORMAL_ACCOUNT				0x00000010
#define USER_DONT_EXPIRE_PASSWORD		0x00000200

#define KRB_KEY_USAGE_AS_REP_TGS_REP	2

#define DEFAULT_GROUP_ATTRIBUTES	(SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED)
#define KIWI_NEVERTIME(filetime)	(*(PLONGLONG) filetime = MAXLONGLONG)

typedef struct _KUHL_M_KERBEROS_LIFETIME_DATA {
	FILETIME TicketStart;
	FILETIME TicketEnd;
	FILETIME TicketRenew;
} KUHL_M_KERBEROS_LIFETIME_DATA, *PKUHL_M_KERBEROS_LIFETIME_DATA;

const KUHL_M kuhl_m_kerberos;

NTSTATUS kuhl_m_kerberos_init();
NTSTATUS kuhl_m_kerberos_clean();

NTSTATUS LsaCallKerberosPackage(PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID *ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus);

NTSTATUS kuhl_m_kerberos_ptt(int argc, wchar_t * argv[]);
void kuhl_m_kerberos_ptt_file(PCWCHAR filename);
NTSTATUS kuhl_m_kerberos_ptt_data(PVOID data, DWORD dataSize);
NTSTATUS kuhl_m_kerberos_golden(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_list(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_tgt(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_purge(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_hash(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_decode(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_test(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_kerberos_hash_data(LONG keyType, PCUNICODE_STRING pString, PCUNICODE_STRING pSalt, DWORD count);
wchar_t * kuhl_m_kerberos_generateFileName(const DWORD index, PKERB_TICKET_CACHE_INFO_EX ticket, LPCWSTR ext);
struct _DIRTY_ASN1_SEQUENCE_EASY * kuhl_m_kerberos_golden_data(LPCWSTR username, LPCWSTR domainname, LPCWSTR LogonDomainName, LPCWSTR servicename, LPCWSTR targetname, PKUHL_M_KERBEROS_LIFETIME_DATA lifetime, PISID sid, LPCBYTE key, DWORD keySize, DWORD keyType, DWORD userid, PGROUP_MEMBERSHIP groups, DWORD cbGroups, PKERB_SID_AND_ATTRIBUTES sids, DWORD cbSids, DWORD rodc);
NTSTATUS kuhl_m_kerberos_encrypt(ULONG eType, ULONG keyUsage, LPCVOID key, DWORD keySize, LPCVOID data, DWORD dataSize, LPVOID *output, DWORD *outputSize, BOOL encrypt);