/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kuhl_m_dpapi.h"
#include "../modules/rpc/kull_m_rpc_dpapi-entries.h"

typedef struct _KUHL_M_DPAPI_OE_MASTERKEY_ENTRY {
	LIST_ENTRY navigator;
	KUHL_M_DPAPI_MASTERKEY_ENTRY data;
} KUHL_M_DPAPI_OE_MASTERKEY_ENTRY, *PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY;

#define KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4		0x00000001
#define KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_SHA1	0x00000002
#define KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4p	0x00000004
#define KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_GUID	0x80000000
typedef struct _KUHL_M_DPAPI_OE_CREDENTIAL_ENTRY {
	LIST_ENTRY navigator;
	KUHL_M_DPAPI_CREDENTIAL_ENTRY data;
/*	
	PVOID DPAPI_SYSTEM_machine;
	PVOID DPAPI_SYSTEM_user;
*/
} KUHL_M_DPAPI_OE_CREDENTIAL_ENTRY, *PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY;

typedef struct _KUHL_M_DPAPI_OE_DOMAINKEY_ENTRY {
	LIST_ENTRY navigator;
	KUHL_M_DPAPI_DOMAINKEY_ENTRY data;
} KUHL_M_DPAPI_OE_DOMAINKEY_ENTRY, *PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY;

NTSTATUS kuhl_m_dpapi_oe_clean();
NTSTATUS kuhl_m_dpapi_oe_cache(int argc, wchar_t * argv[]);
BOOL kuhl_m_dpapi_oe_is_sid_valid_ForCacheOrAuto(PSID sid, LPCWSTR szSid, BOOL AutoOrCache);
BOOL kuhl_m_dpapi_oe_autosid(LPCWSTR filename, LPWSTR * pSid);

LIST_ENTRY gDPAPI_Masterkeys;
LIST_ENTRY gDPAPI_Credentials;
LIST_ENTRY gDPAPI_Domainkeys;

PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY kuhl_m_dpapi_oe_masterkey_get(LPCGUID guid);
BOOL kuhl_m_dpapi_oe_masterkey_add(LPCGUID guid, LPCVOID keyHash, DWORD keyLen);
void kuhl_m_dpapi_oe_masterkey_delete(PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry);
void kuhl_m_dpapi_oe_masterkey_descr(PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry);
void kuhl_m_dpapi_oe_masterkeys_delete();
void kuhl_m_dpapi_oe_masterkeys_descr();

PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY kuhl_m_dpapi_oe_credential_get(LPCWSTR sid, LPCGUID guid);
BOOL kuhl_m_dpapi_oe_credential_add(LPCWSTR sid, LPCGUID guid, LPCVOID md4hash, LPCVOID sha1hash, LPCVOID md4protectedhash, LPCWSTR password);
void kuhl_m_dpapi_oe_credential_delete(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry);
void kuhl_m_dpapi_oe_credential_descr(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry);
void kuhl_m_dpapi_oe_credentials_delete();
void kuhl_m_dpapi_oe_credentials_descr();

PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY kuhl_m_dpapi_oe_domainkey_get(LPCGUID guid);
BOOL kuhl_m_dpapi_oe_domainkey_add(LPCGUID guid, LPCVOID key, DWORD keyLen, BOOL isNewKey);
void kuhl_m_dpapi_oe_domainkey_delete(PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry);
void kuhl_m_dpapi_oe_domainkey_descr(PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry);
void kuhl_m_dpapi_oe_domainkeys_delete();
void kuhl_m_dpapi_oe_domainkeys_descr();

BOOL kuhl_m_dpapi_oe_credential_addtoEntry(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry, LPCGUID guid, LPCVOID md4hash, LPCVOID sha1hash, LPCVOID md4protectedhash, LPCWSTR password);
BOOL kuhl_m_dpapi_oe_credential_copyEntryWithNewGuid(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry, LPCGUID guid);

BOOL kuhl_m_dpapi_oe_SaveToFile(LPCWSTR filename);
BOOL kuhl_m_dpapi_oe_LoadFromFile(LPCWSTR filename);