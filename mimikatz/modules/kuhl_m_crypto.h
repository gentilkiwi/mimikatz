/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_crypto.h"
#include "../modules/kull_m_process.h"
#include "../modules/kull_m_service.h"
#include "../modules/kull_m_memory.h"
#include "../modules/kull_m_patch.h"
#include "../modules/kull_m_string.h"
#include "../modules/kull_m_file.h"

typedef BOOL			(WINAPI * PCP_EXPORTKEY)					(IN HCRYPTPROV hProv, IN HCRYPTKEY hKey, IN HCRYPTKEY hPubKey, IN DWORD dwBlobType, IN DWORD dwFlags, OUT LPBYTE pbData, IN OUT LPDWORD pcbDataLen);

typedef SECURITY_STATUS	(WINAPI * PNCRYPT_OPEN_STORAGE_PROVIDER)	(__out NCRYPT_PROV_HANDLE *phProvider, __in_opt LPCWSTR pszProviderName, __in DWORD dwFlags);
typedef SECURITY_STATUS	(WINAPI * PNCRYPT_ENUM_KEYS)				(__in NCRYPT_PROV_HANDLE hProvider, __in_opt LPCWSTR pszScope, __deref_out NCryptKeyName **ppKeyName, __inout PVOID * ppEnumState, __in DWORD dwFlags);
typedef	SECURITY_STATUS	(WINAPI * PNCRYPT_OPEN_KEY)					(__in NCRYPT_PROV_HANDLE hProvider, __out NCRYPT_KEY_HANDLE *phKey, __in LPCWSTR pszKeyName, __in DWORD dwLegacyKeySpec, __in DWORD dwFlags);
typedef SECURITY_STATUS (WINAPI * PNCRYPT_IMPORT_KEY)					(__in NCRYPT_PROV_HANDLE hProvider, __in_opt NCRYPT_KEY_HANDLE hImportKey, __in LPCWSTR pszBlobType, __in_opt NCryptBufferDesc *pParameterList, __out NCRYPT_KEY_HANDLE *phKey, __in_bcount(cbData) PBYTE pbData, __in DWORD cbData, __in DWORD dwFlags);
typedef SECURITY_STATUS	(WINAPI * PNCRYPT_EXPORT_KEY)				(__in NCRYPT_KEY_HANDLE hKey, __in_opt NCRYPT_KEY_HANDLE hExportKey, __in LPCWSTR pszBlobType, __in_opt NCryptBufferDesc *pParameterList, __out_opt PBYTE pbOutput, __in DWORD cbOutput, __out DWORD *pcbResult, __in DWORD dwFlags);
typedef SECURITY_STATUS	(WINAPI * PNCRYPT_GET_PROPERTY)				(__in NCRYPT_HANDLE hObject, __in LPCWSTR pszProperty, __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput, __in DWORD cbOutput, __out DWORD * pcbResult, __in DWORD dwFlags);
typedef SECURITY_STATUS (WINAPI * PNCRYPT_SET_PROPERTY)				( __in    NCRYPT_HANDLE hObject, __in LPCWSTR pszProperty, __in_bcount(cbInput) PBYTE pbInput, __in DWORD cbInput, __in DWORD dwFlags);
typedef SECURITY_STATUS	(WINAPI * PNCRYPT_FREE_BUFFER)				(__deref PVOID pvInput);
typedef SECURITY_STATUS	(WINAPI * PNCRYPT_FREE_OBJECT)				(__in NCRYPT_HANDLE hObject);
typedef NTSTATUS		(WINAPI * PBCRYPT_ENUM_REGISTERED_PROVIDERS)(__inout ULONG* pcbBuffer, __deref_opt_inout_bcount_part_opt(*pcbBuffer, *pcbBuffer) PCRYPT_PROVIDERS *ppBuffer);
typedef VOID			(WINAPI * PBCRYPT_FREE_BUFFER)				(__in PVOID pvBuffer);

typedef struct _KUHL_M_CRYPTO_DWORD_TO_DWORD{
	PCWSTR	name;
	DWORD	id;
} KUHL_M_CRYPTO_DWORD_TO_DWORD, *PKUHL_M_CRYPTO_DWORD_TO_DWORD;

typedef struct _KUHL_M_CRYPTO_NAME_TO_REALNAME{
	PCWSTR	name;
	PCWSTR	realname;
} KUHL_M_CRYPTO_NAME_TO_REALNAME, *PKUHL_M_CRYPTO_NAME_TO_REALNAME;

const KUHL_M kuhl_m_crypto;

NTSTATUS kuhl_m_crypto_init();
NTSTATUS kuhl_m_crypto_clean();

NTSTATUS kuhl_m_crypto_l_providers(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_l_stores(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_l_certificates(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_l_keys(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_crypto_p_capi(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_p_cng(int argc, wchar_t * argv[]);

BOOL WINAPI kuhl_m_crypto_l_stores_enumCallback_print(const void *pvSystemStore, DWORD dwFlags, PCERT_SYSTEM_STORE_INFO pStoreInfo, void *pvReserved, void *pvArg);

void kuhl_m_crypto_printKeyInfos(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE monProv, HCRYPTKEY maCle);
void kuhl_m_crypto_exportRawKeyToFile(LPCVOID data, DWORD size, BOOL isCNG, const wchar_t * store, const DWORD index, const wchar_t * name, BOOL wantExport, BOOL wantInfos);
void kuhl_m_crypto_exportKeyToFile(NCRYPT_KEY_HANDLE hCngKey, HCRYPTKEY hCapiKey, DWORD keySpec, const wchar_t * store, const DWORD index, const wchar_t * name);
void kuhl_m_crypto_exportCert(PCCERT_CONTEXT pCertificate, BOOL havePrivateKey, const wchar_t * systemStore, const wchar_t * store, const DWORD index, const wchar_t * name);
BOOL kuhl_m_crypto_exportPfx(HCERTSTORE hStore, LPCWSTR filename);
BOOL kuhl_m_crypto_DerAndKeyToPfx(LPCVOID der, DWORD derLen, LPCVOID key, DWORD keyLen, BOOL isPvk, LPCWSTR filename);
wchar_t * kuhl_m_crypto_generateFileName(const wchar_t * term0, const wchar_t * term1, const DWORD index, const wchar_t * name, const wchar_t * ext);