/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_crypto.h"
#include "../modules/kull_m_string.h"
#include "../modules/kull_m_file.h"
#include "../modules/kull_m_registry.h"
#include "crypto/kuhl_m_crypto_sc.h"
#include "crypto/kuhl_m_crypto_extractor.h"
#include "crypto/kuhl_m_crypto_patch.h"

typedef struct _KUHL_M_CRYPTO_DWORD_TO_DWORD {
	PCWSTR	name;
	DWORD	id;
} KUHL_M_CRYPTO_DWORD_TO_DWORD, *PKUHL_M_CRYPTO_DWORD_TO_DWORD;

typedef struct _KUHL_M_CRYPTO_NAME_TO_REALNAME {
	PCWSTR	name;
	PCWSTR	realname;
} KUHL_M_CRYPTO_NAME_TO_REALNAME, *PKUHL_M_CRYPTO_NAME_TO_REALNAME;

typedef struct _KUHL_M_CRYPTO_CRYPT_KEY_PROV_INFO {
	DWORD offsetContainerName;
	DWORD offsetProvName;
	DWORD dwProvType;
	DWORD dwFlags;
	DWORD cProvParam;
	DWORD offsetRgProvParam;
	DWORD dwKeySpec;
} KUHL_M_CRYPTO_CRYPT_KEY_PROV_INFO, *PKUHL_M_CRYPTO_CRYPT_KEY_PROV_INFO;

typedef struct _KUHL_M_CRYPTO_CERT_PROP {
	DWORD dwPropId;
	DWORD flags; // ?
	DWORD size;
	BYTE data[ANYSIZE_ARRAY];
} KUHL_M_CRYPTO_CERT_PROP, *PKUHL_M_CRYPTO_CERT_PROP;

const KUHL_M kuhl_m_crypto;

NTSTATUS kuhl_m_crypto_init();
NTSTATUS kuhl_m_crypto_clean();

NTSTATUS kuhl_m_crypto_l_providers(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_l_stores(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_l_certificates(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_l_keys(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_hash(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_system(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_c_sc_auth(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_c_cert_to_hw(int argc, wchar_t * argv[]);

BOOL WINAPI kuhl_m_crypto_l_stores_enumCallback_print(const void *pvSystemStore, DWORD dwFlags, PCERT_SYSTEM_STORE_INFO pStoreInfo, void *pvReserved, void *pvArg);

void kuhl_m_crypto_printKeyInfos(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE monProv, HCRYPTKEY maCle);
void kuhl_m_crypto_exportRawKeyToFile(LPCVOID data, DWORD size, BOOL isCNG, const wchar_t * store, const DWORD index, const wchar_t * name, BOOL wantExport, BOOL wantInfos);
void kuhl_m_crypto_exportKeyToFile(NCRYPT_KEY_HANDLE hCngKey, HCRYPTKEY hCapiKey, DWORD keySpec, const wchar_t * store, const DWORD index, const wchar_t * name);
void kuhl_m_crypto_exportCert(PCCERT_CONTEXT pCertificate, BOOL havePrivateKey, const wchar_t * systemStore, const wchar_t * store, const DWORD index, const wchar_t * name);
wchar_t * kuhl_m_crypto_generateFileName(const wchar_t * term0, const wchar_t * term1, const DWORD index, const wchar_t * name, const wchar_t * ext);
void kuhl_m_crypto_file_rawData(PKUHL_M_CRYPTO_CERT_PROP prop, PCWCHAR inFile, BOOL isExport);
void kuhl_m_crypto_l_keys_capi(LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags, BOOL export, LPCWSTR szStore);
void kuhl_m_crypto_l_keys_cng(LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwFlags, BOOL export, LPCWSTR szStore);

BOOL kuhl_m_crypto_c_sc_auth_quickEncode(__in LPCSTR lpszStructType, __in const void *pvStructInfo, PDATA_BLOB data);