/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include <cardmod.h>
#include "../modules/kull_m_crypto.h"
#include "../modules/kull_m_process.h"
#include "../modules/kull_m_service.h"
#include "../modules/kull_m_memory.h"
#include "../modules/kull_m_patch.h"
#include "../modules/kull_m_string.h"
#include "../modules/kull_m_file.h"
#include "../modules/kull_m_registry.h"

typedef BOOL			(WINAPI * PCP_EXPORTKEY)					(IN HCRYPTPROV hProv, IN HCRYPTKEY hKey, IN HCRYPTKEY hPubKey, IN DWORD dwBlobType, IN DWORD dwFlags, OUT LPBYTE pbData, IN OUT LPDWORD pcbDataLen);

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
NTSTATUS kuhl_m_crypto_l_sc(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_hash(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_system(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_c_sc_auth(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_c_cert_to_hw(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_crypto_p_capi(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_crypto_p_cng(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_crypto_extract(int argc, wchar_t * argv[]);

BOOL WINAPI kuhl_m_crypto_l_stores_enumCallback_print(const void *pvSystemStore, DWORD dwFlags, PCERT_SYSTEM_STORE_INFO pStoreInfo, void *pvReserved, void *pvArg);

void kuhl_m_crypto_printKeyInfos(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE monProv, HCRYPTKEY maCle);
void kuhl_m_crypto_exportRawKeyToFile(LPCVOID data, DWORD size, BOOL isCNG, const wchar_t * store, const DWORD index, const wchar_t * name, BOOL wantExport, BOOL wantInfos);
void kuhl_m_crypto_exportKeyToFile(NCRYPT_KEY_HANDLE hCngKey, HCRYPTKEY hCapiKey, DWORD keySpec, const wchar_t * store, const DWORD index, const wchar_t * name);
void kuhl_m_crypto_exportCert(PCCERT_CONTEXT pCertificate, BOOL havePrivateKey, const wchar_t * systemStore, const wchar_t * store, const DWORD index, const wchar_t * name);
wchar_t * kuhl_m_crypto_generateFileName(const wchar_t * term0, const wchar_t * term1, const DWORD index, const wchar_t * name, const wchar_t * ext);
void kuhl_m_crypto_file_rawData(PKUHL_M_CRYPTO_CERT_PROP prop, PCWCHAR inFile, BOOL isExport);
void kuhl_m_crypto_l_keys_capi(LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags, BOOL export, LPCWSTR szStore);
void kuhl_m_crypto_l_keys_cng(LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwFlags, BOOL export, LPCWSTR szStore);
void kuhl_m_crypto_l_mdr(LPCWSTR szMdr, SCARDCONTEXT ctxScard, SCARDHANDLE hScard, LPCWSTR szModel, LPCBYTE pbAtr, DWORD cbAtr);
DWORD kuhl_m_crypto_l_sc_provtypefromname(LPCWSTR szProvider);
PWSTR kuhl_m_crypto_l_sc_containerFromReader(LPCWSTR reader);

typedef struct _KIWI_CRYPTPROV {
	PVOID CPAcquireContext;
	PVOID CPReleaseContext;
	PVOID CPGenKey;
	PVOID CPDeriveKey;
	PVOID CPDestroyKey;
	PVOID CPSetKeyParam;
	PVOID CPGetKeyParam;
	PVOID CPExportKey;
	PVOID CPImportKey;
	PVOID CPEncrypt;
	PVOID CPDecrypt;
	PVOID CPCreateHash;
	PVOID CPHashData;
	PVOID CPHashSessionKey;
	PVOID CPDestroyHash;
	PVOID CPSignHash;
	PVOID CPVerifySignature;
	PVOID CPGenRandom;
	PVOID CPGetUserKey;
	PVOID CPSetProvParam;
	PVOID CPGetProvParam;
	PVOID CPSetHashParam;
	PVOID CPGetHashParam;
	PVOID unk0;
	PVOID CPDuplicateKey;
	PVOID CPDuplicateHash;
	PVOID unk1;
	PVOID ImageBase;
	PVOID obfUnk2;
} KIWI_CRYPTPROV, *PKIWI_CRYPTPROV;

typedef struct _KIWI_RAWKEY32 {
	DWORD32 obfUnk0; // 0E380D2CC
	ALG_ID Algid;
	DWORD Flags; // ? 1
	DWORD dwData; // size (0x10) ?
	// align on x64
	DWORD32 Data;
	DWORD unk0; // ? 1
	DWORD unk1;
	DWORD32 unk2; //
	DWORD unk3;
	BYTE IV[32];
	DWORD unk4;
	DWORD dwSalt;
	BYTE Salt[24];
	DWORD unk5; // ? 1
	DWORD dwMode;
	DWORD dwModeBits;
	DWORD dwPermissions;
	DWORD dwEffectiveKeyLen;
	DWORD32 OaepParamsLen;
	DWORD dwOaepParamsLen;
	DWORD dwBlockLen;
} KIWI_RAWKEY32, *PKIWI_RAWKEY32;

#ifdef _M_X64
typedef struct _KIWI_RAWKEY64 {
	DWORD64 obfUnk0; // 0E380D2CC
	ALG_ID Algid;
	DWORD Flags; // ? 1
	DWORD dwData; // size (0x10) ?
	// align on x64
	DWORD64 Data;
	DWORD unk0; // ? 1
	DWORD unk1;
	DWORD64 unk2; //
	DWORD unk3;
	BYTE IV[32];
	DWORD unk4;
	DWORD dwSalt;
	BYTE Salt[24];
	DWORD unk5; // ? 1
	DWORD dwMode;
	DWORD dwModeBits;
	DWORD dwPermissions;
	DWORD dwEffectiveKeyLen;
	DWORD64 OaepParamsLen;
	DWORD dwOaepParamsLen;
	DWORD dwBlockLen;
} KIWI_RAWKEY64, *PKIWI_RAWKEY64;
#endif

typedef struct _KIWI_UNK_INT_KEY32 {
	DWORD32 /*PKIWI_RAWKEY */KiwiRawKey;
	DWORD unk0; // 2
} KIWI_UNK_INT_KEY32, *PKIWI_UNK_INT_KEY32;

#ifdef _M_X64
typedef struct _KIWI_UNK_INT_KEY64 {
	DWORD64 /*PKIWI_RAWKEY */KiwiRawKey;
	DWORD unk0; // 2
} KIWI_UNK_INT_KEY64, *PKIWI_UNK_INT_KEY64;
#endif

typedef struct _KIWI_CRYPTKEY32 {
	DWORD32 CPGenKey;
	DWORD32 CPDeriveKey;
	DWORD32 CPDestroyKey;
	DWORD32 CPSetKeyParam;
	DWORD32 CPGetKeyParam;
	DWORD32 CPExportKey;
	DWORD32 CPImportKey;
	DWORD32 CPEncrypt;
	DWORD32 CPDecrypt;
	DWORD32 CPDuplicateKey;
	DWORD32 /*PKIWI_CRYPTPROV */KiwiProv;
	DWORD32 /*PKIWI_UNK_INT_KEY */obfKiwiIntKey;
} KIWI_CRYPTKEY32, *PKIWI_CRYPTKEY32;

#ifdef _M_X64
typedef struct _KIWI_CRYPTKEY64 {
	DWORD64 CPGenKey;
	DWORD64 CPDeriveKey;
	DWORD64 CPDestroyKey;
	DWORD64 CPSetKeyParam;
	DWORD64 CPGetKeyParam;
	DWORD64 CPExportKey;
	DWORD64 CPImportKey;
	DWORD64 CPEncrypt;
	DWORD64 CPDecrypt;
	DWORD64 CPDuplicateKey;
	DWORD64 /*PKIWI_CRYPTPROV */KiwiProv;
	DWORD64 /*PKIWI_UNK_INT_KEY */obfKiwiIntKey;
} KIWI_CRYPTKEY64, *PKIWI_CRYPTKEY64;
#endif

typedef struct _KIWI_CRYPT_SEARCH {
	PKULL_M_MEMORY_HANDLE hMemory;
	WORD Machine;
	KIWI_CRYPTKEY32 ProcessKiwiCryptKey32;
#ifdef _M_X64
	KIWI_CRYPTKEY64 ProcessKiwiCryptKey64;
#endif
	BOOL bAllProcessKiwiCryptKey;
	DWORD myPid;
	DWORD prevPid;
	DWORD currPid;
	PCUNICODE_STRING processName;
} KIWI_CRYPT_SEARCH, *PKIWI_CRYPT_SEARCH;

#define RSAENH_KEY_32	0xe35a172c
#define DSSENH_KEY_32	0xa2491d83

#ifdef _M_X64
#define RSAENH_KEY_64	0xe35a172cd96214a0
#define DSSENH_KEY_64	0xa2491d83d96214a0
#endif