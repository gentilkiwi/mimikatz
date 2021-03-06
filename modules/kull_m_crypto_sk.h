/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_string.h"

#if !defined(BCRYPT_SP800108_CTR_HMAC_ALGORITHM)
#define BCRYPT_SP800108_CTR_HMAC_ALGORITHM	L"SP800_108_CTR_HMAC"
#define KDF_LABEL			0xD
#define KDF_CONTEXT			0xE
#define KDF_SALT			0xF
#define KDF_ITERATION_COUNT	0x10

extern NTSTATUS WINAPI BCryptKeyDerivation(IN BCRYPT_KEY_HANDLE hKey, IN OPTIONAL BCryptBufferDesc *pParameterList, OUT PUCHAR pbDerivedKey, IN ULONG cbDerivedKey, OUT ULONG *pcbResult, IN ULONG dwFlags);
#endif

#define IUMDATAPROTECT	"IUMDATAPROTECT"
typedef NTSTATUS	(WINAPI * PBCRYPT_ENCRYPT)					(__inout BCRYPT_KEY_HANDLE hKey, __in_bcount_opt(cbInput) PUCHAR pbInput, __in ULONG cbInput, __in_opt VOID *pPaddingInfo, __inout_bcount_opt(cbIV) PUCHAR pbIV, __in ULONG cbIV, __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR pbOutput, __in ULONG cbOutput, __out ULONG *pcbResult, __in ULONG dwFlags);

NTSTATUS SkpOpenAesGcmProvider(BCRYPT_ALG_HANDLE *phAlgAESGCM, DWORD *pObjectLengthAesGcm);
NTSTATUS SkpOpenKdfProvider(BCRYPT_ALG_HANDLE *phAlgSP800108, DWORD *pObjectLengthSP800108);
NTSTATUS SkpImportMasterKeyInKdf(PBYTE BootKey, DWORD cbBootKey, BCRYPT_ALG_HANDLE hAlgSP800108, DWORD ObjectLengthSP800108, BCRYPT_KEY_HANDLE *phKeySP800108, UCHAR *pbKeyObject);
NTSTATUS SkpInitSymmetricEncryption(PBYTE BootKey, DWORD cbBootKey, BCRYPT_ALG_HANDLE *phAlgAESGCM, DWORD *pObjectLengthAesGcm, BCRYPT_ALG_HANDLE *phAlgSP800108, DWORD *pObjectLengthSP800108, BCRYPT_KEY_HANDLE *phKeySP800108, PUCHAR *pbKeyObject);
NTSTATUS SkpDeriveSymmetricKey(BCRYPT_KEY_HANDLE hKey, CHAR *cLabel, ULONG cbLabel, PBYTE pContext, ULONG cbContext, PUCHAR pbDerivedKey, ULONG cbDerivedKey);
NTSTATUS SkpEncryptionWorker(PBYTE BootKey, DWORD cbBootKey, UCHAR *pbInput, ULONG cbInput, UCHAR *pbAuthData, ULONG cbAuthData, UCHAR *pKdfContext, ULONG cbKdfContext, UCHAR *pbTag, ULONG cbTag, UCHAR *pbOutput, ULONG cbOutput, BOOL Encrypt);