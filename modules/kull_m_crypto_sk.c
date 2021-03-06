/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_crypto_sk.h"

NTSTATUS SkpOpenAesGcmProvider(BCRYPT_ALG_HANDLE *phAlgAESGCM, DWORD *pObjectLengthAesGcm)
{
	NTSTATUS status;
	DWORD cbResult;
	status = BCryptOpenAlgorithmProvider(phAlgAESGCM, BCRYPT_AES_ALGORITHM, NULL, 0);
	if(NT_SUCCESS(status))
	{
		status = BCryptSetProperty(*phAlgAESGCM, BCRYPT_CHAINING_MODE, (PUCHAR) BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
		if(NT_SUCCESS(status))
		{
				status = BCryptGetProperty(*phAlgAESGCM, BCRYPT_OBJECT_LENGTH, (PUCHAR) pObjectLengthAesGcm, sizeof(DWORD), &cbResult, 0);
				if(!NT_SUCCESS(status))
					PRINT_ERROR(L"BCryptGetProperty: 0x%08x\n", status);
		}
		else PRINT_ERROR(L"BCryptSetProperty: 0x%08x\n", status);
		if(!NT_SUCCESS(status))
			BCryptCloseAlgorithmProvider(*phAlgAESGCM, 0);
	}
	else PRINT_ERROR(L"BCryptOpenAlgorithmProvider: 0x%08x\n", status);
	return status;
}

NTSTATUS SkpOpenKdfProvider(BCRYPT_ALG_HANDLE *phAlgSP800108, DWORD *pObjectLengthSP800108)
{
	NTSTATUS status;
	DWORD cbResult;
	status = BCryptOpenAlgorithmProvider(phAlgSP800108, BCRYPT_SP800108_CTR_HMAC_ALGORITHM, NULL, 0);
	if(NT_SUCCESS(status))
	{
		status = BCryptGetProperty(*phAlgSP800108, BCRYPT_OBJECT_LENGTH, (PUCHAR) pObjectLengthSP800108, sizeof(DWORD), &cbResult, 0);
		if(!NT_SUCCESS(status))
		{
			PRINT_ERROR(L"BCryptGetProperty: 0x%08x\n", status);
			BCryptCloseAlgorithmProvider(*phAlgSP800108, 0);
		}
	}
	else PRINT_ERROR(L"BCryptOpenAlgorithmProvider: 0x%08x\n", status);
	return status;
}

NTSTATUS SkpImportMasterKeyInKdf(PBYTE BootKey, DWORD cbBootKey, BCRYPT_ALG_HANDLE hAlgSP800108, DWORD ObjectLengthSP800108, BCRYPT_KEY_HANDLE *phKeySP800108, UCHAR *pbKeyObject)
{
	return BCryptGenerateSymmetricKey(hAlgSP800108, phKeySP800108, pbKeyObject, ObjectLengthSP800108, BootKey, cbBootKey, 0);
}

NTSTATUS SkpInitSymmetricEncryption(PBYTE BootKey, DWORD cbBootKey, BCRYPT_ALG_HANDLE *phAlgAESGCM, DWORD *pObjectLengthAesGcm, BCRYPT_ALG_HANDLE *phAlgSP800108, DWORD *pObjectLengthSP800108, BCRYPT_KEY_HANDLE *phKeySP800108, PUCHAR *pbKeyObject)
{
	BOOLEAN bIsAlgAESGCM = FALSE, bIsAlgSP800108 = FALSE;
	NTSTATUS status;

	status = SkpOpenAesGcmProvider(phAlgAESGCM, pObjectLengthAesGcm);
	if(NT_SUCCESS(status))
	{
		bIsAlgAESGCM = TRUE;
		status = SkpOpenKdfProvider(phAlgSP800108, pObjectLengthSP800108);
		if(NT_SUCCESS(status))
		{
			bIsAlgSP800108 = TRUE;
			if(*pbKeyObject = (PUCHAR) LocalAlloc(LPTR, *pObjectLengthSP800108))
			{
				status = SkpImportMasterKeyInKdf(BootKey, cbBootKey, *phAlgSP800108, *pObjectLengthSP800108, phKeySP800108, *pbKeyObject);
				if(!NT_SUCCESS(status))
				{
					PRINT_ERROR(L"SkpImportMasterKeyInKdf: 0x%08x\n", status);
					LocalFree(pbKeyObject);
				}
			}
		}
		else PRINT_ERROR(L"SkpOpenKdfProvider: 0x%08x\n", status);
	}
	else PRINT_ERROR(L"SkpOpenAesGcmProvider: 0x%08x\n", status);

	if(!NT_SUCCESS(status))
	{
		if(bIsAlgAESGCM)
			BCryptCloseAlgorithmProvider(*phAlgAESGCM, 0);
		if(bIsAlgSP800108)
			BCryptCloseAlgorithmProvider(*phAlgSP800108, 0);
	}
	return status;
}

NTSTATUS SkpDeriveSymmetricKey(BCRYPT_KEY_HANDLE hKey, CHAR *cLabel, ULONG cbLabel, PBYTE pContext, ULONG cbContext, PUCHAR pbDerivedKey, ULONG cbDerivedKey)
{
	ULONG cbResult;
	BCryptBuffer Buffers[] = {
		{sizeof(BCRYPT_SHA256_ALGORITHM), KDF_HASH_ALGORITHM, BCRYPT_SHA256_ALGORITHM},
		{cbLabel, KDF_LABEL, cLabel},
		{cbContext, KDF_CONTEXT, pContext}
	};
	BCryptBufferDesc ParameterList = {BCRYPTBUFFER_VERSION, ARRAYSIZE(Buffers), Buffers};
	return BCryptKeyDerivation(hKey, &ParameterList, pbDerivedKey, cbDerivedKey, &cbResult, 0);
}

NTSTATUS SkpEncryptionWorker(PBYTE BootKey, DWORD cbBootKey, UCHAR *pbInput, ULONG cbInput, UCHAR *pbAuthData, ULONG cbAuthData, UCHAR *pKdfContext, ULONG cbKdfContext, UCHAR *pbTag, ULONG cbTag, UCHAR *pbOutput, ULONG cbOutput, BOOL Encrypt)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgAESGCM, hAlgSP800108;
	BCRYPT_KEY_HANDLE hKeyAESGCM, hKeySP800108;
	ULONG ObjectLengthAesGcm, ObjectLengthSP800108, cbResult;
	UCHAR *pbKeyObjectAES, *pbKeyObjectSP800108, DerivedKey[32], pbIV[12] = {0};
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
	PBCRYPT_ENCRYPT cryptFunc = Encrypt ? BCryptEncrypt : BCryptDecrypt;

	__try
	{
	status = SkpInitSymmetricEncryption(BootKey, cbBootKey, &hAlgAESGCM, &ObjectLengthAesGcm, &hAlgSP800108, &ObjectLengthSP800108, &hKeySP800108, &pbKeyObjectSP800108);
	if(NT_SUCCESS(status))
	{
		status = SkpDeriveSymmetricKey(hKeySP800108, IUMDATAPROTECT, sizeof(IUMDATAPROTECT), pKdfContext, cbKdfContext, DerivedKey, sizeof(DerivedKey));
		if(NT_SUCCESS(status))
		{
			if(pbKeyObjectAES = (PUCHAR) LocalAlloc(LPTR, ObjectLengthAesGcm))
			{
				status = BCryptGenerateSymmetricKey(hAlgAESGCM, &hKeyAESGCM, pbKeyObjectAES, ObjectLengthAesGcm, DerivedKey, sizeof(DerivedKey), 0);
				if(NT_SUCCESS(status))
				{
					BCRYPT_INIT_AUTH_MODE_INFO(info);
					info.pbNonce = pbIV;
					info.cbNonce = sizeof(pbIV);
					info.pbAuthData = pbAuthData;
					info.cbAuthData = cbAuthData;
					info.pbTag = pbTag;
					info.cbTag = cbTag;
					status = cryptFunc(hKeyAESGCM, pbInput, cbInput, &info, pbIV, sizeof(pbIV), pbOutput, cbOutput, &cbResult, 0);
					BCryptDestroyKey(hKeyAESGCM);
				}
				else PRINT_ERROR(L"BCryptGenerateSymmetricKey: 0x%08x\n", status);
				LocalFree(pbKeyObjectAES);
			}
		}
		else PRINT_ERROR(L"SkpDeriveSymmetricKey: 0x%08x\n", status);
		BCryptDestroyKey(hKeySP800108);
		LocalFree(pbKeyObjectSP800108);
		BCryptCloseAlgorithmProvider(hAlgSP800108, 0);
		BCryptCloseAlgorithmProvider(hAlgAESGCM, 0);
	}
	else PRINT_ERROR(L"SkpInitSymmetricEncryption: 0x%08x\n", status);
	}
	__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND)
	{
		PRINT_ERROR(L"Skp Crypto without CNG?\n");
	}
	return status;
}