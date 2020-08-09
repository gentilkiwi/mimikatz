/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_crypto_ngc.h"

BOOL kull_m_crypto_ngc_keyvalue_derived_software(PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, LPCBYTE Key, DWORD cbKey, PBYTE DerivedKey, DWORD cbDerivedKey)
{
	BOOL status = FALSE;
	NTSTATUS bStatus;
	BCRYPT_ALG_HANDLE hAlgSP800108;
	BCRYPT_KEY_HANDLE hKeySP800108;
	DWORD ObjectLengthSP800108, cbResult;
	PUCHAR pbKeyObjectSP800108;
	BCryptBuffer buffer[] = {
		{cbLabel, KDF_LABEL, pbLabel},
		{cbContext, KDF_CONTEXT, pbContext},
		{sizeof(BCRYPT_SHA256_ALGORITHM), KDF_HASH_ALGORITHM, BCRYPT_SHA256_ALGORITHM},
	};
	BCryptBufferDesc bufferDesc = {BCRYPTBUFFER_VERSION, ARRAYSIZE(buffer), buffer};

	__try
	{
		bStatus = BCryptOpenAlgorithmProvider(&hAlgSP800108, BCRYPT_SP800108_CTR_HMAC_ALGORITHM, NULL, 0);
		if(BCRYPT_SUCCESS(bStatus))
		{
			bStatus = BCryptGetProperty(hAlgSP800108, BCRYPT_OBJECT_LENGTH, (PUCHAR) &ObjectLengthSP800108, sizeof(ObjectLengthSP800108), &cbResult, 0);
			if(BCRYPT_SUCCESS(bStatus))
			{
				if(pbKeyObjectSP800108 = (PUCHAR) LocalAlloc(LPTR, ObjectLengthSP800108))
				{
					bStatus = BCryptGenerateSymmetricKey(hAlgSP800108, &hKeySP800108, pbKeyObjectSP800108, ObjectLengthSP800108, (PUCHAR) Key, cbKey, 0);
					if(BCRYPT_SUCCESS(bStatus))
					{
						bStatus = BCryptKeyDerivation(hKeySP800108, &bufferDesc, DerivedKey, cbDerivedKey, &cbResult, 0);
						if(BCRYPT_SUCCESS(bStatus))
						{
							status = (cbResult == cbDerivedKey);
							if(!status)
								PRINT_ERROR(L"Bad cbResult (%u vs %u)\n", cbResult, cbDerivedKey);
						}
						else PRINT_ERROR(L"BCryptKeyDerivation: 0x%08x\n", bStatus);
						BCryptDestroyKey(hKeySP800108);
					}
					else PRINT_ERROR(L"BCryptGenerateSymmetricKey: 0x%08x\n", bStatus);
					LocalFree(pbKeyObjectSP800108);
				}
			}
			else PRINT_ERROR(L"BCryptGetProperty: 0x%08x\n", bStatus);
			BCryptCloseAlgorithmProvider(hAlgSP800108, 0);
		}
		else PRINT_ERROR(L"BCryptOpenAlgorithmProvider: 0x%08x\n", bStatus);
	}
	__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND)
	{
		PRINT_ERROR(L"No CNG?\n");
	}
	return status;
}

BOOL kull_m_crypto_ngc_keyvalue_derived_hardware(PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, LPCWSTR TransportKeyName, LPCBYTE Key, DWORD cbKey, PBYTE DerivedKey, DWORD cbDerivedKey)
{
	BOOL status = FALSE;
	SECURITY_STATUS nStatus;
	NCRYPT_PROV_HANDLE hProvider;
	NCRYPT_KEY_HANDLE hImportKey, hKey;
	DWORD cbResult;
	NCryptBuffer buffer[] = {
		{cbLabel, KDF_LABEL, pbLabel},
		{cbContext, KDF_CONTEXT, pbContext},
		{sizeof(NCRYPT_SHA256_ALGORITHM), KDF_HASH_ALGORITHM, NCRYPT_SHA256_ALGORITHM},
	};
	NCryptBufferDesc bufferDesc = {NCRYPTBUFFER_VERSION, ARRAYSIZE(buffer), buffer};
	PNCRYPTKEYDERIVATION NCryptKeyDerivation; // tofix

	__try
	{
		nStatus = NCryptOpenStorageProvider(&hProvider, MS_PLATFORM_CRYPTO_PROVIDER, 0);
		if(nStatus == ERROR_SUCCESS)
		{
			nStatus = NCryptOpenKey(hProvider, &hImportKey, TransportKeyName, 0, 0);
			if(nStatus == ERROR_SUCCESS)
			{
				nStatus = NCryptImportKey(hProvider, hImportKey, NCRYPT_OPAQUETRANSPORT_BLOB, NULL, &hKey, (PBYTE) Key, cbKey, 0);
				if(nStatus == ERROR_SUCCESS)
				{
					NCryptKeyDerivation = (PNCRYPTKEYDERIVATION) GetProcAddress(GetModuleHandle(L"ncrypt.dll"), "NCryptKeyDerivation"); // tofix
					if(NCryptKeyDerivation)
					{
						nStatus = NCryptKeyDerivation(hKey, &bufferDesc, DerivedKey, cbDerivedKey, &cbResult, 0);
						if(nStatus == ERROR_SUCCESS)
						{
							status = (cbResult == cbDerivedKey);
							if(!status)
								PRINT_ERROR(L"Bad cbResult (%u vs %u)\n", cbResult, cbDerivedKey);
						}
						else PRINT_ERROR(L"NCryptKeyDerivation: 0x%08x\n", nStatus);
					}
					else PRINT_ERROR(L"No NCryptKeyDerivation?\n", nStatus);
					NCryptFreeObject(hKey);
				}
				else PRINT_ERROR(L"NCryptImportKey: 0x%08x\n", nStatus);
				NCryptFreeObject(hImportKey);
			}
			else PRINT_ERROR(L"NCryptOpenKey: 0x%08x\n", nStatus);
			NCryptFreeObject(hProvider);
		}
		else PRINT_ERROR(L"NCryptOpenStorageProvider: 0x%08x\n", nStatus);
	}
	__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND)
	{
		PRINT_ERROR(L"No CNG?\n");
	}
	return status;
}

BOOL kull_m_crypto_ngc_signature_derived(LPCBYTE pcbKey, DWORD cbKey, LPCBYTE pcbData, DWORD cbData, LPBYTE pbHash, DWORD cbHash)
{
	BOOL status = FALSE;
	NTSTATUS ntStatus;
	BCRYPT_ALG_HANDLE hAlgorithm;
	BCRYPT_HASH_HANDLE hHash;
	DWORD ObjectLength, cbResult;
	PUCHAR pbHashObject;

	__try
	{
		ntStatus = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, MS_PRIMITIVE_PROVIDER, BCRYPT_ALG_HANDLE_HMAC_FLAG);
		if(BCRYPT_SUCCESS(ntStatus))
		{
			ntStatus = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR) &ObjectLength, sizeof(ObjectLength), &cbResult, 0);
			if(BCRYPT_SUCCESS(ntStatus))
			{
				if(pbHashObject = (PUCHAR) LocalAlloc(LPTR, ObjectLength))
				{
					ntStatus = BCryptCreateHash(hAlgorithm, &hHash, pbHashObject, ObjectLength, (PUCHAR) pcbKey, cbKey, 0);
					if(BCRYPT_SUCCESS(ntStatus))
					{
						BCryptHashData(hHash, (PUCHAR) pcbData, cbData, 0);
						ntStatus = BCryptFinishHash(hHash, pbHash, cbHash, 0);
						status = BCRYPT_SUCCESS(ntStatus);
						if(!status)
							PRINT_ERROR(L"BCryptFinishHash: 0x%08x\n", ntStatus);
						BCryptDestroyHash(hHash);
					}
					else PRINT_ERROR(L"BCryptCreateHash: 0x%08x\n", ntStatus);
					LocalFree(pbHashObject);
				}
			}
			else PRINT_ERROR(L"BCryptGetProperty: 0x%08x\n", ntStatus);
			BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		}
		else PRINT_ERROR(L"BCryptOpenAlgorithmProvider: 0x%08x\n", ntStatus);
	}
	__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND)
	{
		PRINT_ERROR(L"No CNG?\n");
	}
	return status;
}

BOOL kull_m_crypto_ngc_signature_pop(PBYTE pbKey, DWORD cbKey, PBYTE pbLabel, DWORD cbLabel, PBYTE pbContext, DWORD cbContext, PBYTE pbData, DWORD cbData, PBYTE *ppbOutput, PDWORD pcbOutput)
{
	BOOL status = FALSE;
	HMODULE hModule;
	PNGCSIGNWITHSYMMETRICPOPKEY NgcSignWithSymmetricPopKey;
	NTSTATUS ntStatus;

	*ppbOutput = NULL;
	*pcbOutput = 0;

	hModule = LoadLibrary(L"cryptngc.dll");
	if(hModule)
	{
		NgcSignWithSymmetricPopKey = (PNGCSIGNWITHSYMMETRICPOPKEY) GetProcAddress(hModule, "NgcSignWithSymmetricPopKey");
		if(NgcSignWithSymmetricPopKey)
		{
			ntStatus = NgcSignWithSymmetricPopKey(pbKey, cbKey, pbLabel, cbLabel, pbContext, cbContext, pbData, cbData, ppbOutput, pcbOutput);
			status = ntStatus == STATUS_SUCCESS;
			if(!status)
				PRINT_ERROR(L"NgcSignWithSymmetricPopKey: 0x%08x\n", ntStatus);
		}
		else PRINT_ERROR(L"No NgcSignWithSymmetricPopKey?\n");
		FreeLibrary(hModule);
	}
	else PRINT_ERROR_AUTO(L"LoadLibrary");
	return status;
}