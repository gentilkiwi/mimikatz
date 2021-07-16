/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
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

PBYTE kull_m_crypto_ngc_pin_BinaryPinToPinProperty(LPCBYTE pbBinary, DWORD cbBinary, DWORD *pcbResult)
{
	PWSTR data = NULL;
	DWORD i, cbBuffer = cbBinary * 2 + 1;

	if(data = (PWSTR) LocalAlloc(LPTR, cbBuffer * sizeof(wchar_t)))
	{
		for(i = 0; i < cbBinary; i++)
			swprintf_s(data + i * 2, cbBuffer - i * 2, L"%02.2X", pbBinary[i]);
		if(pcbResult)
			*pcbResult = cbBuffer * sizeof(wchar_t);
	}
	return (PBYTE) data;
}

SECURITY_STATUS kull_m_crypto_ngc_hardware_unseal(NCRYPT_PROV_HANDLE hProv, LPCBYTE pbPin, DWORD cbPin, LPCBYTE pbInput, DWORD cbInput, PBYTE *ppOutput, DWORD *pcbOutput)
{
	SECURITY_STATUS status;
	NCRYPT_KEY_HANDLE hSealKey;
	UNK_PIN uPin = {cbPin, 0x46, (PWSTR) pbPin};
	UNK_PADDING uPadding = {0, 1, &uPin};
	DWORD cbResult;

	status = NCryptOpenKey(hProv, &hSealKey, TPM_RSA_SRK_SEAL_KEY, 0, NCRYPT_SILENT_FLAG);
	if(status == ERROR_SUCCESS)
	{
		status = NCryptDecrypt(hSealKey, (PBYTE) pbInput, cbInput, &uPadding, NULL, 0, &cbResult, NCRYPT_SEALING_FLAG);
		if(status == ERROR_SUCCESS)
		{
			if(*ppOutput = (PBYTE) LocalAlloc(LPTR, cbResult))
			{
				status = NCryptDecrypt(hSealKey, (PBYTE) pbInput, cbInput, &uPadding, *ppOutput, cbResult, pcbOutput, NCRYPT_SEALING_FLAG);
				if(status != ERROR_SUCCESS)
				{
					PRINT_ERROR(L"NCryptDecrypt(data): 0x%08x\n", status);
					*ppOutput = (PBYTE) LocalFree(*ppOutput);
					*pcbOutput = 0;
				}
			}
			else status = NTE_NO_MEMORY;
		}
		else PRINT_ERROR(L"NCryptDecrypt(init): 0x%08x\n", status);
		NCryptFreeObject(hSealKey);
	}
	else PRINT_ERROR(L"NCryptOpenKey(seal): 0x%08x\n", status);
	return status;
}

SECURITY_STATUS kull_m_crypto_ngc_software_decrypt(NCRYPT_PROV_HANDLE hProv, LPCWSTR szKeyName, LPCBYTE pbPin, DWORD cbPin, LPCBYTE pbInput, DWORD cbInput, PBYTE *ppOutput, DWORD *pcbOutput)
{
	SECURITY_STATUS status;
	NCRYPT_KEY_HANDLE hKey;
	DWORD cbResult, dwSalt, dwIterations, dwSmartCardPin;
	BYTE DerivedKey[32] = {0}, *SmartCardPin;

	status = NCryptOpenKey(hProv, &hKey, szKeyName, 0, 0x4000); // ?
	if(status == ERROR_SUCCESS)
	{
		status = NCryptGetProperty(hKey, L"NgcSoftwareKeyPbkdf2Salt", (PBYTE) &dwSalt, sizeof(dwSalt), &cbResult, 0x40000000 | NCRYPT_SILENT_FLAG); // ?
		if(status == ERROR_SUCCESS)
		{
			status = NCryptGetProperty(hKey, L"NgcSoftwareKeyPbkdf2Round", (PBYTE) &dwIterations, sizeof(dwIterations), &cbResult, 0x40000000 | NCRYPT_SILENT_FLAG); // ?
			if(status == ERROR_SUCCESS)
			{
				status = BCryptDeriveKeyPBKDF2(BCRYPT_HMAC_SHA256_ALG_HANDLE, (PUCHAR) pbPin, cbPin - sizeof(wchar_t), (PUCHAR) &dwSalt, sizeof(dwSalt), dwIterations, DerivedKey, sizeof(DerivedKey), 0);
				if(status == ERROR_SUCCESS)
				{
					if(SmartCardPin = kull_m_crypto_ngc_pin_BinaryPinToPinProperty(DerivedKey, sizeof(DerivedKey), &dwSmartCardPin))
					{
						status = NCryptSetProperty(hKey, NCRYPT_PIN_PROPERTY, SmartCardPin, dwSmartCardPin - sizeof(wchar_t), NCRYPT_SILENT_FLAG);
						if(status == ERROR_SUCCESS)
						{
							status = NCryptDecrypt(hKey, (PBYTE) pbInput, cbInput, NULL, NULL, 0, &cbResult, NCRYPT_PAD_PKCS1_FLAG | NCRYPT_SILENT_FLAG);
							if(status == ERROR_SUCCESS)
							{
								if(*ppOutput = (PBYTE) LocalAlloc(LPTR, cbResult))
								{
									status = NCryptDecrypt(hKey, (PBYTE) pbInput, cbInput, NULL, *ppOutput, cbResult, pcbOutput, NCRYPT_PAD_PKCS1_FLAG | NCRYPT_SILENT_FLAG);
									if(status != ERROR_SUCCESS)
									{
										PRINT_ERROR(L"NCryptDecrypt(data): 0x%08x\n", status);
										*ppOutput = (PBYTE) LocalFree(*ppOutput);
										*pcbOutput = 0;
									}
								}
								else status = NTE_NO_MEMORY;
							}
							else PRINT_ERROR(L"NCryptDecrypt(init): 0x%08x\n", status);
						}
						else PRINT_ERROR(L"NCryptSetProperty(NCRYPT_PIN_PROPERTY): 0x%08x\n", status);
						LocalFree(SmartCardPin);
					}
					else status = NTE_NO_MEMORY;
				}
				else PRINT_ERROR(L"BCryptDeriveKeyPBKDF2: 0x%08x\n", status);
			}
			else PRINT_ERROR(L"NCryptGetProperty(NgcSoftwareKeyPbkdf2Round): 0x%08x\n", status);
		}
		else PRINT_ERROR(L"NCryptGetProperty(NgcSoftwareKeyPbkdf2Salt): 0x%08x\n", status);
		NCryptFreeObject(hKey);
	}
	else PRINT_ERROR(L"NCryptOpenKey(0x4000): 0x%08x\n", status);

	return status;
}