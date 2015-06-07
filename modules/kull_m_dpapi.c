/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kull_m_dpapi.h"

void kull_m_dpapi_ptr_replace(PVOID ptr, DWORD64 size)
{
	PVOID tempPtr = NULL;
	if(size)
		if(tempPtr = LocalAlloc(LPTR, (SIZE_T) size))
			RtlCopyMemory(tempPtr, *(PVOID *) ptr, (size_t) size);
	*(PVOID *) ptr = tempPtr;
}

PKULL_M_DPAPI_BLOB kull_m_dpapi_blob_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_DPAPI_BLOB blob = NULL;
	if(blob = (PKULL_M_DPAPI_BLOB) LocalAlloc(LPTR, sizeof(KULL_M_DPAPI_BLOB)))
	{
		RtlCopyMemory(blob, data, FIELD_OFFSET(KULL_M_DPAPI_BLOB, szDescription));
		blob->szDescription = (PWSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_BLOB, szDescription));
		RtlCopyMemory(&blob->algCrypt, (PBYTE) blob->szDescription + blob->dwDescriptionLen, blob->dwDescriptionLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbSalt) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, algCrypt));
		blob->pbSalt = (PBYTE) blob->szDescription + blob->dwDescriptionLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbSalt) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, algCrypt);
		blob->dwHmacKeyLen = *(PDWORD) ((PBYTE) blob->pbSalt + blob->dwSaltLen);
		blob->pbHmackKey = (PBYTE) blob->pbSalt + blob->dwSaltLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbHmackKey) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, dwHmacKeyLen);
		RtlCopyMemory(&blob->algHash, (PBYTE) blob->pbHmackKey + blob->dwHmacKeyLen, blob->dwHmacKeyLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbHmack2Key) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, algHash));
		blob->pbHmack2Key = (PBYTE) blob->pbHmackKey + blob->dwHmacKeyLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbHmack2Key) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, algHash);
		blob->dwDataLen = *(PDWORD) ((PBYTE) blob->pbHmack2Key + blob->dwHmac2KeyLen);
		blob->pbData = (PBYTE) blob->pbHmack2Key + blob->dwHmac2KeyLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbData) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, dwDataLen);
		blob->dwSignLen = *(PDWORD) ((PBYTE) blob->pbData + blob->dwDataLen);
		blob->pbSign = (PBYTE) blob->pbData + blob->dwDataLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbSign) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, dwSignLen);
		
		kull_m_dpapi_ptr_replace(&blob->szDescription, blob->dwDescriptionLen);
		kull_m_dpapi_ptr_replace(&blob->pbSalt, blob->dwSaltLen);
		kull_m_dpapi_ptr_replace(&blob->pbHmackKey, blob->dwHmacKeyLen);
		kull_m_dpapi_ptr_replace(&blob->pbHmack2Key, blob->dwHmac2KeyLen);
		kull_m_dpapi_ptr_replace(&blob->pbData, blob->dwDataLen);
		kull_m_dpapi_ptr_replace(&blob->pbSign, blob->dwSignLen);
	}
	return blob;
}

void kull_m_dpapi_blob_delete(PKULL_M_DPAPI_BLOB blob)
{
	if(blob)
	{
		if(blob->szDescription)
			LocalFree(blob->szDescription);
		if(blob->pbSalt)
			LocalFree(blob->pbSalt);
		if(blob->pbHmackKey)
			LocalFree(blob->pbHmackKey);
		if(blob->pbHmack2Key)
			LocalFree(blob->pbHmack2Key);
		if(blob->pbData)
			LocalFree(blob->pbData);
		if(blob->pbSign)
			LocalFree(blob->pbSign);
		LocalFree(blob);
	}
}

void kull_m_dpapi_blob_descr(PKULL_M_DPAPI_BLOB blob)
{
	kprintf(L"**BLOB**\n");
	if(blob)
	{
		kprintf(L"  dwVersion          : %08x - %u\n", blob->dwVersion, blob->dwVersion);
		kprintf(L"  guidProvider       : "); kull_m_string_displayGUID(&blob->guidProvider); kprintf(L"\n");
		kprintf(L"  dwMasterKeyVersion : %08x - %u\n", blob->dwMasterKeyVersion, blob->dwMasterKeyVersion);
		kprintf(L"  guidMasterKey      : "); kull_m_string_displayGUID(&blob->guidMasterKey); kprintf(L"\n");
		kprintf(L"  dwFlags            : %08x - %u\n", blob->dwFlags, blob->dwFlags);
		kprintf(L"  dwDescriptionLen   : %08x - %u\n", blob->dwDescriptionLen, blob->dwDescriptionLen);
		kprintf(L"  szDescription      : %s\n", blob->szDescription);
		kprintf(L"  algCrypt           : %08x - %u (%s)\n", blob->algCrypt, blob->algCrypt, kull_m_crypto_algid_to_name(blob->algCrypt));
		kprintf(L"  dwAlgCryptLen      : %08x - %u\n", blob->dwAlgCryptLen, blob->dwAlgCryptLen);
		kprintf(L"  dwSaltLen          : %08x - %u\n", blob->dwSaltLen, blob->dwSaltLen);
		kprintf(L"  pbSalt             : "); kull_m_string_wprintf_hex(blob->pbSalt, blob->dwSaltLen, 0); kprintf(L"\n");
		kprintf(L"  dwHmacKeyLen       : %08x - %u\n", blob->dwHmacKeyLen, blob->dwHmacKeyLen);
		kprintf(L"  pbHmackKey         : "); kull_m_string_wprintf_hex(blob->pbHmackKey, blob->dwHmacKeyLen, 0); kprintf(L"\n");
		kprintf(L"  algHash            : %08x - %u (%s)\n", blob->algHash, blob->algHash, kull_m_crypto_algid_to_name(blob->algHash));
		kprintf(L"  dwAlgHashLen       : %08x - %u\n", blob->dwAlgHashLen, blob->dwAlgHashLen);
		kprintf(L"  dwHmac2KeyLen      : %08x - %u\n", blob->dwHmac2KeyLen, blob->dwHmac2KeyLen);
		kprintf(L"  pbHmack2Key        : "); kull_m_string_wprintf_hex(blob->pbHmack2Key, blob->dwHmac2KeyLen, 0); kprintf(L"\n");
		kprintf(L"  dwDataLen          : %08x - %u\n", blob->dwDataLen, blob->dwDataLen);
		kprintf(L"  pbData             : "); kull_m_string_wprintf_hex(blob->pbData, blob->dwDataLen, 0); kprintf(L"\n");
		kprintf(L"  dwSignLen          : %08x - %u\n", blob->dwSignLen, blob->dwSignLen);
		kprintf(L"  pbSign             : "); kull_m_string_wprintf_hex(blob->pbSign, blob->dwSignLen, 0); kprintf(L"\n");
	}
}

PKULL_M_DPAPI_MASTERKEY kull_m_dpapi_masterkey_create(PVOID data, DWORD64 size)
{
	PKULL_M_DPAPI_MASTERKEY masterkey = NULL;
	if(masterkey = (PKULL_M_DPAPI_MASTERKEY) LocalAlloc(LPTR, sizeof(KULL_M_DPAPI_MASTERKEY)))
	{
		RtlCopyMemory(masterkey, data, FIELD_OFFSET(KULL_M_DPAPI_MASTERKEY, pbKey));
		masterkey->pbKey = (PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEY, pbKey);
		masterkey->__dwKeyLen = (DWORD) size - FIELD_OFFSET(KULL_M_DPAPI_MASTERKEY, pbKey);
		kull_m_dpapi_ptr_replace(&masterkey->pbKey, masterkey->__dwKeyLen);
	}
	return masterkey;
}

void kull_m_dpapi_masterkey_delete(PKULL_M_DPAPI_MASTERKEY masterkey)
{
	if(masterkey)
	{
		if(masterkey->pbKey)
			LocalFree(masterkey->pbKey);
		LocalFree(masterkey);
	}
}

void kull_m_dpapi_masterkey_descr(PKULL_M_DPAPI_MASTERKEY masterkey)
{
	kprintf(L"  **MASTERKEY**\n");
	if(masterkey)
	{
		kprintf(L"    dwVersion        : %08x - %u\n", masterkey->dwVersion, masterkey->dwVersion);
		kprintf(L"    salt             : "); kull_m_string_wprintf_hex(masterkey->salt, sizeof(masterkey->salt), 0); kprintf(L"\n");
		kprintf(L"    rounds           : %08x - %u\n", masterkey->rounds, masterkey->rounds);
		kprintf(L"    algHash          : %08x - %u (%s)\n", masterkey->algHash, masterkey->algHash, kull_m_crypto_algid_to_name(masterkey->algHash));
		kprintf(L"    algCrypt         : %08x - %u (%s)\n", masterkey->algCrypt, masterkey->algCrypt, kull_m_crypto_algid_to_name(masterkey->algCrypt));
		kprintf(L"    pbKey            : "); kull_m_string_wprintf_hex(masterkey->pbKey, masterkey->__dwKeyLen, 0); kprintf(L"\n");
	}
}

PKULL_M_DPAPI_CREDHIST kull_m_dpapi_credhist_create(PVOID data, DWORD64 size)
{
	PKULL_M_DPAPI_CREDHIST credhist = NULL;
	if(credhist = (PKULL_M_DPAPI_CREDHIST) LocalAlloc(LPTR, sizeof(KULL_M_DPAPI_CREDHIST)))
		RtlCopyMemory(credhist, data, sizeof(KULL_M_DPAPI_CREDHIST));
	return credhist;
}

void kull_m_dpapi_credhist_delete(PKULL_M_DPAPI_CREDHIST credhist)
{
	if(credhist)
		LocalFree(credhist);
}

void kull_m_dpapi_credhist_descr(PKULL_M_DPAPI_CREDHIST credhist)
{
	kprintf(L"  **CREDHIST**\n");
	if(credhist)
	{
		kprintf(L"    dwVersion        : %08x - %u\n", credhist->dwVersion, credhist->dwVersion);
		kprintf(L"    guid             : "); kull_m_string_displayGUID(&credhist->guid); kprintf(L"\n");
	}
}

PKULL_M_DPAPI_DOMAINKEY kull_m_dpapi_domainkey_create(PVOID data, DWORD64 size)
{
	PKULL_M_DPAPI_DOMAINKEY domainkey = NULL;
	if(domainkey = (PKULL_M_DPAPI_DOMAINKEY) LocalAlloc(LPTR, sizeof(KULL_M_DPAPI_DOMAINKEY)))
	{
		RtlCopyMemory(domainkey, data, FIELD_OFFSET(KULL_M_DPAPI_DOMAINKEY, pbSecret));
		domainkey->pbSecret = (PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_DOMAINKEY, pbSecret);
		domainkey->pbAccesscheck = (PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_DOMAINKEY, pbSecret) + domainkey->dwSecretLen;
		kull_m_dpapi_ptr_replace(&domainkey->pbSecret, domainkey->dwSecretLen);
		kull_m_dpapi_ptr_replace(&domainkey->pbAccesscheck, domainkey->dwAccesscheckLen);
	}
	return domainkey;
}

void kull_m_dpapi_domainkey_delete(PKULL_M_DPAPI_DOMAINKEY domainkey)
{
	if(domainkey)
	{
		if(domainkey->pbSecret)
			LocalFree(domainkey->pbSecret);
		if(domainkey->pbAccesscheck)
			LocalFree(domainkey->pbAccesscheck);
		LocalFree(domainkey);
	}
}

void kull_m_dpapi_domainkey_descr(PKULL_M_DPAPI_DOMAINKEY domainkey)
{
	kprintf(L"  **DOMAINKEY**\n");
	if(domainkey)
	{
		kprintf(L"    dwVersion        : %08x - %u\n", domainkey->dwVersion, domainkey->dwVersion);
		kprintf(L"    dwSecretLen      : %08x - %u\n", domainkey->dwSecretLen, domainkey->dwSecretLen);
		kprintf(L"    dwAccesscheckLen : %08x - %u\n", domainkey->dwAccesscheckLen, domainkey->dwAccesscheckLen);
		kprintf(L"    guidMasterKey    : "); kull_m_string_displayGUID(&domainkey->guidMasterKey); kprintf(L"\n");
		kprintf(L"    pbSecret         : "); kull_m_string_wprintf_hex(domainkey->pbSecret, domainkey->dwSecretLen, 0); kprintf(L"\n");
		kprintf(L"    pbAccesscheck    : "); kull_m_string_wprintf_hex(domainkey->pbAccesscheck, domainkey->dwAccesscheckLen, 0); kprintf(L"\n");
	}
}

PKULL_M_DPAPI_MASTERKEYS kull_m_dpapi_masterkeys_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_DPAPI_MASTERKEYS masterkeys = NULL;
	if(masterkeys = (PKULL_M_DPAPI_MASTERKEYS) LocalAlloc(LPTR, sizeof(KULL_M_DPAPI_MASTERKEYS)))
	{
		RtlCopyMemory(masterkeys, data, FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey));
		if(masterkeys->dwMasterKeyLen)
			masterkeys->MasterKey = kull_m_dpapi_masterkey_create((PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey) + 0, masterkeys->dwMasterKeyLen);
		if(masterkeys->dwBackupKeyLen)
			masterkeys->BackupKey = kull_m_dpapi_masterkey_create((PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey) + masterkeys->dwMasterKeyLen, masterkeys->dwBackupKeyLen);
		if(masterkeys->dwCredHistLen)
			masterkeys->CredHist = kull_m_dpapi_credhist_create((PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey) + masterkeys->dwMasterKeyLen + masterkeys->dwBackupKeyLen, masterkeys->dwCredHistLen);
		if(masterkeys->dwDomainKeyLen)
			masterkeys->DomainKey = kull_m_dpapi_domainkey_create((PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey) + masterkeys->dwMasterKeyLen + masterkeys->dwBackupKeyLen + masterkeys->dwCredHistLen, masterkeys->dwDomainKeyLen);
	}
	return masterkeys;
}

void kull_m_dpapi_masterkeys_delete(PKULL_M_DPAPI_MASTERKEYS masterkeys)
{
	if(masterkeys)
	{
		if(masterkeys->MasterKey)
			kull_m_dpapi_masterkey_delete(masterkeys->MasterKey);
		if(masterkeys->BackupKey)
			kull_m_dpapi_masterkey_delete(masterkeys->BackupKey);
		if(masterkeys->CredHist)
			kull_m_dpapi_credhist_delete(masterkeys->CredHist);
		if(masterkeys->DomainKey)
			kull_m_dpapi_domainkey_delete(masterkeys->DomainKey);
		LocalFree(masterkeys);
	}
}

void kull_m_dpapi_masterkeys_descr(PKULL_M_DPAPI_MASTERKEYS masterkeys)
{
	kprintf(L"**MASTERKEYS**\n");
	if(masterkeys)
	{
		kprintf(L"  dwVersion          : %08x - %u\n", masterkeys->dwVersion, masterkeys->dwVersion);
		kprintf(L"  szGuid             : {%.36s}\n", masterkeys->szGuid);
		kprintf(L"  dwFlags            : %08x - %u\n", masterkeys->dwFlags, masterkeys->dwFlags);
		kprintf(L"  dwMasterKeyLen     : %08x - %u\n", (DWORD) masterkeys->dwMasterKeyLen, (DWORD) masterkeys->dwMasterKeyLen);
		kprintf(L"  dwBackupKeyLen     : %08x - %u\n", (DWORD) masterkeys->dwBackupKeyLen, (DWORD) masterkeys->dwBackupKeyLen);
		kprintf(L"  dwCredHistLen      : %08x - %u\n", (DWORD) masterkeys->dwCredHistLen, (DWORD) masterkeys->dwCredHistLen);
		kprintf(L"  dwDomainKeyLen     : %08x - %u\n", (DWORD) masterkeys->dwDomainKeyLen, (DWORD) masterkeys->dwDomainKeyLen);
		
		if(masterkeys->MasterKey)
		{
			kprintf(L"[masterkey]\n");
			kull_m_dpapi_masterkey_descr(masterkeys->MasterKey);
		}
		if(masterkeys->BackupKey)
		{
			kprintf(L"[backupkey]\n");
			kull_m_dpapi_masterkey_descr(masterkeys->BackupKey);
		}
		if(masterkeys->CredHist)
		{
			kprintf(L"[credhist]\n");
			kull_m_dpapi_credhist_descr(masterkeys->CredHist);
		}
		if(masterkeys->DomainKey)
		{
			kprintf(L"[domainkey]\n");
			kull_m_dpapi_domainkey_descr(masterkeys->DomainKey);
		}
	}
}

BOOL kull_m_dpapi_hmac_sha1_incorrect(LPCVOID key, DWORD keyLen, LPCVOID salt, DWORD saltLen, LPCVOID entropy, DWORD entropyLen, LPCVOID data, DWORD dataLen, LPVOID outKey)
{
	BOOL status = FALSE;
	BYTE ipad[64], opad[64], hash[SHA_DIGEST_LENGTH], *bufferI, *bufferO;
	DWORD i;

	RtlFillMemory(ipad, sizeof(ipad), '6');
	RtlFillMemory(opad, sizeof(opad), '\\');
	for(i = 0; i < keyLen; i++)
	{
		ipad[i] ^= ((PBYTE) key)[i];
		opad[i] ^= ((PBYTE) key)[i];
	}
	if(bufferI = (PBYTE) LocalAlloc(LPTR, sizeof(ipad) + saltLen))
	{
		RtlCopyMemory(bufferI, ipad, sizeof(ipad));
		RtlCopyMemory(bufferI + sizeof(ipad), salt, saltLen);
		if(kull_m_crypto_hash(CALG_SHA1, bufferI, sizeof(ipad) + saltLen, hash, SHA_DIGEST_LENGTH))
		{
			if(bufferO = (PBYTE) LocalAlloc(LPTR, sizeof(opad) + SHA_DIGEST_LENGTH + entropyLen + dataLen))
			{
				RtlCopyMemory(bufferO, opad, sizeof(opad));
				RtlCopyMemory(bufferO + sizeof(opad), hash, SHA_DIGEST_LENGTH);
				if(entropy && entropyLen)
					RtlCopyMemory(bufferO + sizeof(opad) + SHA_DIGEST_LENGTH, entropy, entropyLen);
				if(data && dataLen)
					RtlCopyMemory(bufferO + sizeof(opad) + SHA_DIGEST_LENGTH + entropyLen, data, dataLen);
				
				status = kull_m_crypto_hash(CALG_SHA1, bufferO, sizeof(opad) + SHA_DIGEST_LENGTH + entropyLen + dataLen, outKey, SHA_DIGEST_LENGTH);
				LocalFree(bufferO);
			}
		}
		LocalFree(bufferI);
	}
	return status;
}

BOOL kull_m_dpapi_sessionkey(LPCVOID masterkey, DWORD masterkeyLen, LPCVOID salt, DWORD saltLen, LPCVOID entropy, DWORD entropyLen, LPCVOID data, DWORD dataLen, ALG_ID hashAlg, LPVOID outKey, DWORD outKeyLen)
{
	BOOL status = FALSE;
	LPCVOID pKey = NULL;
	BYTE dgstMasterKey[SHA_DIGEST_LENGTH];
	PBYTE tmp;
	if(masterkeyLen == SHA_DIGEST_LENGTH)
		pKey = masterkey;
	else if(kull_m_crypto_hash(CALG_SHA1, masterkey, masterkeyLen, dgstMasterKey, SHA_DIGEST_LENGTH))
		pKey = dgstMasterKey;
	
	if(pKey)
	{
		if((hashAlg == CALG_SHA1) && (entropy || data))
			status = kull_m_dpapi_hmac_sha1_incorrect(masterkey, masterkeyLen, salt, saltLen, entropy, entropyLen, data, dataLen, outKey);
		else if(tmp = (PBYTE) LocalAlloc(LPTR, saltLen + entropyLen + dataLen))
		{
			RtlCopyMemory(tmp, salt, saltLen);
			if(entropy && entropyLen)
				RtlCopyMemory(tmp + saltLen, entropy, entropyLen);
			if(data && dataLen)
				RtlCopyMemory(tmp + saltLen + entropyLen, data, dataLen);
			status = kull_m_crypto_hmac(hashAlg, pKey, SHA_DIGEST_LENGTH, tmp, saltLen + entropyLen + dataLen, outKey, outKeyLen);
			LocalFree(tmp);
		}
	}
	return status;
}

BOOL kull_m_dpapi_unprotect_blob(PKULL_M_DPAPI_BLOB blob, LPCVOID masterkey, DWORD masterkeyLen, LPCVOID entropy, DWORD entropyLen, LPCWSTR password, LPVOID *dataOut, DWORD *dataOutLen)
{
	BOOL status = FALSE, iStatus = !password;
	PVOID hmac, key, hashPassword = NULL;
	HCRYPTPROV hSessionProv;
	HCRYPTKEY hSessionKey;
	DWORD hashLen =  blob->dwAlgHashLen / 8, cryptLen = blob->dwAlgCryptLen / 8, hashPasswordLen;
	ALG_ID passwordHash;

	if((blob->algCrypt == CALG_3DES) && (cryptLen < (192 / 8)))
		cryptLen = 192 / 8;

	if(!iStatus)
	{
		if(blob->algHash == CALG_SHA_512)
		{
			passwordHash = CALG_SHA_512;
			hashPasswordLen = hashLen;
		}
		else
		{
			passwordHash = CALG_SHA1;
			hashPasswordLen = SHA_DIGEST_LENGTH;
		}
		if(hashPassword = LocalAlloc(LPTR, hashPasswordLen))
			iStatus = kull_m_crypto_hash(passwordHash, password, (DWORD) (wcslen(password) * sizeof(wchar_t)), hashPassword, hashPasswordLen);
	}

	if(iStatus)
	{
		if(hmac = LocalAlloc(LPTR, hashLen))
		{
			if(kull_m_dpapi_sessionkey(masterkey, masterkeyLen, blob->pbSalt, blob->dwSaltLen, entropy, entropyLen, hashPassword, hashPassword ? hashPasswordLen : 0, blob->algHash, hmac, hashLen))
			{
				if(key = LocalAlloc(LPTR, cryptLen))
				{
					if(kull_m_crypto_DeriveKeyRaw(blob->algHash, hmac, hashLen, key, cryptLen))
					{
						if(kull_m_crypto_hkey_session(blob->algCrypt, key, cryptLen, 0, &hSessionKey, &hSessionProv))
						{
							if(*dataOut = LocalAlloc(LPTR, blob->dwDataLen))
							{
								RtlCopyMemory(*dataOut, blob->pbData, blob->dwDataLen);
								*dataOutLen = blob->dwDataLen;
								status = CryptDecrypt(hSessionKey, 0, TRUE, 0, (LPBYTE) *dataOut, dataOutLen);
								if(!status)
								{
									LocalFree(*dataOut);	
									PRINT_ERROR_AUTO(L"CryptDecrypt");
								}
							}
							CryptDestroyKey(hSessionKey);
							if(!kull_m_crypto_close_hprov_delete_container(hSessionProv))
								PRINT_ERROR_AUTO(L"kull_m_crypto_close_hprov_delete_container");
						}
						else PRINT_ERROR_AUTO(L"kull_m_crypto_hkey_session");
					}
					LocalFree(key);
				}
			}
			LocalFree(hmac);
		}
	}

	if(hashPassword)
		LocalFree(hashPassword);
	return status;
}

const PCWCHAR DPAPIPromptFlagsToStrings[] = {
	L"on_unprotect", L"on_protect", L"reserved", L"strong", L"require_strong",
};
void kull_m_dpapi_displayPromptFlags(DWORD flags)
{
	DWORD i;
	for(i = 0; i < ARRAYSIZE(DPAPIPromptFlagsToStrings); i++)
		if((flags >> i) & 1)
			kprintf(L"%s ; ", DPAPIPromptFlagsToStrings[i]);
}

const PCWCHAR DPAPIProtectFlagsToStrings[] = {
	L"ui_forbidden", L"unknown", L"local_machine", L"cred_sync",
	L"audit", L"no_recovery", L"verify_protection", L"cred_regenerate"
};
void kull_m_dpapi_displayProtectionFlags(DWORD flags)
{
	DWORD i;
	for(i = 0; i < ARRAYSIZE(DPAPIProtectFlagsToStrings); i++)
		if((flags >> i) & 1)
			kprintf(L"%s ; ", DPAPIProtectFlagsToStrings[i]);
	if(flags & 0x20000000)
		kprintf(L"%s ; ", "system");
}