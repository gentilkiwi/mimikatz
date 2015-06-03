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
		kprintf(L"    dwVersion          : %08x - %u\n", masterkey->dwVersion, masterkey->dwVersion);
		kprintf(L"    salt               : "); kull_m_string_wprintf_hex(masterkey->salt, sizeof(masterkey->salt), 0); kprintf(L"\n");
		kprintf(L"    rounds             : %08x - %u\n", masterkey->rounds, masterkey->rounds);
		kprintf(L"    algHash            : %08x - %u (%s)\n", masterkey->algHash, masterkey->algHash, kull_m_crypto_algid_to_name(masterkey->algHash));
		kprintf(L"    algCrypt           : %08x - %u (%s)\n", masterkey->algCrypt, masterkey->algCrypt, kull_m_crypto_algid_to_name(masterkey->algCrypt));
		kprintf(L"    pbKey              : "); kull_m_string_wprintf_hex(masterkey->pbKey, masterkey->__dwKeyLen, 0); kprintf(L"\n");
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
		kprintf(L"    dwVersion          : %08x - %u\n", credhist->dwVersion, credhist->dwVersion);
		kprintf(L"    guid               : "); kull_m_string_displayGUID(&credhist->guid); kprintf(L"\n");
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
		kprintf(L"    dwVersion          : %08x - %u\n", domainkey->dwVersion, domainkey->dwVersion);
		kprintf(L"    dwSecretLen        : %08x - %u\n", domainkey->dwSecretLen, domainkey->dwSecretLen);
		kprintf(L"    dwAccesscheckLen   : %08x - %u\n", domainkey->dwAccesscheckLen, domainkey->dwAccesscheckLen);
		kprintf(L"    guidMasterKey      : "); kull_m_string_displayGUID(&domainkey->guidMasterKey); kprintf(L"\n");
		kprintf(L"    pbSecret           : "); kull_m_string_wprintf_hex(domainkey->pbSecret, domainkey->dwSecretLen, 0); kprintf(L"\n");
		kprintf(L"    pbAccesscheck      : "); kull_m_string_wprintf_hex(domainkey->pbAccesscheck, domainkey->dwAccesscheckLen, 0); kprintf(L"\n");
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
		kprintf(L"  dwMasterKeyLen     : %016llx - %u\n", masterkeys->dwMasterKeyLen, masterkeys->dwMasterKeyLen);
		kprintf(L"  dwBackupKeyLen     : %016llx - %u\n", masterkeys->dwBackupKeyLen, masterkeys->dwBackupKeyLen);
		kprintf(L"  dwCredHistLen      : %016llx - %u\n", masterkeys->dwCredHistLen, masterkeys->dwCredHistLen);
		kprintf(L"  dwDomainKeyLen     : %016llx - %u\n", masterkeys->dwDomainKeyLen, masterkeys->dwDomainKeyLen);
		
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