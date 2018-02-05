/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_dpapi.h"
										
const GUID KULL_M_DPAPI_GUID_PROVIDER = CRYPTPROTECT_DEFAULT_PROVIDER;

PKULL_M_DPAPI_BLOB kull_m_dpapi_blob_create(LPCVOID data/*, DWORD size*/)
{
	PKULL_M_DPAPI_BLOB blob = NULL;
	if(data && (blob = (PKULL_M_DPAPI_BLOB) LocalAlloc(LPTR, sizeof(KULL_M_DPAPI_BLOB))))
	{
		RtlCopyMemory(blob, data, FIELD_OFFSET(KULL_M_DPAPI_BLOB, szDescription));
		blob->szDescription = (PWSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_BLOB, szDescription));
		RtlCopyMemory(&blob->algCrypt, (PBYTE) blob->szDescription + blob->dwDescriptionLen, /*blob->dwDescriptionLen + */FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbSalt) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, algCrypt));

		blob->pbSalt = (PBYTE) blob->szDescription + blob->dwDescriptionLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbSalt) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, algCrypt);
		blob->dwHmacKeyLen = *(PDWORD) ((PBYTE) blob->pbSalt + blob->dwSaltLen);
		blob->pbHmackKey = (PBYTE) blob->pbSalt + blob->dwSaltLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbHmackKey) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, dwHmacKeyLen);
		RtlCopyMemory(&blob->algHash, (PBYTE) blob->pbHmackKey + blob->dwHmacKeyLen, /*blob->dwHmacKeyLen + */FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbHmack2Key) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, algHash));
		blob->pbHmack2Key = (PBYTE) blob->pbHmackKey + blob->dwHmacKeyLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbHmack2Key) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, algHash);
		blob->dwDataLen = *(PDWORD) ((PBYTE) blob->pbHmack2Key + blob->dwHmac2KeyLen);
		blob->pbData = (PBYTE) blob->pbHmack2Key + blob->dwHmac2KeyLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbData) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, dwDataLen);
		blob->dwSignLen = *(PDWORD) ((PBYTE) blob->pbData + blob->dwDataLen);
		blob->pbSign = (PBYTE) blob->pbData + blob->dwDataLen + FIELD_OFFSET(KULL_M_DPAPI_BLOB, pbSign) - FIELD_OFFSET(KULL_M_DPAPI_BLOB, dwSignLen);
		
		kull_m_string_ptr_replace(&blob->szDescription, blob->dwDescriptionLen);
		kull_m_string_ptr_replace(&blob->pbSalt, blob->dwSaltLen);
		kull_m_string_ptr_replace(&blob->pbHmackKey, blob->dwHmacKeyLen);
		kull_m_string_ptr_replace(&blob->pbHmack2Key, blob->dwHmac2KeyLen);
		kull_m_string_ptr_replace(&blob->pbData, blob->dwDataLen);
		kull_m_string_ptr_replace(&blob->pbSign, blob->dwSignLen);
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

void kull_m_dpapi_blob_descr(DWORD level, PKULL_M_DPAPI_BLOB blob)
{
	kprintf(L"%*s" L"**BLOB**\n", level << 1, L"");
	if(blob)
	{
		kprintf(L"%*s" L"  dwVersion          : %08x - %u\n", level << 1, L"", blob->dwVersion, blob->dwVersion);
		kprintf(L"%*s" L"  guidProvider       : ", level << 1, L""); kull_m_string_displayGUID(&blob->guidProvider); kprintf(L"\n");
		kprintf(L"%*s" L"  dwMasterKeyVersion : %08x - %u\n", level << 1, L"", blob->dwMasterKeyVersion, blob->dwMasterKeyVersion);
		kprintf(L"%*s" L"  guidMasterKey      : ", level << 1, L""); kull_m_string_displayGUID(&blob->guidMasterKey); kprintf(L"\n");
		kprintf(L"%*s" L"  dwFlags            : %08x - %u (", level << 1, L"", blob->dwFlags, blob->dwFlags);
		kull_m_dpapi_displayBlobFlags(blob->dwFlags);
		kprintf(L")\n");
		kprintf(L"%*s" L"  dwDescriptionLen   : %08x - %u\n", level << 1, L"", blob->dwDescriptionLen, blob->dwDescriptionLen);
		kprintf(L"%*s" L"  szDescription      : %s\n", level << 1, L"", blob->szDescription);
		kprintf(L"%*s" L"  algCrypt           : %08x - %u (%s)\n", level << 1, L"", blob->algCrypt, blob->algCrypt, kull_m_crypto_algid_to_name(blob->algCrypt));
		kprintf(L"%*s" L"  dwAlgCryptLen      : %08x - %u\n", level << 1, L"", blob->dwAlgCryptLen, blob->dwAlgCryptLen);
		kprintf(L"%*s" L"  dwSaltLen          : %08x - %u\n", level << 1, L"", blob->dwSaltLen, blob->dwSaltLen);
		kprintf(L"%*s" L"  pbSalt             : ", level << 1, L""); kull_m_string_wprintf_hex(blob->pbSalt, blob->dwSaltLen, 0); kprintf(L"\n");
		kprintf(L"%*s" L"  dwHmacKeyLen       : %08x - %u\n", level << 1, L"", blob->dwHmacKeyLen, blob->dwHmacKeyLen);
		kprintf(L"%*s" L"  pbHmackKey         : ", level << 1, L""); kull_m_string_wprintf_hex(blob->pbHmackKey, blob->dwHmacKeyLen, 0); kprintf(L"\n");
		kprintf(L"%*s" L"  algHash            : %08x - %u (%s)\n", level << 1, L"", blob->algHash, blob->algHash, kull_m_crypto_algid_to_name(blob->algHash));
		kprintf(L"%*s" L"  dwAlgHashLen       : %08x - %u\n", level << 1, L"", blob->dwAlgHashLen, blob->dwAlgHashLen);
		kprintf(L"%*s" L"  dwHmac2KeyLen      : %08x - %u\n", level << 1, L"", blob->dwHmac2KeyLen, blob->dwHmac2KeyLen);
		kprintf(L"%*s" L"  pbHmack2Key        : ", level << 1, L""); kull_m_string_wprintf_hex(blob->pbHmack2Key, blob->dwHmac2KeyLen, 0); kprintf(L"\n");
		kprintf(L"%*s" L"  dwDataLen          : %08x - %u\n", level << 1, L"", blob->dwDataLen, blob->dwDataLen);
		kprintf(L"%*s" L"  pbData             : ", level << 1, L""); kull_m_string_wprintf_hex(blob->pbData, blob->dwDataLen, 0); kprintf(L"\n");
		kprintf(L"%*s" L"  dwSignLen          : %08x - %u\n", level << 1, L"", blob->dwSignLen, blob->dwSignLen);
		kprintf(L"%*s" L"  pbSign             : ", level << 1, L""); kull_m_string_wprintf_hex(blob->pbSign, blob->dwSignLen, 0); kprintf(L"\n\n");
	}
}

void kull_m_dpapi_blob_quick_descr(DWORD level, LPCVOID data/*, DWORD size*/)
{
	PKULL_M_DPAPI_BLOB blob;
	if(blob = kull_m_dpapi_blob_create(data))
	{
		kull_m_dpapi_blob_descr(level, blob);
		kull_m_dpapi_blob_delete(blob);
	}
}

PKULL_M_DPAPI_MASTERKEY kull_m_dpapi_masterkey_create(LPCVOID data, DWORD64 size)
{
	PKULL_M_DPAPI_MASTERKEY masterkey = NULL;
	if(data && (masterkey = (PKULL_M_DPAPI_MASTERKEY) LocalAlloc(LPTR, sizeof(KULL_M_DPAPI_MASTERKEY))))
	{
		RtlCopyMemory(masterkey, data, FIELD_OFFSET(KULL_M_DPAPI_MASTERKEY, pbKey));
		masterkey->pbKey = (PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEY, pbKey);
		masterkey->__dwKeyLen = (DWORD) size - FIELD_OFFSET(KULL_M_DPAPI_MASTERKEY, pbKey);
		kull_m_string_ptr_replace(&masterkey->pbKey, masterkey->__dwKeyLen);
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

void kull_m_dpapi_masterkey_descr(DWORD level, PKULL_M_DPAPI_MASTERKEY masterkey)
{
	kprintf(L"%*s" L"**MASTERKEY**\n", level << 1, L"");
	if(masterkey)
	{
		kprintf(L"%*s" L"  dwVersion        : %08x - %u\n", level << 1, L"", masterkey->dwVersion, masterkey->dwVersion);
		kprintf(L"%*s" L"  salt             : ", level << 1, L""); kull_m_string_wprintf_hex(masterkey->salt, sizeof(masterkey->salt), 0); kprintf(L"\n");
		kprintf(L"%*s" L"  rounds           : %08x - %u\n", level << 1, L"", masterkey->rounds, masterkey->rounds);
		kprintf(L"%*s" L"  algHash          : %08x - %u (%s)\n", level << 1, L"", masterkey->algHash, masterkey->algHash, kull_m_crypto_algid_to_name(masterkey->algHash));
		kprintf(L"%*s" L"  algCrypt         : %08x - %u (%s)\n", level << 1, L"", masterkey->algCrypt, masterkey->algCrypt, kull_m_crypto_algid_to_name(masterkey->algCrypt));
		kprintf(L"%*s" L"  pbKey            : ", level << 1, L""); kull_m_string_wprintf_hex(masterkey->pbKey, masterkey->__dwKeyLen, 0); kprintf(L"\n\n");
	}
}

PKULL_M_DPAPI_MASTERKEY_CREDHIST kull_m_dpapi_masterkeys_credhist_create(LPCVOID data, DWORD64 size)
{
	PKULL_M_DPAPI_MASTERKEY_CREDHIST credhist = NULL;
	if(data && (credhist = (PKULL_M_DPAPI_MASTERKEY_CREDHIST) LocalAlloc(LPTR, sizeof(KULL_M_DPAPI_MASTERKEY_CREDHIST))))
		RtlCopyMemory(credhist, data, sizeof(KULL_M_DPAPI_MASTERKEY_CREDHIST));
	return credhist;
}

void kull_m_dpapi_masterkeys_credhist_delete(PKULL_M_DPAPI_MASTERKEY_CREDHIST credhist)
{
	if(credhist)
		LocalFree(credhist);
}

void kull_m_dpapi_masterkeys_credhist_descr(DWORD level, PKULL_M_DPAPI_MASTERKEY_CREDHIST credhist)
{
	kprintf(L"%*s" L"**CREDHIST INFO**\n", level << 1, L"");
	if(credhist)
	{
		kprintf(L"%*s" L"  dwVersion        : %08x - %u\n", level << 1, L"", credhist->dwVersion, credhist->dwVersion);
		kprintf(L"%*s" L"  guid             : ", level << 1, L""); kull_m_string_displayGUID(&credhist->guid); kprintf(L"\n\n");
	}
}

PKULL_M_DPAPI_MASTERKEY_DOMAINKEY kull_m_dpapi_masterkeys_domainkey_create(LPCVOID data, DWORD64 size)
{
	PKULL_M_DPAPI_MASTERKEY_DOMAINKEY domainkey = NULL;
	if(data && (domainkey = (PKULL_M_DPAPI_MASTERKEY_DOMAINKEY) LocalAlloc(LPTR, sizeof(KULL_M_DPAPI_MASTERKEY_DOMAINKEY))))
	{
		RtlCopyMemory(domainkey, data, FIELD_OFFSET(KULL_M_DPAPI_MASTERKEY_DOMAINKEY, pbSecret));
		domainkey->pbSecret = (PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEY_DOMAINKEY, pbSecret);
		domainkey->pbAccesscheck = (PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEY_DOMAINKEY, pbSecret) + domainkey->dwSecretLen;
		kull_m_string_ptr_replace(&domainkey->pbSecret, domainkey->dwSecretLen);
		kull_m_string_ptr_replace(&domainkey->pbAccesscheck, domainkey->dwAccesscheckLen);
	}
	return domainkey;
}

void kull_m_dpapi_masterkeys_domainkey_delete(PKULL_M_DPAPI_MASTERKEY_DOMAINKEY domainkey)
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

void kull_m_dpapi_masterkeys_domainkey_descr(DWORD level, PKULL_M_DPAPI_MASTERKEY_DOMAINKEY domainkey)
{
	kprintf(L"%*s" L"**DOMAINKEY**\n", level << 1, L"");
	if(domainkey)
	{
		kprintf(L"%*s" L"  dwVersion        : %08x - %u\n", level << 1, L"", domainkey->dwVersion, domainkey->dwVersion);
		kprintf(L"%*s" L"  dwSecretLen      : %08x - %u\n", level << 1, L"", domainkey->dwSecretLen, domainkey->dwSecretLen);
		kprintf(L"%*s" L"  dwAccesscheckLen : %08x - %u\n", level << 1, L"", domainkey->dwAccesscheckLen, domainkey->dwAccesscheckLen);
		kprintf(L"%*s" L"  guidMasterKey    : ", level << 1, L""); kull_m_string_displayGUID(&domainkey->guidMasterKey); kprintf(L"\n");
		kprintf(L"%*s" L"  pbSecret         : ", level << 1, L""); kull_m_string_wprintf_hex(domainkey->pbSecret, domainkey->dwSecretLen, 0); kprintf(L"\n");
		kprintf(L"%*s" L"  pbAccesscheck    : ", level << 1, L""); kull_m_string_wprintf_hex(domainkey->pbAccesscheck, domainkey->dwAccesscheckLen, 0); kprintf(L"\n\n");
	}
}

PKULL_M_DPAPI_MASTERKEYS kull_m_dpapi_masterkeys_create(LPCVOID data/*, DWORD size*/)
{
	PKULL_M_DPAPI_MASTERKEYS masterkeys = NULL;
	if(data && (masterkeys = (PKULL_M_DPAPI_MASTERKEYS) LocalAlloc(LPTR, sizeof(KULL_M_DPAPI_MASTERKEYS))))
	{
		RtlCopyMemory(masterkeys, data, FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey));
		if(masterkeys->dwMasterKeyLen)
			masterkeys->MasterKey = kull_m_dpapi_masterkey_create((PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey) + 0, masterkeys->dwMasterKeyLen);
		if(masterkeys->dwBackupKeyLen)
			masterkeys->BackupKey = kull_m_dpapi_masterkey_create((PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey) + masterkeys->dwMasterKeyLen, masterkeys->dwBackupKeyLen);
		if(masterkeys->dwCredHistLen)
			masterkeys->CredHist = kull_m_dpapi_masterkeys_credhist_create((PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey) + masterkeys->dwMasterKeyLen + masterkeys->dwBackupKeyLen, masterkeys->dwCredHistLen);
		if(masterkeys->dwDomainKeyLen)
			masterkeys->DomainKey = kull_m_dpapi_masterkeys_domainkey_create((PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey) + masterkeys->dwMasterKeyLen + masterkeys->dwBackupKeyLen + masterkeys->dwCredHistLen, masterkeys->dwDomainKeyLen);
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
			kull_m_dpapi_masterkeys_credhist_delete(masterkeys->CredHist);
		if(masterkeys->DomainKey)
			kull_m_dpapi_masterkeys_domainkey_delete(masterkeys->DomainKey);
		LocalFree(masterkeys);
	}
}

void kull_m_dpapi_masterkeys_descr(DWORD level, PKULL_M_DPAPI_MASTERKEYS masterkeys)
{
	kprintf(L"%*s" L"**MASTERKEYS**\n", level << 1, L"");
	if(masterkeys)
	{
		kprintf(L"%*s" L"  dwVersion          : %08x - %u\n", level << 1, L"", masterkeys->dwVersion, masterkeys->dwVersion);
		kprintf(L"%*s" L"  szGuid             : {%.36s}\n", level << 1, L"", masterkeys->szGuid);
		kprintf(L"%*s" L"  dwFlags            : %08x - %u\n", level << 1, L"", masterkeys->dwFlags, masterkeys->dwFlags);
		kprintf(L"%*s" L"  dwMasterKeyLen     : %08x - %u\n", level << 1, L"", (DWORD) masterkeys->dwMasterKeyLen, (DWORD) masterkeys->dwMasterKeyLen);
		kprintf(L"%*s" L"  dwBackupKeyLen     : %08x - %u\n", level << 1, L"", (DWORD) masterkeys->dwBackupKeyLen, (DWORD) masterkeys->dwBackupKeyLen);
		kprintf(L"%*s" L"  dwCredHistLen      : %08x - %u\n", level << 1, L"", (DWORD) masterkeys->dwCredHistLen, (DWORD) masterkeys->dwCredHistLen);
		kprintf(L"%*s" L"  dwDomainKeyLen     : %08x - %u\n", level << 1, L"", (DWORD) masterkeys->dwDomainKeyLen, (DWORD) masterkeys->dwDomainKeyLen);
		
		if(masterkeys->MasterKey)
		{
			kprintf(L"%*s" L"[masterkey]\n", level << 1, L"");
			kull_m_dpapi_masterkey_descr(level + 1, masterkeys->MasterKey);
		}
		if(masterkeys->BackupKey)
		{
			kprintf(L"%*s" L"[backupkey]\n", level << 1, L"");
			kull_m_dpapi_masterkey_descr(level + 1, masterkeys->BackupKey);
		}
		if(masterkeys->CredHist)
		{
			kprintf(L"%*s" L"[credhist]\n", level << 1, L"");
			kull_m_dpapi_masterkeys_credhist_descr(level + 1, masterkeys->CredHist);
		}
		if(masterkeys->DomainKey)
		{
			kprintf(L"%*s" L"[domainkey]\n", level << 1, L"");
			kull_m_dpapi_masterkeys_domainkey_descr(level + 1, masterkeys->DomainKey);
		}
		kprintf(L"\n");
	}
}

PKULL_M_DPAPI_CREDHIST kull_m_dpapi_credhist_create(LPCVOID data, DWORD size)
{
	PKULL_M_DPAPI_CREDHIST credhist = NULL;
	DWORD currSize, sumSize, i;
	if(data && (credhist = (PKULL_M_DPAPI_CREDHIST) LocalAlloc(LPTR, sizeof(KULL_M_DPAPI_CREDHIST))))
	{
		RtlCopyMemory(credhist, (PBYTE) data + size - sizeof(KULL_M_DPAPI_CREDHIST_HEADER), sizeof(KULL_M_DPAPI_CREDHIST_HEADER));

		for(
			sumSize = sizeof(KULL_M_DPAPI_CREDHIST_HEADER), currSize = credhist->current.dwNextLen;
			(sumSize < size) && currSize;
		currSize = ((PKULL_M_DPAPI_CREDHIST_ENTRY) ((PBYTE) data + size - (sumSize + currSize)))->header.dwNextLen, sumSize += currSize, credhist->__dwCount++
			);

		if(credhist->entries = (PKULL_M_DPAPI_CREDHIST_ENTRY *) LocalAlloc(LPTR, credhist->__dwCount * sizeof(PKULL_M_DPAPI_CREDHIST_ENTRY)))
			for(
				i = 0, sumSize = sizeof(KULL_M_DPAPI_CREDHIST_HEADER), currSize = credhist->current.dwNextLen;
				(sumSize < size) && currSize;
		currSize = ((PKULL_M_DPAPI_CREDHIST_ENTRY) ((PBYTE) data + size - (sumSize + currSize)))->header.dwNextLen, sumSize += currSize, i++
			)
			credhist->entries[i] = kull_m_dpapi_credhist_entry_create(((PBYTE) data + size - (sumSize + currSize)), currSize);
	}
	return credhist;
}

void kull_m_dpapi_credhist_delete(PKULL_M_DPAPI_CREDHIST credhist)
{
	DWORD i;
	if(credhist)
	{
		for(i = 0; i < credhist->__dwCount; i++)
			kull_m_dpapi_credhist_entry_delete(credhist->entries[i]);
		LocalFree(credhist);
	}
}

void kull_m_dpapi_credhist_descr(DWORD level, PKULL_M_DPAPI_CREDHIST credhist)
{
	DWORD i;
	kprintf(L"%*s" L"**CREDHIST**\n", level << 1, L"");
	if(credhist)
	{
		kprintf(L"%*s" L"  dwVersion : %08x - %u\n", level << 1, L"", credhist->current.dwVersion, credhist->current.dwVersion);
		kprintf(L"%*s" L"  guid      : ", level << 1, L""); kull_m_string_displayGUID(&credhist->current.guid); kprintf(L"\n");
		kprintf(L"%*s" L"  dwNextLen : %08x - %u\n", level << 1, L"", credhist->current.dwNextLen, credhist->current.dwNextLen);
		for(i = 0; i < credhist->__dwCount; i++)
			kull_m_dpapi_credhist_entry_descr(level + 1, credhist->entries[i]);
		kprintf(L"\n");
	}
}

PKULL_M_DPAPI_CREDHIST_ENTRY kull_m_dpapi_credhist_entry_create(LPCVOID data, DWORD size)
{
	PKULL_M_DPAPI_CREDHIST_ENTRY entry = NULL;
	if(data && (entry = (PKULL_M_DPAPI_CREDHIST_ENTRY) LocalAlloc(LPTR, sizeof(KULL_M_DPAPI_CREDHIST_ENTRY))))
	{
		RtlCopyMemory(entry, data, FIELD_OFFSET(KULL_M_DPAPI_CREDHIST_ENTRY, pSid));
		entry->pSid = (PBYTE) data + FIELD_OFFSET(KULL_M_DPAPI_CREDHIST_ENTRY, pSid);
		entry->pSecret = (PBYTE) entry->pSid + entry->sidLen;

		entry->__dwSecretLen = size - (FIELD_OFFSET(KULL_M_DPAPI_CREDHIST_ENTRY, pSid) + entry->sidLen);

		kull_m_string_ptr_replace(&entry->pSid, entry->sidLen);
		kull_m_string_ptr_replace(&entry->pSecret, entry->__dwSecretLen);
	}
	return entry;
}

void kull_m_dpapi_credhist_entry_delete(PKULL_M_DPAPI_CREDHIST_ENTRY entry)
{
	if(entry)
	{
		if(entry->pSid)
			LocalFree(entry->pSid);
		if(entry->pSecret)
			LocalFree(entry->pSecret);
		LocalFree(entry);
	}
}

void kull_m_dpapi_credhist_entry_descr(DWORD level, PKULL_M_DPAPI_CREDHIST_ENTRY entry)
{
	kprintf(L"%*s" L"**CREDHIST ENTRY**\n", level << 1, L"");
	if(entry)
	{
		kprintf(L"%*s" L"  dwVersion : %08x - %u\n", level << 1, L"", entry->header.dwVersion, entry->header.dwVersion);
		kprintf(L"%*s" L"  guid      : ", level << 1, L""); kull_m_string_displayGUID(&entry->header.guid); kprintf(L"\n");
		kprintf(L"%*s" L"  dwNextLen : %08x - %u\n", level << 1, L"", entry->header.dwNextLen, entry->header.dwNextLen);
		
		kprintf(L"%*s" L"  dwType    : %08x - %u\n", level << 1, L"", entry->dwType, entry->dwType);
		kprintf(L"%*s" L"  algHash   : %08x - %u (%s)\n", level << 1, L"", entry->algHash, entry->algHash, kull_m_crypto_algid_to_name(entry->algHash));
		kprintf(L"%*s" L"  rounds    : %08x - %u\n", level << 1, L"", entry->rounds, entry->rounds);
		kprintf(L"%*s" L"  sidLen    : %08x - %u\n", level << 1, L"", entry->sidLen, entry->sidLen);
		kprintf(L"%*s" L"  algCrypt  : %08x - %u (%s)\n", level << 1, L"", entry->algCrypt, entry->algCrypt, kull_m_crypto_algid_to_name(entry->algCrypt));
		kprintf(L"%*s" L"  sha1Len   : %08x - %u\n", level << 1, L"", entry->sha1Len, entry->sha1Len);
		kprintf(L"%*s" L"  md4Len    : %08x - %u\n", level << 1, L"", entry->md4Len, entry->md4Len);
		
		kprintf(L"%*s" L"  Salt      : ", level << 1, L""); kull_m_string_wprintf_hex(entry->salt, sizeof(entry->salt), 0); kprintf(L"\n");
		kprintf(L"%*s" L"  Sid       : ", level << 1, L""); kull_m_string_displaySID(entry->pSid); kprintf(L"\n");
		kprintf(L"%*s" L"  pSecret   : ", level << 1, L""); kull_m_string_wprintf_hex(entry->pSecret, entry->__dwSecretLen, 0); kprintf(L"\n\n");
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

BOOL kull_m_dpapi_unprotect_raw_or_blob(LPCVOID pDataIn, DWORD dwDataInLen, LPWSTR *ppszDataDescr, LPCVOID pOptionalEntropy, DWORD dwOptionalEntropyLen, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, LPVOID *pDataOut, DWORD *dwDataOutLen, LPCVOID pMasterKey, DWORD dwMasterKeyLen, LPCWSTR pPassword)
{
	BOOL status = FALSE;
	DATA_BLOB dataIn = {dwDataInLen, (PBYTE) pDataIn}, dataEntropy = {dwOptionalEntropyLen, (PBYTE) pOptionalEntropy}, dataOut;
	PKULL_M_DPAPI_BLOB blob;

	if(pMasterKey && dwMasterKeyLen)
	{
		if(blob = kull_m_dpapi_blob_create(pDataIn))
		{
			if(status = kull_m_dpapi_unprotect_blob(blob, pMasterKey, dwMasterKeyLen, pOptionalEntropy, dwOptionalEntropyLen, pPassword, pDataOut, dwDataOutLen))
				if(ppszDataDescr && blob->szDescription && blob->dwDescriptionLen)
					if(*ppszDataDescr = (LPWSTR) LocalAlloc(LPTR, blob->dwDescriptionLen))
						RtlCopyMemory(*ppszDataDescr, blob->szDescription, blob->dwDescriptionLen);
			kull_m_dpapi_blob_delete(blob);
		}
	}
	else
	{
		if(status = CryptUnprotectData(&dataIn, ppszDataDescr, &dataEntropy, NULL, pPromptStruct, dwFlags, &dataOut))
		{
			*dwDataOutLen = dataOut.cbData;
			if(*pDataOut = LocalAlloc(LPTR, *dwDataOutLen))
				RtlCopyMemory(*pDataOut, dataOut.pbData, *dwDataOutLen);
			LocalFree(dataOut.pbData);
		}
	}
	return status;
}

BOOL kull_m_dpapi_unprotect_masterkey_with_password(DWORD flags, PKULL_M_DPAPI_MASTERKEY masterkey, PCWSTR password, PCWSTR sid, BOOL isKeyOfProtectedUser, PVOID *output, DWORD *outputLen)
{
	BOOL status = FALSE;
	ALG_ID PassAlg;
	DWORD PassLen, SidLen = (DWORD) wcslen(sid) * sizeof(wchar_t);
	PVOID PassHash;
	BYTE sha2[32];
	
	PassAlg = (flags & 4) ? CALG_SHA1 : CALG_MD4;
	PassLen = kull_m_crypto_hash_len(PassAlg);
	if(PassHash = LocalAlloc(LPTR, PassLen))
	{
		if(kull_m_crypto_hash(PassAlg, password, (DWORD) wcslen(password) * sizeof(wchar_t), PassHash, PassLen))
		{
			if(isKeyOfProtectedUser && (PassAlg == CALG_MD4))
				if(kull_m_crypto_pkcs5_pbkdf2_hmac(CALG_SHA_256, PassHash, PassLen, sid, SidLen, 10000, sha2, sizeof(sha2), FALSE))
					kull_m_crypto_pkcs5_pbkdf2_hmac(CALG_SHA_256, sha2, sizeof(sha2), sid, SidLen, 1, (PBYTE) PassHash, PassLen, FALSE);

			status = kull_m_dpapi_unprotect_masterkey_with_userHash(masterkey, PassHash, PassLen, sid, output, outputLen);
		}
		LocalFree(PassHash);
	}
	return status;
}

BOOL kull_m_dpapi_unprotect_masterkey_with_userHash(PKULL_M_DPAPI_MASTERKEY masterkey, LPCVOID userHash, DWORD userHashLen, PCWSTR sid, PVOID *output, DWORD *outputLen)
{
	BOOL status = FALSE;
	BYTE sha1DerivedKey[SHA_DIGEST_LENGTH];
	
	if(kull_m_crypto_hmac(CALG_SHA1, userHash, userHashLen, sid, (DWORD) (wcslen(sid) + 1) * sizeof(wchar_t), sha1DerivedKey, SHA_DIGEST_LENGTH))
		status = kull_m_dpapi_unprotect_masterkey_with_shaDerivedkey(masterkey, sha1DerivedKey, SHA_DIGEST_LENGTH, output, outputLen);
	return status;
}

BOOL kull_m_dpapi_unprotect_masterkey_with_shaDerivedkey(PKULL_M_DPAPI_MASTERKEY masterkey, LPCVOID shaDerivedkey, DWORD shaDerivedkeyLen, PVOID *output, DWORD *outputLen)
{
	BOOL status = FALSE;
	HCRYPTPROV hSessionProv;
	HCRYPTKEY hSessionKey;
	ALG_ID HMACAlg;
	DWORD HMACLen, BlockLen, KeyLen, OutLen;
	PVOID  HMACHash, CryptBuffer, hmac1, hmac2;

	HMACAlg = (masterkey->algHash == CALG_HMAC) ? CALG_SHA1 : masterkey->algHash;
	HMACLen = kull_m_crypto_hash_len(HMACAlg);
	KeyLen =  kull_m_crypto_cipher_keylen(masterkey->algCrypt);
	BlockLen = kull_m_crypto_cipher_blocklen(masterkey->algCrypt);

	if(HMACHash = LocalAlloc(LPTR, KeyLen + BlockLen))
	{
		if(kull_m_crypto_pkcs5_pbkdf2_hmac(HMACAlg, shaDerivedkey, shaDerivedkeyLen, masterkey->salt, sizeof(masterkey->salt), masterkey->rounds, (PBYTE) HMACHash, KeyLen + BlockLen, TRUE))
		{
			if(kull_m_crypto_hkey_session(masterkey->algCrypt, HMACHash, KeyLen, 0, &hSessionKey, &hSessionProv))
			{
				if(CryptSetKeyParam(hSessionKey, KP_IV, (PBYTE) HMACHash + KeyLen, 0))
				{
					OutLen = masterkey->__dwKeyLen;
					if(CryptBuffer = LocalAlloc(LPTR, OutLen))
					{
						RtlCopyMemory(CryptBuffer, masterkey->pbKey, OutLen);
						if(CryptDecrypt(hSessionKey, 0, FALSE, 0, (PBYTE) CryptBuffer, &OutLen))
						{
							*outputLen = OutLen - 16 - HMACLen - ((masterkey->algCrypt == CALG_3DES) ? 4 : 0); // reversed
							if(hmac1 = LocalAlloc(LPTR, HMACLen))
							{
								if(kull_m_crypto_hmac(HMACAlg, shaDerivedkey, shaDerivedkeyLen, CryptBuffer, 16, hmac1, HMACLen))
								{
									if(hmac2 = LocalAlloc(LPTR, HMACLen))
									{
										if(kull_m_crypto_hmac(HMACAlg, hmac1, HMACLen, (PBYTE) CryptBuffer + OutLen - *outputLen, *outputLen, hmac2, HMACLen))
										{
											if(status = RtlEqualMemory(hmac2, (PBYTE) CryptBuffer + 16, HMACLen))
											{
												if(*output = LocalAlloc(LPTR, *outputLen))
													RtlCopyMemory(*output, (PBYTE) CryptBuffer + OutLen - *outputLen, *outputLen);
											}
										}
										LocalFree(hmac2);
									}
								}
								LocalFree(hmac1);
							}
						}
						LocalFree(CryptBuffer);
					}
				}
				CryptDestroyKey(hSessionKey);
				if(!kull_m_crypto_close_hprov_delete_container(hSessionProv))
					PRINT_ERROR_AUTO(L"kull_m_crypto_close_hprov_delete_container");
			}
			else PRINT_ERROR_AUTO(L"kull_m_crypto_hkey_session");
		}
		LocalFree(HMACHash);
	}
	return status;
}

//BOOL kull_m_dpapi_unprotect_backupkey_with_secret(DWORD flags, PKULL_M_DPAPI_MASTERKEY masterkey, PCWSTR sid, LPCVOID secret, DWORD secretLen, PVOID *output, DWORD *outputLen)
//{
//	BOOL status = FALSE, isDPAPISecret = flags & 1;
//	LPCBYTE ptrSecret = (LPCBYTE) secret;
//	PVOID data, hash;
//	ALG_ID algID = (masterkey->algHash == CALG_SHA_512) ? CALG_SHA_512 : CALG_SHA1;
//	DWORD sidLen = (DWORD) (wcslen(sid) + 1) * sizeof(wchar_t), hashSize = kull_m_crypto_hash_len(algID), dataSize = sidLen;
//
//	if(!isDPAPISecret || (isDPAPISecret && ptrSecret && secretLen))
//	{
//		if(secretLen == 2 * SHA_DIGEST_LENGTH + sizeof(DWORD))
//		{
//			ptrSecret += sizeof(DWORD);
//			secretLen -= sizeof(DWORD);
//		}
//		if(isDPAPISecret)
//			dataSize += secretLen;
//		if(data = (PBYTE) LocalAlloc(LPTR, dataSize))
//		{
//			RtlCopyMemory(data, sid, sidLen);
//			if(isDPAPISecret)
//				RtlCopyMemory((PBYTE) data + sidLen, ptrSecret, secretLen);
//
//			if(hash = LocalAlloc(LPTR, hashSize))
//			{
//				if(kull_m_crypto_hash(algID, data, dataSize, hash, hashSize))
//					status = kull_m_dpapi_unprotect_masterkey_with_shaDerivedkey(masterkey, hash, hashSize, output, outputLen);
//				LocalFree(hash);
//			}
//			LocalFree(data);
//		}
//	}
//	else PRINT_ERROR(L"This backup key need DPAPI_SYSTEM secret\n");
//	return status;
//}

BOOL kull_m_dpapi_unprotect_domainkey_with_key(PKULL_M_DPAPI_MASTERKEY_DOMAINKEY domainkey, LPCVOID key, DWORD keyLen, PVOID *output, DWORD *outputLen, PSID *sid)
{
	BOOL status = FALSE;
	HCRYPTPROV hProv, hSessionProv;
	HCRYPTKEY hKey, hSessionKey;
	PKULL_M_DPAPI_DOMAIN_RSA_MASTER_KEY rsa_buffer;
	PKULL_M_DPAPI_DOMAIN_ACCESS_CHECK des_buffer;
	BYTE digest[SHA_DIGEST_LENGTH];
	DWORD cbOutput;
	PSID pSid;
	
	if(CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if(CryptImportKey(hProv, (PBYTE) key, keyLen, 0, 0, &hKey))
		{
			cbOutput = domainkey->dwSecretLen;
			if(rsa_buffer = (PKULL_M_DPAPI_DOMAIN_RSA_MASTER_KEY) LocalAlloc(LPTR, cbOutput))
			{
				RtlCopyMemory(rsa_buffer, domainkey->pbSecret, cbOutput);
				if(CryptDecrypt(hKey, 0, TRUE, 0, (PBYTE) rsa_buffer, &cbOutput))
				{
					//kprintf(L"\nRSA decrypt is a success\n");
					//kprintf(L" * MasterKey len: %u\n", rsa_buffer->cbMasterKey);
					//kull_m_string_wprintf_hex(rsa_buffer->buffer, rsa_buffer->cbMasterKey, 1 | (16 << 16));
					//kprintf(L" * SuppKey   len: %u\n", rsa_buffer->cbSuppKey);
					//kull_m_string_wprintf_hex(rsa_buffer->buffer + rsa_buffer->cbMasterKey, rsa_buffer->cbSuppKey, 1 | (16 << 16));
					if(kull_m_crypto_hkey(hProv, CALG_3DES, rsa_buffer->buffer + rsa_buffer->cbMasterKey, 192 / 8, 0, &hSessionKey, &hSessionProv))
					{
						if(CryptSetKeyParam(hSessionKey, KP_IV, rsa_buffer->buffer + rsa_buffer->cbMasterKey + 192 / 8, 0))
						{
							cbOutput = domainkey->dwAccesscheckLen;

							if(des_buffer = (PKULL_M_DPAPI_DOMAIN_ACCESS_CHECK) LocalAlloc(LPTR, cbOutput))
							{
								RtlCopyMemory(des_buffer, domainkey->pbAccesscheck, cbOutput);

								if(CryptDecrypt(hSessionKey, 0, FALSE, 0, (PBYTE) des_buffer, &cbOutput))
								{
									pSid = (PSID) (des_buffer->data + des_buffer->dataLen);
									//kprintf(L"\n3DES decrypt is a success too\n");
									////kull_m_string_wprintf_hex(des_buffer, outSize, 1 | (16 << 16)); kprintf(L"\n");
									//kprintf(L" * nonce    : "); kull_m_string_wprintf_hex(des_buffer->data, des_buffer->dataLen, 0); kprintf(L"\n"); // try to leave it as is =)
									//kprintf(L" * SID      : "); kull_m_string_displaySID(pSid); kprintf(L"\n");
									//kprintf(L" * SHA1     : "); kull_m_string_wprintf_hex((PBYTE) des_buffer + cbOutput - SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH, 0); kprintf(L"\n");
									if(kull_m_crypto_hash(CALG_SHA1, des_buffer, cbOutput - SHA_DIGEST_LENGTH, digest, SHA_DIGEST_LENGTH))
									{
										//kprintf(L" > Calc SHA1: "); kull_m_string_wprintf_hex(digest, SHA_DIGEST_LENGTH, 0); kprintf(L"\n");
										if(RtlEqualMemory((PBYTE) des_buffer + cbOutput - SHA_DIGEST_LENGTH, digest, SHA_DIGEST_LENGTH))
										{
											*outputLen = rsa_buffer->cbMasterKey;
											if(*output = LocalAlloc(LPTR, *outputLen))
											{
												RtlCopyMemory(*output, rsa_buffer->buffer, *outputLen);
												status = TRUE;
												*sid = NULL;
												if(sid)
												{
													status = FALSE;
													cbOutput = GetLengthSid(pSid);
													if(*sid = (PSID) LocalAlloc(LPTR, cbOutput))
														status = CopySid(cbOutput, *sid, pSid);
												}
												if(!status)
												{
													if(*output)
														*output = LocalFree(*output);
													if(*sid)
														*sid = LocalFree(*sid);
													*outputLen = 0;
												}
											}
										}
									}
								}
								else PRINT_ERROR_AUTO(L"CryptDecrypt");
								LocalFree(des_buffer);
							}
						}
						else PRINT_ERROR_AUTO(L"CryptSetKeyParam");
						CryptDestroyKey(hSessionKey);
						if(!kull_m_crypto_close_hprov_delete_container(hSessionProv))
							PRINT_ERROR_AUTO(L"kull_m_crypto_close_hprov_delete_container");
					}
				}
				else PRINT_ERROR_AUTO(L"CryptDecrypt");
				LocalFree(rsa_buffer);
			}
			CryptDestroyKey(hKey);
		}
		CryptReleaseContext(hProv, 0);
	}
	return status;
}

BOOL kull_m_dpapi_unprotect_domainkey_with_rpc(PKULL_M_DPAPI_MASTERKEYS masterkeys, PVOID rawMasterkeys, LPCWSTR server, PVOID *output, DWORD *outputLen)
{
	BOOL status = FALSE;
	PBYTE out;
	DWORD dwOut;
	*output = NULL;
	*outputLen = 0;
	if(status = kull_m_rpc_bkrp_Restore(server, (PBYTE) rawMasterkeys + FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey) + masterkeys->dwMasterKeyLen + masterkeys->dwBackupKeyLen + masterkeys->dwCredHistLen, (DWORD) masterkeys->dwDomainKeyLen, (PVOID *) &out, &dwOut))
	{
		*outputLen = dwOut - sizeof(DWORD);
		if(*output = LocalAlloc(LPTR, *outputLen))
			RtlCopyMemory(*output, out + sizeof(DWORD), dwOut - sizeof(DWORD));
		LocalFree(out);
	}
	return status;
}

BOOL kull_m_dpapi_unprotect_credhist_entry_with_shaDerivedkey(PKULL_M_DPAPI_CREDHIST_ENTRY entry, LPCVOID shaDerivedkey, DWORD shaDerivedkeyLen, PVOID md4hash, PVOID sha1hash)
{
	BOOL status = FALSE;
	HCRYPTPROV hSessionProv;
	HCRYPTKEY hSessionKey;
	ALG_ID HMACAlg;
	DWORD HMACLen, BlockLen, KeyLen, OutLen;
	PVOID  HMACHash, CryptBuffer;
	DWORD i;

	HMACAlg = (entry->algHash == CALG_HMAC) ? CALG_SHA1 : entry->algHash;
	HMACLen = kull_m_crypto_hash_len(HMACAlg);
	KeyLen =  kull_m_crypto_cipher_keylen(entry->algCrypt);
	BlockLen = kull_m_crypto_cipher_blocklen(entry->algCrypt);

	if(HMACHash = LocalAlloc(LPTR, KeyLen + BlockLen))
	{
		if(kull_m_crypto_pkcs5_pbkdf2_hmac(HMACAlg, shaDerivedkey, shaDerivedkeyLen, entry->salt, sizeof(entry->salt), entry->rounds, (PBYTE) HMACHash, KeyLen + BlockLen, TRUE))
		{
			if(kull_m_crypto_hkey_session(entry->algCrypt, HMACHash, KeyLen, 0, &hSessionKey, &hSessionProv))
			{
				if(CryptSetKeyParam(hSessionKey, KP_IV, (PBYTE) HMACHash + KeyLen, 0))
				{
					OutLen = entry->__dwSecretLen;
					if(CryptBuffer = LocalAlloc(LPTR, OutLen))
					{
						RtlCopyMemory(CryptBuffer, entry->pSecret, OutLen);
						if(CryptDecrypt(hSessionKey, 0, FALSE, 0, (PBYTE) CryptBuffer, &OutLen))
						{
							RtlCopyMemory(sha1hash, CryptBuffer, min(entry->sha1Len, SHA_DIGEST_LENGTH));
							RtlCopyMemory(md4hash, (PBYTE) CryptBuffer + entry->sha1Len, min(entry->md4Len, LM_NTLM_HASH_LENGTH));

							status = TRUE;
							if(entry->md4Len - LM_NTLM_HASH_LENGTH)
								for(i = 0; (i < (entry->md4Len - LM_NTLM_HASH_LENGTH) && status); i++)
									status &= ! *((PBYTE) CryptBuffer + entry->sha1Len + LM_NTLM_HASH_LENGTH + i);
						}
						LocalFree(CryptBuffer);
					}
				}
				CryptDestroyKey(hSessionKey);
				if(!kull_m_crypto_close_hprov_delete_container(hSessionProv))
					PRINT_ERROR_AUTO(L"kull_m_crypto_close_hprov_delete_container");
			}
			else PRINT_ERROR_AUTO(L"kull_m_crypto_hkey_session");
		}
		LocalFree(HMACHash);
	}
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
	L"audit", L"no_recovery", L"verify_protection", L"cred_regenerate",
};
void kull_m_dpapi_displayProtectionFlags(DWORD flags)
{
	DWORD i;
	for(i = 0; i < ARRAYSIZE(DPAPIProtectFlagsToStrings); i++)
		if((flags >> i) & 1)
			kprintf(L"%s ; ", DPAPIProtectFlagsToStrings[i]);
	if(flags & CRYPTPROTECT_SYSTEM)
		kprintf(L"%s ; ", L"system");
}

const PCWCHAR DPAPIBlobFlagsToStrings[] = {
	L"prompt_on_unprotect", L"prompt_on_protect", L"local_machine", L"prompt_strong",
	L"audit",
};
void kull_m_dpapi_displayBlobFlags(DWORD flags)
{
	DWORD i;
	for(i = 0; i < ARRAYSIZE(DPAPIBlobFlagsToStrings); i++)
		if((flags >> i) & 1)
			kprintf(L"%s ; ", DPAPIBlobFlagsToStrings[i]);
	if(flags & CRYPTPROTECT_SYSTEM)
		kprintf(L"%s ; ", L"system");
}