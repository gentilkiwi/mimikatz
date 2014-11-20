/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#ifdef DPAPI_TOOLS
#include "kull_m_dpapi.h"

const KULL_M_DWORD_TO_DWORD kull_m_dpapi_calgid[] = {
	{L"CALG_MD2",	CALG_MD2},
	{L"CALG_MD4",	CALG_MD4},
	{L"CALG_MD5",	CALG_MD5},
	//{L"CALG_SHA",	CALG_SHA},
	{L"CALG_SHA1",	CALG_SHA1},
	{L"CALG_MAC",	CALG_MAC},
	{L"CALG_RSA_SIGN",	CALG_RSA_SIGN},
	{L"CALG_DSS_SIGN",	CALG_DSS_SIGN},
	{L"CALG_NO_SIGN",	CALG_NO_SIGN},
	{L"CALG_RSA_KEYX",	CALG_RSA_KEYX},
	{L"CALG_DES",	CALG_DES},
	{L"CALG_3DES_112",	CALG_3DES_112},
	{L"CALG_3DES",	CALG_3DES},
	{L"CALG_DESX",	CALG_DESX},
	{L"CALG_RC2",	CALG_RC2},
	{L"CALG_RC4",	CALG_RC4},
	{L"CALG_SEAL",	CALG_SEAL},
	{L"CALG_DH_SF",	CALG_DH_SF},
	{L"CALG_DH_EPHEM",	CALG_DH_EPHEM},
	{L"CALG_AGREEDKEY_ANY",	CALG_AGREEDKEY_ANY},
	{L"CALG_KEA_KEYX",	CALG_KEA_KEYX},
	{L"CALG_HUGHES_MD5",	CALG_HUGHES_MD5},
	{L"CALG_SKIPJACK",	CALG_SKIPJACK},
	{L"CALG_TEK",	CALG_TEK},
	{L"CALG_CYLINK_MEK",	CALG_CYLINK_MEK},
	{L"CALG_SSL3_SHAMD5",	CALG_SSL3_SHAMD5},
	{L"CALG_SSL3_MASTER",	CALG_SSL3_MASTER},
	{L"CALG_SCHANNEL_MASTER_HASH",	CALG_SCHANNEL_MASTER_HASH},
	{L"CALG_SCHANNEL_MAC_KEY",	CALG_SCHANNEL_MAC_KEY},
	{L"CALG_SCHANNEL_ENC_KEY",	CALG_SCHANNEL_ENC_KEY},
	{L"CALG_PCT1_MASTER",	CALG_PCT1_MASTER},
	{L"CALG_SSL2_MASTER",	CALG_SSL2_MASTER},
	{L"CALG_TLS1_MASTER",	CALG_TLS1_MASTER},
	{L"CALG_RC5",	CALG_RC5},
	{L"CALG_HMAC",	CALG_HMAC},
	{L"CALG_TLS1PRF",	CALG_TLS1PRF},
	{L"CALG_HASH_REPLACE_OWF",	CALG_HASH_REPLACE_OWF},
	{L"CALG_AES_128",	CALG_AES_128},
	{L"CALG_AES_192",	CALG_AES_192},
	{L"CALG_AES_256",	CALG_AES_256},
	{L"CALG_AES",	CALG_AES},
	{L"CALG_SHA_256",	CALG_SHA_256},
	{L"CALG_SHA_384",	CALG_SHA_384},
	{L"CALG_SHA_512",	CALG_SHA_512},
	{L"CALG_ECDH",	CALG_ECDH},
	{L"CALG_ECMQV",	CALG_ECMQV},
	{L"CALG_ECDSA",	CALG_ECDSA},
};

PCWCHAR kull_m_dpapi_algid_to_name(ALG_ID algid)
{
	DWORD i;
	for(i = 0; i < ARRAYSIZE(kull_m_dpapi_calgid); i++)
		if(kull_m_dpapi_calgid[i].id == algid)
			return kull_m_dpapi_calgid[i].name;
	return NULL;
}

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
		RtlCopyMemory(&blob->dwVersion, data, FIELD_OFFSET(KULL_M_DPAPI_BLOB, szDescription));
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
		kprintf(L"  algCrypt           : %08x - %u (%s)\n", blob->algCrypt, blob->algCrypt, kull_m_dpapi_algid_to_name(blob->algCrypt));
		kprintf(L"  dwAlgCryptLen      : %08x - %u\n", blob->dwAlgCryptLen, blob->dwAlgCryptLen);
		kprintf(L"  dwSaltLen          : %08x - %u\n", blob->dwSaltLen, blob->dwSaltLen);
		kprintf(L"  pbSalt             : "); kull_m_string_wprintf_hex(blob->pbSalt, blob->dwSaltLen, 0); kprintf(L"\n");
		kprintf(L"  dwHmacKeyLen       : %08x - %u\n", blob->dwHmacKeyLen, blob->dwHmacKeyLen);
		kprintf(L"  pbHmackKey         : "); kull_m_string_wprintf_hex(blob->pbHmackKey, blob->dwHmacKeyLen, 0); kprintf(L"\n");
		kprintf(L"  algHash            : %08x - %u (%s)\n", blob->algHash, blob->algHash, kull_m_dpapi_algid_to_name(blob->algHash));
		kprintf(L"  dwAlgHashLen       : %08x - %u\n", blob->dwAlgHashLen, blob->dwAlgHashLen);
		kprintf(L"  dwHmac2KeyLen      : %08x - %u\n", blob->dwHmac2KeyLen, blob->dwHmac2KeyLen);
		kprintf(L"  pbHmack2Key        : "); kull_m_string_wprintf_hex(blob->pbHmack2Key, blob->dwHmac2KeyLen, 0); kprintf(L"\n");
		kprintf(L"  dwDataLen          : %08x - %u\n", blob->dwDataLen, blob->dwDataLen);
		kprintf(L"  pbData             : "); kull_m_string_wprintf_hex(blob->pbData, blob->dwDataLen, 0); kprintf(L"\n");
		kprintf(L"  dwSignLen          : %08x - %u\n", blob->dwSignLen, blob->dwSignLen);
		kprintf(L"  pbSign             : "); kull_m_string_wprintf_hex(blob->pbSign, blob->dwSignLen, 0); kprintf(L"\n");
	}
}


PKULL_M_DPAPI_MASTERKEYS kull_m_dpapi_masterkeys_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_DPAPI_MASTERKEYS masterkeys = NULL;
	if(masterkeys = (PKULL_M_DPAPI_MASTERKEYS) LocalAlloc(LPTR, sizeof(KULL_M_DPAPI_MASTERKEYS)))
	{
		RtlCopyMemory(&masterkeys->dwVersion, data, FIELD_OFFSET(KULL_M_DPAPI_MASTERKEYS, MasterKey));
		/**/
	}
	return masterkeys;
}

void kull_m_dpapi_masterkeys_delete(PKULL_M_DPAPI_MASTERKEYS masterkeys)
{
	if(masterkeys)
	{
		/**/
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
		/**/
	}
}
#endif