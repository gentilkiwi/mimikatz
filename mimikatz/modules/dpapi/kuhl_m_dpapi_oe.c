/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi_oe.h"

LIST_ENTRY gDPAPI_Masterkeys = {&gDPAPI_Masterkeys, &gDPAPI_Masterkeys};
LIST_ENTRY gDPAPI_Credentials = {&gDPAPI_Credentials, &gDPAPI_Credentials};
LIST_ENTRY gDPAPI_Domainkeys = {&gDPAPI_Domainkeys, &gDPAPI_Domainkeys};
// to do CREDHIST_encrypted
// to do Masterkey_encrypted

PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY kuhl_m_dpapi_oe_masterkey_get(LPCGUID guid)
{
	PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry;
	for(entry = (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) gDPAPI_Masterkeys.Flink; entry != (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) &gDPAPI_Masterkeys; entry = (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) entry->navigator.Flink)
		if(RtlEqualGuid(guid, &entry->guid))
			return entry;
	return NULL;
}

BOOL kuhl_m_dpapi_oe_masterkey_add(LPCGUID guid, LPCVOID keyHash, DWORD keyLen)
{
	BOOL status = FALSE;
	PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry;
	BYTE digest[SHA_DIGEST_LENGTH];

	if(guid && keyHash && keyLen)
	{
		if(!kuhl_m_dpapi_oe_masterkey_get(guid))
		{
			if(keyLen != SHA_DIGEST_LENGTH)
				kull_m_crypto_hash(CALG_SHA1, keyHash, keyLen, digest, sizeof(digest));

			if(entry = (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) LocalAlloc(LPTR, sizeof(KUHL_M_DPAPI_OE_MASTERKEY_ENTRY)))
			{
				RtlCopyMemory(&entry->guid, guid, sizeof(GUID));
				RtlCopyMemory(entry->keyHash, (keyLen == SHA_DIGEST_LENGTH) ? keyHash : digest, SHA_DIGEST_LENGTH);
				entry->navigator.Blink = gDPAPI_Masterkeys.Blink;
				entry->navigator.Flink = &gDPAPI_Masterkeys;
				((PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) gDPAPI_Masterkeys.Blink)->navigator.Flink = (PLIST_ENTRY) entry;
				gDPAPI_Masterkeys.Blink= (PLIST_ENTRY) entry;
				status = TRUE;
			}
		}
	}
	else PRINT_ERROR(L"No GUID or Key Hash?");
	return status;
}

void kuhl_m_dpapi_oe_masterkey_delete(PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry)
{
	if(entry)
	{
		((PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Blink)->navigator.Flink = entry->navigator.Flink;
		((PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Flink)->navigator.Blink = entry->navigator.Blink;
		LocalFree(entry);
	}
}

void kuhl_m_dpapi_oe_masterkey_descr(PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry)
{
	if(entry)
	{
		kprintf(L"GUID:");
		kull_m_string_displayGUID(&entry->guid);
		kprintf(L";");
		
		kprintf(L"KeyHash:");
		kull_m_string_wprintf_hex(entry->keyHash, sizeof(entry->keyHash), 0);
		kprintf(L"\n");
	}
}

void kuhl_m_dpapi_oe_masterkeys_delete()
{
	PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY tmp, entry;
	for(entry = (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) gDPAPI_Masterkeys.Flink; entry != (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) &gDPAPI_Masterkeys; entry = tmp)
	{
		tmp = (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) entry->navigator.Flink;
		kuhl_m_dpapi_oe_masterkey_delete(entry);
	}
}

void kuhl_m_dpapi_oe_masterkeys_descr()
{
	PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry;
	for(entry = (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) gDPAPI_Masterkeys.Flink; entry != (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) &gDPAPI_Masterkeys; entry = (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) entry->navigator.Flink)
		kuhl_m_dpapi_oe_masterkey_descr(entry);
}

PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY kuhl_m_dpapi_oe_credential_get(LPCWSTR sid, LPCGUID guid)
{
	PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry;
	BOOL cmpGuid, cmpSid;
	for(entry = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) gDPAPI_Credentials.Flink; entry != (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) &gDPAPI_Credentials; entry = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Flink)
	{
		cmpSid = sid && (_wcsicmp(sid, entry->sid) == 0);
		cmpGuid = guid && (entry->flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_GUID) && RtlEqualGuid(guid, &entry->guid);
		
		if(sid && guid)
		{
			if(cmpSid && cmpGuid)
				return entry;
		}
		else if (sid)
		{
			if(cmpSid && !(entry->flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_GUID))
				return entry;
		}
		else if(guid)
		{
			if(cmpGuid)
				return entry;
		}
	}
	return NULL;
}

BOOL kuhl_m_dpapi_oe_credential_copyEntryWithNewGuid(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry, LPCGUID guid)
{
	BOOL status = FALSE;
	if(entry && guid && !(entry->flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_GUID))
		status = kuhl_m_dpapi_oe_credential_add(entry->sid, guid, (entry->flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4) ? entry->md4hash : NULL, (entry->flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_SHA1) ? entry->sha1hash : NULL, (entry->flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4p) ? entry->md4protectedhash : NULL, NULL);
	return status;
}


BOOL kuhl_m_dpapi_oe_credential_addtoEntry(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry, LPCGUID guid, LPCVOID md4hash, LPCVOID sha1hash, LPCVOID md4protectedhash, LPCWSTR password)
{
	DWORD SidLen, PasswordLen;
	if(entry)
	{
		SidLen = (DWORD) wcslen(entry->sid) * sizeof(wchar_t);
		if(!(entry->flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_GUID) && guid)
		{
			RtlCopyMemory(&entry->guid, guid, sizeof(GUID));
			entry->flags |= KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_GUID;
		}
		if(password)
			PasswordLen = (DWORD) wcslen(password) * sizeof(wchar_t);

		if(!(entry->flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4) && (md4hash || password))
		{
			if(md4hash)
				RtlCopyMemory(entry->md4hash, md4hash, LM_NTLM_HASH_LENGTH);
			else
				kull_m_crypto_hash(CALG_MD4, password, PasswordLen, entry->md4hash, LM_NTLM_HASH_LENGTH);

			if(kull_m_crypto_hmac(CALG_SHA1, entry->md4hash, LM_NTLM_HASH_LENGTH, entry->sid, SidLen + sizeof(wchar_t), entry->md4hashDerived, SHA_DIGEST_LENGTH))
				entry->flags |= KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4;
		}
		if(!(entry->flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_SHA1) && (sha1hash || password))
		{
			if(sha1hash)
				RtlCopyMemory(entry->sha1hash, sha1hash, SHA_DIGEST_LENGTH);
			else
				kull_m_crypto_hash(CALG_SHA1, password, PasswordLen, entry->sha1hash, SHA_DIGEST_LENGTH);

			kull_m_crypto_hmac(CALG_SHA1, entry->sha1hash, SHA_DIGEST_LENGTH, entry->sid, SidLen + sizeof(wchar_t), entry->sha1hashDerived, SHA_DIGEST_LENGTH);
			entry->flags |= KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_SHA1;
		}
		//if(!entry->md4protectedhash && (md4protectedhash || entry->md4hash))
		//{
		//		if(md4protectedhash)
		//			RtlCopyMemory(entry->md4protectedhash, md4protectedhash, LM_NTLM_HASH_LENGTH);
		//		else
		//			if(kull_m_crypto_pkcs5_pbkdf2_hmac(CALG_SHA_256, entry->md4hash, LM_NTLM_HASH_LENGTH, sid, SidLen, 10000, sha2, sizeof(sha2), FALSE))
		//				kull_m_crypto_pkcs5_pbkdf2_hmac(CALG_SHA_256, sha2, sizeof(sha2), sid, SidLen, 1, (PBYTE) entry->md4protectedhash, LM_NTLM_HASH_LENGTH, FALSE);
		//		kull_m_crypto_hmac(CALG_SHA1, entry->md4protectedhash, LM_NTLM_HASH_LENGTH, sid, SidLen + sizeof(wchar_t), entry->md4protectedhashDerived, SHA_DIGEST_LENGTH);
		//}
		//kuhl_m_dpapi_oe_credential_descr(entry);
	}
	return TRUE;
}

BOOL kuhl_m_dpapi_oe_credential_add(LPCWSTR sid, LPCGUID guid, LPCVOID md4hash, LPCVOID sha1hash, LPCVOID md4protectedhash, LPCWSTR password)
{
	BOOL status = FALSE;
	PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry;

	if(sid)
	{
		if(!(entry = kuhl_m_dpapi_oe_credential_get(sid, guid)))
		{
			if(entry = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) LocalAlloc(LPTR, sizeof(KUHL_M_DPAPI_OE_CREDENTIAL_ENTRY)))
			{
				entry->sid = _wcsdup(sid);
				entry->navigator.Blink = gDPAPI_Credentials.Blink;
				entry->navigator.Flink = &gDPAPI_Credentials;
				((PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) gDPAPI_Credentials.Blink)->navigator.Flink = (PLIST_ENTRY) entry;
				gDPAPI_Credentials.Blink= (PLIST_ENTRY) entry;
			}
		}
		if(entry)
			status = kuhl_m_dpapi_oe_credential_addtoEntry(entry, guid, md4hash, sha1hash, md4protectedhash, password);
	}
	else PRINT_ERROR(L"No SID?");
	return status;
}

void kuhl_m_dpapi_oe_credential_delete(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry)
{
	PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entryB = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Blink, entryF = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Flink;
	
	if(entry)
	{
		((PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Blink)->navigator.Flink = entry->navigator.Flink;
		((PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Flink)->navigator.Blink = entry->navigator.Blink;
		if(entry->sid)
			free(entry->sid);
		LocalFree(entry);
	}
}

void kuhl_m_dpapi_oe_credential_descr(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry)
{
	if(entry)
	{
		if(entry->sid)
			kprintf(L"SID:%s", entry->sid);
		kprintf(L";");
		if(entry->flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_GUID)
		{
			kprintf(L"GUID:");
			kull_m_string_displayGUID(&entry->guid);
		}
		kprintf(L";");
		if(entry->flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4)
		{
			kprintf(L"MD4:");
			kull_m_string_wprintf_hex(entry->md4hash, LM_NTLM_HASH_LENGTH, 0);
		}
		kprintf(L";");
		if(entry->flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_SHA1)
		{
			kprintf(L"SHA1:");
			kull_m_string_wprintf_hex(entry->sha1hash, SHA_DIGEST_LENGTH, 0);
		}
		kprintf(L";");
		if(entry->flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4p)
		{
			kprintf(L"MD4p:");
			kull_m_string_wprintf_hex(entry->md4protectedhash, LM_NTLM_HASH_LENGTH, 0);
		}
		kprintf(L"\n");
	}
}

void kuhl_m_dpapi_oe_credentials_delete()
{
	PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY tmp, entry;
	for(entry = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) gDPAPI_Credentials.Flink; entry != (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) &gDPAPI_Credentials; entry = tmp)
	{
		tmp = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Flink;
		kuhl_m_dpapi_oe_credential_delete(entry);
	}
}

void kuhl_m_dpapi_oe_credentials_descr()
{
	PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry;
	for(entry = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) gDPAPI_Credentials.Flink; entry != (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) &gDPAPI_Credentials; entry = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Flink)
		kuhl_m_dpapi_oe_credential_descr(entry);
}

PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY kuhl_m_dpapi_oe_domainkey_get(LPCGUID guid)
{
	PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry;
	for(entry = (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) gDPAPI_Domainkeys.Flink; entry != (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) &gDPAPI_Domainkeys; entry = (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) entry->navigator.Flink)
		if(RtlEqualGuid(guid, &entry->guid))
			return entry;
	return NULL;
}

BOOL kuhl_m_dpapi_oe_domainkey_add(LPCGUID guid, LPCVOID key, DWORD keyLen, BOOL isNewKey)
{
	BOOL status = FALSE;
	PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry;
	if(guid && key && keyLen)
	{
		if(!kuhl_m_dpapi_oe_domainkey_get(guid))
		{
			if(entry = (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) LocalAlloc(LPTR, sizeof(KUHL_M_DPAPI_OE_DOMAINKEY_ENTRY)))
			{
				RtlCopyMemory(&entry->guid, guid, sizeof(GUID));
				entry->isNewKey = isNewKey;
				if(entry->key = LocalAlloc(LPTR, keyLen))
				{
					RtlCopyMemory(entry->key, key, keyLen);
					entry->keyLen = keyLen;
					status = TRUE;
				}
				entry->navigator.Blink = gDPAPI_Domainkeys.Blink;
				entry->navigator.Flink = &gDPAPI_Domainkeys;
				((PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) gDPAPI_Domainkeys.Blink)->navigator.Flink = (PLIST_ENTRY) entry;
				gDPAPI_Domainkeys.Blink= (PLIST_ENTRY) entry;
			}
		}
	}
	else PRINT_ERROR(L"No GUID or Key?");
	return status;
}

void kuhl_m_dpapi_oe_domainkey_delete(PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry)
{
	if(entry)
	{
		((PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) entry->navigator.Blink)->navigator.Flink = entry->navigator.Flink;
		((PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) entry->navigator.Flink)->navigator.Blink = entry->navigator.Blink;

		if(entry->key)
			LocalFree(entry->key);
		LocalFree(entry);
	}
}

void kuhl_m_dpapi_oe_domainkey_descr(PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry)
{
	if(entry)
	{
		kprintf(L"GUID:");
		kull_m_string_displayGUID(&entry->guid);
		kprintf(L";TYPE:%s\n", entry->isNewKey ? L"RSA" : L"LEGACY");
	}
}

void kuhl_m_dpapi_oe_domainkeys_delete()
{
	PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY tmp, entry;
	for(entry = (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) gDPAPI_Domainkeys.Flink; entry != (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) &gDPAPI_Domainkeys; entry = tmp)
	{
		tmp = (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) entry->navigator.Flink;
		kuhl_m_dpapi_oe_domainkey_delete(entry);
	}
}

void kuhl_m_dpapi_oe_domainkeys_descr()
{
	PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry;
	for(entry = (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) gDPAPI_Domainkeys.Flink; entry != (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) &gDPAPI_Domainkeys; entry = (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) entry->navigator.Flink)
		kuhl_m_dpapi_oe_domainkey_descr(entry);
}

NTSTATUS kuhl_m_dpapi_oe_clean()
{
	kuhl_m_dpapi_oe_credentials_delete();
	kuhl_m_dpapi_oe_masterkeys_delete();
	kuhl_m_dpapi_oe_domainkeys_delete();
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_dpapi_oe_cache(int argc, wchar_t * argv[])
{
	kprintf(L"\nCREDENTIALS cache\n=================\n");
	kuhl_m_dpapi_oe_credentials_descr();

	kprintf(L"\nMASTERKEYS cache\n================\n");
	kuhl_m_dpapi_oe_masterkeys_descr();

	kprintf(L"\nDOMAINKEYS cache\n================\n");
	kuhl_m_dpapi_oe_domainkeys_descr();

	return STATUS_SUCCESS;
}

BOOL kuhl_m_dpapi_oe_autosid(LPCWSTR filename, LPWSTR * pSid)
{
	BOOL status = FALSE;
	wchar_t *duplicate, *pE;
	PSID tmpSid;
	if(filename && (duplicate = _wcsdup(filename)))
	{
		if(pE = wcsrchr(duplicate, L'\\'))
		{
			*pE = L'\0';
			if(pE = wcsrchr(duplicate, L'\\'))
			{
				if(ConvertStringSidToSid(++pE, &tmpSid))
				{
					if(status = ConvertSidToStringSid(tmpSid, pSid))
					{
						kprintf(L"Auto SID from path seems to be: %s\n", *pSid);
					}
					LocalFree(tmpSid);
				}
			}
		}
		free(duplicate);
	}
	return status;
}