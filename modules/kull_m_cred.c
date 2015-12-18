/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_cred.h"

PKULL_M_CRED_BLOB kull_m_cred_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_CRED_BLOB cred = NULL;
	if(cred = (PKULL_M_CRED_BLOB) LocalAlloc(LPTR, sizeof(KULL_M_CRED_BLOB)))
	{
		RtlCopyMemory(cred, data, FIELD_OFFSET(KULL_M_CRED_BLOB, TargetName));
		cred->TargetName = (LPWSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_CRED_BLOB, TargetName));
		cred->dwTargetAlias = *(PDWORD) ((PBYTE) cred->TargetName + cred->dwTargetName);
		cred->TargetAlias = (LPWSTR) ((PBYTE) cred->TargetName + cred->dwTargetName + sizeof(DWORD));
		cred->dwComment = *(PDWORD) ((PBYTE) cred->TargetAlias + cred->dwTargetAlias);
		cred->Comment = (LPWSTR) ((PBYTE) cred->TargetAlias + cred->dwTargetAlias + sizeof(DWORD));
		cred->dwUnkData = *(PDWORD) ((PBYTE) cred->Comment + cred->dwComment);
		cred->UnkData = (LPWSTR) ((PBYTE) cred->Comment + cred->dwComment + sizeof(DWORD));
		cred->dwUserName = *(PDWORD) ((PBYTE) cred->UnkData + cred->dwUnkData);
		cred->UserName = (LPWSTR) ((PBYTE) cred->UnkData + cred->dwUnkData + sizeof(DWORD));
		cred->CredentialBlobSize = *(PDWORD) ((PBYTE) cred->UserName + cred->dwUserName);
		cred->CredentialBlob = (PBYTE) cred->UserName + cred->dwUserName + sizeof(DWORD);
		
		if(cred->AttributeCount)
			kull_m_cred_attributes_create(((PBYTE) cred->CredentialBlob + cred->CredentialBlobSize + (cred->CredentialBlobSize & 1)), &cred->Attributes, cred->AttributeCount);			

		kull_m_string_ptr_replace(&cred->TargetName, cred->dwTargetName);
		kull_m_string_ptr_replace(&cred->TargetAlias, cred->dwTargetAlias);
		kull_m_string_ptr_replace(&cred->Comment, cred->dwComment);
		kull_m_string_ptr_replace(&cred->UnkData, cred->dwUnkData);
		kull_m_string_ptr_replace(&cred->UserName, cred->dwUserName);
		kull_m_string_ptr_replace(&cred->CredentialBlob, cred->CredentialBlobSize);
	}
	return cred;
}

void kull_m_cred_delete(PKULL_M_CRED_BLOB cred)
{
	if(cred)
	{
		if(cred->TargetName)
			LocalFree(cred->TargetName);
		if(cred->TargetAlias)
			LocalFree(cred->TargetAlias);
		if(cred->Comment)
			LocalFree(cred->Comment);
		if(cred->UnkData)
			LocalFree(cred->UnkData);
		if(cred->UserName)
			LocalFree(cred->UserName);
		if(cred->CredentialBlob)
			LocalFree(cred->CredentialBlob);
		LocalFree(cred);
	}
}

void kull_m_cred_descr(DWORD level, PKULL_M_CRED_BLOB cred)
{
	UNICODE_STRING uString;
	kprintf(L"%*s" L"**CREDENTIAL**\n", level << 1, L"");
	if(cred)
	{
		kprintf(L"%*s" L"  credFlags      : %08x - %u\n", level << 1, L"", cred->credFlags, cred->credFlags);
		kprintf(L"%*s" L"  credSize       : %08x - %u\n", level << 1, L"", cred->credSize, cred->credSize);
		kprintf(L"%*s" L"  credUnk0       : %08x - %u\n\n", level << 1, L"", cred->credUnk0, cred->credUnk0);
		
		kprintf(L"%*s" L"  Type           : %08x - %u\n", level << 1, L"", cred->Type, cred->Type);
		kprintf(L"%*s" L"  Flags          : %08x - %u\n", level << 1, L"", cred->Flags, cred->Flags);

		kprintf(L"%*s" L"  LastWritten    : ", level << 1, L""); kull_m_string_displayFileTime(&cred->LastWritten); kprintf(L"\n");
		kprintf(L"%*s" L"  unkFlagsOrSize : %08x - %u\n", level << 1, L"", cred->unkFlagsOrSize, cred->unkFlagsOrSize);
		kprintf(L"%*s" L"  Persist        : %08x - %u\n", level << 1, L"", cred->Persist, cred->Persist);
		kprintf(L"%*s" L"  AttributeCount : %08x - %u\n", level << 1, L"", cred->AttributeCount, cred->AttributeCount);
		kprintf(L"%*s" L"  unk0           : %08x - %u\n", level << 1, L"", cred->unk0, cred->unk0);
		kprintf(L"%*s" L"  unk1           : %08x - %u\n", level << 1, L"", cred->unk1, cred->unk1);

		kprintf(L"%*s" L"  TargetName     : %s\n", level << 1, L"", cred->TargetName);
		kprintf(L"%*s" L"  TargetAlias    : %s\n", level << 1, L"", cred->TargetAlias);
		kprintf(L"%*s" L"  Comment        : %s\n", level << 1, L"", cred->Comment);
		kprintf(L"%*s" L"  UnkData        : %s\n", level << 1, L"", cred->UnkData);
		kprintf(L"%*s" L"  UserName       : %s\n", level << 1, L"", cred->UserName);
		kprintf(L"%*s" L"  CredentialBlob : ", level << 1, L"");

		uString.Length = uString.MaximumLength = (USHORT) cred->CredentialBlobSize;
		uString.Buffer = (PWSTR) cred->CredentialBlob;
		if(kull_m_string_suspectUnicodeString(&uString))
			kprintf(L"%wZ", &uString);
		else 
			kull_m_string_wprintf_hex(uString.Buffer, uString.Length, 1);
		kprintf(L"\n");

		kprintf(L"%*s" L"  Attributes     : ", level << 1, L"", cred->AttributeCount);
		kull_m_cred_attributes_descr(level + 1, cred->Attributes, cred->AttributeCount);
	}
}

BOOL kull_m_cred_attributes_create(PVOID data, PKULL_M_CRED_ATTRIBUTE **Attributes, DWORD count)
{
	BOOL status = FALSE;
	DWORD i, j;
	
	if((*Attributes) = (PKULL_M_CRED_ATTRIBUTE *) LocalAlloc(LPTR, count * sizeof(PKULL_M_CRED_ATTRIBUTE)))
	{
		for(i = 0, j = 0, status = TRUE; (i < count) && status; i++)
		{
			if((*Attributes)[i] = kull_m_cred_attribute_create((PBYTE) data + j))
				j +=  sizeof(KULL_M_CRED_ATTRIBUTE) - 2 * sizeof(PVOID) + (*Attributes)[i]->dwKeyword + (*Attributes)[i]->ValueSize;
			else status = FALSE;
		}
	}
	if(!status)
	{
		kull_m_cred_attributes_delete(*Attributes, count);
		*Attributes = NULL;
	}
	return status;
}

void kull_m_cred_attributes_delete(PKULL_M_CRED_ATTRIBUTE *Attributes, DWORD count)
{
	DWORD i;
	if(Attributes)
	{
		for(i = 0; i < count; i++)
			kull_m_cred_attribute_delete(Attributes[i]);
		LocalFree(Attributes);
	}
}

void kull_m_cred_attributes_descr(DWORD level, PKULL_M_CRED_ATTRIBUTE *Attributes, DWORD count)
{
	DWORD i;
	if(count && Attributes)
	{
		kprintf(L"%u attributes(s)\n", count);
		for(i = 0; i < count; i++)
			kull_m_cred_attribute_descr(level, Attributes[i]);
	}
}

PKULL_M_CRED_ATTRIBUTE kull_m_cred_attribute_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_CRED_ATTRIBUTE Attribute = NULL;
	if(Attribute = (PKULL_M_CRED_ATTRIBUTE) LocalAlloc(LPTR, sizeof(KULL_M_CRED_ATTRIBUTE)))
	{
		RtlCopyMemory(Attribute, data, FIELD_OFFSET(KULL_M_CRED_ATTRIBUTE, Keyword));
		Attribute->Keyword = (LPWSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_CRED_ATTRIBUTE, Keyword));
		Attribute->ValueSize = *(PDWORD) ((PBYTE) Attribute->Keyword + Attribute->dwKeyword);
		Attribute->Value = (PBYTE) Attribute->Keyword + Attribute->dwKeyword + sizeof(DWORD);

		kull_m_string_ptr_replace(&Attribute->Keyword, Attribute->dwKeyword);
		kull_m_string_ptr_replace(&Attribute->Value, Attribute->ValueSize);
	}
	return Attribute;
}

void kull_m_cred_attribute_delete(PKULL_M_CRED_ATTRIBUTE Attribute)
{
	if(Attribute)
	{
		if(Attribute->Keyword)
			LocalFree(Attribute->Keyword);
		if(Attribute->Value)
			LocalFree(Attribute->Value);
		LocalFree(Attribute);
	}
}

void kull_m_cred_attribute_descr(DWORD level, PKULL_M_CRED_ATTRIBUTE Attribute)
{
	UNICODE_STRING uString;
	kprintf(L"%*s" L"**ATTRIBUTE**\n", level << 1, L"");
	if(Attribute)
	{
		kprintf(L"%*s" L"  Flags   : %08x - %u\n", level << 1, L"", Attribute->Flags, Attribute->Flags);
		kprintf(L"%*s" L"  Keyword : %s\n", level << 1, L"", Attribute->Keyword);
		kprintf(L"%*s" L"  Value : ", level << 1, L"");

		uString.Length = uString.MaximumLength = (USHORT) Attribute->ValueSize;
		uString.Buffer = (PWSTR) Attribute->Value;
		if(kull_m_string_suspectUnicodeString(&uString))
			kprintf(L"%wZ", &uString);
		else
			kull_m_string_wprintf_hex(uString.Buffer, uString.Length, 1);
		kprintf(L"\n");
	}
}

PKULL_M_CRED_VAULT_POLICY kull_m_cred_vault_policy_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_CRED_VAULT_POLICY policy = NULL;
	if(policy = (PKULL_M_CRED_VAULT_POLICY) LocalAlloc(LPTR, sizeof(KULL_M_CRED_VAULT_POLICY)))
	{
		RtlCopyMemory(policy, data, FIELD_OFFSET(KULL_M_CRED_VAULT_POLICY, Name));
		policy->Name = (LPWSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_CRED_VAULT_POLICY, Name));
		RtlCopyMemory(&policy->unk0, (PBYTE) policy->Name + policy->dwName, FIELD_OFFSET(KULL_M_CRED_VAULT_POLICY, key) - FIELD_OFFSET(KULL_M_CRED_VAULT_POLICY, unk0));
		policy->key = kull_m_cred_vault_policy_key_create((PBYTE) policy->Name + policy->dwName +  FIELD_OFFSET(KULL_M_CRED_VAULT_POLICY, key) - FIELD_OFFSET(KULL_M_CRED_VAULT_POLICY, unk0));

		kull_m_string_ptr_replace(&policy->Name, policy->dwName);
	}
	return policy;
}

void kull_m_cred_vault_policy_delete(PKULL_M_CRED_VAULT_POLICY policy)
{
	if(policy)
	{
		if(policy->Name)
			LocalFree(policy->Name);
		if(policy->key)
			kull_m_cred_vault_policy_key_delete(policy->key);
		LocalFree(policy);
	}
}

void kull_m_cred_vault_policy_descr(DWORD level, PKULL_M_CRED_VAULT_POLICY policy)
{
	kprintf(L"%*s" L"**VAULT POLICY**\n", level << 1, L"");
	if(policy)
	{
		kprintf(L"%*s" L"  version : %08x - %u\n", level << 1, L"", policy->version, policy->version);
		kprintf(L"%*s" L"  vault   : ", level << 1, L""); kull_m_string_displayGUID(&policy->vault); kprintf(L"\n");
		kprintf(L"%*s" L"  Name    : %s\n", level << 1, L"", policy->Name);
		kprintf(L"%*s" L"  unk0/1/2: %08x/%08x/%08x\n", level << 1, L"", policy->unk0, policy->unk1, policy->unk2);
		if(policy->key)
			kull_m_cred_vault_policy_key_descr(level + 1, policy->key);
		kprintf(L"\n");
	}
}

PKULL_M_CRED_VAULT_POLICY_KEY kull_m_cred_vault_policy_key_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_CRED_VAULT_POLICY_KEY key = NULL;
	if(key = (PKULL_M_CRED_VAULT_POLICY_KEY) LocalAlloc(LPTR, sizeof(KULL_M_CRED_VAULT_POLICY_KEY)))
	{
		RtlCopyMemory(key, data, FIELD_OFFSET(KULL_M_CRED_VAULT_POLICY_KEY, KeyBlob));
		key->KeyBlob = (PBYTE) data + FIELD_OFFSET(KULL_M_CRED_VAULT_POLICY_KEY, KeyBlob);
		kull_m_string_ptr_replace(&key->KeyBlob, key->dwKeyBlob);
	}
	return key;
}

void kull_m_cred_vault_policy_key_delete(PKULL_M_CRED_VAULT_POLICY_KEY key)
{
	if(key)
	{
		if(key->KeyBlob)
			LocalFree(key->KeyBlob);
		LocalFree(key);
	}
}

void kull_m_cred_vault_policy_key_descr(DWORD level, PKULL_M_CRED_VAULT_POLICY_KEY key)
{
	kprintf(L"%*s" L"**VAULT POLICY KEY**\n", level << 1, L"");
	if(key)
	{
		kprintf(L"%*s" L"  unk0  : ", level << 1, L""); kull_m_string_displayGUID(&key->unk0); kprintf(L"\n");
		kprintf(L"%*s" L"  unk1  : ", level << 1, L""); kull_m_string_displayGUID(&key->unk1); kprintf(L"\n");
		kull_m_dpapi_blob_quick_descr(level + 1, key->KeyBlob);
		kprintf(L"\n");
	}
}

BOOL kull_m_cred_vault_policy_key(PVOID data, DWORD size, BYTE aes128[AES_128_KEY_SIZE], BYTE aes256[AES_256_KEY_SIZE])
{
	BOOL status = FALSE;
	DWORD keySize128, keySize256;
	PBYTE ptr = (PBYTE) data;
	PKULL_M_CRED_VAULT_POLICY_KEY_MBDK pMbdk;
	PKIWI_BCRYPT_KEY pBcrypt;

	keySize128 = *(PDWORD) ptr;
	if(keySize128 >= 0x24)
	{
		if(*(PDWORD) (ptr + 3 * sizeof(DWORD)) == 'MBDK')
		{
			pMbdk = (PKULL_M_CRED_VAULT_POLICY_KEY_MBDK) ptr;
			if(status = ((pMbdk->type == 2) && (pMbdk->key.cbSecret == AES_128_KEY_SIZE)))
				RtlCopyMemory(aes128, pMbdk->key.data, AES_128_KEY_SIZE);
		}
		else if(*(PDWORD) (ptr + 4 * sizeof(DWORD)) == 'MSSK')
		{
			pBcrypt = (PKIWI_BCRYPT_KEY) (ptr + 3 * sizeof(DWORD));
			if(status = ((pBcrypt->bits == 128) && (pBcrypt->hardkey.cbSecret == AES_128_KEY_SIZE)))
				RtlCopyMemory(aes128, pBcrypt->hardkey.data, AES_128_KEY_SIZE);
		}

		if(status)
		{
			status = FALSE;
			ptr += sizeof(DWORD) + keySize128;
			keySize256 = *(PDWORD) ptr;
			if(keySize256 >= 0x34)
			{
				if(*(PDWORD) (ptr + 3 * sizeof(DWORD)) == 'MBDK')
				{
					pMbdk = (PKULL_M_CRED_VAULT_POLICY_KEY_MBDK) ptr;
					if(status = ((pMbdk->type == 1) && (pMbdk->key.cbSecret == AES_256_KEY_SIZE)))
						RtlCopyMemory(aes256, pMbdk->key.data, AES_256_KEY_SIZE);
				}
				else if(*(PDWORD) (ptr + 4 * sizeof(DWORD)) == 'MSSK')
				{
					pBcrypt = (PKIWI_BCRYPT_KEY) (ptr + 3 * sizeof(DWORD));
					if(status = ((pBcrypt->bits == 256) && (pBcrypt->hardkey.cbSecret == AES_256_KEY_SIZE)))
						RtlCopyMemory(aes256, pBcrypt->hardkey.data, AES_256_KEY_SIZE);
				}
			}
		}
	}
	return status;
}

PKULL_M_CRED_VAULT_CREDENTIAL kull_m_cred_vault_credential_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_CRED_VAULT_CREDENTIAL credential = NULL;
	PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE attribute;
	PBYTE ptr;
	DWORD i;
	if(credential = (PKULL_M_CRED_VAULT_CREDENTIAL) LocalAlloc(LPTR, sizeof(KULL_M_CRED_VAULT_CREDENTIAL)))
	{
		RtlCopyMemory(credential, data, FIELD_OFFSET(KULL_M_CRED_VAULT_CREDENTIAL, FriendlyName));
		credential->FriendlyName = (LPWSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_CRED_VAULT_CREDENTIAL, FriendlyName));
		credential->dwAttributesMapSize = *(PDWORD) ((PBYTE) credential->FriendlyName + credential->dwFriendlyName);
		credential->attributesMap = (PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP) ((PBYTE) credential->FriendlyName + credential->dwFriendlyName + sizeof(DWORD));

		kull_m_string_ptr_replace(&credential->FriendlyName, credential->dwFriendlyName);
		kull_m_string_ptr_replace(&credential->attributesMap, credential->dwAttributesMapSize);

		credential->__cbElements = credential->dwAttributesMapSize / sizeof(KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP);
		if(credential->attributes = (PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE * ) LocalAlloc(LPTR, (credential->__cbElements + ((credential->unk0 < 4) ? 1 : 0)) * sizeof(PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE)))
		{
			for(i = 0; i < credential->__cbElements; i++)
			{
				if(credential->attributes[i] = (PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE) LocalAlloc(LPTR, sizeof(KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE)))
				{
					attribute = (PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE) ((PBYTE) data + credential->attributesMap[i].offset);

					RtlCopyMemory(credential->attributes[i], attribute, FIELD_OFFSET(KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE, szData));
					ptr = (PBYTE) attribute;
					if(attribute->id >= 100)
						ptr += sizeof(DWORD); // boo!
					ptr += FIELD_OFFSET(KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE, szData);
					kull_m_cred_vault_credential_create_attribute_from_data(ptr, credential->attributes[i]);
				}
			}
			if(attribute && credential->unk0 < 4)
			{
				if(credential->attributes[i] = (PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE) LocalAlloc(LPTR, sizeof(KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE)))
				{
					kull_m_cred_vault_credential_create_attribute_from_data((PBYTE) attribute + FIELD_OFFSET(KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE, data) + attribute->szData + sizeof(USHORT), credential->attributes[i]);
					credential->__cbElements++;
				}
			}
		}
	}
	return credential;
}

void kull_m_cred_vault_credential_create_attribute_from_data(PBYTE ptr, PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE attribute)
{
	BOOLEAN isIV;
	if(attribute->szData = *(PDWORD) ptr)
	{
		attribute->szData--;
		ptr += sizeof(DWORD);
		isIV = *(PBOOLEAN) ptr;
		ptr += sizeof(BOOLEAN);
		if(isIV)
		{
			attribute->szData -= sizeof(DWORD);;
			if(attribute->szIV = *(PDWORD) ptr)
			{
				attribute->szData -= attribute->szIV;
				ptr += sizeof(DWORD);
				attribute->IV = ptr;
				ptr += attribute->szIV;
				kull_m_string_ptr_replace(&attribute->IV, attribute->szIV);
			}
		}
		attribute->data = ptr;
		kull_m_string_ptr_replace(&attribute->data, attribute->szData);
	}
}

void kull_m_cred_vault_credential_delete(PKULL_M_CRED_VAULT_CREDENTIAL credential)
{
	DWORD i;
	if(credential)
	{
		if(credential->FriendlyName)
			LocalFree(credential->FriendlyName);
		if(credential->attributesMap)
			LocalFree(credential->attributesMap);

		if(credential->attributes)
		{
			for(i = 0; i < credential->__cbElements; i++)
			{
				if(credential->attributes[i])
				{
					if(credential->attributes[i]->data)
							LocalFree(credential->attributes[i]->data);
					if(credential->attributes[i]->IV)
							LocalFree(credential->attributes[i]->IV);
					LocalFree(credential->attributes[i]);
				}
			}
			LocalFree(credential->attributes);
		}
		LocalFree(credential);
	}
}

void kull_m_cred_vault_credential_descr(DWORD level, PKULL_M_CRED_VAULT_CREDENTIAL credential)
{
	DWORD i;
	kprintf(L"%*s" L"**VAULT CREDENTIAL**\n", level << 1, L"");
	if(credential)
	{
		kprintf(L"%*s" L"  SchemaId            : ", level << 1, L""); kull_m_string_displayGUID(&credential->SchemaId); kprintf(L"\n");
		kprintf(L"%*s" L"  unk0                : %08x - %u\n", level << 1, L"", credential->unk0, credential->unk0);
		kprintf(L"%*s" L"  LastWritten         : ", level << 1, L""); kull_m_string_displayFileTime(&credential->LastWritten); kprintf(L"\n");
		kprintf(L"%*s" L"  unk1                : %08x - %u\n", level << 1, L"", credential->unk1, credential->unk1);
		kprintf(L"%*s" L"  unk2                : %08x - %u\n", level << 1, L"", credential->unk2, credential->unk2);
		kprintf(L"%*s" L"  FriendlyName        : %s\n", level << 1, L"", credential->FriendlyName);
		kprintf(L"%*s" L"  dwAttributesMapSize : %08x - %u\n", level << 1, L"", credential->dwAttributesMapSize, credential->dwAttributesMapSize);
		for(i = 0; i < (credential->dwAttributesMapSize / sizeof(KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP)); i++)
			kprintf(L"%*s" L"  * Attribute %3u @ offset %08x - %u  (unk %08x - %u)\n", level << 1, L"", credential->attributesMap[i].id, credential->attributesMap[i].offset, credential->attributesMap[i].offset, credential->attributesMap[i].unk, credential->attributesMap[i].unk);
		for(i = 0; i < credential->__cbElements; i++)
			kull_m_cred_vault_credential_attribute_descr(level + 1, credential->attributes[i]);
		kprintf(L"\n");
	}
}

void kull_m_cred_vault_credential_attribute_descr(DWORD level, PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE attribute)
{
	kprintf(L"%*s" L"**VAULT CREDENTIAL ATTRIBUTE**\n", level << 1, L"");
	if(attribute)
	{
		kprintf(L"%*s" L"  id      : %08x - %u\n", level << 1, L"", attribute->id, attribute->id);
		kprintf(L"%*s" L"  unk0/1/2: %08x/%08x/%08x\n", level << 1, L"", attribute->unk0, attribute->unk1, attribute->unk2);
		if(attribute->szIV && attribute->IV)
		{
			kprintf(L"%*s" L"  IV      : ", level << 1, L"");
			kull_m_string_wprintf_hex(attribute->IV, attribute->szIV, 0);
			kprintf(L"\n");
		}
		if(attribute->szData && attribute->data)
		{
			kprintf(L"%*s" L"  Data    : ", level << 1, L"");
			kull_m_string_wprintf_hex(attribute->data, attribute->szData, 0);
			kprintf(L"\n");
		}
	}
}

PKULL_M_CRED_VAULT_CLEAR kull_m_cred_vault_clear_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_CRED_VAULT_CLEAR clear = NULL;
	DWORD i, size;
	PBYTE ptr;
	if(clear = (PKULL_M_CRED_VAULT_CLEAR) LocalAlloc(LPTR, sizeof(KULL_M_CRED_VAULT_CLEAR)))
	{
		RtlCopyMemory(clear, data, FIELD_OFFSET(KULL_M_CRED_VAULT_CLEAR, entries));
		if(clear->count && (clear->entries = (PKULL_M_CRED_VAULT_CLEAR_ENTRY *) LocalAlloc(LPTR, clear->count * sizeof(PKULL_M_CRED_VAULT_CLEAR_ENTRY))))
		{
			ptr = (PBYTE) data + FIELD_OFFSET(KULL_M_CRED_VAULT_CLEAR, entries);
			for(i = 0; i < clear->count; i++)
			{
				size = FIELD_OFFSET(KULL_M_CRED_VAULT_CLEAR_ENTRY, data) + *(PDWORD) (ptr + FIELD_OFFSET(KULL_M_CRED_VAULT_CLEAR_ENTRY, size));
				if(clear->entries[i] = (PKULL_M_CRED_VAULT_CLEAR_ENTRY) LocalAlloc(LPTR, size))
					RtlCopyMemory(clear->entries[i], ptr, size);
				ptr += size;
			}
		}
	}
	return clear;
}

void kull_m_cred_vault_clear_delete(PKULL_M_CRED_VAULT_CLEAR clear)
{
	DWORD i;
	if(clear)
	{
		if(clear->entries)
		{
			for(i = 0 ; i < clear->count; i++)
				if(clear->entries[i])
					LocalFree(clear->entries[i]);
			LocalFree(clear->entries);
		}
		LocalFree(clear);
	}
}

void kull_m_cred_vault_clear_descr(DWORD level, PKULL_M_CRED_VAULT_CLEAR clear)
{
	DWORD i;
	UNICODE_STRING creds;
	kprintf(L"%*s" L"**VAULT CREDENTIAL CLEAR ATTRIBUTES**\n", level << 1, L"");
	if(clear)
	{
		kprintf(L"%*s" L"  version: %08x - %u\n", level << 1, L"", clear->version, clear->version);
		kprintf(L"%*s" L"  count  : %08x - %u\n", level << 1, L"", clear->count, clear->count);
		kprintf(L"%*s" L"  unk    : %08x - %u\n", level << 1, L"", clear->unk, clear->unk);

		if(clear->entries)
		{
			kprintf(L"\n");
			for(i = 0; i < clear->count; i++)
			{
				kprintf(L"%*s" L"  * ", level << 1, L"");
				switch(clear->entries[i]->id)
				{
				case 1:
					kprintf(L"ressource     : ");
					break;
				case 2:
					kprintf(L"identity      : ");
					break;
				case 3:
					kprintf(L"authenticator : ");
					break;
				default:
					kprintf(L"property %3u  : ", clear->entries[i]->id);
					break;
				}
				creds.Buffer = (PWSTR) clear->entries[i]->data;
				creds.Length = creds.MaximumLength = (USHORT) clear->entries[i]->size;
				if((clear->entries[i]->id < 100) && kull_m_string_suspectUnicodeString(&creds))
					kprintf(L"%s", clear->entries[i]->data);
				else
					kull_m_string_wprintf_hex(clear->entries[i]->data, clear->entries[i]->size, 1);
				kprintf(L"\n");
			}
		}
	}
}