/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kull_m_key.h"

PKULL_M_KEY_CAPI_BLOB kull_m_key_capi_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_KEY_CAPI_BLOB capiKey = NULL;
	if(capiKey = (PKULL_M_KEY_CAPI_BLOB) LocalAlloc(LPTR, sizeof(KULL_M_KEY_CAPI_BLOB)))
	{
		RtlCopyMemory(capiKey, data, FIELD_OFFSET(KULL_M_KEY_CAPI_BLOB, pName));
		capiKey->pName = (PSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_KEY_CAPI_BLOB, pName));
		capiKey->pHash = (PBYTE) capiKey->pName + capiKey->dwNameLen;
		capiKey->pPublicKey = (PBYTE) capiKey->pHash + capiKey->dwHashLen;
		capiKey->pPrivateKey = (PBYTE) capiKey->pPublicKey + capiKey->dwPublicKeyLen;
		capiKey->pExportFlag = (PBYTE) capiKey->pPrivateKey + capiKey->dwPrivateKeyLen;

		kull_m_string_ptr_replace(&capiKey->pName, capiKey->dwNameLen);
		kull_m_string_ptr_replace(&capiKey->pHash, capiKey->dwHashLen);
		kull_m_string_ptr_replace(&capiKey->pPublicKey, capiKey->dwPublicKeyLen);
		kull_m_string_ptr_replace(&capiKey->pPrivateKey, capiKey->dwPrivateKeyLen);
		kull_m_string_ptr_replace(&capiKey->pExportFlag, capiKey->dwExportFlagLen);
	}
	return capiKey;
}

void kull_m_key_capi_delete(PKULL_M_KEY_CAPI_BLOB capiKey)
{
	if(capiKey)
	{
		if(capiKey->pName)
			LocalFree(capiKey->pName);
		if(capiKey->pHash)
			LocalFree(capiKey->pHash);
		if(capiKey->pPublicKey)
			LocalFree(capiKey->pPublicKey);
		if(capiKey->pPrivateKey)
			LocalFree(capiKey->pPrivateKey);
		if(capiKey->pExportFlag)
			LocalFree(capiKey->pExportFlag);
		LocalFree(capiKey);
	}
}

void kull_m_key_capi_descr(PKULL_M_KEY_CAPI_BLOB capiKey)
{
	kprintf(L"**KEY (capi)**\n");
	if(capiKey)
	{
		kprintf(L"  dwVersion          : %08x - %u\n", capiKey->dwVersion, capiKey->dwVersion);
		kprintf(L"  dwUniqueNameLen    : %08x - %u\n", capiKey->dwNameLen, capiKey->dwNameLen);
		kprintf(L"  dwPublicKeyLen     : %08x - %u\n", capiKey->dwPublicKeyLen, capiKey->dwPublicKeyLen);
		kprintf(L"  dwPrivateKeyLen    : %08x - %u\n", capiKey->dwPrivateKeyLen, capiKey->dwPrivateKeyLen);
		kprintf(L"  dwHashLen          : %08x - %u\n", capiKey->dwHashLen, capiKey->dwHashLen);
		kprintf(L"  dwExportFlagLen    : %08x - %u\n", capiKey->dwExportFlagLen, capiKey->dwExportFlagLen);

		kprintf(L"  pUniqueName        : "); kprintf(L"%S\n", capiKey->pName);
		kprintf(L"  pHash              : "); kull_m_string_wprintf_hex(capiKey->pHash, capiKey->dwHashLen, 0); kprintf(L"\n");
		kprintf(L"  pPublicKey         : "); kull_m_string_wprintf_hex(capiKey->pPublicKey, capiKey->dwPublicKeyLen, 0); kprintf(L"\n");
		kprintf(L"  pPrivateKey        : "); kull_m_string_wprintf_hex(capiKey->pPrivateKey, capiKey->dwPrivateKeyLen, 0); kprintf(L"\n");
		kprintf(L"  pExportFlag        : "); kull_m_string_wprintf_hex(capiKey->pExportFlag, capiKey->dwExportFlagLen, 0); kprintf(L"\n\n");
	}
}

BOOL kull_m_key_capi_write(PKULL_M_KEY_CAPI_BLOB capiKey, PVOID *data, DWORD *size)
{
	BOOL status = FALSE;
	PBYTE ptr;
	*size = FIELD_OFFSET(KULL_M_KEY_CAPI_BLOB, pName) + capiKey->dwNameLen + capiKey->dwHashLen + capiKey->dwPublicKeyLen + capiKey->dwPrivateKeyLen + capiKey->dwExportFlagLen;
	if(*data = LocalAlloc(LPTR, *size))
	{
		ptr = (PBYTE) *data;
		RtlCopyMemory(ptr, capiKey, FIELD_OFFSET(KULL_M_KEY_CAPI_BLOB, pName));
		ptr += FIELD_OFFSET(KULL_M_KEY_CAPI_BLOB, pName);
		RtlCopyMemory(ptr, capiKey->pName, capiKey->dwNameLen);
		ptr += capiKey->dwNameLen;
		RtlCopyMemory(ptr, capiKey->pHash, capiKey->dwHashLen);
		ptr += capiKey->dwHashLen;
		RtlCopyMemory(ptr, capiKey->pPublicKey, capiKey->dwPublicKeyLen);
		ptr += capiKey->dwPublicKeyLen;
		RtlCopyMemory(ptr, capiKey->pPrivateKey, capiKey->dwPrivateKeyLen);
		ptr += capiKey->dwPrivateKeyLen;
		RtlCopyMemory(ptr, capiKey->pExportFlag, capiKey->dwExportFlagLen);
		status = TRUE;
	}
	return status;
}

PKULL_M_KEY_CNG_BLOB kull_m_key_cng_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_KEY_CNG_BLOB cngKey = NULL;

	if(cngKey = (PKULL_M_KEY_CNG_BLOB) LocalAlloc(LPTR, sizeof(KULL_M_KEY_CNG_BLOB)))
	{
		RtlCopyMemory(cngKey, data, FIELD_OFFSET(KULL_M_KEY_CNG_BLOB, pName));
		cngKey->pName = (PSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_KEY_CNG_BLOB, pName));
		if(!kull_m_key_cng_properties_create((PBYTE) cngKey->pName + cngKey->dwNameLen, cngKey->dwPublicPropertiesLen, &cngKey->pPublicProperties, &cngKey->cbPublicProperties))
			PRINT_ERROR(L"kull_m_key_cng_properties_create (public)\n");
		cngKey->pPrivateProperties = (PBYTE) cngKey->pName + cngKey->dwNameLen + cngKey->dwPublicPropertiesLen;
		cngKey->pPrivateKey = (PBYTE) cngKey->pPrivateProperties + cngKey->dwPrivatePropertiesLen;
		kull_m_string_ptr_replace(&cngKey->pName, cngKey->dwNameLen);
		kull_m_string_ptr_replace(&cngKey->pPrivateProperties, cngKey->dwPrivatePropertiesLen);
		kull_m_string_ptr_replace(&cngKey->pPrivateKey, cngKey->dwPrivateKeyLen);
	}
	return cngKey;
}

void kull_m_key_cng_delete(PKULL_M_KEY_CNG_BLOB cngKey)
{
	if(cngKey)
	{
		if(cngKey->pName)
			LocalFree(cngKey->pName);
		if(cngKey->cbPublicProperties && cngKey->pPublicProperties)
			kull_m_key_cng_properties_delete(cngKey->pPublicProperties, cngKey->cbPublicProperties);
		if(cngKey->pPrivateProperties)
			LocalFree(cngKey->pPrivateProperties);
		if(cngKey->pPrivateKey)
			LocalFree(cngKey->pPrivateKey);
		LocalFree(cngKey);
	}
}

void kull_m_key_cng_descr(PKULL_M_KEY_CNG_BLOB cngKey)
{
	kprintf(L"**KEY (cng)**\n");
	if(cngKey)
	{
		kprintf(L"  dwVersion             : %08x - %u\n", cngKey->dwVersion, cngKey->dwVersion);
		kprintf(L"  unk                   : %08x - %u\n", cngKey->unk, cngKey->unk);
		kprintf(L"  dwNameLen             : %08x - %u\n", cngKey->dwNameLen, cngKey->dwNameLen);
		kprintf(L"  type                  : %08x - %u\n", cngKey->type, cngKey->type);
		kprintf(L"  dwPublicPropertiesLen : %08x - %u\n", cngKey->dwPublicPropertiesLen, cngKey->dwPublicPropertiesLen);
		kprintf(L"  dwPrivatePropertiesLen: %08x - %u\n", cngKey->dwPrivatePropertiesLen, cngKey->dwPrivatePropertiesLen);
		kprintf(L"  dwPrivateKeyLen       : %08x - %u\n", cngKey->dwPrivateKeyLen, cngKey->dwPrivateKeyLen);
		kprintf(L"  unkArray[16]          : "); kull_m_string_wprintf_hex(cngKey->unkArray, sizeof(cngKey->unkArray), 0); kprintf(L"\n");
		kprintf(L"  pName                 : "); kprintf(L"%.*s\n", cngKey->dwNameLen / sizeof(wchar_t), cngKey->pName);
		kprintf(L"  pPublicProperties     :\n"); kull_m_key_cng_properties_descr(cngKey->pPublicProperties, cngKey->cbPublicProperties);
		kprintf(L"  pPrivateProperties    : "); kull_m_string_wprintf_hex(cngKey->pPrivateProperties, cngKey->dwPrivatePropertiesLen, 0); kprintf(L"\n");
		kprintf(L"  pPrivateKey           : "); kull_m_string_wprintf_hex(cngKey->pPrivateKey, cngKey->dwPrivateKeyLen, 0); kprintf(L"\n\n");
	}
}

PKULL_M_KEY_CNG_PROPERTY kull_m_key_cng_property_create(PVOID data/*, DWORD size*/)
{
	PKULL_M_KEY_CNG_PROPERTY cngProperty = NULL;
	if(cngProperty = (PKULL_M_KEY_CNG_PROPERTY) LocalAlloc(LPTR, sizeof(KULL_M_KEY_CNG_PROPERTY)))
	{
		RtlCopyMemory(cngProperty, data, FIELD_OFFSET(KULL_M_KEY_CNG_PROPERTY, pName));
		cngProperty->pName = (PSTR) ((PBYTE) data + FIELD_OFFSET(KULL_M_KEY_CNG_PROPERTY, pName));
		cngProperty->pProperty = (PBYTE) cngProperty->pName + cngProperty->dwNameLen;
		kull_m_string_ptr_replace(&cngProperty->pName, cngProperty->dwNameLen);
		kull_m_string_ptr_replace(&cngProperty->pProperty, cngProperty->dwPropertyLen);
	}
	return cngProperty;
}

void kull_m_key_cng_property_delete(PKULL_M_KEY_CNG_PROPERTY property)
{
	if(property)
	{
		if(property->pName)
			LocalFree(property->pName);
		if(property->pProperty)
			LocalFree(property->pProperty);
		LocalFree(property);
	}
}

void kull_m_key_cng_property_descr(PKULL_M_KEY_CNG_PROPERTY property)
{
	kprintf(L"    **KEY CNG PROPERTY**\n");
	if(property)
	{
		kprintf(L"      dwStructLen     : %08x - %u\n", property->dwStructLen, property->dwStructLen);
		kprintf(L"      type            : %08x - %u\n", property->type, property->type);
		kprintf(L"      unk             : %08x - %u\n", property->unk, property->unk);
		kprintf(L"      dwNameLen       : %08x - %u\n", property->dwNameLen, property->dwNameLen);
		kprintf(L"      dwPropertyLen   : %08x - %u\n", property->dwPropertyLen, property->dwPropertyLen);
		kprintf(L"      pName           : "); kprintf(L"%.*s\n", property->dwNameLen / sizeof(wchar_t), property->pName);
		kprintf(L"      pProperty       : "); kull_m_string_wprintf_hex(property->pProperty, property->dwPropertyLen, 0); kprintf(L"\n\n");
	}
}

BOOL kull_m_key_cng_properties_create(PVOID data, DWORD size, PKULL_M_KEY_CNG_PROPERTY **properties, DWORD *count)
{
	BOOL status = FALSE;
	DWORD i, j;

	for(i = 0, *count = 0; i < size; i += ((PKULL_M_KEY_CNG_PROPERTY) ((PBYTE) data + i))->dwStructLen, (*count)++);
	
	if((*properties) = (PKULL_M_KEY_CNG_PROPERTY *) LocalAlloc(LPTR, *count * sizeof(PKULL_M_KEY_CNG_PROPERTY)))
	{
		for(i = 0, j = 0, status = TRUE; (i < (*count)) && status; i++)
		{
			if((*properties)[i] = kull_m_key_cng_property_create((PBYTE) data + j))
				j +=  (*properties)[i]->dwStructLen;
			else status = FALSE;
		}
	}
	if(!status)
	{
		kull_m_key_cng_properties_delete(*properties, *count);
		*properties = NULL;
		*count = 0;
	}
	return status;
}

void kull_m_key_cng_properties_delete(PKULL_M_KEY_CNG_PROPERTY *properties, DWORD count)
{
	DWORD i;
	if(properties)
	{
		for(i = 0; i < count; i++)
			kull_m_key_cng_property_delete(properties[i]);
		LocalFree(properties);
	}
}

void kull_m_key_cng_properties_descr(PKULL_M_KEY_CNG_PROPERTY *properties, DWORD count)
{
	DWORD i;
	if(count && properties)
	{
		kprintf(L"    %u field(s)\n", count);
		for(i = 0; i < count; i++)
			kull_m_key_cng_property_descr(properties[i]);
	}
}