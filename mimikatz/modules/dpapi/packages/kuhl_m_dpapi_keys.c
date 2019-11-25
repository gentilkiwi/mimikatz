/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi_keys.h"

NTSTATUS kuhl_m_dpapi_keys_capi(int argc, wchar_t * argv[])
{
	PVOID file, out;
	PRSA_GENERICKEY_BLOB blob;
	DWORD szFile, outLen, szBlob;
	PKULL_M_KEY_CAPI_BLOB capiKey;
	LPCWSTR infile;
	PWSTR name;

	if(kull_m_string_args_byName(argc, argv, L"in", &infile, NULL))
	{
		if(kull_m_file_readData(infile, (PBYTE *) &file, &szFile))
		{
			if(capiKey = kull_m_key_capi_create(file))
			{
				kull_m_key_capi_descr(0, capiKey);

				if(kuhl_m_dpapi_unprotect_raw_or_blob(capiKey->pSiExportFlag, capiKey->dwSiExportFlagLen, NULL, argc, argv, KIWI_DPAPI_ENTROPY_CAPI_KEY_EXPORTFLAGS, sizeof(KIWI_DPAPI_ENTROPY_CAPI_KEY_EXPORTFLAGS), &out, &outLen, L"Decrypting AT_SIGNATURE Export flags:\n"))
				{
					kull_m_string_wprintf_hex(out, outLen, 0); kprintf(L"\n");
					LocalFree(out);
				}
				if(kuhl_m_dpapi_unprotect_raw_or_blob(capiKey->pSiPrivateKey, capiKey->dwSiPrivateKeyLen, NULL, argc, argv, NULL, 0, &out, &outLen, L"Decrypting AT_SIGNATURE Private Key:\n"))
				{
					kull_m_string_wprintf_hex(out, outLen, 0); kprintf(L"\n");
					if(kull_m_key_capi_decryptedkey_to_raw(out, outLen, &blob, &szBlob))
					{
						if(name = kull_m_string_qad_ansi_to_unicode(capiKey->pName))
						{
							kuhl_m_crypto_exportRawKeyToFile(blob, szBlob, FALSE, L"raw_signature", 0, name, TRUE, TRUE);
							LocalFree(name);
						}
						LocalFree(blob);
					}
					LocalFree(out);
				}

				if(kuhl_m_dpapi_unprotect_raw_or_blob(capiKey->pExExportFlag, capiKey->dwExExportFlagLen, NULL, argc, argv, KIWI_DPAPI_ENTROPY_CAPI_KEY_EXPORTFLAGS, sizeof(KIWI_DPAPI_ENTROPY_CAPI_KEY_EXPORTFLAGS), &out, &outLen, L"Decrypting AT_EXCHANGE Export flags:\n"))
				{
					kull_m_string_wprintf_hex(out, outLen, 0); kprintf(L"\n");
					LocalFree(out);
				}
				if(kuhl_m_dpapi_unprotect_raw_or_blob(capiKey->pExPrivateKey, capiKey->dwExPrivateKeyLen, NULL, argc, argv, NULL, 0, &out, &outLen, L"Decrypting AT_EXCHANGE Private Key:\n"))
				{
					kull_m_string_wprintf_hex(out, outLen, 0); kprintf(L"\n");
					if(kull_m_key_capi_decryptedkey_to_raw(out, outLen, &blob, &szBlob))
					{
						if(name = kull_m_string_qad_ansi_to_unicode(capiKey->pName))
						{
							kuhl_m_crypto_exportRawKeyToFile(blob, szBlob, FALSE, L"raw_exchange", 0, name, TRUE, TRUE);
							LocalFree(name);
						}
						LocalFree(blob);
					}
					LocalFree(out);
				}

				kull_m_key_capi_delete(capiKey);
			}
			LocalFree(file);
		}
		else PRINT_ERROR_AUTO(L"kull_m_file_readData");
	}
	else PRINT_ERROR(L"Input CAPI private key file needed (/in:file)\n");

	return STATUS_SUCCESS;
}

BOOL kuhl_m_dpapi_keys_cng_isIso(PKULL_M_KEY_CNG_PROPERTY * properties, DWORD cbProperties)
{
	DWORD i;
	BOOL result = FALSE;
	for(i = 0; i < cbProperties; i++)
	{
		if((properties[i]->dwNameLen >= 22) && RtlEqualMemory(NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY, properties[i]->pName, 22) && (properties[i]->dwPropertyLen == sizeof(BOOL)))
		{
			result = *(PBOOL) properties[i]->pProperty;
			break;
		}
	}
	return result;
}

NTSTATUS kuhl_m_dpapi_keys_cng(int argc, wchar_t * argv[])
{
	PBYTE file;
	PVOID out;
	DWORD szFile, outLen, cbProperties;
	PKULL_M_KEY_CNG_BLOB cngKey;
	PKULL_M_KEY_CNG_PROPERTY * properties;
	LPCWSTR infile;
	PWSTR name;
	BOOL isIso = FALSE;

	if(kull_m_string_args_byName(argc, argv, L"in", &infile, NULL))
	{
		if(kull_m_file_readData(infile, (PBYTE *) &file, &szFile))
		{
			if(cngKey = kull_m_key_cng_create(file))
			{
				kull_m_key_cng_descr(0, cngKey);

				if(kuhl_m_dpapi_unprotect_raw_or_blob(cngKey->pPrivateProperties, cngKey->dwPrivatePropertiesLen, NULL, argc, argv, KIWI_DPAPI_ENTROPY_CNG_KEY_PROPERTIES, sizeof(KIWI_DPAPI_ENTROPY_CNG_KEY_PROPERTIES), &out, &outLen, L"Decrypting Private Properties:\n"))
				{
					if(kull_m_key_cng_properties_create(out, outLen, &properties, &cbProperties))
					{
						kull_m_key_cng_properties_descr(0, properties, cbProperties);
						isIso = kuhl_m_dpapi_keys_cng_isIso(properties, cbProperties);
						kull_m_key_cng_properties_delete(properties, cbProperties);
					}
					LocalFree(out);
				}

				if(kuhl_m_dpapi_unprotect_raw_or_blob(cngKey->pPrivateKey, cngKey->dwPrivateKeyLen, NULL, argc, argv, KIWI_DPAPI_ENTROPY_CNG_KEY_BLOB, sizeof(KIWI_DPAPI_ENTROPY_CNG_KEY_BLOB), &out, &outLen, L"Decrypting Private Key:\n"))
				{
					if(isIso)
					{
						kuhl_m_sekurlsa_genericLsaIsoOutput((PLSAISO_DATA_BLOB) ((PBYTE) out + sizeof(DWORD)));
						kprintf(L"\n");
					}
					else
					{
						kull_m_string_wprintf_hex(out, outLen, 0);kprintf(L"\n");
						if(name = (PWSTR) LocalAlloc(LPTR, cngKey->dwNameLen + sizeof(wchar_t)))
						{
							RtlCopyMemory(name, cngKey->pName, cngKey->dwNameLen);
							kuhl_m_crypto_exportRawKeyToFile(out, outLen, TRUE, L"raw", 0, name, TRUE, TRUE);
							LocalFree(name);
						}
					}
					LocalFree(out);
				}

				kull_m_key_cng_delete(cngKey);
			}
			LocalFree(file);
		}
		else PRINT_ERROR_AUTO(L"kull_m_file_readData");
	}
	else PRINT_ERROR(L"Input CNG private key file needed (/in:file)\n");

	return STATUS_SUCCESS;
}