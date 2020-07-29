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
	DWORD szFile, outLen, szBlob, dwProviderType;
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
					if(kull_m_key_capi_decryptedkey_to_raw(capiKey->pSiPublicKey,capiKey->dwSiPublicKeyLen, out, outLen, CALG_RSA_SIGN, &blob, &szBlob, &dwProviderType))
					{
						if(name = kull_m_string_qad_ansi_to_unicode(capiKey->pName))
						{
							kuhl_m_crypto_exportRawKeyToFile(blob, szBlob, FALSE, AT_SIGNATURE, dwProviderType, L"dpapi_signature", 0, name, TRUE, TRUE);
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
					if(kull_m_key_capi_decryptedkey_to_raw(capiKey->pExPublicKey, capiKey->dwExPublicKeyLen, out, outLen, CALG_RSA_KEYX, &blob, &szBlob, &dwProviderType))
					{
						if(name = kull_m_string_qad_ansi_to_unicode(capiKey->pName))
						{
							kuhl_m_crypto_exportRawKeyToFile(blob, szBlob, FALSE, AT_KEYEXCHANGE, dwProviderType, L"dpapi_exchange", 0, name, TRUE, TRUE);
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
						kuhl_m_sekurlsa_genericLsaIsoOutput((PLSAISO_DATA_BLOB) ((PBYTE) out + sizeof(DWORD)), NULL, NULL);
						kprintf(L"\n");
					}
					else
					{
						kull_m_string_wprintf_hex(out, outLen, 0);kprintf(L"\n");
						if(name = (PWSTR) LocalAlloc(LPTR, cngKey->dwNameLen + sizeof(wchar_t)))
						{
							RtlCopyMemory(name, cngKey->pName, cngKey->dwNameLen);
							kuhl_m_crypto_exportRawKeyToFile(out, outLen, TRUE, CERT_NCRYPT_KEY_SPEC, 0, L"dpapi", 0, name, TRUE, TRUE);
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

NTSTATUS kuhl_m_dpapi_keys_tpm(int argc, wchar_t * argv[])
{
	PBYTE file;
	PVOID out;
	DWORD szFile, dwOut;
	LPCWSTR infile;
	PKUHL_M_DPAPI_KEYS_TPM_TLV cur;

	if(kull_m_string_args_byName(argc, argv, L"in", &infile, NULL))
	{
		if(kull_m_file_readData(infile, &file, &szFile))
		{
			if(szFile > (2 * sizeof(DWORD)))
			{
				if((*(PDWORD) file == 'PSKP') && (*(PDWORD) (file + szFile - sizeof(DWORD)) == 'PSKP'))
				{
					for(cur = (PKUHL_M_DPAPI_KEYS_TPM_TLV) (file + sizeof(DWORD)); cur->Tag != 'PSKP' ; cur =  (PKUHL_M_DPAPI_KEYS_TPM_TLV) ((PBYTE) cur + FIELD_OFFSET(KUHL_M_DPAPI_KEYS_TPM_TLV, Data) + cur->Length))
					{
						kprintf(L"[%08x] ", cur->Tag);
						switch(cur->Tag)
						{
						case 0x01000003:
							kprintf(L"DPAPI encrypted blob\n");
							if(kuhl_m_dpapi_unprotect_raw_or_blob(cur->Data, cur->Length, NULL, argc, argv, NULL, 0, &out, &dwOut, L"Decrypting key data:\n"))
							{
								kuhl_m_dpapi_keys_tpm_descr(out, dwOut);
								LocalFree(out);
							}
							break;
						case 0x02000000:
							kprintf(L"Unique container name\n  %.*s\n", cur->Length / sizeof(wchar_t), cur->Data);
							break;
						case 0x02000004:
							kprintf(L"Key type\n  %.*s\n", cur->Length / sizeof(wchar_t), cur->Data);
							break;
						default:
							kprintf(L"Unknown\n  ");
							kull_m_string_wprintf_hex(cur->Data, cur->Length, 0);
							kprintf(L"\n");
						}
					}
				}
				else PRINT_ERROR(L"Bad headers\n");
			}
			else PRINT_ERROR(L"Bad size\n");
			LocalFree(file);
		}
		else PRINT_ERROR_AUTO(L"kull_m_file_readData");
	}
	else PRINT_ERROR(L"Input TPM PCP key file needed (/in:file)\n");
	return STATUS_SUCCESS;
}

void kuhl_m_dpapi_keys_tpm_descr(LPCVOID data, DWORD dwData)
{
	PPCP_20_KEY_BLOB pBlob = (PPCP_20_KEY_BLOB) data;
	PBYTE ptr;
	BOOL bIsWin8;

	if(pBlob->magic == BCRYPT_PCP_KEY_MAGIC)
	{
		ptr = (PBYTE) pBlob + pBlob->cbHeader;
		switch(pBlob->cbHeader)
		{
		case sizeof(PCP_KEY_BLOB):
			kprintf(L"** PCP Key Blob (classic) **\n");
			kprintf(L"  pcpType         : 0x%08x\n", pBlob->pcpType);
			kprintf(L"  flags           : 0x%08x\n", pBlob->flags);
			kprintf(L"  TpmKey          : ");	// ~TPM_KEY12
			kull_m_string_wprintf_hex(ptr, pBlob->cbPublic, 0); // cbTpmKey in real structure
			kprintf(L"\n");
			break;
		case sizeof(PCP_KEY_BLOB_WIN8):
		case sizeof(PCP_20_KEY_BLOB):
			bIsWin8 = (pBlob->cbHeader == sizeof(PCP_KEY_BLOB_WIN8));
			kprintf(L"** PCP Key Blob (Windows %s8) **\n", bIsWin8 ? L"" : L">");
			kprintf(L"  pcpType         : 0x%08x\n", pBlob->pcpType);
			kprintf(L"  flags           : 0x%08x\n", pBlob->flags);
			kprintf(L"  Public          : ");	// ~TPM2B_PUBLIC
			kull_m_string_wprintf_hex(ptr, pBlob->cbPublic, 0);
			ptr += pBlob->cbPublic;
			kprintf(L"\n  Private         : "); // and so on...
			kull_m_string_wprintf_hex(ptr, pBlob->cbPrivate, 0);
			ptr += pBlob->cbPrivate;
			kprintf(L"\n  MigrationPublic : ");
			kull_m_string_wprintf_hex(ptr, pBlob->cbMigrationPublic, 0);
			ptr += pBlob->cbMigrationPublic;
			kprintf(L"\n  MigrationPrivate: ");
			kull_m_string_wprintf_hex(ptr, pBlob->cbMigrationPrivate, 0);
			ptr += pBlob->cbMigrationPrivate;
			kprintf(L"\n  PolicyDigestList: ");
			kull_m_string_wprintf_hex(ptr, pBlob->cbPolicyDigestList, 0);
			ptr += pBlob->cbPolicyDigestList;
			kprintf(L"\n  PCRBinding      : ");
			kull_m_string_wprintf_hex(ptr, pBlob->cbPCRBinding, 0);
			ptr += pBlob->cbPCRBinding;
			kprintf(L"\n  PCRDigest       : ");
			kull_m_string_wprintf_hex(ptr, pBlob->cbPCRDigest, 0);
			ptr += pBlob->cbPCRDigest;
			kprintf(L"\n  EncryptedSecret : ");
			kull_m_string_wprintf_hex(ptr, pBlob->cbEncryptedSecret, 0);
			ptr += pBlob->cbEncryptedSecret;
			kprintf(L"\n  Tpm12HostageBlob: ");
			kull_m_string_wprintf_hex(ptr, pBlob->cbTpm12HostageBlob, 0);
			if(!bIsWin8)
				kprintf(L"\n  pcrAlgId        : 0x%04x\n", pBlob->pcrAlgId);
			break;
		default:
			PRINT_ERROR(L"Size of header is unknown");
		}
	}
	else PRINT_ERROR(L"No header magic (0x%08x)\n", pBlob->magic);
}