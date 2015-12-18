/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi_creds.h"

NTSTATUS kuhl_m_dpapi_cred(int argc, wchar_t * argv[])
{
	PCWSTR infile;
	PVOID file, out;
	DWORD szFile, szOut;
	PKULL_M_CRED_BLOB cred;
	if(kull_m_string_args_byName(argc, argv, L"in", &infile, NULL))
	{
		if(kull_m_file_readData(infile, (PBYTE *) &file, &szFile))
		{
			kull_m_dpapi_blob_quick_descr(0, ((PKUHL_M_DPAPI_ENCRYPTED_CRED) file)->blob);
			if(kuhl_m_dpapi_unprotect_raw_or_blob(((PKUHL_M_DPAPI_ENCRYPTED_CRED) file)->blob, ((PKUHL_M_DPAPI_ENCRYPTED_CRED) file)->blobSize, NULL, argc, argv, NULL, 0, &out, &szOut, L"Decrypting Credential:\n"))
			{
				if(cred = kull_m_cred_create(out))
				{
					kull_m_cred_descr(0, cred);
					kull_m_cred_delete(cred);
				}
				LocalFree(out);
			}
			LocalFree(file);
		}
		else PRINT_ERROR_AUTO(L"kull_m_file_readData");
	}
	else PRINT_ERROR(L"Input CRED file needed (/in:file)\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_dpapi_vault(int argc, wchar_t * argv[])
{
	PCWSTR inFilePolicy, inFileCred;
	PVOID filePolicy, fileCred, out;
	DWORD szFilePolicy, szFileCred, szOut, len, i, mode = CRYPT_MODE_CBC;
	BYTE aes128[AES_128_KEY_SIZE], aes256[AES_256_KEY_SIZE];
	PKULL_M_CRED_VAULT_POLICY vaultPolicy;
	PKULL_M_CRED_VAULT_CREDENTIAL vaultCredential;
	PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE attribute;
	PKULL_M_CRED_VAULT_CLEAR clear;
	PVOID buffer;
	BOOL isAttr;
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	
	if(kull_m_string_args_byName(argc, argv, L"cred", &inFileCred, NULL))
	{
		if(kull_m_file_readData(inFileCred, (PBYTE *) &fileCred, &szFileCred))
		{
			if(vaultCredential = kull_m_cred_vault_credential_create(fileCred))
			{
				kull_m_cred_vault_credential_descr(0, vaultCredential);

				if(kull_m_string_args_byName(argc, argv, L"policy", &inFilePolicy, NULL))
				{
					if(kull_m_file_readData(inFilePolicy, (PBYTE *) &filePolicy, &szFilePolicy))
					{
						if(vaultPolicy = kull_m_cred_vault_policy_create(filePolicy))
						{
							kull_m_cred_vault_policy_descr(0, vaultPolicy);
							if(kuhl_m_dpapi_unprotect_raw_or_blob(vaultPolicy->key->KeyBlob, vaultPolicy->key->dwKeyBlob, NULL, argc, argv, NULL, 0, &out, &szOut, L"Decrypting Policy Keys:\n"))
							{
								if(kull_m_cred_vault_policy_key(out, szOut, aes128, aes256))
								{
									kprintf(L"  AES128 key: "); kull_m_string_wprintf_hex(aes128, AES_128_KEY_SIZE, 0); kprintf(L"\n");
									kprintf(L"  AES256 key: "); kull_m_string_wprintf_hex(aes256, AES_256_KEY_SIZE, 0); kprintf(L"\n\n");
									
									if(CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
									{
										for(i = 0; i < vaultCredential->__cbElements; i++)
										{
											if(attribute = vaultCredential->attributes[i])
											{
												kprintf(L"  > Attribute %u : ", attribute->id);
												if(attribute->data && (len = attribute->szData))
												{
													if(buffer = LocalAlloc(LPTR, len))
													{
														RtlCopyMemory(buffer, attribute->data, len);
														if(kuhl_m_dpapi_vault_key_type(attribute, hProv, aes128, aes256, &hKey, &isAttr))
														{
															if(CryptDecrypt(hKey, 0, TRUE, 0, (PBYTE) buffer, &len))
															{
																if(isAttr)
																{

																	kull_m_string_wprintf_hex(buffer, len, 0);
																}
																else
																{
																	kprintf(L"\n");
																	if(!attribute->id || (attribute->id == 100))
																	{
																		if(clear = kull_m_cred_vault_clear_create(buffer))
																		{
																			kull_m_cred_vault_clear_descr(1, clear);
																			kull_m_cred_vault_clear_delete(clear);
																		}
																	}
																	else kull_m_string_wprintf_hex(buffer, len, 1 | (16 << 16));
																	kprintf(L"\n");
																}
															}
															else PRINT_ERROR_AUTO(L"CryptDecrypt");
														}
														LocalFree(buffer);
													}
												}
												kprintf(L"\n");
											}
										}
										CryptReleaseContext(hProv, 0);
									}
								}
								LocalFree(out);
							}
							kull_m_cred_vault_policy_delete(vaultPolicy);
						}
						LocalFree(filePolicy);
					}
					else PRINT_ERROR_AUTO(L"kull_m_file_readData (policy)");
				}
				kull_m_cred_vault_credential_delete(vaultCredential);
			}
			LocalFree(fileCred);
		}
		else PRINT_ERROR_AUTO(L"kull_m_file_readData (cred)");
	}
	else PRINT_ERROR(L"Input Cred file needed (/cred:file)\n");
				
	return STATUS_SUCCESS;
}

BOOL kuhl_m_dpapi_vault_key_type(PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE attribute, HCRYPTPROV hProv, BYTE aes128[AES_128_KEY_SIZE], BYTE aes256[AES_256_KEY_SIZE], HCRYPTKEY *hKey, BOOL *isAttr)
{
	BOOL status = FALSE;
	DWORD mode = CRYPT_MODE_CBC, calgId, keyLen;
	LPCVOID key;

	*isAttr = attribute->id && (attribute->id < 100);
	if(*isAttr)
	{
		calgId = CALG_AES_128;
		key = aes128;
		keyLen = AES_128_KEY_SIZE;
		
	}
	else
	{
		calgId = CALG_AES_256;
		key = aes256;
		keyLen = AES_256_KEY_SIZE;
	}

	if(status = kull_m_crypto_hkey(hProv, calgId, key, keyLen, 0, hKey, NULL))
	{
		CryptSetKeyParam(*hKey, KP_MODE, (LPCBYTE) &mode, 0);
		if(attribute->szIV && attribute->IV)
			CryptSetKeyParam(*hKey, KP_IV, attribute->IV, 0);
	}
	return status;
}