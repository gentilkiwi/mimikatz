/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_dpapi_keys.h"
#include "../../kuhl_m_crypto.h"
NTSTATUS kuhl_m_dpapi_keys_capi(int argc, wchar_t * argv[])
{
	PBYTE file;
	DWORD szFile;
	DATA_BLOB in, out, entropy;
	PKULL_M_KEY_CAPI_BLOB capiKey;

	PRSA_GENERICKEY_BLOB blob;
	DWORD szBlob;
	PWSTR name;

	if(argc && kull_m_file_readData(argv[0], &file, &szFile))
	{
		if(capiKey = kull_m_key_capi_create(file))
		{
			kull_m_key_capi_descr(0, capiKey);

			kprintf(L"Decrypting Export flags:\n");
			in.cbData = capiKey->dwExportFlagLen;
			in.pbData = (PBYTE) capiKey->pExportFlag;
			entropy.cbData = sizeof(KIWI_DPAPI_ENTROPY_CAPI_KEY_EXPORTFLAGS);
			entropy.pbData = (BYTE *) KIWI_DPAPI_ENTROPY_CAPI_KEY_EXPORTFLAGS;
			if(CryptUnprotectData(&in, NULL, &entropy, NULL, NULL, 0, &out))
			{
				kull_m_string_wprintf_hex(out.pbData, out.cbData, 0);kprintf(L"\n");
				LocalFree(out.pbData);
			}
			else PRINT_ERROR_AUTO(L"CryptUnprotectData");

			kprintf(L"Decrypting Private Key:\n");
			in.cbData = capiKey->dwPrivateKeyLen;
			in.pbData = (PBYTE) capiKey->pPrivateKey;
			
			if(CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out))
			{
				kull_m_string_wprintf_hex(out.pbData, out.cbData, 0);kprintf(L"\n");
				if(kull_m_key_capi_decryptedkey_to_raw(out.pbData, out.cbData, &blob, &szBlob))
				{
					if(name = kull_m_string_qad_ansi_to_unicode(capiKey->pName))
					{
						kuhl_m_crypto_exportRawKeyToFile(blob, szBlob, FALSE, L"raw", 0, name, TRUE, TRUE);
						LocalFree(name);
					}
					LocalFree(blob);
				}
				LocalFree(out.pbData);
			}
			else PRINT_ERROR_AUTO(L"CryptUnprotectData");
			
			kull_m_key_capi_delete(capiKey);
		}
		LocalFree(file);
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_dpapi_keys_cng(int argc, wchar_t * argv[])
{
	PBYTE file;
	DWORD szFile;
	DATA_BLOB in, out, entropy;
	PKULL_M_KEY_CNG_BLOB cngKey;
	PKULL_M_KEY_CNG_PROPERTY * properties;
	DWORD cbProperties;
	PWSTR name;

	if(argc && kull_m_file_readData(argv[0], &file, &szFile))
	{
		if(cngKey = kull_m_key_cng_create(file))
		{
			kull_m_key_cng_descr(0, cngKey);

			kprintf(L"Decrypting Private Properties:\n");
			in.cbData = cngKey->dwPrivatePropertiesLen;
			in.pbData = (PBYTE) cngKey->pPrivateProperties;
			entropy.cbData = sizeof(KIWI_DPAPI_ENTROPY_CNG_KEY_PROPERTIES);
			entropy.pbData = (BYTE *) KIWI_DPAPI_ENTROPY_CNG_KEY_PROPERTIES;
			if(CryptUnprotectData(&in, NULL, &entropy, NULL, NULL, 0, &out))
			{
				if(kull_m_key_cng_properties_create(out.pbData, out.cbData, &properties, &cbProperties))
				{
					kull_m_key_cng_properties_descr(0, properties, cbProperties);
					kull_m_key_cng_properties_delete(properties, cbProperties);
				}
				LocalFree(out.pbData);
			}
			else PRINT_ERROR_AUTO(L"CryptUnprotectData");

			kprintf(L"Decrypting Private Key:\n");
			in.cbData = cngKey->dwPrivateKeyLen;
			in.pbData = (PBYTE) cngKey->pPrivateKey;
			entropy.cbData = sizeof(KIWI_DPAPI_ENTROPY_CNG_KEY_BLOB);
			entropy.pbData = (BYTE *) KIWI_DPAPI_ENTROPY_CNG_KEY_BLOB;
			if(CryptUnprotectData(&in, NULL, &entropy, NULL, NULL, 0, &out))
			{
				kull_m_string_wprintf_hex(out.pbData, out.cbData, 0);kprintf(L"\n");
				if(name = (PWSTR) LocalAlloc(LPTR, cngKey->dwNameLen + sizeof(wchar_t)))
				{
					RtlCopyMemory(name, cngKey->pName, cngKey->dwNameLen);
					kuhl_m_crypto_exportRawKeyToFile(out.pbData, out.cbData, TRUE, L"raw", 0, name, TRUE, TRUE);
					LocalFree(name);
				}
				LocalFree(out.pbData);
			}
			else PRINT_ERROR_AUTO(L"CryptUnprotectData");

			kull_m_key_cng_delete(cngKey);
		}
		LocalFree(file);
	}
	return STATUS_SUCCESS;
}