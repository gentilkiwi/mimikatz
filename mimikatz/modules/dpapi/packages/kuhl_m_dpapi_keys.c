/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_dpapi_keys.h"

NTSTATUS kuhl_m_dpapi_keys_test(int argc, wchar_t * argv[])
{
	PBYTE file;
	DWORD szFile;
	DATA_BLOB in, out, entropy = {sizeof(KIWI_DPAPI_ENTROPY_CNG_KEY_PROPERTIES), (BYTE *) KIWI_DPAPI_ENTROPY_CNG_KEY_PROPERTIES};
	//PKULL_M_DPAPI_BLOB pk
	PKULL_M_KEY_CNG_BLOB cngKey;
	PKULL_M_KEY_CNG_PROPERTY * properties;
	DWORD cbProperties;

	if(argc && kull_m_file_readData(argv[0]/*L"237b2eeb360f919e498fd3cb9a9405fd_2ca41167-ee31-4707-96db-e909bb1f39a2"*/, &file, &szFile))
	{
		if(cngKey = kull_m_key_cng_create(file))
		{
			kull_m_key_cng_descr(cngKey);
			/*if(pk = kull_m_dpapi_blob_create(cngKey->pPrivateProperties))
			{
				kull_m_dpapi_blob_descr(pk);
				kull_m_dpapi_blob_delete(pk);
			}*/
			kprintf(L"Decrypting Private Properties:\n");
			in.cbData = cngKey->dwPrivatePropertiesLen;
			in.pbData = (PBYTE) cngKey->pPrivateProperties;
			entropy.cbData = sizeof(KIWI_DPAPI_ENTROPY_CNG_KEY_PROPERTIES);
			entropy.pbData = (BYTE *) KIWI_DPAPI_ENTROPY_CNG_KEY_PROPERTIES;
			if(CryptUnprotectData(&in, NULL, &entropy, NULL, NULL, 0, &out))
			{
				if(kull_m_key_cng_properties_create(out.pbData, out.cbData, &properties, &cbProperties))
				{
					kull_m_key_cng_properties_descr(properties, cbProperties);
					kull_m_key_cng_properties_delete(properties, cbProperties);
				}
				LocalFree(out.pbData);
			}
			else PRINT_ERROR_AUTO(L"CryptUnprotectData");

			kprintf(L"Decrypting Private Key: ");
			in.cbData = cngKey->dwPrivateKeyLen;
			in.pbData = (PBYTE) cngKey->pPrivateKey;
			entropy.cbData = sizeof(KIWI_DPAPI_ENTROPY_CNG_KEY_BLOB);
			entropy.pbData = (BYTE *) KIWI_DPAPI_ENTROPY_CNG_KEY_BLOB;
			if(CryptUnprotectData(&in, NULL, &entropy, NULL, NULL, 0, &out))
			{
				kull_m_string_wprintf_hex(out.pbData, out.cbData, 0);kprintf(L"\n");
				LocalFree(out.pbData);
			}
			else PRINT_ERROR_AUTO(L"CryptUnprotectData");

			kull_m_key_cng_delete(cngKey);
		}
		LocalFree(file);
	}

	return STATUS_SUCCESS;
}