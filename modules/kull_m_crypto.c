/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_crypto.h"

BOOL kull_m_crypto_hash(ALG_ID algid, LPCVOID data, DWORD dataLen, LPVOID hash, DWORD hashWanted)
{
	BOOL status = FALSE;
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	DWORD hashLen;
	PBYTE buffer;

	if(CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if(CryptCreateHash(hProv, algid, 0, 0, &hHash))
		{
			if(CryptHashData(hHash, (LPCBYTE) data, dataLen, 0))
			{
				if(CryptGetHashParam(hHash, HP_HASHVAL, NULL, &hashLen, 0))
				{
					if(buffer = (PBYTE) LocalAlloc(LPTR, hashLen))
					{
						status = CryptGetHashParam(hHash, HP_HASHVAL, buffer, &hashLen, 0);
						RtlCopyMemory(hash, buffer, KIWI_MINIMUM(hashLen, hashWanted));
						LocalFree(buffer);
					}
				}
			}
			CryptDestroyHash(hHash);
		}
		CryptReleaseContext(hProv, 0);
	}
	return status;
}

BOOL kull_m_crypto_hkey(HCRYPTPROV hProv, DWORD calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hKey, HCRYPTPROV *hSessionProv)
{
	BOOL status = FALSE;
	PGENERICKEY_BLOB keyBlob;
	DWORD szBlob = sizeof(GENERICKEY_BLOB) + keyLen;
	
	if(calgid != CALG_3DES)
	{
		if(keyBlob = (PGENERICKEY_BLOB) LocalAlloc(LPTR, szBlob))
		{
			keyBlob->Header.bType = PLAINTEXTKEYBLOB;
			keyBlob->Header.bVersion = CUR_BLOB_VERSION;
			keyBlob->Header.reserved = 0;
			keyBlob->Header.aiKeyAlg = calgid;
			keyBlob->dwKeyLen = keyLen;
			RtlCopyMemory((PBYTE) keyBlob + sizeof(GENERICKEY_BLOB), key, keyBlob->dwKeyLen);
			status = CryptImportKey(hProv, (LPCBYTE) keyBlob, szBlob, 0, flags, hKey);
			LocalFree(keyBlob);
		}
	}
	else if(hSessionProv)
		status = kull_m_crypto_hkey_session(calgid, key, keyLen, flags, hKey, hSessionProv);
	
	return status;
}

BOOL kull_m_crypto_DeriveKeyRaw(ALG_ID hashId, LPVOID hash, DWORD hashLen, LPVOID key, DWORD keyLen)
{
	BOOL status = FALSE;
	BYTE buffer[152], ipad[64], opad[64];
	DWORD i;
	
	if(status = (hashLen >= keyLen))
		RtlCopyMemory(key, hash, keyLen);
	else
	{
		RtlFillMemory(ipad, sizeof(ipad), '6');
		RtlFillMemory(opad, sizeof(opad), '\\');
		for(i = 0; i < hashLen; i++)
		{
			ipad[i] ^= ((PBYTE) hash)[i];
			opad[i] ^= ((PBYTE) hash)[i];
		}
		if(kull_m_crypto_hash(hashId, ipad, sizeof(ipad), buffer, hashLen))
			if(status = kull_m_crypto_hash(hashId, opad, sizeof(opad), buffer + hashLen, hashLen))
				RtlCopyMemory(key, buffer, KIWI_MINIMUM(keyLen, 2 * hashLen));
	}
	return status;
}

BOOL kull_m_crypto_close_hprov_delete_container(HCRYPTPROV hProv)
{
	BOOL status = FALSE;
	DWORD provtype, szLen = 0;
	PSTR container, provider;
	if(CryptGetProvParam(hProv, PP_CONTAINER, NULL, &szLen, 0))
	{
		if(container = (PSTR) LocalAlloc(LPTR, szLen))
		{
			if(CryptGetProvParam(hProv, PP_CONTAINER, (LPBYTE) container, &szLen, 0))
			{
				if(CryptGetProvParam(hProv, PP_NAME, NULL, &szLen, 0))
				{
					if(provider = (PSTR) LocalAlloc(LPTR, szLen))
					{
						if(CryptGetProvParam(hProv, PP_NAME, (LPBYTE) provider, &szLen, 0))
						{
							szLen = sizeof(DWORD);
							if(CryptGetProvParam(hProv, PP_PROVTYPE, (LPBYTE) &provtype, &szLen, 0))
							{
								CryptReleaseContext(hProv, 0);
								status = CryptAcquireContextA(&hProv, container, provider, provtype, CRYPT_DELETEKEYSET);
							}
						}
						LocalFree(provider);
					}
				}
				LocalFree(container);
			}
		}
	}
	return status;
}

BOOL kull_m_crypto_hmac(DWORD calgid, LPCVOID key, DWORD keyLen, LPCVOID message, DWORD messageLen, LPVOID hash, DWORD hashWanted) // for keyLen > 1
{
	BOOL status = FALSE;
	DWORD hashLen;
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	HCRYPTHASH hHash;
	HMAC_INFO HmacInfo = {calgid, NULL, 0, NULL, 0};
	PBYTE buffer;

	if(CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if(kull_m_crypto_hkey(hProv, CALG_RC2, key, keyLen, CRYPT_IPSEC_HMAC_KEY, &hKey, NULL))
		{
			if(CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHash))
			{
				if(CryptSetHashParam(hHash, HP_HMAC_INFO, (LPCBYTE) &HmacInfo, 0))
					if(CryptHashData(hHash, (LPCBYTE) message, messageLen, 0))
						if(CryptGetHashParam(hHash, HP_HASHVAL, NULL, &hashLen, 0))
						{
							if(buffer = (PBYTE) LocalAlloc(LPTR, hashLen))
							{
								status = CryptGetHashParam(hHash, HP_HASHVAL, buffer, &hashLen, 0);
								RtlCopyMemory(hash, buffer, KIWI_MINIMUM(hashLen, hashWanted));
								LocalFree(buffer);
							}
						}
						CryptDestroyHash(hHash);
			}
			CryptDestroyKey(hKey);
		}
		CryptReleaseContext(hProv, 0);
	}
	return status;
}

BOOL kull_m_crypto_pkcs5_pbkdf2_hmac(DWORD calgid, LPCVOID password, DWORD passwordLen, LPCVOID salt, DWORD saltLen, DWORD iterations, BYTE *key, DWORD keyLen, BOOL isDpapiInternal)
{
	BOOL status = FALSE;
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	DWORD sizeHmac, count, i, j, r;
	PBYTE asalt, obuf, d1;

	if(CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if(CryptCreateHash(hProv, calgid, 0, 0, &hHash))
		{
			if(CryptGetHashParam(hHash, HP_HASHVAL, NULL, &sizeHmac, 0))
			{
				if(asalt = (PBYTE) LocalAlloc(LPTR, saltLen + sizeof(DWORD)))
				{
					if(obuf = (PBYTE) LocalAlloc(LPTR, sizeHmac))
					{
						if(d1 = (PBYTE) LocalAlloc(LPTR, sizeHmac))
						{
							status = TRUE;
							RtlCopyMemory(asalt, salt, saltLen);
							for (count = 1; keyLen > 0; count++)
							{
								*(PDWORD) (asalt + saltLen) = _byteswap_ulong(count);
								kull_m_crypto_hmac(calgid, password, passwordLen, asalt, saltLen + 4, d1, sizeHmac);
								RtlCopyMemory(obuf, d1, sizeHmac);
								for (i = 1; i < iterations; i++)
								{
									kull_m_crypto_hmac(calgid, password, passwordLen, d1, sizeHmac, d1, sizeHmac);
									for (j = 0; j < sizeHmac; j++)
										obuf[j] ^= d1[j];
									if(isDpapiInternal) // thank you MS!
										RtlCopyMemory(d1, obuf, sizeHmac);
								}
								r = KIWI_MINIMUM(keyLen, sizeHmac);
								RtlCopyMemory(key, obuf, r);
								key += r;
								keyLen -= r;
							}
							LocalFree(d1);
						}
						LocalFree(obuf);
					}
					LocalFree(asalt);
				}
			}
			CryptDestroyHash(hHash);
		}
		CryptReleaseContext(hProv, 0);
	}
	return status;
}

BOOL kull_m_crypto_aesBlockEncryptDecrypt(HCRYPTKEY hKey, PBYTE data, DWORD nbBlock, BOOL encrypt)
{
	nbBlock *= 16;
	return (encrypt ? CryptEncrypt(hKey, 0, FALSE, 0, data, &nbBlock, nbBlock) : CryptDecrypt(hKey, 0, FALSE, 0, data, &nbBlock));
}

BOOL kull_m_crypto_aesCTSDecrypt(HCRYPTKEY hKey, PBYTE data, DWORD szData, PBYTE pbIV)
{
	BOOL status = FALSE;
	DWORD nbBlock, lastLen, i;
	BYTE buffer[32], *ptr;
	HCRYPTKEY hKeyNoIV;

	if(szData > 16)
	{
		if(CryptDuplicateKey(hKey, NULL, 0, &hKeyNoIV))
		{
			if(CryptSetKeyParam(hKey, KP_IV, pbIV, 0))
			{
				nbBlock = (szData + 15) >> 4;
				lastLen = (szData & 0xf) ? (szData & 0xf) : 16;
				if (nbBlock <= 2 || kull_m_crypto_aesBlockEncryptDecrypt(hKey, data, nbBlock - 2, FALSE))
				{
					ptr = &data[16 * (nbBlock - 2)];
					RtlCopyMemory(buffer, ptr, lastLen + 16);
					RtlZeroMemory(&buffer[lastLen + 16], 16 - lastLen);
					if(kull_m_crypto_aesBlockEncryptDecrypt(hKeyNoIV, buffer, 1, FALSE))
					{
						for(i = 0; i < 16; i++)
							buffer[i] ^= buffer[i + 16];
						RtlCopyMemory(&buffer[lastLen + 16], &buffer[lastLen], 16 - lastLen);
						if(status = kull_m_crypto_aesBlockEncryptDecrypt(hKey, buffer + 16, 1, FALSE))
						{
							RtlCopyMemory(ptr, buffer + 16, 16);
							RtlCopyMemory(&data[16 * nbBlock - 16], buffer, lastLen);
						}
					}
				}
			}
			CryptDestroyKey(hKeyNoIV);
		}
	}
	else if(szData == 16)
		status = kull_m_crypto_aesBlockEncryptDecrypt(hKey, data, 1, FALSE);

	return status;
}

BOOL kull_m_crypto_aesCTSEncrypt(HCRYPTKEY hKey, PBYTE data, DWORD szData, PBYTE pbIV)
{
	BOOL status = FALSE;
	DWORD nbBlock, lastLen;
	BYTE buffer[32], *ptr;
	
	if(szData > 16)
	{
		if(CryptSetKeyParam(hKey, KP_IV, pbIV, 0))
		{
			nbBlock = (szData + 15) >> 4;
			lastLen = (szData & 0xf) ? (szData & 0xf) : 16;
			if (nbBlock <= 2 || kull_m_crypto_aesBlockEncryptDecrypt(hKey, data, nbBlock - 2, TRUE))
			{
				ptr = &data[16 * (nbBlock - 2)];
				RtlCopyMemory(buffer, ptr, lastLen + 16);
				RtlZeroMemory(&buffer[lastLen + 16], 16 - lastLen);
				if(status = kull_m_crypto_aesBlockEncryptDecrypt(hKey, buffer, 2, TRUE))
				{
					RtlCopyMemory(ptr, buffer + 16, 16);
					RtlCopyMemory(&data[16 * nbBlock - 16], buffer, lastLen);
				}
			}
		}
	}
	else if(szData == 16)
		status = kull_m_crypto_aesBlockEncryptDecrypt(hKey, data, 1, TRUE);
	
	return status;
}

BOOL kull_m_crypto_aesCTSEncryptDecrypt(DWORD aesCalgId, PVOID data, DWORD szData, PVOID key, DWORD szKey, PVOID pbIV, BOOL encrypt)
{
	BOOL status = FALSE;
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	DWORD mode = CRYPT_MODE_CBC;

	if(CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if(kull_m_crypto_hkey(hProv, aesCalgId, key, szKey, 0, &hKey, NULL))
		{
			if(CryptSetKeyParam(hKey, KP_MODE, (LPCBYTE) &mode, 0))
				status = (encrypt ? kull_m_crypto_aesCTSEncrypt(hKey, (PBYTE) data, szData, (PBYTE) pbIV) : kull_m_crypto_aesCTSDecrypt(hKey, (PBYTE) data, szData, (PBYTE) pbIV));
			CryptDestroyKey(hKey);
		}
		CryptReleaseContext(hProv, 0);
	}
	return status;
}

BOOL kull_m_crypto_hkey_session(ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hSessionKey, HCRYPTPROV *hSessionProv)
{
	BOOL status = FALSE;
	PBYTE keyblob, pbSessionBlob, ptr;
	DWORD dwkeyblob, dwLen, i;
	PWSTR container;
	HCRYPTKEY hPrivateKey;

	if(container = kull_m_string_getRandomGUID())
	{
		if(CryptAcquireContext(hSessionProv, container, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET))
		{
			hPrivateKey = 0;
			if(CryptGenKey(*hSessionProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE | RSA1024BIT_KEY, &hPrivateKey)) // 1024
			{
				if(CryptExportKey(hPrivateKey, 0, PRIVATEKEYBLOB, 0, NULL, &dwkeyblob))
				{
					if(keyblob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob))
					{
						if(CryptExportKey(hPrivateKey, 0, PRIVATEKEYBLOB, 0, keyblob, &dwkeyblob))
						{
							CryptDestroyKey(hPrivateKey);
							hPrivateKey = 0;

							dwLen = ((RSAPUBKEY *) (keyblob + sizeof(PUBLICKEYSTRUC)))->bitlen / 8;
							((RSAPUBKEY *) (keyblob + sizeof(PUBLICKEYSTRUC)))->pubexp = 1;
							ptr = keyblob + sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY);

							ptr += 2 * dwLen; // Skip pubexp, modulus, prime1, prime2
							*ptr = 1; // Convert exponent1 to 1
							RtlZeroMemory(ptr + 1, dwLen / 2 - 1);
							ptr += dwLen / 2; // Skip exponent1
							*ptr = 1; // Convert exponent2 to 1
							RtlZeroMemory(ptr + 1, dwLen / 2 - 1);
							ptr += dwLen; // Skip exponent2, coefficient
							*ptr = 1; // Convert privateExponent to 1
							RtlZeroMemory(ptr + 1, (dwLen/2) - 1);

							if(CryptImportKey(*hSessionProv, keyblob, dwkeyblob, 0, 0, &hPrivateKey))
							{
								dwkeyblob = (1024 / 8) + sizeof(ALG_ID) + sizeof(BLOBHEADER); // 1024
								if(pbSessionBlob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob))
								{
									((BLOBHEADER *) pbSessionBlob)->bType = SIMPLEBLOB;
									((BLOBHEADER *) pbSessionBlob)->bVersion = CUR_BLOB_VERSION;
									((BLOBHEADER *) pbSessionBlob)->reserved = 0;
									((BLOBHEADER *) pbSessionBlob)->aiKeyAlg = calgid;
									ptr = pbSessionBlob + sizeof(BLOBHEADER);
									*(ALG_ID *) ptr = CALG_RSA_KEYX;
									ptr += sizeof(ALG_ID);

									for (i = 0; i < keyLen; i++)
										ptr[i] = ((LPCBYTE) key)[keyLen - i - 1];
									ptr += (keyLen + 1);
									for (i = 0; i < dwkeyblob - (sizeof(ALG_ID) + sizeof(BLOBHEADER) + keyLen + 3); i++)
										if (ptr[i] == 0) ptr[i] = 0x42;
									pbSessionBlob[dwkeyblob - 2] = 2;
									status = CryptImportKey(*hSessionProv, pbSessionBlob, dwkeyblob, hPrivateKey, flags, hSessionKey);
									LocalFree(pbSessionBlob);
								}
							}
						}
						LocalFree(keyblob);
					}
				}
			}
			if(hPrivateKey)
				CryptDestroyKey(hPrivateKey);
			if(!status)
				kull_m_crypto_close_hprov_delete_container(*hSessionProv);
		}
		LocalFree(container);
	}
	return status;
}

DWORD kull_m_crypto_hash_len(ALG_ID hashId)
{
	DWORD len = 0;
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	if(CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if(CryptCreateHash(hProv, hashId, 0, 0, &hHash))
		{
			CryptGetHashParam(hHash, HP_HASHVAL, NULL, &len, 0);
			CryptDestroyHash(hHash);
		}
		CryptReleaseContext(hProv, 0);
	}
	return len;
}

DWORD kull_m_crypto_cipher_blocklen(ALG_ID hashId)
{
	DWORD len = 0, dwSize = sizeof(DWORD);
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	if(CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if(CryptGenKey(hProv, hashId, 0, &hKey))
		{
			CryptGetKeyParam(hKey, KP_BLOCKLEN, (PBYTE) &len, &dwSize, 0);
			CryptDestroyKey(hKey);
		}
		CryptReleaseContext(hProv, 0);
	}
	return len / 8;
}

DWORD kull_m_crypto_cipher_keylen(ALG_ID hashId)
{
	DWORD len = 0, dwSize = sizeof(DWORD);
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	if(CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if(CryptGenKey(hProv, hashId, 0, &hKey))
		{
			CryptGetKeyParam(hKey, KP_KEYLEN, (PBYTE) &len, &dwSize, 0);
			CryptDestroyKey(hKey);
		}
		CryptReleaseContext(hProv, 0);
	}
	return len / 8;
}

NTSTATUS kull_m_crypto_get_dcc(PBYTE dcc, PBYTE ntlm, PUNICODE_STRING Username, DWORD realIterations)
{
	NTSTATUS status;
	LSA_UNICODE_STRING HashAndLowerUsername;
	LSA_UNICODE_STRING LowerUsername;
	BYTE buffer[LM_NTLM_HASH_LENGTH];

	status = RtlDowncaseUnicodeString(&LowerUsername, Username, TRUE);
	if(NT_SUCCESS(status))
	{
		HashAndLowerUsername.Length = HashAndLowerUsername.MaximumLength = LowerUsername.Length + LM_NTLM_HASH_LENGTH;
		if(HashAndLowerUsername.Buffer = (PWSTR) LocalAlloc(LPTR, HashAndLowerUsername.MaximumLength))
		{
			RtlCopyMemory(HashAndLowerUsername.Buffer, ntlm, LM_NTLM_HASH_LENGTH);
			RtlCopyMemory((PBYTE) HashAndLowerUsername.Buffer + LM_NTLM_HASH_LENGTH, LowerUsername.Buffer, LowerUsername.Length);
			status = RtlDigestNTLM(&HashAndLowerUsername, dcc);
			if(realIterations && NT_SUCCESS(status))
			{
				if(kull_m_crypto_pkcs5_pbkdf2_hmac(CALG_SHA1, dcc, LM_NTLM_HASH_LENGTH, LowerUsername.Buffer, LowerUsername.Length, realIterations, buffer, LM_NTLM_HASH_LENGTH, FALSE))
				{
					RtlCopyMemory(dcc, buffer, LM_NTLM_HASH_LENGTH);
					status = STATUS_SUCCESS;
				}
			}
			LocalFree(HashAndLowerUsername.Buffer);
		}
		RtlFreeUnicodeString(&LowerUsername);
	}
	return status;
}


const DWORD kull_m_crypto_crc32_tab[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,	0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
	0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

DWORD kull_m_crypto_crc32(DWORD startCrc, LPCVOID data, DWORD size)
{
	LPCBYTE ptr;
	ptr = (LPCBYTE) data;
	startCrc = startCrc ^ ~0u;
	while (size--)
		startCrc = kull_m_crypto_crc32_tab[(startCrc ^ *ptr++) & 0xff] ^ (startCrc >> 8);
	return startCrc ^ ~0u;
}

const KULL_M_CRYPTO_DUAL_STRING_DWORD kull_m_crypto_system_stores[] = {
	{L"CERT_SYSTEM_STORE_CURRENT_USER",					CERT_SYSTEM_STORE_CURRENT_USER},
	{L"CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY",	CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY},
	{L"CERT_SYSTEM_STORE_LOCAL_MACHINE",				CERT_SYSTEM_STORE_LOCAL_MACHINE},
	{L"CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY",	CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY},
	{L"CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE",		CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE},
	{L"CERT_SYSTEM_STORE_CURRENT_SERVICE",				CERT_SYSTEM_STORE_CURRENT_SERVICE},
	{L"CERT_SYSTEM_STORE_USERS",						CERT_SYSTEM_STORE_USERS},
	{L"CERT_SYSTEM_STORE_SERVICES",						CERT_SYSTEM_STORE_SERVICES},
};

const KULL_M_CRYPTO_DUAL_STRING_STRING kull_m_crypto_provider_names[] = {
	{L"MS_DEF_PROV",									MS_DEF_PROV},
	{L"MS_ENHANCED_PROV",								MS_ENHANCED_PROV},
	{L"MS_STRONG_PROV",									MS_STRONG_PROV},
	{L"MS_DEF_RSA_SIG_PROV",							MS_DEF_RSA_SIG_PROV},
	{L"MS_DEF_RSA_SCHANNEL_PROV",						MS_DEF_RSA_SCHANNEL_PROV},
	{L"MS_DEF_DSS_PROV",								MS_DEF_DSS_PROV},
	{L"MS_DEF_DSS_DH_PROV",								MS_DEF_DSS_DH_PROV},
	{L"MS_ENH_DSS_DH_PROV",								MS_ENH_DSS_DH_PROV},
	{L"MS_DEF_DH_SCHANNEL_PROV",						MS_DEF_DH_SCHANNEL_PROV},
	{L"MS_SCARD_PROV",									MS_SCARD_PROV},
	{L"MS_ENH_RSA_AES_PROV_XP",							MS_ENH_RSA_AES_PROV_XP},
	{L"MS_ENH_RSA_AES_PROV",							MS_ENH_RSA_AES_PROV},
};

const KULL_M_CRYPTO_DUAL_STRING_DWORD kull_m_crypto_provider_types[] = {
	{L"PROV_RSA_FULL",									PROV_RSA_FULL},
	{L"PROV_RSA_SIG",									PROV_RSA_SIG},
	{L"PROV_DSS",										PROV_DSS},
	{L"PROV_FORTEZZA",									PROV_FORTEZZA},
	{L"PROV_MS_EXCHANGE",								PROV_MS_EXCHANGE},
	{L"PROV_SSL",										PROV_SSL},
	{L"PROV_RSA_SCHANNEL",								PROV_RSA_SCHANNEL},
	{L"PROV_DSS_DH",									PROV_DSS_DH},
	{L"PROV_EC_ECDSA_SIG",								PROV_EC_ECDSA_SIG},
	{L"PROV_EC_ECNRA_SIG",								PROV_EC_ECNRA_SIG},
	{L"PROV_EC_ECDSA_FULL",								PROV_EC_ECDSA_FULL},
	{L"PROV_EC_ECNRA_FULL",								PROV_EC_ECNRA_FULL},
	{L"PROV_DH_SCHANNEL",								PROV_DH_SCHANNEL},
	{L"PROV_SPYRUS_LYNKS",								PROV_SPYRUS_LYNKS},
	{L"PROV_RNG",										PROV_RNG},
	{L"PROV_INTEL_SEC",									PROV_INTEL_SEC},
	{L"PROV_REPLACE_OWF",								PROV_REPLACE_OWF},
	{L"PROV_RSA_AES",									PROV_RSA_AES},
};

const KULL_M_CRYPTO_DUAL_STRING_DWORD kull_m_crypto_calgid[] = {
	{L"CALG_MD2",					CALG_MD2},
	{L"CALG_MD4",					CALG_MD4},
	{L"CALG_MD5",					CALG_MD5},
	//{L"CALG_SHA",					CALG_SHA},
	{L"CALG_SHA1",					CALG_SHA1},
	{L"CALG_MAC",					CALG_MAC},
	{L"CALG_RSA_SIGN",				CALG_RSA_SIGN},
	{L"CALG_DSS_SIGN",				CALG_DSS_SIGN},
	{L"CALG_NO_SIGN",				CALG_NO_SIGN},
	{L"CALG_RSA_KEYX",				CALG_RSA_KEYX},
	{L"CALG_DES",					CALG_DES},
	{L"CALG_3DES_112",				CALG_3DES_112},
	{L"CALG_3DES",					CALG_3DES},
	{L"CALG_DESX",					CALG_DESX},
	{L"CALG_RC2",					CALG_RC2},
	{L"CALG_RC4",					CALG_RC4},
	{L"CALG_SEAL",					CALG_SEAL},
	{L"CALG_DH_SF",					CALG_DH_SF},
	{L"CALG_DH_EPHEM",				CALG_DH_EPHEM},
	{L"CALG_AGREEDKEY_ANY",			CALG_AGREEDKEY_ANY},
	{L"CALG_KEA_KEYX",				CALG_KEA_KEYX},
	{L"CALG_HUGHES_MD5",			CALG_HUGHES_MD5},
	{L"CALG_SKIPJACK",				CALG_SKIPJACK},
	{L"CALG_TEK",					CALG_TEK},
	{L"CALG_CYLINK_MEK",			CALG_CYLINK_MEK},
	{L"CALG_SSL3_SHAMD5",			CALG_SSL3_SHAMD5},
	{L"CALG_SSL3_MASTER",			CALG_SSL3_MASTER},
	{L"CALG_SCHANNEL_MASTER_HASH",	CALG_SCHANNEL_MASTER_HASH},
	{L"CALG_SCHANNEL_MAC_KEY",		CALG_SCHANNEL_MAC_KEY},
	{L"CALG_SCHANNEL_ENC_KEY",		CALG_SCHANNEL_ENC_KEY},
	{L"CALG_PCT1_MASTER",			CALG_PCT1_MASTER},
	{L"CALG_SSL2_MASTER",			CALG_SSL2_MASTER},
	{L"CALG_TLS1_MASTER",			CALG_TLS1_MASTER},
	{L"CALG_RC5",					CALG_RC5},
	{L"CALG_HMAC",					CALG_HMAC},
	{L"CALG_TLS1PRF",				CALG_TLS1PRF},
	{L"CALG_HASH_REPLACE_OWF",		CALG_HASH_REPLACE_OWF},
	{L"CALG_AES_128",				CALG_AES_128},
	{L"CALG_AES_192",				CALG_AES_192},
	{L"CALG_AES_256",				CALG_AES_256},
	{L"CALG_AES",					CALG_AES},
	{L"CALG_SHA_256",				CALG_SHA_256},
	{L"CALG_SHA_384",				CALG_SHA_384},
	{L"CALG_SHA_512",				CALG_SHA_512},
	{L"CALG_ECDH",					CALG_ECDH},
	{L"CALG_ECMQV",					CALG_ECMQV},
	{L"CALG_ECDSA",					CALG_ECDSA},
};

DWORD kull_m_crypto_system_store_to_dword(PCWSTR name)
{
	DWORD i;
	if(name)
		for(i = 0; i < ARRAYSIZE(kull_m_crypto_system_stores); i++)
			if((_wcsicmp(name, kull_m_crypto_system_stores[i].name) == 0) || (_wcsicmp(name, kull_m_crypto_system_stores[i].name + 18) == 0))
				return kull_m_crypto_system_stores[i].id;
	return 0;
}

DWORD kull_m_crypto_provider_type_to_dword(PCWSTR name)
{
	DWORD i;
	if(name)
		for(i = 0; i < ARRAYSIZE(kull_m_crypto_provider_types); i++)
			if((_wcsicmp(name, kull_m_crypto_provider_types[i].name) == 0) || (_wcsicmp(name, kull_m_crypto_provider_types[i].name + 5) == 0))
				return kull_m_crypto_provider_types[i].id;
	return 0;
}

PCWCHAR kull_m_crypto_provider_to_realname(PCWSTR name)
{
	DWORD i;
	if(name)
		for(i = 0; i < ARRAYSIZE(kull_m_crypto_provider_names); i++)
			if((_wcsicmp(name, kull_m_crypto_provider_names[i].name) == 0) || (_wcsicmp(name, kull_m_crypto_provider_names[i].name + 3) == 0))
				return kull_m_crypto_provider_names[i].realname;
	return NULL;
}

PCWCHAR kull_m_crypto_keytype_to_str(const DWORD keyType)
{
	switch (keyType)
	{
	case AT_KEYEXCHANGE:
		return L"AT_KEYEXCHANGE";
	case AT_SIGNATURE:
		return L"AT_SIGNATURE";
	case CERT_NCRYPT_KEY_SPEC:
		return L"CNG Key";
	default:
		return L"?";
	}
}

PCWCHAR kull_m_crypto_algid_to_name(ALG_ID algid)
{
	DWORD i;
	for(i = 0; i < ARRAYSIZE(kull_m_crypto_calgid); i++)
		if(kull_m_crypto_calgid[i].id == algid)
			return kull_m_crypto_calgid[i].name;
	return NULL;
}