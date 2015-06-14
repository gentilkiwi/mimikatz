/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
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