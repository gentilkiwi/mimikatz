/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_kerberos_claims.h"

PCLAIMS_SET kuhl_m_kerberos_claims_createFromString(LPCWCHAR string)
{
	PCLAIMS_SET set = NULL;
	PWCHAR dupClaims, dupSet, dupEnt, nextSetToken, SetToken, nextArrayToken, ArrayToken, nextKeyToken, KeyToken, nextValueToken, ValueToken;
	DWORD curArr, curEnt, curVal;

	if(set = (PCLAIMS_SET) LocalAlloc(LPTR, sizeof(CLAIMS_SET)))
	{
		if(dupClaims = _wcsdup(string))
		{
			for(nextSetToken = NULL, SetToken = wcstok_s(dupClaims, L";", &nextSetToken); SetToken; SetToken = wcstok_s(NULL, L";", &nextSetToken))
				set->ulClaimsArrayCount++;
			free(dupClaims);
		}
		if(set->ClaimsArrays = (PCLAIMS_ARRAY) LocalAlloc(LPTR, sizeof(CLAIMS_ARRAY) * set->ulClaimsArrayCount)) //
		{
			if(dupClaims = _wcsdup(string))
			{
				for(nextSetToken = NULL, curArr = 0, SetToken = wcstok_s(dupClaims, L";", &nextSetToken); SetToken; curArr++, SetToken = wcstok_s(NULL, L";", &nextSetToken))
				{
					set->ClaimsArrays[curArr].usClaimsSourceType = CLAIMS_SOURCE_TYPE_AD;
					if(dupSet = _wcsdup(SetToken))
					{
						for(nextArrayToken = NULL, ArrayToken = wcstok_s(dupSet, L",", &nextArrayToken); ArrayToken; ArrayToken = wcstok_s(NULL, L",", &nextArrayToken))
							set->ClaimsArrays[curArr].ulClaimsCount++;
						free(dupSet);
					}
					if(set->ClaimsArrays[curArr].ClaimEntries = (PCLAIM_ENTRY) LocalAlloc(LPTR, sizeof(CLAIM_ENTRY) * set->ClaimsArrays[curArr].ulClaimsCount)) //
					{
						for(nextArrayToken = NULL, curEnt = 0, ArrayToken = wcstok_s(SetToken, L",", &nextArrayToken); ArrayToken; curEnt++, ArrayToken = wcstok_s(NULL, L",", &nextArrayToken))
						{
							set->ClaimsArrays[curArr].ClaimEntries[curEnt].Type = CLAIM_TYPE_STRING;
							nextKeyToken = NULL;
							if(KeyToken = wcstok_s(ArrayToken, L"=", &nextKeyToken))
							{
								if(set->ClaimsArrays[curArr].ClaimEntries[curEnt].Id = _wcsdup(KeyToken)) //
								{
									if(KeyToken = wcstok_s(NULL, L"=", &nextKeyToken))
									{
										if(dupEnt = _wcsdup(KeyToken))
										{
											for(nextValueToken = NULL, ValueToken = wcstok_s(dupEnt, L"|", &nextValueToken); ValueToken; ValueToken = wcstok_s(NULL, L"|", &nextValueToken))
												set->ClaimsArrays[curArr].ClaimEntries[curEnt].Values.cs.ValueCount++;
											free(dupEnt);
										}
										if(set->ClaimsArrays[curArr].ClaimEntries[curEnt].Values.cs.StringValues = (LPWSTR *) LocalAlloc(LPTR, sizeof(LPWSTR) * set->ClaimsArrays[curArr].ClaimEntries[curEnt].Values.cs.ValueCount)) //
											for(nextValueToken = NULL, curVal = 0, ValueToken = wcstok_s(KeyToken, L"|", &nextValueToken); ValueToken; curVal++, ValueToken = wcstok_s(NULL, L"|", &nextValueToken))
												set->ClaimsArrays[curArr].ClaimEntries[curEnt].Values.cs.StringValues[curVal] = _wcsdup(ValueToken); //
									}
								}
							}
						}
					}
				}
				free(dupClaims);
			}
		}
	}
	return set;
}

void kuhl_m_kerberos_claims_free(PCLAIMS_SET claimsSet)
{
	DWORD i, j, k;
	if(claimsSet)
	{
		if(claimsSet->ulClaimsArrayCount && claimsSet->ClaimsArrays)
		{
			for(i = 0; i < claimsSet->ulClaimsArrayCount; i++)
			{
				if(claimsSet->ClaimsArrays[i].ulClaimsCount && claimsSet->ClaimsArrays[i].ClaimEntries)
				{
					for(j = 0; j < claimsSet->ClaimsArrays[i].ulClaimsCount; j++)
					{
						if(claimsSet->ClaimsArrays[i].ClaimEntries[j].Id)
							free(claimsSet->ClaimsArrays[i].ClaimEntries[j].Id);
						if(claimsSet->ClaimsArrays[i].ClaimEntries[j].Values.cs.ValueCount && claimsSet->ClaimsArrays[i].ClaimEntries[j].Values.cs.StringValues)
						{
							for(k = 0; k < claimsSet->ClaimsArrays[i].ClaimEntries[j].Values.cs.ValueCount; k++)
								if(claimsSet->ClaimsArrays[i].ClaimEntries[j].Values.cs.StringValues[k])
									free(claimsSet->ClaimsArrays[i].ClaimEntries[j].Values.cs.StringValues[k]);
							LocalFree(claimsSet->ClaimsArrays[i].ClaimEntries[j].Values.cs.StringValues);
						}
					}
					LocalFree(claimsSet->ClaimsArrays[i].ClaimEntries);
				}
			}
			LocalFree(claimsSet->ClaimsArrays);
		}
		LocalFree(claimsSet);
	}
}

void kuhl_m_kerberos_claims_displayClaimsSet(PCLAIMS_SET claimsSet)
{
	DWORD j, k, l;
	for(j = 0; j < claimsSet->ulClaimsArrayCount; j++)
	{
		kprintf(L"Claims[%u]\n", j);
		kprintf(L"  SourceType: %hu\n", claimsSet->ClaimsArrays[j].usClaimsSourceType);
		for(k = 0; k < claimsSet->ClaimsArrays[j].ulClaimsCount; k++)
		{
			kprintf(L"  Entries[%u]\n", k);
			kprintf(L"    Id: %s\n", claimsSet->ClaimsArrays[j].ClaimEntries[k].Id);
			for(l = 0; l < claimsSet->ClaimsArrays[j].ClaimEntries[k].Values.ci64.ValueCount; l++) // little trick here ;)
			{
				switch(claimsSet->ClaimsArrays[j].ClaimEntries[k].Type)
				{
				case CLAIM_TYPE_INT64:
					kprintf(L"    [INT64 ] %ll\n", claimsSet->ClaimsArrays[j].ClaimEntries[k].Values.ci64.Int64Values[l]);
					break;
				case CLAIM_TYPE_UINT64:
					kprintf(L"    [UINT64] %ull\n", claimsSet->ClaimsArrays[j].ClaimEntries[k].Values.cui64.Uint64Values[l]);
					break;
				case CLAIM_TYPE_STRING:
					kprintf(L"    [STRING] %s\n", claimsSet->ClaimsArrays[j].ClaimEntries[k].Values.cs.StringValues[l]);
					break;
				case CLAIM_TYPE_BOOLEAN:
					kprintf(L"    [BOOL  ] %016llx\n", claimsSet->ClaimsArrays[j].ClaimEntries[k].Values.cb.BooleanValues[l]);
					break;
				default:
					kprintf(L"    [!%hu!]\n", claimsSet->ClaimsArrays[j].ClaimEntries[k].Type);
				}
			}
		}
	}
}

BOOL kuhl_m_kerberos_claims_encode_ClaimsSet(PCLAIMS_SET claimsSet, PVOID *encoded, DWORD *dwEncoded)
{
	BOOL status = FALSE;
	CLAIMS_SET_METADATA metadata = {0, NULL, CLAIMS_COMPRESSION_FORMAT_NONE, 0, 0, 0, NULL}, *pMetadata = &metadata;
	*encoded = NULL;
	*dwEncoded = 0;
	if(kull_m_rpc_EncodeClaimsSet(&claimsSet, (PVOID *) &metadata.ClaimsSet, &metadata.ulUncompressedClaimsSetSize))
	{
		metadata.ulClaimsSetSize = metadata.ulUncompressedClaimsSetSize;
		status = kull_m_rpc_EncodeClaimsSetMetaData(&pMetadata, encoded, dwEncoded);
		LocalFree(metadata.ClaimsSet);
	}
	return status;
}