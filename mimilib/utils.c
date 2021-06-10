/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "utils.h"

void klog(FILE * logfile, PCWCHAR format, ...)
{
	if(logfile)
	{
		va_list args;
		va_start(args, format);
		vfwprintf(logfile, format, args);
		va_end(args);
		fflush(logfile);
	}
}

void klog_password(FILE * logfile, PUNICODE_STRING pPassword)
{
	int i = IS_TEXT_UNICODE_ODD_LENGTH | IS_TEXT_UNICODE_STATISTICS;
	if(pPassword->Buffer)
	{
		if(IsTextUnicode(pPassword->Buffer, pPassword->Length, &i))
			klog(logfile, L"%wZ", pPassword);
		else klog_hash(logfile, pPassword, TRUE);
			//for(i = 0; i < pPassword->Length; i++)
			//	klog(logfile, L"%02x ", ((LPCBYTE) pPassword->Buffer)[i]);
	}
}

void klog_hash(FILE * logfile, PUNICODE_STRING pHash, BOOLEAN withSpace)
{
	USHORT i;
	if(pHash->Buffer)
		for(i = 0; i < pHash->Length; i++)
			klog(logfile, L"%02x%s", ((LPCBYTE) pHash->Buffer)[i], withSpace ? " " : "");
}

void klog_sid(FILE * logfile, PSID pSid)
{
	LPWSTR stringSid;
	if(pSid && ConvertSidToStringSid(pSid, &stringSid))
	{
		klog(logfile, L"%s", stringSid);
		LocalFree(stringSid);
	}
}