/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "mimispool.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	BOOL ret;

	if(ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		kspool();
		ret = FALSE;
	}
	else
	{
		ret = TRUE;
	}

	return ret;
}

void kspool()
{
	FILE * kspool_logfile;
	WCHAR Buffer[256 + 1];
	DWORD cbBuffer = ARRAYSIZE(Buffer);

#pragma warning(push)
#pragma warning(disable:4996)
	if(kspool_logfile = _wfopen(L"mimispool.log", L"a"))
#pragma warning(pop)
	{
		klog(kspool_logfile, L"Hello!\n");
		
		if(GetUserName(Buffer, &cbBuffer))
		{
			klog(kspool_logfile, L"I\'m running with \'%s\' (and I like it :)\n", Buffer);
		}

		fclose(kspool_logfile);
	}
}

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