/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kspool.h"

void kspool()
{
	FILE * kspool_logfile;
	WCHAR Buffer[256 + 1];
	DWORD cbBuffer = ARRAYSIZE(Buffer);

#pragma warning(push)
#pragma warning(disable:4996)
	if(kspool_logfile = _wfopen(L"kiwispool.log", L"a"))
#pragma warning(pop)
	{
		klog(kspool_logfile, L"Hello!\n");

		if(GetUserName(Buffer, &cbBuffer))
		{
			klog(kspool_logfile, L"I\'m running with \'%s\' (and I like it)\n", Buffer);
		}

		fclose(kspool_logfile);
	}
}