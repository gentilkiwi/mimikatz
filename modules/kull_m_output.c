#include "kull_m_output.h"

FILE * logfile = NULL;

void kprintf(PCWCHAR format, ...)
{
	va_list args;
	va_start(args, format);
	vfwprintf(stdout, format, args);
	fflush(stdout);
	if(logfile)
		vfwprintf(logfile, format, args);
	va_end(args);
	fflush(logfile);
}

void kprintf_inputline(PCWCHAR format, ...)
{
	va_list args;
	va_start(args, format);
	if(logfile)
		vfwprintf(logfile, format, args);
	va_end(args);
	fflush(logfile);
}

BOOL kull_m_output_file(PCWCHAR file)
{
	BOOL status = FALSE;
	FILE * newlog = NULL;

	if(file)
#pragma warning(push)
#pragma warning(disable:4996)
		newlog = _wfopen(file, L"a");
#pragma warning(pop)
	if(newlog || !file)
	{
		if(logfile)
			fclose(logfile);
		logfile = newlog;
	}
	return (!file || (file && logfile));
}