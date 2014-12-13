#include "kull_m_output.h"

FILE * logfile = NULL;
#ifdef _WINDLL
wchar_t * outputBuffer = NULL;
size_t outputBufferElements = 0, outputBufferElementsPosition = 0;
#endif

void kprintf(PCWCHAR format, ...)
{
#ifdef _WINDLL
	int varBuf;
	size_t tempSize;
#endif
	va_list args;
	va_start(args, format);
#ifndef _WINDLL
	vwprintf(format, args);
	fflush(stdout);
#else
	if(outputBuffer)
	{
		varBuf = _vscwprintf(format, args);
		if(varBuf > 0)
		{
			if((size_t) varBuf > (outputBufferElements - outputBufferElementsPosition - 1)) // NULL character
			{
				tempSize = (outputBufferElements + varBuf + 1) * 2; // * 2, just to be cool
				if(outputBuffer = (wchar_t *) LocalReAlloc(outputBuffer, tempSize * sizeof(wchar_t), LMEM_MOVEABLE))
					outputBufferElements = tempSize;
			}
			varBuf = vswprintf_s(outputBuffer + outputBufferElementsPosition, outputBufferElements - outputBufferElementsPosition, format, args);
			if(varBuf > 0)
				outputBufferElementsPosition += varBuf;
		}
	}
#endif
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
		newlog = _wfopen(file, L"a"); // XP does not like _wfopen_s
#pragma warning(pop)
	if(newlog || !file)
	{
		if(logfile)
			fclose(logfile);
		logfile = newlog;
	}
	return (!file || (file && logfile));
}

int previousStdOut, previousStdErr;
UINT previousConsoleOutput;
void kull_m_output_init()
{
	previousStdOut = _setmode(_fileno(stdout), _O_U8TEXT);
	previousStdErr = _setmode(_fileno(stderr), _O_U8TEXT);
	previousConsoleOutput = GetConsoleOutputCP();
	SetConsoleOutputCP(CP_UTF8);
}

void kull_m_output_clean()
{
	_setmode(_fileno(stdout), previousStdOut);
	_setmode(_fileno(stderr), previousStdErr);
	SetConsoleOutputCP(previousConsoleOutput);
}
