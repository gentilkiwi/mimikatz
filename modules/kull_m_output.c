/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_output.h"

FILE * logfile = NULL;
#if !defined(MIMIKATZ_W2000_SUPPORT)
wchar_t * outputBuffer = NULL;
size_t outputBufferElements = 0, outputBufferElementsPosition = 0;
#endif

void kprintf(PCWCHAR format, ...)
{
#if !defined(MIMIKATZ_W2000_SUPPORT)
	int varBuf;
	size_t tempSize;
	wchar_t * tmpBuffer;
#endif
	va_list args;
	va_start(args, format);
#if !defined(MIMIKATZ_W2000_SUPPORT)
	if(outputBuffer)
	{
		varBuf = _vscwprintf(format, args);
		if(varBuf > 0)
		{
			if((size_t) varBuf > (outputBufferElements - outputBufferElementsPosition - 1)) // NULL character
			{
				tempSize = (outputBufferElements + varBuf + 1) * 2; // * 2, just to be cool
				if(tmpBuffer = (wchar_t *) LocalAlloc(LPTR, tempSize * sizeof(wchar_t)))
				{
					RtlCopyMemory(tmpBuffer, outputBuffer, outputBufferElementsPosition * sizeof(wchar_t));
					LocalFree(outputBuffer);
					outputBuffer = tmpBuffer;
					outputBufferElements = tempSize;
				}
				else wprintf(L"Erreur LocalAlloc: %u\n", GetLastError());
				//if(outputBuffer = (wchar_t *) LocalReAlloc(outputBuffer, tempSize * sizeof(wchar_t), LPTR))
				//	outputBufferElements = tempSize;
				//else wprintf(L"Erreur ReAlloc: %u\n", GetLastError());
			}
			varBuf = vswprintf_s(outputBuffer + outputBufferElementsPosition, outputBufferElements - outputBufferElementsPosition, format, args);
			if(varBuf > 0)
				outputBufferElementsPosition += varBuf;
		}
	}
#endif
#if !defined(_POWERKATZ)
#if !defined(MIMIKATZ_W2000_SUPPORT)
	else
#endif
	{
		vwprintf(format, args);
		fflush(stdout);
	}
#endif
	if(logfile)
	{
		vfwprintf(logfile, format, args);
		fflush(logfile);
	}
	va_end(args);
}

void kprintf_inputline(PCWCHAR format, ...)
{
	va_list args;
	va_start(args, format);
	if(logfile)
	{
		vfwprintf(logfile, format, args);
		fflush(logfile);
	}
	va_end(args);
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
#if !defined(_POWERKATZ)
#if !defined(_WINDLL)
	previousStdOut = _setmode(_fileno(stdout), _O_U8TEXT);
	previousStdErr = _setmode(_fileno(stderr), _O_U8TEXT);
#endif
	previousConsoleOutput = GetConsoleOutputCP();
	SetConsoleOutputCP(CP_UTF8);
#endif
}

void kull_m_output_clean()
{
#if !defined(_POWERKATZ)
#if !defined(_WINDLL)
	_setmode(_fileno(stdout), previousStdOut);
	_setmode(_fileno(stderr), previousStdErr);
#endif
	SetConsoleOutputCP(previousConsoleOutput);
#endif
}