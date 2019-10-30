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
		if(isBase64Output)
		{
			// get current size
			size_t current_length = ftell(logfile);
			// get new content size
			size_t appended_length = _vscwprintf(format, args);
			// set position to 0
			fseek(logfile, 0, SEEK_SET);
			// alloc current_content buffer
			LPWSTR current_content = LocalAlloc(LPTR, current_length + 1);
			// read current content
			size_t n_read = fread_s(current_content, current_length, sizeof(wchar_t), current_length / sizeof(wchar_t), logfile);
			current_content[current_length] = '\x00';
			// base64decode
			size_t decoded_length = 0;
			CryptStringToBinary(current_content, current_length, CRYPT_STRING_BASE64, NULL, &decoded_length, NULL, NULL);
			wchar_t* decoded_content = LocalAlloc(LPTR, decoded_length * sizeof(wchar_t));
			CryptStringToBinary(current_content, current_length, CRYPT_STRING_BASE64, (BYTE *) decoded_content, &decoded_length, NULL, NULL);
			// concat data
			wchar_t* concatenated_content = LocalAlloc(LPTR, decoded_length * sizeof(wchar_t) + appended_length * sizeof(wchar_t) + 1);
			memcpy(concatenated_content, decoded_content, decoded_length);
			vswprintf(concatenated_content + wcslen(concatenated_content), appended_length + 1, format, args);
			// base64encode
			size_t encoded_length = 0;
			CryptBinaryToString((const BYTE *) concatenated_content, decoded_length + appended_length * sizeof(wchar_t), CRYPT_STRING_BASE64, NULL, &encoded_length);
			LPWSTR encoded_content = LocalAlloc(LPTR, encoded_length * sizeof(wchar_t));
			CryptBinaryToString((const BYTE *) concatenated_content, decoded_length + appended_length * sizeof(wchar_t), CRYPT_STRING_BASE64, encoded_content, &encoded_length);
			// write to file
			fseek(logfile, 0, SEEK_SET);
			for(size_t i = 0; i < encoded_length; i++)
			{
				if(encoded_content[i] != '\x0d' && encoded_content[i] != '\x0a' && encoded_content[i] != '\x00')
					fwrite(encoded_content + i, sizeof(wchar_t), 1, logfile);
			}

			fflush(logfile);
			// free temporary buffers
			LocalFree(current_content);
			LocalFree(decoded_content);
			LocalFree(concatenated_content);
			LocalFree(encoded_content);
			// TODO: check for errors
		}
		else
		{
			vfwprintf(logfile, format, args);
			fflush(logfile);
		}
	}
	va_end(args);
}

void kprintf_inputline(PCWCHAR format, ...)
{
	va_list args;
	va_start(args, format);
	if(logfile)
	{
		if(isBase64Output)
		{
			// get current size
			size_t current_length = ftell(logfile);
			// get new content size
			size_t appended_length = _vscwprintf(format, args);
			// set position to 0
			fseek(logfile, 0, SEEK_SET);
			// alloc current_content buffer
			LPWSTR current_content = LocalAlloc(LPTR, current_length + 1);
			// read current content
			size_t n_read = fread_s(current_content, current_length, sizeof(wchar_t), current_length / sizeof(wchar_t), logfile);
			current_content[current_length] = '\x00';
			// base64decode
			size_t decoded_length = 0;
			CryptStringToBinary(current_content, current_length, CRYPT_STRING_BASE64, NULL, &decoded_length, NULL, NULL);
			wchar_t* decoded_content = LocalAlloc(LPTR, decoded_length * sizeof(wchar_t));
			CryptStringToBinary(current_content, current_length, CRYPT_STRING_BASE64, (BYTE *) decoded_content, &decoded_length, NULL, NULL);
			// concat data
			wchar_t* concatenated_content = LocalAlloc(LPTR, decoded_length * sizeof(wchar_t) + appended_length * sizeof(wchar_t) + 1);
			memcpy(concatenated_content, decoded_content, decoded_length);
			vswprintf(concatenated_content + wcslen(concatenated_content), appended_length + 1, format, args);
			// base64encode
			size_t encoded_length = 0;
			CryptBinaryToString((const BYTE *) concatenated_content, decoded_length + appended_length * sizeof(wchar_t), CRYPT_STRING_BASE64, NULL, &encoded_length);
			LPWSTR encoded_content = LocalAlloc(LPTR, encoded_length * sizeof(wchar_t));
			CryptBinaryToString((const BYTE *) concatenated_content, decoded_length + appended_length * sizeof(wchar_t), CRYPT_STRING_BASE64, encoded_content, &encoded_length);
			// write to file
			fseek(logfile, 0, SEEK_SET);
			for(size_t i = 0; i < encoded_length; i++)
			{
				if(encoded_content[i] != '\x0d' && encoded_content[i] != '\x0a' && encoded_content[i] != '\x00')
					fwrite(encoded_content + i, sizeof(wchar_t), 1, logfile);
			}

			fflush(logfile);
			// free temporary buffers
			LocalFree(current_content);
			LocalFree(decoded_content);
			LocalFree(concatenated_content);
			LocalFree(encoded_content);
			// TODO: check for errors
		}
		else
		{
			vfwprintf(logfile, format, args);
			fflush(logfile);
		}
	}
	va_end(args);
}

BOOL kull_m_output_file(PCWCHAR file)
{
	BOOL status = FALSE;
	FILE * newlog = NULL;

	if(file)
	{
#pragma warning(push)
#pragma warning(disable:4996)
		newlog = _wfopen(file, L"w+"); // XP does not like _wfopen_s
		fseek(newlog, 0, SEEK_END);
#pragma warning(pop)
	}
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
