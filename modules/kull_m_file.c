/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_file.h"

BOOL isBase64Intercept = FALSE;

BOOL kull_m_file_getCurrentDirectory(wchar_t ** ppDirName)
{
	BOOL reussite = FALSE;
	DWORD tailleRequise = GetCurrentDirectory(0, NULL);
	if(*ppDirName = (wchar_t *) LocalAlloc(LPTR, tailleRequise * sizeof(wchar_t)))
		if(!(reussite = (tailleRequise > 0 && (GetCurrentDirectory(tailleRequise, *ppDirName) == tailleRequise - 1))))
			LocalFree(*ppDirName);

	return reussite;
}

BOOL kull_m_file_getAbsolutePathOf(PCWCHAR thisData, wchar_t ** reponse)
{
	BOOL reussite = FALSE;
	wchar_t *monRep;
	*reponse = (wchar_t *) LocalAlloc(LPTR, MAX_PATH);

	if(PathIsRelative(thisData))
	{
		if(kull_m_file_getCurrentDirectory(&monRep))
		{
			reussite = (PathCombine(*reponse , monRep, thisData) != NULL);
			LocalFree(monRep);
		}
	}
	else
		reussite = PathCanonicalize(*reponse, thisData);

	if(!reussite)
		LocalFree(*reponse);

	return reussite;
}

BOOL kull_m_file_isFileExist(PCWCHAR fileName)
{
	BOOL reussite = FALSE;
	HANDLE hFile = NULL;
	PWCHAR fullFileName;

	if(fullFileName = kull_m_file_fullPath(fileName))
	{
		reussite = ((hFile = CreateFile(fullFileName, 0, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) && hFile != INVALID_HANDLE_VALUE);
		if(reussite)
			CloseHandle(hFile);
		LocalFree(fullFileName);
	}
	return reussite;
}

BOOL kull_m_file_writeData(PCWCHAR fileName, LPCVOID data, DWORD lenght)
{
	BOOL reussite = FALSE;
	DWORD dwBytesWritten = 0, i;
	HANDLE hFile = NULL;
	PWCHAR fullFileName;
	LPWSTR base64;

	if(fullFileName = kull_m_file_fullPath(fileName))
	{
		if(isBase64Intercept)
		{
			if(CryptBinaryToString((const BYTE *) data, lenght, CRYPT_STRING_BASE64, NULL, &dwBytesWritten))
			{
				if(base64 = (LPWSTR) LocalAlloc(LPTR, dwBytesWritten * sizeof(wchar_t)))
				{
					if(reussite = CryptBinaryToString((const BYTE *) data, lenght, CRYPT_STRING_BASE64, base64, &dwBytesWritten))
					{
						kprintf(L"\n====================\nBase64 of file : %s\n====================\n", fullFileName);
						for(i = 0; i < dwBytesWritten; i++)
							kprintf(L"%c", base64[i]);
						kprintf(L"====================\n");
					}
					LocalFree(base64);
				}
			}
		}
		else if((hFile = CreateFile(fullFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL)) && hFile != INVALID_HANDLE_VALUE)
		{
			if(WriteFile(hFile, data, lenght, &dwBytesWritten, NULL) && (lenght == dwBytesWritten))
				reussite = FlushFileBuffers(hFile);
			CloseHandle(hFile);
		}
		LocalFree(fullFileName);
	}
	return reussite;
}

BOOL kull_m_file_readData(PCWCHAR fileName, PBYTE * data, PDWORD lenght)	// for ""little"" files !
{
	BOOL reussite = FALSE;
	DWORD dwBytesReaded;
	LARGE_INTEGER filesize;
	HANDLE hFile = NULL;
	PWCHAR fullFileName;
		
	if(fullFileName = kull_m_file_fullPath(fileName))
	{
		if((hFile = CreateFile(fullFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) && hFile != INVALID_HANDLE_VALUE)
		{
			if(GetFileSizeEx(hFile, &filesize) && !filesize.HighPart)
			{
				*lenght = filesize.LowPart;
				if(*data = (PBYTE) LocalAlloc(LPTR, *lenght))
				{
					if(!(reussite = ReadFile(hFile, *data, *lenght, &dwBytesReaded, NULL) && (*lenght == dwBytesReaded)))
						LocalFree(*data);
				}
			}
			CloseHandle(hFile);
		}
		LocalFree(fullFileName);
	}
	return reussite;
}

const wchar_t kull_m_file_forbiddenChars[] = {L'\\', L'/', L':', L'*', L'?', L'\"', L'<', L'>', L'|'};
void kull_m_file_cleanFilename(PWCHAR fileName)
{
	DWORD i, j;
	for(i = 0; fileName[i]; i++)
		for(j = 0; j < ARRAYSIZE(kull_m_file_forbiddenChars); j++)
			if(fileName[i] == kull_m_file_forbiddenChars[j])
				fileName[i] = L'~';
}

PWCHAR kull_m_file_fullPath(PCWCHAR fileName)
{
	PWCHAR buffer = NULL;
	DWORD bufferLen;
	if(fileName)
		if(bufferLen = ExpandEnvironmentStrings(fileName, NULL, 0))
			if(buffer = (PWCHAR) LocalAlloc(LPTR, bufferLen * sizeof(wchar_t)))
				if(bufferLen != ExpandEnvironmentStrings(fileName, buffer, bufferLen))
					buffer = (PWCHAR) LocalFree(buffer);
	return buffer;
}