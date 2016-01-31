/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <shlwapi.h>

BOOL isBase64Intercept;

typedef BOOL (CALLBACK * PKULL_M_FILE_FIND_CALLBACK) (DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg);

BOOL kull_m_file_getCurrentDirectory(wchar_t ** ppDirName);
BOOL kull_m_file_getAbsolutePathOf(PCWCHAR thisData, wchar_t ** reponse);
BOOL kull_m_file_isFileExist(PCWCHAR fileName);
BOOL kull_m_file_writeData(PCWCHAR fileName, LPCVOID data, DWORD lenght);
BOOL kull_m_file_readData(PCWCHAR fileName, PBYTE * data, PDWORD lenght);	// for 'little' files !
void kull_m_file_cleanFilename(PWCHAR fileName);
PWCHAR kull_m_file_fullPath(PCWCHAR fileName);
BOOL kull_m_file_Find(PCWCHAR directory, PCWCHAR filter, BOOL isRecursive /*TODO*/, DWORD level, BOOL isPrintInfos, PKULL_M_FILE_FIND_CALLBACK callback, PVOID pvArg);