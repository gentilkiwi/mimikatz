/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_string.h"

//BOOL kull_m_string_suspectUnicodeStringStructure(IN PUNICODE_STRING pUnicodeString)
//{
//	return (
//		pUnicodeString->Length &&
//		!((pUnicodeString->Length & 1) || (pUnicodeString->MaximumLength & 1)) &&
//		(pUnicodeString->Length < sizeof(wchar_t)*0xff) &&
//		(pUnicodeString->Length <= pUnicodeString->MaximumLength) &&
//		((pUnicodeString->MaximumLength - pUnicodeString->Length) < 4*sizeof(wchar_t)) &&
//		pUnicodeString->Buffer
//		);
//}

BOOL kull_m_string_suspectUnicodeString(IN PUNICODE_STRING pUnicodeString)
{
	int unicodeTestFlags = IS_TEXT_UNICODE_STATISTICS;
	return ((pUnicodeString->Length == sizeof(wchar_t)) && IsCharAlphaNumeric(pUnicodeString->Buffer[0])) || IsTextUnicode(pUnicodeString->Buffer, pUnicodeString->Length, &unicodeTestFlags);
}

void kull_m_string_printSuspectUnicodeString(PVOID data, DWORD size)
{
	UNICODE_STRING uString = {(USHORT) size, (USHORT) size, (LPWSTR) data};
	if(kull_m_string_suspectUnicodeString(&uString))
		kprintf(L"%wZ", &uString);
	else 
		kull_m_string_wprintf_hex(uString.Buffer, uString.Length, 1);
}

void kull_m_string_MakeRelativeOrAbsoluteString(PVOID BaseAddress, PLSA_UNICODE_STRING String, BOOL relative)
{
	if(String->Buffer)
		String->Buffer = (PWSTR) ((ULONG_PTR)(String->Buffer) + ((relative ? -1 : 1) * (ULONG_PTR)(BaseAddress)));
}

BOOL kull_m_string_copyUnicodeStringBuffer(PUNICODE_STRING pSource, PUNICODE_STRING pDestination)
{
	BOOL status = FALSE;
	if(pSource && pDestination && pSource->MaximumLength && pSource->Buffer)
	{
		*pDestination = *pSource;
		if(pDestination->Buffer = (PWSTR) LocalAlloc(LPTR, pSource->MaximumLength))
		{
			status = TRUE;
			RtlCopyMemory(pDestination->Buffer, pSource->Buffer, pSource->MaximumLength);
		}
	}
	return status;
}

void kull_m_string_freeUnicodeStringBuffer(PUNICODE_STRING pString)
{
	if(pString && pString->Buffer)
		pString->Buffer = (PWSTR) LocalFree(pString->Buffer);
}

wchar_t * kull_m_string_qad_ansi_to_unicode(const char * ansi)
{
	wchar_t * buffer = NULL;
	if(ansi)
		buffer = kull_m_string_qad_ansi_c_to_unicode(ansi, strlen(ansi));
	return buffer;
}

wchar_t * kull_m_string_qad_ansi_c_to_unicode(const char * ansi, SIZE_T szStr)
{
	wchar_t * buffer = NULL;
	SIZE_T i;

	if(ansi && szStr)
		if(buffer = (wchar_t *) LocalAlloc(LPTR, (szStr + 1) * sizeof(wchar_t)))
			for(i = 0; i < szStr; i++)
				buffer[i] = ansi[i];
	return buffer;
}

char * kull_m_string_unicode_to_ansi(const wchar_t * unicode)
{
	int needed;
	char * buffer = NULL;
	if(needed = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, unicode, -1, NULL, 0, NULL, NULL))
		if(buffer = (char *) LocalAlloc(LPTR, needed))
			if(needed != WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, unicode, -1, buffer, needed, NULL, NULL))
				buffer = (char *) LocalFree(buffer);
	return buffer;
}

BOOL kull_m_string_stringToHex(IN LPCWCHAR string, IN LPBYTE hex, IN DWORD size)
{
	DWORD i, j;
	BOOL result = (wcslen(string) == (size * 2));
	if(result)
	{
		for(i = 0; i < size; i++)
		{
			swscanf_s(&string[i*2], L"%02x", &j);
			hex[i] = (BYTE) j;
		}
	}
	return result;
}

BOOL kull_m_string_stringToHexBuffer(IN LPCWCHAR string, IN LPBYTE *hex, IN DWORD *size)
{
	BOOL result = FALSE;
	*size = (DWORD) wcslen(string);
	if(!(*size % 2))
	{
		*size >>= 1;
		if(*hex = (PBYTE) LocalAlloc(LPTR, *size))
		{
			result = kull_m_string_stringToHex(string, *hex, *size);
			if(!result)
			{
				*hex = (PBYTE) LocalFree(*hex);
				*size = 0;
			}
		}
	}
	return result;
}

PCWCHAR WPRINTF_TYPES[] =
{
	L"%02x",		// WPRINTF_HEX_SHORT
	L"%02x ",		// WPRINTF_HEX_SPACE
	L"0x%02x, ",	// WPRINTF_HEX_C
	L"\\x%02x",		// WPRINTF_HEX_PYTHON
};

void kull_m_string_wprintf_hex(LPCVOID lpData, DWORD cbData, DWORD flags)
{
	DWORD i, sep = flags >> 16;
	PCWCHAR pType = WPRINTF_TYPES[flags & 0x0000000f];

	if((flags & 0x0000000f) == 2)
		kprintf(L"\nBYTE data[] = {\n\t");

	for(i = 0; i < cbData; i++)
	{
		kprintf(pType, ((LPCBYTE) lpData)[i]);
		if(sep && !((i+1) % sep))
		{
			kprintf(L"\n");
			if((flags & 0x0000000f) == 2)
				kprintf(L"\t");
		}
	}
	if((flags & 0x0000000f) == 2)
		kprintf(L"\n};\n");
}

void kull_m_string_displayFileTime(IN PFILETIME pFileTime)
{
	SYSTEMTIME st;
	wchar_t buffer[0xff];
	if(pFileTime)
	{
		if(FileTimeToSystemTime(pFileTime, &st ))
		{
			if(GetDateFormat(LOCALE_USER_DEFAULT, 0, &st, NULL, buffer, ARRAYSIZE(buffer)))
			{
				kprintf(L"%s ", buffer);
				if(GetTimeFormat(LOCALE_USER_DEFAULT, 0, &st, NULL, buffer, ARRAYSIZE(buffer)))
					kprintf(L"%s", buffer);
			}
		}
	}
}

void kull_m_string_displayLocalFileTime(IN PFILETIME pFileTime)
{
	FILETIME ft;
	if(pFileTime)
		if(FileTimeToLocalFileTime(pFileTime, &ft))
			kull_m_string_displayFileTime(&ft);
}

BOOL kull_m_string_FileTimeToString(IN PFILETIME pFileTime, OUT WCHAR string[14 + 1])
{
	BOOL status = FALSE;
	FILETIME ft;
	SYSTEMTIME st;
	if(pFileTime)
		if(FileTimeToLocalFileTime(pFileTime, &ft))
			if(FileTimeToSystemTime(&ft, &st))
				if(GetDateFormat(LOCALE_USER_DEFAULT, 0, &st, L"yyyyMMdd", string, 8 + 1))
					status = GetTimeFormat(LOCALE_USER_DEFAULT, 0, &st, L"HHmmss", string + 8, 6 + 1);
	return status;
}

void kull_m_string_displayGUID(IN LPCGUID pGuid)
{
	UNICODE_STRING uString;
	if(NT_SUCCESS(RtlStringFromGUID(pGuid, &uString)))
	{
		kprintf(L"%wZ", &uString);
		RtlFreeUnicodeString(&uString);
	}
}

void kull_m_string_displaySID(IN PSID pSid)
{
	LPWSTR stringSid;
	if(ConvertSidToStringSid(pSid, &stringSid))
	{
		kprintf(L"%s", stringSid);
		LocalFree(stringSid);
	}
	else PRINT_ERROR_AUTO(L"ConvertSidToStringSid");
}
#ifndef MIMIKATZ_W2000_SUPPORT
PWSTR kull_m_string_getRandomGUID()
{
	UNICODE_STRING uString;
	GUID guid;
	PWSTR buffer = NULL;
	if(NT_SUCCESS(UuidCreate(&guid)))
	{
		if(NT_SUCCESS(RtlStringFromGUID(&guid, &uString)))
		{
			if(buffer = (PWSTR) LocalAlloc(LPTR, uString.MaximumLength))
				RtlCopyMemory(buffer, uString.Buffer, uString.MaximumLength);
			RtlFreeUnicodeString(&uString);
		}
	}
	return buffer;
}
#endif
void kull_m_string_ptr_replace(PVOID ptr, DWORD64 size)
{
	PVOID tempPtr = NULL;
	if(size)
		if(tempPtr = LocalAlloc(LPTR, (SIZE_T) size))
			RtlCopyMemory(tempPtr, *(PVOID *) ptr, (size_t) size);
	*(PVOID *) ptr = tempPtr;
}

BOOL kull_m_string_args_byName(const int argc, const wchar_t * argv[], const wchar_t * name, const wchar_t ** theArgs, const wchar_t * defaultValue)
{
	BOOL result = FALSE;
	const wchar_t *pArgName, *pSeparator;
	SIZE_T argLen, nameLen = wcslen(name);
	int i;
	for(i = 0; i < argc; i++)
	{
		if((wcslen(argv[i]) > 1) && ((argv[i][0] == L'/') || (argv[i][0] == L'-')))
		{
			pArgName = argv[i] + 1;
			if(!(pSeparator = wcschr(argv[i], L':')))
				pSeparator = wcschr(argv[i], L'=');

			argLen =  (pSeparator) ? (pSeparator - pArgName) : wcslen(pArgName);
			if((argLen == nameLen) && _wcsnicmp(name, pArgName, argLen) == 0)
			{
				if(theArgs)
				{
					if(pSeparator)
					{
						*theArgs = pSeparator + 1;
						result = *theArgs[0] != L'\0';
					}
				}
				else
					result = TRUE;
				break;
			}
		}
	}
	if(!result && theArgs)
	{
		if(defaultValue)
		{
			*theArgs = defaultValue;
			result = TRUE;
		}
		else *theArgs = NULL;
	}
	return result;
}

BOOL kull_m_string_args_bool_byName(int argc, wchar_t * argv[], LPCWSTR name, PBOOL value) // TRUE when name exist (not value related)
{
	BOOL status = FALSE;
	LPCWSTR szData;
	if(status = kull_m_string_args_byName(argc, argv, name, &szData, NULL))
	{
		if((_wcsicmp(szData, L"on") == 0) || (_wcsicmp(szData, L"true") == 0) || (_wcsicmp(szData, L"1") == 0))
			*value = TRUE;
		else if((_wcsicmp(szData, L"off") == 0) || (_wcsicmp(szData, L"false") == 0) || (_wcsicmp(szData, L"0") == 0))
			*value = FALSE;
		else PRINT_ERROR(L"%s argument need on/true/1 or off/false/0\n", name);
	}
	return status;
}

BOOL kull_m_string_copy(LPWSTR *dst, LPCWSTR src)
{
	BOOL status = FALSE;
	size_t size;
	if(src && dst && (size = wcslen(src)))
	{
		size = (size + 1) * sizeof(wchar_t);
		if(*dst = (LPWSTR) LocalAlloc(LPTR, size))
		{
			RtlCopyMemory(*dst, src, size);
			status = TRUE;
		}
	}
	return status;
}

BOOL kull_m_string_copyA(LPSTR *dst, LPCSTR src)
{
	BOOL status = FALSE;
	size_t size;
	if(src && dst && (size = strlen(src)))
	{
		size = (size + 1) * sizeof(char);
		if(*dst = (LPSTR) LocalAlloc(LPTR, size))
		{
			RtlCopyMemory(*dst, src, size);
			status = TRUE;
		}
	}
	return status;
}

BOOL kull_m_string_quickxml_simplefind(LPCWSTR xml, LPCWSTR node, LPWSTR *dst)
{
	BOOL status = FALSE;
	DWORD lenNode, lenBegin, lenEnd;
	LPWSTR begin, end, curBeg, curEnd;
	lenNode = (DWORD) wcslen(node) * sizeof(wchar_t);
	lenBegin = lenNode + 3 * sizeof(wchar_t);
	lenEnd = lenNode + 4 * sizeof(wchar_t);
	if(begin = (LPWSTR) LocalAlloc(LPTR, lenBegin))
	{
		if(end = (LPWSTR) LocalAlloc(LPTR, lenEnd))
		{
			begin[0] = end[0] = L'<';
			end[1] = L'/';
			begin[lenBegin / sizeof(wchar_t) - 2] = end[lenEnd / sizeof(wchar_t) - 2] = L'>';
			RtlCopyMemory(begin + 1, node, lenNode);
			RtlCopyMemory(end + 2, node, lenNode);
			if(curBeg = wcsstr(xml, begin))
			{
				curBeg += lenBegin / sizeof(wchar_t) - 1;
				if(curEnd = wcsstr(curBeg, end))
				{
					if(status = (curBeg <= curEnd))
					{
						lenNode = (DWORD) (curEnd - curBeg) * sizeof(wchar_t);
						if((*dst) = (LPWSTR) LocalAlloc(LPTR, lenNode + sizeof(wchar_t)))
						{
							RtlCopyMemory(*dst, curBeg, lenNode);
						}
					}
				}
			}
			LocalFree(end);
		}
		LocalFree(begin);
	}
	return status;
}
#ifndef MIMIKATZ_W2000_SUPPORT
BOOL kull_m_string_quick_base64_to_Binary(PCWSTR base64, PBYTE *data, DWORD *szData)
{
	BOOL status = FALSE;
	*data = NULL;
	*szData = 0;
	if(CryptStringToBinary(base64, 0, CRYPT_STRING_BASE64, NULL, szData, NULL, NULL))
	{
		if(*data = (PBYTE) LocalAlloc(LPTR, *szData))
		{
			status = CryptStringToBinary(base64, 0, CRYPT_STRING_BASE64, *data, szData, NULL, NULL);
			if(!status)
				*data = (PBYTE) LocalFree(*data);
		}
	}
	return status;
}
#endif

BOOL kull_m_string_sprintf(PWSTR *outBuffer, PCWSTR format, ...)
{
	BOOL status = FALSE;
	int varBuf;
	va_list args;
	va_start(args, format);
	varBuf = _vscwprintf(format, args);
	if(varBuf > 0)
	{
		varBuf++;
		if(*outBuffer = (PWSTR) LocalAlloc(LPTR, varBuf * sizeof(wchar_t)))
		{
			varBuf = vswprintf_s(*outBuffer, varBuf, format, args);
			if(varBuf > 0)
				status = TRUE;
			else *outBuffer = (PWSTR) LocalFree(outBuffer);
		}
	}
	return status;
}

const KIWI_DATETIME_FORMATS STRING_TO_FILETIME_FORMATS[] = {
	{L"%hu/%hu/%hu %hu:%hu:%hu",	4,	1, 2, 3, 4, 5, 6}, // 2014/12/31 12(:34:56)
	{L"%hu/%hu/%hu %hu:%hu:%hu",	4,	3, 2, 1, 4, 5, 6}, // 31/12/2014 12(:34:56)
	{L"%hu-%hu-%hu %hu:%hu:%hu",	4,	1, 2, 3, 4, 5, 6}, // 2014-12-31 12(:34:56)

	{L"%hu/%hu %hu:%hu:%hu",	3,	0, 2, 1, 3, 4, 5}, // 12/2014 12(:34:56)
	{L"%hu-%hu %hu:%hu:%hu",	3,	0, 1, 2, 3, 4, 5}, // 12-31 12(:34:56)
	{L"%hu %hu:%hu:%hu",	2,	0, 0, 1, 2, 3, 4}, // 31 12(:34:56)

	{L"%hu:%hu:%hu",	2,	0, 0, 0, 1, 2, 3}, // 12:34(:56)
	
	{L"%hu/%hu/%hu",	2,	1, 2, 3, 0, 0, 0}, // 2014/12(/31)
	{L"%hu/%hu/%hu",	2,	3, 2, 1, 0, 0, 0}, // 31/12(/2014)
	{L"%hu-%hu-%hu",	2,	1, 2, 3, 0, 0, 0}, // 2014-12(-31)
	
	{L"%hu/%hu",	2,	2, 1, 0, 0, 0, 0}, // 12/2014
	{L"%hu-%hu",	2,	0, 1, 2, 0, 0, 0}, // 12-31
};

BOOL kull_m_string_stringToFileTime(LPCWSTR string, PFILETIME filetime)
{
	BOOL status = FALSE;
	const KIWI_DATETIME_FORMATS * cur;
	SYSTEMTIME st;
	FILETIME ft, lft;
	LONGLONG diff;
	WORD i, data[6] = {0};
	int ret;
	
	for(i = 0; (i < ARRAYSIZE(STRING_TO_FILETIME_FORMATS)) && !status; i++)
	{
		cur = STRING_TO_FILETIME_FORMATS + i;
		RtlZeroMemory(data, sizeof(data));
		ret = swscanf_s(string, cur->format, data + 0, data + 1, data + 2, data + 3, data + 4, data + 5);

		if(ret >=cur->minFields)
		{
			if(cur->idxYear && (cur->idxYear <= ret))
			{
				status = data[cur->idxYear - 1] >= 1900;
				if(!status)
					continue;
			}
			
			if(cur->idxMonth && (cur->idxMonth <= ret))
			{
				status = data[cur->idxMonth - 1] <= 12;
				if(!status)
					continue;
			}

			if(cur->idxDay && (cur->idxDay <= ret))
			{
				status = data[cur->idxDay - 1] <= 31;
				if(!status)
					continue;
			}

			if(cur->idxHour && (cur->idxHour <= ret))
			{
				status = data[cur->idxHour - 1] <= 23;
				if(!status)
					continue;
			}

			if(cur->idxMinute && (cur->idxMinute <= ret))
			{
				status = data[cur->idxMinute - 1] <= 59;
				if(!status)
					continue;
			}

			if(cur->idxSecond && (cur->idxSecond <= ret))
			{
				status = data[cur->idxSecond - 1] <= 59;
				if(!status)
					continue;
			}
		}
	}

	if(status)
	{
		status = FALSE;
		i--;
		GetSystemTimeAsFileTime(&ft);
		if(FileTimeToLocalFileTime(&ft, &lft))
		{
			diff = *((PULONGLONG) &lft) - *((PULONGLONG) &ft);
			if(FileTimeToSystemTime(&lft, &st))
			{
				st.wDayOfWeek = 0;
				st.wMilliseconds = 0;

				if(cur->idxYear && (cur->idxYear <= ret))
					st.wYear = data[cur->idxYear - 1];
				if(cur->idxMonth && (cur->idxMonth <= ret))
					st.wMonth = data[cur->idxMonth - 1];
				if(cur->idxDay && (cur->idxDay <= ret))
					st.wDay = data[cur->idxDay - 1];
				if(cur->idxHour && (cur->idxHour <= ret))
					st.wHour = data[cur->idxHour - 1];
				if(cur->idxMinute && (cur->idxMinute <= ret))
					st.wMinute = data[cur->idxMinute - 1];
				if(cur->idxSecond && (cur->idxSecond <= ret))
					st.wSecond = data[cur->idxSecond - 1];

				if(status = SystemTimeToFileTime(&st, &ft))
				{
					*((PULONGLONG) &ft) -= diff;
					*filetime = ft;
				}
			}
		}

	}
	return status;
}