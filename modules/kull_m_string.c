/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kull_m_string.h"

BOOL kull_m_string_suspectUnicodeStringStructure(IN PUNICODE_STRING pUnicodeString)
{
	return (
		pUnicodeString->Length &&
		!((pUnicodeString->Length & 1) || (pUnicodeString->MaximumLength & 1)) &&
		(pUnicodeString->Length < sizeof(wchar_t)*0xff) &&
		(pUnicodeString->Length <= pUnicodeString->MaximumLength) &&
		((pUnicodeString->MaximumLength - pUnicodeString->Length) < 4*sizeof(wchar_t)) &&
		pUnicodeString->Buffer
		);
}

BOOL kull_m_string_suspectUnicodeString(IN PUNICODE_STRING pUnicodeString)
{
	int unicodeTestFlags = IS_TEXT_UNICODE_STATISTICS;
	return ((pUnicodeString->Length == sizeof(wchar_t)) && IsCharAlphaNumeric(pUnicodeString->Buffer[0])) || IsTextUnicode(pUnicodeString->Buffer, pUnicodeString->Length, &unicodeTestFlags);
}

BOOL kull_m_string_getUnicodeString(IN PUNICODE_STRING string, IN PKULL_M_MEMORY_HANDLE source)
{
	BOOL status = FALSE;
	KULL_M_MEMORY_HANDLE hOwn = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aDestin = {NULL, &hOwn};
	KULL_M_MEMORY_ADDRESS aSource = {string->Buffer, source};
	
	string->Buffer = NULL;
	if(aSource.address && string->MaximumLength)
	{
		if(aDestin.address = LocalAlloc(LPTR, string->MaximumLength))
		{
			string->Buffer = (PWSTR) aDestin.address;
			status = kull_m_memory_copy(&aDestin, &aSource, string->MaximumLength);
		}
	}
	return status;
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

	for(i = 0; i < cbData; i++)
	{
		kprintf(pType, ((LPCBYTE) lpData)[i]);
		if(sep && !((i+1) % sep))
			kprintf(L"\n");
	}
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

	if(!result && theArgs && defaultValue)
	{
		*theArgs = defaultValue;
		result = TRUE;
	}

	return result;
}