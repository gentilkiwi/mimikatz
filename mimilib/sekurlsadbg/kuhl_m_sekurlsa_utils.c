/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sekurlsa_utils.h"

const char * PRINTF_TYPES[] =
{
	"%02x",		// WPRINTF_HEX_SHORT
	"%02x ",	// WPRINTF_HEX_SPACE
	"0x%02x, ",	// WPRINTF_HEX_C
	"\\x%02x",	// WPRINTF_HEX_PYTHON
};
void kull_m_string_dprintf_hex(LPCVOID lpData, DWORD cbData, DWORD flags)
{
	DWORD i, sep = flags >> 16;
	const char * pType = PRINTF_TYPES[flags & 0x0000000f];
	for(i = 0; i < cbData; i++)
	{
		dprintf(pType, ((LPCBYTE) lpData)[i]);
		if(sep && !((i+1) % sep))
			dprintf("\n");
	}
}

void kull_m_string_displayFileTime(IN PFILETIME pFileTime)
{
	SYSTEMTIME st;
	char buffer[0xff];
	if(pFileTime)
	{
		if(FileTimeToSystemTime(pFileTime, &st ))
		{
			if(GetDateFormatA(LOCALE_USER_DEFAULT, 0, &st, NULL, buffer, sizeof(buffer)))
			{
				dprintf("%s ", buffer);
				if(GetTimeFormatA(LOCALE_USER_DEFAULT, 0, &st, NULL, buffer, sizeof(buffer)))
					dprintf("%s", buffer);
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
		dprintf("%wZ", &uString);
		RtlFreeUnicodeString(&uString);
	}
}

void kull_m_string_displaySID(IN PSID pSid)
{
	LPSTR stringSid;
	if(ConvertSidToStringSidA(pSid, &stringSid))
	{
		dprintf("%s", stringSid);
		LocalFree(stringSid);
	}
}

BOOL kull_m_string_suspectUnicodeString(IN PUNICODE_STRING pUnicodeString)
{
	int unicodeTestFlags = IS_TEXT_UNICODE_ODD_LENGTH | IS_TEXT_UNICODE_STATISTICS;
	return IsTextUnicode(pUnicodeString->Buffer, pUnicodeString->Length, &unicodeTestFlags);
}

BOOL kull_m_string_getDbgUnicodeString(IN PUNICODE_STRING string)
{
	BOOL status = FALSE;
	ULONG_PTR buffer = (ULONG_PTR) string->Buffer;
	string->Buffer = NULL;
	if(buffer && string->MaximumLength)
	{
		if(string->Buffer = (PWSTR) LocalAlloc(LPTR, string->MaximumLength))
		{
			if(!(status = ReadMemory(buffer, string->Buffer, string->MaximumLength, NULL)))
			{
				LocalFree(string->Buffer);
				string->Buffer = NULL;
			}
		}
	}
	return status;
}

ULONG_PTR kuhl_m_sekurlsa_utils_pFromLinkedListByLuid(ULONG_PTR pSecurityStruct, ULONG LUIDoffset, PLUID luidToFind)
{
	PVOID buffer;
	ULONG_PTR resultat = 0, pStruct = 0;
	
	if(buffer = LocalAlloc(LPTR, LUIDoffset + sizeof(LUID)))
	{
		if(ReadMemory(pSecurityStruct, &pStruct, sizeof(PVOID), NULL))
		{
			while(pStruct != pSecurityStruct)
			{
				if(ReadMemory(pStruct, buffer, LUIDoffset + sizeof(LUID), NULL))
				{
					if(SecEqualLuid(luidToFind, (PLUID) ((PBYTE) buffer + LUIDoffset)))
					{
						resultat = pStruct;
						break;
					}
					pStruct = (ULONG_PTR) ((PLIST_ENTRY) buffer)->Flink;
				}
				else break;
			}
		}
		LocalFree(buffer);
	}
	return resultat;
}

ULONG_PTR kuhl_m_sekurlsa_utils_pFromAVLByLuid(ULONG_PTR pTable, ULONG LUIDoffset, PLUID luidToFind)
{
	ULONG_PTR resultat = 0;
	RTL_AVL_TABLE maTable;
	if(ReadMemory(pTable, &maTable, sizeof(RTL_AVL_TABLE), NULL))
	{
		pTable = (ULONG_PTR) maTable.BalancedRoot.RightChild;
		resultat = kuhl_m_sekurlsa_utils_pFromAVLByLuidRec(pTable, LUIDoffset, luidToFind);
	}
	return resultat;
}

ULONG_PTR kuhl_m_sekurlsa_utils_pFromAVLByLuidRec(ULONG_PTR pTable, ULONG LUIDoffset, PLUID luidToFind)
{
	ULONG_PTR resultat = 0;
	PVOID buffer;
	RTL_AVL_TABLE maTable;

	if(ReadMemory(pTable, &maTable, sizeof(RTL_AVL_TABLE), NULL))
	{
		if(pTable = (ULONG_PTR) maTable.OrderedPointer)
		{
			if(buffer = LocalAlloc(LPTR, LUIDoffset + sizeof(LUID)))
			{
				if(ReadMemory(pTable, buffer, LUIDoffset + sizeof(LUID), NULL))
				{
					if(SecEqualLuid(luidToFind, (PLUID) ((PBYTE) buffer + LUIDoffset)))
						resultat = (ULONG_PTR) maTable.OrderedPointer;
				}
				LocalFree(buffer);
			}
		}
		if(!resultat && (pTable = (ULONG_PTR) maTable.BalancedRoot.LeftChild))
			resultat = kuhl_m_sekurlsa_utils_pFromAVLByLuidRec(pTable, LUIDoffset, luidToFind);
		if(!resultat && (pTable = (ULONG_PTR) maTable.BalancedRoot.RightChild))
			resultat = kuhl_m_sekurlsa_utils_pFromAVLByLuidRec(pTable, LUIDoffset, luidToFind);
	}
	return resultat;
}

void kuhl_m_sekurlsa_utils_NlpMakeRelativeOrAbsoluteString(PVOID BaseAddress, PLSA_UNICODE_STRING String, BOOL relative)
{
	if(String->Buffer)
		String->Buffer = (PWSTR) ((ULONG_PTR)(String->Buffer) + ((relative ? -1 : 1) * (ULONG_PTR)(BaseAddress)));
}

BOOL kuhl_m_sekurlsa_utils_getSid(IN PSID * pSid)
{
	BOOL status = FALSE;
	BYTE nbAuth;
	DWORD sizeSid;
	ULONG_PTR buffer = (ULONG_PTR) *pSid;

	*pSid = NULL;
	if(ReadMemory(buffer + 1, &nbAuth, sizeof(BYTE), NULL))
	{
		sizeSid =  4 * nbAuth + 6 + 1 + 1;
		if(*pSid = LocalAlloc(LPTR, sizeSid))
			status = ReadMemory(buffer, *pSid, sizeSid, NULL);
	}
	return status;
}

PCSTR kuhl_m_kerberos_ticket_etype(LONG eType)
{
	PCSTR type;
	switch(eType)
	{
	case KERB_ETYPE_NULL:							type = "null             "; break;

	case KERB_ETYPE_DES_PLAIN:						type = "des_plain        "; break;
	case KERB_ETYPE_DES_CBC_CRC:					type = "des_cbc_crc      "; break;
	case KERB_ETYPE_DES_CBC_MD4:					type = "des_cbc_md4      "; break;
	case KERB_ETYPE_DES_CBC_MD5:					type = "des_cbc_md5      "; break;
	case KERB_ETYPE_DES_CBC_MD5_NT:					type = "des_cbc_md5_nt   "; break;

	case KERB_ETYPE_RC4_PLAIN:						type = "rc4_plain        "; break;
	case KERB_ETYPE_RC4_PLAIN2:						type = "rc4_plain2       "; break;
	case KERB_ETYPE_RC4_PLAIN_EXP:					type = "rc4_plain_exp    "; break;
	case KERB_ETYPE_RC4_LM:							type = "rc4_lm           "; break;
	case KERB_ETYPE_RC4_MD4:						type = "rc4_md4          "; break;
	case KERB_ETYPE_RC4_SHA:						type = "rc4_sha          "; break;
	case KERB_ETYPE_RC4_HMAC_NT:					type = "rc4_hmac_nt      "; break;
	case KERB_ETYPE_RC4_HMAC_NT_EXP:				type = "rc4_hmac_nt_exp  "; break;
	case KERB_ETYPE_RC4_PLAIN_OLD:					type = "rc4_plain_old    "; break;
	case KERB_ETYPE_RC4_PLAIN_OLD_EXP:				type = "rc4_plain_old_exp"; break;
	case KERB_ETYPE_RC4_HMAC_OLD:					type = "rc4_hmac_old     "; break;
	case KERB_ETYPE_RC4_HMAC_OLD_EXP:				type = "rc4_hmac_old_exp "; break;

	case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96_PLAIN:	type = "aes128_hmac_plain"; break;
	case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96_PLAIN:	type = "aes256_hmac_plain"; break;
	case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96:		type = "aes128_hmac      "; break;
	case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96:		type = "aes256_hmac      "; break;

	default:										type = "unknow           "; break;
	}
	return type;
}