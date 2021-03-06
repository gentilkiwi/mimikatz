/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi_powershell.h"

NTSTATUS kuhl_m_dpapi_powershell(int argc, wchar_t * argv[])
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
				if((IXMLDOMDocument_selectSingleNode(pXMLDom, (BSTR) L"//Objs/Obj", &pNode) == S_OK) && pNode)
				{
					if(kuhl_m_dpapi_powershell_check_against_one_type(pNode, L"System.Management.Automation.PSCredential") || kuhl_m_dpapi_powershell_check_against_one_type(pNode, L"System.Security.SecureString"))
						kuhl_m_dpapi_powershell_credential(pNode, argc, argv);
					else PRINT_ERROR(L"XML doesn't seem to be a PSCredential/SecureString\n");
				}
				else if((IXMLDOMDocument_selectSingleNode(pXMLDom, (BSTR) L"//Objs/SS", &pNode) == S_OK) && pNode)
					kuhl_m_dpapi_powershell_try_SecureString(pNode, argc, argv);
				else PRINT_ERROR(L"XML doesn't seem to be a SecureString\n");
			}
			kull_m_xml_ReleaseDom(pXMLDom);
		}
	}
	else PRINT_ERROR(L"Missing /in:credentials.xml\n");
	return STATUS_SUCCESS;
}

BOOL kuhl_m_dpapi_powershell_check_against_one_type(IXMLDOMNode *pObj, LPCWSTR TypeName)
{
	BOOL status = FALSE;
	IXMLDOMNode *pNode, *pT;
	IXMLDOMNodeList *pTs;
	DOMNodeType type;
	long lengthT, i;
	BSTR bstrGeneric;

	if((IXMLDOMDocument_selectSingleNode(pObj, (BSTR) L"TN", &pNode) == S_OK) && pNode)
	{
		if((IXMLDOMNode_selectNodes(pNode, L"T", &pTs) == S_OK) && pTs)
		{
			if(IXMLDOMNodeList_get_length(pTs, &lengthT) == S_OK)
			{
				for(i = 0; (i < lengthT) && !status; i++)
				{
					if((IXMLDOMNodeList_get_item(pTs, i, &pT) == S_OK) && pT)
					{
						if((IXMLDOMNode_get_nodeType(pT, &type) == S_OK) && (type == NODE_ELEMENT))
						{
							if(IXMLDOMNode_get_text(pT, &bstrGeneric) == S_OK)
							{
								status = !_wcsicmp(bstrGeneric, TypeName);
								SysFreeString(bstrGeneric);
							}
						}
						IXMLDOMNode_Release(pT);
					}
				}
			}
		}
		else PRINT_ERROR(L"No types\n");
	}
	else PRINT_ERROR(L"No TN\n");
	return status;
}

void kuhl_m_dpapi_powershell_try_SecureString(IXMLDOMNode *pObj, int argc, wchar_t * argv[])
{
	BOOL isSecureString = FALSE;
	BSTR bstrGeneric;
	LPBYTE data;
	LPVOID pDataOut;
	DWORD szData, dwDataOutLen;

	if(IXMLDOMNode_get_nodeName(pObj, &bstrGeneric) == S_OK)
	{
		isSecureString = !_wcsicmp(bstrGeneric, L"SS");
		SysFreeString(bstrGeneric);
		if(IXMLDOMNode_get_text(pObj, &bstrGeneric) == S_OK)
		{
			if(isSecureString)
			{
				if(kull_m_string_stringToHexBuffer(bstrGeneric, &data, &szData))
				{
					kull_m_dpapi_blob_quick_descr(0, data);
					if(kuhl_m_dpapi_unprotect_raw_or_blob(data, szData, NULL, argc, argv, NULL, 0, &pDataOut, &dwDataOutLen, NULL))
					{
						kprintf(L">> cleartext: %.*s\n", dwDataOutLen / sizeof(wchar_t), pDataOut);
						LocalFree(pDataOut);
					}
					LocalFree(data);
				}
			}
			else kprintf(L"%s\n", bstrGeneric);
			SysFreeString(bstrGeneric);
		}
	}
}

void kuhl_m_dpapi_powershell_credential(IXMLDOMNode *pObj, int argc, wchar_t * argv[])
{
	IXMLDOMNode *pNode, *pChild;
	IXMLDOMNodeList *pChilds;
	long listLength, i;
	DOMNodeType type;
	wchar_t *name;

	if((IXMLDOMDocument_selectSingleNode(pObj, (BSTR) L"Props", &pNode) == S_OK) && pNode)
	{
		if(IXMLDOMNode_get_childNodes(pNode, &pChilds) == S_OK)
		{
			if(IXMLDOMNodeList_get_length(pChilds, &listLength) == S_OK)
			{
				for(i = 0; i < listLength; i++)
				{
					if((IXMLDOMNodeList_get_item(pChilds, i, &pChild) == S_OK) && pChild)
					{
						if((IXMLDOMNode_get_nodeType(pChild, &type) == S_OK) && (type == NODE_ELEMENT))
						{
							if(name = kull_m_xml_getAttribute(pChild, L"N"))
							{
								kprintf(L"%s: ", name);
								LocalFree(name);
								kuhl_m_dpapi_powershell_try_SecureString(pChild, argc, argv);
							}
							else PRINT_ERROR(L"No NAME\n");
						}
						else PRINT_ERROR(L"Not ELEMENT\n");
						IXMLDOMNode_Release(pChild);
					}
				}
			}
			IXMLDOMNodeList_Release(pChilds);
		}
	}
	else PRINT_ERROR(L"No Props\n");
}