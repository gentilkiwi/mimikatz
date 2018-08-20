/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_xml.h"

IXMLDOMDocument * kull_m_xml_CreateAndInitDOM()
{
	IXMLDOMDocument *pDoc = NULL;
	HRESULT hr = CoCreateInstance(&CLSID_DOMDocument, NULL, CLSCTX_INPROC_SERVER, &IID_IXMLDOMDocument, (void **) &pDoc);
	if(hr == S_OK)
	{
		IXMLDOMDocument_put_async(pDoc, VARIANT_FALSE);  
		IXMLDOMDocument_put_validateOnParse(pDoc, VARIANT_FALSE);
		IXMLDOMDocument_put_resolveExternals(pDoc, VARIANT_FALSE);
		IXMLDOMDocument_put_preserveWhiteSpace(pDoc, VARIANT_FALSE);
	}
	else PRINT_ERROR(L"CoCreateInstance: 0x%08x\n", hr);
	return pDoc;
}

void kull_m_xml_ReleaseDom(IXMLDOMDocument *pDoc)
{
	if(pDoc)
		IXMLDOMDocument_Release(pDoc);
}

BOOL kull_m_xml_LoadXMLFile(IXMLDOMDocument *pXMLDom, PCWSTR filename)
{
	BOOL status = FALSE;
	VARIANT varFileName;
	VARIANT_BOOL varStatus;
	BSTR bFilename;
	HRESULT hr;
	if(filename)
	{
		if(bFilename = SysAllocString(filename))
		{
			VariantInit(&varFileName);
			V_VT(&varFileName) = VT_BSTR;
			V_BSTR(&varFileName) = bFilename;
			hr = IXMLDOMDocument_load(pXMLDom, varFileName, &varStatus);
			status = (hr == S_OK);
			if(!status)
				PRINT_ERROR(L"IXMLDOMDocument_load: 0x%08x\n", hr);
			SysFreeString(bFilename);
		}
	}
	return status;
}

BOOL kull_m_xml_SaveXMLFile(IXMLDOMDocument *pXMLDom, PCWSTR filename)
{
	BOOL status = FALSE;
	VARIANT varFileName;
	BSTR bFilename;
	HRESULT hr;
	if(filename)
	{
		if(bFilename = SysAllocString(filename))
		{
			VariantInit(&varFileName);
			V_VT(&varFileName) = VT_BSTR;
			V_BSTR(&varFileName) = bFilename;
			hr = IXMLDOMDocument_save(pXMLDom, varFileName);
			status = (hr == S_OK);
			if(!status)
				PRINT_ERROR(L"IXMLDOMDocument_save: 0x%08x\n", hr);
			SysFreeString(bFilename);
		}
	}
	return status;
}

wchar_t * kull_m_xml_getAttribute(IXMLDOMNode *pNode, PCWSTR name)
{
	wchar_t *result = NULL;
	IXMLDOMNamedNodeMap *map;
	IXMLDOMNode *nAttr;
	BSTR bstrGeneric;
	long length, i;
	BOOL isMatch = FALSE;

	if(IXMLDOMNode_get_attributes(pNode, &map) == S_OK)
	{
		if(IXMLDOMNamedNodeMap_get_length(map, &length) == S_OK)
		{
			for(i = 0; (i < length) && !isMatch; i++)
			{
				if(IXMLDOMNamedNodeMap_get_item(map, i, &nAttr) == S_OK)
				{
					if(IXMLDOMNode_get_nodeName(nAttr, &bstrGeneric) == S_OK)
					{
						isMatch = (_wcsicmp(name, bstrGeneric) == 0);
						SysFreeString(bstrGeneric);
						if(isMatch)
						{
							if(IXMLDOMNode_get_text(nAttr, &bstrGeneric) == S_OK)
							{
								kull_m_string_copy(&result, bstrGeneric);
								SysFreeString(bstrGeneric);
							}
						}
					}
					IXMLDOMNode_Release(nAttr);
				}
			}
		}
		IXMLDOMNamedNodeMap_Release(map);
	}
	return result;
}

wchar_t * kull_m_xml_getTextValue(IXMLDOMNode *pNode, PCWSTR name)
{
	wchar_t *result = NULL;
	IXMLDOMNode *pSingleNode, *pChild;
	BSTR bstrGeneric;

	if((IXMLDOMNode_selectSingleNode(pNode, (BSTR) name, &pSingleNode) == S_OK) && pSingleNode)
	{
		if((IXMLDOMNode_get_firstChild(pSingleNode, &pChild) == S_OK) && pChild)
		{
			if(IXMLDOMNode_get_text(pChild, &bstrGeneric) == S_OK)
			{
				kull_m_string_copy(&result, bstrGeneric);
				SysFreeString(bstrGeneric);
			}

		}





	}
	return result;
}