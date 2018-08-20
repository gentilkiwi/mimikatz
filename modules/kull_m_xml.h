/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <msxml2.h>
#include "kull_m_string.h"

IXMLDOMDocument * kull_m_xml_CreateAndInitDOM();
void kull_m_xml_ReleaseDom(IXMLDOMDocument *pDoc);

BOOL kull_m_xml_LoadXMLFile(IXMLDOMDocument *pXMLDom, PCWSTR filename);
BOOL kull_m_xml_SaveXMLFile(IXMLDOMDocument *pXMLDom, PCWSTR filename);

wchar_t * kull_m_xml_getAttribute(IXMLDOMNode *pNode, PCWSTR name);
wchar_t * kull_m_xml_getTextValue(IXMLDOMNode *pNode, PCWSTR name);