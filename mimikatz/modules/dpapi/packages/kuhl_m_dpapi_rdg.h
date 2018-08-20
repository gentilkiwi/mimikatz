/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_dpapi.h"
#include "../../../../modules/kull_m_xml.h"
#include "../../../../modules/kull_m_string.h"

NTSTATUS kuhl_m_dpapi_rdg(int argc, wchar_t * argv[]);

void kuhl_m_dpapi_rdg_Groups(DWORD level, IXMLDOMNode *pNode, int argc, wchar_t * argv[]);
void kuhl_m_dpapi_rdg_Servers(DWORD level, IXMLDOMNode *pNode, int argc, wchar_t * argv[]);
void kuhl_m_dpapi_rdg_LogonCredentials(DWORD level, IXMLDOMNode *pNode, int argc, wchar_t * argv[]);