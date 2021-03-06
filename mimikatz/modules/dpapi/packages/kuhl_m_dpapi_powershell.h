/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_dpapi.h"
#include "../../../../modules/kull_m_xml.h"

NTSTATUS kuhl_m_dpapi_powershell(int argc, wchar_t * argv[]);

BOOL kuhl_m_dpapi_powershell_check_against_one_type(IXMLDOMNode *pObj, LPCWSTR TypeName);
void kuhl_m_dpapi_powershell_try_SecureString(IXMLDOMNode *pObj, int argc, wchar_t * argv[]);
void kuhl_m_dpapi_powershell_credential(IXMLDOMNode *pObj, int argc, wchar_t * argv[]);