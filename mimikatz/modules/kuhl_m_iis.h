/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_crypto.h"
#include "../modules/kull_m_xml.h"
#include "../modules/kull_m_file.h"

const KUHL_M kuhl_m_iis;

NTSTATUS kuhl_m_iis_apphost(int argc, wchar_t * argv[]);


typedef enum _IISXMLType {
	IISXMLType_Providers,
	IISXMLType_ApplicationPools,
	IISXMLType_Sites,
} IISXMLType;

void kuhl_m_iis_apphost_genericEnumNodes(int argc, wchar_t * argv[], IXMLDOMDocument *pXMLDom, PCWSTR path, IISXMLType xmltype, LPCWSTR provider, LPCBYTE data, DWORD szData);
BOOL kuhl_m_iis_apphost_provider(int argc, wchar_t * argv[], IXMLDOMDocument *pXMLDom, IXMLDOMNode *pNode, LPCWSTR provider, LPCBYTE data, DWORD szData);
void kuhl_m_iis_apphost_apppool(int argc, wchar_t * argv[], IXMLDOMDocument *pXMLDom, IXMLDOMNode *pNode);
void kuhl_m_iis_apphost_site(int argc, wchar_t * argv[], IXMLDOMDocument *pXMLDom, IXMLDOMNode *pNode);

void kuhl_m_iis_maybeEncrypted(int argc, wchar_t * argv[], IXMLDOMDocument *pXMLDom, PCWSTR password);
void kuhl_m_iis_apphost_provider_decrypt(int argc, wchar_t * argv[], PCWSTR keyContainerName, BOOL isMachine, LPCBYTE sessionKey, DWORD szSessionKey, LPCBYTE data, DWORD szData);