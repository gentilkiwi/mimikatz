/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_ldap.h"
#include "../modules/kull_m_token.h"
#include "../modules/kull_m_service.h"
#include "../modules/kull_m_patch.h"

const KUHL_M kuhl_m_sid;

NTSTATUS kuhl_m_sid_lookup(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sid_query(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sid_modify(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sid_add(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sid_clear(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sid_patch(int argc, wchar_t * argv[]);

void kuhl_m_sid_displayMessage(PLDAP ld, PLDAPMessage pMessage);
BOOL kuhl_m_sid_quickSearch(int argc, wchar_t * argv[], BOOL needUnique, PCWCHAR system, PLDAP *ld, PLDAPMessage *pMessage);
PWCHAR kuhl_m_sid_filterFromArgs(int argc, wchar_t * argv[]);