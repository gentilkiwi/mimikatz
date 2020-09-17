/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "lsadump/kuhl_m_lsadump_dc.h"
#include "../../modules/kull_m_ldap.h"
#include "../../modules/kull_m_net.h"
#include "../../modules/kull_m_token.h"
#include "../../modules/rpc/kull_m_rpc_ms-dcom_IObjectExporter.h"
#include <WinDNS.h>

const KUHL_M kuhl_m_net;

NTSTATUS kuhl_m_net_user(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_group(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_alias(int argc, wchar_t * argv[]);

void kuhl_m_net_simpleLookup(SAMPR_HANDLE hDomainHandle, DWORD rid);

NTSTATUS kuhl_m_net_autoda(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_session(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_wsession(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_tod(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_stats(int argc, wchar_t * argv[]);

void kuhl_m_net_share_type(DWORD type);

NTSTATUS kuhl_m_net_share(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_serverinfo(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_net_trust(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_deleg(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_dcom_if(int argc, wchar_t * argv[]);