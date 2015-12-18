/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_net.h"
#include "../modules/kull_m_token.h"
#include "../modules/kull_m_samlib.h"
#include "../modules/kull_m_string.h"

const KUHL_M kuhl_m_net;

NTSTATUS kuhl_m_net_user(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_group(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_localgroup(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_net_autoda(int argc, wchar_t * argv[]);