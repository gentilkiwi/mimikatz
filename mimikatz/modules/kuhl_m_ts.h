/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_patch.h"
#include "../modules/kull_m_service.h"
#include "../modules/kull_m_process.h"
#include "../modules/kull_m_memory.h"

const KUHL_M kuhl_m_ts;

NTSTATUS kuhl_m_ts_multirdp(int argc, wchar_t * argv[]);