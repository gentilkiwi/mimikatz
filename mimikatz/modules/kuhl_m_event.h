/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_process.h"
#include "../modules/kull_m_service.h"
#include "../modules/kull_m_memory.h"
#include "../modules/kull_m_patch.h"

const KUHL_M kuhl_m_event;

NTSTATUS kuhl_m_event_drop(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_event_clear(int argc, wchar_t * argv[]);