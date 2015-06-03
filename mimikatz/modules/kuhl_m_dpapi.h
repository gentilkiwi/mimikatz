/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_file.h"
#include "../modules/kull_m_dpapi.h"

const KUHL_M kuhl_m_dpapi;

NTSTATUS kuhl_m_dpapi_masterkeys(int argc, wchar_t * argv[]);