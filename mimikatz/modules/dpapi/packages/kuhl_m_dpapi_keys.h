/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "../kuhl_m_dpapi.h"
#include "../modules/kull_m_key.h"

#define PRINTHEX(data, len) kull_m_string_wprintf_hex(data, len, 1 | (16 << 16)); kprintf(L"\n")

NTSTATUS kuhl_m_dpapi_keys_test(int argc, wchar_t * argv[]);