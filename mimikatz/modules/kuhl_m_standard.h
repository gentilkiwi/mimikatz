/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_string.h"

const KUHL_M kuhl_m_standard;

NTSTATUS kuhl_m_standard_cls(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_exit(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_cite(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_answer(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_sleep(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_log(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_version(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_standard_test(int argc, wchar_t * argv[]);