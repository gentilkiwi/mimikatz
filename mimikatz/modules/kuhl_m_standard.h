/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../../modules/kull_m_string.h"
#include "../../modules/kull_m_file.h"
#include "../../modules/kull_m_process.h"
#include "../../modules/kull_m_net.h"
#include "../../modules/kull_m_cabinet.h"

const KUHL_M kuhl_m_standard;

NTSTATUS kuhl_m_standard_cls(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_exit(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_cite(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_answer(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_coffee(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_sleep(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_log(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_base64(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_version(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_cd(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_localtime(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_hostname(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_standard_test(int argc, wchar_t * argv[]);