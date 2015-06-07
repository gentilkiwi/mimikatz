/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globals.h"
#include "../kuhl_m.h"
#include "../modules/kull_m_file.h"
#include "../modules/kull_m_dpapi.h"

const KUHL_M kuhl_m_dpapi;

NTSTATUS kuhl_m_dpapi_masterkeys(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dpapi_blob(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dpapi_protect(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dpapi_unprotect(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_dpapi_test(int argc, wchar_t * argv[]);