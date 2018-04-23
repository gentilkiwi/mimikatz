/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m.h"
#include <cardmod.h>
#include "../kuhl_m_crypto.h"
//#include "../../../modules/kull_m_crypto.h"

NTSTATUS kuhl_m_crypto_l_sc(int argc, wchar_t * argv[]);

void kuhl_m_crypto_l_mdr(LPCWSTR szMdr, SCARDCONTEXT ctxScard, SCARDHANDLE hScard, LPCWSTR szModel, LPCBYTE pbAtr, DWORD cbAtr);
DWORD kuhl_m_crypto_l_sc_provtypefromname(LPCWSTR szProvider);
PWSTR kuhl_m_crypto_l_sc_containerFromReader(LPCWSTR reader);