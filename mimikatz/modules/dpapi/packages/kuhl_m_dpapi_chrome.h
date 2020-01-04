/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_dpapi.h"
#include "../modules/sqlite3.h"

NTSTATUS kuhl_m_dpapi_chrome(int argc, wchar_t * argv[]);
BOOL kuhl_m_dpapi_chrome_isTableExist(sqlite3 *pDb, const char *table);