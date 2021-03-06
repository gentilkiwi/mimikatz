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
void kuhl_m_dpapi_chrome_decrypt(LPCVOID pData, DWORD dwData, BCRYPT_ALG_HANDLE hAlg, BCRYPT_KEY_HANDLE hKey, int argc, wchar_t * argv[], LPCWSTR type);
void kuhl_m_dpapi_chrome_free_alg_key(BCRYPT_ALG_HANDLE *hAlg, BCRYPT_KEY_HANDLE *hKey);
BOOL kuhl_m_dpapi_chrome_alg_key_from_raw(BYTE key[AES_256_KEY_SIZE], BCRYPT_ALG_HANDLE *hAlg, BCRYPT_KEY_HANDLE *hKey);
BOOL kuhl_m_dpapi_chrome_alg_key_from_b64(LPCWSTR base64, int argc, wchar_t * argv[], BCRYPT_ALG_HANDLE *hAlg, BCRYPT_KEY_HANDLE *hKey);
BOOL kuhl_m_dpapi_chrome_alg_key_from_file(LPCWSTR szState, BOOL forced, int argc, wchar_t * argv[], BCRYPT_ALG_HANDLE *hAlg, BCRYPT_KEY_HANDLE *hKey);
BOOL kuhl_m_dpapi_chrome_alg_key_from_auto(LPCWSTR szFile, int argc, wchar_t * argv[], BCRYPT_ALG_HANDLE *hAlg, BCRYPT_KEY_HANDLE *hKey);