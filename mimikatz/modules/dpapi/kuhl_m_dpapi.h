/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "../kuhl_m.h"
#include "../modules/kull_m_file.h"
#include "../modules/kull_m_dpapi.h"

#include "kuhl_m_dpapi_oe.h"
#include "packages/kuhl_m_dpapi_keys.h"
#include "packages/kuhl_m_dpapi_creds.h"
#include "packages/kuhl_m_dpapi_wlan.h"
#include "packages/kuhl_m_dpapi_chrome.h"
#include "packages/kuhl_m_dpapi_ssh.h"
#include "packages/kuhl_m_dpapi_rdg.h"

const KUHL_M kuhl_m_dpapi;

NTSTATUS kuhl_m_dpapi_blob(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dpapi_protect(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dpapi_masterkey(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_dpapi_credhist(int argc, wchar_t * argv[]);

BOOL kuhl_m_dpapi_unprotect_raw_or_blob(LPCVOID pDataIn, DWORD dwDataInLen, LPWSTR *ppszDataDescr, int argc, wchar_t * argv[], LPCVOID pOptionalEntropy, DWORD dwOptionalEntropyLen, LPVOID *pDataOut, DWORD *dwDataOutLen, LPCWSTR pText);
void kuhl_m_dpapi_display_MasterkeyInfosAndFree(LPCGUID guid, PVOID data, DWORD dataLen, PSID sid);
void kuhl_m_dpapi_display_CredHist(PKULL_M_DPAPI_CREDHIST_ENTRY entry, LPCVOID ntlm, LPCVOID sha1);