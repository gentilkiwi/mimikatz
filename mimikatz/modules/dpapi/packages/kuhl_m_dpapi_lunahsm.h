/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_dpapi.h"

NTSTATUS kuhl_m_dpapi_lunahsm(int argc, wchar_t * argv[]);

void kuhl_m_dpapi_safenet_ksp_registryparser(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hBase, int argc, wchar_t * argv[]);
void kuhl_m_dpapi_safenet_ksp_registry_user_parser(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hEntry, BYTE entropy[MD5_DIGEST_LENGTH], int argc, wchar_t * argv[]);

void kuhl_m_dpapi_safenet_ksp_entropy(IN LPCSTR identity, OUT BYTE entropy[MD5_DIGEST_LENGTH]);
LPSTR kuhl_m_dpapi_safenet_pk_password(IN LPCSTR server);