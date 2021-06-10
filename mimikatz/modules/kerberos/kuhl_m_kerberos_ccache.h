/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m_kerberos.h"
#include "../modules/kull_m_file.h"

/* Info : https://www.gnu.org/software/shishi/manual/html_node/The-Credential-Cache-Binary-File-Format.html */

NTSTATUS kuhl_m_kerberos_ccache_enum(int argc, wchar_t * argv[], BOOL isInject, BOOL isSave);
NTSTATUS kuhl_m_kerberos_ccache_ptc(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_kerberos_ccache_list(int argc, wchar_t * argv[]);

void kuhl_m_kerberos_ccache_UnixTimeToFileTime(time_t t, LPFILETIME pft);
BOOL kuhl_m_kerberos_ccache_unicode_string(PBYTE *data, PUNICODE_STRING ustring);
BOOL kuhl_m_kerberos_ccache_externalname(PBYTE *data, PKERB_EXTERNAL_NAME * name, PUNICODE_STRING realm);
void kuhl_m_kerberos_ccache_skip_buffer(PBYTE *data);
void kuhl_m_kerberos_ccache_skip_struct_with_buffer(PBYTE *data);
wchar_t * kuhl_m_kerberos_ccache_generateFileName(const DWORD index, PKIWI_KERBEROS_TICKET ticket, LPCWSTR ext);