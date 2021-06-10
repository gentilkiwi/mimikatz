/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_process.h"

const KUHL_M kuhl_m_privilege;

NTSTATUS kuhl_m_privilege_debug(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_privilege_driver(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_privilege_security(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_privilege_tcb(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_privilege_backup(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_privilege_restore(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_privilege_sysenv(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_privilege_id(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_privilege_name(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_privilege_simple(ULONG privId);

#define SE_CREATE_TOKEN				2
#define SE_ASSIGNPRIMARYTOKEN		3
#define SE_LOCK_MEMORY				4
#define SE_INCREASE_QUOTA			5
#define SE_UNSOLICITED_INPUT		6
#define SE_TCB						7
#define SE_SECURITY					8
#define SE_TAKE_OWNERSHIP			9
#define SE_LOAD_DRIVER				10
#define SE_SYSTEM_PROFILE			11
#define SE_SYSTEMTIME				12
#define SE_PROF_SINGLE_PROCESS		13
#define SE_INC_BASE_PRIORITY		14
#define SE_CREATE_PAGEFILE			15
#define SE_CREATE_PERMANENT			16
#define SE_BACKUP					17
#define SE_RESTORE					18
#define SE_SHUTDOWN					19
#define SE_DEBUG					20
#define SE_AUDIT					21
#define SE_SYSTEM_ENVIRONMENT		22
#define SE_CHANGE_NOTIFY			23
#define SE_REMOTE_SHUTDOWN			24
#define SE_UNDOCK					25
#define SE_SYNC_AGENT				26
#define SE_ENABLE_DELEGATION		27
#define SE_MANAGE_VOLUME			28
#define SE_IMPERSONATE				29
#define SE_CREATE_GLOBAL			30
#define SE_TRUSTED_CREDMAN_ACCESS	31
#define SE_RELABEL					32
#define SE_INC_WORKING_SET			33
#define SE_TIME_ZONE				34
#define SE_CREATE_SYMBOLIC_LINK		35