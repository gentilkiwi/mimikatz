/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../modules/kull_m_process.h"

const KUHL_M kuhl_m_privilege;

NTSTATUS kuhl_m_privilege_debug(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_privilege_simple(ULONG privId);

#define SE_CREATE_TOKEN				2
#define SE_ASSIGNPRIMARYTOKEN		3
#define SE_LOCK_MEMORY				4
#define SE_INCREASE_QUOTA			5
//#define SE_UNSOLICITED_INPUT
//#define SE_MACHINE_ACCOUNT
#define SE_TCB						7
#define SE_SECURITY					8
#define SE_TAKE_OWNERSHIP			9
#define SE_LOAD_DRIVER				10
//#define SE_SYSTEM_PROFILE
//#define SE_SYSTEMTIME
//#define SE_PROF_SINGLE_PROCESS
//#define SE_INC_BASE_PRIORITY
//#define SE_CREATE_PAGEFILE
//#define SE_CREATE_PERMANENT
#define SE_BACKUP					17
#define SE_RESTORE					18
//#define SE_SHUTDOWN
#define SE_DEBUG					20
#define SE_AUDIT					21
#define SE_SYSTEM_ENVIRONMENT		22
//#define SE_CHANGE
//#define SE_REMOTE_SHUTDOWN
//#define SE_UNDOCK
//#define SE_SYNC_AGENT
#define SE_ENABLE_DELEGATION		27
//#define SE_MANAGE_VOLUME
#define SE_IMPERSONATE				29
//#define SE_CREATE_GLOBAL
//#define SE_TRUSTED_CREDMAN_ACCESS
//#define SE_RELABEL
//#define SE_INC_WORKING_SET
//#define SE_TIME_ZONE
//#define SE_CREATE_SYMBOLIC_LINK