/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../mimikatz.h"
#include "../../modules/rpc/kull_m_rpc_mimicom.h"

const KUHL_M kuhl_m_rpc;

NTSTATUS kuhl_m_c_rpc_init();
NTSTATUS kuhl_m_c_rpc_clean();

NTSTATUS kuhl_m_rpc_server(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_rpc_connect(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_rpc_enum(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_rpc_close(int argc, wchar_t * argv[]);

NTSTATUS kuhl_m_rpc_do(wchar_t * input);

typedef struct _KUHL_M_RPC_SERVER_INF {
	PWSTR szProtSeq;
	PWSTR szEndpoint;
	PWSTR szService;
	BOOL publishMe;
	RPC_IF_HANDLE srvif;
	DWORD AuthnSvc;
	DWORD flags;
	RPC_IF_CALLBACK_FN *sec;
} KUHL_M_RPC_SERVER_INF, *PKUHL_M_RPC_SERVER_INF;


//DWORD WINAPI kuhl_m_rpc_server_start(LPVOID lpThreadParameter);