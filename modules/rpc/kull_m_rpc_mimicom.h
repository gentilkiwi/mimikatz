#pragma once
#include "kull_m_rpc.h"

typedef void *MIMI_HANDLE;

NTSTATUS SRV_MimiBind(handle_t rpc_handle, PMIMI_PUBLICKEY clientPublicKey, PMIMI_PUBLICKEY serverPublicKey, MIMI_HANDLE *phMimi);
NTSTATUS SRV_MiniUnbind(MIMI_HANDLE *phMimi);
NTSTATUS SRV_MimiCommand(MIMI_HANDLE phMimi, DWORD szEncCommand, BYTE *encCommand, DWORD *szEncResult, BYTE **encResult);

NTSTATUS CLI_MimiBind(handle_t rpc_handle, PMIMI_PUBLICKEY clientPublicKey, PMIMI_PUBLICKEY serverPublicKey, MIMI_HANDLE *phMimi);
NTSTATUS CLI_MiniUnbind(MIMI_HANDLE *phMimi);
NTSTATUS CLI_MimiCommand(MIMI_HANDLE phMimi, DWORD szEncCommand, BYTE *encCommand, DWORD *szEncResult, BYTE **encResult);

void __RPC_USER SRV_MIMI_HANDLE_rundown(MIMI_HANDLE phMimi);
extern RPC_IF_HANDLE MimiCom_v1_0_c_ifspec, MimiCom_v1_0_s_ifspec;