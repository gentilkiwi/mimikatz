#pragma once
#include "kull_m_rpc.h"

const UUID EFSR_ObjectUUID;

typedef void *PEXIMPORT_CONTEXT_HANDLE;

long EfsRpcOpenFileRaw(handle_t binding_h, PEXIMPORT_CONTEXT_HANDLE *hContext, wchar_t *FileName, long Flags);
void EfsRpcCloseRaw(PEXIMPORT_CONTEXT_HANDLE *hContext);

extern RPC_IF_HANDLE efsrpc_v1_0_c_ifspec;