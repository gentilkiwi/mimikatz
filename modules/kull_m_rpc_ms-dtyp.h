#pragma once
#include "kull_m_rpc.h"

typedef DWORD NET_API_STATUS;

typedef struct _RPC_UNICODE_STRING {
	unsigned short Length;
	unsigned short MaximumLength;
	WCHAR *Buffer;
} RPC_UNICODE_STRING, *PRPC_UNICODE_STRING;