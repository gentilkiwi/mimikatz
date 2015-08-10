#pragma once

#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif // __RPCNDR_H_VERSION__

typedef struct _RPC_UNICODE_STRING
{
	unsigned short Length;
	unsigned short MaximumLength;
	/* [length_is][size_is] */ WCHAR *Buffer;
} 	RPC_UNICODE_STRING, *PRPC_UNICODE_STRING;

extern RPC_IF_HANDLE __MIDL_itf_ms2Ddtyp_0000_0000_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_ms2Ddtyp_0000_0000_v0_0_s_ifspec;