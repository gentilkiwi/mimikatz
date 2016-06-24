/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif

#include <rpc.h>
#include <rpcndr.h>

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif // __RPCNDR_H_VERSION__

#include <string.h>
#include "kull_m_rpc_ms-dtyp.h"

BOOL kull_m_rpc_createBinding(LPCWSTR ProtSeq, LPCWSTR NetworkAddr, LPCWSTR Endpoint, LPCWSTR Service, DWORD ImpersonationType, RPC_BINDING_HANDLE *hBinding, void (RPC_ENTRY * RpcSecurityCallback)(void *));
BOOL kull_m_rpc_deleteBinding(RPC_BINDING_HANDLE *hBinding);

void __RPC_FAR * __RPC_USER midl_user_allocate(size_t cBytes);
void __RPC_USER midl_user_free(void __RPC_FAR * p);

#define RPC_EXCEPTION (RpcExceptionCode() != STATUS_ACCESS_VIOLATION) && \
	(RpcExceptionCode() != STATUS_DATATYPE_MISALIGNMENT) && \
	(RpcExceptionCode() != STATUS_PRIVILEGED_INSTRUCTION) && \
	(RpcExceptionCode() != STATUS_ILLEGAL_INSTRUCTION) && \
	(RpcExceptionCode() != STATUS_BREAKPOINT) && \
	(RpcExceptionCode() != STATUS_STACK_OVERFLOW) && \
	(RpcExceptionCode() != STATUS_IN_PAGE_ERROR) && \
	(RpcExceptionCode() != STATUS_ASSERTION_FAILURE) && \
	(RpcExceptionCode() != STATUS_STACK_BUFFER_OVERRUN) && \
	(RpcExceptionCode() != STATUS_GUARD_PAGE_VIOLATION)