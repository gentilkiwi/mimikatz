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

#include "midles.h"
#include <string.h>

typedef DWORD NET_API_STATUS;
typedef UNICODE_STRING RPC_UNICODE_STRING;

BOOL kull_m_rpc_createBinding(LPCWSTR ProtSeq, LPCWSTR NetworkAddr, LPCWSTR Endpoint, LPCWSTR Service, DWORD ImpersonationType, RPC_BINDING_HANDLE *hBinding, void (RPC_ENTRY * RpcSecurityCallback)(void *));
BOOL kull_m_rpc_deleteBinding(RPC_BINDING_HANDLE *hBinding);

typedef struct _KULL_M_RPC_FCNSTRUCT {
	PVOID addr;
	size_t size;
} KULL_M_RPC_FCNSTRUCT, *PKULL_M_RPC_FCNSTRUCT;

void __RPC_FAR * __RPC_USER midl_user_allocate(size_t cBytes);
void __RPC_USER midl_user_free(void __RPC_FAR * p);
void __RPC_USER ReadFcn(void *State, char **pBuffer, unsigned int *pSize);
void __RPC_USER WriteFcn(void *State, char *Buffer, unsigned int Size);
void __RPC_USER AllocFcn(void *State, char **pBuffer, unsigned int *pSize);

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

typedef void (* PGENERIC_RPC_DECODE) (IN handle_t pHandle, IN PVOID pObject);
typedef void (* PGENERIC_RPC_ENCODE) (IN handle_t pHandle, IN PVOID pObject);
typedef void (* PGENERIC_RPC_FREE) (IN handle_t pHandle, IN PVOID pObject);
typedef size_t (* PGENERIC_RPC_ALIGNSIZE) (IN handle_t pHandle, IN PVOID pObject);

BOOL kull_m_rpc_Generic_Decode(PVOID data, DWORD size, PVOID pObject, PGENERIC_RPC_DECODE function);
void kull_m_rpc_Generic_Free(PVOID data, PGENERIC_RPC_FREE function);
BOOL kull_m_rpc_Generic_Encode(PVOID pObject, PVOID *data, DWORD *size, PGENERIC_RPC_ENCODE fEncode, PGENERIC_RPC_ALIGNSIZE fAlignSize);