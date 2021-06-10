/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m_sekurlsa_utils.h"
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

typedef struct _KULL_M_RPC_FCNSTRUCT {
	PVOID addr;
	size_t size;
} KULL_M_RPC_FCNSTRUCT, *PKULL_M_RPC_FCNSTRUCT;

void __RPC_FAR * __RPC_USER midl_user_allocate(size_t cBytes);
void __RPC_USER midl_user_free(void __RPC_FAR * p);
void __RPC_USER ReadFcn(void *State, char **pBuffer, unsigned int *pSize);

typedef void (* PGENERIC_RPC_DECODE) (IN handle_t pHandle, IN PVOID pObject);
typedef void (* PGENERIC_RPC_FREE) (IN handle_t pHandle, IN PVOID pObject);

BOOL kull_m_rpc_Generic_Decode(PVOID data, DWORD size, PVOID pObject, PGENERIC_RPC_DECODE fDecode);
void kull_m_rpc_Generic_Free(PVOID data, PGENERIC_RPC_FREE fFree);