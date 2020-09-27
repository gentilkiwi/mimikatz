/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
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
#include "../kull_m_string.h"
#include "../kull_m_crypto.h"
#include "../kull_m_process.h"

typedef DWORD NET_API_STATUS;
typedef UNICODE_STRING RPC_UNICODE_STRING;

LPCWSTR KULL_M_RPC_AUTHNLEV[7];
LPCWSTR KULL_M_RPC_AUTHNSVC(DWORD AuthnSvc);
const SEC_WINNT_AUTH_IDENTITY KULL_M_RPC_NULLSESSION;

#define KULL_M_RPC_AUTH_IDENTITY_HANDLE_NULLSESSION ((RPC_AUTH_IDENTITY_HANDLE) &KULL_M_RPC_NULLSESSION)

BOOL kull_m_rpc_createBinding(LPCWSTR uuid, LPCWSTR ProtSeq, LPCWSTR NetworkAddr, LPCWSTR Endpoint, LPCWSTR Service, BOOL addServiceToNetworkAddr, DWORD AuthnSvc, RPC_AUTH_IDENTITY_HANDLE hAuth, DWORD ImpersonationType, RPC_BINDING_HANDLE *hBinding, void (RPC_ENTRY * RpcSecurityCallback)(void *));
BOOL kull_m_rpc_deleteBinding(RPC_BINDING_HANDLE *hBinding);
RPC_STATUS CALLBACK kull_m_rpc_nice_SecurityCallback(RPC_IF_HANDLE hInterface, void* pBindingHandle);
RPC_STATUS CALLBACK kull_m_rpc_nice_verb_SecurityCallback(RPC_IF_HANDLE hInterface, void* pBindingHandle);
void kull_m_rpc_getArgs(int argc, wchar_t * argv[], LPCWSTR *szRemote, LPCWSTR *szProtSeq, LPCWSTR *szEndpoint, LPCWSTR *szService, LPCWSTR szDefaultService, DWORD *AuthnSvc, DWORD defAuthnSvc, BOOL *isNullSession, SEC_WINNT_AUTH_IDENTITY *pAuthIdentity, GUID *altGuid, BOOL printIt);
PMIDL_STUB_DESC kull_m_rpc_find_stub(LPCWSTR szModuleName, const RPC_SYNTAX_IDENTIFIER *pInterfaceId);
BOOL kull_m_rpc_replace_first_routine_pair_direct(const GENERIC_BINDING_ROUTINE_PAIR *pOriginalBindingPair, const GENERIC_BINDING_ROUTINE_PAIR *pNewBindingPair);
BOOL kull_m_rpc_replace_first_routine_pair(LPCWSTR szModuleName, const RPC_SYNTAX_IDENTIFIER *pInterfaceId, const GENERIC_BINDING_ROUTINE_PAIR *pNewBindingPair, PGENERIC_BINDING_ROUTINE_PAIR pOriginalBindingPair, const GENERIC_BINDING_ROUTINE_PAIR **ppOriginalBindingPair);

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

BOOL kull_m_rpc_Generic_Decode(PVOID data, DWORD size, PVOID pObject, PGENERIC_RPC_DECODE fDecode);
void kull_m_rpc_Generic_Free(PVOID data, PGENERIC_RPC_FREE fFree);
BOOL kull_m_rpc_Generic_Encode(PVOID pObject, PVOID *data, DWORD *size, PGENERIC_RPC_ENCODE fEncode, PGENERIC_RPC_ALIGNSIZE fAlignSize);