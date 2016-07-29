/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_rpc.h"

void __RPC_FAR * __RPC_USER midl_user_allocate(size_t cBytes)
{
	void __RPC_FAR * ptr = NULL;
	if(ptr = malloc(cBytes))
		RtlZeroMemory(ptr, cBytes);
	return ptr;
}

void __RPC_USER midl_user_free(void __RPC_FAR * p)
{
	free(p);
}

void __RPC_USER ReadFcn(void *State, char **pBuffer, unsigned int *pSize)
{
	*pBuffer = (char *) ((PKULL_M_RPC_FCNSTRUCT) State)->addr;
	((PKULL_M_RPC_FCNSTRUCT) State)->addr = *pBuffer + *pSize;
	((PKULL_M_RPC_FCNSTRUCT) State)->size -= *pSize;
}

BOOL kull_m_rpc_Generic_Decode(PVOID data, DWORD size, PVOID pObject, PGENERIC_RPC_DECODE function)
{
	BOOL status = FALSE;
	RPC_STATUS rpcStatus;
	KULL_M_RPC_FCNSTRUCT UserState = {data, size};
	handle_t pHandle;

	rpcStatus = MesDecodeIncrementalHandleCreate(&UserState, ReadFcn, &pHandle);
	if(NT_SUCCESS(rpcStatus))
	{
		rpcStatus = MesIncrementalHandleReset(pHandle, NULL, NULL, NULL, NULL, MES_DECODE);
		if(NT_SUCCESS(rpcStatus))
		{
			RpcTryExcept
				function(pHandle, pObject);
				status = TRUE; //(*(PVOID *) pObject != NULL);
			RpcExcept(RPC_EXCEPTION)
				dprintf("[ERROR] [RPC Decode] Exception 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
			RpcEndExcept
		}
		else dprintf("[ERROR] [RPC Decode] MesIncrementalHandleReset: %08x\n", rpcStatus);
		MesHandleFree(pHandle);
	}
	else dprintf("[ERROR] [RPC Decode] MesDecodeIncrementalHandleCreate: %08x\n", rpcStatus);
	return status;
}

void kull_m_rpc_Generic_Free(PVOID pObject, PGENERIC_RPC_FREE function)
{
	RPC_STATUS rpcStatus;
	KULL_M_RPC_FCNSTRUCT UserState = {NULL, 0};
	handle_t pHandle;

	rpcStatus = MesDecodeIncrementalHandleCreate(&UserState, ReadFcn, &pHandle); // for legacy
	if(NT_SUCCESS(rpcStatus))
	{
		function(pHandle, pObject);
		MesHandleFree(pHandle);
	}
	else dprintf("[ERROR] [RPC Free] MesDecodeIncrementalHandleCreate: %08x\n", rpcStatus);
}