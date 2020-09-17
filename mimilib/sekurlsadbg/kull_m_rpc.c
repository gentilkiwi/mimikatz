/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_rpc.h"

void __RPC_FAR * __RPC_USER midl_user_allocate(size_t cBytes)
{
	return LocalAlloc(LPTR, cBytes);
}

void __RPC_USER midl_user_free(void __RPC_FAR * p)
{
	LocalFree(p);
}

void __RPC_USER ReadFcn(void *State, char **pBuffer, unsigned int *pSize)
{
	*pBuffer = (char *) ((PKULL_M_RPC_FCNSTRUCT) State)->addr;
	((PKULL_M_RPC_FCNSTRUCT) State)->addr = *pBuffer + *pSize;
	((PKULL_M_RPC_FCNSTRUCT) State)->size -= *pSize;
}

BOOL kull_m_rpc_Generic_Decode(PVOID data, DWORD size, PVOID pObject, PGENERIC_RPC_DECODE fDecode)
{
	BOOL status = FALSE;
	RPC_STATUS rpcStatus;
	PVOID buffer;
	KULL_M_RPC_FCNSTRUCT UserState;
	handle_t pHandle;

	if(buffer = UserState.addr = LocalAlloc(LPTR, size))
	{
		UserState.size = size;
		RtlCopyMemory(UserState.addr, data, size); // avoid data alteration
		rpcStatus = MesDecodeIncrementalHandleCreate(&UserState, ReadFcn, &pHandle);
		if(NT_SUCCESS(rpcStatus))
		{
			rpcStatus = MesIncrementalHandleReset(pHandle, NULL, NULL, NULL, NULL, MES_DECODE);
			if(NT_SUCCESS(rpcStatus))
			{
				RpcTryExcept
				{
					fDecode(pHandle, pObject);
					status = TRUE;
				}
				RpcExcept(EXCEPTION_EXECUTE_HANDLER)
					dprintf("[ERROR] [RPC Decode] Exception 0x%08x: (%u)\n", RpcExceptionCode(), RpcExceptionCode());
				RpcEndExcept
			}
			else dprintf("[ERROR] [RPC Decode] MesIncrementalHandleReset: %08x\n", rpcStatus);
			MesHandleFree(pHandle);
		}
		else dprintf("[ERROR] [RPC Decode] MesDecodeIncrementalHandleCreate: %08x\n", rpcStatus);
		LocalFree(buffer);
	}
	return status;
}

void kull_m_rpc_Generic_Free(PVOID pObject, PGENERIC_RPC_FREE fFree)
{
	RPC_STATUS rpcStatus;
	KULL_M_RPC_FCNSTRUCT UserState = {NULL, 0};
	handle_t pHandle;

	rpcStatus = MesDecodeIncrementalHandleCreate(&UserState, ReadFcn, &pHandle); // for legacy
	if(NT_SUCCESS(rpcStatus))
	{
		RpcTryExcept
			fFree(pHandle, pObject);
		RpcExcept(EXCEPTION_EXECUTE_HANDLER)
			dprintf("[ERROR] [RPC Free] Exception 0x%08x: (%u)\n", RpcExceptionCode(), RpcExceptionCode());
		RpcEndExcept
		MesHandleFree(pHandle);
	}
	else dprintf("[ERROR] [RPC Free] MesDecodeIncrementalHandleCreate: %08x\n", rpcStatus);
}