/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_rpc_pac.h"

BOOL kuhl_m_pac_DecodeValidationInformation(PVOID data, DWORD size, PKERB_VALIDATION_INFO *pObject)
{
	BOOL status = FALSE;
	RPC_STATUS rpcStatus;
	KULL_M_RPC_FCNSTRUCT UserState = {data, size};
	handle_t pHandle;

	*pObject = NULL;
	rpcStatus = MesDecodeIncrementalHandleCreate(&UserState, ReadFcn, &pHandle);
	if(NT_SUCCESS(rpcStatus))
	{
		rpcStatus = MesIncrementalHandleReset(pHandle, NULL, NULL, NULL, NULL, MES_DECODE);
		if(NT_SUCCESS(rpcStatus))
		{
			RpcTryExcept
				PKERB_VALIDATION_INFO_Decode(pHandle, pObject);
			status = (*pObject != NULL);
			RpcExcept(RPC_EXCEPTION)
				PRINT_ERROR(L"RPC Exception 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
			RpcEndExcept
		}
		else PRINT_ERROR(L"MesIncrementalHandleReset: %08x\n", rpcStatus);
		MesHandleFree(pHandle);
	}
	else PRINT_ERROR(L"MesDecodeIncrementalHandleCreate: %08x\n", rpcStatus);
	return status;
}

void kuhl_m_pac_FreeValidationInformation(PKERB_VALIDATION_INFO *pObject)
{
	RPC_STATUS rpcStatus;
	handle_t pHandle;

	rpcStatus = MesDecodeIncrementalHandleCreate(NULL, NULL, &pHandle);
	if(NT_SUCCESS(rpcStatus))
	{
		PKERB_VALIDATION_INFO_Free(pHandle, pObject);
		*pObject = NULL;
		MesHandleFree(pHandle);
	}
	else PRINT_ERROR(L"MesDecodeIncrementalHandleCreate: %08x\n", rpcStatus);
}

BOOL kuhl_m_pac_EncodeValidationInformation(PKERB_VALIDATION_INFO pObject, PVOID *data, DWORD *size)
{
	BOOL status = FALSE;
	RPC_STATUS rpcStatus;
	KULL_M_RPC_FCNSTRUCT UserState;
	handle_t pHandle;

	rpcStatus = MesEncodeIncrementalHandleCreate(&UserState, ReadFcn, WriteFcn, &pHandle);
	if(NT_SUCCESS(rpcStatus))
	{
		*size = (DWORD) PKERB_VALIDATION_INFO_AlignSize(pHandle, &pObject);
		if(*data = LocalAlloc(LPTR, *size))
		{
			rpcStatus = MesIncrementalHandleReset(pHandle, NULL, NULL, NULL, NULL, MES_ENCODE);
			if(NT_SUCCESS(rpcStatus))
			{
				UserState.addr = *data;
				UserState.size = *size;
				PKERB_VALIDATION_INFO_Encode(pHandle, &pObject);
				status = TRUE;
			}
			else PRINT_ERROR(L"MesIncrementalHandleReset: %08x\n", rpcStatus);

			if(!status)
			{
				*data = LocalFree(*data);
				*size = 0;
			}
		}
		MesHandleFree(pHandle);
	}
	else PRINT_ERROR(L"MesEncodeIncrementalHandleCreate: %08x\n", rpcStatus);
	return status;
}