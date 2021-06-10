/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_rpc_bkrp.h"

BOOL kull_m_rpc_bkrp_createBinding(LPCWSTR NetworkAddr, RPC_BINDING_HANDLE *hBinding)
{
	BOOL status = FALSE;
	LPWSTR szTmpDc = NULL;
	if(!NetworkAddr)
		if(kull_m_net_getDC(NULL, DS_WRITABLE_REQUIRED, &szTmpDc))
			NetworkAddr = szTmpDc;
	if(NetworkAddr)
		status = kull_m_rpc_createBinding(NULL, L"ncacn_np", NetworkAddr, L"\\pipe\\protected_storage", L"ProtectedStorage", TRUE, (MIMIKATZ_NT_MAJOR_VERSION < 6) ? RPC_C_AUTHN_GSS_KERBEROS : RPC_C_AUTHN_GSS_NEGOTIATE, NULL, RPC_C_IMP_LEVEL_IMPERSONATE, hBinding, NULL);
	if(szTmpDc)
		LocalFree(szTmpDc);
	return status;
}

BOOL kull_m_rpc_bkrp_generic(LPCWSTR NetworkAddr, const GUID * pGuid, PVOID DataIn, DWORD dwDataIn, PVOID *pDataOut, DWORD *pdwDataOut)
{
	BOOL status = FALSE;
	RPC_BINDING_HANDLE hBinding;
	NET_API_STATUS netStatus;
	PBYTE out = NULL;
	*pDataOut = NULL;
	*pdwDataOut = 0;
	if(kull_m_rpc_bkrp_createBinding(NetworkAddr, &hBinding))
	{
		RpcTryExcept
		{
			netStatus = BackuprKey(hBinding, (GUID *) pGuid, (PBYTE) DataIn, dwDataIn, &out, pdwDataOut, 0);
			if(status = (netStatus == 0))
			{
				if(*pDataOut = LocalAlloc(LPTR, *pdwDataOut))
					RtlCopyMemory(*pDataOut, out, *pdwDataOut);
				MIDL_user_free(out);
			}
			else PRINT_ERROR(L"BackuprKey: 0x%08x (%u)\n", netStatus, netStatus);
		}
		RpcExcept(RPC_EXCEPTION)
			PRINT_ERROR(L"RPC Exception: 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
		RpcEndExcept
			kull_m_rpc_deleteBinding(&hBinding);
	}
	return status;
}

BOOL kull_m_rpc_bkrp_Restore(LPCWSTR NetworkAddr, PVOID DataIn, DWORD dwDataIn, PVOID *pDataOut, DWORD *pdwDataOut)
{
	return kull_m_rpc_bkrp_generic(NetworkAddr, &BACKUPKEY_RESTORE_GUID, DataIn, dwDataIn, pDataOut, pdwDataOut);
}

BOOL kull_m_rpc_bkrp_Backup(LPCWSTR NetworkAddr, PVOID DataIn, DWORD dwDataIn, PVOID *pDataOut, DWORD *pdwDataOut)
{
	return kull_m_rpc_bkrp_generic(NetworkAddr, &BACKUPKEY_BACKUP_GUID, DataIn, dwDataIn, pDataOut, pdwDataOut);
}

BOOL kull_m_rpc_bkrp_BackupKey(LPCWSTR NetworkAddr, PVOID *pDataOut, DWORD *pdwDataOut)
{
	BYTE dataIn = 'k';
	return kull_m_rpc_bkrp_generic(NetworkAddr, &BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID, &dataIn, 0, pDataOut, pdwDataOut);
}