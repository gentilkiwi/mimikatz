/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_rpc.h"

BOOL kull_m_rpc_createBinding(LPCWSTR ProtSeq, LPCWSTR NetworkAddr, LPCWSTR Endpoint, LPCWSTR Service, DWORD ImpersonationType, RPC_BINDING_HANDLE *hBinding, void (RPC_ENTRY * RpcSecurityCallback)(void *))
{
	BOOL status = FALSE;
	RPC_STATUS rpcStatus;
	RPC_WSTR StringBinding = NULL;
	RPC_SECURITY_QOS SecurityQOS = {RPC_C_SECURITY_QOS_VERSION, RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH, RPC_C_QOS_IDENTITY_STATIC, ImpersonationType};
	LPWSTR fullServer;
	DWORD szServer = (DWORD) (wcslen(NetworkAddr) * sizeof(wchar_t)), szPrefix = (DWORD) (wcslen(Service) * sizeof(wchar_t));

	*hBinding = NULL;
	rpcStatus = RpcStringBindingCompose(NULL, (RPC_WSTR) ProtSeq, (RPC_WSTR) NetworkAddr, (RPC_WSTR) Endpoint, NULL, &StringBinding);
	if(rpcStatus == RPC_S_OK)
	{
		rpcStatus = RpcBindingFromStringBinding(StringBinding, hBinding);
		if(rpcStatus == RPC_S_OK)
		{
			if(*hBinding)
			{
				if(fullServer = (LPWSTR) LocalAlloc(LPTR, szPrefix + sizeof(wchar_t) + szServer + sizeof(wchar_t)))
				{
					RtlCopyMemory(fullServer, Service, szPrefix);
					RtlCopyMemory((PBYTE) fullServer + szPrefix + sizeof(wchar_t), NetworkAddr, szServer);
					((PBYTE) fullServer)[szPrefix] = L'/';
					rpcStatus = RpcBindingSetAuthInfoEx(*hBinding, (RPC_WSTR) fullServer, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, (MIMIKATZ_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_VISTA) ? RPC_C_AUTHN_GSS_KERBEROS : RPC_C_AUTHN_GSS_NEGOTIATE, NULL, 0, &SecurityQOS);
					if(rpcStatus == RPC_S_OK)
					{
						if(RpcSecurityCallback)
						{
							rpcStatus = RpcBindingSetOption(*hBinding, RPC_C_OPT_SECURITY_CALLBACK, (ULONG_PTR) RpcSecurityCallback);
							status = (rpcStatus == RPC_S_OK);
							if(!status)
								PRINT_ERROR(L"RpcBindingSetOption: 0x%08x (%u)\n", rpcStatus, rpcStatus);
						}
						else status = TRUE;
					}
					else PRINT_ERROR(L"RpcBindingSetAuthInfoEx: 0x%08x (%u)\n", rpcStatus, rpcStatus);
					LocalFree(fullServer);
				}
			}
			else PRINT_ERROR(L"No Binding!\n");
		}
		else PRINT_ERROR(L"RpcBindingFromStringBinding: 0x%08x (%u)\n", rpcStatus, rpcStatus);
		RpcStringFree(&StringBinding);
	}
	else PRINT_ERROR(L"RpcStringBindingCompose: 0x%08x (%u)\n", rpcStatus, rpcStatus);
	return status;
}

BOOL kull_m_rpc_deleteBinding(RPC_BINDING_HANDLE *hBinding)
{
	BOOL status = FALSE;
	if(status = (RpcBindingFree(hBinding) == RPC_S_OK))
		*hBinding = NULL;
	return status;
}

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

void __RPC_USER WriteFcn(void *State, char *Buffer, unsigned int Size)
{
	;	
}

void __RPC_USER AllocFcn (void *State, char **pBuffer, unsigned int *pSize)
{
	; // ???
}