/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_rpc.h"

LPCWSTR KULL_M_RPC_AUTHNLEV[7] = {L"DEFAULT", L"NONCE", L"CONNECT", L"CALL", L"PKT", L"PKT_INTEGRITY", L"PKT_PRIVACY",};
LPCWSTR KULL_M_RPC_AUTHNSVC(DWORD AuthnSvc)
{
	LPCWSTR szAuthnSvc;
	switch(AuthnSvc)
	{
	case RPC_C_AUTHN_NONE:
		szAuthnSvc = L"NONE";
		break;
	case RPC_C_AUTHN_GSS_NEGOTIATE:
		szAuthnSvc = L"GSS_NEGOTIATE";
		break;
	case RPC_C_AUTHN_WINNT:
		szAuthnSvc = L"WINNT";
		break;
	case RPC_C_AUTHN_GSS_KERBEROS:
		szAuthnSvc = L"GSS_KERBEROS";
		break;
	default:
		szAuthnSvc = L"?";
	}
	return szAuthnSvc;
}
const SEC_WINNT_AUTH_IDENTITY KULL_M_RPC_NULLSESSION = {(unsigned short __RPC_FAR *) L"", 0, (unsigned short __RPC_FAR *) L"", 0, (unsigned short __RPC_FAR *) L"", 0, SEC_WINNT_AUTH_IDENTITY_UNICODE};

BOOL kull_m_rpc_createBinding(LPCWSTR uuid, LPCWSTR ProtSeq, LPCWSTR NetworkAddr, LPCWSTR Endpoint, LPCWSTR Service, BOOL addServiceToNetworkAddr, DWORD AuthnSvc, RPC_AUTH_IDENTITY_HANDLE hAuth, DWORD ImpersonationType, RPC_BINDING_HANDLE *hBinding, void (RPC_ENTRY * RpcSecurityCallback)(void *))
{
	BOOL status = FALSE;
	RPC_STATUS rpcStatus;
	RPC_WSTR StringBinding = NULL;
	RPC_SECURITY_QOS SecurityQOS = {RPC_C_SECURITY_QOS_VERSION, RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH, RPC_C_QOS_IDENTITY_STATIC, ImpersonationType};
	DWORD szServer, szPrefix;
	LPWSTR fullServer = NULL;

	*hBinding = NULL;
	rpcStatus = RpcStringBindingCompose((RPC_WSTR) uuid, (RPC_WSTR) ProtSeq, (RPC_WSTR) NetworkAddr, (RPC_WSTR) Endpoint, NULL, &StringBinding);
	if(rpcStatus == RPC_S_OK)
	{
		rpcStatus = RpcBindingFromStringBinding(StringBinding, hBinding);
		if(rpcStatus == RPC_S_OK)
		{
			if(*hBinding)
			{
				if(AuthnSvc != RPC_C_AUTHN_NONE)
				{
					if(addServiceToNetworkAddr)
					{
						if(NetworkAddr && Service)
						{
							szServer = lstrlen(NetworkAddr) * sizeof(wchar_t);
							szPrefix = lstrlen(Service) * sizeof(wchar_t);
							if(fullServer = (LPWSTR) LocalAlloc(LPTR, szPrefix + sizeof(wchar_t) + szServer + sizeof(wchar_t)))
							{
								RtlCopyMemory(fullServer, Service, szPrefix);
								RtlCopyMemory((PBYTE) fullServer + szPrefix + sizeof(wchar_t), NetworkAddr, szServer);
								((PBYTE) fullServer)[szPrefix] = L'/';
							}
						}
						else PRINT_ERROR(L"Cannot add NetworkAddr & Service if NULL\n");
					}

					if(!addServiceToNetworkAddr || fullServer)
					{
						rpcStatus = RpcBindingSetAuthInfoEx(*hBinding, (RPC_WSTR) (fullServer ? fullServer : (Service ? Service : MIMIKATZ)), RPC_C_AUTHN_LEVEL_PKT_PRIVACY, AuthnSvc, hAuth, 0, &SecurityQOS);
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
					}
				}
				else status = TRUE;

				if(!status)
				{
					rpcStatus = RpcBindingFree(hBinding);
					if(rpcStatus == RPC_S_OK)
						*hBinding = NULL;
					else PRINT_ERROR(L"RpcBindingFree: 0x%08x (%u)\n", rpcStatus, rpcStatus);
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

RPC_STATUS CALLBACK kull_m_rpc_nice_SecurityCallback(RPC_IF_HANDLE hInterface, void *pBindingHandle)
{
    return RPC_S_OK;
}

RPC_STATUS CALLBACK kull_m_rpc_nice_verb_SecurityCallback(RPC_IF_HANDLE hInterface, void *pBindingHandle)
{
	RPC_STATUS status;
	RPC_AUTHZ_HANDLE hAuthz;
	RPC_WSTR ServerPrincName;
	DWORD AuthnLevel, AuthnSvc, AuthzSvc;
	LPCWSTR szAuthnLevel, szAuthnSvc;

	kprintf(L"** Security Callback! **\n");
	status = RpcBindingInqAuthClient(pBindingHandle, &hAuthz, &ServerPrincName, &AuthnLevel, &AuthnSvc, &AuthzSvc);
	if(status == RPC_S_OK)
	{
		szAuthnLevel = (AuthnLevel < ARRAYSIZE(KULL_M_RPC_AUTHNLEV)) ? KULL_M_RPC_AUTHNLEV[AuthnLevel] : L"?";
		szAuthnSvc = KULL_M_RPC_AUTHNSVC(AuthnSvc);
		kprintf(L" > ServerPrincName: %s\n"
				L" > AuthnLevel     : %2u - %s\n"
				L" > AuthnSvc       : %2u - %s\n"
				L" > AuthzSvc       : %2u\n", ServerPrincName, AuthnLevel, szAuthnLevel, AuthnSvc, szAuthnSvc, AuthzSvc);
		RpcStringFree(&ServerPrincName);
		RpcImpersonateClient(pBindingHandle);
		RpcRevertToSelf();
	}
	else if(status == RPC_S_BINDING_HAS_NO_AUTH)
		kprintf(L" > No Authentication\n");
	else PRINT_ERROR(L"RpcBindingInqAuthClient: %08x\n", status);
    return RPC_S_OK;
}

void kull_m_rpc_getArgs(int argc, wchar_t * argv[], LPCWSTR *szRemote, LPCWSTR *szProtSeq, LPCWSTR *szEndpoint, LPCWSTR *szService, DWORD *AuthnSvc, DWORD defAuthnSvc, BOOL *isNullSession, GUID *altGuid, BOOL printIt)
{
	PCWSTR data;
	UNICODE_STRING us;

	if(szRemote)
	{
		kull_m_string_args_byName(argc, argv, L"remote", szRemote, NULL);
		if(!*szRemote)
			kull_m_string_args_byName(argc, argv, L"server", szRemote, NULL);
		if(printIt)
			kprintf(L"Remote   : %s\n", *szRemote);
	}

	if(szProtSeq)
	{
		kull_m_string_args_byName(argc, argv, L"protseq", szProtSeq, L"ncacn_ip_tcp");
		if(printIt)
			kprintf(L"ProtSeq  : %s\n", *szProtSeq);

	}
	
	if(szEndpoint)
	{
		kull_m_string_args_byName(argc, argv, L"endpoint", szEndpoint, NULL);
		if(printIt)
			kprintf(L"Endpoint : %s\n", *szEndpoint);
	}
	
	if(szService)
	{
		kull_m_string_args_byName(argc, argv, L"service", szService, NULL);
		if(printIt)
			kprintf(L"Service  : %s\n", *szService);
	}
	
	if(AuthnSvc)
	{
		*AuthnSvc = defAuthnSvc;
		if(kull_m_string_args_byName(argc, argv, L"noauth", NULL, NULL))
			*AuthnSvc = RPC_C_AUTHN_NONE;
		if(kull_m_string_args_byName(argc, argv, L"ntlm", NULL, NULL))
			*AuthnSvc = RPC_C_AUTHN_WINNT;;
		if(kull_m_string_args_byName(argc, argv, L"kerberos", NULL, NULL))
			*AuthnSvc = RPC_C_AUTHN_GSS_KERBEROS;
		if(printIt)
			kprintf(L"AuthnSvc : %s\n", KULL_M_RPC_AUTHNSVC(*AuthnSvc));
	}

	if(isNullSession)
	{
		*isNullSession = kull_m_string_args_byName(argc, argv, L"null", NULL, NULL);
		if(printIt)
			kprintf(L"NULL Sess: %s\n", (*isNullSession) ? L"yes" : L"no");
	}

	if(altGuid)
	{
		if(kull_m_string_args_byName(argc, argv, L"guid", &data, NULL))
		{
			RtlInitUnicodeString(&us, data);
			if(NT_SUCCESS(RtlGUIDFromString(&us, altGuid)) && printIt)
			{
				kprintf(L"Alt GUID : ");
				kull_m_string_displayGUID(altGuid);
				kprintf(L"\n");
			}
		}
	}
}

void __RPC_FAR * __RPC_USER midl_user_allocate(size_t cBytes)
{
	return LocalAlloc(LPTR, cBytes);
}

void __RPC_USER midl_user_free(void __RPC_FAR * p)
{
	if(p)
		LocalFree(p);
}

void __RPC_USER ReadFcn(void *State, char **pBuffer, unsigned int *pSize)
{
	*pBuffer = (char *) ((PKULL_M_RPC_FCNSTRUCT) State)->addr;
	((PKULL_M_RPC_FCNSTRUCT) State)->addr = *pBuffer + *pSize;
	((PKULL_M_RPC_FCNSTRUCT) State)->size -= *pSize;
}

void __RPC_USER WriteFcn(void *State, char *Buffer, unsigned int Size)
{
}

void __RPC_USER AllocFcn (void *State, char **pBuffer, unsigned int *pSize)
{
}

BOOL kull_m_rpc_Generic_Decode(PVOID data, DWORD size, PVOID pObject, PGENERIC_RPC_DECODE fDecode)
{
	BOOL status = FALSE;
	RPC_STATUS rpcStatus;
	PVOID buffer;
	KULL_M_RPC_FCNSTRUCT UserState ;
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
					PRINT_ERROR(L"RPC Exception: 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
				RpcEndExcept
			}
			else PRINT_ERROR(L"MesIncrementalHandleReset: %08x\n", rpcStatus);
			MesHandleFree(pHandle);
		}
		else PRINT_ERROR(L"MesDecodeIncrementalHandleCreate: %08x\n", rpcStatus);
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
			PRINT_ERROR(L"RPC Exception: 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
		RpcEndExcept
		MesHandleFree(pHandle);
	}
	else PRINT_ERROR(L"MesDecodeIncrementalHandleCreate: %08x\n", rpcStatus);
}

BOOL kull_m_rpc_Generic_Encode(PVOID pObject, PVOID *data, DWORD *size, PGENERIC_RPC_ENCODE fEncode, PGENERIC_RPC_ALIGNSIZE fAlignSize)
{
	BOOL status = FALSE;
	RPC_STATUS rpcStatus;
	KULL_M_RPC_FCNSTRUCT UserState;
	handle_t pHandle;

	rpcStatus = MesEncodeIncrementalHandleCreate(&UserState, ReadFcn, WriteFcn, &pHandle);
	if(NT_SUCCESS(rpcStatus))
	{
		*size = (DWORD) fAlignSize(pHandle, pObject);
		if(*data = LocalAlloc(LPTR, *size))
		{
			rpcStatus = MesIncrementalHandleReset(pHandle, NULL, NULL, NULL, NULL, MES_ENCODE);
			if(NT_SUCCESS(rpcStatus))
			{
				UserState.addr = *data;
				UserState.size = *size;
				RpcTryExcept
				{
					fEncode(pHandle, pObject);
					status = TRUE;
				}
				RpcExcept(EXCEPTION_EXECUTE_HANDLER)
					PRINT_ERROR(L"RPC Exception: 0x%08x (%u)\n", RpcExceptionCode(), RpcExceptionCode());
				RpcEndExcept
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