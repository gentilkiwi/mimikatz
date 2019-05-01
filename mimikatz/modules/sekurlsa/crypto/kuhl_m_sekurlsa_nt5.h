/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../globals_sekurlsa.h"
#if !defined(_M_ARM64)
NTSTATUS kuhl_m_sekurlsa_nt5_init();
NTSTATUS kuhl_m_sekurlsa_nt5_clean();

NTSTATUS kuhl_m_sekurlsa_nt5_LsaInitializeProtectedMemory();

const PLSA_PROTECT_MEMORY kuhl_m_sekurlsa_nt5_pLsaProtectMemory, kuhl_m_sekurlsa_nt5_pLsaUnprotectMemory;

BOOL kuhl_m_sekurlsa_nt5_isOld(DWORD osBuildNumber, DWORD moduleTimeStamp);
NTSTATUS kuhl_m_sekurlsa_nt5_acquireKeys(PKUHL_M_SEKURLSA_CONTEXT cLsass, PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION lsassLsaSrvModule);
BOOL kuhl_m_sekurlsa_nt5_acquireKey(PKULL_M_MEMORY_ADDRESS aLsassMemory, PBYTE Key, SIZE_T taille);

VOID WINAPI kuhl_m_sekurlsa_nt5_LsaProtectMemory(IN PVOID Buffer, IN ULONG BufferSize);
VOID WINAPI kuhl_m_sekurlsa_nt5_LsaUnprotectMemory(IN PVOID Buffer, IN ULONG BufferSize);
NTSTATUS kuhl_m_sekurlsa_nt5_LsaEncryptMemory(PUCHAR pMemory, ULONG cbMemory, BOOL Encrypt);

/*	All code below is very (very) inspired from Microsoft SymCrypt
	> https://github.com/Microsoft/SymCrypt
	Lots of thanks to Niels Ferguson ( https://github.com/NielsFerguson )

	Was not able to use CryptoAPI because:
	- DES-X is not supported
		- even if, DES-X main DES key is stored already scheduled, so not compatible with CryptoAPI
	- RC4 is not supported with key > 128 bits (LSA uses one of 2048 bits)

	A good example of 'do not use what I use'
*/
typedef struct _SYMCRYPT_NT5_DES_EXPANDED_KEY {
    UINT32  roundKey[16][2];
} SYMCRYPT_NT5_DES_EXPANDED_KEY, *PSYMCRYPT_NT5_DES_EXPANDED_KEY;
typedef const SYMCRYPT_NT5_DES_EXPANDED_KEY * PCSYMCRYPT_NT5_DES_EXPANDED_KEY;

typedef struct _SYMCRYPT_NT5_DESX_EXPANDED_KEY {
	BYTE inputWhitening[8];
	BYTE outputWhitening[8];
	SYMCRYPT_NT5_DES_EXPANDED_KEY desKey;
} SYMCRYPT_NT5_DESX_EXPANDED_KEY, *PSYMCRYPT_NT5_DESX_EXPANDED_KEY;
typedef const SYMCRYPT_NT5_DESX_EXPANDED_KEY * PCSYMCRYPT_NT5_DESX_EXPANDED_KEY;

typedef struct _SYMCRYPT_RC4_STATE {
    BYTE S[256];
    BYTE i;
    BYTE j;
} SYMCRYPT_RC4_STATE, *PSYMCRYPT_RC4_STATE;

#define ROL32( x, n ) _rotl( (x), (n) )
#define ROR32( x, n ) _rotr( (x), (n) )
#define F(L, R, keyptr) { \
    Ta = keyptr[0] ^ R; \
    Tb = keyptr[1] ^ R; \
    Tb = ROR32(Tb, 4); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[0] + ( Ta     & 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[1] + ( Tb     & 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[2] + ((Ta>> 8)& 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[3] + ((Tb>> 8)& 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[4] + ((Ta>>16)& 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[5] + ((Tb>>16)& 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[6] + ((Ta>>24)& 0xfc)); \
    L ^= *(UINT32 *)((PBYTE)SymCryptDesSpbox[7] + ((Tb>>24)& 0xfc)); }

VOID SymCryptDesGenCrypt2(PCSYMCRYPT_NT5_DES_EXPANDED_KEY pExpandedKey, LPCBYTE pbSrc, PBYTE pbDst, BOOL Encrypt);
VOID SymCryptDesxDecrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, LPCBYTE pbSrc, PBYTE pbDst);
VOID SymCryptDesxEncrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, LPCBYTE pbSrc, PBYTE pbDst);
VOID SymCryptDesxCbcDecrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, PBYTE pbChainingValue, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData);
VOID SymCryptDesxCbcEncrypt2(PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, PBYTE pbChainingValue, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData);

typedef VOID (* PCRYPT_ENCRYPT) (PCSYMCRYPT_NT5_DESX_EXPANDED_KEY pExpandedKey, PBYTE pbChainingValue, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData);

BOOL SymCryptRc4Init2(PSYMCRYPT_RC4_STATE pState, LPCBYTE pbKey, SIZE_T cbKey);
VOID SymCryptRc4Crypt2(PSYMCRYPT_RC4_STATE pState, LPCBYTE pbSrc, PBYTE pbDst, SIZE_T cbData);
#endif