/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_string.h"

#define	MD4_DIGEST_LENGTH	16
#define	MD5_DIGEST_LENGTH	16
#define SHA_DIGEST_LENGTH	20

#define	DES_KEY_LENGTH		7
#define DES_BLOCK_LENGTH	8
#define AES_128_KEY_LENGTH	16
#define AES_256_KEY_LENGTH	32

#if !defined(IPSEC_FLAG_CHECK)
#define IPSEC_FLAG_CHECK 0xf42a19b6
#endif

typedef struct _MD4_CTX {
	DWORD state[4];
	DWORD count[2];
	BYTE buffer[64];
	BYTE digest[MD4_DIGEST_LENGTH];
} MD4_CTX, *PMD4_CTX;

typedef struct _MD5_CTX {
	DWORD count[2];
	DWORD state[4];
	BYTE buffer[64];
	BYTE digest[MD5_DIGEST_LENGTH];
} MD5_CTX, *PMD5_CTX;

typedef struct _SHA_CTX {
	BYTE buffer[64];
	DWORD state[5];
	DWORD count[2];
	DWORD unk[6]; // to avoid error on XP
} SHA_CTX, *PSHA_CTX;

typedef struct _SHA_DIGEST {
	BYTE digest[SHA_DIGEST_LENGTH];
} SHA_DIGEST, *PSHA_DIGEST;

typedef struct _CRYPTO_BUFFER {
	DWORD Length;
	DWORD MaximumLength;
	PBYTE Buffer;
} CRYPTO_BUFFER, *PCRYPTO_BUFFER;
typedef CONST CRYPTO_BUFFER *PCCRYPTO_BUFFER;

extern VOID WINAPI MD4Init(PMD4_CTX pCtx);
extern VOID WINAPI MD4Update(PMD4_CTX pCtx, LPCVOID data, DWORD cbData);
extern VOID WINAPI MD4Final(PMD4_CTX pCtx);

extern VOID WINAPI MD5Init(PMD5_CTX pCtx);
extern VOID WINAPI MD5Update(PMD5_CTX pCtx, LPCVOID data, DWORD cbData);
extern VOID WINAPI MD5Final(PMD5_CTX pCtx);

extern VOID WINAPI A_SHAInit(PSHA_CTX pCtx);
extern VOID WINAPI A_SHAUpdate(PSHA_CTX pCtx, LPCVOID data, DWORD cbData);
extern VOID WINAPI A_SHAFinal(PSHA_CTX pCtx, PSHA_DIGEST pDigest);

#define RtlEncryptDES1block1key		SystemFunction001
#define RtlDecryptDES1block1key		SystemFunction002
#define RtlEncryptDESMagicBlock1key	SystemFunction003
#define RtlEncryptDESblocksECB		SystemFunction004
#define RtlDecryptDESblocksECB		SystemFunction005
#define RtlDigestLM					SystemFunction006
#define RtlDigestNTLM				SystemFunction007
#define RtlLMResponseToChallenge	SystemFunction008
//	=								SystemFunction009 (SystemFunction008 - RtlLMResponseToChallenge)
#define RtlDigestMD4only16Bytes		SystemFunction010
//	=								SystemFunction011 (SystemFunction010 - RtlDigest16BytesMD4)
#define RtlEncryptDES2blocks2keys	SystemFunction012
#define RtlDecryptDES2blocks2keys	SystemFunction013
//	=								SystemFunction014 (SystemFunction012 - RtlEncryptDES2blocks2keys)
//	=								SystemFunction015 (SystemFunction013 - RtlDecryptDES2blocks2keys)
#define RtlEncryptDES2blocks1key	SystemFunction016
#define RtlDecryptDES2blocks1key	SystemFunction017
//	=								SystemFunction018 (SystemFunction016 - RtlEncryptDES2blocks1key)
//	=								SystemFunction019 (SystemFunction017 - RtlDecryptDES2blocks1key)
//	=								SystemFunction020 (SystemFunction012 - RtlEncryptDES2blocks2keys)
//	=								SystemFunction021 (SystemFunction013 - RtlDecryptDES2blocks2keys)
//	=								SystemFunction022 (SystemFunction012 - RtlEncryptDES2blocks2keys)
//	=								SystemFunction023 (SystemFunction013 - RtlDecryptDES2blocks2keys)
#define RtlEncryptDES2blocks1DWORD	SystemFunction024
#define RtlDecryptDES2blocks1DWORD	SystemFunction025
//	=								SystemFunction026 (SystemFunction024 - RtlEncryptDES2blocks1DWORD)
//	=								SystemFunction027 (SystemFunction025 - RtlDecryptDES2blocks1DWORD)
//	?	Session Key through RPC		SystemFunction028
//	?	Session Key through RPC		SystemFunction029
#define RtlEqualMemory16Bytes		SystemFunction030
//	=								SystemFunction031 (SystemFunction030 - RtlEqualMemory16Bytes)
#define RtlEncryptDecryptRC4		SystemFunction032
//	=								SystemFunction033 (SystemFunction032 - RtlEncryptDecryptARC4)
//	?	Session Key through RPC		SystemFunction034
#define RtlCheckSignatureInFile		SystemFunction035

extern NTSTATUS WINAPI RtlEncryptDES1block1key(IN LPCBYTE data, IN LPCBYTE key, OUT LPBYTE output);
extern NTSTATUS WINAPI RtlDecryptDES1block1key(IN LPCBYTE data, IN LPCBYTE key, OUT LPBYTE output);
extern NTSTATUS WINAPI RtlEncryptDESMagicBlock1key(IN LPCBYTE key, OUT LPBYTE output);
extern NTSTATUS WINAPI RtlEncryptDESblocksECB(IN PCCRYPTO_BUFFER data, IN PCCRYPTO_BUFFER key, OUT PCRYPTO_BUFFER output);
extern NTSTATUS WINAPI RtlDecryptDESblocksECB(IN PCCRYPTO_BUFFER data, IN PCCRYPTO_BUFFER key, OUT PCRYPTO_BUFFER output);
extern NTSTATUS WINAPI RtlDigestLM(IN LPCSTR data, OUT LPBYTE output);
extern NTSTATUS WINAPI RtlDigestNTLM(IN PCUNICODE_STRING data, OUT LPBYTE output);
extern NTSTATUS WINAPI RtlLMResponseToChallenge(IN LPCBYTE challenge, IN LPCBYTE hash, OUT LPBYTE output);
extern NTSTATUS WINAPI RtlDigestMD4only16Bytes(IN LPVOID unk0, IN LPCBYTE data, OUT LPBYTE output);
extern NTSTATUS WINAPI RtlEncryptDES2blocks2keys(IN LPCBYTE data, IN LPCBYTE key, OUT LPBYTE output);
extern NTSTATUS WINAPI RtlDecryptDES2blocks2keys(IN LPCBYTE data, IN LPCBYTE key, OUT LPBYTE output);
extern NTSTATUS WINAPI RtlEncryptDES2blocks1key(IN LPCBYTE data, IN LPCBYTE key, OUT LPBYTE output);
extern NTSTATUS WINAPI RtlDecryptDES2blocks1key(IN LPCBYTE data, IN LPCBYTE key, OUT LPBYTE output);
extern NTSTATUS WINAPI RtlEncryptDES2blocks1DWORD(IN LPCBYTE data, IN LPDWORD key, OUT LPBYTE output);
extern NTSTATUS WINAPI RtlDecryptDES2blocks1DWORD(IN LPCBYTE data, IN LPDWORD key, OUT LPBYTE output);
extern NTSTATUS WINAPI SystemFunction028(IN NDR_CCONTEXT CContext, OUT LPBYTE output);
extern RPC_STATUS WINAPI SystemFunction029(IN LPVOID unk0, OUT LPBYTE output);
extern BOOL WINAPI RtlEqualMemory16Bytes(IN LPCBYTE data1, IN LPCBYTE data2);
extern NTSTATUS WINAPI RtlEncryptDecryptRC4(IN OUT PCRYPTO_BUFFER data, IN PCCRYPTO_BUFFER key);
extern NTSTATUS WINAPI SystemFunction034(IN RPC_BINDING_HANDLE hRPC, IN OUT OPTIONAL HANDLE hUnk0, OUT LPBYTE output);
extern BOOL WINAPI RtlCheckSignatureInFile(IN LPCWSTR filename);

#if !defined(RtlGenRandom)
#define RtlGenRandom				SystemFunction036
extern BOOL WINAPI RtlGenRandom(OUT LPBYTE output, IN DWORD length);
#endif

#if !defined(RtlEncryptMemory)
#define RtlEncryptMemory			SystemFunction040
extern NTSTATUS WINAPI RtlEncryptMemory(IN OUT LPBYTE data, DWORD length, DWORD flags);
#endif 

#if !defined(RtlDecryptMemory)
#define RtlDecryptMemory			SystemFunction041
extern NTSTATUS WINAPI RtlDecryptMemory(IN OUT LPBYTE data, DWORD length, DWORD flags);
#endif

#define KERB_NON_KERB_SALT					16
#define KERB_NON_KERB_CKSUM_SALT			17

typedef NTSTATUS (WINAPI * PKERB_CHECKSUM_INITIALIZE) (DWORD unk0, PVOID * pContext);
typedef NTSTATUS (WINAPI * PKERB_CHECKSUM_SUM) (PVOID pContext, DWORD Size, LPCVOID Buffer);
typedef NTSTATUS (WINAPI * PKERB_CHECKSUM_FINALIZE) (PVOID pContext, PVOID Buffer);
typedef NTSTATUS (WINAPI * PKERB_CHECKSUM_FINISH) (PVOID * pContext);
typedef NTSTATUS (WINAPI * PKERB_CHECKSUM_INITIALIZEEX) (LPCVOID Key, DWORD KeySize, DWORD KeyUsage, PVOID * pContext);

typedef struct _KERB_CHECKSUM {
	LONG Type;
	DWORD Size;
	DWORD Flag;
	PKERB_CHECKSUM_INITIALIZE Initialize;
	PKERB_CHECKSUM_SUM Sum;
	PKERB_CHECKSUM_FINALIZE Finalize;
	PKERB_CHECKSUM_FINISH Finish;
	PKERB_CHECKSUM_INITIALIZEEX InitializeEx;
	PVOID unk0_null;
} KERB_CHECKSUM, *PKERB_CHECKSUM;

typedef NTSTATUS (WINAPI * PKERB_ECRYPT_INITIALIZE) (LPCVOID Key, DWORD KeySize, DWORD KeyUsage, PVOID * pContext);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_ENCRYPT) (PVOID pContext, LPCVOID Data, DWORD DataSize, PVOID Output, DWORD * OutputSize);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_DECRYPT) (PVOID pContext, LPCVOID Data, DWORD DataSize, PVOID Output, DWORD * OutputSize);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_FINISH) (PVOID * pContext);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_HASHPASSWORD_NT5) (PCUNICODE_STRING String, PVOID Output);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_HASHPASSWORD_NT6) (PCUNICODE_STRING Password, PCUNICODE_STRING Salt, DWORD Count, PVOID Output);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_RANDOMKEY) (LPCVOID Key, DWORD KeySize, PVOID Output);
// Control

typedef struct _KERB_ECRYPT {
	LONG Type0;
	DWORD BlockSize;
	LONG Type1;
	DWORD KeySize;
	DWORD Size;
	DWORD unk2;
	DWORD unk3;
	PCWSTR AlgName;
	PKERB_ECRYPT_INITIALIZE Initialize;
	PKERB_ECRYPT_ENCRYPT Encrypt;
	PKERB_ECRYPT_DECRYPT Decrypt;
	PKERB_ECRYPT_FINISH Finish;
	union {
		PKERB_ECRYPT_HASHPASSWORD_NT5 HashPassword_NT5;
		PKERB_ECRYPT_HASHPASSWORD_NT6 HashPassword_NT6;
	};
	PKERB_ECRYPT_RANDOMKEY RandomKey;
	PVOID Control;
	PVOID unk0_null;
	PVOID unk1_null;
	PVOID unk2_null;
} KERB_ECRYPT, *PKERB_ECRYPT;

typedef NTSTATUS (WINAPI * PKERB_RNGFN) (PVOID Buffer, DWORD Size);

typedef struct _KERB_RNG {
	LONG Type;
	DWORD unk0;
	DWORD unk1;
	PKERB_RNGFN RngFn;
} KERB_RNG, *PKERB_RNG;

extern NTSTATUS WINAPI CDLocateCSystem(LONG type, PKERB_ECRYPT * pCSystem);
extern NTSTATUS WINAPI CDLocateCheckSum(LONG type, PKERB_CHECKSUM * pCheckSum);
extern NTSTATUS WINAPI CDLocateRng(LONG type, PKERB_RNG * pRng);
extern NTSTATUS WINAPI CDGenerateRandomBits(LPVOID Buffer, DWORD Size);