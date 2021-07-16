/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
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

typedef struct _CRYPT_BUFFER {
	DWORD Length;
	DWORD MaximumLength;
	PVOID Buffer;
} CRYPT_BUFFER, *PCRYPT_BUFFER, DATA_KEY, *PDATA_KEY, CLEAR_DATA, *PCLEAR_DATA, CYPHER_DATA, *PCYPHER_DATA;

VOID WINAPI MD4Init(PMD4_CTX pCtx);
VOID WINAPI MD4Update(PMD4_CTX pCtx, LPCVOID data, DWORD cbData);
VOID WINAPI MD4Final(PMD4_CTX pCtx);

VOID WINAPI MD5Init(PMD5_CTX pCtx);
VOID WINAPI MD5Update(PMD5_CTX pCtx, LPCVOID data, DWORD cbData);
VOID WINAPI MD5Final(PMD5_CTX pCtx);

VOID WINAPI A_SHAInit(PSHA_CTX pCtx);
VOID WINAPI A_SHAUpdate(PSHA_CTX pCtx, LPCVOID data, DWORD cbData);
VOID WINAPI A_SHAFinal(PSHA_CTX pCtx, PSHA_DIGEST pDigest);

#define RtlEncryptBlock						SystemFunction001 // DES
#define RtlDecryptBlock						SystemFunction002 // DES
#define RtlEncryptStdBlock					SystemFunction003 // DES with key "KGS!@#$%" for LM hash
#define RtlEncryptData						SystemFunction004 // DES/ECB
#define RtlDecryptData						SystemFunction005 // DES/ECB
#define RtlCalculateLmOwfPassword			SystemFunction006
#define RtlCalculateNtOwfPassword			SystemFunction007
#define RtlCalculateLmResponse				SystemFunction008
#define RtlCalculateNtResponse				SystemFunction009
#define RtlCalculateUserSessionKeyLm		SystemFunction010
#define RtlCalculateUserSessionKeyNt		SystemFunction011
#define RtlEncryptLmOwfPwdWithLmOwfPwd		SystemFunction012
#define RtlDecryptLmOwfPwdWithLmOwfPwd		SystemFunction013
#define RtlEncryptNtOwfPwdWithNtOwfPwd		SystemFunction014
#define RtlDecryptNtOwfPwdWithNtOwfPwd		SystemFunction015
#define RtlEncryptLmOwfPwdWithLmSesKey		SystemFunction016
#define RtlDecryptLmOwfPwdWithLmSesKey		SystemFunction017
#define RtlEncryptNtOwfPwdWithNtSesKey		SystemFunction018
#define RtlDecryptNtOwfPwdWithNtSesKey		SystemFunction019
#define RtlEncryptLmOwfPwdWithUserKey		SystemFunction020
#define RtlDecryptLmOwfPwdWithUserKey		SystemFunction021
#define RtlEncryptNtOwfPwdWithUserKey		SystemFunction022
#define RtlDecryptNtOwfPwdWithUserKey		SystemFunction023
#define RtlEncryptLmOwfPwdWithIndex			SystemFunction024
#define RtlDecryptLmOwfPwdWithIndex			SystemFunction025
#define RtlEncryptNtOwfPwdWithIndex			SystemFunction026
#define RtlDecryptNtOwfPwdWithIndex			SystemFunction027
#define RtlGetUserSessionKeyClient			SystemFunction028
#define RtlGetUserSessionKeyServer			SystemFunction029
#define RtlEqualLmOwfPassword				SystemFunction030
#define RtlEqualNtOwfPassword				SystemFunction031
#define RtlEncryptData2						SystemFunction032 // RC4
#define RtlDecryptData2						SystemFunction033 // RC4
#define RtlGetUserSessionKeyClientBinding	SystemFunction034
#define RtlCheckSignatureInFile				SystemFunction035

NTSTATUS WINAPI RtlEncryptBlock(IN LPCBYTE ClearBlock, IN LPCBYTE BlockKey, OUT LPBYTE CypherBlock);
NTSTATUS WINAPI RtlDecryptBlock(IN LPCBYTE CypherBlock, IN LPCBYTE BlockKey, OUT LPBYTE ClearBlock);
NTSTATUS WINAPI RtlEncryptStdBlock(IN LPCBYTE BlockKey, OUT LPBYTE CypherBlock);
NTSTATUS WINAPI RtlEncryptData(IN PCLEAR_DATA ClearData, IN PDATA_KEY DataKey, OUT PCYPHER_DATA CypherData);
NTSTATUS WINAPI RtlDecryptData(IN PCYPHER_DATA CypherData, IN PDATA_KEY DataKey, OUT PCLEAR_DATA ClearData);
NTSTATUS WINAPI RtlCalculateLmOwfPassword(IN LPCSTR data, OUT LPBYTE output);
NTSTATUS WINAPI RtlCalculateNtOwfPassword(IN PCUNICODE_STRING data, OUT LPBYTE output);
NTSTATUS WINAPI RtlCalculateLmResponse(IN LPCBYTE LmChallenge, IN LPCBYTE LmOwfPassword, OUT LPBYTE LmResponse);
NTSTATUS WINAPI RtlCalculateNtResponse(IN LPCBYTE NtChallenge, IN LPCBYTE NtOwfPassword, OUT LPBYTE NtResponse);
NTSTATUS WINAPI RtlCalculateUserSessionKeyLm(IN LPCBYTE LmResponse, IN LPCBYTE LmOwfPassword, OUT LPBYTE UserSessionKey);
NTSTATUS WINAPI RtlCalculateUserSessionKeyNt(IN LPCBYTE NtResponse, IN LPCBYTE NtOwfPassword, OUT LPBYTE UserSessionKey);
NTSTATUS WINAPI RtlEncryptLmOwfPwdWithLmOwfPwd(IN LPCBYTE DataLmOwfPassword, IN LPCBYTE KeyLmOwfPassword, OUT LPBYTE EncryptedLmOwfPassword);
NTSTATUS WINAPI RtlDecryptLmOwfPwdWithLmOwfPwd(IN LPCBYTE EncryptedLmOwfPassword, IN LPCBYTE KeyLmOwfPassword, OUT LPBYTE DataLmOwfPassword);
NTSTATUS WINAPI RtlEncryptNtOwfPwdWithNtOwfPwd(IN LPCBYTE DataNtOwfPassword, IN LPCBYTE KeyNtOwfPassword, OUT LPBYTE EncryptedNtOwfPassword);
NTSTATUS WINAPI RtlDecryptNtOwfPwdWithNtOwfPwd(IN LPCBYTE EncryptedNtOwfPassword, IN LPCBYTE KeyNtOwfPassword, OUT LPBYTE DataNtOwfPassword);
NTSTATUS WINAPI RtlEncryptLmOwfPwdWithLmSesKey(IN LPCBYTE LmOwfPassword, IN LPCBYTE LmSessionKey, OUT LPBYTE EncryptedLmOwfPassword);
NTSTATUS WINAPI RtlDecryptLmOwfPwdWithLmSesKey(IN LPCBYTE EncryptedLmOwfPassword, IN LPCBYTE LmSessionKey, OUT LPBYTE LmOwfPassword);
NTSTATUS WINAPI RtlEncryptNtOwfPwdWithNtSesKey(IN LPCBYTE NtOwfPassword, IN LPCBYTE NtSessionKey, OUT LPBYTE EncryptedNtOwfPassword);
NTSTATUS WINAPI RtlDecryptNtOwfPwdWithNtSesKey(IN LPCBYTE EncryptedNtOwfPassword, IN LPCBYTE NtSessionKey, OUT LPBYTE NtOwfPassword);
NTSTATUS WINAPI RtlEncryptLmOwfPwdWithUserKey(IN LPCBYTE LmOwfPassword, IN LPCBYTE UserSessionKey, OUT LPBYTE EncryptedLmOwfPassword);
NTSTATUS WINAPI RtlDecryptLmOwfPwdWithUserKey(IN LPCBYTE EncryptedLmOwfPassword, IN LPCBYTE UserSessionKey, OUT LPBYTE LmOwfPassword);
NTSTATUS WINAPI RtlEncryptNtOwfPwdWithUserKey(IN LPCBYTE NtOwfPassword, IN LPCBYTE UserSessionKey, OUT LPBYTE EncryptedNtOwfPassword);
NTSTATUS WINAPI RtlDecryptNtOwfPwdWithUserKey(IN LPCBYTE EncryptedNtOwfPassword, IN LPCBYTE UserSessionKey, OUT LPBYTE NtOwfPassword);
NTSTATUS WINAPI RtlEncryptLmOwfPwdWithIndex(IN LPCBYTE LmOwfPassword, IN LPDWORD Index, OUT LPBYTE EncryptedLmOwfPassword);
NTSTATUS WINAPI RtlDecryptLmOwfPwdWithIndex(IN LPCBYTE EncryptedLmOwfPassword, IN LPDWORD Index, OUT LPBYTE LmOwfPassword);
NTSTATUS WINAPI RtlEncryptNtOwfPwdWithIndex(IN LPCBYTE NtOwfPassword, IN LPDWORD Index, OUT LPBYTE EncryptedNtOwfPassword);
NTSTATUS WINAPI RtlDecryptNtOwfPwdWithIndex(IN LPCBYTE EncryptedNtOwfPassword, IN LPDWORD Index, OUT LPBYTE NtOwfPassword);
NTSTATUS WINAPI RtlGetUserSessionKeyClient(IN PVOID RpcContextHandle, OUT LPBYTE UserSessionKey);
NTSTATUS WINAPI RtlGetUserSessionKeyServer(IN PVOID RpcContextHandle OPTIONAL, OUT LPBYTE UserSessionKey);
BOOLEAN WINAPI RtlEqualLmOwfPassword(IN LPCBYTE LmOwfPassword1, IN LPCBYTE LmOwfPassword2);
BOOLEAN WINAPI RtlEqualNtOwfPassword(IN LPCBYTE NtOwfPassword1, IN LPCBYTE NtOwfPassword2);
NTSTATUS WINAPI RtlEncryptData2(IN OUT PCRYPT_BUFFER pData, IN PDATA_KEY pkey);
NTSTATUS WINAPI RtlDecryptData2(IN OUT PCRYPT_BUFFER pData, IN PDATA_KEY pkey);
NTSTATUS WINAPI RtlGetUserSessionKeyClientBinding(IN PVOID RpcBindingHandle, OUT HANDLE *RedirHandle, OUT LPBYTE UserSessionKey);
ULONG WINAPI RtlCheckSignatureInFile(IN LPCWSTR filename);

#if !defined(RtlGenRandom)
#define RtlGenRandom				SystemFunction036
BOOL WINAPI RtlGenRandom(OUT LPBYTE output, IN DWORD length);
#endif

#if !defined(RtlEncryptMemory)
#define RtlEncryptMemory			SystemFunction040
NTSTATUS WINAPI RtlEncryptMemory(IN OUT LPBYTE data, DWORD length, DWORD flags);
#endif 

#if !defined(RtlDecryptMemory)
#define RtlDecryptMemory			SystemFunction041
NTSTATUS WINAPI RtlDecryptMemory(IN OUT LPBYTE data, DWORD length, DWORD flags);
#endif

#define KERB_NON_KERB_SALT					16
#define KERB_NON_KERB_CKSUM_SALT			17

typedef NTSTATUS (WINAPI * PKERB_CHECKSUM_INITIALIZE) (ULONG dwSeed, PVOID *pContext);
typedef NTSTATUS (WINAPI * PKERB_CHECKSUM_SUM) (PVOID pContext, ULONG cbData, LPCVOID pbData);
typedef NTSTATUS (WINAPI * PKERB_CHECKSUM_FINALIZE) (PVOID pContext, PVOID pbSum);
typedef NTSTATUS (WINAPI * PKERB_CHECKSUM_FINISH) (PVOID *pContext);
typedef NTSTATUS (WINAPI * PKERB_CHECKSUM_INITIALIZEEX) (LPCVOID Key, ULONG KeySize, ULONG MessageType, PVOID *pContext);
typedef NTSTATUS (WINAPI * PKERB_CHECKSUM_INITIALIZEEX2)(LPCVOID Key, ULONG KeySize, LPCVOID ChecksumToVerify, ULONG MessageType, PVOID *pContext);

typedef struct _KERB_CHECKSUM {
	ULONG CheckSumType;
	ULONG CheckSumSize;
	ULONG Attributes;
	PKERB_CHECKSUM_INITIALIZE Initialize;
	PKERB_CHECKSUM_SUM Sum;
	PKERB_CHECKSUM_FINALIZE Finalize;
	PKERB_CHECKSUM_FINISH Finish;
	PKERB_CHECKSUM_INITIALIZEEX InitializeEx;
	PKERB_CHECKSUM_INITIALIZEEX2 InitializeEx2;
} KERB_CHECKSUM, *PKERB_CHECKSUM;

typedef NTSTATUS (WINAPI * PKERB_ECRYPT_INITIALIZE) (LPCVOID pbKey, ULONG KeySize, ULONG MessageType, PVOID *pContext);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_ENCRYPT) (PVOID pContext, LPCVOID pbInput, ULONG cbInput, PVOID pbOutput, ULONG *cbOutput);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_DECRYPT) (PVOID pContext, LPCVOID pbInput, ULONG cbInput, PVOID pbOutput, ULONG *cbOutput);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_FINISH) (PVOID *pContext);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_HASHPASSWORD_NT5) (PCUNICODE_STRING Password, PVOID pbKey);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_HASHPASSWORD_NT6) (PCUNICODE_STRING Password, PCUNICODE_STRING Salt, ULONG Count, PVOID pbKey);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_RANDOMKEY) (LPCVOID Seed, ULONG SeedLength, PVOID pbKey);
typedef NTSTATUS (WINAPI * PKERB_ECRYPT_CONTROL) (ULONG Function, PVOID pContext, PUCHAR InputBuffer, ULONG InputBufferSize);

typedef struct _KERB_ECRYPT {
	ULONG EncryptionType;
	ULONG BlockSize;
	ULONG ExportableEncryptionType;
	ULONG KeySize;
	ULONG HeaderSize;
	ULONG PreferredCheckSum;
	ULONG Attributes;
	PCWSTR Name;
	PKERB_ECRYPT_INITIALIZE Initialize;
	PKERB_ECRYPT_ENCRYPT Encrypt;
	PKERB_ECRYPT_DECRYPT Decrypt;
	PKERB_ECRYPT_FINISH Finish;
	union {
		PKERB_ECRYPT_HASHPASSWORD_NT5 HashPassword_NT5;
		PKERB_ECRYPT_HASHPASSWORD_NT6 HashPassword_NT6;
	};
	PKERB_ECRYPT_RANDOMKEY RandomKey;
	PKERB_ECRYPT_CONTROL Control;
	PVOID unk0_null;
	PVOID unk1_null;
	PVOID unk2_null;
} KERB_ECRYPT, *PKERB_ECRYPT;

typedef NTSTATUS (WINAPI * PKERB_RNGFN) (PVOID pbBuffer, ULONG cbBuffer);

typedef struct _KERB_RNG {
	ULONG GeneratorId;
	ULONG Attributes;
	ULONG Seed;
	PKERB_RNGFN RngFn;
} KERB_RNG, *PKERB_RNG;

NTSTATUS WINAPI CDLocateCSystem(ULONG Type, PKERB_ECRYPT *ppCSystem);
NTSTATUS WINAPI CDLocateCheckSum(ULONG Type, PKERB_CHECKSUM *ppCheckSum);
NTSTATUS WINAPI CDLocateRng(ULONG Id, PKERB_RNG *ppRng);
NTSTATUS WINAPI CDGenerateRandomBits(LPVOID pbBuffer, ULONG cbBuffer);