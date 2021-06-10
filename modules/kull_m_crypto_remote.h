/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_remotelib.h"

//typedef BOOL (WINAPI * PCRYPTPROTECTMEMORY) (__inout LPVOID pDataIn, __in DWORD cbDataIn, __in DWORD dwFlags);
typedef BOOL (WINAPI * PCRYPTUNPROTECTMEMORY) (__inout LPVOID pDataIn, __in DWORD cbDataIn, __in DWORD dwFlags);

BOOL WINAPI kull_m_crypto_remote_CryptProtectMemory_Generic(__in PKULL_M_MEMORY_HANDLE hProcess, __in BOOL bIsProtect, __inout LPVOID pDataIn, __in DWORD cbDataIn, __in DWORD dwFlags);

#define kull_m_crypto_remote_CryptProtectMemory(hProcess, pDataIn, cbDataIn, dwFlags)	kull_m_crypto_remote_CryptProtectMemory_Generic(hProcess, TRUE, pDataIn, cbDataIn, dwFlags)
#define kull_m_crypto_remote_CryptUnprotectMemory(hProcess, pDataIn, cbDataIn, dwFlags)	kull_m_crypto_remote_CryptProtectMemory_Generic(hProcess, FALSE, pDataIn, cbDataIn, dwFlags)