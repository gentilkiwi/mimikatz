/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"

typedef NTSTATUS (* PKKLL_M_MODULE_CALLBACK) (SIZE_T szBufferIn, PVOID bufferIn, PKIWI_BUFFER outBuffer, PAUX_MODULE_EXTENDED_INFO pModule, PVOID pvArg, BOOLEAN * mustContinue);

typedef struct _KKLL_M_MODULE_FROM_ADDR {
	BOOLEAN isFound;
	ULONG_PTR addr;
} KKLL_M_MODULE_FROM_ADDR, *PKKLL_M_MODULE_FROM_ADDR;

typedef struct _KKLL_M_MODULE_BASIC_INFOS {
	PUCHAR addr;
	SIZE_T size;
} KKLL_M_MODULE_BASIC_INFOS, *PKKLL_M_MODULE_BASIC_INFOS;

NTSTATUS kkll_m_modules_enum(SIZE_T szBufferIn, PVOID bufferIn, PKIWI_BUFFER outBuffer, PKKLL_M_MODULE_CALLBACK callback, PVOID pvArg);

NTSTATUS kkll_m_modules_list_callback(SIZE_T szBufferIn, PVOID bufferIn, PKIWI_BUFFER outBuffer, PAUX_MODULE_EXTENDED_INFO pModule, PVOID pvArg, BOOLEAN * mustContinue);

NTSTATUS kkll_m_modules_fromAddr(PKIWI_BUFFER outBuffer, PVOID addr);
NTSTATUS kkll_m_modules_fromAddr_callback(SIZE_T szBufferIn, PVOID bufferIn, PKIWI_BUFFER outBuffer, PAUX_MODULE_EXTENDED_INFO pModule, PVOID pvArg, BOOLEAN * mustContinue);

NTSTATUS kkll_m_modules_first_callback(SIZE_T szBufferIn, PVOID bufferIn, PKIWI_BUFFER outBuffer, PAUX_MODULE_EXTENDED_INFO pModule, PVOID pvArg, BOOLEAN * mustContinue);