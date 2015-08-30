/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include <ntstatus.h>
#define WIN32_NO_STATUS
#define SECURITY_WIN32
#include <windows.h>
#include <ntsecapi.h>
#include <sspi.h>
#include <sddl.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>
#include <stdio.h>

#ifdef _M_X64
	#define MIMIKATZ_ARCH_A "x64"
#else ifdef _M_IX86
	#define MIMIKATZ_ARCH_A "x86"
#endif

#define MIMIKATZ_A				"mimikatz"
#define MIMIKATZ_VERSION_A		"2.0 alpha"
#define MIMIKATZ_CODENAME_A		"Kiwi en C"
#define MIMIKATZ_FULL_A			MIMIKATZ_A " " MIMIKATZ_VERSION_A " (" MIMIKATZ_ARCH_A ") release \"" MIMIKATZ_CODENAME_A "\" (" __DATE__ " " __TIME__ ")"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define LM_NTLM_HASH_LENGTH	16

void klog(FILE * logfile, PCWCHAR format, ...);
void klog_password(FILE * logfile, PUNICODE_STRING pPassword);

typedef struct _REMOTE_LIB_FUNC {
	DWORD	outputSize;
	PVOID	outputData;
	DWORD	inputSize;
	BYTE	inputData[ANYSIZE_ARRAY];
} REMOTE_LIB_FUNC, *PREMOTE_LIB_FUNC;