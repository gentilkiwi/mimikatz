/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <dbghelp.h>

typedef struct _KULL_M_MINIDUMP_HANDLE {
	HANDLE hFileMapping;
	LPVOID pMapViewOfFile;
} KULL_M_MINIDUMP_HANDLE, *PKULL_M_MINIDUMP_HANDLE;

BOOL kull_m_minidump_open(IN HANDLE hFile, OUT PKULL_M_MINIDUMP_HANDLE *hMinidump);
BOOL kull_m_minidump_close(IN PKULL_M_MINIDUMP_HANDLE hMinidump);
BOOL kull_m_minidump_copy(IN PKULL_M_MINIDUMP_HANDLE hMinidump, OUT VOID *Destination, IN VOID *Source, IN SIZE_T Length);

LPVOID kull_m_minidump_RVAtoPTR(IN PKULL_M_MINIDUMP_HANDLE hMinidump, RVA64 rva);
LPVOID kull_m_minidump_stream(IN PKULL_M_MINIDUMP_HANDLE hMinidump, MINIDUMP_STREAM_TYPE type, OUT OPTIONAL DWORD *pSize);
LPVOID kull_m_minidump_remapVirtualMemory64(IN PKULL_M_MINIDUMP_HANDLE hMinidump, IN VOID *Source, IN SIZE_T Length);