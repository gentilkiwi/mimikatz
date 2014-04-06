/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globals.h"
#include "kull_m_minidump.h"

typedef enum _KULL_M_MEMORY_TYPE
{
	KULL_M_MEMORY_TYPE_OWN,
	KULL_M_MEMORY_TYPE_PROCESS,
	KULL_M_MEMORY_TYPE_PROCESS_DMP,
	KULL_M_MEMORY_TYPE_KERNEL,
	KULL_M_MEMORY_TYPE_KERNEL_DMP,
	KULL_M_MEMORY_TYPE_HYBERFILE,
	KULL_M_MEMORY_TYPE_FILE,
} KULL_M_MEMORY_TYPE;

typedef struct _KULL_M_MEMORY_HANDLE_PROCESS
{
	HANDLE hProcess;
} KULL_M_MEMORY_HANDLE_PROCESS, *PKULL_M_MEMORY_HANDLE_PROCESS;

typedef struct _KULL_M_MEMORY_HANDLE_FILE
{
	HANDLE hFile;
} KULL_M_MEMORY_HANDLE_FILE, *PKULL_M_MEMORY_HANDLE_FILE;

typedef struct _KULL_M_MEMORY_HANDLE_PROCESS_DMP
{
	PKULL_M_MINIDUMP_HANDLE hMinidump;
} KULL_M_MEMORY_HANDLE_PROCESS_DMP, *PKULL_M_MEMORY_HANDLE_PROCESS_DMP;

typedef struct _KULL_M_MEMORY_HANDLE {
	KULL_M_MEMORY_TYPE type;
	union {
		PKULL_M_MEMORY_HANDLE_PROCESS pHandleProcess;
		PKULL_M_MEMORY_HANDLE_FILE pHandleFile;
		PKULL_M_MEMORY_HANDLE_PROCESS_DMP pHandleProcessDmp;
	};
} KULL_M_MEMORY_HANDLE, *PKULL_M_MEMORY_HANDLE;

typedef struct _KULL_M_MEMORY_ADDRESS {
	LPVOID address;
	PKULL_M_MEMORY_HANDLE hMemory;
} KULL_M_MEMORY_ADDRESS, *PKULL_M_MEMORY_ADDRESS;

typedef struct _KULL_M_MEMORY_RANGE {
	KULL_M_MEMORY_ADDRESS kull_m_memoryAdress;
	SIZE_T size;
} KULL_M_MEMORY_RANGE, *PKULL_M_MEMORY_RANGE;

typedef struct _KULL_M_MEMORY_SEARCH {
	KULL_M_MEMORY_RANGE kull_m_memoryRange;
	LPVOID result;
} KULL_M_MEMORY_SEARCH, *PKULL_M_MEMORY_SEARCH;

BOOL kull_m_memory_copy(OUT PKULL_M_MEMORY_ADDRESS Destination, IN PKULL_M_MEMORY_ADDRESS Source, IN SIZE_T Length);
BOOL kull_m_memory_search(IN PKULL_M_MEMORY_ADDRESS Pattern, IN SIZE_T Length, IN PKULL_M_MEMORY_SEARCH Search, IN BOOL bufferMeFirst);

BOOL kull_m_memory_query(IN PKULL_M_MEMORY_ADDRESS Address, OUT PMEMORY_BASIC_INFORMATION MemoryInfo);
BOOL kull_m_memory_protect(IN PKULL_M_MEMORY_ADDRESS Address, IN SIZE_T dwSize, IN DWORD flNewProtect, OUT OPTIONAL PDWORD lpflOldProtect);

BOOL kull_m_memory_open(IN KULL_M_MEMORY_TYPE Type, IN HANDLE hAny, OUT PKULL_M_MEMORY_HANDLE *hMemory);
PKULL_M_MEMORY_HANDLE kull_m_memory_close(IN PKULL_M_MEMORY_HANDLE hMemory);

BOOL kull_m_memory_alloc(IN PKULL_M_MEMORY_ADDRESS Address, IN SIZE_T Lenght, IN DWORD Protection);
BOOL kull_m_memory_free(IN PKULL_M_MEMORY_ADDRESS Address, IN SIZE_T Lenght);
