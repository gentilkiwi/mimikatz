/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_minidump.h"
#include "kull_m_kernel.h"

void * _ReturnAddress(void);
//#pragma intrinsic(_ReturnAddress)

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

typedef struct _KULL_M_MEMORY_HANDLE_KERNEL
{
	HANDLE hDriver;
} KULL_M_MEMORY_HANDLE_KERNEL, *PKULL_M_MEMORY_HANDLE_KERNEL;

typedef struct _KULL_M_MEMORY_HANDLE {
	KULL_M_MEMORY_TYPE type;
	union {
		PKULL_M_MEMORY_HANDLE_PROCESS pHandleProcess;
		PKULL_M_MEMORY_HANDLE_FILE pHandleFile;
		PKULL_M_MEMORY_HANDLE_PROCESS_DMP pHandleProcessDmp;
		PKULL_M_MEMORY_HANDLE_KERNEL pHandleDriver;
	};
} KULL_M_MEMORY_HANDLE, *PKULL_M_MEMORY_HANDLE;
KULL_M_MEMORY_HANDLE KULL_M_MEMORY_GLOBAL_OWN_HANDLE;

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
BOOL kull_m_memory_free(IN PKULL_M_MEMORY_ADDRESS Address);
BOOL kull_m_memory_equal(IN PKULL_M_MEMORY_ADDRESS Address1, IN PKULL_M_MEMORY_ADDRESS Address2, IN SIZE_T Lenght);

#define COMPRESSION_FORMAT_NONE          (0x0000)   // winnt
#define COMPRESSION_FORMAT_DEFAULT       (0x0001)   // winnt
#define COMPRESSION_FORMAT_LZNT1         (0x0002)   // winnt

#define COMPRESSION_ENGINE_STANDARD      (0x0000)   // winnt
#define COMPRESSION_ENGINE_MAXIMUM       (0x0100)   // winnt
#define COMPRESSION_ENGINE_HIBER         (0x0200)   // winnt

NTSYSAPI NTSTATUS NTAPI RtlGetCompressionWorkSpaceSize (__in USHORT CompressionFormatAndEngine, __out PULONG CompressBufferWorkSpaceSize, __out PULONG CompressFragmentWorkSpaceSize);
NTSYSAPI NTSTATUS NTAPI RtlCompressBuffer (__in USHORT CompressionFormatAndEngine, __in_bcount(UncompressedBufferSize) PUCHAR UncompressedBuffer, __in ULONG UncompressedBufferSize, __out_bcount_part(CompressedBufferSize, *FinalCompressedSize) PUCHAR CompressedBuffer, __in ULONG CompressedBufferSize, __in ULONG UncompressedChunkSize, __out PULONG FinalCompressedSize, __in PVOID WorkSpace);
NTSYSAPI NTSTATUS NTAPI RtlDecompressBuffer (__in USHORT CompressionFormat, __out_bcount_part(UncompressedBufferSize, *FinalUncompressedSize) PUCHAR UncompressedBuffer, __in ULONG UncompressedBufferSize, __in_bcount(CompressedBufferSize) PUCHAR CompressedBuffer, __in ULONG CompressedBufferSize, __out PULONG FinalUncompressedSize );

BOOL kull_m_memory_quick_compress(IN PVOID data, IN DWORD size, IN OUT PVOID *compressedData, IN OUT PDWORD compressedSize);
BOOL kull_m_memory_quick_decompress(IN PVOID data, IN DWORD size, IN OPTIONAL DWORD originalSize, IN OUT PVOID *decompressedData, IN OUT PDWORD decompressedSize);

void kull_m_memory_reverseBytes(PVOID start, SIZE_T size);