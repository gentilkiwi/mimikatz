/*++

Copyright (c) Microsoft Corporation. All rights reserved.

Module Name:

    wdbgexts.h

Abstract:

    This file contains the necessary prototypes and data types for a user
    to write a debugger extension DLL.  This header file is also included
    by the NT debuggers (WINDBG & KD).

    This header file must be included after "windows.h" and "dbghelp.h".

    Please see the NT DDK documentation for specific information about
    how to write your own debugger extension DLL.

Environment:

    Win32 only.

Revision History:

--*/

#ifndef _WDBGEXTS_
#define _WDBGEXTS_

#if _MSC_VER > 1000
#pragma once
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if _MSC_VER >= 1200
#pragma warning(push)
#endif
#pragma warning(disable:4115 4201 4204 4214 4221)

// Maximum value of MAXIMUM_PROCESSORS for all platforms.
#define CROSS_PLATFORM_MAXIMUM_PROCESSORS 256

#if !defined(WDBGAPI)
#define WDBGAPI __stdcall
#endif

#if !defined(WDBGAPIV)
#define WDBGAPIV __cdecl
#endif

#ifndef _WINDEF_
typedef CONST void *LPCVOID;
#endif

#ifndef _ULONGLONG_
typedef unsigned __int64 ULONGLONG;
typedef ULONGLONG *PULONGLONG;
#endif

#ifndef __specstrings
// Should include SpecStrings.h to get proper definitions.
#define __field_ecount_opt(x)
#endif

#define WDBGEXTS_MAXSIZE_T ((SIZE_T)~((SIZE_T)0))

typedef
VOID
(WDBGAPIV*PWINDBG_OUTPUT_ROUTINE)(
    PCSTR lpFormat,
    ...
    );

typedef
ULONG_PTR
(WDBGAPI*PWINDBG_GET_EXPRESSION)(
    PCSTR lpExpression
    );

typedef
ULONG
(WDBGAPI*PWINDBG_GET_EXPRESSION32)(
    PCSTR lpExpression
    );

typedef
ULONG64
(WDBGAPI*PWINDBG_GET_EXPRESSION64)(
    PCSTR lpExpression
    );

typedef
VOID
(WDBGAPI*PWINDBG_GET_SYMBOL)(
    PVOID      offset,
    PCHAR      pchBuffer,
    ULONG_PTR *pDisplacement
    );

typedef
VOID
(WDBGAPI*PWINDBG_GET_SYMBOL32)(
    ULONG      offset,
    PCHAR      pchBuffer,
    PULONG     pDisplacement
    );

typedef
VOID
(WDBGAPI*PWINDBG_GET_SYMBOL64)(
    ULONG64    offset,
    PCHAR      pchBuffer,
    PULONG64   pDisplacement
    );

typedef
ULONG
(WDBGAPI*PWINDBG_DISASM)(
    ULONG_PTR *lpOffset,
    PCSTR      lpBuffer,
    ULONG      fShowEffectiveAddress
    );

typedef
ULONG
(WDBGAPI*PWINDBG_DISASM32)(
    ULONG     *lpOffset,
    PCSTR      lpBuffer,
    ULONG      fShowEffectiveAddress
    );

typedef
ULONG
(WDBGAPI*PWINDBG_DISASM64)(
    ULONG64   *lpOffset,
    PCSTR      lpBuffer,
    ULONG      fShowEffectiveAddress
    );

typedef
ULONG
(WDBGAPI*PWINDBG_CHECK_CONTROL_C)(
    VOID
    );

typedef
ULONG
(WDBGAPI*PWINDBG_READ_PROCESS_MEMORY_ROUTINE)(
    ULONG_PTR  offset,
    PVOID      lpBuffer,
    ULONG      cb,
    PULONG     lpcbBytesRead
    );

typedef
ULONG
(WDBGAPI*PWINDBG_READ_PROCESS_MEMORY_ROUTINE32)(
    ULONG      offset,
    PVOID      lpBuffer,
    ULONG      cb,
    PULONG     lpcbBytesRead
    );

typedef
ULONG
(WDBGAPI*PWINDBG_READ_PROCESS_MEMORY_ROUTINE64)(
    ULONG64    offset,
    PVOID      lpBuffer,
    ULONG      cb,
    PULONG     lpcbBytesRead
    );

typedef
ULONG
(WDBGAPI*PWINDBG_WRITE_PROCESS_MEMORY_ROUTINE)(
    ULONG_PTR  offset,
    LPCVOID    lpBuffer,
    ULONG      cb,
    PULONG     lpcbBytesWritten
    );

typedef
ULONG
(WDBGAPI*PWINDBG_WRITE_PROCESS_MEMORY_ROUTINE32)(
    ULONG      offset,
    LPCVOID    lpBuffer,
    ULONG      cb,
    PULONG     lpcbBytesWritten
    );

typedef
ULONG
(WDBGAPI*PWINDBG_WRITE_PROCESS_MEMORY_ROUTINE64)(
    ULONG64    offset,
    LPCVOID    lpBuffer,
    ULONG      cb,
    PULONG     lpcbBytesWritten
    );

typedef
ULONG
(WDBGAPI*PWINDBG_GET_THREAD_CONTEXT_ROUTINE)(
    ULONG       Processor,
    PCONTEXT    lpContext,
    ULONG       cbSizeOfContext
    );

typedef
ULONG
(WDBGAPI*PWINDBG_SET_THREAD_CONTEXT_ROUTINE)(
    ULONG       Processor,
    PCONTEXT    lpContext,
    ULONG       cbSizeOfContext
    );

typedef
ULONG
(WDBGAPI*PWINDBG_IOCTL_ROUTINE)(
    USHORT   IoctlType,
    PVOID    lpvData,
    ULONG    cbSize
    );

typedef
ULONG
(WDBGAPI*PWINDBG_OLDKD_READ_PHYSICAL_MEMORY)(
    ULONGLONG        address,
    PVOID            buffer,
    ULONG            count,
    PULONG           bytesread
    );

typedef
ULONG
(WDBGAPI*PWINDBG_OLDKD_WRITE_PHYSICAL_MEMORY)(
    ULONGLONG        address,
    PVOID            buffer,
    ULONG            length,
    PULONG           byteswritten
    );


typedef struct _EXTSTACKTRACE {
    ULONG       FramePointer;
    ULONG       ProgramCounter;
    ULONG       ReturnAddress;
    ULONG       Args[4];
} EXTSTACKTRACE, *PEXTSTACKTRACE;

typedef struct _EXTSTACKTRACE32 {
    ULONG       FramePointer;
    ULONG       ProgramCounter;
    ULONG       ReturnAddress;
    ULONG       Args[4];
} EXTSTACKTRACE32, *PEXTSTACKTRACE32;

typedef struct _EXTSTACKTRACE64 {
    ULONG64     FramePointer;
    ULONG64     ProgramCounter;
    ULONG64     ReturnAddress;
    ULONG64     Args[4];
} EXTSTACKTRACE64, *PEXTSTACKTRACE64;


typedef
ULONG
(WDBGAPI*PWINDBG_STACKTRACE_ROUTINE)(
    ULONG             FramePointer,
    ULONG             StackPointer,
    ULONG             ProgramCounter,
    PEXTSTACKTRACE    StackFrames,
    ULONG             Frames
    );

typedef
ULONG
(WDBGAPI*PWINDBG_STACKTRACE_ROUTINE32)(
    ULONG             FramePointer,
    ULONG             StackPointer,
    ULONG             ProgramCounter,
    PEXTSTACKTRACE32  StackFrames,
    ULONG             Frames
    );

typedef
ULONG
(WDBGAPI*PWINDBG_STACKTRACE_ROUTINE64)(
    ULONG64           FramePointer,
    ULONG64           StackPointer,
    ULONG64           ProgramCounter,
    PEXTSTACKTRACE64  StackFrames,
    ULONG             Frames
    );

typedef struct _WINDBG_EXTENSION_APIS {
    ULONG                                  nSize;
    PWINDBG_OUTPUT_ROUTINE                 lpOutputRoutine;
    PWINDBG_GET_EXPRESSION                 lpGetExpressionRoutine;
    PWINDBG_GET_SYMBOL                     lpGetSymbolRoutine;
    PWINDBG_DISASM                         lpDisasmRoutine;
    PWINDBG_CHECK_CONTROL_C                lpCheckControlCRoutine;
    PWINDBG_READ_PROCESS_MEMORY_ROUTINE    lpReadProcessMemoryRoutine;
    PWINDBG_WRITE_PROCESS_MEMORY_ROUTINE   lpWriteProcessMemoryRoutine;
    PWINDBG_GET_THREAD_CONTEXT_ROUTINE     lpGetThreadContextRoutine;
    PWINDBG_SET_THREAD_CONTEXT_ROUTINE     lpSetThreadContextRoutine;
    PWINDBG_IOCTL_ROUTINE                  lpIoctlRoutine;
    PWINDBG_STACKTRACE_ROUTINE             lpStackTraceRoutine;
} WINDBG_EXTENSION_APIS, *PWINDBG_EXTENSION_APIS;

typedef struct _WINDBG_EXTENSION_APIS32 {
    ULONG                                  nSize;
    PWINDBG_OUTPUT_ROUTINE                 lpOutputRoutine;
    PWINDBG_GET_EXPRESSION32               lpGetExpressionRoutine;
    PWINDBG_GET_SYMBOL32                   lpGetSymbolRoutine;
    PWINDBG_DISASM32                       lpDisasmRoutine;
    PWINDBG_CHECK_CONTROL_C                lpCheckControlCRoutine;
    PWINDBG_READ_PROCESS_MEMORY_ROUTINE32  lpReadProcessMemoryRoutine;
    PWINDBG_WRITE_PROCESS_MEMORY_ROUTINE32 lpWriteProcessMemoryRoutine;
    PWINDBG_GET_THREAD_CONTEXT_ROUTINE     lpGetThreadContextRoutine;
    PWINDBG_SET_THREAD_CONTEXT_ROUTINE     lpSetThreadContextRoutine;
    PWINDBG_IOCTL_ROUTINE                  lpIoctlRoutine;
    PWINDBG_STACKTRACE_ROUTINE32           lpStackTraceRoutine;
} WINDBG_EXTENSION_APIS32, *PWINDBG_EXTENSION_APIS32;

typedef struct _WINDBG_EXTENSION_APIS64 {
    ULONG                                  nSize;
    PWINDBG_OUTPUT_ROUTINE                 lpOutputRoutine;
    PWINDBG_GET_EXPRESSION64               lpGetExpressionRoutine;
    PWINDBG_GET_SYMBOL64                   lpGetSymbolRoutine;
    PWINDBG_DISASM64                       lpDisasmRoutine;
    PWINDBG_CHECK_CONTROL_C                lpCheckControlCRoutine;
    PWINDBG_READ_PROCESS_MEMORY_ROUTINE64  lpReadProcessMemoryRoutine;
    PWINDBG_WRITE_PROCESS_MEMORY_ROUTINE64 lpWriteProcessMemoryRoutine;
    PWINDBG_GET_THREAD_CONTEXT_ROUTINE     lpGetThreadContextRoutine;
    PWINDBG_SET_THREAD_CONTEXT_ROUTINE     lpSetThreadContextRoutine;
    PWINDBG_IOCTL_ROUTINE                  lpIoctlRoutine;
    PWINDBG_STACKTRACE_ROUTINE64           lpStackTraceRoutine;
} WINDBG_EXTENSION_APIS64, *PWINDBG_EXTENSION_APIS64;


typedef struct _WINDBG_OLD_EXTENSION_APIS {
    ULONG                                  nSize;
    PWINDBG_OUTPUT_ROUTINE                 lpOutputRoutine;
    PWINDBG_GET_EXPRESSION                 lpGetExpressionRoutine;
    PWINDBG_GET_SYMBOL                     lpGetSymbolRoutine;
    PWINDBG_DISASM                         lpDisasmRoutine;
    PWINDBG_CHECK_CONTROL_C                lpCheckControlCRoutine;
} WINDBG_OLD_EXTENSION_APIS, *PWINDBG_OLD_EXTENSION_APIS;

typedef struct _WINDBG_OLDKD_EXTENSION_APIS {
    ULONG                                  nSize;
    PWINDBG_OUTPUT_ROUTINE                 lpOutputRoutine;
    PWINDBG_GET_EXPRESSION32               lpGetExpressionRoutine;
    PWINDBG_GET_SYMBOL32                   lpGetSymbolRoutine;
    PWINDBG_DISASM32                       lpDisasmRoutine;
    PWINDBG_CHECK_CONTROL_C                lpCheckControlCRoutine;
    PWINDBG_READ_PROCESS_MEMORY_ROUTINE32  lpReadVirtualMemRoutine;
    PWINDBG_WRITE_PROCESS_MEMORY_ROUTINE32 lpWriteVirtualMemRoutine;
    PWINDBG_OLDKD_READ_PHYSICAL_MEMORY     lpReadPhysicalMemRoutine;
    PWINDBG_OLDKD_WRITE_PHYSICAL_MEMORY    lpWritePhysicalMemRoutine;
} WINDBG_OLDKD_EXTENSION_APIS, *PWINDBG_OLDKD_EXTENSION_APIS;

typedef
VOID
(WDBGAPI*PWINDBG_OLD_EXTENSION_ROUTINE)(
    ULONG                   dwCurrentPc,
    PWINDBG_EXTENSION_APIS  lpExtensionApis,
    PCSTR                   lpArgumentString
    );

typedef
VOID
(WDBGAPI*PWINDBG_EXTENSION_ROUTINE)(
    HANDLE                  hCurrentProcess,
    HANDLE                  hCurrentThread,
    ULONG                   dwCurrentPc,
    ULONG                   dwProcessor,
    PCSTR                   lpArgumentString
    );

typedef
VOID
(WDBGAPI*PWINDBG_EXTENSION_ROUTINE32)(
    HANDLE                  hCurrentProcess,
    HANDLE                  hCurrentThread,
    ULONG                   dwCurrentPc,
    ULONG                   dwProcessor,
    PCSTR                   lpArgumentString
    );

typedef
VOID
(WDBGAPI*PWINDBG_EXTENSION_ROUTINE64)(
    HANDLE                  hCurrentProcess,
    HANDLE                  hCurrentThread,
    ULONG64                 dwCurrentPc,
    ULONG                   dwProcessor,
    PCSTR                   lpArgumentString
    );

typedef
VOID
(WDBGAPI*PWINDBG_OLDKD_EXTENSION_ROUTINE)(
    ULONG                        dwCurrentPc,
    PWINDBG_OLDKD_EXTENSION_APIS lpExtensionApis,
    PCSTR                        lpArgumentString
    );

typedef
VOID
(WDBGAPI*PWINDBG_EXTENSION_DLL_INIT)(
    PWINDBG_EXTENSION_APIS lpExtensionApis,
    USHORT                 MajorVersion,
    USHORT                 MinorVersion
    );

typedef
VOID
(WDBGAPI*PWINDBG_EXTENSION_DLL_INIT32)(
    PWINDBG_EXTENSION_APIS32 lpExtensionApis,
    USHORT                   MajorVersion,
    USHORT                   MinorVersion
    );

typedef
VOID
(WDBGAPI*PWINDBG_EXTENSION_DLL_INIT64)(
    PWINDBG_EXTENSION_APIS64 lpExtensionApis,
    USHORT                   MajorVersion,
    USHORT                   MinorVersion
    );

typedef
ULONG
(WDBGAPI*PWINDBG_CHECK_VERSION)(
    VOID
    );

#define EXT_API_VERSION_NUMBER   5
#define EXT_API_VERSION_NUMBER32 5
#define EXT_API_VERSION_NUMBER64 6

typedef struct EXT_API_VERSION {
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    USHORT  Revision;
    USHORT  Reserved;
} EXT_API_VERSION, *LPEXT_API_VERSION;

typedef
LPEXT_API_VERSION
(WDBGAPI*PWINDBG_EXTENSION_API_VERSION)(
    VOID
    );

#define IG_KD_CONTEXT                  1
#define IG_READ_CONTROL_SPACE          2
#define IG_WRITE_CONTROL_SPACE         3
#define IG_READ_IO_SPACE               4
#define IG_WRITE_IO_SPACE              5
#define IG_READ_PHYSICAL               6
#define IG_WRITE_PHYSICAL              7
#define IG_READ_IO_SPACE_EX            8
#define IG_WRITE_IO_SPACE_EX           9
#define IG_KSTACK_HELP                10   // obsolete
#define IG_SET_THREAD                 11
#define IG_READ_MSR                   12
#define IG_WRITE_MSR                  13
#define IG_GET_DEBUGGER_DATA          14
#define IG_GET_KERNEL_VERSION         15
#define IG_RELOAD_SYMBOLS             16
#define IG_GET_SET_SYMPATH            17
#define IG_GET_EXCEPTION_RECORD       18
#define IG_IS_PTR64                   19
#define IG_GET_BUS_DATA               20
#define IG_SET_BUS_DATA               21
#define IG_DUMP_SYMBOL_INFO           22
#define IG_LOWMEM_CHECK               23
#define IG_SEARCH_MEMORY              24
#define IG_GET_CURRENT_THREAD         25
#define IG_GET_CURRENT_PROCESS        26
#define IG_GET_TYPE_SIZE              27
#define IG_GET_CURRENT_PROCESS_HANDLE 28
#define IG_GET_INPUT_LINE             29
#define IG_GET_EXPRESSION_EX          30
#define IG_TRANSLATE_VIRTUAL_TO_PHYSICAL 31
#define IG_GET_CACHE_SIZE             32
#define IG_READ_PHYSICAL_WITH_FLAGS   33
#define IG_WRITE_PHYSICAL_WITH_FLAGS  34
#define IG_POINTER_SEARCH_PHYSICAL    35
#define IG_OBSOLETE_PLACEHOLDER_36    36
#define IG_GET_THREAD_OS_INFO         37
#define IG_GET_CLR_DATA_INTERFACE     38
#define IG_MATCH_PATTERN_A            39
#define IG_FIND_FILE                  40
#define IG_TYPED_DATA_OBSOLETE        41
#define IG_QUERY_TARGET_INTERFACE     42
#define IG_TYPED_DATA                 43
#define IG_DISASSEMBLE_BUFFER         44
#define IG_GET_ANY_MODULE_IN_RANGE    45
#define IG_VIRTUAL_TO_PHYSICAL        46
#define IG_PHYSICAL_TO_VIRTUAL        47
#define IG_GET_CONTEXT_EX             48

#define IG_GET_TEB_ADDRESS           128
#define IG_GET_PEB_ADDRESS           129

typedef struct _PROCESSORINFO {
    USHORT      Processor;                // current processor
    USHORT      NumberProcessors;         // total number of processors
} PROCESSORINFO, *PPROCESSORINFO;

typedef struct _READCONTROLSPACE {
    USHORT      Processor;
    ULONG       Address;
    ULONG       BufLen;
    UCHAR       Buf[1];
} READCONTROLSPACE, *PREADCONTROLSPACE;

typedef struct _READCONTROLSPACE32 {
    USHORT      Processor;
    ULONG       Address;
    ULONG       BufLen;
    UCHAR       Buf[1];
} READCONTROLSPACE32, *PREADCONTROLSPACE32;

typedef struct _READCONTROLSPACE64 {
    USHORT      Processor;
    ULONG64     Address;
    ULONG       BufLen;
    UCHAR       Buf[1];
} READCONTROLSPACE64, *PREADCONTROLSPACE64;

typedef struct _IOSPACE {
    ULONG       Address;
    ULONG       Length;                   // 1, 2, or 4 bytes
    ULONG       Data;
} IOSPACE, *PIOSPACE;

typedef struct _IOSPACE32 {
    ULONG       Address;
    ULONG       Length;                   // 1, 2, or 4 bytes
    ULONG       Data;
} IOSPACE32, *PIOSPACE32;

typedef struct _IOSPACE64 {
    ULONG64     Address;
    ULONG       Length;                   // 1, 2, or 4 bytes
    ULONG       Data;
} IOSPACE64, *PIOSPACE64;

typedef struct _IOSPACE_EX {
    ULONG       Address;
    ULONG       Length;                   // 1, 2, or 4 bytes
    ULONG       Data;
    ULONG       InterfaceType;
    ULONG       BusNumber;
    ULONG       AddressSpace;
} IOSPACE_EX, *PIOSPACE_EX;

typedef struct _IOSPACE_EX32 {
    ULONG       Address;
    ULONG       Length;                   // 1, 2, or 4 bytes
    ULONG       Data;
    ULONG       InterfaceType;
    ULONG       BusNumber;
    ULONG       AddressSpace;
} IOSPACE_EX32, *PIOSPACE_EX32;

typedef struct _IOSPACE_EX64 {
    ULONG64     Address;
    ULONG       Length;                   // 1, 2, or 4 bytes
    ULONG       Data;
    ULONG       InterfaceType;
    ULONG       BusNumber;
    ULONG       AddressSpace;
} IOSPACE_EX64, *PIOSPACE_EX64;

typedef struct _GETSETBUSDATA {
    ULONG       BusDataType;
    ULONG       BusNumber;
    ULONG       SlotNumber;
    PVOID       Buffer;
    ULONG       Offset;
    ULONG       Length;
} BUSDATA, *PBUSDATA;

typedef struct _SEARCHMEMORY {
    ULONG64 SearchAddress;
    ULONG64 SearchLength;
    ULONG64 FoundAddress;
    ULONG   PatternLength;
    PVOID   Pattern;
} SEARCHMEMORY, *PSEARCHMEMORY;

typedef struct _PHYSICAL {
    ULONGLONG              Address;
    ULONG                  BufLen;
    UCHAR                  Buf[1];
} PHYSICAL, *PPHYSICAL;

#define PHYS_FLAG_DEFAULT        0
#define PHYS_FLAG_CACHED         1
#define PHYS_FLAG_UNCACHED       2
#define PHYS_FLAG_WRITE_COMBINED 3

typedef struct _PHYSICAL_WITH_FLAGS {
    ULONGLONG              Address;
    ULONG                  BufLen;
    ULONG                  Flags;
    UCHAR                  Buf[1];
} PHYSICAL_WITH_FLAGS, *PPHYSICAL_WITH_FLAGS;

typedef struct _READ_WRITE_MSR {
    ULONG       Msr;
    LONGLONG    Value;
} READ_WRITE_MSR, *PREAD_WRITE_MSR;

typedef struct _GET_SET_SYMPATH {
    PCSTR       Args;       // args to !reload command
    PSTR        Result;     // returns new path
    int         Length;     // Length of result buffer
} GET_SET_SYMPATH, *PGET_SET_SYMPATH;

typedef struct _GET_TEB_ADDRESS {
    ULONGLONG   Address;
} GET_TEB_ADDRESS, *PGET_TEB_ADDRESS;

typedef struct _GET_PEB_ADDRESS {
    ULONG64     CurrentThread;
    ULONGLONG   Address;
} GET_PEB_ADDRESS, *PGET_PEB_ADDRESS;

typedef struct _GET_CURRENT_THREAD_ADDRESS {
    ULONG       Processor;
    ULONG64     Address;
} GET_CURRENT_THREAD_ADDRESS, *PGET_CURRENT_THREAD_ADDRESS;

typedef struct _GET_CURRENT_PROCESS_ADDRESS {
    ULONG       Processor;
    ULONG64     CurrentThread;
    ULONG64     Address;
} GET_CURRENT_PROCESS_ADDRESS, *PGET_CURRENT_PROCESS_ADDRESS;

typedef struct _GET_INPUT_LINE {
    PCSTR       Prompt;
    PSTR        Buffer;
    ULONG       BufferSize;
    ULONG       InputSize;
} GET_INPUT_LINE, *PGET_INPUT_LINE;

typedef struct _GET_EXPRESSION_EX {
    PCSTR       Expression;
    PCSTR       Remainder;
    ULONG64     Value;
} GET_EXPRESSION_EX, *PGET_EXPRESSION_EX;

typedef struct _TRANSLATE_VIRTUAL_TO_PHYSICAL {
    ULONG64     Virtual;
    ULONG64     Physical;
} TRANSLATE_VIRTUAL_TO_PHYSICAL, *PTRANSLATE_VIRTUAL_TO_PHYSICAL;

typedef struct _VIRTUAL_TO_PHYSICAL {
    ULONG       Status;
    ULONG       Size;
    ULONG64     PdeAddress;
    ULONG64     Virtual;
    ULONG64     Physical;
} VIRTUAL_TO_PHYSICAL, *PVIRTUAL_TO_PHYSICAL;

typedef struct _PHYSICAL_TO_VIRTUAL {
    ULONG       Status;
    ULONG       Size;
    ULONG64     PdeAddress;
} PHYSICAL_TO_VIRTUAL, *PPHYSICAL_TO_VIRTUAL;

typedef struct _GET_CONTEXT_EX {
    ULONG       Status;
    ULONG       ContextSize;
    PVOID       pContext;
} GET_CONTEXT_EX, *PGET_CONTEXT_EX;

#define PTR_SEARCH_PHYS_ALL_HITS         0x00000001
#define PTR_SEARCH_PHYS_PTE              0x00000002
#define PTR_SEARCH_PHYS_RANGE_CHECK_ONLY 0x00000004

#define PTR_SEARCH_PHYS_SIZE_SHIFT 3
#define PTR_SEARCH_PHYS_SIZE_MASK  (0xf << PTR_SEARCH_PHYS_SIZE_SHIFT)

#define PTR_SEARCH_NO_SYMBOL_CHECK  0x80000000

typedef struct _POINTER_SEARCH_PHYSICAL {
    IN ULONG64 Offset;
    IN ULONG64 Length;
    IN ULONG64 PointerMin;
    IN ULONG64 PointerMax;
    IN ULONG Flags;
    OUT PULONG64 MatchOffsets;
    IN ULONG MatchOffsetsSize;
    OUT ULONG MatchOffsetsCount;
} POINTER_SEARCH_PHYSICAL, *PPOINTER_SEARCH_PHYSICAL;

typedef struct _WDBGEXTS_THREAD_OS_INFO {
    // System thread ID input.
    ULONG ThreadId;

    //
    // Output information.
    //

    // Exit status is STILL_ACTIVE by default.
    ULONG ExitStatus;
    // Priority class is zero if not known.
    ULONG PriorityClass;
    // Priority defaults to normal.
    ULONG Priority;
    // Times can be zero if not known.
    ULONG64 CreateTime;
    ULONG64 ExitTime;
    ULONG64 KernelTime;
    ULONG64 UserTime;
    // Start offset is zero if not known.
    ULONG64 StartOffset;
    // Affinity is zero if not known.
    ULONG64 Affinity;
} WDBGEXTS_THREAD_OS_INFO, *PWDBGEXTS_THREAD_OS_INFO;

typedef struct _WDBGEXTS_CLR_DATA_INTERFACE {
    // Interface requested.
    const IID* Iid;
    // Interface pointer return.
    PVOID Iface;
} WDBGEXTS_CLR_DATA_INTERFACE, *PWDBGEXTS_CLR_DATA_INTERFACE;

typedef struct _EXT_MATCH_PATTERN_A {
    IN PCSTR Str;
    IN PCSTR Pattern;
    IN ULONG CaseSensitive;
} EXT_MATCH_PATTERN_A, *PEXT_MATCH_PATTERN_A;

#define EXT_FIND_FILE_ALLOW_GIVEN_PATH 0x00000001

typedef struct _EXT_FIND_FILE {
    IN PCWSTR FileName;
    IN ULONG64 IndexedSize;
    IN ULONG ImageTimeDateStamp;
    // Pass zero to ignore.
    IN ULONG ImageCheckSum;
    IN OPTIONAL PVOID ExtraInfo;
    IN ULONG ExtraInfoSize;
    IN ULONG Flags;
    // Free with UnmapViewOfFile.
    OUT PVOID FileMapping;
    OUT ULONG64 FileMappingSize;
    // Free with CloseHandle.
    OUT HANDLE FileHandle;
    // Must be at least MAX_PATH characters if set.
    OUT OPTIONAL PWSTR FoundFileName;
    OUT ULONG FoundFileNameChars;
} EXT_FIND_FILE, *PEXT_FIND_FILE;

#define DEBUG_TYPED_DATA_IS_IN_MEMORY            0x00000001
#define DEBUG_TYPED_DATA_PHYSICAL_DEFAULT        0x00000002
#define DEBUG_TYPED_DATA_PHYSICAL_CACHED         0x00000004
#define DEBUG_TYPED_DATA_PHYSICAL_UNCACHED       0x00000006
#define DEBUG_TYPED_DATA_PHYSICAL_WRITE_COMBINED 0x00000008

// Mask for all physical flags.
#define DEBUG_TYPED_DATA_PHYSICAL_MEMORY 0x0000000e

typedef struct _DEBUG_TYPED_DATA
{
    ULONG64 ModBase;
    ULONG64 Offset;
    ULONG64 EngineHandle;
    ULONG64 Data;
    ULONG Size;
    ULONG Flags;
    ULONG TypeId;
    ULONG BaseTypeId;
    ULONG Tag;
    ULONG Register;
    ULONG64 Internal[9];
} DEBUG_TYPED_DATA, *PDEBUG_TYPED_DATA;

typedef enum _EXT_TDOP {
    EXT_TDOP_COPY,
    EXT_TDOP_RELEASE,
    EXT_TDOP_SET_FROM_EXPR,
    EXT_TDOP_SET_FROM_U64_EXPR,
    EXT_TDOP_GET_FIELD,
    EXT_TDOP_EVALUATE,
    EXT_TDOP_GET_TYPE_NAME,
    EXT_TDOP_OUTPUT_TYPE_NAME,
    EXT_TDOP_OUTPUT_SIMPLE_VALUE,
    EXT_TDOP_OUTPUT_FULL_VALUE,
    EXT_TDOP_HAS_FIELD,
    EXT_TDOP_GET_FIELD_OFFSET,
    EXT_TDOP_GET_ARRAY_ELEMENT,
    EXT_TDOP_GET_DEREFERENCE,
    EXT_TDOP_GET_TYPE_SIZE,
    EXT_TDOP_OUTPUT_TYPE_DEFINITION,
    EXT_TDOP_GET_POINTER_TO,
    EXT_TDOP_SET_FROM_TYPE_ID_AND_U64,
    EXT_TDOP_SET_PTR_FROM_TYPE_ID_AND_U64,

    EXT_TDOP_COUNT
} EXT_TDOP;

// EXT_TDF physical flags must match DEBUG_TYPED.
#define EXT_TDF_PHYSICAL_DEFAULT        0x00000002
#define EXT_TDF_PHYSICAL_CACHED         0x00000004
#define EXT_TDF_PHYSICAL_UNCACHED       0x00000006
#define EXT_TDF_PHYSICAL_WRITE_COMBINED 0x00000008
#define EXT_TDF_PHYSICAL_MEMORY         0x0000000e

// NOTE: Every DEBUG_TYPED_DATA should be released
// via EXT_TDOP_RELEASE when it is no longer needed.
typedef struct _EXT_TYPED_DATA {
    IN EXT_TDOP Operation;
    IN ULONG Flags;
    IN DEBUG_TYPED_DATA InData;
    OUT DEBUG_TYPED_DATA OutData;
    IN ULONG InStrIndex;
    IN ULONG In32;
    OUT ULONG Out32;
    IN ULONG64 In64;
    OUT ULONG64 Out64;
    OUT ULONG StrBufferIndex;
    IN ULONG StrBufferChars;
    OUT ULONG StrCharsNeeded;
    IN OUT ULONG DataBufferIndex;
    IN ULONG DataBufferBytes;
    OUT ULONG DataBytesNeeded;
    OUT HRESULT Status;
    // Must be zeroed.
    ULONG64 Reserved[8];
} EXT_TYPED_DATA, *PEXT_TYPED_DATA;

typedef struct _WDBGEXTS_QUERY_INTERFACE {
    // Interface requested.
    const IID* Iid;
    // Interface pointer return.
    PVOID Iface;
} WDBGEXTS_QUERY_INTERFACE, *PWDBGEXTS_QUERY_INTERFACE;

#define WDBGEXTS_ADDRESS_DEFAULT   0x00000000
#define WDBGEXTS_ADDRESS_SEG16     0x00000001
#define WDBGEXTS_ADDRESS_SEG32     0x00000002
#define WDBGEXTS_ADDRESS_RESERVED0 0x80000000
    
typedef struct _WDBGEXTS_DISASSEMBLE_BUFFER {
    IN ULONG64 InOffset;
    OUT ULONG64 OutOffset;
    // AddrFlags are from above.
    IN ULONG AddrFlags;
    // FormatFlags are from dbgeng's DEBUG_DISASM_*.
    IN ULONG FormatFlags;
    IN ULONG DataBufferBytes;
    IN ULONG DisasmBufferChars;
    IN OPTIONAL PVOID DataBuffer;
    OUT PWSTR DisasmBuffer;
    IN ULONG64 Reserved0[3];
} WDBGEXTS_DISASSEMBLE_BUFFER, *PWDBGEXTS_DISASSEMBLE_BUFFER;

typedef struct _WDBGEXTS_MODULE_IN_RANGE {
    IN ULONG64 Start;
    // Inclusive ending offset.
    IN ULONG64 End;
    OUT ULONG64 FoundModBase;
    OUT ULONG FoundModSize;
} WDBGEXTS_MODULE_IN_RANGE, *PWDBGEXTS_MODULE_IN_RANGE;
    
//
// If DBGKD_VERS_FLAG_DATA is set in Flags, info should be retrieved from
// the KDDEBUGGER_DATA block rather than from the DBGKD_GET_VERSION
// packet.  The data will remain in the version packet for a while to
// reduce compatibility problems.
//

#define DBGKD_VERS_FLAG_MP         0x0001   // kernel is MP built
#define DBGKD_VERS_FLAG_DATA       0x0002   // DebuggerDataList is valid
#define DBGKD_VERS_FLAG_PTR64      0x0004   // native pointers are 64 bits
#define DBGKD_VERS_FLAG_NOMM       0x0008   // No MM - don't decode PTEs
#define DBGKD_VERS_FLAG_HSS        0x0010   // hardware stepping support
#define DBGKD_VERS_FLAG_PARTITIONS 0x0020   // multiple OS partitions exist

#define KDBG_TAG    'GBDK'

//
// KD version MajorVersion high-byte identifiers.
//

typedef enum _DBGKD_MAJOR_TYPES
{
    DBGKD_MAJOR_NT,
    DBGKD_MAJOR_XBOX,
    DBGKD_MAJOR_BIG,
    DBGKD_MAJOR_EXDI,
    DBGKD_MAJOR_NTBD,
    DBGKD_MAJOR_EFI,
    DBGKD_MAJOR_TNT,
    DBGKD_MAJOR_SINGULARITY,
    DBGKD_MAJOR_HYPERVISOR,
    DBGKD_MAJOR_MIDORI,
    DBGKD_MAJOR_COUNT
} DBGKD_MAJOR_TYPES;

#define DBGKD_MAJOR_TYPE(MajorVersion) \
    ((DBGKD_MAJOR_TYPES)((MajorVersion) >> 8))


// **********************************************************************
// DO NOT CHANGE THESE 32 BIT STRUCTURES!
// ONLY MAKE CHAGES TO THE 64 BIT VERSION BELOW!!
// **********************************************************************

//
// The following structure has changed in more than pointer size.
//
// This is the version packet for pre-NT5 Beta 2 systems.
// For now, it is also still used on x86
//
typedef struct _DBGKD_GET_VERSION32 {
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    USHORT  ProtocolVersion;
    USHORT  Flags;
    ULONG   KernBase;
    ULONG   PsLoadedModuleList;

    USHORT  MachineType;

    //
    // help for walking stacks with user callbacks:
    //

    //
    // The address of the thread structure is provided in the
    // WAIT_STATE_CHANGE packet.  This is the offset from the base of
    // the thread structure to the pointer to the kernel stack frame
    // for the currently active usermode callback.
    //

    USHORT  ThCallbackStack;            // offset in thread data

    //
    // these values are offsets into that frame:
    //

    USHORT  NextCallback;               // saved pointer to next callback frame
    USHORT  FramePointer;               // saved frame pointer

    //
    // Address of the kernel callout routine.
    //

    ULONG   KiCallUserMode;             // kernel routine

    //
    // Address of the usermode entry point for callbacks.
    //

    ULONG   KeUserCallbackDispatcher;   // address in ntdll

    //
    // DbgBreakPointWithStatus is a function which takes a ULONG argument
    // and hits a breakpoint.  This field contains the address of the
    // breakpoint instruction.  When the debugger sees a breakpoint
    // at this address, it may retrieve the argument from the first
    // argument register, or on x86 the eax register.
    //

    ULONG   BreakpointWithStatus;       // address of breakpoint

    //
    // Components may register a debug data block for use by
    // debugger extensions.  This is the address of the list head.
    //

    ULONG   DebuggerDataList;

} DBGKD_GET_VERSION32, *PDBGKD_GET_VERSION32;


//
// This is the debugger data packet for pre NT5 Beta 2 systems.
// For now, it is still used on x86
//

typedef struct _DBGKD_DEBUG_DATA_HEADER32 {

    LIST_ENTRY32 List;
    ULONG           OwnerTag;
    ULONG           Size;

} DBGKD_DEBUG_DATA_HEADER32, *PDBGKD_DEBUG_DATA_HEADER32;

typedef struct _KDDEBUGGER_DATA32 {

    DBGKD_DEBUG_DATA_HEADER32 Header;
    ULONG   KernBase;
    ULONG   BreakpointWithStatus;       // address of breakpoint
    ULONG   SavedContext;
    USHORT  ThCallbackStack;            // offset in thread data
    USHORT  NextCallback;               // saved pointer to next callback frame
    USHORT  FramePointer;               // saved frame pointer
    USHORT  PaeEnabled:1;
    ULONG   KiCallUserMode;             // kernel routine
    ULONG   KeUserCallbackDispatcher;   // address in ntdll

    ULONG   PsLoadedModuleList;
    ULONG   PsActiveProcessHead;
    ULONG   PspCidTable;

    ULONG   ExpSystemResourcesList;
    ULONG   ExpPagedPoolDescriptor;
    ULONG   ExpNumberOfPagedPools;

    ULONG   KeTimeIncrement;
    ULONG   KeBugCheckCallbackListHead;
    ULONG   KiBugcheckData;

    ULONG   IopErrorLogListHead;

    ULONG   ObpRootDirectoryObject;
    ULONG   ObpTypeObjectType;

    ULONG   MmSystemCacheStart;
    ULONG   MmSystemCacheEnd;
    ULONG   MmSystemCacheWs;

    ULONG   MmPfnDatabase;
    ULONG   MmSystemPtesStart;
    ULONG   MmSystemPtesEnd;
    ULONG   MmSubsectionBase;
    ULONG   MmNumberOfPagingFiles;

    ULONG   MmLowestPhysicalPage;
    ULONG   MmHighestPhysicalPage;
    ULONG   MmNumberOfPhysicalPages;

    ULONG   MmMaximumNonPagedPoolInBytes;
    ULONG   MmNonPagedSystemStart;
    ULONG   MmNonPagedPoolStart;
    ULONG   MmNonPagedPoolEnd;

    ULONG   MmPagedPoolStart;
    ULONG   MmPagedPoolEnd;
    ULONG   MmPagedPoolInformation;
    ULONG   MmPageSize;

    ULONG   MmSizeOfPagedPoolInBytes;

    ULONG   MmTotalCommitLimit;
    ULONG   MmTotalCommittedPages;
    ULONG   MmSharedCommit;
    ULONG   MmDriverCommit;
    ULONG   MmProcessCommit;
    ULONG   MmPagedPoolCommit;
    ULONG   MmExtendedCommit;

    ULONG   MmZeroedPageListHead;
    ULONG   MmFreePageListHead;
    ULONG   MmStandbyPageListHead;
    ULONG   MmModifiedPageListHead;
    ULONG   MmModifiedNoWritePageListHead;
    ULONG   MmAvailablePages;
    ULONG   MmResidentAvailablePages;

    ULONG   PoolTrackTable;
    ULONG   NonPagedPoolDescriptor;

    ULONG   MmHighestUserAddress;
    ULONG   MmSystemRangeStart;
    ULONG   MmUserProbeAddress;

    ULONG   KdPrintCircularBuffer;
    ULONG   KdPrintCircularBufferEnd;
    ULONG   KdPrintWritePointer;
    ULONG   KdPrintRolloverCount;

    ULONG   MmLoadedUserImageList;

} KDDEBUGGER_DATA32, *PKDDEBUGGER_DATA32;

// **********************************************************************
//
// DO NOT CHANGE KDDEBUGGER_DATA32!!
// ONLY MAKE CHANGES TO KDDEBUGGER_DATA64!!!
//
// **********************************************************************


enum
{
    DBGKD_SIMULATION_NONE,
    DBGKD_SIMULATION_EXDI
};

#define KD_SECONDARY_VERSION_DEFAULT 0

#define KD_SECONDARY_VERSION_AMD64_OBSOLETE_CONTEXT_1 0
#define KD_SECONDARY_VERSION_AMD64_OBSOLETE_CONTEXT_2 1
#define KD_SECONDARY_VERSION_AMD64_CONTEXT            2

#ifdef _AMD64_
#define CURRENT_KD_SECONDARY_VERSION \
    KD_SECONDARY_VERSION_AMD64_CONTEXT
#else
#define CURRENT_KD_SECONDARY_VERSION KD_SECONDARY_VERSION_DEFAULT
#endif

typedef struct _DBGKD_GET_VERSION64 {
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    UCHAR   ProtocolVersion;
    UCHAR   KdSecondaryVersion; // Cannot be 'A' for compat with dump header
    USHORT  Flags;
    USHORT  MachineType;

    //
    // Protocol command support descriptions.
    // These allow the debugger to automatically
    // adapt to different levels of command support
    // in different kernels.
    //

    // One beyond highest packet type understood, zero based.
    UCHAR   MaxPacketType;
    // One beyond highest state change understood, zero based.
    UCHAR   MaxStateChange;
    // One beyond highest state manipulate message understood, zero based.
    UCHAR   MaxManipulate;

    // Kind of execution environment the kernel is running in,
    // such as a real machine or a simulator.  Written back
    // by the simulation if one exists.
    UCHAR   Simulation;

    USHORT  Unused[1];

    ULONG64 KernBase;
    ULONG64 PsLoadedModuleList;

    //
    // Components may register a debug data block for use by
    // debugger extensions.  This is the address of the list head.
    //
    // There will always be an entry for the debugger.
    //

    ULONG64 DebuggerDataList;

} DBGKD_GET_VERSION64, *PDBGKD_GET_VERSION64;


//
// This structure is used by the debugger for all targets
// It is the same size as DBGKD_DATA_HEADER on all systems
//
typedef struct _DBGKD_DEBUG_DATA_HEADER64 {

    //
    // Link to other blocks
    //

    LIST_ENTRY64 List;

    //
    // This is a unique tag to identify the owner of the block.
    // If your component only uses one pool tag, use it for this, too.
    //

    ULONG           OwnerTag;

    //
    // This must be initialized to the size of the data block,
    // including this structure.
    //

    ULONG           Size;

} DBGKD_DEBUG_DATA_HEADER64, *PDBGKD_DEBUG_DATA_HEADER64;


//
// This structure is the same size on all systems.  The only field
// which must be translated by the debugger is Header.List.
//

//
// DO NOT ADD OR REMOVE FIELDS FROM THE MIDDLE OF THIS STRUCTURE!!!
//
// If you remove a field, replace it with an "unused" placeholder.
// Do not reuse fields until there has been enough time for old debuggers
// and extensions to age out.
//
typedef struct _KDDEBUGGER_DATA64 {

    DBGKD_DEBUG_DATA_HEADER64 Header;

    //
    // Base address of kernel image
    //

    ULONG64   KernBase;

    //
    // DbgBreakPointWithStatus is a function which takes an argument
    // and hits a breakpoint.  This field contains the address of the
    // breakpoint instruction.  When the debugger sees a breakpoint
    // at this address, it may retrieve the argument from the first
    // argument register, or on x86 the eax register.
    //

    ULONG64   BreakpointWithStatus;       // address of breakpoint

    //
    // Address of the saved context record during a bugcheck
    //
    // N.B. This is an automatic in KeBugcheckEx's frame, and
    // is only valid after a bugcheck.
    //

    ULONG64   SavedContext;

    //
    // help for walking stacks with user callbacks:
    //

    //
    // The address of the thread structure is provided in the
    // WAIT_STATE_CHANGE packet.  This is the offset from the base of
    // the thread structure to the pointer to the kernel stack frame
    // for the currently active usermode callback.
    //

    USHORT  ThCallbackStack;            // offset in thread data

    //
    // these values are offsets into that frame:
    //

    USHORT  NextCallback;               // saved pointer to next callback frame
    USHORT  FramePointer;               // saved frame pointer

    //
    // pad to a quad boundary
    //
    USHORT  PaeEnabled:1;

    //
    // Address of the kernel callout routine.
    //

    ULONG64   KiCallUserMode;             // kernel routine

    //
    // Address of the usermode entry point for callbacks.
    //

    ULONG64   KeUserCallbackDispatcher;   // address in ntdll


    //
    // Addresses of various kernel data structures and lists
    // that are of interest to the kernel debugger.
    //

    ULONG64   PsLoadedModuleList;
    ULONG64   PsActiveProcessHead;
    ULONG64   PspCidTable;

    ULONG64   ExpSystemResourcesList;
    ULONG64   ExpPagedPoolDescriptor;
    ULONG64   ExpNumberOfPagedPools;

    ULONG64   KeTimeIncrement;
    ULONG64   KeBugCheckCallbackListHead;
    ULONG64   KiBugcheckData;

    ULONG64   IopErrorLogListHead;

    ULONG64   ObpRootDirectoryObject;
    ULONG64   ObpTypeObjectType;

    ULONG64   MmSystemCacheStart;
    ULONG64   MmSystemCacheEnd;
    ULONG64   MmSystemCacheWs;

    ULONG64   MmPfnDatabase;
    ULONG64   MmSystemPtesStart;
    ULONG64   MmSystemPtesEnd;
    ULONG64   MmSubsectionBase;
    ULONG64   MmNumberOfPagingFiles;

    ULONG64   MmLowestPhysicalPage;
    ULONG64   MmHighestPhysicalPage;
    ULONG64   MmNumberOfPhysicalPages;

    ULONG64   MmMaximumNonPagedPoolInBytes;
    ULONG64   MmNonPagedSystemStart;
    ULONG64   MmNonPagedPoolStart;
    ULONG64   MmNonPagedPoolEnd;

    ULONG64   MmPagedPoolStart;
    ULONG64   MmPagedPoolEnd;
    ULONG64   MmPagedPoolInformation;
    ULONG64   MmPageSize;

    ULONG64   MmSizeOfPagedPoolInBytes;

    ULONG64   MmTotalCommitLimit;
    ULONG64   MmTotalCommittedPages;
    ULONG64   MmSharedCommit;
    ULONG64   MmDriverCommit;
    ULONG64   MmProcessCommit;
    ULONG64   MmPagedPoolCommit;
    ULONG64   MmExtendedCommit;

    ULONG64   MmZeroedPageListHead;
    ULONG64   MmFreePageListHead;
    ULONG64   MmStandbyPageListHead;
    ULONG64   MmModifiedPageListHead;
    ULONG64   MmModifiedNoWritePageListHead;
    ULONG64   MmAvailablePages;
    ULONG64   MmResidentAvailablePages;

    ULONG64   PoolTrackTable;
    ULONG64   NonPagedPoolDescriptor;

    ULONG64   MmHighestUserAddress;
    ULONG64   MmSystemRangeStart;
    ULONG64   MmUserProbeAddress;

    ULONG64   KdPrintCircularBuffer;
    ULONG64   KdPrintCircularBufferEnd;
    ULONG64   KdPrintWritePointer;
    ULONG64   KdPrintRolloverCount;

    ULONG64   MmLoadedUserImageList;

    // NT 5.1 Addition

    ULONG64   NtBuildLab;
    ULONG64   KiNormalSystemCall;

    // NT 5.0 hotfix addition

    ULONG64   KiProcessorBlock;
    ULONG64   MmUnloadedDrivers;
    ULONG64   MmLastUnloadedDriver;
    ULONG64   MmTriageActionTaken;
    ULONG64   MmSpecialPoolTag;
    ULONG64   KernelVerifier;
    ULONG64   MmVerifierData;
    ULONG64   MmAllocatedNonPagedPool;
    ULONG64   MmPeakCommitment;
    ULONG64   MmTotalCommitLimitMaximum;
    ULONG64   CmNtCSDVersion;

    // NT 5.1 Addition

    ULONG64   MmPhysicalMemoryBlock;
    ULONG64   MmSessionBase;
    ULONG64   MmSessionSize;
    ULONG64   MmSystemParentTablePage;

    // Server 2003 addition

    ULONG64   MmVirtualTranslationBase;

    USHORT    OffsetKThreadNextProcessor;
    USHORT    OffsetKThreadTeb;
    USHORT    OffsetKThreadKernelStack;
    USHORT    OffsetKThreadInitialStack;

    USHORT    OffsetKThreadApcProcess;
    USHORT    OffsetKThreadState;
    USHORT    OffsetKThreadBStore;
    USHORT    OffsetKThreadBStoreLimit;

    USHORT    SizeEProcess;
    USHORT    OffsetEprocessPeb;
    USHORT    OffsetEprocessParentCID;
    USHORT    OffsetEprocessDirectoryTableBase;

    USHORT    SizePrcb;
    USHORT    OffsetPrcbDpcRoutine;
    USHORT    OffsetPrcbCurrentThread;
    USHORT    OffsetPrcbMhz;

    USHORT    OffsetPrcbCpuType;
    USHORT    OffsetPrcbVendorString;
    USHORT    OffsetPrcbProcStateContext;
    USHORT    OffsetPrcbNumber;

    USHORT    SizeEThread;

    ULONG64   KdPrintCircularBufferPtr;
    ULONG64   KdPrintBufferSize;

    ULONG64   KeLoaderBlock;

    USHORT    SizePcr;
    USHORT    OffsetPcrSelfPcr;
    USHORT    OffsetPcrCurrentPrcb;
    USHORT    OffsetPcrContainedPrcb;

    USHORT    OffsetPcrInitialBStore;
    USHORT    OffsetPcrBStoreLimit;
    USHORT    OffsetPcrInitialStack;
    USHORT    OffsetPcrStackLimit;

    USHORT    OffsetPrcbPcrPage;
    USHORT    OffsetPrcbProcStateSpecialReg;
    USHORT    GdtR0Code;
    USHORT    GdtR0Data;

    USHORT    GdtR0Pcr;
    USHORT    GdtR3Code;
    USHORT    GdtR3Data;
    USHORT    GdtR3Teb;

    USHORT    GdtLdt;
    USHORT    GdtTss;
    USHORT    Gdt64R3CmCode;
    USHORT    Gdt64R3CmTeb;

    ULONG64   IopNumTriageDumpDataBlocks;
    ULONG64   IopTriageDumpDataBlocks;

    // Longhorn addition

    ULONG64   VfCrashDataBlock;
    ULONG64   MmBadPagesDetected;
    ULONG64   MmZeroedPageSingleBitErrorsDetected;

    // Windows 7 addition

    ULONG64   EtwpDebuggerData;
    USHORT    OffsetPrcbContext;

} KDDEBUGGER_DATA64, *PKDDEBUGGER_DATA64;



/************************************

   Type Dump Ioctl

*************************************/


//
// Fields are not indented if this is set
//
#define DBG_DUMP_NO_INDENT                0x00000001
//
// Offsets are not printed if this is set
//
#define DBG_DUMP_NO_OFFSET                0x00000002
//
// Verbose output
//
#define DBG_DUMP_VERBOSE                  0x00000004
//
// Callback is done for each of fields
//
#define DBG_DUMP_CALL_FOR_EACH            0x00000008
//
// A list of type is dumped, listLink should have info about next element pointer
//
#define DBG_DUMP_LIST                     0x00000020
//
// Nothing is printed if this is set (only callbacks and data copies done)
//
#define DBG_DUMP_NO_PRINT                 0x00000040
//
// Ioctl returns the size as usual, but will not do field prints/callbacks if this is set
//
#define DBG_DUMP_GET_SIZE_ONLY            0x00000080
//
// Specifies how much deep into structs we can go
//
#define DBG_DUMP_RECUR_LEVEL(l)           ((l & 0xf) << 8)
//
// No newlines are printed after each field
//
#define DBG_DUMP_COMPACT_OUT              0x00002000
//
// An array of type is dumped, number of elements can be specified in listLink->size
//
#define DBG_DUMP_ARRAY                    0x00008000
//
// The specified addr value is actually the address of field listLink->fName
//
#define DBG_DUMP_ADDRESS_OF_FIELD         0x00010000

//
// The specified addr value is actually the adress at the end of type
//
#define DBG_DUMP_ADDRESS_AT_END           0x00020000

//
// This could be used to copy only the primitive types like ULONG, PVOID etc.
//    - will not work with structures/unions
//
#define DBG_DUMP_COPY_TYPE_DATA           0x00040000
//
// Flag to allow read directly from physical memory
//
#define DBG_DUMP_READ_PHYSICAL            0x00080000
//
// This causes a function type to be dumped in format function(arg1, arg2, ...)
//
#define DBG_DUMP_FUNCTION_FORMAT          0x00100000
//
// This recurses on a struct but doesn't expand pointers
//
#define DBG_DUMP_BLOCK_RECURSE            0x00200000
//
// Match the type size to resolve ambiguity in case multiple matches with same name are available
//
#define DBG_DUMP_MATCH_SIZE               0x00400000

//
// Obsolete defs
//
#define DBG_RETURN_TYPE                   0
#define DBG_RETURN_SUBTYPES               0
#define DBG_RETURN_TYPE_VALUES            0

//
// Dump and callback optons for fields - Options used in FIELD_INFO.fOptions
//

//
// Callback is done before printing the field if this is set
//
#define DBG_DUMP_FIELD_CALL_BEFORE_PRINT  0x00000001
//
// No callback is done
//
#define DBG_DUMP_FIELD_NO_CALLBACK_REQ    0x00000002
//
// Subfields of the fields are processesed
//
#define DBG_DUMP_FIELD_RECUR_ON_THIS      0x00000004
//
// fName must match completely for the field to be dumped instead just a prefix
//  match by default
//
#define DBG_DUMP_FIELD_FULL_NAME          0x00000008
//
// This causes array elements of an array field to be printed
//
#define DBG_DUMP_FIELD_ARRAY              0x00000010
//
// The data of the field is copied into fieldCallBack
//
#define DBG_DUMP_FIELD_COPY_FIELD_DATA    0x00000020
//
// In callback or when Ioctl returns, the FIELD_INFO.address has the address of field.
//  If no address is supplied for the type, it contains total offset of the field.
//
#define DBG_DUMP_FIELD_RETURN_ADDRESS     0x00001000
//
// Return the offset and size in bits instead of bytes is case of Bitfield
//
#define DBG_DUMP_FIELD_SIZE_IN_BITS       0x00002000
//
// Nothing is printed  for field if this is set (only callbacks and data copies done)
//
#define DBG_DUMP_FIELD_NO_PRINT           0x00004000
//
// If the field is a pointer, it is dumped as a string, ANSI, WCHAR, MULTI or GUID
// depending on following options
//
#define DBG_DUMP_FIELD_DEFAULT_STRING     0x00010000
#define DBG_DUMP_FIELD_WCHAR_STRING       0x00020000
#define DBG_DUMP_FIELD_MULTI_STRING       0x00040000
#define DBG_DUMP_FIELD_GUID_STRING        0x00080000


//
// Error status returned on TYPE DUMP Ioctl failure
//
#define MEMORY_READ_ERROR            0x01
#define SYMBOL_TYPE_INDEX_NOT_FOUND  0x02
#define SYMBOL_TYPE_INFO_NOT_FOUND   0x03
#define FIELDS_DID_NOT_MATCH         0x04
#define NULL_SYM_DUMP_PARAM          0x05
#define NULL_FIELD_NAME              0x06
#define INCORRECT_VERSION_INFO       0x07
#define EXIT_ON_CONTROLC             0x08
#define CANNOT_ALLOCATE_MEMORY       0x09
#define INSUFFICIENT_SPACE_TO_COPY   0x0a
#define ADDRESS_TYPE_INDEX_NOT_FOUND 0x0b


//////////////////////////////////////////////////////////////////////////*/


typedef
ULONG
(WDBGAPI*PSYM_DUMP_FIELD_CALLBACK)(
    struct _FIELD_INFO *pField,
    PVOID UserContext
    );

typedef struct _FIELD_INFO {
   PUCHAR       fName;          // Name of the field
   PUCHAR       printName;      // Name to be printed at dump
   ULONG        size;           // Size of the field
   ULONG        fOptions;       // Dump Options for the field
   ULONG64      address;        // address of the field
   union {
       PVOID    fieldCallBack;  // Return info or callBack routine for the field
       PVOID    pBuffer;        // the type data is copied into this
   };
   ULONG        TypeId;         // OUT Type index of the field
   ULONG        FieldOffset;    // OUT Offset of field inside struct
   ULONG        BufferSize;     // size of buffer used with DBG_DUMP_FIELD_COPY_FIELD_DATA
   struct _BitField {
       USHORT Position;         // OUT set to start position for bitfield
       USHORT Size;             // OUT set to size for bitfields
   } BitField;
   ULONG        fPointer:2;     // OUT set to 1 for pointers, 3 for 64bit pointers
   ULONG        fArray:1;       // OUT set to 1 for array types
   ULONG        fStruct:1;      // OUT set to 1 for struct/class tyoes
   ULONG        fConstant:1;    // OUT set to 1 for constants (enumerate as fields)
   ULONG        fStatic:1;      // OUT set to 1 for statics (class/struct static members)
   ULONG        Reserved:26;    // unused
} FIELD_INFO, *PFIELD_INFO;

typedef struct _SYM_DUMP_PARAM {
   ULONG               size;          // size of this struct
   PUCHAR              sName;         // type name
   ULONG               Options;       // Dump options
   ULONG64             addr;          // Address to take data for type
   PFIELD_INFO         listLink;      // fName here would be used to do list dump
   union {
       PVOID           Context;       // Usercontext passed to CallbackRoutine
       PVOID           pBuffer;       // the type data is copied into this
   };
   PSYM_DUMP_FIELD_CALLBACK CallbackRoutine;
                                      // Routine called back
   ULONG               nFields;       // # elements in Fields
   __field_ecount_opt(nFields) PFIELD_INFO         Fields;        // Used to return information about field
   ULONG64             ModBase;       // OUT Module base address containing type
   ULONG               TypeId;        // OUT Type index of the symbol
   ULONG               TypeSize;      // OUT Size of type
   ULONG               BufferSize;    // IN size of buffer (used with DBG_DUMP_COPY_TYPE_DATA)
   ULONG               fPointer:2;    // OUT set to 1 for pointers, 3 for 64bit pointers
   ULONG               fArray:1;      // OUT set to 1 for array types
   ULONG               fStruct:1;     // OUT set to 1 for struct/class tyoes
   ULONG               fConstant:1;   // OUT set to 1 for constant types (unused)
   ULONG               Reserved:27;   // unused
} SYM_DUMP_PARAM, *PSYM_DUMP_PARAM;

#ifdef __cplusplus
#define CPPMOD extern "C"
#else
#define CPPMOD
#endif


#ifndef NOEXTAPI

#if   defined(KDEXT_64BIT)
#define WINDBG_EXTENSION_APIS WINDBG_EXTENSION_APIS64
#define PWINDBG_EXTENSION_APIS PWINDBG_EXTENSION_APIS64
#define PWINDBG_EXTENSION_ROUTINE PWINDBG_EXTENSION_ROUTINE64
#define DECLARE_API(s) DECLARE_API64(s)
#elif defined(KDEXT_32BIT)
#define WINDBG_EXTENSION_APIS WINDBG_EXTENSION_APIS32
#define PWINDBG_EXTENSION_APIS PWINDBG_EXTENSION_APIS32
#define PWINDBG_EXTENSION_ROUTINE PWINDBG_EXTENSION_ROUTINE32
#define DECLARE_API(s) DECLARE_API32(s)
#else
#define DECLARE_API(s)                             \
    CPPMOD VOID                                    \
    s(                                             \
        HANDLE                 hCurrentProcess,    \
        HANDLE                 hCurrentThread,     \
        ULONG                  dwCurrentPc,        \
        ULONG                  dwProcessor,        \
        PCSTR                  args                \
     )
#endif

#define DECLARE_API32(s)                           \
    CPPMOD VOID                                    \
    s(                                             \
        HANDLE                 hCurrentProcess,    \
        HANDLE                 hCurrentThread,     \
        ULONG                  dwCurrentPc,        \
        ULONG                  dwProcessor,        \
        PCSTR                  args                \
     )

#define DECLARE_API64(s)                           \
    CPPMOD VOID                                    \
    s(                                             \
        HANDLE                 hCurrentProcess,    \
        HANDLE                 hCurrentThread,     \
        ULONG64                dwCurrentPc,        \
        ULONG                  dwProcessor,        \
        PCSTR                  args                \
     )


extern WINDBG_EXTENSION_APIS   ExtensionApis;


#define dprintf          (ExtensionApis.lpOutputRoutine)
#define GetExpression    (ExtensionApis.lpGetExpressionRoutine)
#define CheckControlC    (ExtensionApis.lpCheckControlCRoutine)
#define GetContext       (ExtensionApis.lpGetThreadContextRoutine)
#define SetContext       (ExtensionApis.lpSetThreadContextRoutine)
#define Ioctl            (ExtensionApis.lpIoctlRoutine)
#define Disasm           (ExtensionApis.lpDisasmRoutine)
#define GetSymbol        (ExtensionApis.lpGetSymbolRoutine)
#define ReadMemory       (ExtensionApis.lpReadProcessMemoryRoutine)
#define WriteMemory      (ExtensionApis.lpWriteProcessMemoryRoutine)
#define StackTrace       (ExtensionApis.lpStackTraceRoutine)


#define GetKdContext(ppi) \
    Ioctl( IG_KD_CONTEXT, (PVOID)ppi, sizeof(*ppi) )


//
// BOOL
// GetDebuggerData(
//     ULONG Tag,
//     PVOID Buf,
//     ULONG Size
//     )
//

#define GetDebuggerData(TAG, BUF, SIZE)                             \
      ( (((PDBGKD_DEBUG_DATA_HEADER64)(BUF))->OwnerTag = (TAG)),      \
        (((PDBGKD_DEBUG_DATA_HEADER64)(BUF))->Size = (SIZE)),         \
        Ioctl( IG_GET_DEBUGGER_DATA, (PVOID)(BUF), (SIZE) ) )

// Check if LocalAlloc is prototyped
//#ifdef _WINBASE_

__inline VOID
ReadPhysical(
    ULONG64             address,
    PVOID               buf,
    ULONG               size,
    PULONG              sizer
    )
{
    PPHYSICAL phy = NULL;
    *sizer = 0;
    if (size <= WDBGEXTS_MAXSIZE_T - sizeof(*phy)) {
        phy = (PPHYSICAL)LocalAlloc(LPTR,  sizeof(*phy) + size );
    }
    if (phy) {
        ZeroMemory( phy->Buf, size );
        phy->Address = address;
        phy->BufLen = size;
        Ioctl( IG_READ_PHYSICAL, (PVOID)phy, sizeof(*phy) + size );
        *sizer = phy->BufLen;
        CopyMemory( buf, phy->Buf, *sizer );
        LocalFree( phy );
    }
}

__inline VOID
WritePhysical(
    ULONG64             address,
    PVOID               buf,
    ULONG               size,
    PULONG              sizew
    )
{
    PPHYSICAL phy = NULL;
    *sizew = 0;
    if (size <= WDBGEXTS_MAXSIZE_T - sizeof(*phy)) {
        phy = (PPHYSICAL)LocalAlloc(LPTR, sizeof(*phy) + size );
    }
    if (phy) {
        ZeroMemory( phy->Buf, size );
        phy->Address = address;
        phy->BufLen = size;
        CopyMemory( phy->Buf, buf, size );
        Ioctl( IG_WRITE_PHYSICAL, (PVOID)phy, sizeof(*phy) + size );
        *sizew = phy->BufLen;
        LocalFree( phy );
    }
}

__inline VOID
ReadPhysicalWithFlags(
    ULONG64             address,
    PVOID               buf,
    ULONG               size,
    ULONG               flags,
    PULONG              sizer
    )
{
    PPHYSICAL_WITH_FLAGS phy = NULL;
    *sizer = 0;
    if (size <= WDBGEXTS_MAXSIZE_T - sizeof(*phy)) {
        phy = (PPHYSICAL_WITH_FLAGS)LocalAlloc(LPTR,  sizeof(*phy) + size );
    }
    if (phy) {
        ZeroMemory( phy->Buf, size );
        phy->Address = address;
        phy->BufLen = size;
        phy->Flags = flags;
        Ioctl( IG_READ_PHYSICAL_WITH_FLAGS, (PVOID)phy, sizeof(*phy) + size );
        *sizer = phy->BufLen;
        CopyMemory( buf, phy->Buf, *sizer );
        LocalFree( phy );
    }
}

__inline VOID
WritePhysicalWithFlags(
    ULONG64             address,
    PVOID               buf,
    ULONG               size,
    ULONG               flags,
    PULONG              sizew
    )
{
    PPHYSICAL_WITH_FLAGS phy = NULL;
    *sizew = 0;
    if (size <= WDBGEXTS_MAXSIZE_T - sizeof(*phy)) {
        phy = (PPHYSICAL_WITH_FLAGS)LocalAlloc(LPTR, sizeof(*phy) + size );
    }
    if (phy) {
        ZeroMemory( phy->Buf, size );
        phy->Address = address;
        phy->BufLen = size;
        phy->Flags = flags;
        CopyMemory( phy->Buf, buf, size );
        Ioctl( IG_WRITE_PHYSICAL_WITH_FLAGS, (PVOID)phy, sizeof(*phy) + size );
        *sizew = phy->BufLen;
        LocalFree( phy );
    }
}

__inline VOID
ReadMsr(
    ULONG       MsrReg,
    ULONGLONG   *MsrValue
    )
{
    READ_WRITE_MSR msr;

    msr.Msr = MsrReg;
    Ioctl( IG_READ_MSR, (PVOID)&msr, sizeof(msr) );

    *MsrValue = msr.Value;
}

__inline VOID
WriteMsr(
    ULONG       MsrReg,
    ULONGLONG   MsrValue
    )
{
    READ_WRITE_MSR msr;

    msr.Msr = MsrReg;
    msr.Value = MsrValue;
    Ioctl( IG_WRITE_MSR, (PVOID)&msr, sizeof(msr) );
}

__inline VOID
SetThreadForOperation(
    ULONG_PTR * Thread
    )
{
    Ioctl(IG_SET_THREAD, (PVOID)Thread, sizeof(PULONG));
}

__inline VOID
SetThreadForOperation32(
    ULONG Thread
    )
{
    Ioctl(IG_SET_THREAD, (PVOID)LongToPtr(Thread), sizeof(ULONG));
}

__inline VOID
SetThreadForOperation64(
    PULONG64 Thread
    )
{
    Ioctl(IG_SET_THREAD, (PVOID)Thread, sizeof(ULONG64));
}


__inline VOID
ReadControlSpace(
    USHORT  processor,
    ULONG   address,
    PVOID   buf,
    ULONG   size
    )
{
    PREADCONTROLSPACE prc = NULL;
    if (size <= WDBGEXTS_MAXSIZE_T - sizeof(*prc)) {
        prc = (PREADCONTROLSPACE)LocalAlloc(LPTR, sizeof(*prc) + size );
    }
    if (prc) {
        ZeroMemory( prc->Buf, size );
        prc->Processor = processor;
        prc->Address = address;
        prc->BufLen = size;
        Ioctl( IG_READ_CONTROL_SPACE, (PVOID)prc, sizeof(*prc) + size );
        CopyMemory( buf, prc->Buf, size );
        LocalFree( prc );
    }
}

__inline VOID
ReadControlSpace32(
    USHORT  processor,
    ULONG   address,
    PVOID   buf,
    ULONG   size
    )
{
    PREADCONTROLSPACE32 prc = NULL;
    if (size <= WDBGEXTS_MAXSIZE_T - sizeof(*prc)) {
        prc = (PREADCONTROLSPACE32)LocalAlloc(LPTR, sizeof(*prc) + size );
    }
    if (prc) {
        ZeroMemory( prc->Buf, size );
        prc->Processor = processor;
        prc->Address = address;
        prc->BufLen = size;
        Ioctl( IG_READ_CONTROL_SPACE, (PVOID)prc, sizeof(*prc) + size );
        CopyMemory( buf, prc->Buf, size );
        LocalFree( prc );
    }
}

#define ReadTypedControlSpace32( _Proc, _Addr, _Buf )  \
     ReadControlSpace64( (USHORT)(_Proc), (ULONG)(_Addr), (PVOID)&(_Buf), (ULONG)sizeof(_Buf) )

__inline VOID
ReadControlSpace64(
    USHORT  processor,
    ULONG64 address,
    PVOID   buf,
    ULONG   size
    )
{
    PREADCONTROLSPACE64 prc = NULL;
    if (size <= WDBGEXTS_MAXSIZE_T - sizeof(*prc)) {
        prc = (PREADCONTROLSPACE64)LocalAlloc(LPTR, sizeof(*prc) + size );
    }
    if (prc) {
        ZeroMemory( prc->Buf, size );
        prc->Processor = processor;
        prc->Address = address;
        prc->BufLen = size;
        Ioctl( IG_READ_CONTROL_SPACE, (PVOID)prc, sizeof(*prc) + size );
        CopyMemory( buf, prc->Buf, size );
        LocalFree( prc );
    }
}

#define ReadTypedControlSpace64( _Proc, _Addr, _Buf )  \
     ReadControlSpace64( (USHORT)(_Proc), (ULONG64)(_Addr), (PVOID)&(_Buf), (ULONG)sizeof(_Buf) )

__inline VOID
WriteControlSpace(
    USHORT  processor,
    ULONG   address,
    PVOID   buf,
    ULONG   size
    )
{
    PREADCONTROLSPACE64 prc = NULL;
    if (size <= WDBGEXTS_MAXSIZE_T - sizeof(*prc)) {
        prc = (PREADCONTROLSPACE64)LocalAlloc(LPTR, sizeof(*prc) + size );
    }
    if (prc) {
        ZeroMemory( prc->Buf, size );
        prc->Processor = processor;
        prc->Address = address;
        prc->BufLen = size;
        CopyMemory( prc->Buf, buf, size );
        Ioctl( IG_WRITE_CONTROL_SPACE, (PVOID)prc, sizeof(*prc) + size );
        LocalFree( prc );
    }
}

// #endif //  _WINBASE_

__inline VOID
ReadIoSpace(
    ULONG   address,
    PULONG  data,
    PULONG  size
    )
{
    IOSPACE is;
    is.Address = address;
    is.Length = *size;
    Ioctl( IG_READ_IO_SPACE, (PVOID)&is, sizeof(is) );
    memcpy(data, &is.Data, is.Length);
    *size = is.Length;
}

__inline VOID
ReadIoSpace32(
    ULONG   address,
    PULONG  data,
    PULONG  size
    )
{
    IOSPACE32 is;
    is.Address = address;
    is.Length = *size;
    Ioctl( IG_READ_IO_SPACE, (PVOID)&is, sizeof(is) );
    memcpy(data, &is.Data, is.Length);
    *size = is.Length;
}

__inline VOID
ReadIoSpace64(
    ULONG64 address,
    PULONG  data,
    PULONG  size
    )
{
    IOSPACE64 is;
    is.Address = address;
    is.Length = *size;
    Ioctl( IG_READ_IO_SPACE, (PVOID)&is, sizeof(is) );
    memcpy(data, &is.Data, is.Length);
    *size = is.Length;
}

__inline VOID
WriteIoSpace(
    ULONG   address,
    ULONG   data,
    PULONG  size
    )
{
    IOSPACE is;
    is.Address = (ULONG)address;
    is.Length = *size;
    is.Data = data;
    Ioctl( IG_WRITE_IO_SPACE, (PVOID)&is, sizeof(is) );
    *size = is.Length;
}

__inline VOID
WriteIoSpace32(
    ULONG   address,
    ULONG   data,
    PULONG  size
    )
{
    IOSPACE32 is;
    is.Address = address;
    is.Length = *size;
    is.Data = data;
    Ioctl( IG_WRITE_IO_SPACE, (PVOID)&is, sizeof(is) );
    *size = is.Length;
}

__inline VOID
WriteIoSpace64(
    ULONG64 address,
    ULONG   data,
    PULONG  size
    )
{
    IOSPACE64 is;
    is.Address = address;
    is.Length = *size;
    is.Data = data;
    Ioctl( IG_WRITE_IO_SPACE, (PVOID)&is, sizeof(is) );
    *size = is.Length;
}

__inline VOID
ReadIoSpaceEx(
    ULONG   address,
    PULONG  data,
    PULONG  size,
    ULONG   interfacetype,
    ULONG   busnumber,
    ULONG   addressspace
    )
{
    IOSPACE_EX is;
    is.Address = (ULONG)address;
    is.Length = *size;
    is.Data = 0;
    is.InterfaceType = interfacetype;
    is.BusNumber = busnumber;
    is.AddressSpace = addressspace;
    Ioctl( IG_READ_IO_SPACE_EX, (PVOID)&is, sizeof(is) );
    *data = is.Data;
    *size = is.Length;
}

__inline VOID
ReadIoSpaceEx32(
    ULONG   address,
    PULONG  data,
    PULONG  size,
    ULONG   interfacetype,
    ULONG   busnumber,
    ULONG   addressspace
    )
{
    IOSPACE_EX32 is;
    is.Address = address;
    is.Length = *size;
    is.Data = 0;
    is.InterfaceType = interfacetype;
    is.BusNumber = busnumber;
    is.AddressSpace = addressspace;
    Ioctl( IG_READ_IO_SPACE_EX, (PVOID)&is, sizeof(is) );
    *data = is.Data;
    *size = is.Length;
}

__inline VOID
ReadIoSpaceEx64(
    ULONG64 address,
    PULONG  data,
    PULONG  size,
    ULONG   interfacetype,
    ULONG   busnumber,
    ULONG   addressspace
    )
{
    IOSPACE_EX64 is;
    is.Address = address;
    is.Length = *size;
    is.Data = 0;
    is.InterfaceType = interfacetype;
    is.BusNumber = busnumber;
    is.AddressSpace = addressspace;
    Ioctl( IG_READ_IO_SPACE_EX, (PVOID)&is, sizeof(is) );
    *data = is.Data;
    *size = is.Length;
}

__inline VOID
WriteIoSpaceEx(
    ULONG   address,
    ULONG   data,
    PULONG  size,
    ULONG   interfacetype,
    ULONG   busnumber,
    ULONG   addressspace
    )
{
    IOSPACE_EX is;
    is.Address = (ULONG)address;
    is.Length = *size;
    is.Data = data;
    is.InterfaceType = interfacetype;
    is.BusNumber = busnumber;
    is.AddressSpace = addressspace;
    Ioctl( IG_WRITE_IO_SPACE_EX, (PVOID)&is, sizeof(is) );
    *size = is.Length;
}

__inline VOID
WriteIoSpaceEx32(
    ULONG   address,
    ULONG   data,
    PULONG  size,
    ULONG   interfacetype,
    ULONG   busnumber,
    ULONG   addressspace
    )
{
    IOSPACE_EX32 is;
    is.Address = address;
    is.Length = *size;
    is.Data = data;
    is.InterfaceType = interfacetype;
    is.BusNumber = busnumber;
    is.AddressSpace = addressspace;
    Ioctl( IG_WRITE_IO_SPACE_EX, (PVOID)&is, sizeof(is) );
    *size = is.Length;
}

__inline VOID
WriteIoSpaceEx64(
    ULONG64 address,
    ULONG   data,
    PULONG  size,
    ULONG   interfacetype,
    ULONG   busnumber,
    ULONG   addressspace
    )
{
    IOSPACE_EX64 is;
    is.Address = address;
    is.Length = *size;
    is.Data = data;
    is.InterfaceType = interfacetype;
    is.BusNumber = busnumber;
    is.AddressSpace = addressspace;
    Ioctl( IG_WRITE_IO_SPACE_EX, (PVOID)&is, sizeof(is) );
    *size = is.Length;
}

__inline VOID
ReloadSymbols(
    IN PSTR Arg OPTIONAL
    )
/*++

Routine Description:

    Calls the debugger to reload symbols.

Arguments:

    Args - Supplies the tail of a !reload command string.

        !reload [flags] [module[=address]]
        flags:   /n  do not load from usermode list
                 /u  unload symbols, no reload
                 /v  verbose

        A value of NULL is equivalent to an empty string

Return Value:

    None

--*/
{
    Ioctl(IG_RELOAD_SYMBOLS, (PVOID)Arg, Arg?((ULONG)strlen(Arg)+1):0);
}

__inline VOID
GetSetSympath(
    IN PSTR Arg,
    OUT PSTR Result OPTIONAL,
    IN int Length
    )
/*++

Routine Description:

    Calls the debugger to set or retrieve symbol search path.

Arguments:

    Arg - Supplies new search path.  If Arg is NULL or string is empty,
            the search path is not changed and the current setting is
            returned in Result.  When the symbol search path is changed,
            a call to ReloadSymbols is made implicitly.

    Result - OPTIONAL Returns the symbol search path setting.

    Length - Supplies the size of the buffer supplied by Result.

Return Value:

    None

--*/
{
    GET_SET_SYMPATH gss;
    gss.Args = Arg;
    gss.Result = Result;
    gss.Length = Length;
    Ioctl(IG_GET_SET_SYMPATH, (PVOID)&gss, sizeof(gss));
}

#if   defined(KDEXT_64BIT)

__inline
ULONG
IsPtr64(
    void
    )
{
    ULONG flag;
    ULONG dw;

    if (Ioctl(IG_IS_PTR64, &dw, sizeof(dw))) {
        flag = ((dw != 0) ? 1 : 0);
    } else {
        flag = 0;
    }
    return flag;
}

__inline
ULONG
ReadListEntry(
    ULONG64 Address,
    PLIST_ENTRY64 List
    )
{
    ULONG cb;
    if (IsPtr64()) {
        return (ReadMemory(Address, (PVOID)List, sizeof(*List), &cb) &&
                cb == sizeof(*List));
    } else {
        LIST_ENTRY32 List32;
        ULONG Status;
        Status = ReadMemory(Address,
                            (PVOID)&List32,
                            sizeof(List32),
                            &cb);
        if (Status && cb == sizeof(List32)) {
            List->Flink = (ULONG64)(LONG64)(LONG)List32.Flink;
            List->Blink = (ULONG64)(LONG64)(LONG)List32.Blink;
            return 1;
        }
        return 0;
    }
}

__inline
ULONG
ReadPointer(
    ULONG64 Address,
    PULONG64 Pointer
    )
{
    ULONG cb;
    if (IsPtr64()) {
        return (ReadMemory(Address, (PVOID)Pointer, sizeof(*Pointer), &cb) &&
                cb == sizeof(*Pointer));
    } else {
        ULONG Pointer32;
        ULONG Status;
        Status = ReadMemory(Address,
                            (PVOID)&Pointer32,
                            sizeof(Pointer32),
                            &cb);
        if (Status && cb == sizeof(Pointer32)) {
            *Pointer = (ULONG64)(LONG64)(LONG)Pointer32;
            return 1;
        }
        return 0;
    }
}

__inline
ULONG
WritePointer(
    ULONG64 Address,
    ULONG64 Pointer
    )
{
    ULONG cb;
    if (IsPtr64()) {
        return (WriteMemory(Address, &Pointer, sizeof(Pointer), &cb) &&
                cb == sizeof(Pointer));
    } else {
        ULONG Pointer32 = (ULONG)Pointer;
        ULONG Status;
        Status = WriteMemory(Address,
                             &Pointer32,
                             sizeof(Pointer32),
                             &cb);
        return (Status && cb == sizeof(Pointer32)) ? 1 : 0;
    }
}

/**
   This does Ioctl call for type info and returns size of the type on success.

 **/
__inline
ULONG
GetTypeSize (
   IN LPCSTR    Type
   )
{
   SYM_DUMP_PARAM Sym = {
      sizeof (SYM_DUMP_PARAM), (PUCHAR)Type, DBG_DUMP_NO_PRINT | DBG_DUMP_GET_SIZE_ONLY, 0,
      NULL, NULL, NULL, 0, NULL
   };

   return Ioctl( IG_GET_TYPE_SIZE, &Sym, Sym.size );
}

/**
    GetFieldData

   Copies the value of the specified field into pOutValue assuming TypeAddress
   points to start of the type in debugee.

   If the Field is NULL and the size of Type is <= 8 Whole type value is read into
   pOutValue. This is to allow to read in primitive types suchas ULONG, PVOID etc.

   If address is zero this considers Type a global variable.

   It raises an exception if OutSize is less than size to be copied.

   Returns 0 on success, errorvalue (defined with SYM_DUMP_PARAM) otherwise.

 **/
__inline
ULONG
GetFieldData (
    IN  ULONG64 TypeAddress,
    IN  LPCSTR  Type,
    IN  LPCSTR  Field,
    IN  ULONG   OutSize,
    OUT PVOID   pOutValue
   )
{
   FIELD_INFO flds = {(PUCHAR)Field, NULL, 0, DBG_DUMP_FIELD_FULL_NAME | DBG_DUMP_FIELD_COPY_FIELD_DATA | DBG_DUMP_FIELD_RETURN_ADDRESS, 0, pOutValue};
   SYM_DUMP_PARAM Sym = {
      sizeof (SYM_DUMP_PARAM), (PUCHAR)Type, DBG_DUMP_NO_PRINT, TypeAddress,
      NULL, NULL, NULL, 1, &flds
   };
   ULONG RetVal;

   if (!Field) {
       Sym.nFields =0; Sym.Options |= DBG_DUMP_COPY_TYPE_DATA;
       Sym.Context = pOutValue;
   }

   ZeroMemory(pOutValue, OutSize);
   RetVal = Ioctl( IG_DUMP_SYMBOL_INFO, &Sym, Sym.size );

   if (OutSize < ((Field == NULL) ? 8 : flds.size)) {
       // Fail
       dprintf("Not enough space to read %s-%s\n", Type, Field);
       RaiseException((DWORD)EXCEPTION_ACCESS_VIOLATION, 0, 0, NULL);
       return 0;
   }
   return RetVal;
}

//
// Typecast the buffer where value is to be read
//
#define GetFieldValue(Addr, Type, Field, OutValue)         \
     GetFieldData(Addr, Type, Field, sizeof(OutValue), (PVOID) &(OutValue))

//
// Used to read in value of a short (<= 8 bytes) fields
//
__inline
ULONG64
GetShortField (
    IN  ULONG64 TypeAddress,
    IN  LPCSTR  Name,
    IN  USHORT  StoreAddress
   )
{
    static ULONG64 SavedAddress;
    static PUCHAR  SavedName;
    static ULONG   ReadPhysical;
    FIELD_INFO flds = {(PUCHAR) Name, NULL, 0, DBG_DUMP_FIELD_FULL_NAME, 0, NULL};
    SYM_DUMP_PARAM Sym = {
       sizeof (SYM_DUMP_PARAM), SavedName, DBG_DUMP_NO_PRINT | ((StoreAddress & 2) ? DBG_DUMP_READ_PHYSICAL : 0),
       SavedAddress, NULL, NULL, NULL, 1, &flds
    };


    if (StoreAddress) {
        Sym.sName = (PUCHAR) Name;
        Sym.nFields = 0;
        SavedName = (PUCHAR) Name;
        Sym.addr = SavedAddress = TypeAddress;
        ReadPhysical = (StoreAddress & 2);
        return SavedAddress ? Ioctl( IG_DUMP_SYMBOL_INFO, &Sym, Sym.size ) : MEMORY_READ_ERROR; // zero on success
    } else {
        Sym.Options |= ReadPhysical ? DBG_DUMP_READ_PHYSICAL : 0;
    }

    if (!Ioctl( IG_DUMP_SYMBOL_INFO, &Sym, Sym.size )) {
        return flds.address;
    }
    return 0;
}

//
// Stores the address and type name for future reads
//
#define InitTypeRead(Addr, Type)  GetShortField(Addr, #Type, 1)
#define InitTypeStrRead(Addr, TypeStr)  GetShortField(Addr, TypeStr, 1)

//
// Stores the address and type name for future reads
//
#define InitTypeReadPhysical(Addr, Type)  GetShortField(Addr, #Type, 3)
#define InitTypeStrReadPhysical(Addr, TypeStr)  GetShortField(Addr, TypeStr, 3)

//
// Returns the field's value as ULONG64 if size of field is <= sizeof (ULONG64)
//
#define ReadField(Field)          GetShortField(0, #Field, 0)
#define ReadFieldStr(FieldStr)          GetShortField(0, FieldStr, 0)

//
// Read in a pointer value
//
__inline
ULONG
ReadPtr(
    ULONG64 Addr,
    PULONG64 pPointer
    )
{
    return !ReadPointer(Addr, pPointer);
}

/*
 * ListType
 *
 *  Routine ListType gives a callback on each element in the list of Type.
 *
 *   Type  :  Name of the type to be listed
 *
 *   NextPointer : Name of field which gives address of next element in list
 *
 *   Context, CallbackRoutine :
 *            Context and the callback routine. The address field in PFIELD_INFO
 *            parameter of callback contains the address of next Type element in list.
 *
 *   Address, ListByFieldAddress :
 *      if ListByFieldAddress is 0, Adress is the address of first element of Type List.
 *
 *   Lists by LIST_ENTRY are also handled implicitly (by Ioctl). If the NextPointer
 *   is a pointer to LIST_ENTRY type, the type address is properly calculated by
 *   subtracting the offsets.
 *
 *      If ListByFieldAddress is 1, the Address is considered to be the address of field
 *   "NextPointer" of the first Type element and first element address is derived
 *   from it.
 *
 */

__inline
ULONG
ListType (
    IN LPCSTR  Type,
    IN ULONG64 Address,
    IN USHORT  ListByFieldAddress,
    IN LPCSTR  NextPointer,
    IN PVOID   Context,
    IN PSYM_DUMP_FIELD_CALLBACK CallbackRoutine
    )
{
    FIELD_INFO flds = {(PUCHAR)NextPointer, NULL, 0, 0, 0, NULL};
    SYM_DUMP_PARAM Sym = {
       sizeof (SYM_DUMP_PARAM), (PUCHAR) Type, DBG_DUMP_NO_PRINT | DBG_DUMP_LIST, Address,
       &flds, Context, CallbackRoutine, 0, NULL
    };

    if (ListByFieldAddress==1) {
        //
        // Address is the address of "NextPointer"
        //
        Sym.Options |= DBG_DUMP_ADDRESS_OF_FIELD;
    }

    return Ioctl( IG_DUMP_SYMBOL_INFO, &Sym, Sym.size );
}


/**

   Routine to get offset of a "Field" of "Type" on a debugee machine. This uses
   Ioctl call for type info.
   Returns 0 on success, Ioctl error value otherwise.

 **/

__inline
ULONG
GetFieldOffset (
   IN LPCSTR     Type,
   IN LPCSTR     Field,
   OUT PULONG   pOffset
   )
{
   FIELD_INFO flds = {
       (PUCHAR)Field,
       (PUCHAR)"",
       0,
       DBG_DUMP_FIELD_FULL_NAME | DBG_DUMP_FIELD_RETURN_ADDRESS,
       0,
       NULL};

   SYM_DUMP_PARAM Sym = {
      sizeof (SYM_DUMP_PARAM),
      (PUCHAR)Type,
      DBG_DUMP_NO_PRINT,
      0,
      NULL,
      NULL,
      NULL,
      1,
      &flds
   };

   ULONG Err;

   Sym.nFields = 1;
   Err = Ioctl( IG_DUMP_SYMBOL_INFO, &Sym, Sym.size );
   *pOffset = (ULONG) flds.FieldOffset;
   return Err;
}


#endif // defined(KDEXT_64BIT)

__inline VOID
 GetCurrentProcessHandle(
    PHANDLE hp
    )
{
    Ioctl(IG_GET_CURRENT_PROCESS_HANDLE, hp, sizeof(HANDLE));
}

__inline VOID
 GetTebAddress(
    PULONGLONG Address
    )
{
    GET_TEB_ADDRESS gpt;
    gpt.Address = 0;
    Ioctl(IG_GET_TEB_ADDRESS, (PVOID)&gpt, sizeof(gpt));
    *Address = gpt.Address;
}

__inline VOID
 GetPebAddress(
    ULONG64 CurrentThread,
    PULONGLONG Address
    )
{
    GET_PEB_ADDRESS gpt;
    gpt.CurrentThread = CurrentThread;
    gpt.Address = 0;
    Ioctl(IG_GET_PEB_ADDRESS, (PVOID)&gpt, sizeof(gpt));
    *Address = gpt.Address;
}

__inline VOID
 GetCurrentThreadAddr(
    DWORD    Processor,
    PULONG64  Address
    )
{
    GET_CURRENT_THREAD_ADDRESS ct;
    ct.Processor = Processor;
    Ioctl(IG_GET_CURRENT_THREAD, (PVOID)&ct, sizeof(ct));
    *Address = ct.Address;
}

__inline VOID
 GetCurrentProcessAddr(
    DWORD    Processor,
    ULONG64  CurrentThread,
    PULONG64 Address
    )
{
    GET_CURRENT_PROCESS_ADDRESS cp;
    cp.Processor = Processor;
    cp.CurrentThread = CurrentThread;
    Ioctl(IG_GET_CURRENT_PROCESS, (PVOID)&cp, sizeof(cp));
    *Address = cp.Address;
}

__inline VOID
SearchMemory(
    ULONG64  SearchAddress,
    ULONG64  SearchLength,
    ULONG    PatternLength,
    PVOID    Pattern,
    PULONG64 FoundAddress
    )
{
    SEARCHMEMORY sm;
    sm.SearchAddress = SearchAddress;
    sm.SearchLength  = SearchLength;
    sm.FoundAddress  = 0;
    sm.PatternLength = PatternLength;
    sm.Pattern       = Pattern;
    Ioctl(IG_SEARCH_MEMORY, (PVOID)&sm, sizeof(sm));
    *FoundAddress = sm.FoundAddress;
}

__inline ULONG
GetInputLine(
    PCSTR Prompt,
    PSTR Buffer,
    ULONG BufferSize
    )
{
    GET_INPUT_LINE InLine;
    InLine.Prompt = Prompt;
    InLine.Buffer = Buffer;
    InLine.BufferSize = BufferSize;
    if (Ioctl(IG_GET_INPUT_LINE, (PVOID)&InLine, sizeof(InLine)))
    {
        return InLine.InputSize;
    }
    else
    {
        return 0;
    }
}

__inline BOOL
GetExpressionEx(
    PCSTR Expression,
    ULONG64* Value,
    PCSTR* Remainder
    )
{
    GET_EXPRESSION_EX Expr;
    Expr.Expression = Expression;
    if (Ioctl(IG_GET_EXPRESSION_EX, (PVOID)&Expr, sizeof(Expr)))
    {
        *Value = Expr.Value;

        if (Remainder != NULL)
        {
            *Remainder = Expr.Remainder;
        }

        return TRUE;
    }

    return FALSE;
}

__inline BOOL
TranslateVirtualToPhysical(
    ULONG64 Virtual,
    ULONG64* Physical
    )
{
    TRANSLATE_VIRTUAL_TO_PHYSICAL VToP;
    VToP.Virtual = Virtual;
    if (Ioctl(IG_TRANSLATE_VIRTUAL_TO_PHYSICAL, (PVOID)&VToP, sizeof(VToP)))
    {
        *Physical = VToP.Physical;
        return TRUE;
    }

    return FALSE;
}

__inline BOOL
GetDebuggerCacheSize(
    OUT PULONG64 CacheSize
    )
{
    return Ioctl(IG_GET_CACHE_SIZE, (PVOID) CacheSize, sizeof(ULONG64));
}

__inline BOOL
ExtMatchPatternA(
    IN PCSTR Str,
    IN PCSTR Pattern,
    IN BOOL CaseSensitive
    )
{
    EXT_MATCH_PATTERN_A Args;

    Args.Str = Str;
    Args.Pattern = Pattern;
    Args.CaseSensitive = CaseSensitive;
    return Ioctl(IG_MATCH_PATTERN_A, (PVOID)&Args, sizeof(Args));
}

#endif

#pragma warning(default:4115 4201 4204 4214 4221)
#if _MSC_VER >= 1200
#pragma warning(pop)
#endif

#ifdef __cplusplus
}
#endif

#endif // _WDBGEXTS_

