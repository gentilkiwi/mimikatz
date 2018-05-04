/***    types.h  - Common defines for FCI/FDI stuff -- goes into FCI/FDI.H
 *
 *  Copyright (C) Microsoft Corporation
 *  All Rights Reserved.
 *
 */

#ifndef INCLUDED_TYPES_FCI_FDI
#define INCLUDED_TYPES_FCI_FDI 1

#ifdef __cplusplus
extern "C" {            /* Assume C declarations for C++ */
#endif  /* __cplusplus */


//** Define away for 32-bit build
#ifndef HUGE
#define HUGE
#endif

#ifndef FAR
#define FAR
#endif


#ifndef DIAMONDAPI
#define DIAMONDAPI __cdecl
#endif


//** Specify structure packing explicitly for clients of FDI

#ifndef _WIN64
#include <pshpack4.h>
#endif


//** Don't redefine types defined in Win16 WINDOWS.H (_INC_WINDOWS)
//   or Win32 WINDOWS.H (_WINDOWS_)
//
#if !defined(_INC_WINDOWS) && !defined(_WINDOWS_)
typedef int            BOOL;     /* f */
typedef unsigned char  BYTE;     /* b */
typedef unsigned int   UINT;     /* ui */
typedef unsigned short USHORT;   /* us */
typedef unsigned long  ULONG;    /* ul */
#endif   // _INC_WINDOWS

typedef unsigned long  CHECKSUM; /* csum */

typedef unsigned long  UOFF;     /* uoff - uncompressed offset */
typedef unsigned long  COFF;     /* coff - cabinet file offset */


#ifndef TRUE
#define TRUE    1
#endif

#ifndef FALSE
#define FALSE   0
#endif

#ifndef NULL
#define NULL    0
#endif


/***    ERF - Error structure
 *
 *  This structure returns error information from FCI/FDI.  The caller should
 *  not modify this structure.
 */
typedef struct {
    int     erfOper;            // FCI/FDI error code -- see FDIERROR_XXX
                                //  and FCIERR_XXX equates for details.

    int     erfType;            // Optional error value filled in by FCI/FDI.
                                // For FCI, this is usually the C run-time
                                // *errno* value.

    BOOL    fError;             // TRUE => error present
} ERF;      /* erf */
typedef ERF FAR *PERF;  /* perf */

#ifdef _DEBUG
// don't hide statics from map during debugging
#define STATIC
#else // !DEBUG
#define STATIC static
#endif // !DEBUG

#define CB_MAX_CHUNK            32768U
#define CB_MAX_DISK        0x7fffffffL
#define CB_MAX_FILENAME            256
#define CB_MAX_CABINET_NAME        256
#define CB_MAX_CAB_PATH            256
#define CB_MAX_DISK_NAME           256

/***    tcompXXX - Diamond compression types
 *
 *  These are passed to FCIAddFile(), and are also stored in the CFFOLDER
 *  structures in cabinet files.
 *
 *  NOTE: We reserve bits for the TYPE, QUANTUM_LEVEL, and QUANTUM_MEM
 *        to provide room for future expansion.  Since this value is stored
 *        in the CFDATA records in the cabinet file, we don't want to
 *        have to change the format for existing compression configurations
 *        if we add new ones in the future.  This will allows us to read
 *        old cabinet files in the future.
 */

typedef unsigned short TCOMP; /* tcomp */

#define tcompMASK_TYPE          0x000F  // Mask for compression type
#define tcompTYPE_NONE          0x0000  // No compression
#define tcompTYPE_MSZIP         0x0001  // MSZIP
#define tcompTYPE_QUANTUM       0x0002  // Quantum
#define tcompTYPE_LZX           0x0003  // LZX
#define tcompBAD                0x000F  // Unspecified compression type

#define tcompMASK_LZX_WINDOW    0x1F00  // Mask for LZX Compression Memory
#define tcompLZX_WINDOW_LO      0x0F00  // Lowest LZX Memory (15)
#define tcompLZX_WINDOW_HI      0x1500  // Highest LZX Memory (21)
#define tcompSHIFT_LZX_WINDOW        8  // Amount to shift over to get int

#define tcompMASK_QUANTUM_LEVEL 0x00F0  // Mask for Quantum Compression Level
#define tcompQUANTUM_LEVEL_LO   0x0010  // Lowest Quantum Level (1)
#define tcompQUANTUM_LEVEL_HI   0x0070  // Highest Quantum Level (7)
#define tcompSHIFT_QUANTUM_LEVEL     4  // Amount to shift over to get int

#define tcompMASK_QUANTUM_MEM   0x1F00  // Mask for Quantum Compression Memory
#define tcompQUANTUM_MEM_LO     0x0A00  // Lowest Quantum Memory (10)
#define tcompQUANTUM_MEM_HI     0x1500  // Highest Quantum Memory (21)
#define tcompSHIFT_QUANTUM_MEM       8  // Amount to shift over to get int

#define tcompMASK_RESERVED      0xE000  // Reserved bits (high 3 bits)



#define CompressionTypeFromTCOMP(tc) \
            ((tc) & tcompMASK_TYPE)

#define CompressionLevelFromTCOMP(tc) \
            (((tc) & tcompMASK_QUANTUM_LEVEL) >> tcompSHIFT_QUANTUM_LEVEL)

#define CompressionMemoryFromTCOMP(tc) \
            (((tc) & tcompMASK_QUANTUM_MEM) >> tcompSHIFT_QUANTUM_MEM)

#define TCOMPfromTypeLevelMemory(t,l,m)           \
            (((m) << tcompSHIFT_QUANTUM_MEM  ) |  \
             ((l) << tcompSHIFT_QUANTUM_LEVEL) |  \
             ( t                             ))

#define LZXCompressionWindowFromTCOMP(tc) \
            (((tc) & tcompMASK_LZX_WINDOW) >> tcompSHIFT_LZX_WINDOW)

#define TCOMPfromLZXWindow(w)      \
            (((w) << tcompSHIFT_LZX_WINDOW ) |  \
             ( tcompTYPE_LZX ))


//** Revert to default structure packing

#ifndef _WIN64
#include <poppack.h>
#endif

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif // !INCLUDED_TYPES_FCI_FDI
/***    fci_int.h - File Compression Interface definitions
 *
 *      Copyright (C) Microsoft Corporation 1993-1994
 *      All Rights Reserved.
 *
 *  Author:
 *      Chuck Strouss
 *
 *  History:
 *      09-Jan-1994 chuckst Contents moved to bfol.h, this file is a
 *                          placeholder for the new 'higher-level' fci
 *      14-Feb-1994 bens    Cleaned up some comments.
 *      09-Mar-1994 bens    Added error codes (moved from buildcab.h);
 *                          Added RESERVE control
 *      17-Mar-1994 bens    Specify structure packing explicitly
 *      21-Mar-1994 bens    Cleaned up names
 *      22-Mar-1994 bens    Documented error cods
 *      29-Mar-1994 bens    Add FCIFlushFolder, renamed FCIFlushCabinet
 *      18-Apr-1994 bens    Changed CDECL to DIAMONDAPI
 *      18-May-1994 bens    Add ccab.fFailOnIncompressible field for
 *                              Chicago M6 hack.
 *      11-Nov-2005 kinshu  SAL annotation
 */

#ifndef INCLUDED_FCI
#define INCLUDED_FCI 1

#include <specstrings.h>
typedef __nullterminated char* LPSTR;
#include <basetsd.h>

#ifdef __cplusplus
extern "C" {            /* Assume C declarations for C++ */
#endif  /* __cplusplus */

//** Specify structure packing explicitly for clients of FCI

#ifndef _WIN64
#include <pshpack4.h>
#endif


/***    FCIERROR - Error codes returned in erf.erfOper field
 *
 */
typedef enum {
FCIERR_NONE,                // No error

FCIERR_OPEN_SRC,            // Failure opening file to be stored in cabinet
                            //  erf.erfTyp has C run-time *errno* value

FCIERR_READ_SRC,            // Failure reading file to be stored in cabinet
                            //  erf.erfTyp has C run-time *errno* value

FCIERR_ALLOC_FAIL,          // Out of memory in FCI

FCIERR_TEMP_FILE,           // Could not create a temporary file
                            //  erf.erfTyp has C run-time *errno* value

FCIERR_BAD_COMPR_TYPE,      // Unknown compression type

FCIERR_CAB_FILE,            // Could not create cabinet file
                            //  erf.erfTyp has C run-time *errno* value

FCIERR_USER_ABORT,          // Client requested abort

FCIERR_MCI_FAIL,            // Failure compressing data

FCIERR_CAB_FORMAT_LIMIT     // Data-size or file-count exceeded CAB format limits
                            // i.e. Total-bytes (uncompressed) in a CAB-folder exceeded 0x7FFF8000 (~ 2GB)
                            //  or, CAB size (compressed) exceeded 0x7FFFFFFF
                            //  or, File-count in CAB exceeded 0xFFFF

} FCIERROR;


/*
 * FAT file attribute flag used by FCI/FDI to indicate that
 * the filename in the CAB is a UTF string
 */
#ifndef _A_NAME_IS_UTF
#define _A_NAME_IS_UTF  0x80
#endif

/*
 * FAT file attribute flag used by FCI/FDI to indicate that
 * the file should be executed after extraction
 */
#ifndef _A_EXEC
#define _A_EXEC         0x40
#endif


/***    HFCI - Handle to an FCI Context
 *
 */
typedef void * HFCI;


/***    CCAB - Current Cabinet
 *
 *  This structure is used for passing in the cabinet parameters to FCI,
 *  and is passed back on certain FCI callbacks to provide cabinet
 *  information to the client.
 */
typedef struct {
// longs first
    ULONG  cb;                  // size available for cabinet on this media
    ULONG  cbFolderThresh;      // Thresshold for forcing a new Folder

// then ints
    UINT   cbReserveCFHeader;   // Space to reserve in CFHEADER
    UINT   cbReserveCFFolder;   // Space to reserve in CFFOLDER
    UINT   cbReserveCFData;     // Space to reserve in CFDATA
    int    iCab;                // sequential numbers for cabinets
    int    iDisk;               // Disk number
#ifndef REMOVE_CHICAGO_M6_HACK
    int    fFailOnIncompressible; // TRUE => Fail if a block is incompressible
#endif

//  then shorts
    USHORT setID;               // Cabinet set ID

// then chars
    char   szDisk[CB_MAX_DISK_NAME];    // current disk name
    char   szCab[CB_MAX_CABINET_NAME];  // current cabinet name
    char   szCabPath[CB_MAX_CAB_PATH];  // path for creating cabinet
} CCAB; /* ccab */
typedef CCAB *PCCAB; /* pccab */


/***    FNALLOC - Memory Allocation
 *      FNFREE  - Memory Free
 *
 *  These are modeled after the C run-time routines malloc() and free()
 *  (16-bit clients please note -- the size is a ULONG, so you may need
 *  to write a wrapper routine for halloc!).  FDI expects error
 *  handling to be identical to these C run-time routines.
 *
 *  As long as you faithfully copy the semantics of malloc() and free(),
 *  you can supply any functions you like!
 *
 *  WARNING: You should never assume anything about the sequence of
 *           PFNALLOC and PFNFREE calls -- incremental releases of
 *           Diamond/FDI may have radically different numbers of
 *           PFNALLOC calls and allocation sizes!
 */
//** Memory functions for FCI
typedef void HUGE * (FAR DIAMONDAPI *PFNFCIALLOC)(ULONG cb); /* pfna */
#define FNFCIALLOC(fn) void HUGE * FAR DIAMONDAPI fn(ULONG cb)

typedef void (FAR DIAMONDAPI *PFNFCIFREE)(void HUGE *memory); /* pfnf */
#define FNFCIFREE(fn) void FAR DIAMONDAPI fn(void HUGE *memory)


//** File I/O functions for FCI
typedef INT_PTR (FAR DIAMONDAPI *PFNFCIOPEN) (__in LPSTR pszFile, int oflag, int pmode, int FAR *err, void FAR *pv);
typedef UINT (FAR DIAMONDAPI *PFNFCIREAD) (INT_PTR hf, void FAR *memory, UINT cb, int FAR *err, void FAR *pv);
typedef UINT (FAR DIAMONDAPI *PFNFCIWRITE)(INT_PTR hf, void FAR *memory, UINT cb, int FAR *err, void FAR *pv);
typedef int  (FAR DIAMONDAPI *PFNFCICLOSE)(INT_PTR hf, int FAR *err, void FAR *pv);
typedef long (FAR DIAMONDAPI *PFNFCISEEK) (INT_PTR hf, long dist, int seektype, int FAR *err, void FAR *pv);
typedef int  (FAR DIAMONDAPI *PFNFCIDELETE) (__in LPSTR pszFile, int FAR *err, void FAR *pv);

#define FNFCIOPEN(fn) INT_PTR FAR DIAMONDAPI fn(__in LPSTR pszFile, int oflag, int pmode, int FAR *err, void FAR *pv)
#define FNFCIREAD(fn) UINT FAR DIAMONDAPI fn(INT_PTR hf, void FAR *memory, UINT cb, int FAR *err, void FAR *pv)
#define FNFCIWRITE(fn) UINT FAR DIAMONDAPI fn(INT_PTR hf, void FAR *memory, UINT cb, int FAR *err, void FAR *pv)
#define FNFCICLOSE(fn) int FAR DIAMONDAPI fn(INT_PTR hf, int FAR *err, void FAR *pv)
#define FNFCISEEK(fn) long FAR DIAMONDAPI fn(INT_PTR hf, long dist, int seektype, int FAR *err, void FAR *pv)
#define FNFCIDELETE(fn) int FAR DIAMONDAPI fn(__in LPSTR pszFile, int FAR *err, void FAR *pv)


/***    FNFCIGETNEXTCABINET - Callback used to request new cabinet info
 *
 *  Entry:
 *      pccab     - Points to copy of old ccab structure to modify
 *      cbPrevCab - Estimate of size of previous cabinet
 *      pv        - Has the caller's context pointer
 *
 *  Exit-Success:
 *      returns TRUE;
 *
 *  Exit-Failure:
 *      returns FALSE;
 */
typedef BOOL (DIAMONDAPI *PFNFCIGETNEXTCABINET)(PCCAB  pccab,
                                                ULONG  cbPrevCab,
                                                void FAR *pv); /* pfnfcignc */

#define FNFCIGETNEXTCABINET(fn) BOOL DIAMONDAPI fn(PCCAB  pccab,     \
                                                   ULONG  cbPrevCab, \
                                                   void FAR *pv)


/***    FNFCIFILEPLACED - Notify FCI client that file was placed
 *
 *  Entry:
 *      pccab         - cabinet structure to fill in, with copy of previous one
 *      pszFile       - name of file, from cabinet
 *      cbFile        - length of file
 *      fContinuation - true if this is a later segment of a continued file
 *      pv            - the context of the client
 *
 *  Exit-Success:
 *      return value anything but -1
 *
 *  Exit-Failure:
 *      return value -1 means to abort
 */
typedef int (DIAMONDAPI *PFNFCIFILEPLACED)(PCCAB pccab,
                                           __in LPSTR pszFile,
                                           long  cbFile,
                                           BOOL  fContinuation,
                                           void FAR *pv); /* pfnfcifp */

#define FNFCIFILEPLACED(fn) int DIAMONDAPI fn(PCCAB pccab,              \
                                              __in LPSTR pszFile,   \
                                              long  cbFile,             \
                                              BOOL  fContinuation,      \
                                              void FAR *pv)


/***    FNCDIGETOPENINFO - Open source file, get date/time/attribs
 *
 *  Entry:
 *      pszName  -- complete path to filename
 *      pdate    -- location to return FAT-style date code
 *      ptime    -- location to return FAT-style time code
 *      pattribs -- location to return FAT-style attributes
 *      pv       -- client's context
 *
 *  Exit-Success:
 *      Return value is file handle of open file to read
 *
 *  Exit-Failure:
 *      Return value is -1
 */
typedef INT_PTR (DIAMONDAPI *PFNFCIGETOPENINFO)(__in LPSTR pszName,
                                                USHORT *pdate,
                                                USHORT *ptime,
                                                USHORT *pattribs,
                                                int FAR *err,
                                                void FAR *pv); /* pfnfcigoi */

#define FNFCIGETOPENINFO(fn) INT_PTR DIAMONDAPI fn(__in LPSTR pszName,  \
                                                   USHORT *pdate,    \
                                                   USHORT *ptime,    \
                                                   USHORT *pattribs, \
                                                   int FAR *err, \
                                                   void FAR *pv)
                            
/***    FNFCISTATUS - Status/Cabinet Size callback
 *
 *  Entry:
 *      typeStatus == statusFile if compressing a block into a folder
 *                      cb1 = Size of compressed block
 *                      cb2 = Size of uncompressed block
 *
 *      typeStatus == statusFolder if adding a folder to a cabinet
 *                      cb1 = Amount of folder copied to cabinet so far
 *                      cb2 = Total size of folder
 *
 *      typeStatus == statusCabinet if writing out a complete cabinet
 *                      cb1 = Estimated cabinet size that was previously
 *                              passed to fnfciGetNextCabinet().
 *                      cb2 = Actual cabinet size
 *                    NOTE: Return value is desired client size for cabinet
 *                          file.  FCI updates the maximum cabinet size
 *                          remaining using this value.  This allows a client
 *                          to generate multiple cabinets per disk, and have
 *                          FCI limit the size correctly -- the client can do
 *                          cluster size rounding on the cabinet size!
 *                          The client should either return cb2, or round cb2
 *                          up to some larger value and return that.
 *  Exit-Success:
 *      Returns anything other than -1;
 *      NOTE: See statusCabinet for special return values!
 *
 *  Exit-Failure:
 *      Returns -1 to signal that FCI should abort;
 */

#define statusFile      0   // Add File to Folder callback
#define statusFolder    1   // Add Folder to Cabinet callback
#define statusCabinet   2   // Write out a completed cabinet callback

typedef long (DIAMONDAPI *PFNFCISTATUS)(UINT   typeStatus,
                                        ULONG  cb1,
                                        ULONG  cb2,
                                        void FAR *pv); /* pfnfcis */

#define FNFCISTATUS(fn) long DIAMONDAPI fn(UINT   typeStatus, \
                                           ULONG  cb1,        \
                                           ULONG  cb2,        \
                                           void FAR *pv)


/***    FNFCIGETTEMPFILE - Callback, requests temporary file name
 *
 *  Entry:
 *      pszTempName - Buffer to receive complete tempfile name
 *      cbTempName  - Size of pszTempName buffer
 *
 *  Exit-Success:
 *      return TRUE
 *
 *  Exit-Failure:
 *      return FALSE; could not create tempfile, or buffer too small
 *
 *  Note:
 *      It is conceivable that this function may return a filename
 *      that will already exist by the time it is opened.  For this
 *      reason, the caller should make several attempts to create
 *      temporary files before giving up.
 */
typedef BOOL (DIAMONDAPI *PFNFCIGETTEMPFILE)(__out_bcount(cbTempName) char *pszTempName,
                                             __in_range(>=, MAX_PATH) int   cbTempName,
                                             void FAR *pv); /* pfnfcigtf */

#define FNFCIGETTEMPFILE(fn) BOOL DIAMONDAPI fn(__out_bcount(cbTempName) char *pszTempName, \
                                                __in_range(>=, MAX_PATH) int   cbTempName, \
                                                void FAR *pv)


/***    FCICreate -- create an FCI context (an open CAB, an open FOL)
 *
 *  Entry:
 *      perf      - structure where we return error codes
 *      pfnfcifp  - callback to inform caller of eventual dest of files
 *      pfna      - memory allocation function callback
 *      pfnf      - memory free function callback
 *      pfnfcigtf - temp file name generator callback
 *      pccab     - pointer to cabinet/disk name & size structure
 *
 *  Notes:
 *  (1) The alloc/free callbacks must remain valid throughout
 *      the life of the context, up to and including the call to
 *      FCIDestroy.
 *  (2) The perf pointer is stored in the compression context (HCI),
 *      and any errors from subsequent FCI calls are stored in the
 *      erf that was passed in on *this* call.
 *
 *  Exit-Success:
 *      Returns non-NULL handle to an FCI context.
 *
 *  Exit-Failure:
 *      Returns NULL, perf filled in.
 */
HFCI DIAMONDAPI FCICreate(__in       PERF               perf,
                          __callback PFNFCIFILEPLACED   pfnfcifp,
                          __callback PFNFCIALLOC        pfna,
                          __callback PFNFCIFREE         pfnf,
                          __callback PFNFCIOPEN         pfnopen,
                          __callback PFNFCIREAD         pfnread,
                          __callback PFNFCIWRITE        pfnwrite,
                          __callback PFNFCICLOSE        pfnclose,
                          __callback PFNFCISEEK         pfnseek,
                          __callback PFNFCIDELETE       pfndelete,
                          __callback PFNFCIGETTEMPFILE  pfnfcigtf,
                          __in       PCCAB              pccab,
                          __in_opt void FAR            *pv
                         );


/***   FCIAddFile - Add a disk file to a folder/cabinet
 *
 *  Entry:
 *      hfci          - FCI context handle
 *      pszSourceFile - Name of file to add to folder
 *      pszFileName   - Name to store into folder/cabinet
 *      fExecute      - Flag indicating execute on extract
 *      pfn_progress  - Progress callback
 *      pfnfcignc     - GetNextCabinet callback
 *      pfnfcis       - Status callback
 *      pfnfcigoi     - OpenInfo callback
 *      typeCompress  - Type of compression to use for this file
 *      pv            - pointer to caller's internal context
 *
 *  Exit-Success:
 *      returns TRUE
 *
 *  Exit-Failure:
 *      returns FALSE, error filled in
 *    
 *    This is the main function used to add file(s) to a cabinet
 *    or series of cabinets.  If the current file causes the current
 *    folder/cabinet to overflow the disk image currently being built,
 *    the cabinet will be terminated, and a new cabinet/disk name will
 *    be prompted for via a callback.  The pending folder will be trimmed
 *    of the data which has already been generated in the finished cabinet.
 */
BOOL DIAMONDAPI FCIAddFile(__in HFCI                        hfci,
                           __in LPSTR                       pszSourceFile,
                           __in LPSTR                       pszFileName,
                           BOOL                             fExecute,
                           __callback PFNFCIGETNEXTCABINET  pfnfcignc,
                           __callback PFNFCISTATUS          pfnfcis,
                           __callback PFNFCIGETOPENINFO     pfnfcigoi,
                           TCOMP                            typeCompress
                          );
            

/***   FCIFlushCabinet - Complete the current cabinet under construction
 *
 *  This will cause the current cabinet (assuming it is not empty) to
 *  be gathered together and written to disk.
 *
 *  Entry:
 *      hfci        - FCI context
 *      fGetNextCab - TRUE  => Call GetNextCab to get continuation info;
 *                    FALSE => Don't call GetNextCab unless this cabinet
 *                             overflows.
 *      pfnfcignc   - callback function to get continuation cabinets
 *      pfnfcis     - callback function for progress reporting
 *      pv          - caller's internal context for callbacks
 *
 *  Exit-Success:
 *      return code TRUE
 *
 *  Exit-Failure:
 *      return code FALSE, error structure filled in
 */
BOOL DIAMONDAPI FCIFlushCabinet(__in HFCI                       hfci,
                                BOOL                            fGetNextCab,
                                __callback PFNFCIGETNEXTCABINET pfnfcignc,
                                __callback PFNFCISTATUS         pfnfcis
                               );

                                                                  
/***   FCIFlushFolder - Complete the current folder under construction
 *
 *  This will force the termination of the current folder, which may or
 *  may not cause one or more cabinet files to be completed.
 *
 *  Entry:
 *      hfci        - FCI context
 *      GetNextCab  - callback function to get continuation cabinets
 *      pfnProgress - callback function for progress reporting
 *      pv          - caller's internal context for callbacks
 *
 *  Exit-Success:
 *      return code TRUE
 *
 *  Exit-Failure:
 *      return code FALSE, error structure filled in
 */
BOOL DIAMONDAPI FCIFlushFolder(__in HFCI                        hfci,
                               __callback PFNFCIGETNEXTCABINET  pfnfcignc,
                               __callback PFNFCISTATUS          pfnfcis
                              );

                                                                  
/***   FCIDestroy - Destroy a FCI context and delete temp files
 *
 *  Entry:
 *      hfci - FCI context
 *
 *  Exit-Success:
 *      return code TRUE
 *
 *  Exit-Failure:
 *      return code FALSE, error structure filled in
 */
BOOL DIAMONDAPI FCIDestroy (__in HFCI hfci);
                                                                  
//** Revert to default structure packing

#ifndef _WIN64
#include <poppack.h>
#endif

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif // !INCLUDED_FCI

