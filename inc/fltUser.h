/*++

Copyright (c) 1989-2002  Microsoft Corporation

Module Name:

    fltUser.h

Abstract:
    Header file which contains the structures, type definitions,
    constants, global variables and function prototypes that are
    visible to user mode applications that interact with filters.

Environment:

    User mode

--*/
#ifndef __FLTUSER_H__
#define __FLTUSER_H__

//
// IMPORTANT!!!!!
//
// This is how FltMgr was released (from oldest to newest)
// xpsp2, (srv03, w2ksp5), LH, Win7
//

//
//  The defines items that are part of the filter manager baseline
//

#define FLT_MGR_BASELINE (((OSVER(NTDDI_VERSION) == NTDDI_WIN2K) && (SPVER(NTDDI_VERSION) >= SPVER(NTDDI_WIN2KSP4))) || \
                          ((OSVER(NTDDI_VERSION) == NTDDI_WINXP) && (SPVER(NTDDI_VERSION) >= SPVER(NTDDI_WINXPSP2))) || \
                          ((OSVER(NTDDI_VERSION) == NTDDI_WS03)  && (SPVER(NTDDI_VERSION) >= SPVER(NTDDI_WS03SP1))) ||  \
                          (NTDDI_VERSION >= NTDDI_VISTA))

//
//  This defines items that were added after XPSP2 was released.  This means
//  they are in Srv03 SP1, W2K SP4+URP, and Longhorn and above.
//

#define FLT_MGR_AFTER_XPSP2 (((OSVER(NTDDI_VERSION) == NTDDI_WIN2K) && (SPVER(NTDDI_VERSION) >= SPVER(NTDDI_WIN2KSP4))) ||  \
                             ((OSVER(NTDDI_VERSION) == NTDDI_WINXP) && (SPVER(NTDDI_VERSION) >  SPVER(NTDDI_WINXPSP2))) ||  \
                             ((OSVER(NTDDI_VERSION) == NTDDI_WS03)  && (SPVER(NTDDI_VERSION) >= SPVER(NTDDI_WS03SP1))) ||   \
                             (NTDDI_VERSION >= NTDDI_VISTA))

//
//  This defines items that only exist in longhorn or later
//

#define FLT_MGR_LONGHORN (NTDDI_VERSION >= NTDDI_VISTA)

//
//  This defines items that only exist in Windows 7 or later
//

#define FLT_MGR_WIN7 (NTDDI_VERSION >= NTDDI_WIN7)



///////////////////////////////////////////////////////////////////////////////
//
//  Standard includes
//
///////////////////////////////////////////////////////////////////////////////

#include <fltUserStructures.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// These are all of the baseline set of user-mode functions in FltMgr.
//

#if FLT_MGR_BASELINE

//
//  Functions for loading, unloading and monitoring Filters
//

__checkReturn
HRESULT
WINAPI
FilterLoad (
    __in LPCWSTR lpFilterName
    );

__checkReturn
HRESULT
WINAPI
FilterUnload (
    __in LPCWSTR lpFilterName
    );


//****************************************************************************
//
//  Functions for creating and closing handles
//
//****************************************************************************

//
//  Filter
//

__checkReturn
HRESULT
WINAPI
FilterCreate (
    __in LPCWSTR lpFilterName,
    __deref_out HFILTER *hFilter
    );

HRESULT
WINAPI
FilterClose(
    __in HFILTER hFilter
    );

//
//  FilterInstance
//

__checkReturn
HRESULT
WINAPI
FilterInstanceCreate (
    __in LPCWSTR lpFilterName,
    __in LPCWSTR lpVolumeName,
    __in_opt LPCWSTR lpInstanceName,
   __deref_out HFILTER_INSTANCE *hInstance
    );

HRESULT
WINAPI
FilterInstanceClose(
    __in HFILTER_INSTANCE hInstance
    );


//****************************************************************************
//
//  Functions for creating and deleting FilterInstances in the
//  device stack.
//
//****************************************************************************

__checkReturn
HRESULT
WINAPI
FilterAttach (
    __in LPCWSTR lpFilterName,
    __in LPCWSTR lpVolumeName,
    __in_opt LPCWSTR lpInstanceName ,
    __in_opt DWORD dwCreatedInstanceNameLength ,
    __out_bcount_opt(dwCreatedInstanceNameLength) LPWSTR lpCreatedInstanceName
    );

__checkReturn
HRESULT
WINAPI
FilterAttachAtAltitude (
    __in LPCWSTR lpFilterName,
    __in LPCWSTR lpVolumeName,
    __in LPCWSTR lpAltitude,
    __in_opt LPCWSTR lpInstanceName ,
    __in_opt DWORD dwCreatedInstanceNameLength ,
    __out_bcount_opt(dwCreatedInstanceNameLength) LPWSTR lpCreatedInstanceName
    );

__checkReturn
HRESULT
WINAPI
FilterDetach (
    __in LPCWSTR lpFilterName,
    __in LPCWSTR lpVolumeName,
    __in_opt LPCWSTR lpInstanceName
    );


//****************************************************************************
//
//  Functions for iterating through Filters and FilterInstances and
//  getting information on a Filter or FilterInstance.
//
//****************************************************************************

//
//  Functions for iterating through Filters
//

__checkReturn
HRESULT
WINAPI
FilterFindFirst (
    __in FILTER_INFORMATION_CLASS dwInformationClass,
    __out_bcount_part(dwBufferSize,*lpBytesReturned) LPVOID lpBuffer,
    __in DWORD dwBufferSize,
    __out LPDWORD lpBytesReturned,
    __out LPHANDLE lpFilterFind
    );

__checkReturn
HRESULT
WINAPI
FilterFindNext (
    __in HANDLE hFilterFind,
    __in FILTER_INFORMATION_CLASS dwInformationClass,
    __out_bcount_part(dwBufferSize,*lpBytesReturned) LPVOID lpBuffer,
    __in DWORD dwBufferSize,
    __out LPDWORD lpBytesReturned
    );

__checkReturn
HRESULT
WINAPI
FilterFindClose(
    __in HANDLE hFilterFind
    );


__checkReturn
HRESULT
WINAPI
FilterVolumeFindFirst (
    __in FILTER_VOLUME_INFORMATION_CLASS dwInformationClass,
    __out_bcount_part(dwBufferSize,*lpBytesReturned) LPVOID lpBuffer,
    __in DWORD dwBufferSize,
    __out LPDWORD lpBytesReturned,
    __out PHANDLE lpVolumeFind
    );

__checkReturn
HRESULT
WINAPI
FilterVolumeFindNext (
    __in HANDLE hVolumeFind,
    __in FILTER_VOLUME_INFORMATION_CLASS dwInformationClass,
    __out_bcount_part(dwBufferSize,*lpBytesReturned) LPVOID lpBuffer,
    __in DWORD dwBufferSize,
    __out LPDWORD lpBytesReturned
    );

HRESULT
WINAPI
FilterVolumeFindClose(
    __in HANDLE hVolumeFind
    );

//
//  Functions for iterating through FilterInstances
//

__checkReturn
HRESULT
WINAPI
FilterInstanceFindFirst (
    __in LPCWSTR lpFilterName,
    __in INSTANCE_INFORMATION_CLASS dwInformationClass,
    __out_bcount_part(dwBufferSize,*lpBytesReturned) LPVOID lpBuffer,
    __in DWORD dwBufferSize,
    __out LPDWORD lpBytesReturned,
    __out LPHANDLE lpFilterInstanceFind
    );

__checkReturn
HRESULT
WINAPI
FilterInstanceFindNext (
    __in HANDLE hFilterInstanceFind,
    __in INSTANCE_INFORMATION_CLASS dwInformationClass,
    __out_bcount_part(dwBufferSize,*lpBytesReturned) LPVOID lpBuffer,
    __in DWORD dwBufferSize,
    __out LPDWORD lpBytesReturned
    );

__checkReturn
HRESULT
WINAPI
FilterInstanceFindClose(
    __in HANDLE hFilterInstanceFind
    );


//
//  Functions for iterating through VolumeInstances
//

__checkReturn
HRESULT
WINAPI
FilterVolumeInstanceFindFirst (
    __in LPCWSTR lpVolumeName,
    __in INSTANCE_INFORMATION_CLASS dwInformationClass,
    __out_bcount_part(dwBufferSize,*lpBytesReturned) LPVOID lpBuffer,
    __in DWORD dwBufferSize,
    __out LPDWORD lpBytesReturned,
    __out LPHANDLE lpVolumeInstanceFind
    );

__checkReturn
HRESULT
WINAPI
FilterVolumeInstanceFindNext (
    __in HANDLE hVolumeInstanceFind,
    __in INSTANCE_INFORMATION_CLASS dwInformationClass,
    __out_bcount_part(dwBufferSize,*lpBytesReturned) LPVOID lpBuffer,
    __in DWORD dwBufferSize,
    __out LPDWORD lpBytesReturned
    );

HRESULT
WINAPI
FilterVolumeInstanceFindClose(
    __in HANDLE hVolumeInstanceFind
    );


//
//  Functions for getting information on Filters and FilterInstances
//

__checkReturn
HRESULT
WINAPI
FilterGetInformation (
    __in HFILTER hFilter,
    __in FILTER_INFORMATION_CLASS dwInformationClass,
    __out_bcount_part(dwBufferSize,*lpBytesReturned) LPVOID lpBuffer,
    __in DWORD dwBufferSize,
    __out LPDWORD lpBytesReturned
    );

__checkReturn
HRESULT
WINAPI
FilterInstanceGetInformation (
    __in HFILTER_INSTANCE hInstance,
    __in INSTANCE_INFORMATION_CLASS dwInformationClass,
    __out_bcount_part(dwBufferSize,*lpBytesReturned) LPVOID lpBuffer,
    __in DWORD dwBufferSize,
    __out LPDWORD lpBytesReturned
    );


//****************************************************************************
//
//  Functions for communicating with Filters and FilterInstances
//
//****************************************************************************

__checkReturn
HRESULT
WINAPI
FilterConnectCommunicationPort(
    __in LPCWSTR lpPortName,
    __in DWORD dwOptions,
    __in_bcount_opt(wSizeOfContext) LPCVOID lpContext,
    __in WORD wSizeOfContext,
    __in_opt LPSECURITY_ATTRIBUTES lpSecurityAttributes ,
    __deref_out HANDLE *hPort
    );

__checkReturn
HRESULT
WINAPI
FilterSendMessage (
    __in HANDLE hPort,
    __in_bcount_opt(dwInBufferSize) LPVOID lpInBuffer,
    __in DWORD dwInBufferSize,
    __out_bcount_part_opt(dwOutBufferSize,*lpBytesReturned) LPVOID lpOutBuffer,
    __in DWORD dwOutBufferSize,
    __out LPDWORD lpBytesReturned
    );

__checkReturn
HRESULT
WINAPI
FilterGetMessage (
    __in HANDLE hPort,
    __out_bcount(dwMessageBufferSize) PFILTER_MESSAGE_HEADER lpMessageBuffer,
    __in DWORD dwMessageBufferSize,
    __inout LPOVERLAPPED lpOverlapped
    );

__checkReturn
HRESULT
WINAPI
FilterReplyMessage (
    __in HANDLE hPort,
    __in_bcount(dwReplyBufferSize) PFILTER_REPLY_HEADER lpReplyBuffer,
    __in DWORD dwReplyBufferSize
    );

//****************************************************************************
//
//  Other support functions
//
//****************************************************************************

__checkReturn
HRESULT
WINAPI
FilterGetDosName (
    __in LPCWSTR lpVolumeName,
    __out_ecount(dwDosNameBufferSize) LPWSTR lpDosName,
    __in DWORD dwDosNameBufferSize
    );

#endif // end the FLT_MGR_BASELINE

#ifdef __cplusplus
}       // Balance extern "C" above
#endif

#endif /* __FLTUSER_H__ */

