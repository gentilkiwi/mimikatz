/*++ BUILD Version: 0001    // Increment this if a change has global effects

Copyright (c) 1996-1999  Microsoft Corporation

Module Name:

    dsgetdc.h

Abstract:

    This file contains structures, function prototypes, and definitions
    for the DsGetDcName API.

Environment:

    User Mode - Win32

Notes:

--*/


#ifndef _DSGETDC_
#define _DSGETDC_

#if _MSC_VER > 1000
#pragma once
#endif

#if !defined(_DSGETDCAPI_)
#define DSGETDCAPI DECLSPEC_IMPORT
#else
#define DSGETDCAPI
#endif

#ifdef __cplusplus
extern "C" {
#endif

//
// Structure definitions
//

//
// Flags to passed to DsGetDcName
//

#define DS_FORCE_REDISCOVERY            0x00000001

#define DS_DIRECTORY_SERVICE_REQUIRED   0x00000010
#define DS_DIRECTORY_SERVICE_PREFERRED  0x00000020
#define DS_GC_SERVER_REQUIRED           0x00000040
#define DS_PDC_REQUIRED                 0x00000080
#define DS_BACKGROUND_ONLY              0x00000100
#define DS_IP_REQUIRED                  0x00000200
#define DS_KDC_REQUIRED                 0x00000400
#define DS_TIMESERV_REQUIRED            0x00000800
#define DS_WRITABLE_REQUIRED            0x00001000
#define DS_GOOD_TIMESERV_PREFERRED      0x00002000
#define DS_AVOID_SELF                   0x00004000
#define DS_ONLY_LDAP_NEEDED             0x00008000


#define DS_IS_FLAT_NAME                 0x00010000
#define DS_IS_DNS_NAME                  0x00020000

#define DS_TRY_NEXTCLOSEST_SITE         0x00040000

#define DS_DIRECTORY_SERVICE_6_REQUIRED 0x00080000

#define DS_WEB_SERVICE_REQUIRED         0x00100000

#define DS_RETURN_DNS_NAME              0x40000000
#define DS_RETURN_FLAT_NAME             0x80000000

#define DSGETDC_VALID_FLAGS ( \
            DS_FORCE_REDISCOVERY | \
            DS_DIRECTORY_SERVICE_REQUIRED | \
            DS_DIRECTORY_SERVICE_PREFERRED | \
            DS_GC_SERVER_REQUIRED | \
            DS_PDC_REQUIRED | \
            DS_BACKGROUND_ONLY | \
            DS_IP_REQUIRED | \
            DS_KDC_REQUIRED | \
            DS_TIMESERV_REQUIRED | \
            DS_WRITABLE_REQUIRED | \
            DS_GOOD_TIMESERV_PREFERRED | \
            DS_AVOID_SELF | \
            DS_ONLY_LDAP_NEEDED | \
            DS_IS_FLAT_NAME | \
            DS_IS_DNS_NAME | \
            DS_TRY_NEXTCLOSEST_SITE | \
            DS_DIRECTORY_SERVICE_6_REQUIRED | \
            DS_WEB_SERVICE_REQUIRED | \
            DS_RETURN_FLAT_NAME  | \
            DS_RETURN_DNS_NAME )


//
// Structure returned from DsGetDcName
//

typedef struct _DOMAIN_CONTROLLER_INFOA {
    LPSTR DomainControllerName;
    LPSTR DomainControllerAddress;
    ULONG DomainControllerAddressType;
    GUID DomainGuid;
    LPSTR DomainName;
    LPSTR DnsForestName;
    ULONG Flags;
    LPSTR DcSiteName;
    LPSTR ClientSiteName;
} DOMAIN_CONTROLLER_INFOA, *PDOMAIN_CONTROLLER_INFOA;

typedef struct _DOMAIN_CONTROLLER_INFOW {
#ifdef MIDL_PASS
    [string,unique] wchar_t *DomainControllerName;
#else // MIDL_PASS
    LPWSTR DomainControllerName;
#endif // MIDL_PASS
#ifdef MIDL_PASS
    [string,unique] wchar_t *DomainControllerAddress;
#else // MIDL_PASS
    LPWSTR DomainControllerAddress;
#endif // MIDL_PASS
    ULONG DomainControllerAddressType;
    GUID DomainGuid;
#ifdef MIDL_PASS
    [string,unique] wchar_t *DomainName;
#else // MIDL_PASS
    LPWSTR DomainName;
#endif // MIDL_PASS
#ifdef MIDL_PASS
    [string,unique] wchar_t *DnsForestName;
#else // MIDL_PASS
    LPWSTR DnsForestName;
#endif // MIDL_PASS
    ULONG Flags;
#ifdef MIDL_PASS
    [string,unique] wchar_t *DcSiteName;
#else // MIDL_PASS
    LPWSTR DcSiteName;
#endif // MIDL_PASS
#ifdef MIDL_PASS
    [string,unique] wchar_t *ClientSiteName;
#else // MIDL_PASS
    LPWSTR ClientSiteName;
#endif // MIDL_PASS
} DOMAIN_CONTROLLER_INFOW, *PDOMAIN_CONTROLLER_INFOW;

#ifdef UNICODE
#define DOMAIN_CONTROLLER_INFO DOMAIN_CONTROLLER_INFOW
#define PDOMAIN_CONTROLLER_INFO PDOMAIN_CONTROLLER_INFOW
#else
#define DOMAIN_CONTROLLER_INFO DOMAIN_CONTROLLER_INFOA
#define PDOMAIN_CONTROLLER_INFO PDOMAIN_CONTROLLER_INFOA
#endif // !UNICODE

//
// Values for DomainControllerAddressType
//

#define DS_INET_ADDRESS    1
#define DS_NETBIOS_ADDRESS 2

//
// Values for returned Flags
//

#define DS_PDC_FLAG            0x00000001    // DC is PDC of Domain
#define DS_GC_FLAG             0x00000004    // DC is a GC of forest
#define DS_LDAP_FLAG           0x00000008    // Server supports an LDAP server
#define DS_DS_FLAG             0x00000010    // DC supports a DS and is a Domain Controller
#define DS_KDC_FLAG            0x00000020    // DC is running KDC service
#define DS_TIMESERV_FLAG       0x00000040    // DC is running time service
#define DS_CLOSEST_FLAG        0x00000080    // DC is in closest site to client
#define DS_WRITABLE_FLAG       0x00000100    // DC has a writable DS
#define DS_GOOD_TIMESERV_FLAG  0x00000200    // DC is running time service (and has clock hardware)
#define DS_NDNC_FLAG           0x00000400    // DomainName is non-domain NC serviced by the LDAP server
#define DS_SELECT_SECRET_DOMAIN_6_FLAG  0x00000800  // DC has some secrets
#define DS_FULL_SECRET_DOMAIN_6_FLAG    0x00001000  // DC has all secrets
#define DS_WS_FLAG             0x00002000    // DC is running web service
#define DS_PING_FLAGS          0x000FFFFF    // Flags returned on ping

#define DS_DNS_CONTROLLER_FLAG 0x20000000    // DomainControllerName is a DNS name
#define DS_DNS_DOMAIN_FLAG     0x40000000    // DomainName is a DNS name
#define DS_DNS_FOREST_FLAG     0x80000000    // DnsForestName is a DNS name


//
// Function Prototypes
//

DSGETDCAPI
DWORD
WINAPI
DsGetDcNameA(
    IN __in_opt LPCSTR ComputerName OPTIONAL,
    IN __in_opt LPCSTR DomainName OPTIONAL,
    IN GUID *DomainGuid OPTIONAL,
    IN __in_opt LPCSTR SiteName OPTIONAL,
    IN ULONG Flags,
    OUT PDOMAIN_CONTROLLER_INFOA *DomainControllerInfo
);

DSGETDCAPI
DWORD
WINAPI
DsGetDcNameW(
    IN __in_opt LPCWSTR ComputerName OPTIONAL,
    IN __in_opt LPCWSTR DomainName OPTIONAL,
    IN GUID *DomainGuid OPTIONAL,
    IN __in_opt LPCWSTR SiteName OPTIONAL,
    IN ULONG Flags,
    OUT PDOMAIN_CONTROLLER_INFOW *DomainControllerInfo
);

#ifdef UNICODE
#define DsGetDcName DsGetDcNameW
#else
#define DsGetDcName DsGetDcNameA
#endif // !UNICODE

DSGETDCAPI
DWORD
WINAPI
DsGetSiteNameA(
    IN __in_opt LPCSTR ComputerName OPTIONAL,
    OUT __deref_out LPSTR *SiteName
);

DSGETDCAPI
DWORD
WINAPI
DsGetSiteNameW(
    IN __in_opt LPCWSTR ComputerName OPTIONAL,
    OUT  __deref_out LPWSTR *SiteName
);

#ifdef UNICODE
#define DsGetSiteName DsGetSiteNameW
#else
#define DsGetSiteName DsGetSiteNameA
#endif // !UNICODE


DSGETDCAPI
DWORD
WINAPI
DsValidateSubnetNameW(
    __in IN LPCWSTR SubnetName
);

DSGETDCAPI
DWORD
WINAPI
DsValidateSubnetNameA(
    __in IN LPCSTR SubnetName
);

#ifdef UNICODE
#define DsValidateSubnetName DsValidateSubnetNameW
#else
#define DsValidateSubnetName DsValidateSubnetNameA
#endif // !UNICODE


//
// Only include if winsock2.h has been included
//
#ifdef _WINSOCK2API_
DSGETDCAPI
DWORD
WINAPI
DsAddressToSiteNamesW(
    IN __in_opt LPCWSTR ComputerName OPTIONAL,
    IN DWORD EntryCount,
    IN PSOCKET_ADDRESS SocketAddresses,
    OUT __deref_out_ecount(EntryCount) LPWSTR **SiteNames
    );

DSGETDCAPI
DWORD
WINAPI
DsAddressToSiteNamesA(
    IN __in_opt LPCSTR ComputerName OPTIONAL,
    IN DWORD EntryCount,
    IN PSOCKET_ADDRESS SocketAddresses,
    OUT __deref_out_ecount(EntryCount) LPSTR **SiteNames
    );

#ifdef UNICODE
#define DsAddressToSiteNames DsAddressToSiteNamesW
#else
#define DsAddressToSiteNames DsAddressToSiteNamesA
#endif // !UNICODE

DSGETDCAPI
DWORD
WINAPI
DsAddressToSiteNamesExW(
    IN __in_opt LPCWSTR ComputerName OPTIONAL,
    IN DWORD EntryCount,
    IN PSOCKET_ADDRESS SocketAddresses,
    OUT __deref_out_ecount(EntryCount) LPWSTR **SiteNames,
    OUT __deref_out_ecount(EntryCount) LPWSTR **SubnetNames
    );

DSGETDCAPI
DWORD
WINAPI
DsAddressToSiteNamesExA(
    IN __in_opt LPCSTR ComputerName OPTIONAL,
    IN DWORD EntryCount,
    IN PSOCKET_ADDRESS SocketAddresses,
    OUT __deref_out_ecount(EntryCount) LPSTR **SiteNames,
    OUT __deref_out_ecount(EntryCount) LPSTR **SubnetNames
    );

#ifdef UNICODE
#define DsAddressToSiteNamesEx DsAddressToSiteNamesExW
#else
#define DsAddressToSiteNamesEx DsAddressToSiteNamesExA
#endif // !UNICODE
#endif // _WINSOCK2API_

//
// API to enumerate trusted domains
//

typedef struct _DS_DOMAIN_TRUSTSW {

    //
    // Name of the trusted domain.
    //
#ifdef MIDL_PASS
    [string] wchar_t * NetbiosDomainName;
    [string] wchar_t * DnsDomainName;
#else // MIDL_PASS
    LPWSTR NetbiosDomainName;
    LPWSTR DnsDomainName;
#endif // MIDL_PASS


    //
    // Flags defining attributes of the trust.
    //
    ULONG Flags;
#define DS_DOMAIN_IN_FOREST           0x0001  // Domain is a member of the forest
#define DS_DOMAIN_DIRECT_OUTBOUND     0x0002  // Domain is directly trusted
#define DS_DOMAIN_TREE_ROOT           0x0004  // Domain is root of a tree in the forest
#define DS_DOMAIN_PRIMARY             0x0008  // Domain is the primary domain of queried server
#define DS_DOMAIN_NATIVE_MODE         0x0010  // Primary domain is running in native mode
#define DS_DOMAIN_DIRECT_INBOUND      0x0020  // Domain is directly trusting
#define DS_DOMAIN_VALID_FLAGS (         \
            DS_DOMAIN_IN_FOREST       | \
            DS_DOMAIN_DIRECT_OUTBOUND | \
            DS_DOMAIN_TREE_ROOT       | \
            DS_DOMAIN_PRIMARY         | \
            DS_DOMAIN_NATIVE_MODE     | \
            DS_DOMAIN_DIRECT_INBOUND )

    //
    // Index to the domain that is the parent of this domain.
    //  Only defined if NETLOGON_DOMAIN_IN_FOREST is set and
    //      NETLOGON_DOMAIN_TREE_ROOT is not set.
    //
    ULONG ParentIndex;

    //
    // The trust type and attributes of this trust.
    //
    // If NETLOGON_DOMAIN_DIRECTLY_TRUSTED is not set,
    //  these value are infered.
    //
    ULONG TrustType;
    ULONG TrustAttributes;

    //
    // The SID of the trusted domain.
    //
    // If NETLOGON_DOMAIN_DIRECTLY_TRUSTED is not set,
    //  this value will be NULL.
    //
#if defined(MIDL_PASS)
    PISID DomainSid;
#else
    PSID DomainSid;
#endif

    //
    // The GUID of the trusted domain.
    //

    GUID DomainGuid;

} DS_DOMAIN_TRUSTSW, *PDS_DOMAIN_TRUSTSW;

//
// ANSI version of the above struct
//
typedef struct _DS_DOMAIN_TRUSTSA {
    LPSTR NetbiosDomainName;
    LPSTR DnsDomainName;
    ULONG Flags;
    ULONG ParentIndex;
    ULONG TrustType;
    ULONG TrustAttributes;
    PSID DomainSid;
    GUID DomainGuid;
} DS_DOMAIN_TRUSTSA, *PDS_DOMAIN_TRUSTSA;

#ifdef UNICODE
#define DS_DOMAIN_TRUSTS DS_DOMAIN_TRUSTSW
#define PDS_DOMAIN_TRUSTS PDS_DOMAIN_TRUSTSW
#else
#define DS_DOMAIN_TRUSTS DS_DOMAIN_TRUSTSA
#define PDS_DOMAIN_TRUSTS PDS_DOMAIN_TRUSTSA
#endif // !UNICODE

DSGETDCAPI
DWORD
WINAPI
DsEnumerateDomainTrustsW (
    __in_opt LPWSTR ServerName OPTIONAL,
    __in ULONG Flags,
    __deref_out_ecount(*DomainCount) PDS_DOMAIN_TRUSTSW *Domains,
    __out PULONG DomainCount
    );

DSGETDCAPI
DWORD
WINAPI
DsEnumerateDomainTrustsA (
    __in_opt LPSTR ServerName OPTIONAL,
    __in ULONG Flags,
    __deref_out_ecount(*DomainCount) PDS_DOMAIN_TRUSTSA *Domains,
    __out PULONG DomainCount
    );

#ifdef UNICODE
#define DsEnumerateDomainTrusts DsEnumerateDomainTrustsW
#else
#define DsEnumerateDomainTrusts DsEnumerateDomainTrustsA
#endif // !UNICODE



//
// Only define this API if the caller has #included the pre-requisite 
// ntlsa.h or ntsecapi.h  
//

#if defined(_NTLSA_) || defined(_NTSECAPI_)

DSGETDCAPI
DWORD
WINAPI
DsGetForestTrustInformationW (
    IN LPCWSTR ServerName OPTIONAL,
    IN LPCWSTR TrustedDomainName OPTIONAL,
    IN DWORD Flags,
    OUT PLSA_FOREST_TRUST_INFORMATION *ForestTrustInfo
    );

#define DS_GFTI_UPDATE_TDO      0x1     // Update TDO with information returned
#define DS_GFTI_VALID_FLAGS     0x1     // All valid flags to DsGetForestTrustInformation

DSGETDCAPI
DWORD
WINAPI
DsMergeForestTrustInformationW(
    IN LPCWSTR DomainName,
    IN PLSA_FOREST_TRUST_INFORMATION NewForestTrustInfo,
    IN PLSA_FOREST_TRUST_INFORMATION OldForestTrustInfo OPTIONAL,
    OUT PLSA_FOREST_TRUST_INFORMATION *MergedForestTrustInfo
    );

#endif // _NTLSA_ || _NTSECAPI_

DSGETDCAPI
DWORD
WINAPI
DsGetDcSiteCoverageW(
    IN __in_opt LPCWSTR ServerName OPTIONAL,
    OUT PULONG EntryCount,
    OUT __deref_out_ecount(*EntryCount) LPWSTR **SiteNames
    );

DSGETDCAPI
DWORD
WINAPI
DsGetDcSiteCoverageA(
    IN __in_opt LPCSTR ServerName OPTIONAL,
    OUT PULONG EntryCount,
    OUT __deref_out_ecount(*EntryCount) LPSTR **SiteNames
    );

#ifdef UNICODE
#define DsGetDcSiteCoverage DsGetDcSiteCoverageW
#else
#define DsGetDcSiteCoverage DsGetDcSiteCoverageA
#endif // !UNICODE

DSGETDCAPI
DWORD
WINAPI
DsDeregisterDnsHostRecordsW (
    __in_opt LPWSTR ServerName OPTIONAL,
    __in_opt LPWSTR DnsDomainName OPTIONAL,
    __in_opt GUID   *DomainGuid OPTIONAL,
    __in_opt GUID   *DsaGuid OPTIONAL,
    __in LPWSTR DnsHostName
    );

DSGETDCAPI
DWORD
WINAPI
DsDeregisterDnsHostRecordsA (
    __in_opt LPSTR ServerName OPTIONAL,
    __in_opt LPSTR DnsDomainName OPTIONAL,
    __in_opt GUID  *DomainGuid OPTIONAL,
    __in_opt GUID  *DsaGuid OPTIONAL,
    __in LPSTR DnsHostName
    );

#ifdef UNICODE
#define DsDeregisterDnsHostRecords DsDeregisterDnsHostRecordsW
#else
#define DsDeregisterDnsHostRecords DsDeregisterDnsHostRecordsA
#endif // !UNICODE


#ifdef _WINSOCK2API_  // DsGetDcOpen/Next/Close depend on winsock2.h be included

//
// Option flags passed to DsGetDcOpen
//

#define DS_ONLY_DO_SITE_NAME         0x01   // Non-site specific names should be avoided.
#define DS_NOTIFY_AFTER_SITE_RECORDS 0x02   // Return ERROR_FILEMARK_DETECTED after all
                                            //  site specific records have been processed.

#define DS_OPEN_VALID_OPTION_FLAGS ( DS_ONLY_DO_SITE_NAME | DS_NOTIFY_AFTER_SITE_RECORDS )

//
// Valid DcFlags for DsGetDcOpen
//

#define DS_OPEN_VALID_FLAGS (       \
            DS_FORCE_REDISCOVERY  | \
            DS_ONLY_LDAP_NEEDED   | \
            DS_KDC_REQUIRED       | \
            DS_PDC_REQUIRED       | \
            DS_GC_SERVER_REQUIRED | \
            DS_WRITABLE_REQUIRED )

DSGETDCAPI
DWORD
WINAPI
DsGetDcOpenW(
    IN LPCWSTR DnsName,
    IN ULONG OptionFlags,
    IN LPCWSTR SiteName OPTIONAL,
    IN GUID *DomainGuid OPTIONAL,
    IN LPCWSTR DnsForestName OPTIONAL,
    IN ULONG DcFlags,
    OUT PHANDLE RetGetDcContext
    );

DSGETDCAPI
DWORD
WINAPI
DsGetDcOpenA(
    IN LPCSTR DnsName,
    IN ULONG OptionFlags,
    IN LPCSTR SiteName OPTIONAL,
    IN GUID *DomainGuid OPTIONAL,
    IN LPCSTR DnsForestName OPTIONAL,
    IN ULONG DcFlags,
    OUT PHANDLE RetGetDcContext
    );

#ifdef UNICODE
#define DsGetDcOpen DsGetDcOpenW
#else
#define DsGetDcOpen DsGetDcOpenA
#endif // !UNICODE

DSGETDCAPI
DWORD
WINAPI
DsGetDcNextW(
    IN HANDLE GetDcContextHandle,
    OUT PULONG SockAddressCount OPTIONAL,
    OUT LPSOCKET_ADDRESS *SockAddresses OPTIONAL,
    OUT __deref_opt_out LPWSTR *DnsHostName OPTIONAL
    );

DSGETDCAPI
DWORD
WINAPI
DsGetDcNextA(
    IN HANDLE GetDcContextHandle,
    OUT PULONG SockAddressCount OPTIONAL,
    OUT LPSOCKET_ADDRESS *SockAddresses OPTIONAL,
    OUT __deref_opt_out LPSTR *DnsHostName OPTIONAL
    );

#ifdef UNICODE
#define DsGetDcNext DsGetDcNextW
#else
#define DsGetDcNext DsGetDcNextA
#endif // !UNICODE

DSGETDCAPI
VOID
WINAPI
DsGetDcCloseW(
    IN HANDLE GetDcContextHandle
    );

#ifdef UNICODE
#define DsGetDcClose DsGetDcCloseW
#else
#define DsGetDcClose DsGetDcCloseW  // same for ANSI
#endif // !UNICODE

#endif // _WINSOCK2API_

#ifdef __cplusplus
}
#endif

#endif // _DSGETDC_

