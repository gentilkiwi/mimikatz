//+---------------------------------------------------------------------------
//
//  Microsoft Windows
//  Copyright (C) Microsoft Corporation, 1992-1999.
//
//  File:       schannel.h
//
//  Contents:   Public Definitions for SCHANNEL Security Provider
//
//  Classes:
//
//  Functions:
//
//----------------------------------------------------------------------------



#ifndef __SCHANNEL_H__
#define __SCHANNEL_H__

#if _MSC_VER > 1000
#pragma once
#endif

#include <wincrypt.h>


//
// Security package names.
//

#define UNISP_NAME_A    "Microsoft Unified Security Protocol Provider"
#define UNISP_NAME_W    L"Microsoft Unified Security Protocol Provider"

#define SSL2SP_NAME_A    "Microsoft SSL 2.0"
#define SSL2SP_NAME_W    L"Microsoft SSL 2.0"

#define SSL3SP_NAME_A    "Microsoft SSL 3.0"
#define SSL3SP_NAME_W    L"Microsoft SSL 3.0"

#define TLS1SP_NAME_A    "Microsoft TLS 1.0"
#define TLS1SP_NAME_W    L"Microsoft TLS 1.0"

#define PCT1SP_NAME_A    "Microsoft PCT 1.0"
#define PCT1SP_NAME_W    L"Microsoft PCT 1.0"

#define SCHANNEL_NAME_A  "Schannel"
#define SCHANNEL_NAME_W  L"Schannel"


#ifdef UNICODE

#define UNISP_NAME  UNISP_NAME_W
#define PCT1SP_NAME  PCT1SP_NAME_W
#define SSL2SP_NAME  SSL2SP_NAME_W
#define SSL3SP_NAME  SSL3SP_NAME_W
#define TLS1SP_NAME  TLS1SP_NAME_W
#define SCHANNEL_NAME  SCHANNEL_NAME_W

#else

#define UNISP_NAME  UNISP_NAME_A
#define PCT1SP_NAME  PCT1SP_NAME_A
#define SSL2SP_NAME  SSL2SP_NAME_A
#define SSL3SP_NAME  SSL3SP_NAME_A
#define TLS1SP_NAME  TLS1SP_NAME_A
#define SCHANNEL_NAME  SCHANNEL_NAME_A

#endif


enum eTlsSignatureAlgorithm
{
    TlsSignatureAlgorithm_Anonymous         = 0,
    TlsSignatureAlgorithm_Rsa               = 1,
    TlsSignatureAlgorithm_Dsa               = 2,
    TlsSignatureAlgorithm_Ecdsa             = 3
};

enum eTlsHashAlgorithm
{
    TlsHashAlgorithm_None                   = 0,
    TlsHashAlgorithm_Md5                    = 1,
    TlsHashAlgorithm_Sha1                   = 2,
    TlsHashAlgorithm_Sha224                 = 3,
    TlsHashAlgorithm_Sha256                 = 4,
    TlsHashAlgorithm_Sha384                 = 5,
    TlsHashAlgorithm_Sha512                 = 6
};


//
// RPC constants.
//

#define UNISP_RPC_ID    14


//
// QueryContextAttributes/QueryCredentialsAttribute extensions
//

#define SECPKG_ATTR_ISSUER_LIST          0x50   // (OBSOLETE) returns SecPkgContext_IssuerListInfo
#define SECPKG_ATTR_REMOTE_CRED          0x51   // (OBSOLETE) returns SecPkgContext_RemoteCredentialInfo
#define SECPKG_ATTR_LOCAL_CRED           0x52   // (OBSOLETE) returns SecPkgContext_LocalCredentialInfo
#define SECPKG_ATTR_REMOTE_CERT_CONTEXT  0x53   // returns PCCERT_CONTEXT
#define SECPKG_ATTR_LOCAL_CERT_CONTEXT   0x54   // returns PCCERT_CONTEXT
#define SECPKG_ATTR_ROOT_STORE           0x55   // returns HCERTCONTEXT to the root store
#define SECPKG_ATTR_SUPPORTED_ALGS       0x56   // returns SecPkgCred_SupportedAlgs
#define SECPKG_ATTR_CIPHER_STRENGTHS     0x57   // returns SecPkgCred_CipherStrengths
#define SECPKG_ATTR_SUPPORTED_PROTOCOLS  0x58   // returns SecPkgCred_SupportedProtocols
#define SECPKG_ATTR_ISSUER_LIST_EX       0x59   // returns SecPkgContext_IssuerListInfoEx
#define SECPKG_ATTR_CONNECTION_INFO      0x5a   // returns SecPkgContext_ConnectionInfo
#define SECPKG_ATTR_EAP_KEY_BLOCK        0x5b   // returns SecPkgContext_EapKeyBlock
#define SECPKG_ATTR_MAPPED_CRED_ATTR     0x5c   // returns SecPkgContext_MappedCredAttr
#define SECPKG_ATTR_SESSION_INFO         0x5d   // returns SecPkgContext_SessionInfo
#define SECPKG_ATTR_APP_DATA             0x5e   // sets/returns SecPkgContext_SessionAppData
#define SECPKG_ATTR_REMOTE_CERTIFICATES  0x5F   // returns SecPkgContext_Certificates
#define SECPKG_ATTR_CLIENT_CERT_POLICY   0x60   // sets    SecPkgCred_ClientCertCtlPolicy
#define SECPKG_ATTR_CC_POLICY_RESULT     0x61   // returns SecPkgContext_ClientCertPolicyResult
#define SECPKG_ATTR_USE_NCRYPT           0x62   // Sets the CRED_FLAG_USE_NCRYPT_PROVIDER FLAG on cred group
#define SECPKG_ATTR_LOCAL_CERT_INFO      0x63   // returns SecPkgContext_CertInfo
#define SECPKG_ATTR_CIPHER_INFO          0x64   // returns new CNG SecPkgContext_CipherInfo
#define SECPKG_ATTR_EAP_PRF_INFO         0x65   // sets    SecPkgContext_EapPrfInfo
#define SECPKG_ATTR_SUPPORTED_SIGNATURES 0x66   // returns SecPkgContext_SupportedSignatures


// OBSOLETE - included here for backward compatibility only
typedef struct _SecPkgContext_RemoteCredentialInfo
{
    DWORD   cbCertificateChain;
    PBYTE   pbCertificateChain;
    DWORD   cCertificates;
    DWORD   fFlags;
    DWORD   dwBits;
} SecPkgContext_RemoteCredentialInfo, *PSecPkgContext_RemoteCredentialInfo;

typedef SecPkgContext_RemoteCredentialInfo SecPkgContext_RemoteCredenitalInfo, *PSecPkgContext_RemoteCredenitalInfo;

#define RCRED_STATUS_NOCRED          0x00000000
#define RCRED_CRED_EXISTS            0x00000001
#define RCRED_STATUS_UNKNOWN_ISSUER  0x00000002


// OBSOLETE - included here for backward compatibility only
typedef struct _SecPkgContext_LocalCredentialInfo
{
    DWORD   cbCertificateChain;
    PBYTE   pbCertificateChain;
    DWORD   cCertificates;
    DWORD   fFlags;
    DWORD   dwBits;
} SecPkgContext_LocalCredentialInfo, *PSecPkgContext_LocalCredentialInfo;

typedef SecPkgContext_LocalCredentialInfo SecPkgContext_LocalCredenitalInfo, *PSecPkgContext_LocalCredenitalInfo;

#define LCRED_STATUS_NOCRED          0x00000000
#define LCRED_CRED_EXISTS            0x00000001
#define LCRED_STATUS_UNKNOWN_ISSUER  0x00000002


typedef struct _SecPkgCred_SupportedAlgs
{
    DWORD		cSupportedAlgs;
    ALG_ID		*palgSupportedAlgs;
} SecPkgCred_SupportedAlgs, *PSecPkgCred_SupportedAlgs;


typedef struct _SecPkgCred_CipherStrengths
{
    DWORD       dwMinimumCipherStrength;
    DWORD       dwMaximumCipherStrength;
} SecPkgCred_CipherStrengths, *PSecPkgCred_CipherStrengths;


typedef struct _SecPkgCred_SupportedProtocols
{
    DWORD      	grbitProtocol;
} SecPkgCred_SupportedProtocols, *PSecPkgCred_SupportedProtocols;


typedef struct _SecPkgCred_ClientCertPolicy
{
    DWORD   dwFlags;
    GUID    guidPolicyId;
    DWORD   dwCertFlags;
    DWORD   dwUrlRetrievalTimeout;
    BOOL    fCheckRevocationFreshnessTime;
    DWORD   dwRevocationFreshnessTime;
    BOOL    fOmitUsageCheck;
    LPWSTR  pwszSslCtlStoreName;
    LPWSTR  pwszSslCtlIdentifier;
} SecPkgCred_ClientCertPolicy, *PSecPkgCred_ClientCertPolicy;


typedef struct _SecPkgContext_ClientCertPolicyResult
{
    HRESULT dwPolicyResult;
    GUID    guidPolicyId;
} SecPkgContext_ClientCertPolicyResult, *PSecPkgContext_ClientCertPolicyResult;


typedef struct _SecPkgContext_IssuerListInfoEx
{
    PCERT_NAME_BLOB   	aIssuers;
    DWORD           	cIssuers;
} SecPkgContext_IssuerListInfoEx, *PSecPkgContext_IssuerListInfoEx;


typedef struct _SecPkgContext_ConnectionInfo
{
    DWORD   dwProtocol;
    ALG_ID  aiCipher;
    DWORD   dwCipherStrength;
    ALG_ID  aiHash;
    DWORD   dwHashStrength;
    ALG_ID  aiExch;
    DWORD   dwExchStrength;
} SecPkgContext_ConnectionInfo, *PSecPkgContext_ConnectionInfo;

#define SZ_ALG_MAX_SIZE 64
#define SECPKGCONTEXT_CIPHERINFO_V1 1

typedef struct _SecPkgContext_CipherInfo
{

    DWORD dwVersion;
    DWORD dwProtocol;
    DWORD dwCipherSuite;
    DWORD dwBaseCipherSuite;
    WCHAR szCipherSuite[SZ_ALG_MAX_SIZE];
    WCHAR szCipher[SZ_ALG_MAX_SIZE];
    DWORD dwCipherLen;
    DWORD dwCipherBlockLen;    // in bytes
    WCHAR szHash[SZ_ALG_MAX_SIZE];
    DWORD dwHashLen;
    WCHAR szExchange[SZ_ALG_MAX_SIZE];
    DWORD dwMinExchangeLen;
    DWORD dwMaxExchangeLen;
    WCHAR szCertificate[SZ_ALG_MAX_SIZE];
    DWORD dwKeyType;
} SecPkgContext_CipherInfo, *PSecPkgContext_CipherInfo;



typedef struct _SecPkgContext_EapKeyBlock
{
    BYTE    rgbKeys[128];
    BYTE    rgbIVs[64];
} SecPkgContext_EapKeyBlock, *PSecPkgContext_EapKeyBlock;


typedef struct _SecPkgContext_MappedCredAttr
{
    DWORD   dwAttribute;
    PVOID   pvBuffer;
} SecPkgContext_MappedCredAttr, *PSecPkgContext_MappedCredAttr;


// Flag values for SecPkgContext_SessionInfo
#define SSL_SESSION_RECONNECT   1

typedef struct _SecPkgContext_SessionInfo
{
    DWORD dwFlags;
    DWORD cbSessionId;
    BYTE  rgbSessionId[32];
} SecPkgContext_SessionInfo, *PSecPkgContext_SessionInfo;


typedef struct _SecPkgContext_SessionAppData
{
    DWORD dwFlags;
    DWORD cbAppData;
    __field_bcount(cbAppData) PBYTE pbAppData;
} SecPkgContext_SessionAppData, *PSecPkgContext_SessionAppData;

typedef struct _SecPkgContext_EapPrfInfo
{
    DWORD dwVersion;
    DWORD cbPrfData;
    __field_bcount(cbPrfData) PBYTE pbPrfData;
} SecPkgContext_EapPrfInfo, *PSecPkgContext_EapPrfInfo;


typedef struct _SecPkgContext_SupportedSignatures
{
    WORD cSignatureAndHashAlgorithms;

    //
    // Upper byte (from TLS 1.2, RFC 4346):
    //     enum {
    //         anonymous(0), rsa(1), dsa(2), ecdsa(3), (255)
    //     } SignatureAlgorithm;
    //
    // enum eTlsSignatureAlgorithm
    
    //
    // Lower byte (from TLS 1.2, RFC 4346):
    //     enum {
    //         none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
    //         sha512(6), (255)
    //     } HashAlgorithm;
    //
    //
    // enum eTlsHashAlgorithm
    
    __field_ecount(cSignatureAndHashAlgorithms)
        WORD *pSignatureAndHashAlgorithms;
} SecPkgContext_SupportedSignatures, *PSecPkgContext_SupportedSignatures;


//
// This property returns the raw binary certificates that were received 
// from the remote party. The format of the buffer that's returned is as 
// follows.
// 
//     <4 bytes> length of certificate #1
//     <n bytes> certificate #1
//     <4 bytes> length of certificate #2
//     <n bytes> certificate #2
//     ...
//
// After this data is processed, the caller of QueryContextAttributes 
// must free the pbCertificateChain buffer using FreeContextBuffer.
//
typedef struct _SecPkgContext_Certificates
{
    DWORD   cCertificates;
    DWORD   cbCertificateChain;
    PBYTE   pbCertificateChain;
} SecPkgContext_Certificates, *PSecPkgContext_Certificates;


//
// This property returns information about a certificate. In particular 
// it is useful (and only available) in the kernel where CAPI2 is not
// available.
//
typedef struct _SecPkgContext_CertInfo
{
    DWORD   dwVersion;
    DWORD   cbSubjectName;
    LPWSTR  pwszSubjectName;
    DWORD   cbIssuerName;
    LPWSTR  pwszIssuerName;
    DWORD   dwKeySize;
} SecPkgContext_CertInfo, *PSecPkgContext_CertInfo;

#define KERN_CONTEXT_CERT_INFO_V1 0x00000000

//
// Schannel credentials data structure.
//

#define SCH_CRED_V1              0x00000001
#define SCH_CRED_V2              0x00000002  // for legacy code
#define SCH_CRED_VERSION         0x00000002  // for legacy code
#define SCH_CRED_V3              0x00000003  // for legacy code
#define SCHANNEL_CRED_VERSION    0x00000004


struct _HMAPPER;

typedef struct _SCHANNEL_CRED
{
    DWORD           dwVersion;      // always SCHANNEL_CRED_VERSION
    DWORD           cCreds;
    PCCERT_CONTEXT *paCred;
    HCERTSTORE      hRootStore;

    DWORD           cMappers;
    struct _HMAPPER **aphMappers;

    DWORD           cSupportedAlgs;
    ALG_ID *        palgSupportedAlgs;

    DWORD           grbitEnabledProtocols;
    DWORD           dwMinimumCipherStrength;
    DWORD           dwMaximumCipherStrength;
    DWORD           dwSessionLifespan;
    DWORD           dwFlags;
    DWORD           dwCredFormat;
} SCHANNEL_CRED, *PSCHANNEL_CRED;


// Values for SCHANNEL_CRED dwCredFormat field.
#define SCH_CRED_FORMAT_CERT_CONTEXT    0x00000000
#define SCH_CRED_FORMAT_CERT_HASH       0x00000001
#define SCH_CRED_FORMAT_CERT_HASH_STORE 0x00000002

#define SCH_CRED_MAX_STORE_NAME_SIZE    128
#define SCH_CRED_MAX_SUPPORTED_ALGS     256
#define SCH_CRED_MAX_SUPPORTED_CERTS    100

typedef struct _SCHANNEL_CERT_HASH
{
    DWORD           dwLength;
    DWORD           dwFlags;
    HCRYPTPROV      hProv;
    BYTE            ShaHash[20];
} SCHANNEL_CERT_HASH, *PSCHANNEL_CERT_HASH;

typedef struct _SCHANNEL_CERT_HASH_STORE
{
    DWORD           dwLength;
    DWORD           dwFlags;
    HCRYPTPROV      hProv;
    BYTE            ShaHash[20];
    WCHAR           pwszStoreName[SCH_CRED_MAX_STORE_NAME_SIZE];
} SCHANNEL_CERT_HASH_STORE, *PSCHANNEL_CERT_HASH_STORE;

// Values for SCHANNEL_CERT_HASH dwFlags field.
#define SCH_MACHINE_CERT_HASH           0x00000001


//+-------------------------------------------------------------------------
// Flags for use with SCHANNEL_CRED
//
// SCH_CRED_NO_SYSTEM_MAPPER
//      This flag is intended for use by server applications only. If this
//      flag is set, then schannel does *not* attempt to map received client
//      certificate chains to an NT user account using the built-in system
//      certificate mapper.This flag is ignored by non-NT5 versions of
//      schannel.
//
// SCH_CRED_NO_SERVERNAME_CHECK
//      This flag is intended for use by client applications only. If this
//      flag is set, then when schannel validates the received server
//      certificate chain, is does *not* compare the passed in target name
//      with the subject name embedded in the certificate. This flag is
//      ignored by non-NT5 versions of schannel. This flag is also ignored
//      if the SCH_CRED_MANUAL_CRED_VALIDATION flag is set.
//
// SCH_CRED_MANUAL_CRED_VALIDATION
//      This flag is intended for use by client applications only. If this
//      flag is set, then schannel will *not* automatically attempt to
//      validate the received server certificate chain. This flag is
//      ignored by non-NT5 versions of schannel, but all client applications
//      that wish to validate the certificate chain themselves should
//      specify this flag, so that there's at least a chance they'll run
//      correctly on NT5.
//
// SCH_CRED_NO_DEFAULT_CREDS
//      This flag is intended for use by client applications only. If this
//      flag is set, and the server requests client authentication, then
//      schannel will *not* attempt to automatically acquire a suitable
//      default client certificate chain. This flag is ignored by non-NT5
//      versions of schannel, but all client applications that wish to
//      manually specify their certicate chains should specify this flag,
//      so that there's at least a chance they'll run correctly on NT5.
//
// SCH_CRED_AUTO_CRED_VALIDATION
//      This flag is the opposite of SCH_CRED_MANUAL_CRED_VALIDATION.
//      Conservatively written client applications will always specify one
//      flag or the other.
//
// SCH_CRED_USE_DEFAULT_CREDS
//      This flag is the opposite of SCH_CRED_NO_DEFAULT_CREDS.
//      Conservatively written client applications will always specify one
//      flag or the other.
//
// SCH_CRED_DISABLE_RECONNECTS
//      This flag is intended for use by server applications only. If this 
//      flag is set, then full handshakes performed with this credential 
//      will not be marked suitable for reconnects. A cache entry will still 
//      be created, however, so the session can be made resumable later
//      via a call to ApplyControlToken.
//      
//
// SCH_CRED_REVOCATION_CHECK_END_CERT
// SCH_CRED_REVOCATION_CHECK_CHAIN
// SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
//      These flags specify that when schannel automatically validates a
//      received certificate chain, some or all of the certificates are to
//      be checked for revocation. Only one of these flags may be specified.
//      See the CertGetCertificateChain function. These flags are ignored by
//      non-NT5 versions of schannel.
//
// SCH_CRED_IGNORE_NO_REVOCATION_CHECK
// SCH_CRED_IGNORE_REVOCATION_OFFLINE
//      These flags instruct schannel to ignore the
//      CRYPT_E_NO_REVOCATION_CHECK and CRYPT_E_REVOCATION_OFFLINE errors
//      respectively if they are encountered when attempting to check the
//      revocation status of a received certificate chain. These flags are
//      ignored if none of the above flags are set.
//
// SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE
//      This flag instructs schannel to pass CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
//      flags to CertGetCertificateChain when validating the specified
//      credentials during a call to AcquireCredentialsHandle. The default for 
//      vista is to not specify CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL. Use 
//      SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE to override this behavior.
//      NOTE: Prior to Vista, this flag(CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL) was
//      specified by default. 
//
//  SCH_SEND_ROOT_CERT
//      This flag instructs schannel to send the root cert as part of the 
//      certificate message.
//+-------------------------------------------------------------------------
#define SCH_CRED_NO_SYSTEM_MAPPER                    0x00000002
#define SCH_CRED_NO_SERVERNAME_CHECK                 0x00000004
#define SCH_CRED_MANUAL_CRED_VALIDATION              0x00000008
#define SCH_CRED_NO_DEFAULT_CREDS                    0x00000010
#define SCH_CRED_AUTO_CRED_VALIDATION                0x00000020
#define SCH_CRED_USE_DEFAULT_CREDS                   0x00000040
#define SCH_CRED_DISABLE_RECONNECTS                  0x00000080

#define SCH_CRED_REVOCATION_CHECK_END_CERT           0x00000100
#define SCH_CRED_REVOCATION_CHECK_CHAIN              0x00000200
#define SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT 0x00000400
#define SCH_CRED_IGNORE_NO_REVOCATION_CHECK          0x00000800
#define SCH_CRED_IGNORE_REVOCATION_OFFLINE           0x00001000

#define SCH_CRED_RESTRICTED_ROOTS                    0x00002000
#define SCH_CRED_REVOCATION_CHECK_CACHE_ONLY         0x00004000
#define SCH_CRED_CACHE_ONLY_URL_RETRIEVAL            0x00008000

#define SCH_CRED_MEMORY_STORE_CERT                   0x00010000

#define SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE  0x00020000

#define SCH_SEND_ROOT_CERT                           0x00040000

//
//
// ApplyControlToken PkgParams types
//
// These identifiers are the DWORD types
// to be passed into ApplyControlToken
// through a PkgParams buffer.

#define SCHANNEL_RENEGOTIATE    0   // renegotiate a connection
#define SCHANNEL_SHUTDOWN       1   // gracefully close down a connection
#define SCHANNEL_ALERT          2   // build an error message
#define SCHANNEL_SESSION        3   // session control


// Alert token structure.
typedef struct _SCHANNEL_ALERT_TOKEN
{
    DWORD   dwTokenType;            // SCHANNEL_ALERT
    DWORD   dwAlertType;
    DWORD   dwAlertNumber;
} SCHANNEL_ALERT_TOKEN;

// Alert types.
#define TLS1_ALERT_WARNING              1
#define TLS1_ALERT_FATAL                2

// Alert messages.
#define TLS1_ALERT_CLOSE_NOTIFY         0       // warning
#define TLS1_ALERT_UNEXPECTED_MESSAGE   10      // error
#define TLS1_ALERT_BAD_RECORD_MAC       20      // error
#define TLS1_ALERT_DECRYPTION_FAILED    21      // reserved
#define TLS1_ALERT_RECORD_OVERFLOW      22      // error
#define TLS1_ALERT_DECOMPRESSION_FAIL   30      // error
#define TLS1_ALERT_HANDSHAKE_FAILURE    40      // error
#define TLS1_ALERT_BAD_CERTIFICATE      42      // warning or error
#define TLS1_ALERT_UNSUPPORTED_CERT     43      // warning or error
#define TLS1_ALERT_CERTIFICATE_REVOKED  44      // warning or error
#define TLS1_ALERT_CERTIFICATE_EXPIRED  45      // warning or error
#define TLS1_ALERT_CERTIFICATE_UNKNOWN  46      // warning or error
#define TLS1_ALERT_ILLEGAL_PARAMETER    47      // error
#define TLS1_ALERT_UNKNOWN_CA           48      // error
#define TLS1_ALERT_ACCESS_DENIED        49      // error
#define TLS1_ALERT_DECODE_ERROR         50      // error
#define TLS1_ALERT_DECRYPT_ERROR        51      // error
#define TLS1_ALERT_EXPORT_RESTRICTION   60      // reserved
#define TLS1_ALERT_PROTOCOL_VERSION     70      // error
#define TLS1_ALERT_INSUFFIENT_SECURITY  71      // error
#define TLS1_ALERT_INTERNAL_ERROR       80      // error
#define TLS1_ALERT_USER_CANCELED        90      // warning or error
#define TLS1_ALERT_NO_RENEGOTIATION    100      // warning
#define TLS1_ALERT_UNSUPPORTED_EXT     110      // error


// Session control flags
#define SSL_SESSION_ENABLE_RECONNECTS   1
#define SSL_SESSION_DISABLE_RECONNECTS  2

// Session control token structure.
typedef struct _SCHANNEL_SESSION_TOKEN
{
    DWORD   dwTokenType;        // SCHANNEL_SESSION
    DWORD   dwFlags;
} SCHANNEL_SESSION_TOKEN;


typedef struct _SCHANNEL_CLIENT_SIGNATURE
{
    DWORD       cbLength;
    ALG_ID      aiHash;
    DWORD       cbHash;
    BYTE        HashValue[36];
    BYTE        CertThumbprint[20];
} SCHANNEL_CLIENT_SIGNATURE, *PSCHANNEL_CLIENT_SIGNATURE;


//
// Flags for identifying the various different protocols.
//

/* flag/identifiers for protocols we support */
#define SP_PROT_PCT1_SERVER             0x00000001
#define SP_PROT_PCT1_CLIENT             0x00000002
#define SP_PROT_PCT1                    (SP_PROT_PCT1_SERVER | SP_PROT_PCT1_CLIENT)

#define SP_PROT_SSL2_SERVER             0x00000004
#define SP_PROT_SSL2_CLIENT             0x00000008
#define SP_PROT_SSL2                    (SP_PROT_SSL2_SERVER | SP_PROT_SSL2_CLIENT)

#define SP_PROT_SSL3_SERVER             0x00000010
#define SP_PROT_SSL3_CLIENT             0x00000020
#define SP_PROT_SSL3                    (SP_PROT_SSL3_SERVER | SP_PROT_SSL3_CLIENT)

#define SP_PROT_TLS1_SERVER             0x00000040
#define SP_PROT_TLS1_CLIENT             0x00000080
#define SP_PROT_TLS1                    (SP_PROT_TLS1_SERVER | SP_PROT_TLS1_CLIENT)

#define SP_PROT_SSL3TLS1_CLIENTS        (SP_PROT_TLS1_CLIENT | SP_PROT_SSL3_CLIENT)
#define SP_PROT_SSL3TLS1_SERVERS        (SP_PROT_TLS1_SERVER | SP_PROT_SSL3_SERVER)
#define SP_PROT_SSL3TLS1                (SP_PROT_SSL3 | SP_PROT_TLS1)

#define SP_PROT_UNI_SERVER              0x40000000
#define SP_PROT_UNI_CLIENT              0x80000000
#define SP_PROT_UNI                     (SP_PROT_UNI_SERVER | SP_PROT_UNI_CLIENT)

#define SP_PROT_ALL                     0xffffffff
#define SP_PROT_NONE                    0
#define SP_PROT_CLIENTS                 (SP_PROT_PCT1_CLIENT | SP_PROT_SSL2_CLIENT | SP_PROT_SSL3_CLIENT | SP_PROT_UNI_CLIENT | SP_PROT_TLS1_CLIENT)
#define SP_PROT_SERVERS                 (SP_PROT_PCT1_SERVER | SP_PROT_SSL2_SERVER | SP_PROT_SSL3_SERVER | SP_PROT_UNI_SERVER | SP_PROT_TLS1_SERVER)


#define SP_PROT_TLS1_0_SERVER           SP_PROT_TLS1_SERVER
#define SP_PROT_TLS1_0_CLIENT           SP_PROT_TLS1_CLIENT
#define SP_PROT_TLS1_0                  (SP_PROT_TLS1_0_SERVER | \
                                         SP_PROT_TLS1_0_CLIENT)

#define SP_PROT_TLS1_1_SERVER           0x00000100
#define SP_PROT_TLS1_1_CLIENT           0x00000200
#define SP_PROT_TLS1_1                  (SP_PROT_TLS1_1_SERVER | \
                                         SP_PROT_TLS1_1_CLIENT)

#define SP_PROT_TLS1_2_SERVER           0x00000400
#define SP_PROT_TLS1_2_CLIENT           0x00000800
#define SP_PROT_TLS1_2                  (SP_PROT_TLS1_2_SERVER | \
                                         SP_PROT_TLS1_2_CLIENT)

#define SP_PROT_TLS1_1PLUS_SERVER       (SP_PROT_TLS1_1_SERVER | \
                                         SP_PROT_TLS1_2_SERVER)
#define SP_PROT_TLS1_1PLUS_CLIENT       (SP_PROT_TLS1_1_CLIENT | \
                                         SP_PROT_TLS1_2_CLIENT)
#define SP_PROT_TLS1_1PLUS              (SP_PROT_TLS1_1PLUS_SERVER | \
                                         SP_PROT_TLS1_1PLUS_CLIENT)

#define SP_PROT_TLS1_X_SERVER           (SP_PROT_TLS1_0_SERVER | \
                                         SP_PROT_TLS1_1_SERVER | \
                                         SP_PROT_TLS1_2_SERVER)
#define SP_PROT_TLS1_X_CLIENT           (SP_PROT_TLS1_0_CLIENT | \
                                         SP_PROT_TLS1_1_CLIENT | \
                                         SP_PROT_TLS1_2_CLIENT)
#define SP_PROT_TLS1_X                  (SP_PROT_TLS1_X_SERVER | \
                                         SP_PROT_TLS1_X_CLIENT)

#define SP_PROT_SSL3TLS1_X_CLIENTS      (SP_PROT_TLS1_X_CLIENT | \
                                         SP_PROT_SSL3_CLIENT)
#define SP_PROT_SSL3TLS1_X_SERVERS      (SP_PROT_TLS1_X_SERVER | \
                                         SP_PROT_SSL3_SERVER)
#define SP_PROT_SSL3TLS1_X              (SP_PROT_SSL3 | SP_PROT_TLS1_X)

#define SP_PROT_X_CLIENTS               (SP_PROT_CLIENTS | \
                                         SP_PROT_TLS1_X_CLIENT)
#define SP_PROT_X_SERVERS               (SP_PROT_SERVERS | \
                                         SP_PROT_TLS1_X_SERVER)

//
// Helper function used to flush the SSL session cache.
//

typedef BOOL
(WINAPI * SSL_EMPTY_CACHE_FN_A)(
    LPSTR  pszTargetName,
    DWORD  dwFlags);

BOOL 
WINAPI
SslEmptyCacheA(__in LPSTR  pszTargetName,
               __in DWORD  dwFlags);

typedef BOOL
(WINAPI * SSL_EMPTY_CACHE_FN_W)(
    LPWSTR pszTargetName,
    DWORD  dwFlags);

BOOL 
WINAPI
SslEmptyCacheW(__in LPWSTR pszTargetName,
               __in DWORD  dwFlags);

#ifdef UNICODE
#define SSL_EMPTY_CACHE_FN SSL_EMPTY_CACHE_FN_W
#define SslEmptyCache SslEmptyCacheW
#else
#define SSL_EMPTY_CACHE_FN SSL_EMPTY_CACHE_FN_A
#define SslEmptyCache SslEmptyCacheA
#endif



// Structures for compatability with the
// NT 4.0 SP2 / IE 3.0 schannel interface, do
// not use.

typedef struct _SSL_CREDENTIAL_CERTIFICATE {
    DWORD   cbPrivateKey;
    PBYTE   pPrivateKey;
    DWORD   cbCertificate;
    PBYTE   pCertificate;
    PSTR    pszPassword;
} SSL_CREDENTIAL_CERTIFICATE, * PSSL_CREDENTIAL_CERTIFICATE;




// Structures for use with the
// NT 4.0 SP3 Schannel interface,
// do not use.
#define SCHANNEL_SECRET_TYPE_CAPI   0x00000001
#define SCHANNEL_SECRET_PRIVKEY     0x00000002
#define SCH_CRED_X509_CERTCHAIN     0x00000001
#define SCH_CRED_X509_CAPI          0x00000002
#define SCH_CRED_CERT_CONTEXT       0x00000003

struct _HMAPPER;
typedef struct _SCH_CRED
{
    DWORD     dwVersion;                // always SCH_CRED_VERSION.
    DWORD     cCreds;                   // Number of credentials.
    PVOID     *paSecret;                // Array of SCH_CRED_SECRET_* pointers
    PVOID     *paPublic;                // Array of SCH_CRED_PUBLIC_* pointers
    DWORD     cMappers;                 // Number of credential mappers.
    struct _HMAPPER   **aphMappers;     // pointer to an array of pointers to credential mappers
} SCH_CRED, * PSCH_CRED;

// Structures for use with the
// NT 4.0 SP3 Schannel interface,
// do not use.
typedef struct _SCH_CRED_SECRET_CAPI
{
    DWORD           dwType;      // SCHANNEL_SECRET_TYPE_CAPI
    HCRYPTPROV      hProv;       // credential secret information.

} SCH_CRED_SECRET_CAPI, * PSCH_CRED_SECRET_CAPI;


// Structures for use with the
// NT 4.0 SP3 Schannel interface,
// do not use.
typedef struct _SCH_CRED_SECRET_PRIVKEY
{
    DWORD           dwType;       // SCHANNEL_SECRET_PRIVKEY
    PBYTE           pPrivateKey;   // Der encoded private key
    DWORD           cbPrivateKey;
    PSTR            pszPassword;  // Password to crack the private key.

} SCH_CRED_SECRET_PRIVKEY, * PSCH_CRED_SECRET_PRIVKEY;


// Structures for use with the
// NT 4.0 SP3 Schannel interface,
// do not use.
typedef struct _SCH_CRED_PUBLIC_CERTCHAIN
{
    DWORD       dwType;
    DWORD       cbCertChain;
    PBYTE       pCertChain;
} SCH_CRED_PUBLIC_CERTCHAIN, *PSCH_CRED_PUBLIC_CERTCHAIN;


// Structures needed for Pre NT4.0 SP2 calls.
typedef struct _PctPublicKey
{
    DWORD Type;
    DWORD cbKey;
    UCHAR pKey[1];
} PctPublicKey;

typedef struct _X509Certificate {
    DWORD           Version;
    DWORD           SerialNumber[4];
    ALG_ID          SignatureAlgorithm;
    FILETIME        ValidFrom;
    FILETIME        ValidUntil;
    PSTR            pszIssuer;
    PSTR            pszSubject;
    PctPublicKey    *pPublicKey;
} X509Certificate, * PX509Certificate;



// Pre NT4.0 SP2 calls.  Call CAPI1 or CAPI2
// to get the same functionality instead.
BOOL
WINAPI
SslGenerateKeyPair(
    PSSL_CREDENTIAL_CERTIFICATE pCerts,
    __in PSTR pszDN,
    __in PSTR pszPassword,
    DWORD Bits );

// Pre NT4.0 SP2 calls.  Call CAPI1 or CAPI2
// to get the same functionality instead.
VOID
WINAPI
SslGenerateRandomBits(
    PUCHAR      pRandomData,
    LONG        cRandomData
    );

// Pre NT4.0 SP2 calls.  Call CAPI1 or CAPI2
// to get the same functionality instead.
BOOL
WINAPI
SslCrackCertificate(
    PUCHAR              pbCertificate,
    DWORD               cbCertificate,
    DWORD               dwFlags,
    PX509Certificate *  ppCertificate
    );

// Pre NT4.0 SP2 calls.  Call CAPI1 or CAPI2
// to get the same functionality instead.
VOID
WINAPI
SslFreeCertificate(
    PX509Certificate    pCertificate
    );

DWORD
WINAPI
SslGetMaximumKeySize(
    DWORD   Reserved );

BOOL
WINAPI
SslGetDefaultIssuers(
    PBYTE pbIssuers,
    DWORD *pcbIssuers);

#define SSL_CRACK_CERTIFICATE_NAME  TEXT("SslCrackCertificate")
#define SSL_FREE_CERTIFICATE_NAME   TEXT("SslFreeCertificate")

// Pre NT4.0 SP2 calls.  Call CAPI1 or CAPI2
// to get the same functionality instead.
typedef BOOL
(WINAPI * SSL_CRACK_CERTIFICATE_FN)
(
    PUCHAR              pbCertificate,
    DWORD               cbCertificate,
    BOOL                VerifySignature,
    PX509Certificate *  ppCertificate
);


// Pre NT4.0 SP2 calls.  Call CAPI1 or CAPI2
// to get the same functionality instead.
typedef VOID
(WINAPI * SSL_FREE_CERTIFICATE_FN)
(
    PX509Certificate    pCertificate
);


#endif //__SCHANNEL_H__

