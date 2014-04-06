/*++ BUILD Version: 0000     Increment this if a change has global effects

Copyright (c) Microsoft Corporation. All rights reserved.

Module Name:

    ntsecpkg.h

Abstract:

    This module defines the structures and APIs for use by a
    authentication or security package.

Revision History:

--*/

#ifndef _NTSECPKG_
#define _NTSECPKG_

#ifdef __cplusplus
extern "C" {
#endif


/////////////////////////////////////////////////////////////////////////
//                                                                     //
// Data types used by authentication packages                          //
//                                                                     //
/////////////////////////////////////////////////////////////////////////

//
// opaque data type which represents a client request
//

typedef PVOID *PLSA_CLIENT_REQUEST;


//
// When a logon of a user is requested, the authentication package
// is expected to return one of the following structures indicating
// the contents of a user's token.
//

typedef enum _LSA_TOKEN_INFORMATION_TYPE {
    LsaTokenInformationNull,  // Implies LSA_TOKEN_INFORMATION_NULL data type
    LsaTokenInformationV1,     // Implies LSA_TOKEN_INFORMATION_V1 data type
    LsaTokenInformationV2     // Implies LSA_TOKEN_INFORMATION_V2 data type
} LSA_TOKEN_INFORMATION_TYPE, *PLSA_TOKEN_INFORMATION_TYPE;


//
// The NULL information is used in cases where a non-authenticated
// system access is needed.  For example, a non-authentication network
// circuit (such as LAN Manager's null session) can be given NULL
// information.  This will result in an anonymous token being generated
// for the logon that gives the user no ability to access protected system
// resources, but does allow access to non-protected system resources.
//

typedef struct _LSA_TOKEN_INFORMATION_NULL {

    //
    // Time at which the security context becomes invalid.
    // Use a value in the distant future if the context
    // never expires.
    //

    LARGE_INTEGER ExpirationTime;

    //
    // The SID(s) of groups the user is to be made a member of.  This should
    // not include WORLD or other system defined and assigned
    // SIDs.  These will be added automatically by LSA.
    //
    // Each SID is expected to be in a separately allocated block
    // of memory.  The TOKEN_GROUPS structure is also expected to
    // be in a separately allocated block of memory.
    //

    PTOKEN_GROUPS Groups;

} LSA_TOKEN_INFORMATION_NULL, *PLSA_TOKEN_INFORMATION_NULL;


//
// The V1 token information structure is superceeded by the V2 token
// information structure.  The V1 strucure should only be used for
// backwards compatability.
// This structure contains information that an authentication package
// can place in a Version 1 NT token object.
//

typedef struct _LSA_TOKEN_INFORMATION_V1 {

    //
    // Time at which the security context becomes invalid.
    // Use a value in the distant future if the context
    // never expires.
    //

    LARGE_INTEGER ExpirationTime;

    //
    // The SID of the user logging on.  The SID value is in a
    // separately allocated block of memory.
    //

    TOKEN_USER User;

    //
    // The SID(s) of groups the user is a member of.  This should
    // not include WORLD or other system defined and assigned
    // SIDs.  These will be added automatically by LSA.
    //
    // Each SID is expected to be in a separately allocated block
    // of memory.  The TOKEN_GROUPS structure is also expected to
    // be in a separately allocated block of memory.
    //

    PTOKEN_GROUPS Groups;

    //
    // This field is used to establish the primary group of the user.
    // This value does not have to correspond to one of the SIDs
    // assigned to the user.
    //
    // The SID pointed to by this structure is expected to be in
    // a separately allocated block of memory.
    //
    // This field is mandatory and must be filled in.
    //

    TOKEN_PRIMARY_GROUP PrimaryGroup;



    //
    // The privileges the user is assigned.  This list of privileges
    // will be augmented or over-ridden by any local security policy
    // assigned privileges.
    //
    // Each privilege is expected to be in a separately allocated
    // block of memory.  The TOKEN_PRIVILEGES structure is also
    // expected to be in a separately allocated block of memory.
    //
    // If there are no privileges to assign to the user, this field
    // may be set to NULL.
    //

    PTOKEN_PRIVILEGES Privileges;



    //
    // This field may be used to establish an explicit default
    // owner.  Normally, the user ID is used as the default owner.
    // If another value is desired, it must be specified here.
    //
    // The Owner.Sid field may be set to NULL to indicate there is no
    // alternate default owner value.
    //

    TOKEN_OWNER Owner;

    //
    // This field may be used to establish a default
    // protection for the user.  If no value is provided, then
    // a default protection that grants everyone all access will
    // be established.
    //
    // The DefaultDacl.DefaultDacl field may be set to NULL to indicate
    // there is no default protection.
    //

    TOKEN_DEFAULT_DACL DefaultDacl;

} LSA_TOKEN_INFORMATION_V1, *PLSA_TOKEN_INFORMATION_V1;

//
// The V2 information is used in most cases of logon.  The structure is identical
// to the V1 token information structure, with the exception that the memory allocation
// is handled differently.  The LSA_TOKEN_INFORMATION_V2 structure is intended to be
// allocated monolithiclly, with the privileges, DACL, sids, and group array either part of
// same allocation, or allocated and freed externally.
//

typedef LSA_TOKEN_INFORMATION_V1 LSA_TOKEN_INFORMATION_V2, *PLSA_TOKEN_INFORMATION_V2;


/////////////////////////////////////////////////////////////////////////
//                                                                     //
// Interface definitions available for use by authentication packages  //
//                                                                     //
/////////////////////////////////////////////////////////////////////////



typedef NTSTATUS
(NTAPI LSA_CREATE_LOGON_SESSION) (
    IN PLUID LogonId
    );

typedef NTSTATUS
(NTAPI LSA_DELETE_LOGON_SESSION) (
    IN PLUID LogonId
    );

typedef NTSTATUS
(NTAPI LSA_ADD_CREDENTIAL) (
    IN PLUID LogonId,
    IN ULONG AuthenticationPackage,
    IN PLSA_STRING PrimaryKeyValue,
    IN PLSA_STRING Credentials
    );

typedef NTSTATUS
(NTAPI LSA_GET_CREDENTIALS) (
    IN PLUID LogonId,
    IN ULONG AuthenticationPackage,
    IN OUT PULONG QueryContext,
    IN BOOLEAN RetrieveAllCredentials,
    IN PLSA_STRING PrimaryKeyValue,
    OUT PULONG PrimaryKeyLength,
    IN PLSA_STRING Credentials
    );

typedef NTSTATUS
(NTAPI LSA_DELETE_CREDENTIAL) (
    IN PLUID LogonId,
    IN ULONG AuthenticationPackage,
    IN PLSA_STRING PrimaryKeyValue
    );

typedef PVOID
(NTAPI LSA_ALLOCATE_LSA_HEAP) (
    IN ULONG Length
    );

typedef VOID
(NTAPI LSA_FREE_LSA_HEAP) (
    IN PVOID Base
    );

typedef PVOID
(NTAPI LSA_ALLOCATE_PRIVATE_HEAP) (
    IN SIZE_T Length
    );

typedef VOID
(NTAPI LSA_FREE_PRIVATE_HEAP) (
    IN PVOID Base
    );

typedef NTSTATUS
(NTAPI LSA_ALLOCATE_CLIENT_BUFFER) (
    IN PLSA_CLIENT_REQUEST ClientRequest,
    IN ULONG LengthRequired,
    OUT PVOID *ClientBaseAddress
    );

typedef NTSTATUS
(NTAPI LSA_FREE_CLIENT_BUFFER) (
    IN PLSA_CLIENT_REQUEST ClientRequest,
    IN PVOID ClientBaseAddress
    );

typedef NTSTATUS
(NTAPI LSA_COPY_TO_CLIENT_BUFFER) (
    IN PLSA_CLIENT_REQUEST ClientRequest,
    IN ULONG Length,
    IN PVOID ClientBaseAddress,
    IN PVOID BufferToCopy
    );

typedef NTSTATUS
(NTAPI LSA_COPY_FROM_CLIENT_BUFFER) (
    IN PLSA_CLIENT_REQUEST ClientRequest,
    IN ULONG Length,
    IN PVOID BufferToCopy,
    IN PVOID ClientBaseAddress
    );

typedef LSA_CREATE_LOGON_SESSION * PLSA_CREATE_LOGON_SESSION;
typedef LSA_DELETE_LOGON_SESSION * PLSA_DELETE_LOGON_SESSION;
typedef LSA_ADD_CREDENTIAL * PLSA_ADD_CREDENTIAL;
typedef LSA_GET_CREDENTIALS * PLSA_GET_CREDENTIALS;
typedef LSA_DELETE_CREDENTIAL * PLSA_DELETE_CREDENTIAL;
typedef LSA_ALLOCATE_LSA_HEAP * PLSA_ALLOCATE_LSA_HEAP;
typedef LSA_FREE_LSA_HEAP * PLSA_FREE_LSA_HEAP;
typedef LSA_ALLOCATE_PRIVATE_HEAP * PLSA_ALLOCATE_PRIVATE_HEAP;
typedef LSA_FREE_PRIVATE_HEAP * PLSA_FREE_PRIVATE_HEAP;
typedef LSA_ALLOCATE_CLIENT_BUFFER * PLSA_ALLOCATE_CLIENT_BUFFER;
typedef LSA_FREE_CLIENT_BUFFER * PLSA_FREE_CLIENT_BUFFER;
typedef LSA_COPY_TO_CLIENT_BUFFER * PLSA_COPY_TO_CLIENT_BUFFER;
typedef LSA_COPY_FROM_CLIENT_BUFFER * PLSA_COPY_FROM_CLIENT_BUFFER;

//
// The dispatch table of LSA services which are available to
// authentication packages.
//
typedef struct _LSA_DISPATCH_TABLE {
    PLSA_CREATE_LOGON_SESSION CreateLogonSession;
    PLSA_DELETE_LOGON_SESSION DeleteLogonSession;
    PLSA_ADD_CREDENTIAL AddCredential;
    PLSA_GET_CREDENTIALS GetCredentials;
    PLSA_DELETE_CREDENTIAL DeleteCredential;
    PLSA_ALLOCATE_LSA_HEAP AllocateLsaHeap;
    PLSA_FREE_LSA_HEAP FreeLsaHeap;
    PLSA_ALLOCATE_CLIENT_BUFFER AllocateClientBuffer;
    PLSA_FREE_CLIENT_BUFFER FreeClientBuffer;
    PLSA_COPY_TO_CLIENT_BUFFER CopyToClientBuffer;
    PLSA_COPY_FROM_CLIENT_BUFFER CopyFromClientBuffer;
} LSA_DISPATCH_TABLE, *PLSA_DISPATCH_TABLE;



////////////////////////////////////////////////////////////////////////////
//                                                                        //
// Interface definitions of services provided by authentication packages  //
//                                                                        //
////////////////////////////////////////////////////////////////////////////



//
// Routine names
//
// The routines provided by the DLL must be assigned the following names
// so that their addresses can be retrieved when the DLL is loaded.
//

#define LSA_AP_NAME_INITIALIZE_PACKAGE      "LsaApInitializePackage\0"
#define LSA_AP_NAME_LOGON_USER              "LsaApLogonUser\0"
#define LSA_AP_NAME_LOGON_USER_EX           "LsaApLogonUserEx\0"
#define LSA_AP_NAME_CALL_PACKAGE            "LsaApCallPackage\0"
#define LSA_AP_NAME_LOGON_TERMINATED        "LsaApLogonTerminated\0"
#define LSA_AP_NAME_CALL_PACKAGE_UNTRUSTED  "LsaApCallPackageUntrusted\0"
#define LSA_AP_NAME_CALL_PACKAGE_PASSTHROUGH "LsaApCallPackagePassthrough\0"


//
// Routine templates
//


typedef NTSTATUS
(NTAPI LSA_AP_INITIALIZE_PACKAGE) (
    IN ULONG AuthenticationPackageId,
    IN PLSA_DISPATCH_TABLE LsaDispatchTable,
    IN PLSA_STRING Database OPTIONAL,
    IN PLSA_STRING Confidentiality OPTIONAL,
    OUT PLSA_STRING *AuthenticationPackageName
    );

typedef NTSTATUS
(NTAPI LSA_AP_LOGON_USER) (
    IN PLSA_CLIENT_REQUEST ClientRequest,
    IN SECURITY_LOGON_TYPE LogonType,
    IN PVOID AuthenticationInformation,
    IN PVOID ClientAuthenticationBase,
    IN ULONG AuthenticationInformationLength,
    OUT PVOID *ProfileBuffer,
    OUT PULONG ProfileBufferLength,
    OUT PLUID LogonId,
    OUT PNTSTATUS SubStatus,
    OUT PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    OUT PVOID *TokenInformation,
    OUT PLSA_UNICODE_STRING *AccountName,
    OUT PLSA_UNICODE_STRING *AuthenticatingAuthority
    );

typedef NTSTATUS
(NTAPI LSA_AP_LOGON_USER_EX) (
    IN PLSA_CLIENT_REQUEST ClientRequest,
    IN SECURITY_LOGON_TYPE LogonType,
    IN PVOID AuthenticationInformation,
    IN PVOID ClientAuthenticationBase,
    IN ULONG AuthenticationInformationLength,
    OUT PVOID *ProfileBuffer,
    OUT PULONG ProfileBufferLength,
    OUT PLUID LogonId,
    OUT PNTSTATUS SubStatus,
    OUT PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    OUT PVOID *TokenInformation,
    OUT PUNICODE_STRING *AccountName,
    OUT PUNICODE_STRING *AuthenticatingAuthority,
    OUT PUNICODE_STRING *MachineName
    );

typedef NTSTATUS
(NTAPI LSA_AP_CALL_PACKAGE) (
    IN PLSA_CLIENT_REQUEST ClientRequest,
    IN PVOID ProtocolSubmitBuffer,
    IN PVOID ClientBufferBase,
    IN ULONG SubmitBufferLength,
    OUT PVOID *ProtocolReturnBuffer,
    OUT PULONG ReturnBufferLength,
    OUT PNTSTATUS ProtocolStatus
    );

typedef NTSTATUS
(NTAPI LSA_AP_CALL_PACKAGE_PASSTHROUGH) (
    IN PLSA_CLIENT_REQUEST ClientRequest,
    IN PVOID ProtocolSubmitBuffer,
    IN PVOID ClientBufferBase,
    IN ULONG SubmitBufferLength,
    OUT PVOID *ProtocolReturnBuffer,
    OUT PULONG ReturnBufferLength,
    OUT PNTSTATUS ProtocolStatus
    );

typedef VOID
(NTAPI LSA_AP_LOGON_TERMINATED) (
    IN PLUID LogonId
    );

typedef LSA_AP_CALL_PACKAGE LSA_AP_CALL_PACKAGE_UNTRUSTED;

typedef LSA_AP_INITIALIZE_PACKAGE * PLSA_AP_INITIALIZE_PACKAGE;
typedef LSA_AP_LOGON_USER * PLSA_AP_LOGON_USER;
typedef LSA_AP_LOGON_USER_EX * PLSA_AP_LOGON_USER_EX;
typedef LSA_AP_CALL_PACKAGE * PLSA_AP_CALL_PACKAGE;
typedef LSA_AP_CALL_PACKAGE_PASSTHROUGH * PLSA_AP_CALL_PACKAGE_PASSTHROUGH;
typedef LSA_AP_LOGON_TERMINATED * PLSA_AP_LOGON_TERMINATED;
typedef LSA_AP_CALL_PACKAGE_UNTRUSTED * PLSA_AP_CALL_PACKAGE_UNTRUSTED;


#ifndef _SAM_CREDENTIAL_UPDATE_DEFINED
#define _SAM_CREDENTIAL_UPDATE_DEFINED

typedef NTSTATUS (*PSAM_CREDENTIAL_UPDATE_NOTIFY_ROUTINE) (
    __in                                   PUNICODE_STRING ClearPassword,
    __in_bcount(OldCredentialSize)         PVOID OldCredentials,
    __in                                   ULONG OldCredentialSize,
    __in                                   ULONG UserAccountControl,
    __in_opt                               PUNICODE_STRING UPN,  
    __in                                   PUNICODE_STRING UserName,
    __in                                   PUNICODE_STRING NetbiosDomainName,
    __in                                   PUNICODE_STRING DnsDomainName,
    __deref_out_bcount(*NewCredentialSize) PVOID * NewCredentials,
    __out                                  ULONG * NewCredentialSize
    );

#define SAM_CREDENTIAL_UPDATE_NOTIFY_ROUTINE "CredentialUpdateNotify"

typedef BOOLEAN (*PSAM_CREDENTIAL_UPDATE_REGISTER_ROUTINE) (
    __out PUNICODE_STRING CredentialName
    );

#define SAM_CREDENTIAL_UPDATE_REGISTER_ROUTINE "CredentialUpdateRegister"

typedef VOID (*PSAM_CREDENTIAL_UPDATE_FREE_ROUTINE) (
    __in PVOID p
    );

#define SAM_CREDENTIAL_UPDATE_FREE_ROUTINE "CredentialUpdateFree"

typedef struct {
    PSTR   Original;
    PSTR   Mapped;
    BOOLEAN Continuable;  // only honored for some operations
} SAM_REGISTER_MAPPING_ELEMENT, *PSAM_REGISTER_MAPPING_ELEMENT;

typedef struct {
                    ULONG                           Count;
    __ecount(Count) PSAM_REGISTER_MAPPING_ELEMENT   Elements;
} SAM_REGISTER_MAPPING_LIST, *PSAM_REGISTER_MAPPING_LIST;

typedef struct {
                    ULONG                          Count;
    __ecount(Count) PSAM_REGISTER_MAPPING_LIST     Lists;
} SAM_REGISTER_MAPPING_TABLE, *PSAM_REGISTER_MAPPING_TABLE;

typedef NTSTATUS (*PSAM_CREDENTIAL_UPDATE_REGISTER_MAPPED_ENTRYPOINTS_ROUTINE) (
    __out SAM_REGISTER_MAPPING_TABLE *Table
    );

#define SAM_CREDENTIAL_UPDATE_REGISTER_MAPPED_ENTRYPOINTS_ROUTINE "RegisterMappedEntrypoints"

#endif // _SAM_CREDENTIAL_UPDATE_DEFINED


#ifdef SECURITY_KERNEL
//
// Can't use the windows.h def'ns in kernel mode.
//
typedef PVOID                   SEC_THREAD_START;
typedef PVOID                   SEC_ATTRS;
#else
typedef LPTHREAD_START_ROUTINE  SEC_THREAD_START;
typedef LPSECURITY_ATTRIBUTES   SEC_ATTRS;
#endif


#define SecEqualLuid(L1, L2)    \
            ( ( ((PLUID)L1)->LowPart == ((PLUID)L2)->LowPart ) && \
              ( ((PLUID)L1)->HighPart == ((PLUID)L2)->HighPart ) ) \

#define SecIsZeroLuid( L1 ) \
            ( ( L1->LowPart | L1->HighPart ) == 0 )

//
// The following structures are used by the helper functions
//

typedef struct _SECPKG_CLIENT_INFO {
    LUID            LogonId;            // Effective Logon Id
    ULONG           ProcessID;          // Process Id of caller
    ULONG           ThreadID;           // Thread Id of caller
    BOOLEAN         HasTcbPrivilege;    // Client has TCB
    BOOLEAN         Impersonating;      // Client is impersonating
    BOOLEAN         Restricted;         // Client is restricted

    //
    // NT 5.1
    //

    UCHAR                           ClientFlags;            // Extra flags about the client
    SECURITY_IMPERSONATION_LEVEL    ImpersonationLevel;     // Impersonation level of client

    //
    // NT 6
    //

    HANDLE                          ClientToken;

} SECPKG_CLIENT_INFO, * PSECPKG_CLIENT_INFO;

#define SECPKG_CLIENT_PROCESS_TERMINATED    0x01    // The client process has terminated
#define SECPKG_CLIENT_THREAD_TERMINATED     0x02    // The client thread has terminated

typedef struct _SECPKG_CALL_INFO {
    ULONG           ProcessId;
    ULONG           ThreadId;
    ULONG           Attributes;
    ULONG           CallCount;
    PVOID           MechOid; // mechanism objection identifer
} SECPKG_CALL_INFO, * PSECPKG_CALL_INFO;

#define SECPKG_CALL_KERNEL_MODE     0x00000001  // Call originated in kernel mode
#define SECPKG_CALL_ANSI            0x00000002  // Call came from ANSI stub
#define SECPKG_CALL_URGENT          0x00000004  // Call designated urgent
#define SECPKG_CALL_RECURSIVE       0x00000008  // Call is recursing
#define SECPKG_CALL_IN_PROC         0x00000010  // Call originated in process
#define SECPKG_CALL_CLEANUP         0x00000020  // Call is cleanup from a client
#define SECPKG_CALL_WOWCLIENT       0x00000040  // Call is from a WOW client process
#define SECPKG_CALL_THREAD_TERM     0x00000080  // Call is from a thread that has term'd
#define SECPKG_CALL_PROCESS_TERM    0x00000100  // Call is from a process that has term'd
#define SECPKG_CALL_IS_TCB          0x00000200  // Call is from TCB
#define SECPKG_CALL_NETWORK_ONLY    0x00000400  // Call asks for network logon only, no cached logons
#define SECPKG_CALL_WINLOGON        0x00000800  // the caller of LsaLogonuser() is Winlogon
#define SECPKG_CALL_ASYNC_UPDATE    0x00001000  // asynchronous update for unlock
#define SECPKG_CALL_SYSTEM_PROC     0x00002000  // Call originated from the System process
#define SECPKG_CALL_NEGO            0x00004000  // Called by SPNEGO
#define SECPKG_CALL_NEGO_EXTENDER   0x00008000  // Called by NEGO extender
#define SECPKG_CALL_BUFFER_MARSHAL  0x00010000  // Buffer passed is marshaled (by RPC)

typedef struct _SECPKG_SUPPLEMENTAL_CRED {
    UNICODE_STRING PackageName;
    ULONG CredentialSize;
#ifdef MIDL_PASS
    [size_is(CredentialSize)]
#endif // MIDL_PASS
    PUCHAR Credentials;
} SECPKG_SUPPLEMENTAL_CRED, *PSECPKG_SUPPLEMENTAL_CRED;

typedef struct _SECPKG_BYTE_VECTOR
{
    ULONG ByteArrayOffset; // each element is a byte
    USHORT ByteArrayLength;
} SECPKG_BYTE_VECTOR, *PSECPKG_BYTE_VECTOR;

typedef struct _SECPKG_SHORT_VECTOR
{
    ULONG ShortArrayOffset; // each element is a short
    USHORT ShortArrayCount; // number of characters
} SECPKG_SHORT_VECTOR, *PSECPKG_SHORT_VECTOR;

//
// the supplied credential structure
//

typedef struct _SECPKG_SUPPLIED_CREDENTIAL {
    USHORT cbHeaderLength; // the length of the header
    USHORT cbStructureLength; //  pay load length including the header
    SECPKG_SHORT_VECTOR UserName; // unicode only
    SECPKG_SHORT_VECTOR DomainName; // unicode only
    SECPKG_BYTE_VECTOR PackedCredentials; // SEC_WINNT_AUTH_PACKED_CREDENTIALS
    ULONG CredFlags; // authidentity flags
} SECPKG_SUPPLIED_CREDENTIAL, *PSECPKG_SUPPLIED_CREDENTIAL;

//
// the credential structure used by Nego2-SPMI
//

#define SECPKG_CREDENTIAL_VERSION  201

//
//  credentials flags
//

#define SECPKG_CREDENTIAL_FLAGS_CALLER_HAS_TCB 0x1

typedef struct _SECPKG_CREDENTIAL {
    ULONG64 Version; // contains SECPKG_CREDENTIAL_VERSION
    USHORT cbHeaderLength;   // the length of the header
    ULONG cbStructureLength; // pay load length including the header,
    // all the content of this structure is within a contiguous buffer
    ULONG ClientProcess; // the caller's identity
    ULONG ClientThread;  // the caller's identity
    LUID LogonId;        // the caller's identity
    HANDLE ClientToken;  // the caller's identity
    ULONG SessionId;     // the caller's identity
    LUID ModifiedId;     // the caller's identity
    ULONG fCredentials;  // inbound or outbound?
    ULONG Flags;  // contains SECPKG_CREDENTIAL_FLAGS
    SECPKG_BYTE_VECTOR PrincipalName; // not used
    SECPKG_BYTE_VECTOR PackageList;   // list of packages, relevant only to SPNEGO
    SECPKG_BYTE_VECTOR MarshaledSuppliedCreds; // contains a SECPKG_SUPPLIED_CREDENTIAL structure
} SECPKG_CREDENTIAL, *PSECPKG_CREDENTIAL;

typedef ULONG_PTR LSA_SEC_HANDLE;
typedef LSA_SEC_HANDLE * PLSA_SEC_HANDLE;
typedef struct _SECPKG_SUPPLEMENTAL_CRED_ARRAY {
    ULONG CredentialCount;
#ifdef MIDL_PASS
    [size_is(CredentialCount)] SECPKG_SUPPLEMENTAL_CRED Credentials[*];
#else // MIDL_PASS
    SECPKG_SUPPLEMENTAL_CRED Credentials[1];
#endif // MIDL_PASS
} SECPKG_SUPPLEMENTAL_CRED_ARRAY, *PSECPKG_SUPPLEMENTAL_CRED_ARRAY;

//
// This flag is used for to indicate which buffers in the LSA are located
// in the client's address space
//

#define SECBUFFER_UNMAPPED      0x40000000

//
// This flag is used to indicate that the buffer was mapped into the LSA
// from kernel mode.
//

#define SECBUFFER_KERNEL_MAP    0x20000000

typedef NTSTATUS
(NTAPI LSA_CALLBACK_FUNCTION)(
    ULONG_PTR    Argument1,
    ULONG_PTR    Argument2,
    PSecBuffer  InputBuffer,
    PSecBuffer  OutputBuffer
    );

typedef LSA_CALLBACK_FUNCTION * PLSA_CALLBACK_FUNCTION;



#define PRIMARY_CRED_CLEAR_PASSWORD     0x1
#define PRIMARY_CRED_OWF_PASSWORD       0x2
#define PRIMARY_CRED_UPDATE             0x4     // this is a change of existing creds
#define PRIMARY_CRED_CACHED_LOGON       0x8
#define PRIMARY_CRED_LOGON_NO_TCB       0x10
#define PRIMARY_CRED_LOGON_LUA          0x20
#define PRIMARY_CRED_INTERACTIVE_SMARTCARD_LOGON 0x40
#define PRIMARY_CRED_REFRESH_NEEDED     0x80   // unlock refresh needed


#define PRIMARY_CRED_LOGON_PACKAGE_SHIFT 24
#define PRIMARY_CRED_PACKAGE_MASK 0xff000000

//
// For cached logons, the RPC id of the package doing the logon is identified
// by shifting the flags to the right by the PRIMARY_CRED_LOGON_PACKAGE_SHIFT.
//

typedef struct _SECPKG_PRIMARY_CRED {
    LUID LogonId;
    UNICODE_STRING DownlevelName;   // Sam Account Name
    UNICODE_STRING DomainName;      // Netbios domain name where account is located
    UNICODE_STRING Password;
    UNICODE_STRING OldPassword;
    PSID UserSid;
    ULONG Flags;
    UNICODE_STRING DnsDomainName;   // DNS domain name where account is located (if known)
    UNICODE_STRING Upn;             // UPN of account (if known)

    UNICODE_STRING LogonServer;
    UNICODE_STRING Spare1;
    UNICODE_STRING Spare2;
    UNICODE_STRING Spare3;
    UNICODE_STRING Spare4;
} SECPKG_PRIMARY_CRED, *PSECPKG_PRIMARY_CRED;

//
// Maximum size of stored credentials.
//

#define MAX_CRED_SIZE 1024

// Values for MachineState

#define SECPKG_STATE_ENCRYPTION_PERMITTED               0x01
#define SECPKG_STATE_STRONG_ENCRYPTION_PERMITTED        0x02
#define SECPKG_STATE_DOMAIN_CONTROLLER                  0x04
#define SECPKG_STATE_WORKSTATION                        0x08
#define SECPKG_STATE_STANDALONE                         0x10

typedef struct _SECPKG_PARAMETERS {
    ULONG           Version;
    ULONG           MachineState;
    ULONG           SetupMode;
    PSID            DomainSid;
    UNICODE_STRING  DomainName;
    UNICODE_STRING  DnsDomainName;
    GUID            DomainGuid;
} SECPKG_PARAMETERS, *PSECPKG_PARAMETERS;


//
// Extended Package information structures
//

typedef enum _SECPKG_EXTENDED_INFORMATION_CLASS {
    SecpkgGssInfo = 1,
    SecpkgContextThunks,
    SecpkgMutualAuthLevel,
    SecpkgWowClientDll,
    SecpkgExtraOids,
    SecpkgMaxInfo,
    SecpkgNego2Info,
} SECPKG_EXTENDED_INFORMATION_CLASS;

typedef struct _SECPKG_GSS_INFO {
    ULONG   EncodedIdLength;
    UCHAR   EncodedId[4];
} SECPKG_GSS_INFO, * PSECPKG_GSS_INFO;

typedef struct _SECPKG_CONTEXT_THUNKS {
    ULONG   InfoLevelCount;
    ULONG   Levels[1];
} SECPKG_CONTEXT_THUNKS, *PSECPKG_CONTEXT_THUNKS;

typedef struct _SECPKG_MUTUAL_AUTH_LEVEL {
    ULONG   MutualAuthLevel;
} SECPKG_MUTUAL_AUTH_LEVEL, * PSECPKG_MUTUAL_AUTH_LEVEL;

typedef struct _SECPKG_WOW_CLIENT_DLL {
    SECURITY_STRING WowClientDllPath;
} SECPKG_WOW_CLIENT_DLL, * PSECPKG_WOW_CLIENT_DLL;

#define SECPKG_MAX_OID_LENGTH   32

typedef struct _SECPKG_SERIALIZED_OID {
    ULONG OidLength;
    ULONG OidAttributes;
    UCHAR OidValue[ SECPKG_MAX_OID_LENGTH ];
} SECPKG_SERIALIZED_OID, * PSECPKG_SERIALIZED_OID;

typedef struct _SECPKG_EXTRA_OIDS {
    ULONG   OidCount;
    SECPKG_SERIALIZED_OID Oids[ 1 ];
} SECPKG_EXTRA_OIDS, * PSECPKG_EXTRA_OIDS;

// used by Nego2
typedef struct _SECPKG_NEGO2_INFO {
    UCHAR AuthScheme[16]; // auth id
    ULONG PackageFlags;
} SECPKG_NEGO2_INFO, * PSECPKG_NEGO2_INFO;

typedef struct _SECPKG_EXTENDED_INFORMATION {
    SECPKG_EXTENDED_INFORMATION_CLASS   Class;
    union {
        SECPKG_GSS_INFO          GssInfo;
        SECPKG_CONTEXT_THUNKS    ContextThunks;
        SECPKG_MUTUAL_AUTH_LEVEL MutualAuthLevel;
        SECPKG_WOW_CLIENT_DLL    WowClientDll;
        SECPKG_EXTRA_OIDS        ExtraOids;
        SECPKG_NEGO2_INFO        Nego2Info;
    } Info;
} SECPKG_EXTENDED_INFORMATION, * PSECPKG_EXTENDED_INFORMATION;

typedef struct  _SECPKG_TARGETINFO
{
    PSID    DomainSid;
    PCWSTR  ComputerName;
} SECPKG_TARGETINFO, *PSECPKG_TARGETINFO;

#define SECPKG_ATTR_SASL_CONTEXT    0x00010000

typedef struct _SecPkgContext_SaslContext {
    PVOID   SaslContext;
} SecPkgContext_SaslContext, * PSecPkgContext_SaslContext;

//
// Setting this value as the first context thunk value will cause all
// calls to go to the LSA:
//

#define SECPKG_ATTR_THUNK_ALL   0x00010000


#ifndef SECURITY_USER_DATA_DEFINED
#define SECURITY_USER_DATA_DEFINED

typedef struct _SECURITY_USER_DATA {
    SECURITY_STRING UserName;           // User name
    SECURITY_STRING LogonDomainName;    // Domain the user logged on to
    SECURITY_STRING LogonServer;        // Server that logged the user on
    PSID            pSid;               // SID of user
} SECURITY_USER_DATA, *PSECURITY_USER_DATA;

typedef SECURITY_USER_DATA SecurityUserData, * PSecurityUserData;


#define UNDERSTANDS_LONG_NAMES  1
#define NO_LONG_NAMES           2

#endif // SECURITY_USER_DATA_DEFINED

//////////////////////////////////////////////////////////////////////////
//
// The following prototypes are to functions that are provided by the SPMgr
// to security packages.
//
//////////////////////////////////////////////////////////////////////////

typedef NTSTATUS
(NTAPI LSA_IMPERSONATE_CLIENT) (
    VOID
    );


typedef NTSTATUS
(NTAPI LSA_UNLOAD_PACKAGE)(
    VOID
    );

typedef NTSTATUS
(NTAPI LSA_DUPLICATE_HANDLE)(
    IN HANDLE SourceHandle,
    OUT PHANDLE DestionationHandle);


typedef NTSTATUS
(NTAPI LSA_SAVE_SUPPLEMENTAL_CREDENTIALS)(
    IN PLUID LogonId,
    IN ULONG SupplementalCredSize,
    IN PVOID SupplementalCreds,
    IN BOOLEAN Synchronous
    );


typedef HANDLE
(NTAPI LSA_CREATE_THREAD)(
    IN SEC_ATTRS SecurityAttributes,
    IN ULONG StackSize,
    IN SEC_THREAD_START StartFunction,
    IN PVOID ThreadParameter,
    IN ULONG CreationFlags,
    OUT PULONG ThreadId
    );


typedef NTSTATUS
(NTAPI LSA_GET_CLIENT_INFO)(
    OUT PSECPKG_CLIENT_INFO ClientInfo
    );


typedef HANDLE
(NTAPI LSA_REGISTER_NOTIFICATION)(
    IN SEC_THREAD_START StartFunction,
    IN PVOID Parameter,
    IN ULONG NotificationType,
    IN ULONG NotificationClass,
    IN ULONG NotificationFlags,
    IN ULONG IntervalMinutes,
    IN OPTIONAL HANDLE WaitEvent
    );


typedef NTSTATUS
(NTAPI LSA_CANCEL_NOTIFICATION)(
    IN HANDLE NotifyHandle
    );

typedef NTSTATUS
(NTAPI LSA_MAP_BUFFER)(
    IN PSecBuffer InputBuffer,
    OUT PSecBuffer OutputBuffer
    );

typedef NTSTATUS
(NTAPI LSA_CREATE_TOKEN) (
    IN PLUID LogonId,
    IN PTOKEN_SOURCE TokenSource,
    IN SECURITY_LOGON_TYPE LogonType,
    IN SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    IN LSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    IN PVOID TokenInformation,
    IN PTOKEN_GROUPS TokenGroups,
    IN PUNICODE_STRING AccountName,
    IN PUNICODE_STRING AuthorityName,
    IN PUNICODE_STRING Workstation,
    IN PUNICODE_STRING ProfilePath,
    OUT PHANDLE Token,
    OUT PNTSTATUS SubStatus
    );

typedef enum _SECPKG_SESSIONINFO_TYPE {
    SecSessionPrimaryCred       // SessionInformation is SECPKG_PRIMARY_CRED
} SECPKG_SESSIONINFO_TYPE;

typedef NTSTATUS
(NTAPI LSA_CREATE_TOKEN_EX) (
    IN PLUID LogonId,
    IN PTOKEN_SOURCE TokenSource,
    IN SECURITY_LOGON_TYPE LogonType,
    IN SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    IN LSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    IN PVOID TokenInformation,
    IN PTOKEN_GROUPS TokenGroups,
    IN PUNICODE_STRING Workstation,
    IN PUNICODE_STRING ProfilePath,
    IN PVOID SessionInformation,
    IN SECPKG_SESSIONINFO_TYPE SessionInformationType,
    OUT PHANDLE Token,
    OUT PNTSTATUS SubStatus
    );

typedef VOID
(NTAPI LSA_AUDIT_LOGON) (
    IN NTSTATUS Status,
    IN NTSTATUS SubStatus,
    IN PUNICODE_STRING AccountName,
    IN PUNICODE_STRING AuthenticatingAuthority,
    IN PUNICODE_STRING WorkstationName,
    IN OPTIONAL PSID UserSid,
    IN SECURITY_LOGON_TYPE LogonType,
    IN PTOKEN_SOURCE TokenSource,
    IN PLUID LogonId
    );

typedef NTSTATUS
(NTAPI LSA_CALL_PACKAGE) (
    IN PUNICODE_STRING AuthenticationPackage,
    IN PVOID ProtocolSubmitBuffer,
    IN ULONG SubmitBufferLength,
    OUT PVOID *ProtocolReturnBuffer,
    OUT PULONG ReturnBufferLength,
    OUT PNTSTATUS ProtocolStatus
    );

typedef NTSTATUS
(NTAPI LSA_CALL_PACKAGEEX) (
    IN PUNICODE_STRING AuthenticationPackage,
    IN PVOID ClientBufferBase,
    IN PVOID ProtocolSubmitBuffer,
    IN ULONG SubmitBufferLength,
    OUT PVOID *ProtocolReturnBuffer,
    OUT PULONG ReturnBufferLength,
    OUT PNTSTATUS ProtocolStatus
    );

typedef NTSTATUS
(NTAPI LSA_CALL_PACKAGE_PASSTHROUGH) (
    IN PUNICODE_STRING AuthenticationPackage,
    IN PVOID ClientBufferBase,
    IN PVOID ProtocolSubmitBuffer,
    IN ULONG SubmitBufferLength,
    OUT PVOID *ProtocolReturnBuffer,
    OUT PULONG ReturnBufferLength,
    OUT PNTSTATUS ProtocolStatus
    );

typedef BOOLEAN
(NTAPI LSA_GET_CALL_INFO) (
    OUT PSECPKG_CALL_INFO   Info
    );

typedef PVOID
(NTAPI LSA_CREATE_SHARED_MEMORY)(
    ULONG MaxSize,
    ULONG InitialSize
    );

typedef PVOID
(NTAPI LSA_ALLOCATE_SHARED_MEMORY)(
    PVOID SharedMem,
    ULONG Size
    );

typedef VOID
(NTAPI LSA_FREE_SHARED_MEMORY)(
    PVOID SharedMem,
    PVOID Memory
    );

typedef BOOLEAN
(NTAPI LSA_DELETE_SHARED_MEMORY)(
    PVOID SharedMem
    );

//
// Account Access
//

typedef enum _SECPKG_NAME_TYPE {
    SecNameSamCompatible,
    SecNameAlternateId,
    SecNameFlat,
    SecNameDN,
    SecNameSPN
} SECPKG_NAME_TYPE;

typedef NTSTATUS
(NTAPI LSA_OPEN_SAM_USER)(
    PSECURITY_STRING Name,
    SECPKG_NAME_TYPE NameType,
    PSECURITY_STRING Prefix,
    BOOLEAN AllowGuest,
    ULONG Reserved,
    PVOID * UserHandle
    );

typedef NTSTATUS
(NTAPI LSA_GET_USER_CREDENTIALS)(
    PVOID UserHandle,
    PVOID * PrimaryCreds,
    PULONG PrimaryCredsSize,
    PVOID * SupplementalCreds,
    PULONG SupplementalCredsSize
    );

typedef NTSTATUS
(NTAPI LSA_GET_USER_AUTH_DATA)(
    PVOID UserHandle,
    PUCHAR * UserAuthData,
    PULONG UserAuthDataSize
    );

typedef NTSTATUS
(NTAPI LSA_CLOSE_SAM_USER)(
    PVOID UserHandle
    );

typedef NTSTATUS
(NTAPI LSA_GET_AUTH_DATA_FOR_USER)(
    PSECURITY_STRING Name,
    SECPKG_NAME_TYPE NameType,
    PSECURITY_STRING Prefix,
    PUCHAR * UserAuthData,
    PULONG UserAuthDataSize,
    PUNICODE_STRING UserFlatName
    );

typedef NTSTATUS
(NTAPI LSA_CONVERT_AUTH_DATA_TO_TOKEN)(
    IN PVOID UserAuthData,
    IN ULONG UserAuthDataSize,
    IN SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
    IN PTOKEN_SOURCE TokenSource,
    IN SECURITY_LOGON_TYPE LogonType,
    IN PUNICODE_STRING AuthorityName,
    OUT PHANDLE Token,
    OUT PLUID LogonId,
    OUT PUNICODE_STRING AccountName,
    OUT PNTSTATUS SubStatus
    );

typedef NTSTATUS
(NTAPI LSA_CRACK_SINGLE_NAME)(
    IN ULONG FormatOffered,
    IN BOOLEAN PerformAtGC,
    IN PUNICODE_STRING NameInput,
    IN PUNICODE_STRING Prefix OPTIONAL,
    IN ULONG RequestedFormat,
    OUT PUNICODE_STRING CrackedName,
    OUT PUNICODE_STRING DnsDomainName,
    OUT PULONG SubStatus
    );

typedef NTSTATUS
(NTAPI LSA_AUDIT_ACCOUNT_LOGON)(
    IN ULONG AuditId,
    IN BOOLEAN Success,
    IN PUNICODE_STRING Source,
    IN PUNICODE_STRING ClientName,
    IN PUNICODE_STRING MappedName,
    IN NTSTATUS Status
    );


typedef NTSTATUS
(NTAPI LSA_CLIENT_CALLBACK)(
    __in  PCHAR      Callback,
    __in  ULONG_PTR  Argument1,
    __in  ULONG_PTR  Argument2,
    __in  PSecBuffer Input,
    __out PSecBuffer Output
    );

typedef
NTSTATUS
(NTAPI LSA_REGISTER_CALLBACK)(
    ULONG   CallbackId,
    PLSA_CALLBACK_FUNCTION Callback
    );

#define NOTIFIER_FLAG_NEW_THREAD    0x00000001
#define NOTIFIER_FLAG_ONE_SHOT      0x00000002
#define NOTIFIER_FLAG_SECONDS       0x80000000

#define NOTIFIER_TYPE_INTERVAL      1
#define NOTIFIER_TYPE_HANDLE_WAIT   2
#define NOTIFIER_TYPE_STATE_CHANGE  3
#define NOTIFIER_TYPE_NOTIFY_EVENT  4
#define NOTIFIER_TYPE_IMMEDIATE 16

#define NOTIFY_CLASS_PACKAGE_CHANGE     1
#define NOTIFY_CLASS_ROLE_CHANGE        2
#define NOTIFY_CLASS_DOMAIN_CHANGE      3
#define NOTIFY_CLASS_REGISTRY_CHANGE    4

typedef struct _SECPKG_EVENT_PACKAGE_CHANGE {
    ULONG   ChangeType;
    LSA_SEC_HANDLE  PackageId;
    SECURITY_STRING PackageName;
} SECPKG_EVENT_PACKAGE_CHANGE, * PSECPKG_EVENT_PACKAGE_CHANGE;

#define SECPKG_PACKAGE_CHANGE_LOAD      0
#define SECPKG_PACKAGE_CHANGE_UNLOAD    1
#define SECPKG_PACKAGE_CHANGE_SELECT    2

typedef struct _SECPKG_EVENT_ROLE_CHANGE {
    ULONG   PreviousRole;
    ULONG   NewRole;
} SECPKG_EVENT_ROLE_CHANGE, * PSECPKG_EVENT_ROLE_CHANGE;

typedef struct _SECPKG_PARAMETERS SECPKG_EVENT_DOMAIN_CHANGE;
typedef struct _SECPKG_PARAMETERS * PSECPKG_EVENT_DOMAIN_CHANGE;


typedef struct _SECPKG_EVENT_NOTIFY {
    ULONG EventClass;
    ULONG Reserved;
    ULONG EventDataSize;
    PVOID EventData;
    PVOID PackageParameter;
} SECPKG_EVENT_NOTIFY, *PSECPKG_EVENT_NOTIFY;


typedef
NTSTATUS
(NTAPI LSA_UPDATE_PRIMARY_CREDENTIALS)(
    IN PSECPKG_PRIMARY_CRED PrimaryCredentials,
    IN OPTIONAL PSECPKG_SUPPLEMENTAL_CRED_ARRAY Credentials
    );

typedef
VOID
(NTAPI LSA_PROTECT_MEMORY)(
    IN PVOID Buffer,
    IN ULONG BufferSize
    );

typedef
NTSTATUS
(NTAPI LSA_OPEN_TOKEN_BY_LOGON_ID)(
    IN PLUID LogonId,
    OUT HANDLE *RetTokenHandle
    );

typedef
NTSTATUS
(NTAPI LSA_EXPAND_AUTH_DATA_FOR_DOMAIN)(
    IN PUCHAR UserAuthData,
    IN ULONG UserAuthDataSize,
    IN PVOID Reserved,
    OUT PUCHAR * ExpandedAuthData,
    OUT PULONG ExpandedAuthDataSize
    );

typedef LSA_IMPERSONATE_CLIENT * PLSA_IMPERSONATE_CLIENT;
typedef LSA_UNLOAD_PACKAGE * PLSA_UNLOAD_PACKAGE;
typedef LSA_DUPLICATE_HANDLE * PLSA_DUPLICATE_HANDLE;
typedef LSA_SAVE_SUPPLEMENTAL_CREDENTIALS * PLSA_SAVE_SUPPLEMENTAL_CREDENTIALS;
typedef LSA_CREATE_THREAD * PLSA_CREATE_THREAD;
typedef LSA_GET_CLIENT_INFO * PLSA_GET_CLIENT_INFO;
typedef LSA_REGISTER_NOTIFICATION * PLSA_REGISTER_NOTIFICATION;
typedef LSA_CANCEL_NOTIFICATION * PLSA_CANCEL_NOTIFICATION;
typedef LSA_MAP_BUFFER * PLSA_MAP_BUFFER;
typedef LSA_CREATE_TOKEN * PLSA_CREATE_TOKEN;
typedef LSA_AUDIT_LOGON * PLSA_AUDIT_LOGON;
typedef LSA_CALL_PACKAGE * PLSA_CALL_PACKAGE;
typedef LSA_CALL_PACKAGEEX * PLSA_CALL_PACKAGEEX;
typedef LSA_GET_CALL_INFO * PLSA_GET_CALL_INFO;
typedef LSA_CREATE_SHARED_MEMORY * PLSA_CREATE_SHARED_MEMORY;
typedef LSA_ALLOCATE_SHARED_MEMORY * PLSA_ALLOCATE_SHARED_MEMORY;
typedef LSA_FREE_SHARED_MEMORY * PLSA_FREE_SHARED_MEMORY;
typedef LSA_DELETE_SHARED_MEMORY * PLSA_DELETE_SHARED_MEMORY;
typedef LSA_OPEN_SAM_USER * PLSA_OPEN_SAM_USER;
typedef LSA_GET_USER_CREDENTIALS * PLSA_GET_USER_CREDENTIALS;
typedef LSA_GET_USER_AUTH_DATA * PLSA_GET_USER_AUTH_DATA;
typedef LSA_CLOSE_SAM_USER * PLSA_CLOSE_SAM_USER;
typedef LSA_CONVERT_AUTH_DATA_TO_TOKEN * PLSA_CONVERT_AUTH_DATA_TO_TOKEN;
typedef LSA_CLIENT_CALLBACK * PLSA_CLIENT_CALLBACK;
typedef LSA_REGISTER_CALLBACK * PLSA_REGISTER_CALLBACK;
typedef LSA_UPDATE_PRIMARY_CREDENTIALS * PLSA_UPDATE_PRIMARY_CREDENTIALS;
typedef LSA_GET_AUTH_DATA_FOR_USER * PLSA_GET_AUTH_DATA_FOR_USER;
typedef LSA_CRACK_SINGLE_NAME * PLSA_CRACK_SINGLE_NAME;
typedef LSA_AUDIT_ACCOUNT_LOGON * PLSA_AUDIT_ACCOUNT_LOGON;
typedef LSA_CALL_PACKAGE_PASSTHROUGH * PLSA_CALL_PACKAGE_PASSTHROUGH;
typedef LSA_PROTECT_MEMORY * PLSA_PROTECT_MEMORY;
typedef LSA_OPEN_TOKEN_BY_LOGON_ID * PLSA_OPEN_TOKEN_BY_LOGON_ID;
typedef LSA_EXPAND_AUTH_DATA_FOR_DOMAIN * PLSA_EXPAND_AUTH_DATA_FOR_DOMAIN;
typedef LSA_CREATE_TOKEN_EX * PLSA_CREATE_TOKEN_EX;

#ifdef _WINCRED_H_

//
// When passing a credential around, the CredentialBlob field is encrypted.
// This structure describes this encrypted form.
//
//
#ifndef _ENCRYPTED_CREDENTIAL_DEFINED
#define _ENCRYPTED_CREDENTIAL_DEFINED

typedef struct _ENCRYPTED_CREDENTIALW {

    //
    // The credential
    //
    // The CredentialBlob field points to the encrypted credential
    // The CredentialBlobSize field is the length (in bytes) of the encrypted credential
    //

    CREDENTIALW Cred;

    //
    // The size in bytes of the clear text credential blob
    //

    ULONG ClearCredentialBlobSize;
} ENCRYPTED_CREDENTIALW, *PENCRYPTED_CREDENTIALW;
#endif // _ENCRYPTED_CREDENTIAL_DEFINED

//
// Values for CredFlags parameter
//

#define CREDP_FLAGS_IN_PROCESS      0x01    // Caller is in-process. Password data may be returned
#define CREDP_FLAGS_USE_MIDL_HEAP   0x02    // Allocated buffer should use MIDL_user_allocte
#define CREDP_FLAGS_DONT_CACHE_TI   0x04    // TargetInformation shouldn't be cached for CredGetTargetInfo
#define CREDP_FLAGS_CLEAR_PASSWORD  0x08    // Credential blob is passed in in-the-clear
#define CREDP_FLAGS_USER_ENCRYPTED_PASSWORD 0x10    // Credential blob is passed protected by RtlEncryptMemory
#define CREDP_FLAGS_TRUSTED_CALLER 0x20     // Caller is a trusted process (eg. logon process).

//
// Possible forms of the username returned from CredMan
//

typedef enum _CredParsedUserNameType
{
    parsedUsernameInvalid = 0,
    parsedUsernameUpn,
    parsedUsernameNt4Style,
    parsedUsernameCertificate,
    parsedUsernameNonQualified
} CredParsedUserNameType;


typedef NTSTATUS
(NTAPI CredReadFn) (
    IN PLUID LogonId,
    IN ULONG CredFlags,
    IN LPWSTR TargetName,
    IN ULONG Type,
    IN ULONG Flags,
    OUT PENCRYPTED_CREDENTIALW *Credential
    );

typedef NTSTATUS
(NTAPI CredReadDomainCredentialsFn) (
    IN PLUID LogonId,
    IN ULONG CredFlags,
    IN PCREDENTIAL_TARGET_INFORMATIONW TargetInfo,
    IN ULONG Flags,
    OUT PULONG Count,
    OUT PENCRYPTED_CREDENTIALW **Credential
    );

typedef VOID
(NTAPI CredFreeCredentialsFn) (
    IN ULONG Count,
    IN PENCRYPTED_CREDENTIALW *Credentials OPTIONAL
    );

typedef NTSTATUS
(NTAPI CredWriteFn) (
    IN PLUID LogonId,
    IN ULONG CredFlags,
    IN PENCRYPTED_CREDENTIALW Credential,
    IN ULONG Flags
    );

typedef NTSTATUS
(NTAPI CrediUnmarshalandDecodeStringFn)(
    IN  LPWSTR  MarshaledString,
    OUT LPBYTE  *Blob,
    OUT ULONG *BlobSize,
    OUT BOOLEAN *IsFailureFatal
    );


NTSTATUS
CredMarshalTargetInfo (
    __in        PCREDENTIAL_TARGET_INFORMATIONW InTargetInfo,
    __deref_out PUSHORT *Buffer,
    __out       PULONG   BufferSize
    );

NTSTATUS
CredUnmarshalTargetInfo (
    __in_bcount(BufferSize) PUSHORT            Buffer,
    __in      ULONG                            BufferSize,
    __out_opt PCREDENTIAL_TARGET_INFORMATIONW *RetTargetInfo,
    __out_opt PULONG                           RetActualSize
    );

// Number of bytes consumed by the trailing size ULONG
#define CRED_MARSHALED_TI_SIZE_SIZE 12

NTSTATUS
CredParseUserNameWithType (
    __inout LPWSTR                  szParseName,
    __out_opt PUNICODE_STRING       pUserName,
    __out_opt PUNICODE_STRING       pDomainName,
    __out CredParsedUserNameType *  pParseType
    );

#endif // _WINCRED_H_


//
// Pure 32-bit versions of credential structures for packages
// running wow64:
//

typedef struct _SEC_WINNT_AUTH_IDENTITY32 {
    ULONG User;
    ULONG UserLength;
    ULONG Domain;
    ULONG DomainLength;
    ULONG Password;
    ULONG PasswordLength;
    ULONG Flags;
} SEC_WINNT_AUTH_IDENTITY32, * PSEC_WINNT_AUTH_IDENTITY32;

typedef struct _SEC_WINNT_AUTH_IDENTITY_EX32 {
    ULONG Version;
    ULONG Length;
    ULONG User;
    ULONG UserLength;
    ULONG Domain;
    ULONG DomainLength;
    ULONG Password;
    ULONG PasswordLength;
    ULONG Flags;
    ULONG PackageList;
    ULONG PackageListLength;
} SEC_WINNT_AUTH_IDENTITY_EX32, * PSEC_WINNT_AUTH_IDENTITY_EX32;

// Functions provided by the SPM to the packages:
typedef struct _LSA_SECPKG_FUNCTION_TABLE {
    PLSA_CREATE_LOGON_SESSION CreateLogonSession;
    PLSA_DELETE_LOGON_SESSION DeleteLogonSession;
    PLSA_ADD_CREDENTIAL AddCredential;
    PLSA_GET_CREDENTIALS GetCredentials;
    PLSA_DELETE_CREDENTIAL DeleteCredential;
    PLSA_ALLOCATE_LSA_HEAP AllocateLsaHeap;
    PLSA_FREE_LSA_HEAP FreeLsaHeap;
    PLSA_ALLOCATE_CLIENT_BUFFER AllocateClientBuffer;
    PLSA_FREE_CLIENT_BUFFER FreeClientBuffer;
    PLSA_COPY_TO_CLIENT_BUFFER CopyToClientBuffer;
    PLSA_COPY_FROM_CLIENT_BUFFER CopyFromClientBuffer;
    PLSA_IMPERSONATE_CLIENT ImpersonateClient;
    PLSA_UNLOAD_PACKAGE UnloadPackage;
    PLSA_DUPLICATE_HANDLE DuplicateHandle;
    PLSA_SAVE_SUPPLEMENTAL_CREDENTIALS SaveSupplementalCredentials;
    PLSA_CREATE_THREAD CreateThread;
    PLSA_GET_CLIENT_INFO GetClientInfo;
    PLSA_REGISTER_NOTIFICATION RegisterNotification;
    PLSA_CANCEL_NOTIFICATION CancelNotification;
    PLSA_MAP_BUFFER MapBuffer;
    PLSA_CREATE_TOKEN CreateToken;
    PLSA_AUDIT_LOGON AuditLogon;
    PLSA_CALL_PACKAGE CallPackage;
    PLSA_FREE_LSA_HEAP FreeReturnBuffer;
    PLSA_GET_CALL_INFO GetCallInfo;
    PLSA_CALL_PACKAGEEX CallPackageEx;
    PLSA_CREATE_SHARED_MEMORY CreateSharedMemory;
    PLSA_ALLOCATE_SHARED_MEMORY AllocateSharedMemory;
    PLSA_FREE_SHARED_MEMORY FreeSharedMemory;
    PLSA_DELETE_SHARED_MEMORY DeleteSharedMemory;
    PLSA_OPEN_SAM_USER OpenSamUser;
    PLSA_GET_USER_CREDENTIALS GetUserCredentials;
    PLSA_GET_USER_AUTH_DATA GetUserAuthData;
    PLSA_CLOSE_SAM_USER CloseSamUser;
    PLSA_CONVERT_AUTH_DATA_TO_TOKEN ConvertAuthDataToToken;
    PLSA_CLIENT_CALLBACK ClientCallback;
    PLSA_UPDATE_PRIMARY_CREDENTIALS UpdateCredentials;
    PLSA_GET_AUTH_DATA_FOR_USER GetAuthDataForUser;
    PLSA_CRACK_SINGLE_NAME CrackSingleName;
    PLSA_AUDIT_ACCOUNT_LOGON AuditAccountLogon;
    PLSA_CALL_PACKAGE_PASSTHROUGH CallPackagePassthrough;
#ifdef _WINCRED_H_
    CredReadFn *CrediRead;
    CredReadDomainCredentialsFn *CrediReadDomainCredentials;
    CredFreeCredentialsFn *CrediFreeCredentials;
#else // _WINCRED_H_
    PLSA_PROTECT_MEMORY DummyFunction1;
    PLSA_PROTECT_MEMORY DummyFunction2;
    PLSA_PROTECT_MEMORY DummyFunction3;
#endif // _WINCRED_H_
    PLSA_PROTECT_MEMORY LsaProtectMemory;
    PLSA_PROTECT_MEMORY LsaUnprotectMemory;
    PLSA_OPEN_TOKEN_BY_LOGON_ID OpenTokenByLogonId;
    PLSA_EXPAND_AUTH_DATA_FOR_DOMAIN ExpandAuthDataForDomain;
    PLSA_ALLOCATE_PRIVATE_HEAP AllocatePrivateHeap;
    PLSA_FREE_PRIVATE_HEAP FreePrivateHeap;
    PLSA_CREATE_TOKEN_EX CreateTokenEx;
#ifdef _WINCRED_H_
    CredWriteFn *CrediWrite;
    CrediUnmarshalandDecodeStringFn *CrediUnmarshalandDecodeString;
#else // _WINCRED_H_
    PLSA_PROTECT_MEMORY DummyFunction4;
    PLSA_PROTECT_MEMORY DummyFunction5;
#endif // _WINCRED_H_
} LSA_SECPKG_FUNCTION_TABLE, *PLSA_SECPKG_FUNCTION_TABLE;


typedef
PVOID
(NTAPI LSA_LOCATE_PKG_BY_ID)(
    __in ULONG PackgeId
    );

typedef LSA_LOCATE_PKG_BY_ID * PLSA_LOCATE_PKG_BY_ID;

typedef struct _SECPKG_DLL_FUNCTIONS {
    PLSA_ALLOCATE_LSA_HEAP AllocateHeap;
    PLSA_FREE_LSA_HEAP FreeHeap;
    PLSA_REGISTER_CALLBACK RegisterCallback;
    PLSA_LOCATE_PKG_BY_ID LocatePackageById;
} SECPKG_DLL_FUNCTIONS, * PSECPKG_DLL_FUNCTIONS;


//
// The following prototypes are to functions that will be called only while
// in the Security Package Manager context.
//

typedef NTSTATUS
(NTAPI SpInitializeFn)(
    IN ULONG_PTR PackageId,
    IN PSECPKG_PARAMETERS Parameters,
    IN PLSA_SECPKG_FUNCTION_TABLE FunctionTable
    );

typedef NTSTATUS
(NTAPI SpShutdownFn)(
    VOID
    );

typedef NTSTATUS
(NTAPI SpGetInfoFn)(
    OUT PSecPkgInfo PackageInfo
    );

typedef NTSTATUS
(NTAPI SpGetExtendedInformationFn)(
    IN  SECPKG_EXTENDED_INFORMATION_CLASS Class,
    OUT PSECPKG_EXTENDED_INFORMATION * ppInformation
    );

typedef NTSTATUS
(NTAPI SpSetExtendedInformationFn)(
    IN SECPKG_EXTENDED_INFORMATION_CLASS Class,
    IN PSECPKG_EXTENDED_INFORMATION Info
    );

typedef NTSTATUS
(LSA_AP_LOGON_USER_EX2) (
    __in PLSA_CLIENT_REQUEST ClientRequest,
    __in SECURITY_LOGON_TYPE LogonType,
    __in_bcount(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
    __in PVOID ClientBufferBase,
    __in ULONG SubmitBufferSize,
    __deref_out_bcount(*ProfileBufferSize) PVOID *ProfileBuffer,
    __out PULONG ProfileBufferSize,
    __out PLUID LogonId,
    __out PNTSTATUS SubStatus,
    __out PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    __deref_out PVOID *TokenInformation,
    __out PUNICODE_STRING *AccountName,
    __out PUNICODE_STRING *AuthenticatingAuthority,
    __out PUNICODE_STRING *MachineName,
    __out PSECPKG_PRIMARY_CRED PrimaryCredentials,
    __deref_out PSECPKG_SUPPLEMENTAL_CRED_ARRAY * SupplementalCredentials
    );

typedef LSA_AP_LOGON_USER_EX2 *PLSA_AP_LOGON_USER_EX2;
#define LSA_AP_NAME_LOGON_USER_EX2 "LsaApLogonUserEx2\0"

typedef NTSTATUS
(NTAPI SpAcceptCredentialsFn)(
    IN SECURITY_LOGON_TYPE LogonType,
    IN PUNICODE_STRING AccountName,
    IN PSECPKG_PRIMARY_CRED PrimaryCredentials,
    IN PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials
    );
#define SP_ACCEPT_CREDENTIALS_NAME "SpAcceptCredentials\0"

typedef NTSTATUS
(NTAPI SpAcquireCredentialsHandleFn)(
    IN OPTIONAL PUNICODE_STRING PrincipalName,
    IN ULONG CredentialUseFlags,
    IN OPTIONAL PLUID LogonId,
    IN PVOID AuthorizationData,
    IN PVOID GetKeyFunciton,
    IN PVOID GetKeyArgument,
    OUT PLSA_SEC_HANDLE CredentialHandle,
    OUT PTimeStamp ExpirationTime
    );

typedef NTSTATUS
(NTAPI SpFreeCredentialsHandleFn)(
    IN LSA_SEC_HANDLE CredentialHandle
    );

typedef NTSTATUS
(NTAPI SpQueryCredentialsAttributesFn)(
    IN LSA_SEC_HANDLE CredentialHandle,
    IN ULONG CredentialAttribute,
    IN OUT PVOID Buffer
    );

typedef NTSTATUS
(NTAPI SpSetCredentialsAttributesFn)(
    IN LSA_SEC_HANDLE CredentialHandle,
    IN ULONG CredentialAttribute,
    IN PVOID Buffer,
    IN ULONG BufferSize );

typedef NTSTATUS
(NTAPI SpAddCredentialsFn)(
    IN LSA_SEC_HANDLE CredentialHandle,
    IN OPTIONAL PUNICODE_STRING PrincipalName,
    IN PUNICODE_STRING Package,
    IN ULONG CredentialUseFlags,
    IN PVOID AuthorizationData,
    IN PVOID GetKeyFunciton,
    IN PVOID GetKeyArgument,
    OUT PTimeStamp ExpirationTime
    );

typedef NTSTATUS
(NTAPI SpSaveCredentialsFn)(
    IN LSA_SEC_HANDLE CredentialHandle,
    IN PSecBuffer Credentials);

typedef NTSTATUS
(NTAPI SpGetCredentialsFn)(
    IN LSA_SEC_HANDLE CredentialHandle,
    IN OUT PSecBuffer Credentials
    );

typedef NTSTATUS
(NTAPI SpDeleteCredentialsFn)(
    IN LSA_SEC_HANDLE CredentialHandle,
    IN PSecBuffer Key
    );

typedef NTSTATUS
(NTAPI SpInitLsaModeContextFn)(
    IN OPTIONAL LSA_SEC_HANDLE CredentialHandle,
    IN OPTIONAL LSA_SEC_HANDLE ContextHandle,
    IN OPTIONAL PUNICODE_STRING TargetName,
    IN ULONG ContextRequirements,
    IN ULONG TargetDataRep,
    IN PSecBufferDesc InputBuffers,
    OUT PLSA_SEC_HANDLE NewContextHandle,
    IN OUT PSecBufferDesc OutputBuffers,
    OUT PULONG ContextAttributes,
    OUT PTimeStamp ExpirationTime,
    OUT PBOOLEAN MappedContext,
    OUT PSecBuffer ContextData
    );




typedef NTSTATUS
(NTAPI SpDeleteContextFn)(
    IN LSA_SEC_HANDLE ContextHandle
    );

typedef NTSTATUS
(NTAPI SpApplyControlTokenFn)(
    IN LSA_SEC_HANDLE ContextHandle,
    IN PSecBufferDesc ControlToken);


typedef NTSTATUS
(NTAPI SpAcceptLsaModeContextFn)(
    IN OPTIONAL LSA_SEC_HANDLE CredentialHandle,
    IN OPTIONAL LSA_SEC_HANDLE ContextHandle,
    IN PSecBufferDesc InputBuffer,
    IN ULONG ContextRequirements,
    IN ULONG TargetDataRep,
    OUT PLSA_SEC_HANDLE NewContextHandle,
    OUT PSecBufferDesc OutputBuffer,
    OUT PULONG ContextAttributes,
    OUT PTimeStamp ExpirationTime,
    OUT PBOOLEAN MappedContext,
    OUT PSecBuffer ContextData
    );




typedef NTSTATUS
(NTAPI SpGetUserInfoFn)(
    IN PLUID LogonId,
    IN ULONG Flags,
    OUT PSecurityUserData * UserData
    );

typedef NTSTATUS
(NTAPI SpQueryContextAttributesFn)(
    IN LSA_SEC_HANDLE ContextHandle,
    IN ULONG ContextAttribute,
    IN OUT PVOID Buffer);

typedef NTSTATUS
(NTAPI SpSetContextAttributesFn)(
    IN LSA_SEC_HANDLE ContextHandle,
    IN ULONG ContextAttribute,
    IN PVOID Buffer,
    IN ULONG BufferSize );

typedef NTSTATUS
(NTAPI SpChangeAccountPasswordFn)(
    __in PUNICODE_STRING      pDomainName,
    __in PUNICODE_STRING      pAccountName,
    __in PUNICODE_STRING      pOldPassword,
    __in PUNICODE_STRING      pNewPassword,
    __in BOOLEAN              Impersonating,
    __inout PSecBufferDesc   pOutput
    );

typedef NTSTATUS
(NTAPI SpQueryMetaDataFn)(
    __in_opt LSA_SEC_HANDLE CredentialHandle,
    __in_opt PUNICODE_STRING TargetName,
    __in ULONG ContextRequirements,
    __out PULONG MetaDataLength,
    __deref_out_bcount(*MetaDataLength) PUCHAR* MetaData,
    __inout PLSA_SEC_HANDLE ContextHandle
    );

typedef NTSTATUS
(NTAPI SpExchangeMetaDataFn)(
    __in_opt LSA_SEC_HANDLE CredentialHandle,
    __in_opt PUNICODE_STRING TargetName,
    __in ULONG ContextRequirements,
    __in ULONG MetaDataLength,
    __in_bcount(MetaDataLength) PUCHAR MetaData,
    __inout PLSA_SEC_HANDLE ContextHandle
    );

typedef NTSTATUS
(NTAPI SpGetCredUIContextFn)(
   __in LSA_SEC_HANDLE ContextHandle,
   __in GUID* CredType,
   __out PULONG FlatCredUIContextLength,
   __deref_out_bcount(*FlatCredUIContextLength)  PUCHAR* FlatCredUIContext
   );

typedef NTSTATUS
(NTAPI SpUpdateCredentialsFn)(
  __in LSA_SEC_HANDLE ContextHandle,
  __in GUID* CredType,
  __in ULONG FlatCredUIContextLength,
  __in_bcount(FlatCredUIContextLength) PUCHAR FlatCredUIContext
  );

typedef NTSTATUS
(NTAPI SpValidateTargetInfoFn) (
    __in_opt PLSA_CLIENT_REQUEST ClientRequest,
    __in_bcount(SubmitBufferLength) PVOID ProtocolSubmitBuffer,
    __in PVOID ClientBufferBase,
    __in ULONG SubmitBufferLength,
    __in PSECPKG_TARGETINFO TargetInfo
    );

typedef struct _SECPKG_FUNCTION_TABLE {
    PLSA_AP_INITIALIZE_PACKAGE InitializePackage;
    PLSA_AP_LOGON_USER LogonUser;
    PLSA_AP_CALL_PACKAGE CallPackage;
    PLSA_AP_LOGON_TERMINATED LogonTerminated;
    PLSA_AP_CALL_PACKAGE_UNTRUSTED CallPackageUntrusted;
    PLSA_AP_CALL_PACKAGE_PASSTHROUGH CallPackagePassthrough;
    PLSA_AP_LOGON_USER_EX LogonUserEx;
    PLSA_AP_LOGON_USER_EX2 LogonUserEx2;
    SpInitializeFn * Initialize;
    SpShutdownFn * Shutdown;
    SpGetInfoFn * GetInfo;
    SpAcceptCredentialsFn * AcceptCredentials;
    SpAcquireCredentialsHandleFn * AcquireCredentialsHandle;
    SpQueryCredentialsAttributesFn * QueryCredentialsAttributes;
    SpFreeCredentialsHandleFn * FreeCredentialsHandle;
    SpSaveCredentialsFn * SaveCredentials;
    SpGetCredentialsFn * GetCredentials;
    SpDeleteCredentialsFn * DeleteCredentials;
    SpInitLsaModeContextFn * InitLsaModeContext;
    SpAcceptLsaModeContextFn * AcceptLsaModeContext;
    SpDeleteContextFn * DeleteContext;
    SpApplyControlTokenFn * ApplyControlToken;
    SpGetUserInfoFn * GetUserInfo;
    SpGetExtendedInformationFn * GetExtendedInformation;
    SpQueryContextAttributesFn * QueryContextAttributes;
    SpAddCredentialsFn * AddCredentials;
    SpSetExtendedInformationFn * SetExtendedInformation;
    SpSetContextAttributesFn * SetContextAttributes;
    SpSetCredentialsAttributesFn * SetCredentialsAttributes;
    SpChangeAccountPasswordFn * ChangeAccountPassword;
    SpQueryMetaDataFn* QueryMetaData;
    SpExchangeMetaDataFn* ExchangeMetaData;
    SpGetCredUIContextFn* GetCredUIContext;
    SpUpdateCredentialsFn* UpdateCredentials;
    SpValidateTargetInfoFn* ValidateTargetInfo;
} SECPKG_FUNCTION_TABLE, *PSECPKG_FUNCTION_TABLE;

//
// The following prototypes are to functions that will be called while in the
// context of a user process that is using the functions through the security
// DLL.
//
typedef NTSTATUS
(NTAPI SpInstanceInitFn)(
    IN ULONG Version,
    IN PSECPKG_DLL_FUNCTIONS FunctionTable,
    OUT PVOID * UserFunctions
    );

typedef NTSTATUS
(NTAPI SpInitUserModeContextFn)(
    IN LSA_SEC_HANDLE ContextHandle,
    IN PSecBuffer PackedContext
    );

typedef NTSTATUS
(NTAPI SpMakeSignatureFn)(
    IN LSA_SEC_HANDLE ContextHandle,
    IN ULONG QualityOfProtection,
    IN PSecBufferDesc MessageBuffers,
    IN ULONG MessageSequenceNumber
    );

typedef NTSTATUS
(NTAPI SpVerifySignatureFn)(
    IN LSA_SEC_HANDLE ContextHandle,
    IN PSecBufferDesc MessageBuffers,
    IN ULONG MessageSequenceNumber,
    OUT PULONG QualityOfProtection
    );

typedef NTSTATUS
(NTAPI SpSealMessageFn)(
    IN LSA_SEC_HANDLE ContextHandle,
    IN ULONG QualityOfProtection,
    IN PSecBufferDesc MessageBuffers,
    IN ULONG MessageSequenceNumber
    );

typedef NTSTATUS
(NTAPI SpUnsealMessageFn)(
    IN LSA_SEC_HANDLE ContextHandle,
    IN PSecBufferDesc MessageBuffers,
    IN ULONG MessageSequenceNumber,
    OUT PULONG QualityOfProtection
    );


typedef NTSTATUS
(NTAPI SpGetContextTokenFn)(
    IN LSA_SEC_HANDLE ContextHandle,
    OUT PHANDLE ImpersonationToken
    );


typedef NTSTATUS
(NTAPI SpExportSecurityContextFn)(
    LSA_SEC_HANDLE             phContext,             // (in) context to export
    ULONG                fFlags,                // (in) option flags
    PSecBuffer           pPackedContext,        // (out) marshalled context
    PHANDLE              pToken                 // (out, optional) token handle for impersonation
    );

typedef NTSTATUS
(NTAPI SpImportSecurityContextFn)(
    PSecBuffer           pPackedContext,        // (in) marshalled context
    HANDLE               Token,                 // (in, optional) handle to token for context
    PLSA_SEC_HANDLE            phContext              // (out) new context handle
    );


typedef NTSTATUS
(NTAPI SpCompleteAuthTokenFn)(
    IN LSA_SEC_HANDLE ContextHandle,
    IN PSecBufferDesc InputBuffer
    );


typedef NTSTATUS
(NTAPI SpFormatCredentialsFn)(
    IN PSecBuffer Credentials,
    OUT PSecBuffer FormattedCredentials
    );

typedef NTSTATUS
(NTAPI SpMarshallSupplementalCredsFn)(
    IN ULONG CredentialSize,
    IN PUCHAR Credentials,
    OUT PULONG MarshalledCredSize,
    OUT PVOID * MarshalledCreds);

typedef struct _SECPKG_USER_FUNCTION_TABLE {
    SpInstanceInitFn *                      InstanceInit;
    SpInitUserModeContextFn *               InitUserModeContext;
    SpMakeSignatureFn *                     MakeSignature;
    SpVerifySignatureFn *                   VerifySignature;
    SpSealMessageFn *                       SealMessage;
    SpUnsealMessageFn *                     UnsealMessage;
    SpGetContextTokenFn *                   GetContextToken;
    SpQueryContextAttributesFn *            QueryContextAttributes;
    SpCompleteAuthTokenFn *                 CompleteAuthToken;
    SpDeleteContextFn *                     DeleteUserModeContext;
    SpFormatCredentialsFn *                 FormatCredentials;
    SpMarshallSupplementalCredsFn *         MarshallSupplementalCreds;
    SpExportSecurityContextFn *             ExportContext;
    SpImportSecurityContextFn *             ImportContext;
} SECPKG_USER_FUNCTION_TABLE, *PSECPKG_USER_FUNCTION_TABLE;


typedef NTSTATUS
(SEC_ENTRY * SpLsaModeInitializeFn)(
    IN ULONG LsaVersion,
    OUT PULONG PackageVersion,
    OUT PSECPKG_FUNCTION_TABLE * ppTables,
    OUT PULONG pcTables);

typedef NTSTATUS
(SEC_ENTRY * SpUserModeInitializeFn)(
    IN ULONG LsaVersion,
    OUT PULONG PackageVersion,
    OUT PSECPKG_USER_FUNCTION_TABLE *ppTables,
    OUT PULONG pcTables
    );

#define SECPKG_LSAMODEINIT_NAME     "SpLsaModeInitialize"
#define SECPKG_USERMODEINIT_NAME    "SpUserModeInitialize"

//
// Version of the security package interface.
//
// These defines are used for all of the following:
//
// * Passed by the LSA to SpLsaModeInitializeFn to indicate the version of the LSA.
//      All packages currently expect the LSA to pass SECPKG_INTERFACE_VERSION.
//
// * Passed by secur32.dll to SpUserModeInitialzeFn to indicate the version of the secur32 DLL.
//      All packages currently expect secur32 to pass SECPKG_INTERFACE_VERSION.
//
// * Returned from SpLsaModeInitializeFn to indicate the version of SECPKG_FUNCTION_TABLE.
//      SECPKG_INTERFACE_VERSION indicates all fields through SetExtendedInformation are defined (potentially to NULL)
//      SECPKG_INTERFACE_VERSION_2 indicates all fields through SetContextAttributes are defined (potentially to NULL)
//      SECPKG_INTERFACE_VERSION_3 indicates all fields through SetCredentialsAttributes are defined (potentially to NULL)
//      SECPKG_INTERFACE_VERSION_4 indicates all fields through ChangeAccountPassword are defined (potentially to NULL)
//      SECPKG_INTERFACE_VERSION_5 indicates all fields through UpdateCredentials are defined (potentially to NULL)
//      SECPKG_INTERFACE_VERSION_6 indicates all fields through ValidateTargetInfo are defined (potentially to NULL)
//
// * Returned from SpUserModeInitializeFn to indicate the version of the auth package.
//      All packages currently return SECPKG_INTERFACE_VERSION
//

#define SECPKG_INTERFACE_VERSION    0x00010000
#define SECPKG_INTERFACE_VERSION_2  0x00020000
#define SECPKG_INTERFACE_VERSION_3  0x00040000
#define SECPKG_INTERFACE_VERSION_4  0x00080000
#define SECPKG_INTERFACE_VERSION_5  0x00100000
#define SECPKG_INTERFACE_VERSION_6  0x00200000

typedef enum _KSEC_CONTEXT_TYPE {
    KSecPaged,
    KSecNonPaged
} KSEC_CONTEXT_TYPE;

typedef struct _KSEC_LIST_ENTRY {
    LIST_ENTRY List;
    LONG RefCount;
    ULONG Signature;
    PVOID OwningList;
    PVOID Reserved;
} KSEC_LIST_ENTRY, * PKSEC_LIST_ENTRY;

#define KsecInitializeListEntry( Entry, SigValue ) \
    ((PKSEC_LIST_ENTRY) Entry)->List.Flink = ((PKSEC_LIST_ENTRY) Entry)->List.Blink = NULL; \
    ((PKSEC_LIST_ENTRY) Entry)->RefCount = 1; \
    ((PKSEC_LIST_ENTRY) Entry)->Signature = SigValue; \
    ((PKSEC_LIST_ENTRY) Entry)->OwningList = NULL; \
    ((PKSEC_LIST_ENTRY) Entry)->Reserved = NULL;



typedef PVOID
(SEC_ENTRY KSEC_CREATE_CONTEXT_LIST)(
    IN KSEC_CONTEXT_TYPE Type
    );

typedef VOID
(SEC_ENTRY KSEC_INSERT_LIST_ENTRY)(
    IN PVOID List,
    IN PKSEC_LIST_ENTRY Entry
    );

typedef NTSTATUS
(SEC_ENTRY KSEC_REFERENCE_LIST_ENTRY)(
    IN PKSEC_LIST_ENTRY Entry,
    IN ULONG Signature,
    IN BOOLEAN RemoveNoRef
    );

typedef VOID
(SEC_ENTRY KSEC_DEREFERENCE_LIST_ENTRY)(
    IN PKSEC_LIST_ENTRY Entry,
    OUT BOOLEAN * Delete OPTIONAL
    );

typedef NTSTATUS
(SEC_ENTRY KSEC_SERIALIZE_WINNT_AUTH_DATA)(
    __in PVOID pvAuthData,
    __out PULONG Size,
    __deref_out PVOID * SerializedData );

typedef NTSTATUS
(SEC_ENTRY KSEC_SERIALIZE_SCHANNEL_AUTH_DATA)(
    __in PVOID pvAuthData,
    __out PULONG Size,
    __deref_out PVOID * SerializedData );

#ifndef MIDL_PASS

KSEC_CREATE_CONTEXT_LIST KSecCreateContextList;
KSEC_INSERT_LIST_ENTRY KSecInsertListEntry;
KSEC_REFERENCE_LIST_ENTRY KSecReferenceListEntry;
KSEC_DEREFERENCE_LIST_ENTRY KSecDereferenceListEntry;
KSEC_SERIALIZE_WINNT_AUTH_DATA KSecSerializeWinntAuthData;
KSEC_SERIALIZE_SCHANNEL_AUTH_DATA KSecSerializeSchannelAuthData;

#endif // not valid for MIDL_PASS

typedef KSEC_CREATE_CONTEXT_LIST * PKSEC_CREATE_CONTEXT_LIST;
typedef KSEC_INSERT_LIST_ENTRY * PKSEC_INSERT_LIST_ENTRY;
typedef KSEC_REFERENCE_LIST_ENTRY * PKSEC_REFERENCE_LIST_ENTRY;
typedef KSEC_DEREFERENCE_LIST_ENTRY * PKSEC_DEREFERENCE_LIST_ENTRY;
typedef KSEC_SERIALIZE_WINNT_AUTH_DATA * PKSEC_SERIALIZE_WINNT_AUTH_DATA;
typedef KSEC_SERIALIZE_SCHANNEL_AUTH_DATA * PKSEC_SERIALIZE_SCHANNEL_AUTH_DATA;

typedef PVOID
(SEC_ENTRY KSEC_LOCATE_PKG_BY_ID)(
    __in ULONG PackageId
    );

typedef KSEC_LOCATE_PKG_BY_ID * PKSEC_LOCATE_PKG_BY_ID;

#ifndef MIDL_PASS

KSEC_LOCATE_PKG_BY_ID KSecLocatePackageById;

#endif // not valid for MIDL_PASS

typedef struct _SECPKG_KERNEL_FUNCTIONS {
    PLSA_ALLOCATE_LSA_HEAP AllocateHeap;
    PLSA_FREE_LSA_HEAP FreeHeap;
    PKSEC_CREATE_CONTEXT_LIST CreateContextList;
    PKSEC_INSERT_LIST_ENTRY InsertListEntry;
    PKSEC_REFERENCE_LIST_ENTRY ReferenceListEntry;
    PKSEC_DEREFERENCE_LIST_ENTRY DereferenceListEntry;
    PKSEC_SERIALIZE_WINNT_AUTH_DATA SerializeWinntAuthData;
    PKSEC_SERIALIZE_SCHANNEL_AUTH_DATA SerializeSchannelAuthData;
    PKSEC_LOCATE_PKG_BY_ID LocatePackageById;
} SECPKG_KERNEL_FUNCTIONS, *PSECPKG_KERNEL_FUNCTIONS;

typedef NTSTATUS
(NTAPI KspInitPackageFn)(
    PSECPKG_KERNEL_FUNCTIONS    FunctionTable
    );

typedef NTSTATUS
(NTAPI KspDeleteContextFn)(
    IN LSA_SEC_HANDLE ContextId,
    OUT PLSA_SEC_HANDLE LsaContextId
    );

typedef NTSTATUS
(NTAPI KspInitContextFn)(
    IN LSA_SEC_HANDLE ContextId,
    IN PSecBuffer ContextData,
    OUT PLSA_SEC_HANDLE NewContextId
    );

typedef NTSTATUS
(NTAPI KspMakeSignatureFn)(
    IN LSA_SEC_HANDLE ContextId,
    IN ULONG fQOP,
    IN OUT PSecBufferDesc Message,
    IN ULONG MessageSeqNo
    );

typedef NTSTATUS
(NTAPI KspVerifySignatureFn)(
    IN LSA_SEC_HANDLE ContextId,
    IN OUT PSecBufferDesc Message,
    IN ULONG MessageSeqNo,
    OUT PULONG pfQOP
    );


typedef NTSTATUS
(NTAPI KspSealMessageFn)(
    IN LSA_SEC_HANDLE ContextId,
    IN ULONG fQOP,
    IN OUT PSecBufferDesc Message,
    IN ULONG MessageSeqNo
    );

typedef NTSTATUS
(NTAPI KspUnsealMessageFn)(
    IN LSA_SEC_HANDLE ContextId,
    IN OUT PSecBufferDesc Message,
    IN ULONG MessageSeqNo,
    OUT PULONG pfQOP
    );

typedef NTSTATUS
(NTAPI KspGetTokenFn)(
    IN LSA_SEC_HANDLE ContextId,
    OUT PHANDLE ImpersonationToken,
    OUT OPTIONAL PACCESS_TOKEN * RawToken
    );

typedef NTSTATUS
(NTAPI KspQueryAttributesFn)(
    IN LSA_SEC_HANDLE ContextId,
    IN ULONG Attribute,
    IN OUT PVOID Buffer
    );

typedef NTSTATUS
(NTAPI KspCompleteTokenFn)(
    IN LSA_SEC_HANDLE ContextId,
    IN PSecBufferDesc Token
    );


typedef NTSTATUS
(NTAPI KspMapHandleFn)(
    IN LSA_SEC_HANDLE ContextId,
    OUT PLSA_SEC_HANDLE LsaContextId
    );

typedef NTSTATUS
(NTAPI KspSetPagingModeFn)(
    IN BOOLEAN PagingMode
    );

typedef NTSTATUS
(NTAPI KspSerializeAuthDataFn)(
    IN PVOID pvAuthData,
    OUT PULONG Size,
    OUT PVOID * SerializedData
    );

typedef struct _SECPKG_KERNEL_FUNCTION_TABLE {
    KspInitPackageFn *      Initialize;
    KspDeleteContextFn *    DeleteContext;
    KspInitContextFn *      InitContext;
    KspMapHandleFn *        MapHandle;
    KspMakeSignatureFn *    Sign;
    KspVerifySignatureFn *  Verify;
    KspSealMessageFn *      Seal;
    KspUnsealMessageFn *    Unseal;
    KspGetTokenFn *         GetToken;
    KspQueryAttributesFn *  QueryAttributes;
    KspCompleteTokenFn *    CompleteToken;
    SpExportSecurityContextFn * ExportContext;
    SpImportSecurityContextFn * ImportContext;
    KspSetPagingModeFn *    SetPackagePagingMode;
    KspSerializeAuthDataFn * SerializeAuthData;
} SECPKG_KERNEL_FUNCTION_TABLE, *PSECPKG_KERNEL_FUNCTION_TABLE;

SECURITY_STATUS
SEC_ENTRY
KSecRegisterSecurityProvider(
    __in PSECURITY_STRING    ProviderName,
    __in PSECPKG_KERNEL_FUNCTION_TABLE Table
    );

extern SECPKG_KERNEL_FUNCTIONS KspKernelFunctions;


#ifdef __cplusplus
}
#endif

#endif /* _NTSECPKG_ */


