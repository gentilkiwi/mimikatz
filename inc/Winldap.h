/*++

Copyright (c) 1996-1999  Microsoft Corporation

Module Name:

    winldap.h   LDAP client 32 API header file

Abstract:

   This module is the header file for the 32 bit LDAP client API for
   Windows NT and Windows 95.  This API is based on RFC 1823 with some
   enhancements for LDAP v3.

   Notes about Unicode support :

   If you have UNICODE defined at compile time, you'll pull in the unicode
   versions of the calls.  Note that your executable may then not work with
   other implementations of the LDAP API that don't support Unicode.  If
   UNICODE is not defined, then we define the LDAP calls without the trailing
   'A' (as in ldap_bind rather than ldap_bindA) so that your app may work
   with other implementations that don't support Unicode.

   The import library has all three forms of the call present... ldap_bindW,
   ldap_bindA, and ldap_bind.  ldap_bindA simply calls ldap_bind.  ldap_bind
   simply converts the arguments to unicode and calls ldap_bindW.  The
   reason this is done is because we have to put UTF-8 on the wire, so if
   we converted from Unicode to single byte, we'd loose information.  Since
   all core processing is done in Unicode, nothing is lost.

Updates :

   11/01/96  Modified for new API RFC draft.

Environments :

    Win32 user mode

--*/

//
//  Only pull in this header file once... controlled by LDAP_CLIENT_DEFINED
//  variable.
//

#ifndef LDAP_CLIENT_DEFINED
#define LDAP_CLIENT_DEFINED

#if _MSC_VER > 1000
#pragma once
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef BASETYPES
#include <windef.h>
#endif

#ifndef _SCHNLSP_H_
#include <schnlsp.h>
#endif

#if !defined(_WINLDAP_)
#define WINLDAPAPI DECLSPEC_IMPORT
#else
//#define WINLDAPAPI __declspec(dllexport)
#define WINLDAPAPI
#endif

#ifndef LDAPAPI
#define LDAPAPI __cdecl
#endif

//
//  The #define LDAP_UNICODE controls if we map the undecorated calls to
//  their unicode counterparts or just leave them defined as the normal
//  single byte entry points.
//
//  If you want to write a UNICODE enabled application, you'd normally
//  just have UNICODE defined and then we'll default to using all LDAP
//  Unicode calls.
//

#ifndef LDAP_UNICODE
#ifdef UNICODE
#define LDAP_UNICODE 1
#else
#define LDAP_UNICODE 0
#endif
#endif

//
//  Global constants
//

#define LDAP_PORT               389
#define LDAP_SSL_PORT           636
#define LDAP_GC_PORT            3268
#define LDAP_SSL_GC_PORT        3269

//
// The default version of the API is 2. If required, the user MUST set the
// version to 3 using the LDAP_OPT_VERSION option.
//

#define LDAP_VERSION1           1
#define LDAP_VERSION2           2
#define LDAP_VERSION3           3
#define LDAP_VERSION            LDAP_VERSION2

//
//  All tags are CCFTTTTT.
//               CC        Tag Class 00 = universal
//                                   01 = application wide
//                                   10 = context specific
//                                   11 = private use
//
//                 F       Form 0 primitive
//                              1 constructed
//
//                  TTTTT  Tag Number
//

//
// LDAP v2 & v3 commands.
//

#define LDAP_BIND_CMD           0x60L   // application + constructed
#define LDAP_UNBIND_CMD         0x42L   // application + primitive
#define LDAP_SEARCH_CMD         0x63L   // application + constructed
#define LDAP_MODIFY_CMD         0x66L   // application + constructed
#define LDAP_ADD_CMD            0x68L   // application + constructed
#define LDAP_DELETE_CMD         0x4aL   // application + primitive
#define LDAP_MODRDN_CMD         0x6cL   // application + constructed
#define LDAP_COMPARE_CMD        0x6eL   // application + constructed
#define LDAP_ABANDON_CMD        0x50L   // application + primitive
#define LDAP_SESSION_CMD        0x71L   // not in base LDAP protocol
#define LDAP_EXTENDED_CMD       0x77L   // application + constructed

//
// Responses/Results for LDAP v2 & v3
//

#define LDAP_RES_BIND           0x61L   // application + constructed
#define LDAP_RES_SEARCH_ENTRY   0x64L   // application + constructed
#define LDAP_RES_SEARCH_RESULT  0x65L   // application + constructed
#define LDAP_RES_MODIFY         0x67L   // application + constructed
#define LDAP_RES_ADD            0x69L   // application + constructed
#define LDAP_RES_DELETE         0x6bL   // application + constructed
#define LDAP_RES_MODRDN         0x6dL   // application + constructed
#define LDAP_RES_COMPARE        0x6fL   // application + constructed
#define LDAP_RES_SESSION        0x72L   // not in base LDAP protocol
#define LDAP_RES_REFERRAL       0x73L   // application + constructed
#define LDAP_RES_EXTENDED       0x78L   // application + constructed

#define LDAP_RES_ANY            (-1L)

#define LDAP_INVALID_CMD         0xff
#define LDAP_INVALID_RES         0xff


//
// We'll make the error codes compatible with reference implementation
//

typedef enum {
    LDAP_SUCCESS                    =   0x00,
    LDAP_OPERATIONS_ERROR           =   0x01,
    LDAP_PROTOCOL_ERROR             =   0x02,
    LDAP_TIMELIMIT_EXCEEDED         =   0x03,
    LDAP_SIZELIMIT_EXCEEDED         =   0x04,
    LDAP_COMPARE_FALSE              =   0x05,
    LDAP_COMPARE_TRUE               =   0x06,
    LDAP_AUTH_METHOD_NOT_SUPPORTED  =   0x07,
    LDAP_STRONG_AUTH_REQUIRED       =   0x08,
    LDAP_REFERRAL_V2                =   0x09,
    LDAP_PARTIAL_RESULTS            =   0x09,
    LDAP_REFERRAL                   =   0x0a,
    LDAP_ADMIN_LIMIT_EXCEEDED       =   0x0b,
    LDAP_UNAVAILABLE_CRIT_EXTENSION =   0x0c,
    LDAP_CONFIDENTIALITY_REQUIRED   =   0x0d,
    LDAP_SASL_BIND_IN_PROGRESS      =   0x0e,

    LDAP_NO_SUCH_ATTRIBUTE          =   0x10,
    LDAP_UNDEFINED_TYPE             =   0x11,
    LDAP_INAPPROPRIATE_MATCHING     =   0x12,
    LDAP_CONSTRAINT_VIOLATION       =   0x13,
    LDAP_ATTRIBUTE_OR_VALUE_EXISTS  =   0x14,
    LDAP_INVALID_SYNTAX             =   0x15,

    LDAP_NO_SUCH_OBJECT             =   0x20,
    LDAP_ALIAS_PROBLEM              =   0x21,
    LDAP_INVALID_DN_SYNTAX          =   0x22,
    LDAP_IS_LEAF                    =   0x23,
    LDAP_ALIAS_DEREF_PROBLEM        =   0x24,

    LDAP_INAPPROPRIATE_AUTH         =   0x30,
    LDAP_INVALID_CREDENTIALS        =   0x31,
    LDAP_INSUFFICIENT_RIGHTS        =   0x32,
    LDAP_BUSY                       =   0x33,
    LDAP_UNAVAILABLE                =   0x34,
    LDAP_UNWILLING_TO_PERFORM       =   0x35,
    LDAP_LOOP_DETECT                =   0x36,
    LDAP_SORT_CONTROL_MISSING       =   0x3C,
    LDAP_OFFSET_RANGE_ERROR         =   0x3D,

    LDAP_NAMING_VIOLATION           =   0x40,
    LDAP_OBJECT_CLASS_VIOLATION     =   0x41,
    LDAP_NOT_ALLOWED_ON_NONLEAF     =   0x42,
    LDAP_NOT_ALLOWED_ON_RDN         =   0x43,
    LDAP_ALREADY_EXISTS             =   0x44,
    LDAP_NO_OBJECT_CLASS_MODS       =   0x45,
    LDAP_RESULTS_TOO_LARGE          =   0x46,
    LDAP_AFFECTS_MULTIPLE_DSAS      =   0x47,
    
    LDAP_VIRTUAL_LIST_VIEW_ERROR    =   0x4c,

    LDAP_OTHER                      =   0x50,
    LDAP_SERVER_DOWN                =   0x51,
    LDAP_LOCAL_ERROR                =   0x52,
    LDAP_ENCODING_ERROR             =   0x53,
    LDAP_DECODING_ERROR             =   0x54,
    LDAP_TIMEOUT                    =   0x55,
    LDAP_AUTH_UNKNOWN               =   0x56,
    LDAP_FILTER_ERROR               =   0x57,
    LDAP_USER_CANCELLED             =   0x58,
    LDAP_PARAM_ERROR                =   0x59,
    LDAP_NO_MEMORY                  =   0x5a,
    LDAP_CONNECT_ERROR              =   0x5b,
    LDAP_NOT_SUPPORTED              =   0x5c,
    LDAP_NO_RESULTS_RETURNED        =   0x5e,
    LDAP_CONTROL_NOT_FOUND          =   0x5d,
    LDAP_MORE_RESULTS_TO_RETURN     =   0x5f,

    LDAP_CLIENT_LOOP                =   0x60,
    LDAP_REFERRAL_LIMIT_EXCEEDED    =   0x61
} LDAP_RETCODE;

//
//  Bind methods.  We support the following methods :
//
//      Simple         Clear text password... try not to use as it's not secure.
//
//      MSN            MSN (Microsoft Network) authentication. This package
//                     may bring up UI to prompt the user for MSN credentials.
//
//      DPA            Normandy authentication... new MSN authentication.  Same
//                     usage as MSN.
//
//      NTLM           NT domain authentication.  Use NULL credentials and
//                     we'll try to use default logged in user credentials.
//
//      Sicily         Negotiate with the server for any of: MSN, DPA, NTLM
//                     Should be used for LDAPv2 servers only.
//
//      Negotiate      Use GSSAPI Negotiate package to negotiate security
//                     package of either Kerberos v5 or NTLM (or any other
//                     package the client and server negotiate).  Pass in
//                     NULL credentials to specify default logged in user.
//                     If Negotiate package is not installed on server or
//                     client, this will fall back to Sicily negotiation.
//
//  For all bind methods except for Simple, you may pass in a
//  SEC_WINNT_AUTH_IDENTITY_W (defined in rpcdce.h) or the newer
//  SEC_WINNT_AUTH_IDENTITY_EXW (defined in secext.h) to specify alternate
//  credentials.
//
//  All bind methods other than simple are synchronous only calls.
//  Calling the asynchronous bind call for any of these messages will
//  return LDAP_PARAM_ERROR.
//
//  Using any other method besides simple will cause WLDAP32 to pull in
//  the SSPI security DLLs (SECURITY.DLL etc).
//
//  On non-Simple methods, if you specify NULL credentials, we'll attempt to use
//  the default logged in user.
//

#define LDAP_AUTH_SIMPLE                0x80L
#define LDAP_AUTH_SASL                  0x83L   // don't use... should go away

#define LDAP_AUTH_OTHERKIND             0x86L

// The SICILY type covers package negotiation to MSN servers.
// Each of the supported types can also be specified without
// doing the package negotiation, assuming the caller knows
// what the server supports.

#define LDAP_AUTH_SICILY                (LDAP_AUTH_OTHERKIND | 0x0200)

#define LDAP_AUTH_MSN                   (LDAP_AUTH_OTHERKIND | 0x0800)
#define LDAP_AUTH_NTLM                  (LDAP_AUTH_OTHERKIND | 0x1000)
#define LDAP_AUTH_DPA                   (LDAP_AUTH_OTHERKIND | 0x2000)

// This will cause the client to use the GSSAPI negotiation
// package to determine the most appropriate authentication type.
// This type should be used when talking to NT5.

#define LDAP_AUTH_NEGOTIATE             (LDAP_AUTH_OTHERKIND | 0x0400)

// backward compatible #define for older constant name.

#define LDAP_AUTH_SSPI                   LDAP_AUTH_NEGOTIATE

//
// uses the DIGEST-MD5 mechanism.
//

#define LDAP_AUTH_DIGEST                (LDAP_AUTH_OTHERKIND | 0x4000)

// The external auth mechanism is used upon setting up an SSL/TLS connection
// to denote that the server must use the client cert credentials presented
// at the outset of the SSL/TLS connection.


#define LDAP_AUTH_EXTERNAL              (LDAP_AUTH_OTHERKIND | 0x0020)

//
//  Client applications typically don't have to encode/decode LDAP filters,
//  but if they do, we define the operators here.
//
//  Filter types.

#define LDAP_FILTER_AND         0xa0    // context specific + constructed - SET OF Filters.
#define LDAP_FILTER_OR          0xa1    // context specific + constructed - SET OF Filters.
#define LDAP_FILTER_NOT         0xa2    // context specific + constructed - Filter
#define LDAP_FILTER_EQUALITY    0xa3    // context specific + constructed - AttributeValueAssertion.
#define LDAP_FILTER_SUBSTRINGS  0xa4    // context specific + constructed - SubstringFilter
#define LDAP_FILTER_GE          0xa5    // context specific + constructed - AttributeValueAssertion.
#define LDAP_FILTER_LE          0xa6    // context specific + constructed - AttributeValueAssertion.
#define LDAP_FILTER_PRESENT     0x87    // context specific + primitive   - AttributeType.
#define LDAP_FILTER_APPROX      0xa8    // context specific + constructed - AttributeValueAssertion.
#define LDAP_FILTER_EXTENSIBLE  0xa9    // context specific + constructed - MatchingRuleAssertion.

//  Substring filter types

#define LDAP_SUBSTRING_INITIAL  0x80L   // class context specific
#define LDAP_SUBSTRING_ANY      0x81L   // class context specific
#define LDAP_SUBSTRING_FINAL    0x82L   // class context specific

//
//  Possible values for ld_deref field.
//      "Never"     - never deref aliases.  return only the alias.
//      "Searching" - only deref aliases when searching, not when locating
//                    the base object of a search.
//      "Finding"   - dereference the alias when locating the base object but
//                    not during a search.
//      "Always"    - always dereference aliases.
//

#define LDAP_DEREF_NEVER        0
#define LDAP_DEREF_SEARCHING    1
#define LDAP_DEREF_FINDING      2
#define LDAP_DEREF_ALWAYS       3

//  Special values for ld_sizelimit :

#define LDAP_NO_LIMIT       0

//  Flags for ld_options field :

#define LDAP_OPT_DNS                0x00000001  // utilize DN & DNS
#define LDAP_OPT_CHASE_REFERRALS    0x00000002  // chase referrals
#define LDAP_OPT_RETURN_REFS        0x00000004  // return referrals to calling app

//
//  LDAP structure per connection
//

#if !defined(_WIN64)
#pragma pack(push, 4)
#endif

typedef struct ldap {

    struct {

        UINT_PTR sb_sd;

        UCHAR Reserved1[(10*sizeof(ULONG))+1];

        ULONG_PTR sb_naddr;   // notzero implies CLDAP available

        UCHAR Reserved2[(6*sizeof(ULONG))];

    } ld_sb;

    //
    //  Following parameters MAY match up to reference implementation of LDAP
    //

    PCHAR   ld_host;
    ULONG   ld_version;
    UCHAR   ld_lberoptions;

    //
    //  Safe to assume that these parameters are in same location as
    //  reference implementation of LDAP API.
    //

    ULONG   ld_deref;

    ULONG   ld_timelimit;
    ULONG   ld_sizelimit;

    ULONG   ld_errno;
    PCHAR   ld_matched;
    PCHAR   ld_error;
    ULONG   ld_msgid;

    UCHAR Reserved3[(6*sizeof(ULONG))+1];

    //
    //  Following parameters may match up to reference implementation of LDAP API.
    //

    ULONG   ld_cldaptries;
    ULONG   ld_cldaptimeout;
    ULONG   ld_refhoplimit;
    ULONG   ld_options;

} LDAP, * PLDAP;

//
//  Our timeval structure is a bit different from the reference implementation
//  since Win32 defines a _timeval structure that is different from the LDAP
//  one.
//

typedef struct l_timeval {
    LONG    tv_sec;
    LONG    tv_usec;
} LDAP_TIMEVAL, * PLDAP_TIMEVAL;

//
//  The berval structure is used to pass in any arbitrary octet string.  It
//  is useful for attributes that cannot be represented using a null
//  terminated string.
//

typedef struct berval {
    ULONG  bv_len;
    PCHAR  bv_val;
} LDAP_BERVAL, * PLDAP_BERVAL, BERVAL, * PBERVAL, BerValue;

//
//  The following structure has to be compatible with reference implementation.
//

typedef struct ldapmsg {

    ULONG lm_msgid;             // message number for given connection
    ULONG lm_msgtype;           // message type of the form LDAP_RES_xxx

    PVOID lm_ber;               // ber form of message

    struct ldapmsg *lm_chain;   // pointer to next result value
    struct ldapmsg *lm_next;    // pointer to next message
    ULONG lm_time;

    //
    //  new fields below not in reference implementation
    //

    PLDAP   Connection;         // connection from which we received response
    PVOID   Request;            // owning request (opaque structure)
    ULONG   lm_returncode;      // server's return code
    USHORT  lm_referral;        // index of referral within ref table
    BOOLEAN lm_chased;          // has referral been chased already?
    BOOLEAN lm_eom;             // is this the last entry for this message?
    BOOLEAN ConnectionReferenced; // is the Connection still valid?

} LDAPMessage, *PLDAPMessage;

//
//  Controls... there are three types :
//
//   1) those passed to the server
//   2) those passed to the client and handled by the client API
//   3) those returned by the server
//

typedef struct ldapcontrolA {

    PCHAR         ldctl_oid;
    struct berval ldctl_value;
    BOOLEAN       ldctl_iscritical;

} LDAPControlA, *PLDAPControlA;

typedef struct ldapcontrolW {

    PWCHAR        ldctl_oid;
    struct berval ldctl_value;
    BOOLEAN       ldctl_iscritical;

} LDAPControlW, *PLDAPControlW;

#if LDAP_UNICODE
#define LDAPControl LDAPControlW
#define PLDAPControl PLDAPControlW
#else
#define LDAPControl LDAPControlA
#define PLDAPControl PLDAPControlA
#endif

//
//  Client controls section : these are the client controls that wldap32.dll
//  supports.
//
//  If you specify LDAP_CONTROL_REFERRALS in a control, the value field should
//  point to a ULONG of the following flags :
//
//      LDAP_CHASE_SUBORDINATE_REFERRALS
//      LDAP_CHASE_EXTERNAL_REFERRALS
//

#define LDAP_CONTROL_REFERRALS_W L"1.2.840.113556.1.4.616"
#define LDAP_CONTROL_REFERRALS    "1.2.840.113556.1.4.616"

//
//  Values required for Modification command  These are options for the
//  mod_op field of LDAPMod structure
//

#define LDAP_MOD_ADD            0x00
#define LDAP_MOD_DELETE         0x01
#define LDAP_MOD_REPLACE        0x02
#define LDAP_MOD_BVALUES        0x80  // AND in this flag if berval structure used

typedef struct ldapmodW {
     ULONG     mod_op;
     PWCHAR    mod_type;
     union {
        PWCHAR  *modv_strvals;
        struct berval   **modv_bvals;
    } mod_vals;
} LDAPModW, *PLDAPModW;

typedef struct ldapmodA {
     ULONG     mod_op;
     PCHAR     mod_type;
     union {
        PCHAR  *modv_strvals;
        struct berval   **modv_bvals;
    } mod_vals;
} LDAPModA, *PLDAPModA;

#if LDAP_UNICODE
#define LDAPMod LDAPModW
#define PLDAPMod PLDAPModW
#else
#define LDAPMod LDAPModA
#define PLDAPMod PLDAPModA
#endif

#if !defined(_WIN64)
#pragma pack(pop)
#endif

//
//  macros compatible with reference implementation...
//

#define LDAP_IS_CLDAP( ld ) ( (ld)->ld_sb.sb_naddr > 0 )
#define mod_values      mod_vals.modv_strvals
#define mod_bvalues     mod_vals.modv_bvals
#define NAME_ERROR(n)   ((n & 0xf0) == 0x20)

//
//  function definitions for LDAP API
//

//
//  Create a connection block to an LDAP server.  HostName can be NULL, in
//  which case we'll try to go off and find the "default" LDAP server.
//
//  Note that if we have to go off and find the default server, we'll pull
//  in NETAPI32.DLL and ADVAPI32.DLL.
//
//  If it returns NULL, an error occurred.  Pick up error code with
//     GetLastError().
//
//  ldap_open actually opens the connection at the time of the call,
//  whereas ldap_init only opens the connection when an operation is performed
//  that requires it.
//
//  multi-thread: ldap_open*, ldap_init*, and ldap_sslinit* calls are safe.
//

WINLDAPAPI LDAP * LDAPAPI ldap_openW( __in const PWCHAR HostName, ULONG PortNumber );
WINLDAPAPI LDAP * LDAPAPI ldap_openA( __in const PCHAR HostName, ULONG PortNumber );

WINLDAPAPI LDAP * LDAPAPI ldap_initW( __in const PWCHAR HostName, ULONG PortNumber );
WINLDAPAPI LDAP * LDAPAPI ldap_initA( __in const PCHAR HostName, ULONG PortNumber );

WINLDAPAPI LDAP * LDAPAPI ldap_sslinitW( __in PWCHAR HostName, ULONG PortNumber, int secure );
WINLDAPAPI LDAP * LDAPAPI ldap_sslinitA( __in PCHAR HostName, ULONG PortNumber, int secure );

//
//  when calling ldap_init, you can call ldap_connect explicitly to have the
//  library contact the server.  This is useful for checking for server
//  availability.  This call is not required however, since the other functions
//  will call it internally if it hasn't already been called.
//

WINLDAPAPI ULONG LDAPAPI ldap_connect(  LDAP *ld,
                                        struct l_timeval  *timeout
                                        );

#if LDAP_UNICODE

#define ldap_open ldap_openW
#define ldap_init ldap_initW
#define ldap_sslinit ldap_sslinitW

#else

WINLDAPAPI LDAP * LDAPAPI ldap_open( __in PCHAR HostName, ULONG PortNumber );
WINLDAPAPI LDAP * LDAPAPI ldap_init( __in PCHAR HostName, ULONG PortNumber );
WINLDAPAPI LDAP * LDAPAPI ldap_sslinit( __in PCHAR HostName, ULONG PortNumber, int secure );

#endif

//
//  This is similar to ldap_open except it creates a connection block for
//  UDP based Connectionless LDAP services.  No TCP session is maintained.
//
//  If it returns NULL, an error occurred.  Pick up error code with
//     GetLastError().
//
//  multi-thread: cldap_open* calls are safe.
//

WINLDAPAPI LDAP * LDAPAPI cldap_openW( __in PWCHAR HostName, ULONG PortNumber );
WINLDAPAPI LDAP * LDAPAPI cldap_openA( __in PCHAR HostName, ULONG PortNumber );


#if LDAP_UNICODE

#define cldap_open cldap_openW

#else

WINLDAPAPI LDAP * LDAPAPI cldap_open( __in PCHAR HostName, ULONG PortNumber );

#endif



//
//  Call unbind when you're done with the connection, it will free all
//  resources associated with the connection.
//
//  There is no ldap_close... use ldap_unbind even if you haven't called
//  ldap_bind on the connection.
//
//  multi-thread: ldap_unbind* calls are safe EXCEPT don't use the LDAP *
//                stucture after it's been freed.
//

WINLDAPAPI ULONG LDAPAPI ldap_unbind( LDAP *ld );
WINLDAPAPI ULONG LDAPAPI ldap_unbind_s( LDAP *ld ); // calls ldap_unbind

//
//  Calls to get and set options on connection blocks... use them rather
//  than modifying the LDAP block directly.
//
//
//  multi-thread: ldap_get_option is safe
//  multi-thread: ldap_set_option is not safe in that it affects the
//                connection as a whole.  beware if threads share connections.


WINLDAPAPI ULONG LDAPAPI ldap_get_option( LDAP *ld, int option, void *outvalue );
WINLDAPAPI ULONG LDAPAPI ldap_get_optionW( LDAP *ld, int option, void *outvalue );

WINLDAPAPI ULONG LDAPAPI ldap_set_option( LDAP *ld, int option, const void *invalue );
WINLDAPAPI ULONG LDAPAPI ldap_set_optionW( LDAP *ld, int option, const void *invalue );

#if LDAP_UNICODE

#define ldap_get_option ldap_get_optionW
#define ldap_set_option ldap_set_optionW

#endif

//
//  These are the values to pass to ldap_get/set_option :
//

#define LDAP_OPT_API_INFO           0x00
#define LDAP_OPT_DESC               0x01
#define LDAP_OPT_DEREF              0x02
#define LDAP_OPT_SIZELIMIT          0x03
#define LDAP_OPT_TIMELIMIT          0x04
#define LDAP_OPT_THREAD_FN_PTRS     0x05
#define LDAP_OPT_REBIND_FN          0x06
#define LDAP_OPT_REBIND_ARG         0x07
#define LDAP_OPT_REFERRALS          0x08
#define LDAP_OPT_RESTART            0x09

#define LDAP_OPT_SSL                0x0a
#define LDAP_OPT_IO_FN_PTRS         0x0b
#define LDAP_OPT_CACHE_FN_PTRS      0x0d
#define LDAP_OPT_CACHE_STRATEGY     0x0e
#define LDAP_OPT_CACHE_ENABLE       0x0f
#define LDAP_OPT_REFERRAL_HOP_LIMIT 0x10

#define LDAP_OPT_PROTOCOL_VERSION   0x11        // known by two names.
#define LDAP_OPT_VERSION            0x11
#define LDAP_OPT_API_FEATURE_INFO   0x15

//
//  These are new ones that we've defined, not in current RFC draft.
//

#define LDAP_OPT_HOST_NAME          0x30
#define LDAP_OPT_ERROR_NUMBER       0x31
#define LDAP_OPT_ERROR_STRING       0x32
#define LDAP_OPT_SERVER_ERROR       0x33
#define LDAP_OPT_SERVER_EXT_ERROR   0x34
#define LDAP_OPT_HOST_REACHABLE     0x3E

//
//  These options control the keep-alive logic.  Keep alives are sent as
//  ICMP ping messages (which currently don't go through firewalls).
//
//  There are three values that control how this works :
//  PING_KEEP_ALIVE : min number of seconds since we last received a response
//                    from the server before we send a keep-alive ping
//  PING_WAIT_TIME  : number of milliseconds we wait for the response to
//                    come back when we send a ping
//  PING_LIMIT      : number of unanswered pings we send before we close the
//                    connection.
//
//  To disable the keep-alive logic, set any of the values (PING_KEEP_ALIVE,
//  PING_LIMIT, or PING_WAIT_TIME) to zero.
//
//  The current default/min/max for these values are as follows :
//
//  PING_KEEP_ALIVE :  120/5/maxInt  seconds (may also be zero)
//  PING_WAIT_TIME  :  2000/10/60000 milliseconds (may also be zero)
//  PING_LIMIT      :  4/0/maxInt
//

#define LDAP_OPT_PING_KEEP_ALIVE    0x36
#define LDAP_OPT_PING_WAIT_TIME     0x37
#define LDAP_OPT_PING_LIMIT         0x38

//
//  These won't be in the RFC.  Only use these if you're going to be dependent
//  on our implementation.
//

#define LDAP_OPT_DNSDOMAIN_NAME     0x3B    // return DNS name of domain
#define LDAP_OPT_GETDSNAME_FLAGS    0x3D    // flags for DsGetDcName

#define LDAP_OPT_PROMPT_CREDENTIALS 0x3F    // prompt for creds? currently
                                            // only for DPA & NTLM if no creds
                                            // are loaded

#define LDAP_OPT_AUTO_RECONNECT     0x91    // enable/disable autoreconnect
#define LDAP_OPT_SSPI_FLAGS         0x92    // flags to pass to InitSecurityContext

//
// To retrieve information on an secure connection, a pointer to a
// SecPkgContext_connectionInfo structure (defined in schannel.h) must be
// passed in. On success, it is filled with relevent security information.
//

#define LDAP_OPT_SSL_INFO           0x93

// backward compatible #define for older constant name.

#define LDAP_OPT_TLS                        LDAP_OPT_SSL
#define LDAP_OPT_TLS_INFO                   LDAP_OPT_SSL_INFO

//
// Turing on either the sign or the encrypt option prior to binding using
// LDAP_AUTH_NEGOTIATE will result in the ensuing LDAP session to be signed
// or encrypted using Kerberos. Note that these options can't be used with SSL.
//

#define LDAP_OPT_SIGN               0x95
#define LDAP_OPT_ENCRYPT            0x96

//
// The user can set a preferred SASL method prior to binding using LDAP_AUTH_NEGOTIATE
// We will try to use this mechanism while binding. One example is "GSSAPI".
//

#define LDAP_OPT_SASL_METHOD        0x97

//
// Setting this option to LDAP_OPT_ON will instruct the library to only perform an
// A-Record DNS lookup on the supplied host string. This option is OFF by default.
//

#define LDAP_OPT_AREC_EXCLUSIVE     0x98

//
// Retrieve the security context associated with the connection.
//

#define LDAP_OPT_SECURITY_CONTEXT   0x99

//
// Enable/Disable the built-in RootDSE cache. This option is ON by default.
//

#define LDAP_OPT_ROOTDSE_CACHE      0x9a

//
// Turns on TCP keep-alives.  This is separate from the ICMP ping keep-alive
// mechanism (discussed above), and enables the keep-alive mechanism built into
// the TCP protocol.  This has no effect when using connectionless (UDP) LDAP.
// This option is OFF by default.
//

#define LDAP_OPT_TCP_KEEPALIVE     0x40


//
// Turns on support for fast concurrent binds (extended operation
// 1.2.840.113556.1.4.1781).  This option can be set only on a fresh
// (never bound/authenticated) connection.  Setting this option will
// (1) switch the client into a mode where it supports simultaneous
// simple binds on the connection, and (2) sends the extended operation
// to the server to switch it into fast bind mode.  Only simple binds
// are supported in this mode.
//
#define LDAP_OPT_FAST_CONCURRENT_BIND   0x41

#define LDAP_OPT_SEND_TIMEOUT           0x42

//
// Flags to control the behavior of Schannel
//
#define LDAP_OPT_SCH_FLAGS              0x43

//
// List of local interface addresses (IPv4 or IPv6) that will be used for
// socket bind when establishing a connecting.
//
#define LDAP_OPT_SOCKET_BIND_ADDRESSES  0x44

//
//  End of Microsoft only options
//

#define LDAP_OPT_ON                 ((void *) 1)
#define LDAP_OPT_OFF                ((void *) 0)

//
//  For chasing referrals, we extend this a bit for LDAP_OPT_REFERRALS.  If
//  the value is not LDAP_OPT_ON or LDAP_OPT_OFF, we'll treat them as the
//  following :
//
//  LDAP_CHASE_SUBORDINATE_REFERRALS  : chase subordinate referrals (or
//                                      references) returned in a v3 search
//  LDAP_CHASE_EXTERNAL_REFERRALS : chase external referrals. These are
//                          returned possibly on any operation except bind.
//
//  If you OR these flags together, it's equivalent to setting referrals to
//  LDAP_OPT_ON.
//

#define LDAP_CHASE_SUBORDINATE_REFERRALS    0x00000020
#define LDAP_CHASE_EXTERNAL_REFERRALS       0x00000040

//
//  Bind is required as the first operation to v2 servers, not so for v3
//  servers.  See above description of authentication methods.
//
//  multi-thread: bind calls are not safe in that it affects the
//                connection as a whole.  beware if threads share connections
//                and try to mulithread binds with other operations.


WINLDAPAPI ULONG LDAPAPI ldap_simple_bindW( LDAP *ld, __in_opt PWCHAR dn, __in_opt PWCHAR passwd );
WINLDAPAPI ULONG LDAPAPI ldap_simple_bindA( LDAP *ld, __in_opt PCHAR dn, __in_opt PCHAR passwd );
WINLDAPAPI ULONG LDAPAPI ldap_simple_bind_sW( LDAP *ld, __in_opt PWCHAR dn, __in_opt PWCHAR passwd );
WINLDAPAPI ULONG LDAPAPI ldap_simple_bind_sA( LDAP *ld, __in_opt PCHAR dn, __in_opt PCHAR passwd );

WINLDAPAPI ULONG LDAPAPI ldap_bindW( LDAP *ld, __in_opt PWCHAR dn, __in_opt PWCHAR cred, ULONG method );
WINLDAPAPI ULONG LDAPAPI ldap_bindA( LDAP *ld, __in_opt PCHAR dn, __in_opt PCHAR cred, ULONG method );
WINLDAPAPI ULONG LDAPAPI ldap_bind_sW( LDAP *ld, __in_opt PWCHAR dn, __in_opt PWCHAR cred, ULONG method );
WINLDAPAPI ULONG LDAPAPI ldap_bind_sA( LDAP *ld, __in_opt PCHAR dn, __in_opt PCHAR cred, ULONG method );


//
// The following functions can be used to pass in any arbitrary credentials
// to the server. The application must be ready to interpret the response
// sent back from the server.
//

 WINLDAPAPI INT LDAPAPI ldap_sasl_bindA(
         LDAP  *ExternalHandle,
         __in const  PCHAR DistName,
         __in const PCHAR AuthMechanism,
         const BERVAL   *cred,
         PLDAPControlA *ServerCtrls,
         PLDAPControlA *ClientCtrls,
         int *MessageNumber
         );

 WINLDAPAPI INT LDAPAPI ldap_sasl_bindW(
         LDAP  *ExternalHandle,
         __in const PWCHAR DistName,
         __in const PWCHAR AuthMechanism,
         const BERVAL   *cred,
         PLDAPControlW *ServerCtrls,
         PLDAPControlW *ClientCtrls,
         int *MessageNumber
         );

 WINLDAPAPI INT LDAPAPI ldap_sasl_bind_sA(
         LDAP  *ExternalHandle,
         __in const PCHAR DistName,
         __in const PCHAR AuthMechanism,
         const BERVAL   *cred,
         PLDAPControlA *ServerCtrls,
         PLDAPControlA *ClientCtrls,
         PBERVAL *ServerData
         );

 WINLDAPAPI INT LDAPAPI ldap_sasl_bind_sW(
         LDAP  *ExternalHandle,
         __in const PWCHAR DistName,
         __in const PWCHAR AuthMechanism,
         const BERVAL   *cred,
         PLDAPControlW *ServerCtrls,
         PLDAPControlW *ClientCtrls,
         PBERVAL *ServerData
         );


#if LDAP_UNICODE

#define ldap_simple_bind ldap_simple_bindW
#define ldap_simple_bind_s ldap_simple_bind_sW

#define ldap_bind ldap_bindW
#define ldap_bind_s ldap_bind_sW

#define ldap_sasl_bind ldap_sasl_bindW
#define ldap_sasl_bind_s ldap_sasl_bind_sW

#else

WINLDAPAPI ULONG LDAPAPI ldap_simple_bind( LDAP *ld, __in_opt const PCHAR dn, __in_opt const PCHAR passwd );
WINLDAPAPI ULONG LDAPAPI ldap_simple_bind_s( LDAP *ld, __in_opt const PCHAR dn, __in_opt const PCHAR passwd );

WINLDAPAPI ULONG LDAPAPI ldap_bind( LDAP *ld, __in_opt const PCHAR dn, __in_opt const PCHAR cred, ULONG method );
WINLDAPAPI ULONG LDAPAPI ldap_bind_s( LDAP *ld, __in_opt const PCHAR dn, __in_opt const PCHAR cred, ULONG method );

#define ldap_sasl_bind ldap_sasl_bindA
#define ldap_sasl_bind_s ldap_sasl_bind_sA

#endif

//
//  Synchronous and asynch search routines.
//
//  filter follows RFC 1960 with the addition that '(' ')' '*' ' ' '\' and
//   '\0' are all escaped with '\'
//
// Scope of search.  This corresponds to the "scope" parameter on search

#define LDAP_SCOPE_BASE         0x00
#define LDAP_SCOPE_ONELEVEL     0x01
#define LDAP_SCOPE_SUBTREE      0x02

//
//  multi-thread: ldap_search calls are not safe in that the message number
//                is returned rather than the return code.  You have to look
//                at the connection block in an error case and the return code
//                may be overwritten by another thread inbetween.
//
//                Use ldap_search_ext instead, as these are thread safe.
//
//                ldap_search_s and ldap_search_ext* calls are thread safe.
//

WINLDAPAPI ULONG LDAPAPI ldap_searchW(
        LDAP    *ld,
        __in const PWCHAR  base,     // distinguished name or ""
        ULONG   scope,          // LDAP_SCOPE_xxxx
        __in const PWCHAR  filter,
        __in PWCHAR  attrs[],        // pointer to an array of PCHAR attribute names
        ULONG   attrsonly       // boolean on whether to only return attr names
    );
WINLDAPAPI ULONG LDAPAPI ldap_searchA(
        LDAP    *ld,
        __in const PCHAR   base,     // distinguished name or ""
        ULONG   scope,          // LDAP_SCOPE_xxxx
        __in const PCHAR   filter,
        __in PCHAR   attrs[],        // pointer to an array of PCHAR attribute names
        ULONG   attrsonly       // boolean on whether to only return attr names
    );

WINLDAPAPI ULONG LDAPAPI ldap_search_sW(
        LDAP            *ld,
        __in const PWCHAR    base,
        ULONG           scope,
        __in const PWCHAR    filter,
        __in PWCHAR          attrs[],
        ULONG           attrsonly,
        LDAPMessage     **res
    );
WINLDAPAPI ULONG LDAPAPI ldap_search_sA(
        LDAP            *ld,
        __in const PCHAR     base,
        ULONG           scope,
        __in const PCHAR     filter,
        __in PCHAR           attrs[],
        ULONG           attrsonly,
        LDAPMessage     **res
    );

WINLDAPAPI ULONG LDAPAPI ldap_search_stW(
        LDAP            *ld,
        __in const PWCHAR    base,
        ULONG           scope,
        __in const PWCHAR    filter,
        __in PWCHAR          attrs[],
        ULONG           attrsonly,
        struct l_timeval  *timeout,
        LDAPMessage     **res
    );
WINLDAPAPI ULONG LDAPAPI ldap_search_stA(
        LDAP            *ld,
        __in const PCHAR     base,
        ULONG           scope,
        __in const PCHAR     filter,
        __in PCHAR           attrs[],
        ULONG           attrsonly,
        struct l_timeval  *timeout,
        LDAPMessage     **res
    );


WINLDAPAPI ULONG LDAPAPI ldap_search_extW(
        LDAP            *ld,
        __in const PWCHAR    base,
        ULONG           scope,
        __in const PWCHAR    filter,
        __in PWCHAR          attrs[],
        ULONG           attrsonly,
        PLDAPControlW   *ServerControls,
        PLDAPControlW   *ClientControls,
        ULONG           TimeLimit,
        ULONG           SizeLimit,
        ULONG           *MessageNumber
    );

WINLDAPAPI ULONG LDAPAPI ldap_search_extA(
        LDAP            *ld,
        __in const PCHAR     base,
        ULONG           scope,
        __in const PCHAR     filter,
        __in PCHAR           attrs[],
        ULONG           attrsonly,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        ULONG           TimeLimit,
        ULONG           SizeLimit,
        ULONG           *MessageNumber
    );

WINLDAPAPI ULONG LDAPAPI ldap_search_ext_sW(
        LDAP            *ld,
        __in const PWCHAR    base,
        __in ULONG           scope,
        __in const PWCHAR    filter,
        __in PWCHAR          attrs[],
        ULONG           attrsonly,
        PLDAPControlW   *ServerControls,
        PLDAPControlW   *ClientControls,
        struct l_timeval  *timeout,
        ULONG           SizeLimit,
        LDAPMessage     **res
    );

WINLDAPAPI ULONG LDAPAPI ldap_search_ext_sA(
        LDAP            *ld,
        __in const PCHAR     base,
        ULONG           scope,
        __in const PCHAR     filter,
        __in PCHAR           attrs[],
        ULONG           attrsonly,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        struct l_timeval  *timeout,
        ULONG           SizeLimit,
        LDAPMessage     **res
    );

#if LDAP_UNICODE

#define ldap_search ldap_searchW
#define ldap_search_s ldap_search_sW
#define ldap_search_st ldap_search_stW

#define ldap_search_ext ldap_search_extW
#define ldap_search_ext_s ldap_search_ext_sW

#else

WINLDAPAPI ULONG LDAPAPI ldap_search(
        LDAP    *ld,
        __in PCHAR   base,           // distinguished name or ""
        ULONG   scope,          // LDAP_SCOPE_xxxx
        __in PCHAR   filter,
        __in PCHAR   attrs[],        // pointer to an array of PCHAR attribute names
        ULONG   attrsonly       // boolean on whether to only return attr names
    );

WINLDAPAPI ULONG LDAPAPI ldap_search_s(
        LDAP            *ld,
        __in PCHAR           base,
        ULONG           scope,
        __in PCHAR           filter,
        __in PCHAR           attrs[],
        ULONG           attrsonly,
        LDAPMessage     **res
    );

WINLDAPAPI ULONG LDAPAPI ldap_search_st(
        LDAP            *ld,
        __in PCHAR           base,
        ULONG           scope,
        __in PCHAR           filter,
        __in PCHAR           attrs[],
        ULONG           attrsonly,
        struct l_timeval  *timeout,
        LDAPMessage     **res
    );

WINLDAPAPI ULONG LDAPAPI ldap_search_ext(
        LDAP            *ld,
        PCHAR           base,
        ULONG           scope,
        PCHAR           filter,
        PCHAR           attrs[],
        ULONG           attrsonly,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        ULONG           TimeLimit,
        ULONG           SizeLimit,
        ULONG           *MessageNumber
    );

WINLDAPAPI ULONG LDAPAPI ldap_search_ext_s(
        LDAP            *ld,
        PCHAR           base,
        ULONG           scope,
        PCHAR           filter,
        PCHAR           attrs[],
        ULONG           attrsonly,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        struct l_timeval  *timeout,
        ULONG           SizeLimit,
        LDAPMessage     **res
    );

#endif

//
//  Extended API to check filter syntax.  Returns LDAP error code if syntax
//  is invalid or LDAP_SUCCESS if it's ok.
//

WINLDAPAPI ULONG LDAPAPI
ldap_check_filterW(
        LDAP    *ld,
        __in PWCHAR  SearchFilter
    );

WINLDAPAPI ULONG LDAPAPI
ldap_check_filterA(
        LDAP    *ld,
        __in PCHAR   SearchFilter
    );

#if LDAP_UNICODE
#define ldap_check_filter ldap_check_filterW
#else
#define ldap_check_filter ldap_check_filterA
#endif


//
//  modify an existing entry
//

//
//  multi-thread: ldap_modify calls are not safe in that the message number
//                is returned rather than the return code.  You have to look
//                at the connection block in an error case and the return code
//                may be overwritten by another thread inbetween.
//
//                Use ldap_modify_ext instead, as these are thread safe.
//
//                ldap_modify_s and ldap_modify_ext* calls are thread safe.
//

WINLDAPAPI ULONG LDAPAPI ldap_modifyW( LDAP *ld, __in PWCHAR dn, LDAPModW *mods[] );
WINLDAPAPI ULONG LDAPAPI ldap_modifyA( LDAP *ld, __in PCHAR dn, LDAPModA *mods[] );

WINLDAPAPI ULONG LDAPAPI ldap_modify_sW( LDAP *ld, __in PWCHAR dn, LDAPModW *mods[] );
WINLDAPAPI ULONG LDAPAPI ldap_modify_sA( LDAP *ld, __in PCHAR dn, LDAPModA *mods[] );

WINLDAPAPI ULONG LDAPAPI ldap_modify_extW(
        LDAP *ld,
        __in const PWCHAR dn,
        LDAPModW *mods[],
        PLDAPControlW   *ServerControls,
        PLDAPControlW   *ClientControls,
        ULONG           *MessageNumber
        );

WINLDAPAPI ULONG LDAPAPI ldap_modify_extA(
        LDAP *ld,
        __in const PCHAR dn,
        LDAPModA *mods[],
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        ULONG           *MessageNumber
        );

WINLDAPAPI ULONG LDAPAPI ldap_modify_ext_sW(
        LDAP *ld,
        __in const PWCHAR dn,
        LDAPModW *mods[],
        PLDAPControlW   *ServerControls,
        PLDAPControlW   *ClientControls
        );

WINLDAPAPI ULONG LDAPAPI ldap_modify_ext_sA(
        LDAP *ld,
        __in const PCHAR dn,
        LDAPModA *mods[],
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls
        );

#if LDAP_UNICODE

#define ldap_modify ldap_modifyW
#define ldap_modify_s ldap_modify_sW

#define ldap_modify_ext ldap_modify_extW
#define ldap_modify_ext_s ldap_modify_ext_sW

#else

WINLDAPAPI ULONG LDAPAPI ldap_modify( LDAP *ld, __in PCHAR dn, LDAPModA *mods[] );
WINLDAPAPI ULONG LDAPAPI ldap_modify_s( LDAP *ld, __in PCHAR dn, LDAPModA *mods[] );

WINLDAPAPI ULONG LDAPAPI ldap_modify_ext(
        LDAP *ld,
        const PCHAR dn,
        LDAPModA *mods[],
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        ULONG           *MessageNumber
        );

WINLDAPAPI ULONG LDAPAPI ldap_modify_ext_s(
        LDAP *ld,
        const PCHAR dn,
        LDAPModA *mods[],
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls
        );
#endif

//
//  modrdn and modrdn2 function both as RenameObject and MoveObject.
//
//  Note that to LDAP v2 servers, only rename within a given container
//  is supported... therefore NewDistinguishedName is actually NewRDN.
//  Here are some examples :
//
//  This works to both v2 and v3 servers :
//
//    DN = CN=Bob,OU=FOO,O=BAR
//    NewDN = CN=Joe
//
//    result is: CN=Joe,OU=FOO,O=BAR
//
//  This works to only v3 and above servers :
//
//    DN = CN=Bob,OU=FOO,O=BAR
//    NewDN = CN=Joe,OU=FOOBAR,O=BAR
//
//    result is: CN=Joe,OU=FOOBAR,O=BAR
//
//  If you try the second example to a v2 server, we'll send the whole
//  NewDN over as the new RDN (rather than break up the parent OU and
//  child).  The server will then give you back some unknown error.
//

//
//  multi-thread: ldap_modrdn and ldap_modrdn2 calls are not safe in that
//                the message number is returned rather than the return code.
//                You have to look   at the connection block in an error case
//                and the return code may be overwritten by another thread
//                inbetween.
//
//                Use ldap_rename_ext instead, as these are thread safe.
//

WINLDAPAPI ULONG LDAPAPI ldap_modrdn2W (
    LDAP    *ExternalHandle,
    __in const PWCHAR  DistinguishedName,
    __in const PWCHAR  NewDistinguishedName,
    INT     DeleteOldRdn
    );
WINLDAPAPI ULONG LDAPAPI ldap_modrdn2A (
    LDAP    *ExternalHandle,
    __in const PCHAR   DistinguishedName,
    __in const PCHAR   NewDistinguishedName,
    INT     DeleteOldRdn
    );

//
//  ldap_modrdn simply calls ldap_modrdn2 with a value of 1 for DeleteOldRdn.
//

WINLDAPAPI ULONG LDAPAPI ldap_modrdnW (
    LDAP    *ExternalHandle,
    __in const PWCHAR   DistinguishedName,
    __in const PWCHAR   NewDistinguishedName
    );
WINLDAPAPI ULONG LDAPAPI ldap_modrdnA (
    LDAP    *ExternalHandle,
    __in const PCHAR   DistinguishedName,
    __in const PCHAR   NewDistinguishedName
    );

WINLDAPAPI ULONG LDAPAPI ldap_modrdn2_sW (
    LDAP    *ExternalHandle,
    __in const PWCHAR   DistinguishedName,
    __in const PWCHAR   NewDistinguishedName,
    INT     DeleteOldRdn
    );
WINLDAPAPI ULONG LDAPAPI ldap_modrdn2_sA (
    LDAP    *ExternalHandle,
    __in const PCHAR   DistinguishedName,
    __in const PCHAR   NewDistinguishedName,
    INT     DeleteOldRdn
    );

WINLDAPAPI ULONG LDAPAPI ldap_modrdn_sW (
    LDAP    *ExternalHandle,
    __in const PWCHAR   DistinguishedName,
    __in const PWCHAR   NewDistinguishedName
    );
WINLDAPAPI ULONG LDAPAPI ldap_modrdn_sA (
    LDAP    *ExternalHandle,
    __in const PCHAR   DistinguishedName,
    __in const PCHAR   NewDistinguishedName
    );

#if LDAP_UNICODE

#define ldap_modrdn2 ldap_modrdn2W
#define ldap_modrdn ldap_modrdnW
#define ldap_modrdn2_s ldap_modrdn2_sW
#define ldap_modrdn_s ldap_modrdn_sW

#else

WINLDAPAPI ULONG LDAPAPI ldap_modrdn2 (
    LDAP    *ExternalHandle,
    __in const PCHAR   DistinguishedName,
    __in const PCHAR   NewDistinguishedName,
    INT     DeleteOldRdn
    );
WINLDAPAPI ULONG LDAPAPI ldap_modrdn (
    LDAP    *ExternalHandle,
    __in const PCHAR   DistinguishedName,
    __in const PCHAR   NewDistinguishedName
    );
WINLDAPAPI ULONG LDAPAPI ldap_modrdn2_s (
    LDAP    *ExternalHandle,
    __in const PCHAR   DistinguishedName,
    __in const PCHAR   NewDistinguishedName,
    INT     DeleteOldRdn
    );
WINLDAPAPI ULONG LDAPAPI ldap_modrdn_s (
    LDAP    *ExternalHandle,
    __in const PCHAR   DistinguishedName,
    __in const PCHAR   NewDistinguishedName
    );

#endif

//
//  Extended Rename operations.  These take controls and separate out the
//  parent from the RDN, for clarity.
//

WINLDAPAPI ULONG LDAPAPI ldap_rename_extW(
        LDAP *ld,
        __in const PWCHAR dn,
        __in const PWCHAR NewRDN,
        __in_opt const PWCHAR NewParent,
        INT DeleteOldRdn,
        PLDAPControlW   *ServerControls,
        PLDAPControlW   *ClientControls,
        ULONG           *MessageNumber
        );

WINLDAPAPI ULONG LDAPAPI ldap_rename_extA(
        LDAP *ld,
        __in const PCHAR dn,
        __in const PCHAR NewRDN,
        __in_opt const PCHAR NewParent,
        INT DeleteOldRdn,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        ULONG           *MessageNumber
        );

WINLDAPAPI ULONG LDAPAPI ldap_rename_ext_sW(
        LDAP *ld,
        __in const PWCHAR dn,
        __in const PWCHAR NewRDN,
        __in_opt const PWCHAR NewParent,
        INT DeleteOldRdn,
        PLDAPControlW   *ServerControls,
        PLDAPControlW   *ClientControls
        );

WINLDAPAPI ULONG LDAPAPI ldap_rename_ext_sA(
        LDAP *ld,
        __in const PCHAR dn,
        __in const PCHAR NewRDN,
        __in_opt const PCHAR NewParent,
        INT DeleteOldRdn,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls
        );

#if LDAP_UNICODE

#define ldap_rename   ldap_rename_extW
#define ldap_rename_s ldap_rename_ext_sW

#else

#define ldap_rename   ldap_rename_extA
#define ldap_rename_s ldap_rename_ext_sA

#endif

#if LDAP_UNICODE

#define ldap_rename_ext ldap_rename_extW
#define ldap_rename_ext_s ldap_rename_ext_sW

#else

WINLDAPAPI ULONG LDAPAPI ldap_rename_ext(
        LDAP *ld,
        const PCHAR dn,
        const PCHAR NewRDN,
        const PCHAR NewParent,
        INT DeleteOldRdn,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        ULONG           *MessageNumber
        );

WINLDAPAPI ULONG LDAPAPI ldap_rename_ext_s(
        LDAP *ld,
        const PCHAR dn,
        const PCHAR NewRDN,
        const PCHAR NewParent,
        INT DeleteOldRdn,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls
        );
#endif

//
//  Add an entry to the tree
//

//
//  multi-thread: ldap_add calls are not safe in that the message number
//                is returned rather than the return code.  You have to look
//                at the connection block in an error case and the return code
//                may be overwritten by another thread inbetween.
//
//                Use ldap_add_ext instead, as these are thread safe.
//
//                ldap_add_s and ldap_add_ext* calls are thread safe.
//

WINLDAPAPI ULONG LDAPAPI ldap_addW( LDAP *ld, __in PWCHAR dn, LDAPModW *attrs[] );
WINLDAPAPI ULONG LDAPAPI ldap_addA( LDAP *ld, __in PCHAR dn, LDAPModA *attrs[] );

WINLDAPAPI ULONG LDAPAPI ldap_add_sW( LDAP *ld, __in PWCHAR dn, LDAPModW *attrs[] );
WINLDAPAPI ULONG LDAPAPI ldap_add_sA( LDAP *ld, __in PCHAR dn, LDAPModA *attrs[] );

WINLDAPAPI ULONG LDAPAPI ldap_add_extW(
        LDAP *ld,
        __in const PWCHAR dn,
        LDAPModW *attrs[],
        PLDAPControlW   *ServerControls,
        PLDAPControlW   *ClientControls,
        ULONG           *MessageNumber
        );

WINLDAPAPI ULONG LDAPAPI ldap_add_extA(
        LDAP *ld,
        __in const PCHAR dn,
        LDAPModA *attrs[],
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        ULONG           *MessageNumber
        );

WINLDAPAPI ULONG LDAPAPI ldap_add_ext_sW(
        LDAP *ld,
        __in const PWCHAR dn,
        LDAPModW *attrs[],
        PLDAPControlW   *ServerControls,
        PLDAPControlW   *ClientControls
        );

WINLDAPAPI ULONG LDAPAPI ldap_add_ext_sA(
        LDAP *ld,
        __in const PCHAR dn,
        LDAPModA *attrs[],
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls
        );

#if LDAP_UNICODE

#define ldap_add ldap_addW
#define ldap_add_s ldap_add_sW

#define ldap_add_ext ldap_add_extW
#define ldap_add_ext_s ldap_add_ext_sW

#else

WINLDAPAPI ULONG LDAPAPI ldap_add( LDAP *ld, __in PCHAR dn, LDAPMod *attrs[] );
WINLDAPAPI ULONG LDAPAPI ldap_add_s( LDAP *ld, __in PCHAR dn, LDAPMod *attrs[] );

WINLDAPAPI ULONG LDAPAPI ldap_add_ext(
        LDAP *ld,
        const PCHAR dn,
        LDAPModA *attrs[],
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        ULONG           *MessageNumber
        );

WINLDAPAPI ULONG LDAPAPI ldap_add_ext_s(
        LDAP *ld,
        const PCHAR dn,
        LDAPModA *attrs[],
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls
        );

#endif


//
//  Compare the attribute for a given entry to a known value.
//

//
//  multi-thread: ldap_compare calls are not safe in that the message number
//                is returned rather than the return code.  You have to look
//                at the connection block in an error case and the return code
//                may be overwritten by another thread inbetween.
//
//                Use ldap_compare_ext instead, as these are thread safe.
//
//                ldap_compare_s and ldap_compare_ext* calls are thread safe.
//


WINLDAPAPI ULONG LDAPAPI ldap_compareW( LDAP *ld, __in const PWCHAR dn, __in const PWCHAR attr, __in PWCHAR value );
WINLDAPAPI ULONG LDAPAPI ldap_compareA( LDAP *ld, __in const PCHAR dn, __in const PCHAR attr, __in PCHAR value );

WINLDAPAPI ULONG LDAPAPI ldap_compare_sW( LDAP *ld, __in const PWCHAR dn, __in const PWCHAR attr, __in PWCHAR value );
WINLDAPAPI ULONG LDAPAPI ldap_compare_sA( LDAP *ld, __in const PCHAR dn, __in const PCHAR attr, PCHAR value );

#if LDAP_UNICODE

#define ldap_compare ldap_compareW
#define ldap_compare_s ldap_compare_sW

#else

WINLDAPAPI ULONG LDAPAPI ldap_compare( LDAP *ld, __in const PCHAR dn, __in const PCHAR attr, __in PCHAR value );
WINLDAPAPI ULONG LDAPAPI ldap_compare_s( LDAP *ld, __in const PCHAR dn, __in const PCHAR attr, __in PCHAR value );

#endif

//
//  Extended Compare operations.  These take controls and are thread safe.
//  They also allow you to specify a bval structure for the data, so that it
//  isn't translated from Unicode or ANSI to UTF8.  Allows for comparison of
//  raw binary data.
//
//  Specify either Data or Value as not NULL.  If both are not NULL, the
//  berval Data will be used.
//

WINLDAPAPI ULONG LDAPAPI ldap_compare_extW(
        LDAP *ld,
        __in const PWCHAR dn,
        __in const PWCHAR Attr,
        __in_opt const PWCHAR Value,           // either value or Data is not null, not both
        __in_opt struct berval   *Data,
        PLDAPControlW   *ServerControls,
        PLDAPControlW   *ClientControls,
        ULONG           *MessageNumber
        );

WINLDAPAPI ULONG LDAPAPI ldap_compare_extA(
        LDAP *ld,
        __in const PCHAR dn,
        __in const PCHAR Attr,
        __in_opt const PCHAR Value,            // either value or Data is not null, not both
        __in_opt struct berval   *Data,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        ULONG           *MessageNumber
        );

WINLDAPAPI ULONG LDAPAPI ldap_compare_ext_sW(
        LDAP *ld,
        __in const PWCHAR dn,
        __in const PWCHAR Attr,
        __in_opt const PWCHAR Value,           // either value or Data is not null, not both
        __in_opt struct berval   *Data,
        PLDAPControlW   *ServerControls,
        PLDAPControlW   *ClientControls
        );

WINLDAPAPI ULONG LDAPAPI ldap_compare_ext_sA(
        LDAP *ld,
        __in const PCHAR dn,
        __in const PCHAR Attr,
        __in_opt const PCHAR Value,            // either value or Data is not null, not both
        __in_opt struct berval   *Data,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls
        );

#if LDAP_UNICODE

#define ldap_compare_ext ldap_compare_extW
#define ldap_compare_ext_s ldap_compare_ext_sW

#else

WINLDAPAPI ULONG LDAPAPI ldap_compare_ext(
        LDAP *ld,
        const PCHAR dn,
        const PCHAR Attr,
        const PCHAR Value,            // either value or Data is not null, not both
        struct berval   *Data,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        ULONG           *MessageNumber
        );

WINLDAPAPI ULONG LDAPAPI ldap_compare_ext_s(
        LDAP *ld,
        const PCHAR dn,
        const PCHAR Attr,
        const PCHAR Value,            // either value or Data is not null, not both
        struct berval   *Data,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls
        );
#endif


//
//  Delete an object out of the tree
//

//
//  multi-thread: ldap_delete calls are not safe in that the message number
//                is returned rather than the return code.  You have to look
//                at the connection block in an error case and the return code
//                may be overwritten by another thread inbetween.
//
//                Use ldap_delete_ext instead, as these are thread safe.
//
//                ldap_delete_s and ldap_delete_ext* calls are thread safe.
//


WINLDAPAPI ULONG LDAPAPI ldap_deleteW( LDAP *ld, __in const PWCHAR dn );
WINLDAPAPI ULONG LDAPAPI ldap_deleteA( LDAP *ld, __in const PCHAR dn );

WINLDAPAPI ULONG LDAPAPI ldap_delete_sW( LDAP *ld, __in const PWCHAR dn );
WINLDAPAPI ULONG LDAPAPI ldap_delete_sA( LDAP *ld, __in const PCHAR dn );

WINLDAPAPI ULONG LDAPAPI ldap_delete_extW(
        LDAP *ld,
        __in const PWCHAR dn,
        PLDAPControlW   *ServerControls,
        PLDAPControlW   *ClientControls,
        ULONG           *MessageNumber
        );

WINLDAPAPI ULONG LDAPAPI ldap_delete_extA(
        LDAP *ld,
        __in const PCHAR dn,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        ULONG           *MessageNumber
        );

WINLDAPAPI ULONG LDAPAPI ldap_delete_ext_sW(
        LDAP *ld,
        __in const PWCHAR dn,
        PLDAPControlW   *ServerControls,
        PLDAPControlW   *ClientControls
        );

WINLDAPAPI ULONG LDAPAPI ldap_delete_ext_sA(
        LDAP *ld,
        __in const PCHAR dn,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls
        );

#if LDAP_UNICODE

#define ldap_delete ldap_deleteW
#define ldap_delete_ext ldap_delete_extW
#define ldap_delete_s ldap_delete_sW
#define ldap_delete_ext_s ldap_delete_ext_sW

#else

WINLDAPAPI ULONG LDAPAPI ldap_delete( LDAP *ld, __in PCHAR dn );
WINLDAPAPI ULONG LDAPAPI ldap_delete_s( LDAP *ld, __in PCHAR dn );

WINLDAPAPI ULONG LDAPAPI ldap_delete_ext(
        LDAP *ld,
        const PCHAR dn,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        ULONG           *MessageNumber
        );

WINLDAPAPI ULONG LDAPAPI ldap_delete_ext_s(
        LDAP *ld,
        const PCHAR dn,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls
        );
#endif



//
//  Give up on a request.  No guarentee that it got there as there is no
//  response from the server.
//

//  multi-thread: ldap_abandon calls are thread safe

WINLDAPAPI ULONG LDAPAPI ldap_abandon( LDAP *ld, ULONG msgid );



//
//  Possible values for "all" field in ldap_result.  We've enhanced it such
//  that if someone passes in LDAP_MSG_RECEIVED, we'll pass all values we've
//  received up to that point.
//

#define LDAP_MSG_ONE    0
#define LDAP_MSG_ALL    1
#define LDAP_MSG_RECEIVED  2

//
//  Get a response from a connection.  One enhancement here is that ld can
//  be null, in which case we'll return responses from any server.  Free
//  responses here with ldap_msgfree.
//
//  For connection-less LDAP, you should pass in both a LDAP connection
//  handle and a msgid.  This will ensure we know which request the app
//  is waiting on a reply to.  ( we actively resend request until we get
//  a response.)
//

//  multi-thread: ldap_result calls are thread safe

WINLDAPAPI ULONG LDAPAPI ldap_result(
        LDAP            *ld,
        ULONG           msgid,
        ULONG           all,
        struct l_timeval  *timeout,
        LDAPMessage     **res
    );

WINLDAPAPI ULONG LDAPAPI ldap_msgfree( LDAPMessage *res );

//
//  This parses a message and returns the error code.  It optionally frees
//  the message by calling ldap_msgfree.
//

//  multi-thread: ldap_result2error call is thread safe

WINLDAPAPI ULONG LDAPAPI ldap_result2error(
        LDAP            *ld,
        LDAPMessage     *res,
        ULONG           freeit      // boolean.. free the message?
    );


//
//  Similar to ldap_result2error, this parses responses from the server and
//  returns the appropriate fields.  Use this one if you want to get at the
//  referrals, matchingDNs, or server controls returned.
//

//  multi-thread: ldap_parse_result call is thread safe

WINLDAPAPI ULONG LDAPAPI ldap_parse_resultW (
        LDAP *Connection,
        LDAPMessage *ResultMessage,
        ULONG *ReturnCode OPTIONAL,          // returned by server
        __deref_opt_out_opt PWCHAR *MatchedDNs OPTIONAL,         // free with ldap_memfree
        __deref_opt_out_opt PWCHAR *ErrorMessage OPTIONAL,       // free with ldap_memfree
        __deref_opt_out_opt PWCHAR **Referrals OPTIONAL,         // free with ldap_value_freeW
        PLDAPControlW **ServerControls OPTIONAL,    // free with ldap_free_controlsW
        BOOLEAN Freeit
        );

WINLDAPAPI ULONG LDAPAPI ldap_parse_resultA (
        LDAP *Connection,
        LDAPMessage *ResultMessage,
        ULONG *ReturnCode OPTIONAL,         // returned by server
        __deref_opt_out_opt PCHAR *MatchedDNs OPTIONAL,         // free with ldap_memfree
        __deref_opt_out_opt PCHAR *ErrorMessage OPTIONAL,       // free with ldap_memfree
        __deref_opt_out_opt PCHAR **Referrals OPTIONAL,         // free with ldap_value_freeA
        PLDAPControlA **ServerControls OPTIONAL,    // free with ldap_free_controlsA
        BOOLEAN Freeit
        );

WINLDAPAPI ULONG LDAPAPI ldap_parse_extended_resultA (
        LDAP           *Connection,
        LDAPMessage    *ResultMessage,      // returned by server
        __deref_opt_out_opt PCHAR          *ResultOID,          // free with ldap_memfree
        struct berval **ResultData,         // free with ldap_memfree
        BOOLEAN         Freeit              // Don't need the message anymore
        );

WINLDAPAPI ULONG LDAPAPI ldap_parse_extended_resultW (
        LDAP           *Connection,
        LDAPMessage    *ResultMessage,      // returned by server
        __deref_opt_out_opt PWCHAR          *ResultOID,         // free with ldap_memfree
        struct berval **ResultData,         // free with ldap_memfree
        BOOLEAN         Freeit              // Don't need the message anymore
        );

WINLDAPAPI ULONG LDAPAPI ldap_controls_freeA (
        LDAPControlA **Controls
        );

WINLDAPAPI ULONG LDAPAPI ldap_control_freeA (
        LDAPControlA *Controls
        );

WINLDAPAPI ULONG LDAPAPI ldap_controls_freeW (
        LDAPControlW **Control
        );

WINLDAPAPI ULONG LDAPAPI ldap_control_freeW (
        LDAPControlW *Control
        );

//
// ldap_free_controls are old, use ldap_controls_free
//

WINLDAPAPI ULONG LDAPAPI ldap_free_controlsW (
        LDAPControlW **Controls
        );

WINLDAPAPI ULONG LDAPAPI ldap_free_controlsA (
        LDAPControlA **Controls
        );

#if LDAP_UNICODE

#define ldap_parse_result ldap_parse_resultW
#define ldap_controls_free ldap_controls_freeW
#define ldap_control_free ldap_control_freeW
#define ldap_free_controls ldap_free_controlsW
#define ldap_parse_extended_result ldap_parse_extended_resultW

#else

#define ldap_parse_extended_result ldap_parse_extended_resultA

WINLDAPAPI ULONG LDAPAPI ldap_parse_result (
        LDAP *Connection,
        LDAPMessage *ResultMessage,
        ULONG *ReturnCode OPTIONAL,         // returned by server
        PCHAR *MatchedDNs OPTIONAL,         // free with ldap_memfree
        PCHAR *ErrorMessage OPTIONAL,       // free with ldap_memfree
        PCHAR **Referrals OPTIONAL,         // free with ldap_value_free
        PLDAPControlA **ServerControls OPTIONAL,    // free with ldap_free_controls
        BOOLEAN Freeit
        );

WINLDAPAPI ULONG LDAPAPI ldap_controls_free (
        LDAPControlA **Controls
        );

WINLDAPAPI ULONG LDAPAPI ldap_control_free (
        LDAPControlA *Control
        );

WINLDAPAPI ULONG LDAPAPI ldap_free_controls (
        LDAPControlA **Controls
        );

#endif

//
//  ldap_err2string returns a pointer to a string describing the error.  This
//  string should not be freed.
//

WINLDAPAPI PWCHAR LDAPAPI ldap_err2stringW( ULONG err );
WINLDAPAPI PCHAR LDAPAPI ldap_err2stringA( ULONG err );

#if LDAP_UNICODE

#define ldap_err2string ldap_err2stringW

#else

WINLDAPAPI PCHAR LDAPAPI ldap_err2string( ULONG err );

#endif

//
//  ldap_perror does nothing and is here just for compatibility.
//

WINLDAPAPI void LDAPAPI ldap_perror( LDAP *ld, __in const PCHAR msg );

//
//  Return the first entry of a message.  It is freed when the message is
//  freed so should not be freed explicitly.
//

WINLDAPAPI LDAPMessage *LDAPAPI ldap_first_entry( LDAP *ld, LDAPMessage *res );

//
//  Return the next entry of a message.  It is freed when the message is
//  freed so should not be freed explicitly.
//

WINLDAPAPI LDAPMessage *LDAPAPI ldap_next_entry( LDAP *ld, LDAPMessage *entry );

//
//  Count the number of search entries returned by the server in a response
//  to a server request.
//

WINLDAPAPI ULONG LDAPAPI ldap_count_entries( LDAP *ld, LDAPMessage *res );

//
//  A BerElement really maps out to a C++ class object that does BER encoding.
//  Don't mess with it as it's opaque.
//

typedef struct berelement {
    PCHAR   opaque;     // this is an opaque structure used just for
                        // compatibility with reference implementation
} BerElement;
#define NULLBER ((BerElement *) 0)

//
//  For a given entry, return the first attribute.  The pointer returned is
//  actually a buffer in the connection block (with allowances for
//  multi-threaded apps) so it should not be freed.
//

WINLDAPAPI PWCHAR LDAPAPI ldap_first_attributeW(
        LDAP            *ld,
        LDAPMessage     *entry,
        BerElement      **ptr
        );

WINLDAPAPI PCHAR LDAPAPI ldap_first_attributeA(
        LDAP            *ld,
        LDAPMessage     *entry,
        BerElement      **ptr
        );

#if LDAP_UNICODE

#define ldap_first_attribute ldap_first_attributeW

#else

WINLDAPAPI PCHAR LDAPAPI ldap_first_attribute(
        LDAP            *ld,
        LDAPMessage     *entry,
        BerElement      **ptr
        );
#endif

//
//  Return the next attribute... again, the attribute pointer should not be
//  freed.
//

WINLDAPAPI PWCHAR LDAPAPI ldap_next_attributeW(
        LDAP            *ld,
        LDAPMessage     *entry,
        BerElement      *ptr
        );

WINLDAPAPI PCHAR LDAPAPI ldap_next_attributeA(
        LDAP            *ld,
        LDAPMessage     *entry,
        BerElement      *ptr
        );


#if LDAP_UNICODE

#define ldap_next_attribute ldap_next_attributeW

#else

WINLDAPAPI PCHAR LDAPAPI ldap_next_attribute(
        LDAP            *ld,
        LDAPMessage     *entry,
        BerElement      *ptr
        );
#endif

//
//  Get a given attribute's list of values.  This is used during parsing of
//  a search response.  It returns a list of pointers to values, the list is
//  null terminated.
//
//  If the values are generic octet strings and not null terminated strings,
//  use ldap_get_values_len instead.
//
//  The returned value should be freed when your done with it by calling
//  ldap_value_free.
//

WINLDAPAPI PWCHAR *LDAPAPI ldap_get_valuesW(
        LDAP            *ld,
        LDAPMessage     *entry,
        __in const PWCHAR          attr
        );
WINLDAPAPI PCHAR *LDAPAPI ldap_get_valuesA(
        LDAP            *ld,
        LDAPMessage     *entry,
        __in const PCHAR           attr
        );

#if LDAP_UNICODE

#define ldap_get_values ldap_get_valuesW

#else

WINLDAPAPI PCHAR *LDAPAPI ldap_get_values(
        LDAP            *ld,
        LDAPMessage     *entry,
        __in const PCHAR           attr
        );
#endif




//
//  Get a given attribute's list of values.  This is used during parsing of
//  a search response.  It returns a list of berval structures to values,
//  the list is null terminated.
//
//  If the values are null terminated strings, it may be easier to process them
//  by calling ldap_get_values instead.
//
//  The returned value should be freed when your done with it by calling
//  ldap_value_free_len.
//

WINLDAPAPI struct berval **LDAPAPI ldap_get_values_lenW (
    LDAP            *ExternalHandle,
    LDAPMessage     *Message,
    __in const PWCHAR          attr
    );
WINLDAPAPI struct berval **LDAPAPI ldap_get_values_lenA (
    LDAP            *ExternalHandle,
    LDAPMessage     *Message,
    __in const PCHAR           attr
    );

#if LDAP_UNICODE

#define ldap_get_values_len ldap_get_values_lenW

#else

WINLDAPAPI struct berval **LDAPAPI ldap_get_values_len (
    LDAP            *ExternalHandle,
    LDAPMessage     *Message,
    __in const PCHAR           attr
    );

#endif


//
//  Return the number of values in a list returned by ldap_get_values.
//

WINLDAPAPI ULONG LDAPAPI ldap_count_valuesW( __in_opt PWCHAR *vals );
WINLDAPAPI ULONG LDAPAPI ldap_count_valuesA( __in_opt PCHAR *vals );

#if LDAP_UNICODE

#define ldap_count_values ldap_count_valuesW

#else

WINLDAPAPI ULONG LDAPAPI ldap_count_values( __in_opt PCHAR *vals );

#endif



//
//  Return the number of values in a list returned by ldap_get_values_len.
//

WINLDAPAPI ULONG LDAPAPI ldap_count_values_len( struct berval **vals );

//
//  Free structures returned by ldap_get_values.
//

WINLDAPAPI ULONG LDAPAPI ldap_value_freeW( __in_opt PWCHAR *vals );
WINLDAPAPI ULONG LDAPAPI ldap_value_freeA( __in_opt PCHAR *vals );

#if LDAP_UNICODE

#define ldap_value_free ldap_value_freeW

#else

WINLDAPAPI ULONG LDAPAPI ldap_value_free( __in_opt PCHAR *vals );

#endif



//
//  Free structures returned by ldap_get_values_len.
//

WINLDAPAPI ULONG LDAPAPI ldap_value_free_len( struct berval **vals );

//
//  Get the distinguished name for a given search entry.  It should be freed
//  by calling ldap_memfree.
//

WINLDAPAPI PWCHAR LDAPAPI ldap_get_dnW( LDAP *ld, LDAPMessage *entry );
WINLDAPAPI PCHAR LDAPAPI ldap_get_dnA( LDAP *ld, LDAPMessage *entry );

#if LDAP_UNICODE

#define ldap_get_dn ldap_get_dnW

#else

WINLDAPAPI PCHAR LDAPAPI ldap_get_dn( LDAP *ld, LDAPMessage *entry );

#endif


//
//  When using ldap_explode_dn, you should free the returned string by
//  calling ldap_value_free.
//

WINLDAPAPI PWCHAR *LDAPAPI ldap_explode_dnW( __in const PWCHAR dn, ULONG notypes );
WINLDAPAPI PCHAR *LDAPAPI ldap_explode_dnA( __in const PCHAR dn, ULONG notypes );

#if LDAP_UNICODE

#define ldap_explode_dn ldap_explode_dnW

#else

WINLDAPAPI PCHAR *LDAPAPI ldap_explode_dn( __in const PCHAR dn, ULONG notypes );

#endif


//
//  When calling ldap_dn2ufn, you should free the returned string by calling
//  ldap_memfree.
//

WINLDAPAPI PWCHAR LDAPAPI ldap_dn2ufnW( __in const PWCHAR dn );
WINLDAPAPI PCHAR LDAPAPI ldap_dn2ufnA( __in const PCHAR dn );

#if LDAP_UNICODE

#define ldap_dn2ufn ldap_dn2ufnW

#else

WINLDAPAPI PCHAR LDAPAPI ldap_dn2ufn( __in const PCHAR dn );

#endif



//
//  This is used to free strings back to the LDAP API heap.  Don't pass in
//  values that you've gotten from ldap_open, ldap_get_values, etc.
//

WINLDAPAPI VOID LDAPAPI ldap_memfreeW( __in PWCHAR Block );
WINLDAPAPI VOID LDAPAPI ldap_memfreeA( __in PCHAR Block );

WINLDAPAPI VOID LDAPAPI ber_bvfree( struct berval *bv );

#if LDAP_UNICODE

#define ldap_memfree ldap_memfreeW

#else

WINLDAPAPI VOID LDAPAPI ldap_memfree( __in PCHAR Block );

#endif


//
//  The function ldap_ufn2dn attempts to "normalize" a user specified DN
//  to make it "proper".  It follows RFC 1781 (add CN= if not present,
//  add OU= if none present, etc).  If it runs into any problems at all
//  while normalizing, it simply returns a copy of what was passed in.
//
//  It allocates the output string from the LDAP memory pool.  If the pDn
//  comes back as non-NULL, you should free it when you're done with a call
//  to ldap_memfree.
//

WINLDAPAPI ULONG LDAPAPI ldap_ufn2dnW (
    __in const PWCHAR ufn,
    __deref_out PWCHAR *pDn
    );
WINLDAPAPI ULONG LDAPAPI ldap_ufn2dnA (
    __in const PCHAR ufn,
    __deref_out PCHAR *pDn
    );

#if LDAP_UNICODE

#define ldap_ufn2dn ldap_ufn2dnW

#else

WINLDAPAPI ULONG LDAPAPI ldap_ufn2dn (
    __in const PCHAR ufn,
    __deref_out PCHAR *pDn
    );

#endif

#define LBER_USE_DER        0x01
#define LBER_USE_INDEFINITE_LEN 0x02
#define LBER_TRANSLATE_STRINGS  0x04

//
//  Call to initialize the LDAP library.  Pass in a version structure with
//  lv_size set to sizeof( LDAP_VERSION ), lv_major set to LAPI_MAJOR_VER1,
//  and lv_minor set to LAPI_MINOR_VER1.  Return value will be either
//  LDAP_SUCCESS if OK or LDAP_OPERATIONS_ERROR if can't be supported.
//

#define LAPI_MAJOR_VER1     1
#define LAPI_MINOR_VER1     1

typedef struct ldap_version_info {
     ULONG   lv_size;
     ULONG   lv_major;
     ULONG   lv_minor;
} LDAP_VERSION_INFO, *PLDAP_VERSION_INFO;

WINLDAPAPI ULONG LDAPAPI ldap_startup (
    PLDAP_VERSION_INFO version,
    HANDLE *Instance
    );


//
// Calls to retrieve basic information about the API and specific implementations
// being used. The caller has to pass the LDAP_OPT_API_INFO option along with 
// a pointer to the following structure to retrieve information about this library.
// It is the caller's responsibility to free the individual strings and string
// arrays in the structure using ldap_memfree() and ldap_value_free() respectively.
//

#define LDAP_API_INFO_VERSION     1
#define LDAP_API_VERSION          2004
#define LDAP_VERSION_MIN          2
#define LDAP_VERSION_MAX          3
#define LDAP_VENDOR_NAME          "Microsoft Corporation."
#define LDAP_VENDOR_NAME_W       L"Microsoft Corporation."
#define LDAP_VENDOR_VERSION       510

typedef struct ldapapiinfoA {
    
    int  ldapai_info_version;     /* version of this struct: LDAP_API_INFO_VERSION */
    int  ldapai_api_version;      /* revision of API supported */
    int  ldapai_protocol_version; /* highest LDAP version supported */
    char **ldapai_extensions;     /* names of API extensions */
    char *ldapai_vendor_name;     /* name of supplier */
    int  ldapai_vendor_version;   /* supplier-specific version times 100 */

} LDAPAPIInfoA;

typedef struct ldapapiinfoW {
    
    int    ldapai_info_version;     /* version of this struct: LDAP_API_INFO_VERSION */
    int    ldapai_api_version;      /* revision of API supported */
    int    ldapai_protocol_version; /* highest LDAP version supported */
    PWCHAR *ldapai_extensions;     /* names of API extensions */
    PWCHAR ldapai_vendor_name;     /* name of supplier */
    int    ldapai_vendor_version;   /* supplier-specific version times 100 */

} LDAPAPIInfoW;

#define LDAP_FEATURE_INFO_VERSION    1

typedef struct ldap_apifeature_infoA {
    
    int   ldapaif_info_version; /* version of this struct : LDAP_FEATURE_INFO_VERSION */
    char  *ldapaif_name;        /* name of supported feature */
    int   ldapaif_version;      /* revision of supported feature */

} LDAPAPIFeatureInfoA;

typedef struct ldap_apifeature_infoW {
    
    int    ldapaif_info_version; /* version of this struct : LDAP_FEATURE_INFO_VERSION */
    PWCHAR ldapaif_name;         /* name of supported feature */
    int    ldapaif_version;      /* revision of supported feature */

} LDAPAPIFeatureInfoW;

#if LDAP_UNICODE

#define LDAPAPIInfo   LDAPAPIInfoW
#define LDAPAPIFeatureInfo  LDAPAPIFeatureInfoW

#else

#define LDAPAPIInfo   LDAPAPIInfoA
#define LDAPAPIFeatureInfo  LDAPAPIFeatureInfoA

#endif

//
//  ldap_cleanup unloads the library when the refcount of opens goes to zero.
//  (i.e. if a DLL calls it within a program that is also using it, it won't
//  free all resources)
//

WINLDAPAPI ULONG LDAPAPI ldap_cleanup (
    HANDLE hInstance
    );

//
//  Extended API to support allowing opaque blobs of data in search filters.
//  This API takes any filter element and converts it to a safe text string that
//  can safely be passed in a search filter.
//  An example of using this is :
//
//  filter is something like guid=4826BF6CF0123444
//  this will put out on the wire guid of binary 0x4826BF6CF0123444
//
//  call ldap_escape_filter_element with sourceFilterElement pointing to
//  raw data, sourceCount set appropriately to length of data.
//
//  if destFilterElement is NULL, then return value is length required for
//  output buffer.
//
//  if destFilterElement is not NULL, then the function will copy the source
//  into the dest buffer and ensure that it is of a safe format.
//
//  then simply insert the dest buffer into your search filter after the
//  "attributetype=".
//
//  this will put out on the wire guid of binary 0x004826BF6CF000123444
//
//  Note : don't call this for attribute values that are really strings, as
//  we won't do any conversion from what you passed in to UTF-8.  Should only
//  be used for attributes that really are raw binary.
//

WINLDAPAPI ULONG LDAPAPI ldap_escape_filter_elementW (
   __in_bcount(sourceLength) PCHAR   sourceFilterElement,
   ULONG   sourceLength,
   __out_bcount_opt(destLength) PWCHAR   destFilterElement,
   ULONG   destLength
   );
WINLDAPAPI ULONG LDAPAPI ldap_escape_filter_elementA (
   __in_bcount(sourceLength) PCHAR   sourceFilterElement,
   ULONG   sourceLength,
   __out_bcount_opt(destLength) PCHAR   destFilterElement,
   ULONG   destLength
   );

#if LDAP_UNICODE

#define ldap_escape_filter_element ldap_escape_filter_elementW

#else

WINLDAPAPI ULONG LDAPAPI ldap_escape_filter_element (
   __in_bcount(sourceLength) PCHAR   sourceFilterElement,
   ULONG   sourceLength,
   __out_bcount_opt(destLength) PCHAR   destFilterElement,
   ULONG   destLength
   );

#endif

//
//  Misc extensions for additional debugging.
//
//  Note that these do nothing on free builds.
//

WINLDAPAPI ULONG LDAPAPI ldap_set_dbg_flags( ULONG NewFlags );

typedef ULONG (_cdecl *DBGPRINT)( PCCH Format, ... );

WINLDAPAPI VOID LDAPAPI ldap_set_dbg_routine( DBGPRINT DebugPrintRoutine );

//
//  These routines are possibly useful by other modules.  Note that Win95
//  doesn't by default have the UTF-8 codepage loaded.  So a good way to
//  convert from UTF-8 to Unicode.
//


WINLDAPAPI int LDAPAPI
LdapUTF8ToUnicode(
    __in_ecount(cchSrc) LPCSTR lpSrcStr,
    int cchSrc,
    __out_ecount(cchDest) LPWSTR lpDestStr,
    int cchDest
    );

WINLDAPAPI
int LDAPAPI
LdapUnicodeToUTF8(
    __in_ecount(cchSrc) LPCWSTR lpSrcStr,
    int cchSrc,
    __out_ecount(cchDest) LPSTR lpDestStr,
    int cchDest
    );

//
//  LDAPv3 features :
//
//  Sort Keys... these are used to ask the server to sort the results
//  before sending the results back.  LDAPv3 only and optional to implement
//  on the server side.  Check supportedControl for an OID of
//  "1.2.840.113556.1.4.473" to see if the server supports it.
//

#define LDAP_SERVER_SORT_OID "1.2.840.113556.1.4.473"
#define LDAP_SERVER_SORT_OID_W L"1.2.840.113556.1.4.473"

#define LDAP_SERVER_RESP_SORT_OID "1.2.840.113556.1.4.474"
#define LDAP_SERVER_RESP_SORT_OID_W L"1.2.840.113556.1.4.474"

typedef struct ldapsearch LDAPSearch, *PLDAPSearch;

typedef struct ldapsortkeyW {

    PWCHAR  sk_attrtype;
    PWCHAR  sk_matchruleoid;
    BOOLEAN sk_reverseorder;

} LDAPSortKeyW, *PLDAPSortKeyW;

typedef struct ldapsortkeyA {

    PCHAR   sk_attrtype;
    PCHAR   sk_matchruleoid;
    BOOLEAN sk_reverseorder;

} LDAPSortKeyA, *PLDAPSortKeyA;

#if LDAP_UNICODE
#define LDAPSortKey LDAPSortKeyW
#define PLDAPSortKey PLDAPSortKeyW
#else
#define LDAPSortKey LDAPSortKeyA
#define PLDAPSortKey PLDAPSortKeyA
#endif

//
//  This API formats a list of sort keys into a search control.  Call
//  ldap_control_free when you're finished with the control.
//
//  Use this one rather than ldap_encode_sort_control as this is per RFC.
//

WINLDAPAPI ULONG LDAPAPI ldap_create_sort_controlA (
        PLDAP           ExternalHandle,
        PLDAPSortKeyA  *SortKeys,
        UCHAR           IsCritical,
        PLDAPControlA  *Control
        );

WINLDAPAPI ULONG LDAPAPI ldap_create_sort_controlW (
        PLDAP           ExternalHandle,
        PLDAPSortKeyW  *SortKeys,
        UCHAR           IsCritical,
        PLDAPControlW  *Control
        );

//
//  This API parses the sort control returned by the server.  Use ldap_memfree
//  to free the attribute value, if it's returned.
//

WINLDAPAPI ULONG LDAPAPI ldap_parse_sort_controlA (
        PLDAP           ExternalHandle,
        PLDAPControlA  *Control,
        ULONG          *Result,
        __deref_opt_out_opt PCHAR          *Attribute
        );

WINLDAPAPI ULONG LDAPAPI ldap_parse_sort_controlW (
        PLDAP           ExternalHandle,
        PLDAPControlW  *Control,
        ULONG          *Result,
        __deref_opt_out_opt PWCHAR         *Attribute
        );

#if LDAP_UNICODE

#define ldap_create_sort_control ldap_create_sort_controlW
#define ldap_parse_sort_control ldap_parse_sort_controlW

#else

WINLDAPAPI ULONG LDAPAPI ldap_create_sort_control (
        PLDAP           ExternalHandle,
        PLDAPSortKeyA  *SortKeys,
        UCHAR           IsCritical,
        PLDAPControlA  *Control
        );

WINLDAPAPI ULONG LDAPAPI ldap_parse_sort_control (
        PLDAP           ExternalHandle,
        PLDAPControlA  *Control,
        ULONG          *Result,
        PCHAR          *Attribute
        );
#endif

//
//  This API formats a list of sort keys into a search control.  Call
//  ldap_memfree for both Control->ldctl_value.bv_val and
//  Control->currentControl->ldctl_oid when you're finished with the control.
//
//  This is the old sort API that will be shortly pulled.  Please use
//  ldap_create_sort_control defined above.
//

WINLDAPAPI ULONG LDAPAPI ldap_encode_sort_controlW (
        PLDAP           ExternalHandle,
        PLDAPSortKeyW  *SortKeys,
        PLDAPControlW  Control,
        BOOLEAN Criticality
        );

WINLDAPAPI ULONG LDAPAPI ldap_encode_sort_controlA (
        PLDAP           ExternalHandle,
        PLDAPSortKeyA  *SortKeys,
        PLDAPControlA  Control,
        BOOLEAN Criticality
        );

#if LDAP_UNICODE

#define ldap_encode_sort_control ldap_encode_sort_controlW

#else

WINLDAPAPI ULONG LDAPAPI ldap_encode_sort_control (
        PLDAP           ExternalHandle,
        PLDAPSortKeyA  *SortKeys,
        PLDAPControlA  Control,
        BOOLEAN Criticality
        );
#endif

//
//  LDAPv3: This is the RFC defined API for the simple paging of results
//  control.  Use ldap_control_free to free the control allocated by
//  ldap_create_page_control.
//

WINLDAPAPI ULONG LDAPAPI ldap_create_page_controlW(
        PLDAP           ExternalHandle,
        ULONG           PageSize,
        struct berval  *Cookie,
        UCHAR           IsCritical,
        PLDAPControlW  *Control
        );

WINLDAPAPI ULONG LDAPAPI ldap_create_page_controlA(
        PLDAP           ExternalHandle,
        ULONG           PageSize,
        struct berval  *Cookie,
        UCHAR           IsCritical,
        PLDAPControlA  *Control
        );

WINLDAPAPI ULONG LDAPAPI ldap_parse_page_controlW (
        PLDAP           ExternalHandle,
        PLDAPControlW  *ServerControls,
        ULONG          *TotalCount,
        struct berval  **Cookie     // Use ber_bvfree to free
        );

WINLDAPAPI ULONG LDAPAPI ldap_parse_page_controlA (
        PLDAP           ExternalHandle,
        PLDAPControlA  *ServerControls,
        ULONG          *TotalCount,
        struct berval  **Cookie     // Use ber_bvfree to free
        );

#if LDAP_UNICODE

#define ldap_create_page_control ldap_create_page_controlW
#define ldap_parse_page_control  ldap_parse_page_controlW

#else

WINLDAPAPI ULONG LDAPAPI ldap_create_page_control(
        PLDAP           ExternalHandle,
        ULONG           PageSize,
        struct berval  *Cookie,
        UCHAR           IsCritical,
        PLDAPControlA  *Control
        );

WINLDAPAPI ULONG LDAPAPI ldap_parse_page_control (
        PLDAP           ExternalHandle,
        PLDAPControlA  *ServerControls,
        ULONG          *TotalCount,
        struct berval  **Cookie     // Use ber_bvfree to free
        );
#endif

//
//  LDAPv3: This is the interface for simple paging of results.  To ensure
//  that the server supports it, check the supportedControl property off of
//  the root for an OID of 1.2.840.113556.1.4.319.  If it is there, then it
//  supports this feature.
//
//  If you're going to specify sort keys, see section above on sort keys on
//  now to tell if they're supported by the server.
//
//  You first call ldap_search_init_page.  If it returns a non-NULL LDAPSearch
//  block, then it worked ok.  Otherwise call LdapGetLastError to find error.
//
//  With a valid LDAPSearch block (there are opaque), call ldap_get_next_page
//  or ldap_get_next_page_s.  If you call ldap_get_next_page, you MUST call
//  ldap_get_paged_count for each set of results that you get for that message.
//  This allows the library to save off the cookie that the server sent to
//  resume the search.
//
//  Other than calling ldap_get_paged_count, the results you get back from
//  ldap_get_next_page can be treated as any other search result, and should
//  be freed when you're done by calling ldap_msgfree.
//
//  When the end of the search is hit, you'll get a return code of
//  LDAP_NO_RESULTS_RETURNED.  At this point, (or any point after LDAPSearch
//  structure has been allocated), you call ldap_search_abandon_page.  You
//  need to call this even after you get a return code of
//  LDAP_NO_RESULTS_RETURNED.
//
//  If you call ldap_get_next_page_s, you don't need to call
//  ldap_get_paged_count.
//

#define LDAP_PAGED_RESULT_OID_STRING "1.2.840.113556.1.4.319"
#define LDAP_PAGED_RESULT_OID_STRING_W L"1.2.840.113556.1.4.319"

WINLDAPAPI PLDAPSearch LDAPAPI ldap_search_init_pageW(
        PLDAP           ExternalHandle,
        __in const PWCHAR    DistinguishedName,
        ULONG           ScopeOfSearch,
        __in const PWCHAR    SearchFilter,
        __in PWCHAR          AttributeList[],
        ULONG           AttributesOnly,
        PLDAPControlW   *ServerControls,
        PLDAPControlW   *ClientControls,
        ULONG           PageTimeLimit,
        ULONG           TotalSizeLimit,
        PLDAPSortKeyW  *SortKeys
    );

WINLDAPAPI PLDAPSearch LDAPAPI ldap_search_init_pageA(
        PLDAP           ExternalHandle,
        __in const PCHAR     DistinguishedName,
        ULONG           ScopeOfSearch,
        __in const PCHAR     SearchFilter,
        __in PCHAR           AttributeList[],
        ULONG           AttributesOnly,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        ULONG           PageTimeLimit,
        ULONG           TotalSizeLimit,
        PLDAPSortKeyA  *SortKeys
    );

#if LDAP_UNICODE

#define ldap_search_init_page ldap_search_init_pageW

#else

WINLDAPAPI PLDAPSearch LDAPAPI ldap_search_init_page(
        PLDAP           ExternalHandle,
        const PCHAR     DistinguishedName,
        ULONG           ScopeOfSearch,
        const PCHAR     SearchFilter,
        PCHAR           AttributeList[],
        ULONG           AttributesOnly,
        PLDAPControl    *ServerControls,
        PLDAPControl    *ClientControls,
        ULONG           PageTimeLimit,
        ULONG           TotalSizeLimit,
        PLDAPSortKey    *SortKeys
    );

#endif

WINLDAPAPI ULONG LDAPAPI ldap_get_next_page(
        PLDAP           ExternalHandle,
        PLDAPSearch     SearchHandle,
        ULONG           PageSize,
        ULONG          *MessageNumber
    );

WINLDAPAPI ULONG LDAPAPI ldap_get_next_page_s(
        PLDAP           ExternalHandle,
        PLDAPSearch     SearchHandle,
        struct l_timeval  *timeout,
        ULONG           PageSize,
        ULONG          *TotalCount,
        LDAPMessage     **Results
    );

WINLDAPAPI ULONG LDAPAPI ldap_get_paged_count(
        PLDAP           ExternalHandle,
        PLDAPSearch     SearchBlock,
        ULONG          *TotalCount,
        PLDAPMessage    Results
    );

WINLDAPAPI ULONG LDAPAPI ldap_search_abandon_page(
        PLDAP           ExternalHandle,
        PLDAPSearch     SearchBlock
    );


//
// The Virtual List View (VLV) functions are used to simulate an address book
// like client scenario where the user can request a small window of results
// within a larger result set. The advantage of this method is that the client
// does not have to store all of the results sent back from the server. This
// also acts as a superset of simple paging.
//

#define LDAP_CONTROL_VLVREQUEST       "2.16.840.1.113730.3.4.9"
#define LDAP_CONTROL_VLVREQUEST_W    L"2.16.840.1.113730.3.4.9"

#define LDAP_CONTROL_VLVRESPONSE      "2.16.840.1.113730.3.4.10"
#define LDAP_CONTROL_VLVRESPONSE_W   L"2.16.840.1.113730.3.4.10"

//
// This library supports the version 01 of the internet draft 
// draft-smith-ldap-c-api-ext-vlv-01.txt
//

#define LDAP_API_FEATURE_VIRTUAL_LIST_VIEW   1001

#define LDAP_VLVINFO_VERSION        1

typedef struct ldapvlvinfo {
    
    int       ldvlv_version;    // version of this struct (1)
    ULONG     ldvlv_before_count;
    ULONG     ldvlv_after_count;
    ULONG     ldvlv_offset;     // used if ldvlv_attrvalue is NULL
    ULONG     ldvlv_count;      // used if ldvlv_attrvalue is NULL
    PBERVAL   ldvlv_attrvalue;
    PBERVAL   ldvlv_context;
    VOID      *ldvlv_extradata; // for use by application

} LDAPVLVInfo, *PLDAPVLVInfo;


WINLDAPAPI INT LDAPAPI ldap_create_vlv_controlW (
        PLDAP             ExternalHandle,
        PLDAPVLVInfo      VlvInfo,
        UCHAR             IsCritical,
        PLDAPControlW    *Control
    );

WINLDAPAPI INT LDAPAPI ldap_create_vlv_controlA (
        PLDAP             ExternalHandle,
        PLDAPVLVInfo      VlvInfo,
        UCHAR             IsCritical,
        PLDAPControlA    *Control
    );

WINLDAPAPI INT LDAPAPI ldap_parse_vlv_controlW (
        PLDAP            ExternalHandle,
        PLDAPControlW   *Control,
        PULONG           TargetPos,
        PULONG           ListCount,
        PBERVAL         *Context,
        PINT             ErrCode
    );

WINLDAPAPI INT LDAPAPI ldap_parse_vlv_controlA (
        PLDAP             ExternalHandle,
        PLDAPControlA    *Control,
        PULONG            TargetPos,
        PULONG            ListCount,
        PBERVAL          *Context,
        PINT              ErrCode
    );

#if LDAP_UNICODE

#define ldap_create_vlv_control ldap_create_vlv_controlW
#define ldap_parse_vlv_control  ldap_parse_vlv_controlW

#else

#define ldap_create_vlv_control ldap_create_vlv_controlA
#define ldap_parse_vlv_control  ldap_parse_vlv_controlA

#endif

//
// The StartTLS APIs are used for establishing Transport Layer Security on
// the fly. 
//

#define LDAP_START_TLS_OID       "1.3.6.1.4.1.1466.20037"
#define LDAP_START_TLS_OID_W    L"1.3.6.1.4.1.1466.20037"

//
// This API is called by users to initiate Transport Level Security on an
// LDAP connection. If the server accepts our proposal and initiates TLS,
// this API will return LDAP_SUCCESS.
//
// If the server fails the request for whatever reason, the API returns LDAP_OTHER
// and the ServerReturnValue will contain the error code from the server.
//
// It is possible that the server returns a referral - either in response to the
// StartTLS request or during the subsequent encrypted session. For security
// reasons, we have decided to NOT chase referrals by default. In the former case
// the referral message is returned as an LDAPMessage to the user.
//
// The operation has a default timeout of about 30 seconds.
//

WINLDAPAPI ULONG LDAPAPI ldap_start_tls_sW (
    IN   PLDAP          ExternalHandle,
    OUT  PULONG         ServerReturnValue,
    OUT  LDAPMessage    **result,
    IN   PLDAPControlW  *ServerControls,
    IN   PLDAPControlW  *ClientControls
);


WINLDAPAPI ULONG LDAPAPI ldap_start_tls_sA (
    IN   PLDAP          ExternalHandle,
    OUT  PULONG         ServerReturnValue,
    OUT  LDAPMessage    **result,
    IN   PLDAPControlA  *ServerControls,
    IN   PLDAPControlA  *ClientControls
);

//
// This API is called by the user to stop Transport Level Security on an open
// LDAP connection on which TLS has already been started.
//
// If the operation succeeds, the user can resume normal plaintext LDAP
// operations on the connection.
//
// If the operation fails, the user MUST close the connection by calling
// ldap_unbind as the TLS state of the connection will be indeterminate.
//
// The operation has a default timeout of about 30 seconds.
//

WINLDAPAPI BOOLEAN LDAPAPI ldap_stop_tls_s (
    IN  PLDAP ExternalHandle
 );

#if LDAP_UNICODE

#define ldap_start_tls_s ldap_start_tls_sW

#else

#define ldap_start_tls_s ldap_start_tls_sA

#endif

//
// This OID is used in a Refresh Extended operation as defined in
// RFC 2589: LDAP v3 Extensions for Dynamic Directory Services
//

#define LDAP_TTL_EXTENDED_OP_OID    "1.3.6.1.4.1.1466.101.119.1"
#define LDAP_TTL_EXTENDED_OP_OID_W L"1.3.6.1.4.1.1466.101.119.1"

//
//  These functions return subordinate referrals (references) that are returned
//  in search responses.  There are two types of referrals.  External referrals
//  where the naming context doesn't reside on the server (e.g. server says "I
//  don't have the data, look over there") and Subordinate referrals (or
//  references) where some data has been returned and the referrals are passed
//  to other naming contexts below the current one (e.g. servers says "Here's
//  some data from the tree I hold, go look here, there, and over there for
//  more data that is further down in the tree.").
//
//  These routines handle the latter.  For external references, use
//  ldap_parse_result.
//
//  Return the first reference from a message.  It is freed when the message is
//  freed so should not be freed explicitly.
//

WINLDAPAPI LDAPMessage *LDAPAPI ldap_first_reference( LDAP *ld, LDAPMessage *res );

//
//  Return the next entry of a message.  It is freed when the message is
//  freed so should not be freed explicitly.
//

WINLDAPAPI LDAPMessage *LDAPAPI ldap_next_reference( LDAP *ld, LDAPMessage *entry );

//
//  Count the number of subordinate references returned by the server in a
//  response to a search request.
//

WINLDAPAPI ULONG LDAPAPI ldap_count_references( LDAP *ld, LDAPMessage *res );

//
//  We return the list of subordinate referrals in a search response message.
//

WINLDAPAPI ULONG LDAPAPI ldap_parse_referenceW (
        LDAP *Connection,
        LDAPMessage *ResultMessage,
        __deref_out PWCHAR **Referrals                   // free with ldap_value_freeW
        );

WINLDAPAPI ULONG LDAPAPI ldap_parse_referenceA (
        LDAP *Connection,
        LDAPMessage *ResultMessage,
        __deref_out PCHAR **Referrals                   // free with ldap_value_freeA
        );

#if LDAP_UNICODE

#define ldap_parse_reference ldap_parse_referenceW

#else

WINLDAPAPI ULONG LDAPAPI ldap_parse_reference (
        LDAP *Connection,
        LDAPMessage *ResultMessage,
        PCHAR **Referrals                   // free with ldap_value_free
        );

#endif


//
//  These APIs allow a client to send an extended request (free for all) to
//  an LDAPv3 (or above) server.  The functionality is fairly open... you can
//  send any request you'd like.  Note that since we don't know if you'll
//  be receiving a single or multiple responses, you'll have to explicitly tell
//  us when you're done with the request by calling ldap_close_extended_op.
//
//  These are thread safe.
//

WINLDAPAPI ULONG LDAPAPI ldap_extended_operationW(
        LDAP *ld,
        __in const PWCHAR Oid,
        struct berval   *Data,
        PLDAPControlW   *ServerControls,
        PLDAPControlW   *ClientControls,
        ULONG           *MessageNumber
        );

WINLDAPAPI ULONG LDAPAPI ldap_extended_operationA(
        LDAP *ld,
        __in const PCHAR Oid,
        struct berval   *Data,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        ULONG           *MessageNumber
        );

WINLDAPAPI ULONG LDAPAPI ldap_extended_operation_sA (
        LDAP            *ExternalHandle,
        __in PCHAR           Oid,
        struct berval   *Data,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        __deref_out PCHAR           *ReturnedOid,
        struct berval   **ReturnedData
        );

WINLDAPAPI ULONG LDAPAPI ldap_extended_operation_sW (
        LDAP            *ExternalHandle,
        __in PWCHAR          Oid,
        struct berval   *Data,
        PLDAPControlW   *ServerControls,
        PLDAPControlW   *ClientControls,
        __deref_out PWCHAR          *ReturnedOid,
        struct berval   **ReturnedData
        );



#if LDAP_UNICODE

#define ldap_extended_operation ldap_extended_operationW
#define ldap_extended_operation_s ldap_extended_operation_sW

#else

WINLDAPAPI ULONG LDAPAPI ldap_extended_operation(
        LDAP *ld,
        const PCHAR Oid,
        struct berval   *Data,
        PLDAPControlA   *ServerControls,
        PLDAPControlA   *ClientControls,
        ULONG           *MessageNumber
        );

#define ldap_extended_operation_s ldap_extended_operation_sA

#endif

WINLDAPAPI ULONG LDAPAPI ldap_close_extended_op(
        LDAP    *ld,
        ULONG   MessageNumber
        );


//
//  Some enhancements that will probably never make it into the RFC related
//  to callouts to allow external caching of connections.
//
//  Call ldap_set_option( conn, LDAP_OPT_REFERRAL_CALLBACK, &referralRoutines )
//  where referralRoutines is the address of an LDAP_REFERRAL_CALLBACK
//  structure with your routines.  They may be NULL, in which case we'll
//  obviously not make the calls.
//
//  Any connections that are created will inherit the current callbacks from
//  the primary connection that the request was initiated on.
//

#define LDAP_OPT_REFERRAL_CALLBACK  0x70

//
//  This first routine is called when we're about to chase a referral.  We
//  callout to it to see if there is already a connection cached that we
//  can use.  If so, the callback routine returns the pointer to the
//  connection to use in ConnectionToUse.  If not, it sets
//  *ConnectionToUse to NULL.
//
//  For a return code, it should return 0 if we should continue to chase the
//  referral.  If it returns a non-zero return code, we'll treat that as the
//  error code for chasing the referral.  This allows caching of host names
//  that are not reachable, if we decide to add that in the future.
//

typedef ULONG (_cdecl QUERYFORCONNECTION)(
    PLDAP       PrimaryConnection,
    PLDAP       ReferralFromConnection,
    PWCHAR      NewDN,
    PCHAR       HostName,
    ULONG       PortNumber,
    PVOID       SecAuthIdentity,    // if null, use CurrentUser below
    PVOID       CurrentUserToken,   // pointer to current user's LUID
    PLDAP       *ConnectionToUse
    );

//
//  This next function is called when we've created a new connection while
//  chasing a referral.  Note that it gets assigned the same callback functions
//  as the PrimaryConnection.  If the return code is FALSE, then the call
//  back function doesn't want to cache the connection and it will be
//  destroyed after the operation is complete.  If TRUE is returned, we'll
//  assume that the callee has taken ownership of the connection and it will
//  not be destroyed after the operation is complete.
//
//  If the ErrorCodeFromBind field is not 0, then the bind operation to
//  that server failed.
//

typedef BOOLEAN (_cdecl NOTIFYOFNEWCONNECTION) (
    PLDAP       PrimaryConnection,
    PLDAP       ReferralFromConnection,
    PWCHAR      NewDN,
    PCHAR       HostName,
    PLDAP       NewConnection,
    ULONG       PortNumber,
    PVOID       SecAuthIdentity,    // if null, use CurrentUser below
    PVOID       CurrentUser,        // pointer to current user's LUID
    ULONG       ErrorCodeFromBind
    );

//
//  This next function is called when we've successfully called off to the
//  QueryForConnection call and received a connection OR when we called off
//  to the NotifyOfNewConnection call and it returned TRUE.  We call this
//  function when we're dereferencing the connection after we're done with it.
//
//  Return code is currently ignored, but the function should return
//  LDAP_SUCCESS if all went well.
//

typedef ULONG (_cdecl DEREFERENCECONNECTION)(
    PLDAP       PrimaryConnection,
    PLDAP       ConnectionToDereference
    );

typedef struct LdapReferralCallback {

    ULONG   SizeOfCallbacks;        // set to sizeof( LDAP_REFERRAL_CALLBACK )
    QUERYFORCONNECTION *QueryForConnection;
    NOTIFYOFNEWCONNECTION *NotifyRoutine;
    DEREFERENCECONNECTION *DereferenceRoutine;

} LDAP_REFERRAL_CALLBACK, *PLDAP_REFERRAL_CALLBACK;

//
//  Thread Safe way to get last error code returned by LDAP API is to call
//  LdapGetLastError();
//

WINLDAPAPI ULONG LDAPAPI LdapGetLastError( VOID );

//
//  Translate from LdapError to closest Win32 error code.
//

WINLDAPAPI ULONG LDAPAPI LdapMapErrorToWin32( ULONG LdapError );

//
// This is an arrangement for specifying client certificates while establishing
// an SSL connection.
// Simply Call ldap_set_option( conn, LDAP_OPT_CLIENT_CERTIFICATE, &CertRoutine )
// where CertRoutine is the address of your callback routine. If it is NULL,
// we will obviously not make the call.
//

#define LDAP_OPT_CLIENT_CERTIFICATE    0x80

//
// This callback is invoked when the server demands a client certificate for
// authorization. The application should examine the list of Certificate Authorities
// the server trusts and supply an appropriate client certificate. wldap32.dll 
// subsequently passes these credentials to the SSL server as part of the
// handshake. If the application desires that anonymous credentials be used,
// it must return FALSE instead of a certificate. Any certificate must be freed
// by the application after the connection has been completed. Note that the
// application MUST perform an EXTERNAL bind subsequent to connection
// establishment for these credentials to be used by the server.
//


typedef BOOLEAN (_cdecl QUERYCLIENTCERT) (
    IN PLDAP Connection,
    IN PSecPkgContext_IssuerListInfoEx trusted_CAs,
    IN OUT PCCERT_CONTEXT *ppCertificate
    );

//
// We are also giving an opportunity for the client to verify the certificate
// of the server. The client registers a callback which is invoked after the
// secure connection is setup. The server certificate is presented to the
// client who invokes it and decides it it is acceptable. To register this
// callback, simply call ldap_set_option( conn, LDAP_OPT_SERVER_CERTIFICATE, &CertRoutine )
//

#define LDAP_OPT_SERVER_CERTIFICATE    0x81

//
// This function is called after the secure connection has been established. The
// certificate of the server is supplied for examination by the client. If the
// client approves it, it returns TRUE else, it returns false and the secure
// connection is torn down.
//

typedef BOOLEAN (_cdecl VERIFYSERVERCERT) (
     PLDAP Connection,
     PCCERT_CONTEXT* pServerCert
     );

//
//  Given an LDAP message, return the connection pointer where the message
//  came from.  It can return NULL if the connection has already been freed.
//

WINLDAPAPI LDAP * LDAPAPI ldap_conn_from_msg (
    LDAP *PrimaryConn,
    LDAPMessage *res
    );

//
//  Do we reference the connection for each message so that we can safely get
//  the connection pointer back by calling ldap_conn_from_msg?
//

#define LDAP_OPT_REF_DEREF_CONN_PER_MSG 0x94

#ifdef __cplusplus
}
#endif

#endif  // LDAP_CLIENT_DEFINED

