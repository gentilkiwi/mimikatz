/*********************************************************************
*
* WTSAPI32.H
*
*   Windows Terminal Server public APIs
*
*   Copyright (c) 1997-2001 Microsoft Corporation
*
**********************************************************************/

#ifndef _INC_WTSAPI
#define _INC_WTSAPI

#if _MSC_VER > 1000
#pragma once
#endif
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif


/*===================================================================
==   Defines
=====================================================================*/

/*
 *  Specifies the current server
 */
#define WTS_CURRENT_SERVER         ((HANDLE)NULL)
#define WTS_CURRENT_SERVER_HANDLE  ((HANDLE)NULL)
#define WTS_CURRENT_SERVER_NAME    (NULL)

/*
 *  Specifies the current session (SessionId)
 */
#define WTS_CURRENT_SESSION ((DWORD)-1)

/*
 *  Specifies any-session (SessionId)
 */
#define WTS_ANY_SESSION ((DWORD)-2)

/*
 *  Possible pResponse values from WTSSendMessage()
 */
#ifndef IDTIMEOUT
#define IDTIMEOUT 32000
#endif
#ifndef IDASYNC
#define IDASYNC   32001
#endif

#ifndef __HYDRIX_H__
#define USERNAME_LENGTH          20
#define CLIENTNAME_LENGTH        20
#define CLIENTADDRESS_LENGTH     30
#endif
/*
 *  Shutdown flags
 */
#define WTS_WSD_LOGOFF      0x00000001  // log off all users except
                                        // current user; deletes
                                        // WinStations (a reboot is
                                        // required to recreate the
                                        // WinStations)
#define WTS_WSD_SHUTDOWN    0x00000002  // shutdown system
#define WTS_WSD_REBOOT      0x00000004  // shutdown and reboot
#define WTS_WSD_POWEROFF    0x00000008  // shutdown and power off (on
                                        // machines that support power
                                        // off through software)
#define WTS_WSD_FASTREBOOT  0x00000010  // reboot without logging users
                                        // off or shutting down
#define MAX_ELAPSED_TIME_LENGTH         15
#define MAX_DATE_TIME_LENGTH            56
#define WINSTATIONNAME_LENGTH    32
#define DOMAIN_LENGTH            17

#define WTS_DRIVE_LENGTH                3
#define WTS_LISTENER_NAME_LENGTH        32
#define WTS_COMMENT_LENGTH              60

/*
 *  Flags for WTSCreateListener
 */
#define WTS_LISTENER_CREATE 0x00000001
#define WTS_LISTENER_UPDATE 0x00000010

/*********************************
 *   Listener access values
 *********************************/
#define WTS_SECURITY_QUERY_INFORMATION        0x00000001
#define WTS_SECURITY_SET_INFORMATION          0x00000002
#define WTS_SECURITY_RESET                    0x00000004
#define WTS_SECURITY_VIRTUAL_CHANNELS         0x00000008
#define WTS_SECURITY_REMOTE_CONTROL           0x00000010
#define WTS_SECURITY_LOGON                    0x00000020
#define WTS_SECURITY_LOGOFF                   0x00000040
#define WTS_SECURITY_MESSAGE                  0x00000080
#define WTS_SECURITY_CONNECT                  0x00000100
#define WTS_SECURITY_DISCONNECT               0x00000200

#define WTS_SECURITY_GUEST_ACCESS             (WTS_SECURITY_LOGON)

#define WTS_SECURITY_CURRENT_GUEST_ACCESS     (WTS_SECURITY_VIRTUAL_CHANNELS | WTS_SECURITY_LOGOFF)

#define WTS_SECURITY_USER_ACCESS              (WTS_SECURITY_CURRENT_GUEST_ACCESS | WTS_SECURITY_QUERY_INFORMATION | WTS_SECURITY_CONNECT )

#define WTS_SECURITY_CURRENT_USER_ACCESS      (WTS_SECURITY_SET_INFORMATION | WTS_SECURITY_RESET \
                                               WTS_SECURITY_VIRTUAL_CHANNELS | WTS_SECURITY_LOGOFF \
                                               WTS_SECURITY_DISCONNECT)

#define WTS_SECURITY_ALL_ACCESS               (STANDARD_RIGHTS_REQUIRED | WTS_SECURITY_QUERY_INFORMATION |       \
                                               WTS_SECURITY_SET_INFORMATION | WTS_SECURITY_RESET |               \
                                               WTS_SECURITY_VIRTUAL_CHANNELS |    WTS_SECURITY_REMOTE_CONTROL |  \
                                               WTS_SECURITY_LOGON |                                              \
                                               WTS_SECURITY_MESSAGE |                                            \
                                               WTS_SECURITY_CONNECT | WTS_SECURITY_DISCONNECT)

/*===================================================================
==   WTS_CONNECTSTATE_CLASS - Session connect state
=====================================================================*/

typedef enum _WTS_CONNECTSTATE_CLASS {
    WTSActive,              // User logged on to WinStation
    WTSConnected,           // WinStation connected to client
    WTSConnectQuery,        // In the process of connecting to client
    WTSShadow,              // Shadowing another WinStation
    WTSDisconnected,        // WinStation logged on without client
    WTSIdle,                // Waiting for client to connect
    WTSListen,              // WinStation is listening for connection
    WTSReset,               // WinStation is being reset
    WTSDown,                // WinStation is down due to error
    WTSInit,                // WinStation in initialization
} WTS_CONNECTSTATE_CLASS;

/*=====================================================================
==   WTS_SERVER_INFO - returned by WTSEnumerateServers (version 1)
=====================================================================*/

/*
 *  WTSEnumerateServers() returns two variables: pServerInfo and Count.
 *  The latter is the number of WTS_SERVER_INFO structures contained in
 *  the former.  In order to read each server, iterate i from 0 to
 *  Count-1 and reference the server name as
 *  pServerInfo[i].pServerName; for example:
 *
 *  for ( i=0; i < Count; i++ ) {
 *      _tprintf( TEXT("%s "), pServerInfo[i].pServerName );
 *  }
 *
 *  The memory returned looks like the following.  P is a pServerInfo
 *  pointer, and D is the string data for that pServerInfo:
 *
 *  P1 P2 P3 P4 ... Pn D1 D2 D3 D4 ... Dn
 *
 *  This makes it easier to iterate the servers, using code similar to
 *  the above.
 */

typedef struct _WTS_SERVER_INFOW {
    LPWSTR pServerName;    // server name
} WTS_SERVER_INFOW, * PWTS_SERVER_INFOW;

typedef struct _WTS_SERVER_INFOA {
    LPSTR pServerName;     // server name
} WTS_SERVER_INFOA, * PWTS_SERVER_INFOA;

#ifdef UNICODE
#define WTS_SERVER_INFO  WTS_SERVER_INFOW
#define PWTS_SERVER_INFO PWTS_SERVER_INFOW
#else
#define WTS_SERVER_INFO  WTS_SERVER_INFOA
#define PWTS_SERVER_INFO PWTS_SERVER_INFOA
#endif


/*=====================================================================
==   WTS_SESSION_INFO - returned by WTSEnumerateSessions (version 1)
=====================================================================*/

/*
 *  WTSEnumerateSessions() returns data in a similar format to the above
 *  WTSEnumerateServers().  It returns two variables: pSessionInfo and
 *  Count.  The latter is the number of WTS_SESSION_INFO structures
 *  contained in the former.  Iteration is similar, except that there
 *  are three parts to each entry, so it would look like this:
 *
 *  for ( i=0; i < Count; i++ ) {
 *      _tprintf( TEXT("%-5u  %-20s  %u\n"),
                  pSessionInfo[i].SessionId,
 *                pSessionInfo[i].pWinStationName,
 *                pSessionInfo[i].State );
 *  }
 *
 *  The memory returned is also segmented as the above, with all the
 *  structures allocated at the start and the string data at the end.
 *  We'll use S for the SessionId, P for the pWinStationName pointer
 *  and D for the string data, and C for the connect State:
 *
 *  S1 P1 C1 S2 P2 C2 S3 P3 C3 S4 P4 C4 ... Sn Pn Cn D1 D2 D3 D4 ... Dn
 *
 *  As above, this makes it easier to iterate the sessions.
 */

typedef struct _WTS_SESSION_INFOW {
    DWORD SessionId;             // session id
    LPWSTR pWinStationName;      // name of WinStation this session is
                                 // connected to
    WTS_CONNECTSTATE_CLASS State; // connection state (see enum)
} WTS_SESSION_INFOW, * PWTS_SESSION_INFOW;

typedef struct _WTS_SESSION_INFOA {
    DWORD SessionId;             // session id
    LPSTR pWinStationName;       // name of WinStation this session is
                                 // connected to
    WTS_CONNECTSTATE_CLASS State; // connection state (see enum)
} WTS_SESSION_INFOA, * PWTS_SESSION_INFOA;

typedef struct _WTS_SESSION_INFO_1W {
    DWORD ExecEnvId;
    WTS_CONNECTSTATE_CLASS State;
    DWORD SessionId;
    LPWSTR pSessionName;
    LPWSTR pHostName;
    LPWSTR pUserName;
    LPWSTR pDomainName;
    LPWSTR pFarmName;
} WTS_SESSION_INFO_1W, * PWTS_SESSION_INFO_1W;

typedef struct _WTS_SESSION_INFO_1A {
    DWORD ExecEnvId;
    WTS_CONNECTSTATE_CLASS State;
    DWORD SessionId;
    LPSTR pSessionName;
    LPSTR pHostName;
    LPSTR pUserName;
    LPSTR pDomainName;
    LPSTR pFarmName;
} WTS_SESSION_INFO_1A, * PWTS_SESSION_INFO_1A;

#ifdef UNICODE
#define WTS_SESSION_INFO  WTS_SESSION_INFOW
#define PWTS_SESSION_INFO PWTS_SESSION_INFOW
#define WTS_SESSION_INFO_1  WTS_SESSION_INFO_1W
#define PWTS_SESSION_INFO_1 PWTS_SESSION_INFO_1W
#else
#define WTS_SESSION_INFO  WTS_SESSION_INFOA
#define PWTS_SESSION_INFO PWTS_SESSION_INFOA
#define WTS_SESSION_INFO_1  WTS_SESSION_INFO_1A
#define PWTS_SESSION_INFO_1 PWTS_SESSION_INFO_1A
#endif


/*=====================================================================
==   WTS_PROCESS_INFO - returned by WTSEnumerateProcesses (version 1)
=====================================================================*/

/*
 *  WTSEnumerateProcesses() also returns data similar to
 *  WTSEnumerateServers().  It returns two variables: pProcessInfo and
 *  Count.  The latter is the number of WTS_PROCESS_INFO structures
 *  contained in the former.  Iteration is similar, except that there
 *  are four parts to each entry, so it would look like this:
 *
 *  for ( i=0; i < Count; i++ ) {
 *      GetUserNameFromSid( pProcessInfo[i].pUserSid, UserName,
 *                          sizeof(UserName) );
 *      _tprintf( TEXT("%-5u  %-20s  %-5u  %s\n"),
 *              pProcessInfo[i].SessionId,
 *              UserName,
 *              pProcessInfo[i].ProcessId,
 *              pProcessInfo[i].pProcessName );
 *  }
 *
 *  The memory returned is also segmented as the above, with all the
 *  structures allocated at the start and the string data at the end.
 *  We'll use S for the SessionId, R for the ProcessId, P for the
 *  pProcessName pointer and D for the string data, and U for pUserSid:
 *
 *  S1 R1 P1 U1 S2 R2 P2 U2 S3 R3 P3 U3 ... Sn Rn Pn Un D1 D2 D3 ... Dn
 *
 *  As above, this makes it easier to iterate the processes.
 */

typedef struct _WTS_PROCESS_INFOW {
    DWORD SessionId;     // session id
    DWORD ProcessId;     // process id
    LPWSTR pProcessName; // name of process
    PSID pUserSid;       // user's SID
} WTS_PROCESS_INFOW, * PWTS_PROCESS_INFOW;

typedef struct _WTS_PROCESS_INFOA {
    DWORD SessionId;     // session id
    DWORD ProcessId;     // process id
    LPSTR pProcessName;  // name of process
    PSID pUserSid;       // user's SID
} WTS_PROCESS_INFOA, * PWTS_PROCESS_INFOA;

#ifdef UNICODE
#define WTS_PROCESS_INFO  WTS_PROCESS_INFOW
#define PWTS_PROCESS_INFO PWTS_PROCESS_INFOW
#else
#define WTS_PROCESS_INFO  WTS_PROCESS_INFOA
#define PWTS_PROCESS_INFO PWTS_PROCESS_INFOA
#endif

/*=====================================================================
==   WTS_INFO_CLASS - WTSQuerySessionInformation
==    (See additional typedefs for more info on structures)
=====================================================================*/

#define WTS_PROTOCOL_TYPE_CONSOLE         0    // Console
#define WTS_PROTOCOL_TYPE_ICA             1    // ICA Protocol
#define WTS_PROTOCOL_TYPE_RDP             2    // RDP Protocol

typedef enum _WTS_INFO_CLASS {
    WTSInitialProgram,
    WTSApplicationName,
    WTSWorkingDirectory,
    WTSOEMId,
    WTSSessionId,
    WTSUserName,
    WTSWinStationName,
    WTSDomainName,
    WTSConnectState,
    WTSClientBuildNumber,
    WTSClientName,
    WTSClientDirectory,
    WTSClientProductId,
    WTSClientHardwareId,
    WTSClientAddress,
    WTSClientDisplay,
    WTSClientProtocolType,
    WTSIdleTime,
    WTSLogonTime,
    WTSIncomingBytes,
    WTSOutgoingBytes,
    WTSIncomingFrames,
    WTSOutgoingFrames,
    WTSClientInfo,
    WTSSessionInfo,
    WTSSessionInfoEx,
    WTSConfigInfo,
    WTSValidationInfo,   // Info Class value used to fetch Validation Information through the WTSQuerySessionInformation
    WTSSessionAddressV4,
    WTSIsRemoteSession
} WTS_INFO_CLASS;

/*=====================================================================
==   WTS Config Information
=====================================================================*/

typedef struct  _WTSCONFIGINFOW {
    ULONG version; 
    ULONG fConnectClientDrivesAtLogon;
    ULONG fConnectPrinterAtLogon;
    ULONG fDisablePrinterRedirection;
    ULONG fDisableDefaultMainClientPrinter;
    ULONG ShadowSettings;
    WCHAR LogonUserName[USERNAME_LENGTH + 1 ];
    WCHAR LogonDomain[DOMAIN_LENGTH + 1 ];
    WCHAR WorkDirectory[MAX_PATH + 1 ];
    WCHAR InitialProgram[MAX_PATH + 1 ];
    WCHAR ApplicationName[MAX_PATH + 1 ];
} WTSCONFIGINFOW, *PWTSCONFIGINFOW;

typedef struct  _WTSCONFIGINFOA {
    ULONG version; 
    ULONG fConnectClientDrivesAtLogon;
    ULONG fConnectPrinterAtLogon;
    ULONG fDisablePrinterRedirection;
    ULONG fDisableDefaultMainClientPrinter;
    ULONG ShadowSettings;
    CHAR LogonUserName[USERNAME_LENGTH + 1 ];
    CHAR LogonDomain[DOMAIN_LENGTH + 1 ];
    CHAR WorkDirectory[MAX_PATH + 1 ];
    CHAR InitialProgram[MAX_PATH + 1 ];
    CHAR ApplicationName[MAX_PATH + 1 ];
} WTSCONFIGINFOA, *PWTSCONFIGINFOA;

/*=====================================================================
==   WTS Session Information
=====================================================================*/
typedef struct _WTSINFOW {
    WTS_CONNECTSTATE_CLASS State; // connection state (see enum)
    DWORD SessionId;             // session id
    DWORD IncomingBytes;
    DWORD OutgoingBytes;
    DWORD IncomingFrames;
    DWORD OutgoingFrames;
    DWORD IncomingCompressedBytes;
    DWORD OutgoingCompressedBytes;
    WCHAR WinStationName[WINSTATIONNAME_LENGTH];
    WCHAR Domain[DOMAIN_LENGTH];
    WCHAR UserName[USERNAME_LENGTH+1];// name of WinStation this session is
                                 // connected to
    LARGE_INTEGER ConnectTime;
    LARGE_INTEGER DisconnectTime;
    LARGE_INTEGER LastInputTime;
    LARGE_INTEGER LogonTime;
    LARGE_INTEGER CurrentTime;

} WTSINFOW, * PWTSINFOW;

typedef struct _WTSINFOA {
    WTS_CONNECTSTATE_CLASS State; // connection state (see enum)
    DWORD SessionId;             // session id
    DWORD IncomingBytes;
    DWORD OutgoingBytes;
    DWORD IncomingFrames;
    DWORD OutgoingFrames;
    DWORD IncomingCompressedBytes;
    DWORD OutgoingCompressedBy;
    CHAR WinStationName[WINSTATIONNAME_LENGTH];
    CHAR Domain[DOMAIN_LENGTH];
    CHAR UserName[USERNAME_LENGTH+1];// name of WinStation this session is
                                 // connected to
    LARGE_INTEGER ConnectTime;
    LARGE_INTEGER DisconnectTime;
    LARGE_INTEGER LastInputTime;
    LARGE_INTEGER LogonTime;
    LARGE_INTEGER CurrentTime;

} WTSINFOA, * PWTSINFOA;


/*=====================================================================
==   WTS Extended Session State Flags
=====================================================================*/
#define WTS_SESSIONSTATE_UNKNOWN    0xFFFFFFFF
#define WTS_SESSIONSTATE_LOCK       0x00000000
#define WTS_SESSIONSTATE_UNLOCK     0x00000001

/*=====================================================================
==   WTS Extended Session Information
=====================================================================*/
typedef struct _WTSINFOEX_LEVEL1_W {
    ULONG SessionId;
    WTS_CONNECTSTATE_CLASS SessionState;
    LONG SessionFlags;
    WCHAR WinStationName[WINSTATIONNAME_LENGTH + 1] ;
    WCHAR UserName[USERNAME_LENGTH + 1];
    WCHAR DomainName[DOMAIN_LENGTH + 1];
    LARGE_INTEGER LogonTime;
    LARGE_INTEGER ConnectTime;
    LARGE_INTEGER DisconnectTime;
    LARGE_INTEGER LastInputTime;
    LARGE_INTEGER CurrentTime;
    DWORD IncomingBytes;
    DWORD OutgoingBytes;
    DWORD IncomingFrames;
    DWORD OutgoingFrames;
    DWORD IncomingCompressedBytes;
    DWORD OutgoingCompressedBytes;
} WTSINFOEX_LEVEL1_W, *PWTSINFOEX_LEVEL1_W;

typedef struct _WTSINFOEX_LEVEL1_A {
    ULONG SessionId;
    WTS_CONNECTSTATE_CLASS SessionState;
    LONG SessionFlags;
    CHAR WinStationName[WINSTATIONNAME_LENGTH + 1];
    CHAR UserName[USERNAME_LENGTH + 1];
    CHAR DomainName[DOMAIN_LENGTH + 1];
    LARGE_INTEGER LogonTime;
    LARGE_INTEGER ConnectTime;
    LARGE_INTEGER DisconnectTime;
    LARGE_INTEGER LastInputTime;
    LARGE_INTEGER CurrentTime;
    DWORD IncomingBytes;
    DWORD OutgoingBytes;
    DWORD IncomingFrames;
    DWORD OutgoingFrames;
    DWORD IncomingCompressedBytes;
    DWORD OutgoingCompressedBytes;
} WTSINFOEX_LEVEL1_A, *PWTSINFOEX_LEVEL1_A;

typedef union _WTSINFOEX_LEVEL_W {
    WTSINFOEX_LEVEL1_W WTSInfoExLevel1;
} WTSINFOEX_LEVEL_W, *PWTSINFOEX_LEVEL_W;

typedef union _WTSINFOEX_LEVEL_A {
    WTSINFOEX_LEVEL1_A WTSInfoExLevel1;
} WTSINFOEX_LEVEL_A, *PWTSINFOEX_LEVEL_A;

typedef struct _WTSINFOEXW {
    DWORD Level;
    WTSINFOEX_LEVEL_W Data;
} WTSINFOEXW, *PWTSINFOEXW;

typedef struct _WTSINFOEXA {
    DWORD Level;
    WTSINFOEX_LEVEL_A Data;
} WTSINFOEXA, *PWTSINFOEXA;


/*=====================================================================
==   WTS Client Information
=====================================================================*/
typedef struct _WTSCLIENTW {
    WCHAR ClientName[ CLIENTNAME_LENGTH + 1 ];
    WCHAR Domain[ DOMAIN_LENGTH + 1 ];
    WCHAR UserName[ USERNAME_LENGTH + 1 ];
    WCHAR WorkDirectory[ MAX_PATH + 1];
    WCHAR InitialProgram[ MAX_PATH + 1];
    BYTE EncryptionLevel;       // security level of encryption pd
    ULONG ClientAddressFamily;
    USHORT ClientAddress[ CLIENTADDRESS_LENGTH + 1 ];
    USHORT HRes;
    USHORT VRes;
    USHORT ColorDepth;
    WCHAR ClientDirectory[ MAX_PATH + 1 ];
    ULONG ClientBuildNumber;
    ULONG ClientHardwareId;    // client software serial number
    USHORT ClientProductId;     // client software product id
    USHORT OutBufCountHost;     // number of outbufs on host
    USHORT OutBufCountClient;   // number of outbufs on client
    USHORT OutBufLength;        // length of outbufs in bytes
    WCHAR  DeviceId[ MAX_PATH + 1];
} WTSCLIENTW, * PWTSCLIENTW;


/*=====================================================================
==   WTS Client Information
=====================================================================*/
typedef struct _WTSCLIENTA {
    CHAR ClientName[ CLIENTNAME_LENGTH + 1 ];
    CHAR Domain[ DOMAIN_LENGTH + 1 ];
    CHAR UserName[ USERNAME_LENGTH + 1 ];
    CHAR WorkDirectory[ MAX_PATH + 1];
    CHAR InitialProgram[ MAX_PATH + 1 ];
    BYTE EncryptionLevel;       // security level of encryption pd
    ULONG ClientAddressFamily;
    USHORT ClientAddress[ CLIENTADDRESS_LENGTH + 1 ];
    USHORT HRes;
    USHORT VRes;
    USHORT ColorDepth;
    CHAR ClientDirectory[ MAX_PATH + 1 ];
    ULONG ClientBuildNumber;
    ULONG ClientHardwareId;    // client software serial number
    USHORT ClientProductId;     // client software product id
    USHORT OutBufCountHost;     // number of outbufs on host
    USHORT OutBufCountClient;   // number of outbufs on client
    USHORT OutBufLength;        // length of outbufs in bytes
    CHAR  DeviceId[ MAX_PATH + 1];
} WTSCLIENTA, * PWTSCLIENTA;

/*=====================================================================
==   WTS License Validation Information - Product Information
=====================================================================*/

#define PRODUCTINFO_COMPANYNAME_LENGTH 256
#define PRODUCTINFO_PRODUCTID_LENGTH 4

typedef struct _WTS_PRODUCT_INFOA
{
    CHAR CompanyName[PRODUCTINFO_COMPANYNAME_LENGTH];
    CHAR ProductID[PRODUCTINFO_PRODUCTID_LENGTH];
} PRODUCT_INFOA;

typedef struct _WTS_PRODUCT_INFOW
{
    WCHAR CompanyName[PRODUCTINFO_COMPANYNAME_LENGTH];
    WCHAR ProductID[PRODUCTINFO_PRODUCTID_LENGTH];
} PRODUCT_INFOW;

/*=====================================================================
     WTS License Validation Information
     This structure will be returned from WTSQuerySessionInformation when the user
     queries for license validation information.
=====================================================================*/

#define VALIDATIONINFORMATION_LICENSE_LENGTH 16384 //16 Kb
#define VALIDATIONINFORMATION_HARDWAREID_LENGTH 20

typedef struct _WTS_VALIDATION_INFORMATIONA {
    PRODUCT_INFOA ProductInfo;
    BYTE License[VALIDATIONINFORMATION_LICENSE_LENGTH];
    DWORD LicenseLength;
    BYTE HardwareID[VALIDATIONINFORMATION_HARDWAREID_LENGTH];
    DWORD HardwareIDLength;

} WTS_VALIDATION_INFORMATIONA, * PWTS_VALIDATION_INFORMATIONA;

typedef struct _WTS_VALIDATION_INFORMATIONW {
    PRODUCT_INFOW ProductInfo;
    BYTE License[VALIDATIONINFORMATION_LICENSE_LENGTH];
    DWORD LicenseLength;
    BYTE HardwareID[VALIDATIONINFORMATION_HARDWAREID_LENGTH];
    DWORD HardwareIDLength;

} WTS_VALIDATION_INFORMATIONW, * PWTS_VALIDATION_INFORMATIONW;


#ifdef UNICODE
#define WTSCONFIGINFO WTSCONFIGINFOW
#define PWTSCONFIGINFO PWTSCONFIGINFOW
#define PRODUCT_INFO PRODUCT_INFOW
#define WTS_VALIDATION_INFORMATION WTS_VALIDATION_INFORMATIONW
#define PWTS_VALIDATION_INFORMATION PWTS_VALIDATION_INFORMATIONW
#define WTSINFO  WTSINFOW
#define PWTSINFO PWTSINFOW
#define WTSINFOEX  WTSINFOEXW
#define PWTSINFOEX PWTSINFOEXW
#define WTSINFOEX_LEVEL WTSINFOEX_LEVEL_W
#define PWTSINFOEX_LEVEL PWTSINFOEX_LEVEL_W
#define WTSINFOEX_LEVEL1 WTSINFOEX_LEVEL1_W
#define PWTSINFOEX_LEVEL1 PWTSINFOEX_LEVEL1_W
#define WTSCLIENT WTSCLIENTW
#define PWTSCLIENT PWTSCLIENTW
#else
#define WTSCONFIGINFO WTSCONFIGINFOA
#define PWTSCONFIGINFO PWTSCONFIGINFOA
#define PRODUCT_INFO PRODUCT_INFOA
#define WTS_VALIDATION_INFORMATION WTS_VALIDATION_INFORMATIONA
#define PWTS_VALIDATION_INFORMATION PWTS_VALIDATION_INFORMATIONA
#define WTSINFO  WTSINFOA
#define PWTSINFO PWTSINFOA
#define WTSINFOEX  WTSINFOEXA
#define PWTSINFOEX PWTSINFOEXA
#define WTSINFOEX_LEVEL WTSINFOEX_LEVEL_A
#define PWTSINFOEX_LEVEL PWTSINFOEX_LEVEL_A
#define WTSINFOEX_LEVEL1 WTSINFOEX_LEVEL1_A
#define PWTSINFOEX_LEVEL1 PWTSINFOEX_LEVEL1_A
#define WTSCLIENT WTSCLIENTA
#define PWTSCLIENT PWTSCLIENTA

#endif


/*=====================================================================
==   WTSQuerySessionInformation - (WTSClientAddress)
=====================================================================*/

typedef struct _WTS_CLIENT_ADDRESS {
    DWORD AddressFamily;  // AF_INET, AF_INET6, AF_IPX, AF_NETBIOS, AF_UNSPEC
    BYTE  Address[20];    // client network address
} WTS_CLIENT_ADDRESS, * PWTS_CLIENT_ADDRESS;


/*=====================================================================
==   WTSQuerySessionInformation - (WTSClientDisplay)
=====================================================================*/

typedef struct _WTS_CLIENT_DISPLAY {
    DWORD HorizontalResolution; // horizontal dimensions, in pixels
    DWORD VerticalResolution;   // vertical dimensions, in pixels
    DWORD ColorDepth;           // 1=16, 2=256, 4=64K, 8=16M
} WTS_CLIENT_DISPLAY, * PWTS_CLIENT_DISPLAY;


/*=====================================================================
==   WTS_CONFIG_CLASS - WTSQueryUserConfig/WTSSetUserConfig
=====================================================================*/


typedef enum _WTS_CONFIG_CLASS {
    //Initial program settings
    WTSUserConfigInitialProgram,            // string returned/expected
    WTSUserConfigWorkingDirectory,          // string returned/expected
    WTSUserConfigfInheritInitialProgram,    // DWORD returned/expected
    //
    WTSUserConfigfAllowLogonTerminalServer,     //DWORD returned/expected
    //Timeout settings
    WTSUserConfigTimeoutSettingsConnections,    //DWORD returned/expected
    WTSUserConfigTimeoutSettingsDisconnections, //DWORD returned/expected
    WTSUserConfigTimeoutSettingsIdle,           //DWORD returned/expected
    //Client device settings
    WTSUserConfigfDeviceClientDrives,       //DWORD returned/expected
    WTSUserConfigfDeviceClientPrinters,         //DWORD returned/expected
    WTSUserConfigfDeviceClientDefaultPrinter,   //DWORD returned/expected
    //Connection settings
    WTSUserConfigBrokenTimeoutSettings,         //DWORD returned/expected
    WTSUserConfigReconnectSettings,             //DWORD returned/expected
    //Modem settings
    WTSUserConfigModemCallbackSettings,         //DWORD returned/expected
    WTSUserConfigModemCallbackPhoneNumber,      // string returned/expected
    //Shadow settings
    WTSUserConfigShadowingSettings,             //DWORD returned/expected
    //User Profile settings
    WTSUserConfigTerminalServerProfilePath,     // string returned/expected
    //Terminal Server home directory
    WTSUserConfigTerminalServerHomeDir,       // string returned/expected
    WTSUserConfigTerminalServerHomeDirDrive,    // string returned/expected
    WTSUserConfigfTerminalServerRemoteHomeDir,  // DWORD 0:LOCAL 1:REMOTE

    WTSUserConfigUser,                          // returns WTSUSERCONFIG struct
} WTS_CONFIG_CLASS;

typedef enum _WTS_CONFIG_SOURCE {
    WTSUserConfigSourceSAM
} WTS_CONFIG_SOURCE;

typedef struct _WTSUSERCONFIGA {
    DWORD Source;
    DWORD InheritInitialProgram;
    DWORD AllowLogonTerminalServer;
    DWORD TimeoutSettingsConnections;
    DWORD TimeoutSettingsDisconnections;
    DWORD TimeoutSettingsIdle;
    DWORD DeviceClientDrives;
    DWORD DeviceClientPrinters;
    DWORD ClientDefaultPrinter;
    DWORD BrokenTimeoutSettings;
    DWORD ReconnectSettings;
    DWORD ShadowingSettings;
    DWORD TerminalServerRemoteHomeDir;
    CHAR InitialProgram[ MAX_PATH + 1 ];
    CHAR WorkDirectory[ MAX_PATH + 1 ];
    CHAR TerminalServerProfilePath[ MAX_PATH + 1 ];
    CHAR TerminalServerHomeDir[ MAX_PATH + 1 ];
    CHAR TerminalServerHomeDirDrive[ WTS_DRIVE_LENGTH + 1 ];
} WTSUSERCONFIGA, * PWTSUSERCONFIGA;

typedef struct _WTSUSERCONFIGW {
    DWORD Source;
    DWORD InheritInitialProgram;
    DWORD AllowLogonTerminalServer;
    DWORD TimeoutSettingsConnections;
    DWORD TimeoutSettingsDisconnections;
    DWORD TimeoutSettingsIdle;
    DWORD DeviceClientDrives;
    DWORD DeviceClientPrinters;
    DWORD ClientDefaultPrinter;
    DWORD BrokenTimeoutSettings;
    DWORD ReconnectSettings;
    DWORD ShadowingSettings;
    DWORD TerminalServerRemoteHomeDir;
    WCHAR InitialProgram[ MAX_PATH + 1 ];
    WCHAR WorkDirectory[ MAX_PATH + 1 ];
    WCHAR TerminalServerProfilePath[ MAX_PATH + 1 ];
    WCHAR TerminalServerHomeDir[ MAX_PATH + 1 ];
    WCHAR TerminalServerHomeDirDrive[ WTS_DRIVE_LENGTH + 1 ];
} WTSUSERCONFIGW, * PWTSUSERCONFIGW;

#ifdef UNICODE
#define WTSUSERCONFIG WTSUSERCONFIGW
#define PWTSUSERCONFIG PWTSUSERCONFIGW
#else
#define WTSUSERCONFIG WTSUSERCONFIGA
#define PWTSUSERCONFIG PWTSUSERCONFIGA
#endif /* UNICODE */


/*=====================================================================
==   WTS_EVENT - Event flags for WTSWaitSystemEvent
=====================================================================*/

#define WTS_EVENT_NONE         0x00000000 // return no event
#define WTS_EVENT_CREATE       0x00000001 // new WinStation created
#define WTS_EVENT_DELETE       0x00000002 // existing WinStation deleted
#define WTS_EVENT_RENAME       0x00000004 // existing WinStation renamed
#define WTS_EVENT_CONNECT      0x00000008 // WinStation connect to client
#define WTS_EVENT_DISCONNECT   0x00000010 // WinStation logged on without
                                          //     client
#define WTS_EVENT_LOGON        0x00000020 // user logged on to existing
                                          //     WinStation
#define WTS_EVENT_LOGOFF       0x00000040 // user logged off from
                                          //     existing WinStation
#define WTS_EVENT_STATECHANGE  0x00000080 // WinStation state change
#define WTS_EVENT_LICENSE      0x00000100 // license state change
#define WTS_EVENT_ALL          0x7fffffff // wait for all event types
#define WTS_EVENT_FLUSH        0x80000000 // unblock all waiters

/*=====================================================================
==   Flags for HotkeyModifiers in WTSStartRemoteControlSession
=====================================================================*/

#define REMOTECONTROL_KBDSHIFT_HOTKEY              0x1    // Shift key
#define REMOTECONTROL_KBDCTRL_HOTKEY               0x2    // Ctrl key
#define REMOTECONTROL_KBDALT_HOTKEY                0x4    // Alt key

/*=====================================================================
==   WTS_VIRTUAL_CLASS - WTSVirtualChannelQuery
=====================================================================*/
typedef enum _WTS_VIRTUAL_CLASS {
    WTSVirtualClientData,  // Virtual channel client module data
                           //     (C2H data)
    WTSVirtualFileHandle
} WTS_VIRTUAL_CLASS;

/*=====================================================================
==   WTSQuerySessionInformation - (WTSSessionAddress)
=====================================================================*/

typedef struct _WTS_SESSION_ADDRESS {
    DWORD AddressFamily;  // AF_INET only.
    BYTE  Address[20];    // client network address
} WTS_SESSION_ADDRESS, * PWTS_SESSION_ADDRESS;


/*=====================================================================
==   Windows Terminal Server public APIs
=====================================================================*/

BOOL WINAPI
WTSStopRemoteControlSession(
    IN ULONG   LogonId
    );

BOOL WINAPI
WTSStartRemoteControlSessionW(
    IN LPWSTR  pTargetServerName,
    IN ULONG   TargetLogonId,
    IN BYTE    HotkeyVk,
    IN USHORT  HotkeyModifiers
    );

BOOL WINAPI
WTSStartRemoteControlSessionA(
    IN LPSTR  pTargetServerName,
    IN ULONG   TargetLogonId,
    IN BYTE    HotkeyVk,
    IN USHORT  HotkeyModifiers
    );

#ifdef UNICODE
#define WTSStartRemoteControlSession WTSStartRemoteControlSessionW
#else
#define WTSStartRemoteControlSession WTSStartRemoteControlSessionA
#endif /* UNICODE */

BOOL
WINAPI
WTSConnectSessionA(
    IN ULONG LogonId,
    IN ULONG TargetLogonId,
    IN PSTR pPassword,
    IN BOOL bWait
    );

BOOL
WINAPI
WTSConnectSessionW(
    IN ULONG LogonId,
    IN ULONG TargetLogonId,
    IN PWSTR pPassword,
    IN BOOL bWait
    );

#ifdef UNICODE
#define WTSConnectSession WTSConnectSessionW
#else
#define WTSConnectSession WTSConnectSessionA
#endif

BOOL
WINAPI
WTSEnumerateServersW(
    IN LPWSTR pDomainName,
    IN DWORD Reserved,
    IN DWORD Version,
    OUT PWTS_SERVER_INFOW * ppServerInfo,
    OUT DWORD * pCount
    );

BOOL
WINAPI
WTSEnumerateServersA(
    IN LPSTR pDomainName,
    IN DWORD Reserved,
    IN DWORD Version,
    OUT PWTS_SERVER_INFOA * ppServerInfo,
    OUT DWORD * pCount
    );

#ifdef UNICODE
#define WTSEnumerateServers WTSEnumerateServersW
#else
#define WTSEnumerateServers WTSEnumerateServersA
#endif

/*------------------------------------------------*/

HANDLE
WINAPI
WTSOpenServerW(
    IN LPWSTR pServerName
    );

HANDLE
WINAPI
WTSOpenServerA(
    IN LPSTR pServerName
    );

HANDLE
WINAPI
WTSOpenServerExW(
    IN LPWSTR pServerName
    );

HANDLE
WINAPI
WTSOpenServerExA(
    IN LPSTR pServerName
    );

#ifdef UNICODE
#define WTSOpenServer WTSOpenServerW
#define WTSOpenServerEx WTSOpenServerExW
#else
#define WTSOpenServer WTSOpenServerA
#define WTSOpenServerEx WTSOpenServerExA
#endif

/*------------------------------------------------*/

VOID
WINAPI
WTSCloseServer(
    IN HANDLE hServer
    );

/*------------------------------------------------*/

BOOL
WINAPI
WTSEnumerateSessionsW(
    IN HANDLE hServer,
    IN DWORD Reserved,
    IN DWORD Version,
    OUT PWTS_SESSION_INFOW * ppSessionInfo,
    OUT DWORD * pCount
    );

BOOL
WINAPI
WTSEnumerateSessionsA(
    IN HANDLE hServer,
    IN DWORD Reserved,
    IN DWORD Version,
    OUT PWTS_SESSION_INFOA * ppSessionInfo,
    OUT DWORD * pCount
    );

BOOL
WINAPI
WTSEnumerateSessionsExW(
    IN HANDLE hServer,
    IN OUT DWORD *pLevel,
    IN DWORD Filter,
    OUT PWTS_SESSION_INFO_1W * ppSessionInfo,
    OUT DWORD * pCount );

BOOL
WINAPI
WTSEnumerateSessionsExA(
    IN HANDLE hServer,
    IN OUT DWORD *pLevel,
    IN DWORD Filter,
    OUT PWTS_SESSION_INFO_1A * ppSessionInfo,
    OUT DWORD * pCount );

#ifdef UNICODE
#define WTSEnumerateSessions WTSEnumerateSessionsW
#define WTSEnumerateSessionsEx WTSEnumerateSessionsExW
#else
#define WTSEnumerateSessions WTSEnumerateSessionsA
#define WTSEnumerateSessionsEx WTSEnumerateSessionsExA
#endif

/*------------------------------------------------*/

BOOL
WINAPI
WTSEnumerateProcessesW(
    IN HANDLE hServer,
    IN DWORD Reserved,
    IN DWORD Version,
    OUT PWTS_PROCESS_INFOW * ppProcessInfo,
    OUT DWORD * pCount
    );

BOOL
WINAPI
WTSEnumerateProcessesA(
    IN HANDLE hServer,
    IN DWORD Reserved,
    IN DWORD Version,
    OUT PWTS_PROCESS_INFOA * ppProcessInfo,
    OUT DWORD * pCount
    );

#ifdef UNICODE
#define WTSEnumerateProcesses WTSEnumerateProcessesW
#else
#define WTSEnumerateProcesses WTSEnumerateProcessesA
#endif

/*------------------------------------------------*/

BOOL
WINAPI
WTSTerminateProcess(
    IN HANDLE hServer,
    IN DWORD ProcessId,
    IN DWORD ExitCode
    );


/*------------------------------------------------*/

BOOL
WINAPI
WTSQuerySessionInformationW(
    IN HANDLE hServer,
    IN DWORD SessionId,
    IN WTS_INFO_CLASS WTSInfoClass,
    OUT LPWSTR * ppBuffer,
    OUT DWORD * pBytesReturned
    );

BOOL
WINAPI
WTSQuerySessionInformationA(
    IN HANDLE hServer,
    IN DWORD SessionId,
    IN WTS_INFO_CLASS WTSInfoClass,
    OUT LPSTR * ppBuffer,
    OUT DWORD * pBytesReturned
    );

#ifdef UNICODE
#define WTSQuerySessionInformation WTSQuerySessionInformationW
#else
#define WTSQuerySessionInformation WTSQuerySessionInformationA
#endif

/*------------------------------------------------*/

BOOL
WINAPI
WTSQueryUserConfigW(
    IN LPWSTR pServerName,
    IN LPWSTR pUserName,
    IN WTS_CONFIG_CLASS WTSConfigClass,
    OUT LPWSTR * ppBuffer,
    OUT DWORD * pBytesReturned
    );

BOOL
WINAPI
WTSQueryUserConfigA(
    IN LPSTR pServerName,
    IN LPSTR pUserName,
    IN WTS_CONFIG_CLASS WTSConfigClass,
    OUT LPSTR * ppBuffer,
    OUT DWORD * pBytesReturned
    );

#ifdef UNICODE
#define WTSQueryUserConfig WTSQueryUserConfigW
#else
#define WTSQueryUserConfig WTSQueryUserConfigA
#endif

/*------------------------------------------------*/

BOOL
WINAPI
WTSSetUserConfigW(
    IN LPWSTR pServerName,
    IN LPWSTR pUserName,
    IN WTS_CONFIG_CLASS WTSConfigClass,
    IN LPWSTR pBuffer,
    IN DWORD DataLength
    );

BOOL
WINAPI
WTSSetUserConfigA(
    IN LPSTR pServerName,
    IN LPSTR pUserName,
    IN WTS_CONFIG_CLASS WTSConfigClass,
    IN LPSTR pBuffer,
    IN DWORD DataLength
    );

#ifdef UNICODE
#define WTSSetUserConfig WTSSetUserConfigW
#else
#define WTSSetUserConfig WTSSetUserConfigA
#endif

/*------------------------------------------------*/

BOOL
WINAPI
WTSSendMessageW(
    IN HANDLE hServer,
    IN DWORD SessionId,
    IN LPWSTR pTitle,
    IN DWORD TitleLength,
    IN LPWSTR pMessage,
    IN DWORD MessageLength,
    IN DWORD Style,
    IN DWORD Timeout,
    OUT DWORD * pResponse,
    IN BOOL bWait
    );

BOOL
WINAPI
WTSSendMessageA(
    IN HANDLE hServer,
    IN DWORD SessionId,
    IN LPSTR pTitle,
    IN DWORD TitleLength,
    IN LPSTR pMessage,
    IN DWORD MessageLength,
    IN DWORD Style,
    IN DWORD Timeout,
    OUT DWORD * pResponse,
    IN BOOL bWait
    );

#ifdef UNICODE
#define WTSSendMessage WTSSendMessageW
#else
#define WTSSendMessage WTSSendMessageA
#endif

/*------------------------------------------------*/

BOOL
WINAPI
WTSDisconnectSession(
    IN HANDLE hServer,
    IN DWORD SessionId,
    IN BOOL bWait
    );

/*------------------------------------------------*/

BOOL
WINAPI
WTSLogoffSession(
    IN HANDLE hServer,
    IN DWORD SessionId,
    IN BOOL bWait
    );

/*------------------------------------------------*/

BOOL
WINAPI
WTSShutdownSystem(
    IN HANDLE hServer,
    IN DWORD ShutdownFlag
    );

/*------------------------------------------------*/

BOOL
WINAPI
WTSWaitSystemEvent(
    IN HANDLE hServer,
    IN DWORD EventMask,
    OUT DWORD * pEventFlags
    );

/*------------------------------------------------*/

HANDLE
WINAPI
WTSVirtualChannelOpen(
    IN HANDLE hServer,
    IN DWORD SessionId,
    IN LPSTR pVirtualName   /* ascii name */
    );

#define WTS_CHANNEL_OPTION_DYNAMIC          0x00000001       // dynamic channel
#define WTS_CHANNEL_OPTION_DYNAMIC_PRI_LOW  0x00000000   // priorities
#define WTS_CHANNEL_OPTION_DYNAMIC_PRI_MED  0x00000002
#define WTS_CHANNEL_OPTION_DYNAMIC_PRI_HIGH 0x00000004
#define WTS_CHANNEL_OPTION_DYNAMIC_PRI_REAL 0x00000006
#define WTS_CHANNEL_OPTION_DYNAMIC_NO_COMPRESS 0x00000008

HANDLE
WINAPI
WTSVirtualChannelOpenEx(
                     IN DWORD SessionId,
                     IN LPSTR pVirtualName,   /* ascii name */
                     IN DWORD flags
                     );

BOOL
WINAPI
WTSVirtualChannelClose(
    IN HANDLE hChannelHandle
    );

BOOL
WINAPI
WTSVirtualChannelRead(
    IN HANDLE hChannelHandle,
    IN ULONG TimeOut,
    OUT PCHAR Buffer,
    IN ULONG BufferSize,
    OUT PULONG pBytesRead
    );

BOOL
WINAPI
WTSVirtualChannelWrite(
    IN HANDLE hChannelHandle,
    IN PCHAR Buffer,
    IN ULONG Length,
    OUT PULONG pBytesWritten
    );

BOOL
WINAPI
WTSVirtualChannelPurgeInput(
    IN HANDLE hChannelHandle
    );

BOOL
WINAPI
WTSVirtualChannelPurgeOutput(
    IN HANDLE hChannelHandle
    );


BOOL
WINAPI
WTSVirtualChannelQuery(
    IN HANDLE hChannelHandle,
    IN WTS_VIRTUAL_CLASS,
    OUT PVOID *ppBuffer,
    OUT DWORD *pBytesReturned
    );

/*------------------------------------------------*/


VOID
WINAPI
WTSFreeMemory(
    IN PVOID pMemory
    );

/* Flags for Console Notification */

#define NOTIFY_FOR_ALL_SESSIONS     1
#define NOTIFY_FOR_THIS_SESSION     0


BOOL
WINAPI
WTSRegisterSessionNotification(
    HWND hWnd,
    DWORD dwFlags
    );

BOOL
WINAPI
WTSUnRegisterSessionNotification(
    HWND hWnd
    );


BOOL
WINAPI
WTSRegisterSessionNotificationEx(
    IN HANDLE hServer,
    IN HWND hWnd,
    IN DWORD dwFlags
    );

BOOL
WINAPI
WTSUnRegisterSessionNotificationEx(
    IN HANDLE hServer,
    IN HWND hWnd
    );

BOOL
WINAPI
WTSQueryUserToken(
    ULONG SessionId,
    PHANDLE phToken
    );

#define WTS_PROCESS_INFO_LEVEL_0 0
#define WTS_PROCESS_INFO_LEVEL_1 1

/*
==   WTS_PROCESS_INFO_EX - returned by WTSEnumerateProcessesEX
*/

typedef struct _WTS_PROCESS_INFO_EXW {
    DWORD SessionId;
    DWORD ProcessId;
    LPWSTR pProcessName;
    PSID pUserSid;
    DWORD NumberOfThreads;
    DWORD HandleCount;
    DWORD PagefileUsage;
    DWORD PeakPagefileUsage;
    DWORD WorkingSetSize;
    DWORD PeakWorkingSetSize;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
} WTS_PROCESS_INFO_EXW, * PWTS_PROCESS_INFO_EXW;

typedef struct _WTS_PROCESS_INFO_EXA {
    DWORD SessionId;
    DWORD ProcessId;
    LPSTR pProcessName;
    PSID pUserSid;
    DWORD NumberOfThreads;
    DWORD HandleCount;
    DWORD PagefileUsage;
    DWORD PeakPagefileUsage;
    DWORD WorkingSetSize;
    DWORD PeakWorkingSetSize;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
} WTS_PROCESS_INFO_EXA, * PWTS_PROCESS_INFO_EXA;

#ifdef UNICODE
#define WTS_PROCESS_INFO_EX  WTS_PROCESS_INFO_EXW
#define PWTS_PROCESS_INFO_EX PWTS_PROCESS_INFO_EXW
#else
#define WTS_PROCESS_INFO_EX  WTS_PROCESS_INFO_EXA
#define PWTS_PROCESS_INFO_EX PWTS_PROCESS_INFO_EXA
#endif

/*------------------------------------------------*/

typedef enum _WTS_TYPE_CLASS {
    WTSTypeProcessInfoLevel0,
    WTSTypeProcessInfoLevel1,
    WTSTypeSessionInfoLevel1,
} WTS_TYPE_CLASS;

BOOL WINAPI
WTSFreeMemoryExW(
    IN WTS_TYPE_CLASS WTSTypeClass,
    IN PVOID   pMemory,
    IN ULONG   NumberOfEntries
);

BOOL WINAPI
WTSFreeMemoryExA(
    IN WTS_TYPE_CLASS WTSTypeClass,
    IN PVOID   pMemory,
    IN ULONG   NumberOfEntries
);

#ifdef UNICODE
#define WTSFreeMemoryEx WTSFreeMemoryExW
#else
#define WTSFreeMemoryEx WTSFreeMemoryExA
#endif

/*------------------------------------------------*/

BOOL WINAPI
WTSEnumerateProcessesExW
(
    IN HANDLE    hServer,
    IN OUT DWORD *pLevel,
    IN DWORD SessionId,
    OUT LPWSTR *ppProcessInfo,
    OUT DWORD * pCount
);

BOOL WINAPI
WTSEnumerateProcessesExA
(
    IN HANDLE    hServer,
    IN OUT DWORD *pLevel,
    IN DWORD SessionId,
    OUT LPSTR *ppProcessInfo,
    OUT DWORD * pCount
);

#ifdef UNICODE
#define WTSEnumerateProcessesEx WTSEnumerateProcessesExW
#else
#define WTSEnumerateProcessesEx WTSEnumerateProcessesExA
#endif


/*------------------------------------------------*/
// Listener management APIs

typedef WCHAR WTSLISTENERNAMEW[WTS_LISTENER_NAME_LENGTH + 1 ];
typedef WTSLISTENERNAMEW *PWTSLISTENERNAMEW;
typedef CHAR WTSLISTENERNAMEA[WTS_LISTENER_NAME_LENGTH + 1 ];
typedef WTSLISTENERNAMEA *PWTSLISTENERNAMEA;

#ifdef UNICODE
#define WTSLISTENERNAME WTSLISTENERNAMEW
#define PWTSLISTENERNAME PWTSLISTENERNAMEW
#else
#define WTSLISTENERNAME WTSLISTENERNAMEA
#define PWTSLISTENERNAME PWTSLISTENERNAMEA
#endif

BOOL WINAPI
WTSEnumerateListenersW (
  IN                  HANDLE hServer,
  IN                  PVOID pReserved,
  IN          DWORD   Reserved,
  OUT PWTSLISTENERNAMEW pListeners,
  IN OUT       DWORD*  pCount
);

BOOL WINAPI
WTSEnumerateListenersA (
  IN                  HANDLE hServer,
  IN                  PVOID pReserved,
  IN                  DWORD Reserved,
  OUT PWTSLISTENERNAMEA pListeners,
  IN OUT       DWORD*  pCount
);

#ifdef UNICODE
#define WTSEnumerateListeners WTSEnumerateListenersW
#else
#define WTSEnumerateListeners WTSEnumerateListenersA
#endif

/*------------------------------------------------*/
// Listener Config, used by WTSQueryListenerConfig and WTSCreateListener

typedef struct _WTSLISTENERCONFIGW{
    ULONG version;
    ULONG fEnableListener;
    ULONG MaxConnectionCount;
    ULONG fPromptForPassword;
    ULONG fInheritColorDepth;
    ULONG ColorDepth;
    ULONG fInheritBrokenTimeoutSettings;
    ULONG BrokenTimeoutSettings;

    ULONG fDisablePrinterRedirection;
    ULONG fDisableDriveRedirection;
    ULONG fDisableComPortRedirection;
    ULONG fDisableLPTPortRedirection;
    ULONG fDisableClipboardRedirection;
    ULONG fDisableAudioRedirection;
    ULONG fDisablePNPRedirection;
    ULONG fDisableDefaultMainClientPrinter;

    ULONG LanAdapter;
    ULONG PortNumber;

    ULONG fInheritShadowSettings;
    ULONG ShadowSettings;

    ULONG TimeoutSettingsConnection;
    ULONG TimeoutSettingsDisconnection;
    ULONG TimeoutSettingsIdle;
   
    ULONG SecurityLayer;
    ULONG MinEncryptionLevel;   
    ULONG UserAuthentication;

    WCHAR Comment[ WTS_COMMENT_LENGTH + 1 ];
    WCHAR LogonUserName[USERNAME_LENGTH + 1 ];
    WCHAR LogonDomain[DOMAIN_LENGTH + 1 ];

    WCHAR WorkDirectory[ MAX_PATH + 1 ];
    WCHAR InitialProgram[ MAX_PATH + 1 ];
} WTSLISTENERCONFIGW, *PWTSLISTENERCONFIGW;

typedef struct _WTSLISTENERCONFIGA{
    ULONG version;
    ULONG fEnableListener;
    ULONG MaxConnectionCount;
    ULONG fPromptForPassword;
    ULONG fInheritColorDepth;
    ULONG ColorDepth;
    ULONG fInheritBrokenTimeoutSettings;
    ULONG BrokenTimeoutSettings;

    ULONG fDisablePrinterRedirection;
    ULONG fDisableDriveRedirection;
    ULONG fDisableComPortRedirection;
    ULONG fDisableLPTPortRedirection;
    ULONG fDisableClipboardRedirection;
    ULONG fDisableAudioRedirection;
    ULONG fDisablePNPRedirection;
    ULONG fDisableDefaultMainClientPrinter;

    ULONG LanAdapter;
    ULONG PortNumber;

    ULONG fInheritShadowSettings;
    ULONG ShadowSettings;

    ULONG TimeoutSettingsConnection;
    ULONG TimeoutSettingsDisconnection;
    ULONG TimeoutSettingsIdle;

    ULONG SecurityLayer;
    ULONG MinEncryptionLevel;  
    ULONG UserAuthentication;
    
    CHAR Comment[ WTS_COMMENT_LENGTH + 1 ];
    CHAR LogonUserName[USERNAME_LENGTH + 1 ];
    CHAR LogonDomain[DOMAIN_LENGTH + 1 ];

    CHAR WorkDirectory[ MAX_PATH + 1 ];
    CHAR InitialProgram[ MAX_PATH + 1 ];
} WTSLISTENERCONFIGA, *PWTSLISTENERCONFIGA;

BOOL WINAPI WTSQueryListenerConfigW (
  IN          HANDLE hServer,
  IN          PVOID pReserved,
  IN          DWORD Reserved,
  IN          LPWSTR pListenerName,
  OUT         PWTSLISTENERCONFIGW pBuffer
);

BOOL WINAPI WTSQueryListenerConfigA (
  IN          HANDLE hServer,
  IN          PVOID pReserved,
  IN          DWORD Reserved,
  IN          LPSTR pListenerName,
  OUT         PWTSLISTENERCONFIGA pBuffer
);

BOOL WINAPI WTSCreateListenerW (
  IN          HANDLE hServer,
  IN          PVOID pReserved,
  IN          DWORD Reserved,
  IN          LPWSTR pListenerName,
  IN          PWTSLISTENERCONFIGW pBuffer,
  IN          DWORD flag
);

BOOL WINAPI WTSCreateListenerA (
  IN          HANDLE hServer,
  IN          PVOID pReserved,
  IN          DWORD Reserved,
  IN          LPSTR pListenerName,
  IN          PWTSLISTENERCONFIGA pBuffer,
  IN          DWORD flag
);

BOOL WINAPI WTSSetListenerSecurityW(
  IN          HANDLE hServer, 
  IN          PVOID pReserved,  
  IN          DWORD Reserved, 
  IN          LPWSTR pListenerName, 
  IN          SECURITY_INFORMATION SecurityInformation,
  IN          PSECURITY_DESCRIPTOR pSecurityDescriptor);

BOOL WINAPI WTSSetListenerSecurityA(
  IN          HANDLE hServer, 
  IN          PVOID pReserved,  
  IN          DWORD Reserved, 
  IN          LPSTR pListenerName, 
  IN          SECURITY_INFORMATION SecurityInformation,
  IN          PSECURITY_DESCRIPTOR pSecurityDescriptor);

BOOL WINAPI WTSGetListenerSecurityW(
  IN          HANDLE hServer,
  IN          PVOID pReserved,
  IN          DWORD Reserved,
  IN          LPWSTR pListenerName, 
  IN          SECURITY_INFORMATION SecurityInformation,
  OUT         PSECURITY_DESCRIPTOR pSecurityDescriptor,
  IN          DWORD nLength,
  OUT         LPDWORD lpnLengthNeeded);


BOOL WINAPI WTSGetListenerSecurityA(
  IN          HANDLE hServer,
  IN          PVOID pReserved,
  IN          DWORD Reserved,
  IN          LPSTR pListenerName,
  IN          SECURITY_INFORMATION SecurityInformation,
  OUT         PSECURITY_DESCRIPTOR pSecurityDescriptor,
  IN          DWORD nLength,
  OUT         LPDWORD lpnLengthNeeded);

#ifdef UNICODE
#define WTSLISTENERCONFIG WTSLISTENERCONFIGW
#define PWTSLISTENERCONFIG PWTSLISTENERCONFIGW
#define WTSQueryListenerConfig WTSQueryListenerConfigW
#define WTSCreateListener WTSCreateListenerW
#define WTSSetListenerSecurity WTSSetListenerSecurityW
#define WTSGetListenerSecurity WTSGetListenerSecurityW
#else
#define WTSLISTENERCONFIG WTSLISTENERCONFIGA
#define PWTSLISTENERCONFIG PWTSLISTENERCONFIGA
#define WTSQueryListenerConfig WTSQueryListenerConfigA
#define WTSCreateListener WTSCreateListenerA
#define WTSSetListenerSecurity WTSSetListenerSecurityA
#define WTSGetListenerSecurity WTSGetListenerSecurityA
#endif

BOOL
WTSEnableChildSessions(
    BOOL bEnable
    );

BOOL
WTSIsChildSessionsEnabled(
    OUT PBOOL pbEnabled
    );

BOOL
WTSGetChildSessionId(
    OUT PULONG pSessionId
    );

#ifdef __cplusplus
}
#endif

#endif  /* !_INC_WTSAPI */