/*++

Copyright (c) 1989-2002  Microsoft Corporation

Module Name:

    fltUserStructures.h

Abstract:

    This contains structures, types, and defintiions that are common to both
    USER mode and KERNEL mode environments.

Environment:

    User mode

--*/
#ifndef __FLT_USER_STRUCTURES_H__
#define __FLT_USER_STRUCTURES_H__

#if FLT_MGR_BASELINE

//
//  Disable warning for this file
//

#define FLTAPI NTAPI

#define FILTER_NAME_MAX_CHARS     255
#define FILTER_NAME_MAX_BYTES     (FILTER_NAME_MAX_CHARS * sizeof( WCHAR ))

#define VOLUME_NAME_MAX_CHARS     1024
#define VOLUME_NAME_MAX_BYTES     (VOLUME_NAME_MAX_CHARS * sizeof( WCHAR ))

#define INSTANCE_NAME_MAX_CHARS   255
#define INSTANCE_NAME_MAX_BYTES   (INSTANCE_NAME_MAX_CHARS * sizeof( WCHAR ))

typedef HANDLE  HFILTER;
typedef HANDLE  HFILTER_INSTANCE;
typedef HANDLE  HFILTER_VOLUME;


//
//  Note: this may be removed in future when all translations from NTSTATUS to
//  Win32 error codes are checked in. This is interim - since there the
//  translation is not in for all filter manager error codes,
//  apps will have to access NTSTATUS codes directly
//

typedef __success(return >= 0) LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;

///////////////////////////////////////////////////////////////////////////////
//
//                      Known File System Types
//
///////////////////////////////////////////////////////////////////////////////

typedef enum _FLT_FILESYSTEM_TYPE {

    FLT_FSTYPE_UNKNOWN,         //an UNKNOWN file system type
    FLT_FSTYPE_RAW,             //Microsoft's RAW file system       (\FileSystem\RAW)
    FLT_FSTYPE_NTFS,            //Microsoft's NTFS file system      (\FileSystem\Ntfs)
    FLT_FSTYPE_FAT,             //Microsoft's FAT file system       (\FileSystem\Fastfat)
    FLT_FSTYPE_CDFS,            //Microsoft's CDFS file system      (\FileSystem\Cdfs)
    FLT_FSTYPE_UDFS,            //Microsoft's UDFS file system      (\FileSystem\Udfs)
    FLT_FSTYPE_LANMAN,          //Microsoft's LanMan Redirector     (\FileSystem\MRxSmb)
    FLT_FSTYPE_WEBDAV,          //Microsoft's WebDav redirector     (\FileSystem\MRxDav)
    FLT_FSTYPE_RDPDR,           //Microsoft's Terminal Server redirector    (\Driver\rdpdr)
    FLT_FSTYPE_NFS,             //Microsoft's NFS file system       (\FileSystem\NfsRdr)
    FLT_FSTYPE_MS_NETWARE,      //Microsoft's NetWare redirector    (\FileSystem\nwrdr)
    FLT_FSTYPE_NETWARE,         //Novell's NetWare redirector
    FLT_FSTYPE_BSUDF,           //The BsUDF CD-ROM driver           (\FileSystem\BsUDF)
    FLT_FSTYPE_MUP,             //Microsoft's Mup redirector        (\FileSystem\Mup)
    FLT_FSTYPE_RSFX,            //Microsoft's WinFS redirector      (\FileSystem\RsFxDrv)
    FLT_FSTYPE_ROXIO_UDF1,      //Roxio's UDF writeable file system (\FileSystem\cdudf_xp)
    FLT_FSTYPE_ROXIO_UDF2,      //Roxio's UDF readable file system  (\FileSystem\UdfReadr_xp)
    FLT_FSTYPE_ROXIO_UDF3,      //Roxio's DVD file system           (\FileSystem\DVDVRRdr_xp)
    FLT_FSTYPE_TACIT,           //Tacit FileSystem                  (\Device\TCFSPSE)
    FLT_FSTYPE_FS_REC,          //Microsoft's File system recognizer (\FileSystem\Fs_rec)
    FLT_FSTYPE_INCD,            //Nero's InCD file system           (\FileSystem\InCDfs)
    FLT_FSTYPE_INCD_FAT,        //Nero's InCD FAT file system       (\FileSystem\InCDFat)
    FLT_FSTYPE_EXFAT,           //Microsoft's EXFat FILE SYSTEM     (\FileSystem\exfat)
    FLT_FSTYPE_PSFS,            //PolyServ's file system            (\FileSystem\psfs)
    FLT_FSTYPE_GPFS             //IBM General Parallel File System  (\FileSystem\gpfs)

} FLT_FILESYSTEM_TYPE, *PFLT_FILESYSTEM_TYPE;


/////////////////////////////////////////////////////////////////////////////
//
//  The different types information that can be return on an Filter.
//
//  Note: Entries with "Aggregate" in the name return information for
//        both LEGACY and MINI filters.
//
/////////////////////////////////////////////////////////////////////////////


//
// In xpsp2 we do not have the concept of enumerating legacy filters
// For this reason there is no FilterAggregateBasicInfo in the V1 version
// of the enum
//

typedef enum _FILTER_INFORMATION_CLASS {

    FilterFullInformation,
    FilterAggregateBasicInformation,        //Added to XP SP2 via QFE
    FilterAggregateStandardInformation      //Longhorn and later

} FILTER_INFORMATION_CLASS, *PFILTER_INFORMATION_CLASS;

//
//  The structures for the information returned from the query of
//  information on a Filter.
//

typedef struct _FILTER_FULL_INFORMATION {

    ULONG NextEntryOffset;

    ULONG FrameID;

    ULONG NumberOfInstances;

    USHORT FilterNameLength;
    WCHAR FilterNameBuffer[1];

} FILTER_FULL_INFORMATION, *PFILTER_FULL_INFORMATION;


//
//  This structure returns information for both legacy filters and mini
//  filters.
//
//  NOTE: Support for this structures exists in all OS's that support
//        filter manager except XP SP2.  It was added later to XP SP2
//        via a QFE.
//

typedef struct _FILTER_AGGREGATE_BASIC_INFORMATION {

    ULONG NextEntryOffset;

    //
    //  ABI - Aggregate Basic Information flags
    //

    ULONG Flags;
        #define FLTFL_AGGREGATE_INFO_IS_MINIFILTER      0x00000001
        #define FLTFL_AGGREGATE_INFO_IS_LEGACYFILTER    0x00000002

    union {

        //
        //  Minifilter FULL information
        //

        struct {

            ULONG FrameID;

            ULONG NumberOfInstances;

            USHORT FilterNameLength;
            USHORT FilterNameBufferOffset;

            USHORT FilterAltitudeLength;
            USHORT FilterAltitudeBufferOffset;

        } MiniFilter;

        //
        //  Legacyfilter information
        //

        struct {

            USHORT FilterNameLength;
            USHORT FilterNameBufferOffset;

        } LegacyFilter;

    } Type;

} FILTER_AGGREGATE_BASIC_INFORMATION, *PFILTER_AGGREGATE_BASIC_INFORMATION;


//
//  This structure returns information for both legacy filters and mini
//  filters.
//
//  NOTE: Support for this structures exists in Vista and Later
//

#if FLT_MGR_LONGHORN
typedef struct _FILTER_AGGREGATE_STANDARD_INFORMATION {

    ULONG NextEntryOffset;

    //
    //  ASI - Aggregate Standard Information flags
    //

    ULONG Flags;
        #define FLTFL_ASI_IS_MINIFILTER      0x00000001
        #define FLTFL_ASI_IS_LEGACYFILTER    0x00000002

    union {

        //
        //  Minifilter FULL information
        //

        struct {

            //
            //  ASIM - Aggregate Standard Information Minifilter flags
            //

            ULONG Flags;


            ULONG FrameID;

            ULONG NumberOfInstances;

            USHORT FilterNameLength;
            USHORT FilterNameBufferOffset;

            USHORT FilterAltitudeLength;
            USHORT FilterAltitudeBufferOffset;

        } MiniFilter;

        //
        //  Legacyfilter information
        //

        struct {

            //
            //  ASIL - Aggregate Standard Information LegacyFilter flags
            //

            ULONG Flags;


            USHORT FilterNameLength;
            USHORT FilterNameBufferOffset;

            USHORT FilterAltitudeLength;
            USHORT FilterAltitudeBufferOffset;

        } LegacyFilter;

    } Type;

} FILTER_AGGREGATE_STANDARD_INFORMATION, *PFILTER_AGGREGATE_STANDARD_INFORMATION;
#endif // FLT_MGR_LONGHORN


/////////////////////////////////////////////////////////////////////////////
//
//  The different types information that can be return for a Volume
//
/////////////////////////////////////////////////////////////////////////////

typedef enum _FILTER_VOLUME_INFORMATION_CLASS {

    FilterVolumeBasicInformation,
    FilterVolumeStandardInformation     //Longhorn and later

} FILTER_VOLUME_INFORMATION_CLASS, *PFILTER_VOLUME_INFORMATION_CLASS;


//
//  Basic information about a volume (its name)
//

typedef struct _FILTER_VOLUME_BASIC_INFORMATION {

   //
   //  Length of name
   //

   USHORT FilterVolumeNameLength;

   //
   //  Buffer containing name (it's NOT NULL-terminated)
   //

   WCHAR FilterVolumeName[1];

} FILTER_VOLUME_BASIC_INFORMATION, *PFILTER_VOLUME_BASIC_INFORMATION;

//
//  Additional volume information.
//
//  NOTE: Only available in LONGHORN and later OS's
//

#if FLT_MGR_LONGHORN
typedef struct _FILTER_VOLUME_STANDARD_INFORMATION {

    ULONG NextEntryOffset;

    //
    //  VSI - VOlume Standard Information flags
    //

    ULONG Flags;

        //
        //  If set this volume is not current attached to a storage stack
        //

        #define FLTFL_VSI_DETACHED_VOLUME 0x00000001

    //
    //  Identifies which frame this volume structure is in
    //

    ULONG FrameID;

    //
    //  Identifies the type of file system being used on the volume
    //

    FLT_FILESYSTEM_TYPE FileSystemType;

    //
    //  Length of name
    //

    USHORT FilterVolumeNameLength;

    //
    //  Buffer containing name (it's NOT NULL-terminated)
    //

    WCHAR FilterVolumeName[1];

} FILTER_VOLUME_STANDARD_INFORMATION, *PFILTER_VOLUME_STANDARD_INFORMATION;
#endif // FLT_MGR_LONGHORN



/////////////////////////////////////////////////////////////////////////////
//
//  The different types information that can be return on an Instance.
//
/////////////////////////////////////////////////////////////////////////////

typedef enum _INSTANCE_INFORMATION_CLASS {

    InstanceBasicInformation,
    InstancePartialInformation,
    InstanceFullInformation,
    InstanceAggregateStandardInformation    //LONGHORN and later

} INSTANCE_INFORMATION_CLASS, *PINSTANCE_INFORMATION_CLASS;


//
//  The structures for the information returned from the query of the information
//  on the Instance.
//

typedef __struct_bcount(sizeof(INSTANCE_BASIC_INFORMATION) * InstanceNameLength) struct _INSTANCE_BASIC_INFORMATION {

    ULONG NextEntryOffset;

    USHORT InstanceNameLength;
    USHORT InstanceNameBufferOffset;

} INSTANCE_BASIC_INFORMATION, *PINSTANCE_BASIC_INFORMATION;

typedef __struct_bcount(sizeof(INSTANCE_PARTIAL_INFORMATION) + InstanceNameLength + AltitudeLength) struct _INSTANCE_PARTIAL_INFORMATION {

    ULONG NextEntryOffset;

    USHORT InstanceNameLength;
    USHORT InstanceNameBufferOffset;

    USHORT AltitudeLength;
    USHORT AltitudeBufferOffset;

} INSTANCE_PARTIAL_INFORMATION, *PINSTANCE_PARTIAL_INFORMATION;

typedef __struct_bcount(sizeof(INSTANCE_FULL_INFORMATION) + InstanceNameLength + AltitudeLength + VolumeNameLength + FilterNameLength) struct _INSTANCE_FULL_INFORMATION {

    ULONG NextEntryOffset;

    USHORT InstanceNameLength;
    USHORT InstanceNameBufferOffset;

    USHORT AltitudeLength;
    USHORT AltitudeBufferOffset;

    USHORT VolumeNameLength;
    USHORT VolumeNameBufferOffset;

    USHORT FilterNameLength;
    USHORT FilterNameBufferOffset;

} INSTANCE_FULL_INFORMATION, *PINSTANCE_FULL_INFORMATION;


//
//  This information class is used to return instance information about both
//  legacy filters and minifilters.
//

#if FLT_MGR_LONGHORN
typedef struct _INSTANCE_AGGREGATE_STANDARD_INFORMATION {

    ULONG NextEntryOffset;

    //
    //  IASI - Instance Aggregate Standard Information flags
    //

    ULONG Flags;
        #define FLTFL_IASI_IS_MINIFILTER      0x00000001
        #define FLTFL_IASI_IS_LEGACYFILTER    0x00000002

    union {

        //
        //  MiniFilter information
        //

        struct {

            //
            //  IASIM - Instance Aggregate Standard Information Minifilter flags
            //

            ULONG Flags;

                //
                //  If set this volume is not current attached to a storage stack
                //

                #define FLTFL_IASIM_DETACHED_VOLUME 0x00000001

            //
            //  Identifies which frame this volume structure is in
            //

            ULONG FrameID;

            //
            //  The type of file system this instance is attached to
            //

            FLT_FILESYSTEM_TYPE VolumeFileSystemType;

            //
            //  The name of this instance
            //

            USHORT InstanceNameLength;
            USHORT InstanceNameBufferOffset;

            //
            //  The altitude of this instance
            //

            USHORT AltitudeLength;
            USHORT AltitudeBufferOffset;

            //
            //  The volume name this instance is attached to
            //

            USHORT VolumeNameLength;
            USHORT VolumeNameBufferOffset;

            //
            //  The name of the minifilter associated with this instace
            //

            USHORT FilterNameLength;
            USHORT FilterNameBufferOffset;

        } MiniFilter;

        //
        //  Legacyfilter information
        //

        struct {

            //
            //  IASIL - Instance Aggregate Standard Information LegacyFilter flags
            //

            ULONG Flags;

                //
                //  If set this volume is not current attached to a storage stack
                //

                #define FLTFL_IASIL_DETACHED_VOLUME 0x00000001

            //
            //  The altitude of this attachment
            //

            USHORT AltitudeLength;
            USHORT AltitudeBufferOffset;

            //
            //  The volume name this filter is attached to
            //

            USHORT VolumeNameLength;
            USHORT VolumeNameBufferOffset;

            //
            //  The name of the filter associated with this attachment
            //

            USHORT FilterNameLength;
            USHORT FilterNameBufferOffset;

        } LegacyFilter;

    } Type;

} INSTANCE_AGGREGATE_STANDARD_INFORMATION, *PINSTANCE_AGGREGATE_STANDARD_INFORMATION;
#endif // FLT_MGR_LONGHORN


/////////////////////////////////////////////////////////////////////////////
//
//  Message defintitions
//
/////////////////////////////////////////////////////////////////////////////

typedef struct _FILTER_MESSAGE_HEADER {

    //
    //  OUT
    //
    //  Total buffer length in bytes, including the FILTER_REPLY_HEADER, of
    //  the expected reply.  If no reply is expected, 0 is returned.
    //

    ULONG ReplyLength;

    //
    //  OUT
    //
    //  Unique Id for this message.  This will be set when the kernel message
    //  satifies this FilterGetMessage or FilterInstanceGetMessage request.
    //  If replying to this message, this is the MessageId that should be used.
    //

    ULONGLONG MessageId;

    //
    //  General filter-specific buffer data follows...
    //

} FILTER_MESSAGE_HEADER, *PFILTER_MESSAGE_HEADER;

typedef struct _FILTER_REPLY_HEADER {

    //
    //  IN.
    //
    //  Status of this reply. This status will be returned back to the filter
    //  driver who is waiting for a reply.
    //

    NTSTATUS Status;

    //
    //  IN
    //
    //  Unique Id for this message.  This id was returned in the
    //  FILTER_MESSAGE_HEADER from the kernel message to which we are replying.
    //

    ULONGLONG MessageId;

    //
    //  General filter-specific buffer data follows...
    //

} FILTER_REPLY_HEADER, *PFILTER_REPLY_HEADER;

#endif //FLT_MGR_BASELINE

#endif /* __FLT_USER_STRUCTURES_H__ */

