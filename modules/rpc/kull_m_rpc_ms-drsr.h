#pragma once
#include "kull_m_rpc.h"

typedef LONGLONG DSTIME;
typedef LONGLONG USN;
typedef ULONG ATTRTYP;
typedef void *DRS_HANDLE;

typedef struct _NT4SID {
	unsigned char Data[ 28 ];
} NT4SID;

typedef struct _DSNAME {
	unsigned long structLen;
	unsigned long SidLen;
	GUID Guid;
	NT4SID Sid;
	unsigned long NameLen;
	WCHAR StringName[ANYSIZE_ARRAY];
} DSNAME;

typedef struct _USN_VECTOR {
	USN usnHighObjUpdate;
	USN usnReserved;
	USN usnHighPropUpdate;
} USN_VECTOR;

typedef struct _UPTODATE_CURSOR_V1 {
	UUID uuidDsa;
	USN usnHighPropUpdate;
} UPTODATE_CURSOR_V1;

typedef struct _UPTODATE_VECTOR_V1_EXT {
	DWORD dwVersion;
	DWORD dwReserved1;
	DWORD cNumCursors;
	DWORD dwReserved2;
	UPTODATE_CURSOR_V1 rgCursors[ANYSIZE_ARRAY];
} UPTODATE_VECTOR_V1_EXT;

typedef struct _OID_t {
	unsigned int length;
	BYTE *elements;
} OID_t;

typedef struct _PrefixTableEntry {
	unsigned long ndx;
	OID_t prefix;
} PrefixTableEntry;

typedef struct _SCHEMA_PREFIX_TABLE {
	DWORD PrefixCount;
	PrefixTableEntry *pPrefixEntry;
} SCHEMA_PREFIX_TABLE;

typedef struct _PARTIAL_ATTR_VECTOR_V1_EXT {
	DWORD dwVersion;
	DWORD dwReserved1;
	DWORD cAttrs;
	ATTRTYP rgPartialAttr[ANYSIZE_ARRAY];
} PARTIAL_ATTR_VECTOR_V1_EXT;

typedef struct _MTX_ADDR {
	unsigned long mtx_namelen;
	unsigned char mtx_name[ANYSIZE_ARRAY];
} MTX_ADDR;

typedef struct _ATTRVAL {
	ULONG valLen;
	UCHAR *pVal;
} ATTRVAL;

typedef struct _ATTRVALBLOCK {
	ULONG valCount;
	ATTRVAL *pAVal;
} ATTRVALBLOCK;

typedef struct _ATTR {
	ATTRTYP attrTyp;
	ATTRVALBLOCK AttrVal;
} ATTR;

typedef struct _ATTRBLOCK {
	ULONG attrCount;
	ATTR *pAttr;
} ATTRBLOCK;

typedef struct _ENTINF {
	DSNAME *pName;
	unsigned long ulFlags;
	ATTRBLOCK AttrBlock;
} ENTINF;

typedef struct _PROPERTY_META_DATA_EXT {
	DWORD dwVersion;
	DSTIME timeChanged;
	UUID uuidDsaOriginating;
	USN usnOriginating;
} PROPERTY_META_DATA_EXT;

typedef struct _PROPERTY_META_DATA_EXT_VECTOR {
	DWORD cNumProps;
	PROPERTY_META_DATA_EXT rgMetaData[ANYSIZE_ARRAY];
} PROPERTY_META_DATA_EXT_VECTOR;

typedef struct _REPLENTINFLIST {
	struct _REPLENTINFLIST *pNextEntInf;
	ENTINF Entinf;
	BOOL fIsNCPrefix;
	UUID *pParentGuid;
	PROPERTY_META_DATA_EXT_VECTOR *pMetaDataExt;
} REPLENTINFLIST;

typedef struct _UPTODATE_CURSOR_V2 {
	UUID uuidDsa;
	USN usnHighPropUpdate;
	DSTIME timeLastSyncSuccess;
} UPTODATE_CURSOR_V2;

typedef struct _UPTODATE_VECTOR_V2_EXT {
	DWORD dwVersion;
	DWORD dwReserved1;
	DWORD cNumCursors;
	DWORD dwReserved2;
	UPTODATE_CURSOR_V2 rgCursors[ANYSIZE_ARRAY];
} UPTODATE_VECTOR_V2_EXT;

typedef struct _VALUE_META_DATA_EXT_V1 {
	DSTIME timeCreated;
	PROPERTY_META_DATA_EXT MetaData;
} VALUE_META_DATA_EXT_V1;

typedef struct _VALUE_META_DATA_EXT_V3 {
	DSTIME timeCreated;
	PROPERTY_META_DATA_EXT MetaData;
	DWORD unused1;
	DWORD unused2;
	DWORD unused3;
	DSTIME timeExpired;
} VALUE_META_DATA_EXT_V3;

typedef struct _REPLVALINF_V1 {
	DSNAME *pObject;
	ATTRTYP attrTyp;
	ATTRVAL Aval;
	BOOL fIsPresent;
	VALUE_META_DATA_EXT_V1 MetaData;
} REPLVALINF_V1;

typedef struct REPLVALINF_V3 {
	DSNAME *pObject;
	ATTRTYP attrTyp;
	ATTRVAL Aval;
	BOOL fIsPresent;
	VALUE_META_DATA_EXT_V3 MetaData;
} REPLVALINF_V3;

typedef struct _DS_NAME_RESULT_ITEMW {
	DWORD status;
	WCHAR *pDomain;
	WCHAR *pName;
} DS_NAME_RESULT_ITEMW, *PDS_NAME_RESULT_ITEMW;

typedef struct _DS_NAME_RESULTW {
	DWORD cItems;
	PDS_NAME_RESULT_ITEMW rItems;
} DS_NAME_RESULTW, *PDS_NAME_RESULTW;

typedef struct _DS_DOMAIN_CONTROLLER_INFO_1W {
	WCHAR *NetbiosName;
	WCHAR *DnsHostName;
	WCHAR *SiteName;
	WCHAR *ComputerObjectName;
	WCHAR *ServerObjectName;
	BOOL fIsPdc;
	BOOL fDsEnabled;
} DS_DOMAIN_CONTROLLER_INFO_1W;

typedef struct _DS_DOMAIN_CONTROLLER_INFO_2W {
	WCHAR *NetbiosName;
	WCHAR *DnsHostName;
	WCHAR *SiteName;
	WCHAR *SiteObjectName;
	WCHAR *ComputerObjectName;
	WCHAR *ServerObjectName;
	WCHAR *NtdsDsaObjectName;
	BOOL fIsPdc;
	BOOL fDsEnabled;
	BOOL fIsGc;
	GUID SiteObjectGuid;
	GUID ComputerObjectGuid;
	GUID ServerObjectGuid;
	GUID NtdsDsaObjectGuid;
} DS_DOMAIN_CONTROLLER_INFO_2W;

typedef struct _DS_DOMAIN_CONTROLLER_INFO_3W {
	WCHAR *NetbiosName;
	WCHAR *DnsHostName;
	WCHAR *SiteName;
	WCHAR *SiteObjectName;
	WCHAR *ComputerObjectName;
	WCHAR *ServerObjectName;
	WCHAR *NtdsDsaObjectName;
	BOOL fIsPdc;
	BOOL fDsEnabled;
	BOOL fIsGc;
	BOOL fIsRodc;
	GUID SiteObjectGuid;
	GUID ComputerObjectGuid;
	GUID ServerObjectGuid;
	GUID NtdsDsaObjectGuid;
} DS_DOMAIN_CONTROLLER_INFO_3W;

typedef struct _DS_DOMAIN_CONTROLLER_INFO_FFFFFFFFW {
	DWORD IPAddress;
	DWORD NotificationCount;
	DWORD secTimeConnected;
	DWORD Flags;
	DWORD TotalRequests;
	DWORD Reserved1;
	WCHAR *UserName;
} DS_DOMAIN_CONTROLLER_INFO_FFFFFFFFW;

typedef struct _ENTINFLIST {
	struct _ENTINFLIST *pNextEntInf;
	ENTINF Entinf;
} ENTINFLIST;

typedef struct _DRS_EXTENSIONS {
	DWORD cb;
	BYTE rgb[ANYSIZE_ARRAY];
} DRS_EXTENSIONS;

typedef struct _DRS_MSG_GETCHGREQ_V3 {
	UUID uuidDsaObjDest;
	UUID uuidInvocIdSrc;
	DSNAME *pNC;
	USN_VECTOR usnvecFrom;
	UPTODATE_VECTOR_V1_EXT *pUpToDateVecDestV1;
	PARTIAL_ATTR_VECTOR_V1_EXT *pPartialAttrVecDestV1;
	SCHEMA_PREFIX_TABLE PrefixTableDest;
	ULONG ulFlags;
	ULONG cMaxObjects;
	ULONG cMaxBytes;
	ULONG ulExtendedOp;
} DRS_MSG_GETCHGREQ_V3;

typedef struct _DRS_MSG_GETCHGREQ_V4 {
	UUID uuidTransportObj;
	MTX_ADDR *pmtxReturnAddress;
	DRS_MSG_GETCHGREQ_V3 V3;
} DRS_MSG_GETCHGREQ_V4;

typedef struct _DRS_MSG_GETCHGREQ_V7 {
	UUID uuidTransportObj;
	MTX_ADDR *pmtxReturnAddress;
	DRS_MSG_GETCHGREQ_V3 V3;
	PARTIAL_ATTR_VECTOR_V1_EXT *pPartialAttrSet;
	PARTIAL_ATTR_VECTOR_V1_EXT *pPartialAttrSetEx;
	SCHEMA_PREFIX_TABLE PrefixTableDest;
} DRS_MSG_GETCHGREQ_V7;

typedef struct _DRS_MSG_GETCHGREPLY_V1 {
	UUID uuidDsaObjSrc;
	UUID uuidInvocIdSrc;
	DSNAME *pNC;
	USN_VECTOR usnvecFrom;
	USN_VECTOR usnvecTo;
	UPTODATE_VECTOR_V1_EXT *pUpToDateVecSrcV1;
	SCHEMA_PREFIX_TABLE PrefixTableSrc;
	ULONG ulExtendedRet;
	ULONG cNumObjects;
	ULONG cNumBytes;
	REPLENTINFLIST *pObjects;
	BOOL fMoreData;
} DRS_MSG_GETCHGREPLY_V1;

typedef struct _DRS_MSG_GETCHGREPLY_V6 {
	UUID uuidDsaObjSrc;
	UUID uuidInvocIdSrc;
	DSNAME *pNC;
	USN_VECTOR usnvecFrom;
	USN_VECTOR usnvecTo;
	UPTODATE_VECTOR_V2_EXT *pUpToDateVecSrc;
	SCHEMA_PREFIX_TABLE PrefixTableSrc;
	ULONG ulExtendedRet;
	ULONG cNumObjects;
	ULONG cNumBytes;
	REPLENTINFLIST *pObjects;
	BOOL fMoreData;
	ULONG cNumNcSizeObjects;
	ULONG cNumNcSizeValues;
	DWORD cNumValues;
	REPLVALINF_V1 *rgValues;
	DWORD dwDRSError;
} DRS_MSG_GETCHGREPLY_V6;

typedef struct _DRS_MSG_GETCHGREPLY_V9 {
	UUID uuidDsaObjSrc;
	UUID uuidInvocIdSrc;
	DSNAME *pNC;
	USN_VECTOR usnvecFrom;
	USN_VECTOR usnvecTo;
	UPTODATE_VECTOR_V2_EXT *pUpToDateVecSrc;
	SCHEMA_PREFIX_TABLE PrefixTableSrc;
	ULONG ulExtendedRet;
	ULONG cNumObjects;
	ULONG cNumBytes;
	REPLENTINFLIST *pObjects;
	BOOL fMoreData;
	ULONG cNumNcSizeObjects;
	ULONG cNumNcSizeValues;
	DWORD cNumValues;
	REPLVALINF_V3 *rgValues;
	DWORD dwDRSError;
} DRS_MSG_GETCHGREPLY_V9;

typedef struct _DRS_COMPRESSED_BLOB {
	DWORD cbUncompressedSize;
	DWORD cbCompressedSize;
	BYTE *pbCompressedData;
} DRS_COMPRESSED_BLOB;

typedef struct _DRS_MSG_GETCHGREQ_V5 {
	UUID uuidDsaObjDest;
	UUID uuidInvocIdSrc;
	DSNAME *pNC;
	USN_VECTOR usnvecFrom;
	UPTODATE_VECTOR_V1_EXT *pUpToDateVecDestV1;
	ULONG ulFlags;
	ULONG cMaxObjects;
	ULONG cMaxBytes;
	ULONG ulExtendedOp;
	ULARGE_INTEGER liFsmoInfo;
} DRS_MSG_GETCHGREQ_V5;

typedef struct _DRS_MSG_GETCHGREQ_V8 {
	UUID uuidDsaObjDest;
	UUID uuidInvocIdSrc;
	DSNAME *pNC;
	USN_VECTOR usnvecFrom;
	UPTODATE_VECTOR_V1_EXT *pUpToDateVecDest;
	ULONG ulFlags;
	ULONG cMaxObjects;
	ULONG cMaxBytes;
	ULONG ulExtendedOp;
	ULARGE_INTEGER liFsmoInfo;
	PARTIAL_ATTR_VECTOR_V1_EXT *pPartialAttrSet;
	PARTIAL_ATTR_VECTOR_V1_EXT *pPartialAttrSetEx;
	SCHEMA_PREFIX_TABLE PrefixTableDest;
} DRS_MSG_GETCHGREQ_V8;

typedef struct _DRS_MSG_GETCHGREQ_V10 {
	UUID uuidDsaObjDest;
	UUID uuidInvocIdSrc;
	DSNAME *pNC;
	USN_VECTOR usnvecFrom;
	UPTODATE_VECTOR_V1_EXT *pUpToDateVecDest;
	ULONG ulFlags;
	ULONG cMaxObjects;
	ULONG cMaxBytes;
	ULONG ulExtendedOp;
	ULARGE_INTEGER liFsmoInfo;
	PARTIAL_ATTR_VECTOR_V1_EXT *pPartialAttrSet;
	PARTIAL_ATTR_VECTOR_V1_EXT *pPartialAttrSetEx;
	SCHEMA_PREFIX_TABLE PrefixTableDest;
	ULONG ulMoreFlags;
} DRS_MSG_GETCHGREQ_V10;

typedef union _DRS_MSG_GETCHGREQ {
	DRS_MSG_GETCHGREQ_V4 V4;
	DRS_MSG_GETCHGREQ_V5 V5;
	DRS_MSG_GETCHGREQ_V7 V7;
	DRS_MSG_GETCHGREQ_V8 V8;
	DRS_MSG_GETCHGREQ_V10 V10;
} DRS_MSG_GETCHGREQ;

typedef struct _DRS_MSG_GETCHGREPLY_V2 {
	DRS_COMPRESSED_BLOB CompressedV1;
} DRS_MSG_GETCHGREPLY_V2;

typedef enum _DRS_COMP_ALG_TYPE {
	DRS_COMP_ALG_NONE	= 0,
	DRS_COMP_ALG_UNUSED	= 1,
	DRS_COMP_ALG_MSZIP	= 2,
	DRS_COMP_ALG_WIN2K3	= 3
} DRS_COMP_ALG_TYPE;

typedef struct _DRS_MSG_GETCHGREPLY_V7 {
	DWORD dwCompressedVersion;
	DRS_COMP_ALG_TYPE CompressionAlg;
	DRS_COMPRESSED_BLOB CompressedAny;
} DRS_MSG_GETCHGREPLY_V7;

typedef union _DRS_MSG_GETCHGREPLY {
	DRS_MSG_GETCHGREPLY_V1 V1;
	DRS_MSG_GETCHGREPLY_V2 V2;
	DRS_MSG_GETCHGREPLY_V6 V6;
	DRS_MSG_GETCHGREPLY_V7 V7;
	DRS_MSG_GETCHGREPLY_V9 V9;
} DRS_MSG_GETCHGREPLY;

typedef struct _DRS_MSG_CRACKREQ_V1 {
	ULONG CodePage;
	ULONG LocaleId;
	DWORD dwFlags;
	DWORD formatOffered;
	DWORD formatDesired;
	DWORD cNames;
	WCHAR **rpNames;
} DRS_MSG_CRACKREQ_V1;

typedef union _DRS_MSG_CRACKREQ {
	DRS_MSG_CRACKREQ_V1 V1;
} DRS_MSG_CRACKREQ;

typedef struct _DRS_MSG_CRACKREPLY_V1 {
	DS_NAME_RESULTW *pResult;
} DRS_MSG_CRACKREPLY_V1;

typedef union _DRS_MSG_CRACKREPLY {
	DRS_MSG_CRACKREPLY_V1 V1;
} DRS_MSG_CRACKREPLY;

typedef struct _DRS_MSG_DCINFOREQ_V1 {
	WCHAR *Domain;
	DWORD InfoLevel;
} DRS_MSG_DCINFOREQ_V1;

typedef union _DRS_MSG_DCINFOREQ {
	DRS_MSG_DCINFOREQ_V1 V1;
} DRS_MSG_DCINFOREQ, *PDRS_MSG_DCINFOREQ;

typedef struct _DRS_MSG_DCINFOREPLY_V1 {
	DWORD cItems;
	DS_DOMAIN_CONTROLLER_INFO_1W *rItems;
} DRS_MSG_DCINFOREPLY_V1;

typedef struct _DRS_MSG_DCINFOREPLY_V2 {
	DWORD cItems;
	DS_DOMAIN_CONTROLLER_INFO_2W *rItems;
} DRS_MSG_DCINFOREPLY_V2;

typedef struct _DRS_MSG_DCINFOREPLY_V3 {
	DWORD cItems;
	DS_DOMAIN_CONTROLLER_INFO_3W *rItems;
} DRS_MSG_DCINFOREPLY_V3;

typedef struct _DRS_MSG_DCINFOREPLY_VFFFFFFFF {
	DWORD cItems;
	DS_DOMAIN_CONTROLLER_INFO_FFFFFFFFW *rItems;
} DRS_MSG_DCINFOREPLY_VFFFFFFFF;

typedef union _DRS_MSG_DCINFOREPLY {
	DRS_MSG_DCINFOREPLY_V1 V1;
	DRS_MSG_DCINFOREPLY_V2 V2;
	DRS_MSG_DCINFOREPLY_V3 V3;
	DRS_MSG_DCINFOREPLY_VFFFFFFFF VFFFFFFFF;
} DRS_MSG_DCINFOREPLY;

ULONG IDL_DRSBind(handle_t rpc_handle, UUID *puuidClientDsa, DRS_EXTENSIONS *pextClient, DRS_EXTENSIONS **ppextServer, DRS_HANDLE *phDrs);
ULONG IDL_DRSUnbind(DRS_HANDLE *phDrs);
ULONG IDL_DRSGetNCChanges(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_GETCHGREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_GETCHGREPLY *pmsgOut);
ULONG IDL_DRSCrackNames(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_CRACKREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_CRACKREPLY *pmsgOut);
ULONG IDL_DRSDomainControllerInfo(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_DCINFOREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_DCINFOREPLY *pmsgOut);

void DRS_MSG_GETCHGREPLY_V6_Free(handle_t _MidlEsHandle, DRS_MSG_GETCHGREPLY_V6 * _pType);
void DRS_MSG_CRACKREPLY_V1_Free(handle_t _MidlEsHandle, DRS_MSG_CRACKREPLY_V1 * _pType);
void DRS_MSG_DCINFOREPLY_V2_Free(handle_t _MidlEsHandle, DRS_MSG_DCINFOREPLY_V2 * _pType);

#define kull_m_rpc_ms_drsr_FreeDRS_MSG_GETCHGREPLY_V6(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_GETCHGREPLY_V6_Free)
#define kull_m_rpc_ms_drsr_FreeDRS_MSG_CRACKREPLY_V1(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_CRACKREPLY_V1_Free)
#define kull_m_rpc_ms_drsr_FreeDRS_MSG_DCINFOREPLY_V2(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_DCINFOREPLY_V2_Free)