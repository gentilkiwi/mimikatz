#pragma once
#include "kull_m_rpc.h"

typedef LONGLONG DSTIME;
typedef LONGLONG USN;
typedef ULONG ATTRTYP;
typedef void *DRS_HANDLE;

typedef struct _NT4SID {
	UCHAR Data[28];
} NT4SID;

typedef struct _DSNAME {
	ULONG structLen;
	ULONG SidLen;
	GUID Guid;
	NT4SID Sid;
	ULONG NameLen;
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
	ULONG ndx;
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
	ULONG ulFlags;
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

typedef struct _REPLVALINF_V1 {
	DSNAME *pObject;
	ATTRTYP attrTyp;
	ATTRVAL Aval;
	BOOL fIsPresent;
	VALUE_META_DATA_EXT_V1 MetaData;
} REPLVALINF_V1;

typedef struct _REPLTIMES {
	UCHAR rgTimes[84];
} REPLTIMES;

typedef struct _DS_NAME_RESULT_ITEMW {
	DWORD status;
	WCHAR *pDomain;
	WCHAR *pName;
} DS_NAME_RESULT_ITEMW, *PDS_NAME_RESULT_ITEMW;

typedef struct _DS_NAME_RESULTW {
	DWORD cItems;
	PDS_NAME_RESULT_ITEMW rItems;
} DS_NAME_RESULTW, *PDS_NAME_RESULTW;

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

typedef struct _ENTINFLIST {
	struct _ENTINFLIST *pNextEntInf;
	ENTINF Entinf;
} ENTINFLIST;

typedef struct _DRS_EXTENSIONS {
	DWORD cb;
	BYTE rgb[ANYSIZE_ARRAY];
} DRS_EXTENSIONS;

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

typedef union _DRS_MSG_GETCHGREPLY {
	DRS_MSG_GETCHGREPLY_V6 V6;
} DRS_MSG_GETCHGREPLY;

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

typedef union _DRS_MSG_GETCHGREQ {
	DRS_MSG_GETCHGREQ_V8 V8;
} DRS_MSG_GETCHGREQ;

typedef struct _DRS_MSG_UPDREFS_V1 {
	DSNAME *pNC;
	UCHAR *pszDsaDest;
	UUID uuidDsaObjDest;
	ULONG ulOptions;
} DRS_MSG_UPDREFS_V1;

typedef union _DRS_MSG_UPDREFS {
	DRS_MSG_UPDREFS_V1 V1;
} 	DRS_MSG_UPDREFS;

typedef struct _DRS_MSG_REPADD_V1 {
	DSNAME *pNC;
	UCHAR *pszDsaSrc;
	REPLTIMES rtSchedule;
	ULONG ulOptions;
} DRS_MSG_REPADD_V1;

typedef union _DRS_MSG_REPADD {
	DRS_MSG_REPADD_V1 V1;
} DRS_MSG_REPADD;

typedef struct _DRS_MSG_REPDEL_V1 {
	DSNAME *pNC;
	UCHAR *pszDsaSrc;
	ULONG ulOptions;
} DRS_MSG_REPDEL_V1;

typedef union _DRS_MSG_REPDEL {
	DRS_MSG_REPDEL_V1 V1;
} DRS_MSG_REPDEL;

typedef struct _DRS_MSG_VERIFYREQ_V1 {
	DWORD dwFlags;
	DWORD cNames;
	DSNAME **rpNames;
	ATTRBLOCK RequiredAttrs;
	SCHEMA_PREFIX_TABLE PrefixTable;
} DRS_MSG_VERIFYREQ_V1;

typedef union _DRS_MSG_VERIFYREQ {
	DRS_MSG_VERIFYREQ_V1 V1;
} DRS_MSG_VERIFYREQ;

typedef struct _DRS_MSG_VERIFYREPLY_V1 {
	DWORD error;
	DWORD cNames;
	ENTINF *rpEntInf;
	SCHEMA_PREFIX_TABLE PrefixTable;
} DRS_MSG_VERIFYREPLY_V1;

typedef union _DRS_MSG_VERIFYREPLY {
	DRS_MSG_VERIFYREPLY_V1 V1;
} DRS_MSG_VERIFYREPLY;

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

typedef struct _DRS_MSG_DCINFOREPLY_V2 {
	DWORD cItems;
	DS_DOMAIN_CONTROLLER_INFO_2W *rItems;
} DRS_MSG_DCINFOREPLY_V2;

typedef union _DRS_MSG_DCINFOREPLY {
	DRS_MSG_DCINFOREPLY_V2 V2;
} DRS_MSG_DCINFOREPLY;

typedef struct _DRS_MSG_ADDENTRYREQ_V2 {
	ENTINFLIST EntInfList;
} DRS_MSG_ADDENTRYREQ_V2;

typedef union _DRS_MSG_ADDENTRYREQ {
	DRS_MSG_ADDENTRYREQ_V2 V2;
} DRS_MSG_ADDENTRYREQ;

typedef struct _ADDENTRY_REPLY_INFO {
	GUID objGuid;
	NT4SID objSid;
} ADDENTRY_REPLY_INFO;

typedef struct _DRS_MSG_ADDENTRYREPLY_V2 {
	DSNAME *pErrorObject;
	DWORD errCode;
	DWORD dsid;
	DWORD extendedErr;
	DWORD extendedData;
	USHORT problem;
	ULONG cObjectsAdded;
	ADDENTRY_REPLY_INFO *infoList;
} DRS_MSG_ADDENTRYREPLY_V2;

typedef union _DRS_MSG_ADDENTRYREPLY {
	DRS_MSG_ADDENTRYREPLY_V2 V2;
} DRS_MSG_ADDENTRYREPLY;

extern RPC_IF_HANDLE drsuapi_v4_0_c_ifspec;
extern RPC_IF_HANDLE drsuapi_v4_0_s_ifspec;

ULONG IDL_DRSBind(handle_t rpc_handle, UUID *puuidClientDsa, DRS_EXTENSIONS *pextClient, DRS_EXTENSIONS **ppextServer, DRS_HANDLE *phDrs);
ULONG IDL_DRSUnbind(DRS_HANDLE *phDrs);
ULONG IDL_DRSReplicaAdd(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_REPADD *pmsgAdd);
ULONG IDL_DRSReplicaDel(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_REPDEL *pmsgDel);
ULONG IDL_DRSGetNCChanges(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_GETCHGREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_GETCHGREPLY *pmsgOut);
ULONG IDL_DRSCrackNames(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_CRACKREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_CRACKREPLY *pmsgOut);
ULONG IDL_DRSDomainControllerInfo(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_DCINFOREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_DCINFOREPLY *pmsgOut);
ULONG IDL_DRSAddEntry(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_ADDENTRYREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_ADDENTRYREPLY *pmsgOut);

void DRS_MSG_GETCHGREPLY_V6_Free(handle_t _MidlEsHandle, DRS_MSG_GETCHGREPLY_V6 * _pType);
void DRS_MSG_CRACKREPLY_V1_Free(handle_t _MidlEsHandle, DRS_MSG_CRACKREPLY_V1 * _pType);
void DRS_MSG_DCINFOREPLY_V2_Free(handle_t _MidlEsHandle, DRS_MSG_DCINFOREPLY_V2 * _pType);
void DRS_MSG_ADDENTRYREPLY_V2_Free(handle_t _MidlEsHandle, DRS_MSG_ADDENTRYREPLY_V2 * _pType);

#define kull_m_rpc_ms_drsr_FreeDRS_MSG_GETCHGREPLY_V6(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_GETCHGREPLY_V6_Free)
#define kull_m_rpc_ms_drsr_FreeDRS_MSG_CRACKREPLY_V1(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_CRACKREPLY_V1_Free)
#define kull_m_rpc_ms_drsr_FreeDRS_MSG_DCINFOREPLY_V2(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_DCINFOREPLY_V2_Free)
#define kull_m_rpc_ms_drsr_FreeDRS_MSG_ADDENTRYREPLY_V2(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) DRS_MSG_ADDENTRYREPLY_V2_Free)

void __RPC_USER SRV_DRS_HANDLE_rundown(DRS_HANDLE hDrs);
ULONG SRV_IDL_DRSBind(handle_t rpc_handle, UUID *puuidClientDsa, DRS_EXTENSIONS *pextClient, DRS_EXTENSIONS **ppextServer, DRS_HANDLE *phDrs);
ULONG SRV_IDL_DRSUnbind(DRS_HANDLE *phDrs);
ULONG SRV_IDL_DRSGetNCChanges(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_GETCHGREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_GETCHGREPLY *pmsgOut);
ULONG SRV_IDL_DRSVerifyNames(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_VERIFYREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_VERIFYREPLY *pmsgOut);
ULONG SRV_IDL_DRSUpdateRefs(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_UPDREFS *pmsgUpdRefs);

void SRV_OpnumNotImplemented(handle_t IDL_handle);
ULONG SRV_IDL_DRSReplicaAddNotImplemented(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_REPADD *pmsgAdd);
ULONG SRV_IDL_DRSReplicaDelNotImplemented(DRS_HANDLE hDrs, DWORD dwVersion, DRS_MSG_REPDEL *pmsgDel);
ULONG SRV_IDL_DRSCrackNamesNotImplemented(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_CRACKREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_CRACKREPLY *pmsgOut);
ULONG SRV_IDL_DRSDomainControllerInfoNotImplemented(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_DCINFOREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_DCINFOREPLY *pmsgOut);
ULONG SRV_IDL_DRSAddEntryNotImplemented(DRS_HANDLE hDrs, DWORD dwInVersion, DRS_MSG_ADDENTRYREQ *pmsgIn, DWORD *pdwOutVersion, DRS_MSG_ADDENTRYREPLY *pmsgOut);