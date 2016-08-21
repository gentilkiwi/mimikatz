#pragma once
#include "kull_m_rpc.h"

typedef wchar_t *CLAIM_ID;
typedef wchar_t **PCLAIM_ID;

typedef enum _CLAIM_TYPE {
	CLAIM_TYPE_INT64	= 1,
	CLAIM_TYPE_UINT64	= 2,
	CLAIM_TYPE_STRING	= 3,
	CLAIM_TYPE_BOOLEAN	= 6
} CLAIM_TYPE, *PCLAIM_TYPE;

typedef enum _CLAIMS_SOURCE_TYPE {
	CLAIMS_SOURCE_TYPE_AD	= 1,
	CLAIMS_SOURCE_TYPE_CERTIFICATE	= ( CLAIMS_SOURCE_TYPE_AD + 1 ) 
} CLAIMS_SOURCE_TYPE;

typedef enum _CLAIMS_COMPRESSION_FORMAT {
	CLAIMS_COMPRESSION_FORMAT_NONE			= 0,
	CLAIMS_COMPRESSION_FORMAT_LZNT1			= 2,
	CLAIMS_COMPRESSION_FORMAT_XPRESS		= 3,
	CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF	= 4
} CLAIMS_COMPRESSION_FORMAT;

typedef struct _CLAIM_ENTRY {
	CLAIM_ID Id;
	CLAIM_TYPE Type;
	union 
	{
		struct _ci64
		{
			ULONG ValueCount;
			LONG64 *Int64Values;
		} 	ci64;
		struct _cui64
		{
			ULONG ValueCount;
			ULONG64 *Uint64Values;
		} 	cui64;
		struct _cs
		{
			ULONG ValueCount;
			LPWSTR *StringValues;
		} 	cs;
		struct _cb
		{
			ULONG ValueCount;
			ULONG64 *BooleanValues;
		} 	cb;
	} 	Values;
} CLAIM_ENTRY, *PCLAIM_ENTRY;

typedef struct _CLAIMS_ARRAY {
	CLAIMS_SOURCE_TYPE usClaimsSourceType;
	ULONG ulClaimsCount;
	PCLAIM_ENTRY ClaimEntries;
} CLAIMS_ARRAY, *PCLAIMS_ARRAY;

typedef struct _CLAIMS_SET {
	ULONG ulClaimsArrayCount;
	PCLAIMS_ARRAY ClaimsArrays;
	USHORT usReservedType;
	ULONG ulReservedFieldSize;
	BYTE *ReservedField;
} CLAIMS_SET, *PCLAIMS_SET;

typedef struct _CLAIMS_SET_METADATA {
	ULONG ulClaimsSetSize;
	BYTE *ClaimsSet;
	CLAIMS_COMPRESSION_FORMAT usCompressionFormat;
	ULONG ulUncompressedClaimsSetSize;
	USHORT usReservedType;
	ULONG ulReservedFieldSize;
	BYTE *ReservedField;
} CLAIMS_SET_METADATA, *PCLAIMS_SET_METADATA;

size_t PCLAIMS_SET_METADATA_AlignSize(handle_t _MidlEsHandle, PCLAIMS_SET_METADATA * _pType);
void PCLAIMS_SET_METADATA_Encode(handle_t _MidlEsHandle, PCLAIMS_SET_METADATA * _pType);
void PCLAIMS_SET_METADATA_Decode(handle_t _MidlEsHandle, PCLAIMS_SET_METADATA * _pType);
void PCLAIMS_SET_METADATA_Free(handle_t _MidlEsHandle, PCLAIMS_SET_METADATA * _pType);

size_t PCLAIMS_SET_AlignSize(handle_t _MidlEsHandle, PCLAIMS_SET * _pType);
void PCLAIMS_SET_Encode(handle_t _MidlEsHandle, PCLAIMS_SET * _pType);
void PCLAIMS_SET_Decode(handle_t _MidlEsHandle, PCLAIMS_SET * _pType);
void PCLAIMS_SET_Free(handle_t _MidlEsHandle, PCLAIMS_SET * _pType);

#define kull_m_rpc_DecodeClaimsSetMetaData(data, size, pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) PCLAIMS_SET_METADATA_Decode)
#define kull_m_rpc_FreeClaimsSetMetaData(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) PCLAIMS_SET_METADATA_Free)
#define kull_m_rpc_EncodeClaimsSetMetaData(pObject, data, size) kull_m_rpc_Generic_Encode(pObject, data, size, (PGENERIC_RPC_ENCODE) PCLAIMS_SET_METADATA_Encode, (PGENERIC_RPC_ALIGNSIZE) PCLAIMS_SET_METADATA_AlignSize)

#define kull_m_rpc_DecodeClaimsSet(data, size, pObject) kull_m_rpc_Generic_Decode(data, size, pObject, (PGENERIC_RPC_DECODE) PCLAIMS_SET_Decode)
#define kull_m_rpc_FreeClaimsSet(pObject) kull_m_rpc_Generic_Free(pObject, (PGENERIC_RPC_FREE) PCLAIMS_SET_Free)
#define kull_m_rpc_EncodeClaimsSet(pObject, data, size) kull_m_rpc_Generic_Encode(pObject, data, size, (PGENERIC_RPC_ENCODE) PCLAIMS_SET_Encode, (PGENERIC_RPC_ALIGNSIZE) PCLAIMS_SET_AlignSize)