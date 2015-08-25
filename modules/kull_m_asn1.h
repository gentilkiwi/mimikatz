/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_string.h"

#define DIRTY_ASN1_ID_BOOLEAN			0x01
#define DIRTY_ASN1_ID_INTEGER			0x02
#define DIRTY_ASN1_ID_BIT_STRING		0x03
#define DIRTY_ASN1_ID_OCTET_STRING		0x04
#define DIRTY_ASN1_ID_NULL				0x05
#define DIRTY_ASN1_ID_OBJECT_IDENTIFIER	0x06
#define DIRTY_ASN1_ID_GENERAL_STRING	0x1b
#define DIRTY_ASN1_ID_GENERALIZED_TIME	0x18
#define DIRTY_ASN1_ID_SEQUENCE			0x30

#define DIRTY_ASN1_MASK_HIGH_SIZE		0x80
#define DIRTY_ASN1_MASK_APPLICATION		0x60
#define DIRTY_ASN1_MASK_CONTEXT			0xA0

typedef struct  _DIRTY_ASN1_SEQUENCE_1 {
	UCHAR type;
	UCHAR size;
} DIRTY_ASN1_SEQUENCE_1, *PDIRTY_ASN1_SEQUENCE_1;

typedef struct _DIRTY_ASN1_SEQUENCE_2 {
	UCHAR type;
	UCHAR sizeSize;
	USHORT size;
} DIRTY_ASN1_SEQUENCE_2, *PDIRTY_ASN1_SEQUENCE_2;

typedef struct _DIRTY_ASN1_SEQUENCE_EASY {
	union {
		DIRTY_ASN1_SEQUENCE_1 seq1;
		DIRTY_ASN1_SEQUENCE_2 seq2;
	};
} DIRTY_ASN1_SEQUENCE_EASY, *PDIRTY_ASN1_SEQUENCE_EASY;

DWORD kull_m_asn1_getSize(PDIRTY_ASN1_SEQUENCE_EASY sequence);
void kull_m_asn1_append(PDIRTY_ASN1_SEQUENCE_EASY * parent, PDIRTY_ASN1_SEQUENCE_EASY child);
void kull_m_asn1_append_ctx_and_data_to_seq(PDIRTY_ASN1_SEQUENCE_EASY * Seq, UCHAR CtxId, PDIRTY_ASN1_SEQUENCE_EASY Data);
PDIRTY_ASN1_SEQUENCE_EASY kull_m_asn1_create(UCHAR type, LPCVOID data, DWORD size, PDIRTY_ASN1_SEQUENCE_EASY *parent);
PDIRTY_ASN1_SEQUENCE_EASY kull_m_asn1_GenTime(PFILETIME localtime);
PDIRTY_ASN1_SEQUENCE_EASY kull_m_asn1_GenString(PCUNICODE_STRING String);
PDIRTY_ASN1_SEQUENCE_EASY kull_m_asn1_BitStringFromULONG(ULONG data);

#define KULL_M_ASN1_CREATE_APP(AppId)	kull_m_asn1_create(DIRTY_ASN1_MASK_APPLICATION	| AppId	, NULL, 0, NULL)
#define KULL_M_ASN1_CREATE_CTX(CtxId)	kull_m_asn1_create(DIRTY_ASN1_MASK_CONTEXT		| CtxId	, NULL, 0, NULL)
#define KULL_M_ASN1_CREATE_SEQ()		kull_m_asn1_create(DIRTY_ASN1_ID_SEQUENCE				, NULL, 0, NULL)