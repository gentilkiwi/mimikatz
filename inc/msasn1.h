/* Copyright (C) Boris Nikolaus, Germany, 1996-1997. All rights reserved. */
/* Copyright (C) Microsoft Corporation 1997-1998, All rights reserved. */

#ifndef __MS_ASN1_H__
#define __MS_ASN1_H__

#include <pshpack8.h> /* Assume 8 byte packing throughout */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __MINGW32__
#define DISCARD(x)
#define DISCARD2(x,y)
#endif

/* ------ Basic integer types ------ */

typedef unsigned char   ASN1uint8_t;
typedef signed char     ASN1int8_t;

typedef unsigned short  ASN1uint16_t;
typedef signed short    ASN1int16_t;

typedef unsigned long   ASN1uint32_t;
typedef signed long     ASN1int32_t;


/* ------ Function modifiers ------ */

#ifdef ASN1LIB
#define ASN1_PUBLIC
#elif defined(ASN1C)
#define ASN1_PUBLIC
#else
#define ASN1_PUBLIC     __declspec(dllimport)
#endif
#define ASN1API         __stdcall
#define ASN1CALL        __stdcall

#ifdef _M_CEE_PURE
#define ASN1API_INLINE  __clrcall
#else
#define ASN1API_INLINE  ASN1API
#endif

/* ------ Basic ASN.1 types ------ */

typedef ASN1uint8_t ASN1octet_t;

typedef ASN1uint8_t ASN1bool_t;

typedef struct tagASN1intx_t
{
    ASN1uint32_t length;
   
    __field_bcount(length) 
    ASN1octet_t *value;
}
ASN1intx_t;

typedef struct tagASN1octetstring_t
{
    ASN1uint32_t length;

    __field_bcount(length) 
    ASN1octet_t *value;
}
ASN1octetstring_t;

typedef struct tagASN1octetstring2_t
{
    ASN1uint32_t length;
    ASN1octet_t value[1];
}
ASN1octetstring2_t;

typedef struct ASN1iterator_s
{
    struct ASN1iterator_s *next;
    void *value;
}
ASN1iterator_t;

typedef struct tagASN1bitstring_t
{
    ASN1uint32_t length;
    
    __field_bcount(length) 
    ASN1octet_t *value;
}
ASN1bitstring_t;

typedef char ASN1char_t;

typedef struct tagASN1charstring_t
{
    ASN1uint32_t length;
    
    __field_ecount(length) 
    ASN1char_t *value;
}
ASN1charstring_t;

typedef ASN1uint16_t ASN1char16_t;

typedef struct tagASN1char16string_t
{
    ASN1uint32_t length;
    
    __field_ecount(length) 
    ASN1char16_t *value;
}
ASN1char16string_t;

typedef ASN1uint32_t ASN1char32_t;

typedef struct tagASN1char32string_t
{
    ASN1uint32_t length;
    
    __field_ecount(length) 
    ASN1char32_t *value;
}
ASN1char32string_t;

typedef ASN1char_t *ASN1ztcharstring_t;
typedef ASN1char16_t *ASN1ztchar16string_t;
typedef ASN1char32_t *ASN1ztchar32string_t;

typedef struct tagASN1wstring_t
{
    ASN1uint32_t length;
    
    __field_ecount(length) 
    WCHAR *value;
}
ASN1wstring_t;

typedef struct ASN1objectidentifier_s
{
    struct ASN1objectidentifier_s *next;
    ASN1uint32_t value;
}
*ASN1objectidentifier_t;

typedef struct tagASN1objectidentifier2_t
{
    __range(0, 16)
    ASN1uint16_t count;
    ASN1uint32_t value[16];
}
ASN1objectidentifier2_t;

typedef struct tagASN1encodedOID_t
{
    ASN1uint16_t length;
    
    __field_bcount(length) 
    ASN1octet_t  *value;
}
ASN1encodedOID_t;

typedef ASN1ztcharstring_t ASN1objectdescriptor_t;

typedef struct tagASN1generalizedtime_t
{
    ASN1uint16_t year;
    ASN1uint8_t month;
    ASN1uint8_t day;
    ASN1uint8_t hour;
    ASN1uint8_t minute;
    ASN1uint8_t second;
    ASN1uint16_t millisecond;
    ASN1bool_t universal;
    ASN1int16_t diff;
}
ASN1generalizedtime_t;

typedef struct tagASN1utctime_t
{
    ASN1uint8_t year;
    ASN1uint8_t month;
    ASN1uint8_t day;
    ASN1uint8_t hour;
    ASN1uint8_t minute;
    ASN1uint8_t second;
    ASN1bool_t universal;
    ASN1int16_t diff;
}
ASN1utctime_t;

typedef struct tagASN1open_t
{
    // encoded
    ASN1uint32_t    length;
    union
    {
        __field_bcount(length) 
        void           *encoded;

        __field_bcount(length) 
        void           *value;
    };
}
ASN1open_t;

typedef enum tagASN1blocktype_e
{
    ASN1_DER_SET_OF_BLOCK,
}
ASN1blocktype_e;

typedef ASN1int32_t     ASN1enum_t;     // enumerated type

typedef ASN1uint16_t    ASN1choice_t;   // choice

typedef ASN1uint32_t    ASN1magic_t;

/* ------ Current version of this ASN.1 software ------ */

#define ASN1_MAKE_VERSION(major,minor)  (((major) << 16) | (minor))
#define ASN1_THIS_VERSION               ASN1_MAKE_VERSION(1,0)

enum
{
    ASN1_CHOICE_BASE      = 1,
    ASN1_CHOICE_INVALID   = -1,     // invalid choice
    ASN1_CHOICE_EXTENSION = 0,      // extension choice
};



/*
   Error codes for decoding functions:
   - err == 0:    data has been successfully decoded
   - err <  0:    fatal error has occured, no data has been generated
                  err contains the error number
   - err >  0:    non-fatal event has occured, data has been generated
                  err is a bit set of occured events
 */

typedef enum tagASN1error_e
{
    ASN1_SUCCESS        = 0,            /* success */

    // Teles specific error codes
    ASN1_ERR_INTERNAL   = (-1001),      /* internal error */
    ASN1_ERR_EOD        = (-1002),      /* unexpected end of data */
    ASN1_ERR_CORRUPT    = (-1003),      /* corrupted data */
    ASN1_ERR_LARGE      = (-1004),      /* value too large */
    ASN1_ERR_CONSTRAINT = (-1005),      /* constraint violated */
    ASN1_ERR_MEMORY     = (-1006),      /* out of memory */
    ASN1_ERR_OVERFLOW   = (-1007),      /* buffer overflow */
    ASN1_ERR_BADPDU     = (-1008),      /* function not supported for this pdu*/
    ASN1_ERR_BADARGS    = (-1009),      /* bad arguments to function call */
    ASN1_ERR_BADREAL    = (-1010),      /* bad real value */
    ASN1_ERR_BADTAG     = (-1011),      /* bad tag value met */
    ASN1_ERR_CHOICE     = (-1012),      /* bad choice value */
    ASN1_ERR_RULE       = (-1013),      /* bad encoding rule */
    ASN1_ERR_UTF8       = (-1014),      /* bad unicode (utf8) */

    // New error codes
    ASN1_ERR_PDU_TYPE   = (-1051),      /* bad pdu type */
    ASN1_ERR_NYI        = (-1052),      /* not yet implemented */

    // Teles specific warning codes
    ASN1_WRN_EXTENDED   = 1001,         /* skipped unknown extension(s) */
    ASN1_WRN_NOEOD      = 1002,         /* end of data expected */
}
ASN1error_e;

#define ASN1_SUCCEEDED(ret)     (((int) (ret)) >= 0)
#define ASN1_FAILED(ret)        (((int) (ret)) < 0)


/* ------ Encoding rules ------ */

typedef enum
{
    ASN1_BER_RULE_BER           = 0x0100,
    ASN1_BER_RULE_CER           = 0x0200,
    ASN1_BER_RULE_DER           = 0x0400,
    ASN1_BER_RULE               = ASN1_BER_RULE_BER | ASN1_BER_RULE_CER | ASN1_BER_RULE_DER,
}
ASN1encodingrule_e;

/* ------ public structures ------ */

typedef struct ASN1encoding_s   *ASN1encoding_t;
typedef struct ASN1decoding_s   *ASN1decoding_t;

typedef ASN1int32_t (ASN1CALL *ASN1BerEncFun_t)( __in ASN1encoding_t enc, ASN1uint32_t tag, __in void *data);
typedef ASN1int32_t (ASN1CALL *ASN1BerDecFun_t)( __in ASN1decoding_t enc, ASN1uint32_t tag, __out void *data);

typedef struct tagASN1BerFunArr_t
{
    const ASN1BerEncFun_t *apfnEncoder;
    const ASN1BerDecFun_t *apfnDecoder;
}
ASN1BerFunArr_t;

typedef void (ASN1CALL *ASN1GenericFun_t)(void);
typedef void (ASN1CALL *ASN1FreeFun_t)( __in void *data);

typedef struct tagASN1module_t
{
    ASN1magic_t             nModuleName;
    ASN1encodingrule_e      eRule;
    ASN1uint32_t            dwFlags;
    ASN1uint32_t            cPDUs;

    __field_xcount(cPDUs)
    const ASN1FreeFun_t    *apfnFreeMemory;
    
    __field_xcount(cPDUs)
    const ASN1uint32_t     *acbStructSize;
    
    ASN1BerFunArr_t         BER;
}
*ASN1module_t;


struct ASN1encoding_s
{
    ASN1magic_t         magic;  /* magic for this structure */
    ASN1uint32_t        version;/* version number of this library */
    ASN1module_t        module; /* module this encoding_t depends to */
    __field_bcount(size)
    ASN1octet_t        *buf;    /* buffer to encode into */
    ASN1uint32_t        size;   /* current size of buffer */
    ASN1uint32_t        len;    /* len of encoded data in buffer */
    ASN1error_e         err;    /* error code for last encoding */
    ASN1uint32_t        bit;
    ASN1octet_t        *pos;
    ASN1uint32_t        cbExtraHeader;
    ASN1encodingrule_e  eRule;
    ASN1uint32_t        dwFlags;
};

struct ASN1decoding_s
{
    ASN1magic_t         magic;  /* magic for this structure */
    ASN1uint32_t        version;/* version number of this library */
    ASN1module_t        module; /* module this decoding_t depends to */
    __field_bcount(size)
    ASN1octet_t        *buf;    /* buffer to decode from */
    ASN1uint32_t        size;   /* size of buffer */
    ASN1uint32_t        len;    /* len of decoded data in buffer */
    ASN1error_e         err;    /* error code for last decoding */
    ASN1uint32_t        bit;
    ASN1octet_t        *pos;
    ASN1encodingrule_e  eRule;
    ASN1uint32_t        dwFlags;
};


/* --- flags for functions --- */

#define ASN1DECFREE_NON_PDU_ID    ((ASN1uint32_t) -1)

enum
{
    ASN1FLAGS_NONE              = 0x00000000L, /* no flags */
    ASN1FLAGS_NOASSERT          = 0x00001000L, /* no asertion */
};

enum
{
    ASN1ENCODE_APPEND           = 0x00000001L, /* append to current buffer*/
    ASN1ENCODE_REUSEBUFFER      = 0x00000004L, /* empty destination buffer */
    ASN1ENCODE_SETBUFFER        = 0x00000008L, /* use a user-given destination buffer */
    ASN1ENCODE_ALLOCATEBUFFER   = 0x00000010L, /* do not free/reuse buffer */
    ASN1ENCODE_NOASSERT         = ASN1FLAGS_NOASSERT, /* no asertion */
};

enum
{
    ASN1DECODE_APPENDED         = 0x00000001L, /* continue behind last pdu*/
    ASN1DECODE_REWINDBUFFER     = 0x00000004L, /* rescan from buffer start*/
    ASN1DECODE_SETBUFFER        = 0x00000008L, /* use a user-given src buffer */
    ASN1DECODE_AUTOFREEBUFFER   = 0x00000010L, /* Assume responsibility for allocated buffer */
    ASN1DECODE_NOASSERT         = ASN1FLAGS_NOASSERT, /* no asertion */
};

/*****************************************************************************
  ASN1_CreateModule

*****************************************************************************/
extern ASN1_PUBLIC 
ASN1module_t 
ASN1API 
ASN1_CreateModule(
                ASN1uint32_t            nVersion,
                ASN1encodingrule_e      eRule,
                ASN1uint32_t            dwFlags, /* ASN1FLAGS_NONE or ASN1FLAGS_NOASSERT */
                ASN1uint32_t            cPDU,
                const ASN1GenericFun_t  apfnEncoder[],
                const ASN1GenericFun_t  apfnDecoder[],
                const ASN1FreeFun_t     apfnFreeMemory[],
                const ASN1uint32_t      acbStructSize[],
                ASN1magic_t             nModuleName
    );

/*****************************************************************************
  ASN1_CloseModule

*****************************************************************************/
extern ASN1_PUBLIC 
void 
ASN1API 
ASN1_CloseModule(
    __in        ASN1module_t        pModule
    );

/*****************************************************************************
  ASN1_CreateEncoder

*****************************************************************************/
extern ASN1_PUBLIC 
__success( return >= 0 )
ASN1error_e 
ASN1API 
ASN1_CreateEncoder(
    __in        ASN1module_t        pModule,
    __deref_out ASN1encoding_t     *ppEncoderInfo,
    __in_bcount_opt( cbBufSize )
                ASN1octet_t        *pbBuf,
                ASN1uint32_t        cbBufSize,
    __in_opt    ASN1encoding_t      pParent
    );

/*****************************************************************************
  ASN1_Encode

*****************************************************************************/
extern ASN1_PUBLIC 
__success( return >= 0 )
ASN1error_e 
ASN1API 
ASN1_Encode(
    __in        ASN1encoding_t      pEncoderInfo,
    __in        void               *pDataStruct,
                ASN1uint32_t        nPduNum,
                ASN1uint32_t        dwFlags,
    __out_bcount_opt( cbBufSize )          
                ASN1octet_t        *pbBuf,
                ASN1uint32_t        cbBufSize
    );

/*****************************************************************************
  ASN1_CloseEncoder

*****************************************************************************/
extern ASN1_PUBLIC 
void 
ASN1API 
ASN1_CloseEncoder(
    __in        ASN1encoding_t      pEncoderInfo
    );

/*****************************************************************************
  ASN1_CloseEncoder2

*****************************************************************************/
extern ASN1_PUBLIC 
void 
ASN1API 
ASN1_CloseEncoder2(
    __in        ASN1encoding_t      pEncoderInfo
    );

/*****************************************************************************
  ASN1_CreateDecoder

*****************************************************************************/
extern ASN1_PUBLIC 
__success( return >= 0 )
ASN1error_e 
ASN1API 
ASN1_CreateDecoder(
    __in        ASN1module_t        pModule,
    __deref_out ASN1decoding_t     *ppDecoderInfo,
    __in_bcount_opt(cbBufSize)
                ASN1octet_t        *pbBuf,
                ASN1uint32_t        cbBufSize,
    __in_opt    ASN1decoding_t      pParent
    );

/*****************************************************************************
  ASN1_CreateDecoderEx

*****************************************************************************/
extern ASN1_PUBLIC 
__success( return >= 0 )
ASN1error_e 
ASN1API 
ASN1_CreateDecoderEx(
    __in        ASN1module_t        pModule,
    __deref_out ASN1decoding_t     *ppDecoderInfo,
    __in_bcount_opt(cbBufSize)
                ASN1octet_t        *pbBuf,
                ASN1uint32_t        cbBufSize,
    __in_opt    ASN1decoding_t      pParent,
                ASN1uint32_t        dwFlags
    );

/*****************************************************************************
  ASN1_Decode

*****************************************************************************/
extern ASN1_PUBLIC 
__success( return >= 0 )
ASN1error_e 
ASN1API 
ASN1_Decode(
    __in        ASN1decoding_t      pDecoderInfo,
    __deref_out void              **ppDataStruct,
                ASN1uint32_t        nPduNum,
                ASN1uint32_t        dwFlags,
    __in_bcount(cbBufSize)
                ASN1octet_t        *pbBuf,
                ASN1uint32_t        cbBufSize
    );

/*****************************************************************************
  ASN1_CloseDecoder

*****************************************************************************/
extern ASN1_PUBLIC 
void 
ASN1API 
ASN1_CloseDecoder(
    __in        ASN1decoding_t      pDecoderInfo
    );


/*****************************************************************************
  ASN1_FreeEncoded

*****************************************************************************/
extern ASN1_PUBLIC 
void 
ASN1API 
ASN1_FreeEncoded(
    __in        ASN1encoding_t      pEncoderInfo,
    __in        void               *pBuf
    );

/*****************************************************************************
  ASN1_FreeDecoded

*****************************************************************************/
extern 
ASN1_PUBLIC 
void 
ASN1API 
ASN1_FreeDecoded(
    __in        ASN1decoding_t      pDecoderInfo,
    __in        void               *pDataStruct,
                ASN1uint32_t        nPduNum
    );


/*****************************************************************************
  Options

*****************************************************************************/
typedef enum
{
    // common set option
    ASN1OPT_CHANGE_RULE                 = 0x101,

    // common get option
    ASN1OPT_GET_RULE                    = 0x201,

    // set encoder option
    ASN1OPT_NOT_REUSE_BUFFER            = 0x301,
    ASN1OPT_REWIND_BUFFER               = 0x302,

    // get encoder option

    // set decoder option
    ASN1OPT_SET_DECODED_BUFFER          = 0x501,
    ASN1OPT_DEL_DECODED_BUFFER          = 0x502,

    // get decoder option
    ASN1OPT_GET_DECODED_BUFFER_SIZE     = 0x601,
}
ASN1option_e;

typedef struct tagASN1optionparam_t
{
    ASN1option_e    eOption;
    union
    {
        ASN1encodingrule_e              eRule;
        ASN1uint32_t                    cbRequiredDecodedBufSize;
        struct
        {
            ASN1octet_t    *pbBuf;
            ASN1uint32_t    cbBufSize;
        }                               Buffer;
    };
}
ASN1optionparam_t, ASN1optionparam_s;


/*****************************************************************************
  ASN1_SetEncoderOption

*****************************************************************************/
extern ASN1_PUBLIC 
__success( return >= 0 )
ASN1error_e 
ASN1API 
ASN1_SetEncoderOption(
    __in        ASN1encoding_t      pEncoderInfo,
    __in        ASN1optionparam_t  *pOptParam
    );

/*****************************************************************************
  ASN1_GetEncoderOption

*****************************************************************************/
extern ASN1_PUBLIC 
__success( return >= 0 )
ASN1error_e 
ASN1API 
ASN1_GetEncoderOption(
    __in        ASN1encoding_t      pEncoderInfo,
    __inout     ASN1optionparam_t  *pOptParam
    );

/*****************************************************************************
  ASN1_SetDecoderOption

*****************************************************************************/
extern ASN1_PUBLIC 
__success( return >= 0 )
ASN1error_e 
ASN1API 
ASN1_SetDecoderOption(
    __in        ASN1decoding_t      pDecoderInfo,
    __in        ASN1optionparam_t  *pOptParam
    );

/*****************************************************************************
  ASN1_GetDecoderOption

*****************************************************************************/
extern ASN1_PUBLIC 
__success( return >= 0 )
ASN1error_e 
ASN1API 
ASN1_GetDecoderOption(
    __in        ASN1decoding_t      pDecoderInfo,
    __inout     ASN1optionparam_t  *pOptParam
    );


/*****************************************************************************
  XXX_free

*****************************************************************************/
extern ASN1_PUBLIC 
void 
ASN1API 
ASN1bitstring_free(
    __in ASN1bitstring_t *
    );

extern ASN1_PUBLIC 
void 
ASN1API 
ASN1octetstring_free(
    __in ASN1octetstring_t *
    );

extern ASN1_PUBLIC 
void 
ASN1API 
ASN1objectidentifier_free(
    __in ASN1objectidentifier_t *
    );
    
extern ASN1_PUBLIC 
void 
ASN1API 
ASN1charstring_free(
    __in ASN1charstring_t *
    );
    
extern ASN1_PUBLIC 
void 
ASN1API 
ASN1char16string_free(
    __in ASN1char16string_t *
    );
    
extern ASN1_PUBLIC 
void 
ASN1API 
ASN1char32string_free(
    __in ASN1char32string_t *
    );
    
extern ASN1_PUBLIC 
void 
ASN1API 
ASN1ztcharstring_free(
    __in ASN1ztcharstring_t
    );
    
extern ASN1_PUBLIC 
void 
ASN1API 
ASN1ztchar16string_free(
    __in ASN1ztchar16string_t
    );
    
extern ASN1_PUBLIC 
void 
ASN1API 
ASN1ztchar32string_free(
    __in ASN1ztchar32string_t
    );
    
extern ASN1_PUBLIC 
void 
ASN1API 
ASN1open_free(
    __in ASN1open_t *
    );
    
extern ASN1_PUBLIC 
void 
ASN1API 
ASN1utf8string_free(
    __in ASN1wstring_t *
    );

/*****************************************************************************
  ASN1DecAlloc

*****************************************************************************/
extern ASN1_PUBLIC 
__out_bcount_opt( size )
LPVOID 
ASN1API 
ASN1DecAlloc(
    __in        ASN1decoding_t dec, 
                ASN1uint32_t size
    );

/*****************************************************************************
  ASN1DecRealloc

*****************************************************************************/
extern ASN1_PUBLIC 
__out_bcount_opt( size )
LPVOID 
ASN1API 
ASN1DecRealloc(
    __in        ASN1decoding_t dec, 
    __in        LPVOID ptr, 
                ASN1uint32_t size
                );

/*****************************************************************************
  ASN1Free

*****************************************************************************/
extern ASN1_PUBLIC 
void   
ASN1API 
ASN1Free(
    __in        LPVOID  ptr
    );

/*****************************************************************************
  ASN1EncSetError

*****************************************************************************/
extern ASN1_PUBLIC 
__success( return >= 0 )
ASN1error_e 
ASN1API ASN1EncSetError(
    __in        ASN1encoding_t enc, 
                ASN1error_e err
    );
    
/*****************************************************************************
  ASN1EncSetError

*****************************************************************************/
extern ASN1_PUBLIC 
__success( return >= 0 )
ASN1error_e 
ASN1API 
ASN1DecSetError(
    __in        ASN1decoding_t dec, 
                ASN1error_e err
    );

/*****************************************************************************
  intx conversions

*****************************************************************************/
extern ASN1_PUBLIC 
ASN1uint32_t 
ASN1API 
ASN1intx_uoctets(
    __in ASN1intx_t *
    );
    
extern ASN1_PUBLIC 
void         
ASN1API 
ASN1intx_free(
    __in ASN1intx_t *
    );
    
extern ASN1_PUBLIC 
ASN1int32_t  
ASN1API 
ASN1intx2int32(
    __in ASN1intx_t *
    );
    
extern ASN1_PUBLIC 
ASN1uint32_t 
ASN1API 
ASN1intx2uint32(
    __in ASN1intx_t *
    );
    
extern ASN1_PUBLIC 
int          
ASN1API 
ASN1intxisuint32(
    __in ASN1intx_t *
    );
    
extern ASN1_PUBLIC 
void         
ASN1API 
ASN1intx_setuint32(
    __out   ASN1intx_t *dst, 
            ASN1uint32_t val 
    );
    
/*****************************************************************************
 ASN1uint32_uoctets

    count octets for unsigned encoding of an uint32 value 

*****************************************************************************/
extern ASN1_PUBLIC 
ASN1uint32_t 
ASN1API 
ASN1uint32_uoctets(
    ASN1uint32_t
    );

/*****************************************************************************
  Comparisson APIs

*****************************************************************************/
extern ASN1_PUBLIC 
int 
ASN1API 
ASN1intx_cmp(
    __in        ASN1intx_t *, 
    __in        ASN1intx_t *
    );

extern ASN1_PUBLIC 
int 
ASN1API 
ASN1objectidentifier_cmp(
    __in        ASN1objectidentifier_t *,
    __in        ASN1objectidentifier_t *
    );
    
extern ASN1_PUBLIC 
int 
ASN1API 
ASN1objectidentifier2_cmp(
    __in        ASN1objectidentifier2_t *, 
    __in        ASN1objectidentifier2_t *
    );
    
extern ASN1_PUBLIC 
int 
ASN1API 
ASN1bitstring_cmp(
    __in        ASN1bitstring_t *, 
    __in        ASN1bitstring_t *, 
                int
    );
    
extern ASN1_PUBLIC 
int 
ASN1API 
ASN1octetstring_cmp(
    __in        ASN1octetstring_t *, 
    __in        ASN1octetstring_t *
    );
    
extern ASN1_PUBLIC 
int 
ASN1API 
ASN1charstring_cmp(
    __in        ASN1charstring_t *, 
    __in        ASN1charstring_t *
    );

extern ASN1_PUBLIC 
int 
ASN1API 
ASN1char16string_cmp(
    __in        ASN1char16string_t *, 
    __in        ASN1char16string_t *
    );

extern ASN1_PUBLIC 
int 
ASN1API 
ASN1char32string_cmp(
    __in        ASN1char32string_t *, 
    __in        ASN1char32string_t *
    );

extern ASN1_PUBLIC 
int 
ASN1API 
ASN1ztcharstring_cmp(
    __in_z      ASN1ztcharstring_t, 
    __in_z      ASN1ztcharstring_t
    );

extern ASN1_PUBLIC 
int 
ASN1API 
ASN1ztchar16string_cmp(
    __in_z      ASN1ztchar16string_t, 
    __in_z      ASN1ztchar16string_t
    );

extern ASN1_PUBLIC 
int 
ASN1API 
ASN1ztchar32string_cmp(
    __in_z      ASN1ztchar32string_t, 
    __in_z      ASN1ztchar32string_t
    );

extern ASN1_PUBLIC 
int 
ASN1API 
ASN1open_cmp(
    __in        ASN1open_t *, 
    __in        ASN1open_t *
    );

extern ASN1_PUBLIC 
int 
ASN1API
ASN1generalizedtime_cmp(
    __in        ASN1generalizedtime_t *, 
    __in        ASN1generalizedtime_t *
    );
 
extern ASN1_PUBLIC 
int 
ASN1API 
ASN1utctime_cmp(
    __in        ASN1utctime_t *, 
    __in        ASN1utctime_t *
    );


#ifdef __cplusplus
}
#endif

#include <poppack.h> /* End 8-byte packing */

#endif // __MS_ASN1_H__

