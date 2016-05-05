/*++

Copyright (c) 1996-1999  Microsoft Corporation

Module Name:

    winber.h   Basic Encoding Rules (BER) API header file

Abstract:

   This module is the header file for the 32 bit BER library on
   Windows NT and Windows 95.

Updates :

Environments :

    Win32 user mode

--*/

//
// Only pull in this header file once.
//

#ifndef _WINBER_DEFINED_
#define _WINBER_DEFINED_

#if _MSC_VER > 1000
#pragma once
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_WINBER_)
#define WINBERAPI DECLSPEC_IMPORT
#else
//#define WINBERAPI __declspec(dllexport)
#define WINBERAPI
#endif

#ifndef BERAPI
#define BERAPI __cdecl
#endif

#define LBER_ERROR   0xffffffffL
#define LBER_DEFAULT 0xffffffffL

typedef unsigned int ber_tag_t;   /* for BER tags */
typedef int ber_int_t;            /* for BER ints, enums, and Booleans */
typedef unsigned int ber_uint_t;  /* unsigned equivalent of ber_int_t */
typedef unsigned int ber_len_t;   /* for BER octet strings and bit strings */
typedef int ber_slen_t;           /* signed equivalent of ber_len_t */

//
// This constructs a new BerElement structure containing a copy of the
// data in the supplied berval structure.
//

WINBERAPI BerElement * BERAPI ber_init( BERVAL *pBerVal );

//
// This frees a BerElement which is returned from ber_alloc_t()
// or ber_init(). The second argument - fbuf should always be set
// to 1.
//
//

WINBERAPI VOID BERAPI ber_free( BerElement *pBerElement, INT fbuf );

//
// Frees a BERVAL structure. Applications should not call
// this API to free BERVAL structures which they themselves
// have allocated
//

WINBERAPI VOID BERAPI ber_bvfree( BERVAL *pBerVal );


//
// Frees an array of BERVAL structures.
//

WINBERAPI VOID BERAPI ber_bvecfree( PBERVAL *pBerVal );

//
// Returns a copy of a the supplied berval structure
//

WINBERAPI BERVAL * BERAPI ber_bvdup( BERVAL *pBerVal );


//
// Constructs and returns a BerElement structure. The options field
// contains a bitwise-or of options which are to be used when generating
// the encoding of the BerElement
//
// The LBER_USE_DER options should always be specified.
//

WINBERAPI BerElement * BERAPI ber_alloc_t( INT options );


//
// This skips over the current tag and returns the tag of the next
// element in the supplied BerElement. The lenght of this element is
// stored in the pLen argument.
//
// LBER_DEFAULT is returned if there is no further data to be read
// else the tag of the next element is returned.
//
// The difference between ber_skip_tag() and ber_peek_tag() is that the
// state pointer is advanced past the first tag+lenght and is pointed to
// the value part of the next element
//

WINBERAPI ULONG BERAPI ber_skip_tag( BerElement *pBerElement, ULONG *pLen );

//
// This returns the tag of the next element to be parsed in the
// supplied BerElement. The length of this element is stored in the
// pLen argument.
//
// LBER_DEFAULT is returned if there is no further data to be read
// else the tag of the next element is returned.
//

WINBERAPI ULONG BERAPI ber_peek_tag( BerElement *pBerElement, ULONG *pLen);

//
// This returns the tag and length of the first element in a SET, SET OF
// or SEQUENCE OF data value.
//
// LBER_DEFAULT is returned if the constructed value is empty else, the tag
// is returned. It also returns an opaque cookie which has to be passed to
// subsequent invocations of ber_next_element().
//

WINBERAPI ULONG BERAPI ber_first_element( BerElement *pBerElement, ULONG *pLen, __out CHAR **ppOpaque );

//
// This positions the state at the start of the next element in the
// constructed type.
//
// LBER_DEFAULT is returned if the constructed value is empty else, the tag
// is returned.
//

WINBERAPI ULONG BERAPI ber_next_element( BerElement *pBerElement, ULONG *pLen, __in CHAR *opaque );

//
// This allocates a BerVal structure whose contents are taken from the
// supplied BerElement structure.
//
// The return values are 0 on success and -1 on error.
//

WINBERAPI INT BERAPI ber_flatten( BerElement *pBerElement, PBERVAL *pBerVal );


/*
The ber_printf() routine is used to encode a BER element in much the
same way that sprintf() works.  One important difference, though, is
that state information is kept in the ber argument so that multiple
calls can be made to ber_printf() to append to the end of the BER ele-
ment. ber MUST be a pointer to a BerElement returned by ber_alloc_t().
ber_printf() interprets and formats its arguments according to the for-
mat string fmt.  ber_printf() returns -1 if there is an error during
encoding and a non-negative number if successful.  As with sprintf(),
each character in fmt refers to an argument to ber_printf().
 
The format string can contain the following format characters:

't'     Tag.  The next argument is a ber_tag_t specifying the tag to
        override the next element to be written to the ber.  This works
        across calls.  The integer tag value SHOULD contain the tag
        class, constructed bit, and tag value.  For example, a tag of
        "[3]" for a constructed type is 0xA3U.  All implementations MUST
        support tags that fit in a single octet (i.e., where the tag
        value is less than 32) and they MAY support larger tags.

'b'     Boolean.  The next argument is an ber_int_t, containing either 0
        for FALSE or 0xff for TRUE.  A boolean element is output.  If
        this format character is not preceded by the 't' format modif-
        ier, the tag 0x01U is used for the element.

'e'     Enumerated.  The next argument is a ber_int_t, containing the
        enumerated value in the host's byte order.  An enumerated ele-
        ment is output.  If this format character is not preceded by the
        't' format modifier, the tag 0x0AU is used for the element.

'i'     Integer.  The next argument is a ber_int_t, containing the
        integer in the host's byte order.  An integer element is output.
        If this format character is not preceded by the 't' format
        modifier, the tag 0x02U is used for the element.

'n'     Null.  No argument is needed.  An ASN.1 NULL element is output.
        If this format character is not preceded by the 't' format
        modifier, the tag 0x05U is used for the element.
        
'o'     Octet string.  The next two arguments are a char *, followed by
        a ber_len_t with the length of the string.  The string MAY con-
        tain null bytes and are do not have to be zero-terminated.   An
        octet string element is output, in primitive form.  If this for-
        mat character is not preceded by the 't' format modifier, the
        tag 0x04U is used for the element.

's'     Octet string.  The next argument is a char * pointing to a
        zero-terminated string.  An octet string element in primitive
        form is output, which does not include the trailing '\0' (null)
        byte. If this format character is not preceded by the 't' format
        modifier, the tag 0x04U is used for the element.

'v'     Several octet strings.  The next argument is a char **, an array
        of char * pointers to zero-terminated strings.  The last element
        in the array MUST be a NULL pointer. The octet strings do not
        include the trailing '\0' (null) byte.  Note that a construct
        like '{v}' is used to get an actual SEQUENCE OF octet strings.
        The 't' format modifier cannot be used with this format charac-
        ter.

'V'     Several octet strings.  A NULL-terminated array of struct berval
        *'s is supplied.  Note that a construct like '{V}' is used to
        get an actual SEQUENCE OF octet strings. The 't' format modifier
        cannot be used with this format character.

'{'     Begin sequence.  No argument is needed.  If this format charac-
        ter is not preceded by the 't' format modifier, the tag 0x30U is
        used.

'}'     End sequence.  No argument is needed.  The 't' format modifier
        cannot be used with this format character.

'['     Begin set.  No argument is needed.  If this format character is
        not preceded by the 't' format modifier, the tag 0x31U is used.

']'     End set.  No argument is needed.  The 't' format modifier cannot
        be used with this format character.
*/

WINBERAPI INT BERAPI ber_printf( BerElement *pBerElement, __in PCHAR fmt, ... );

/*
The ber_scanf() routine is used to decode a BER element in much the same
way that sscanf() works.  One important difference, though, is that some
state information is kept with the ber argument so that multiple calls
can be made to ber_scanf() to sequentially read from the BER element.
The ber argument SHOULD be a pointer to a BerElement returned by
ber_init().  ber_scanf interprets the bytes according to the format
string fmt, and stores the results in its additional arguments.
ber_scanf() returns LBER_ERROR on error, and a different value on suc-
cess.

The format string contains conversion specifications which are used to
direct the interpretation of the BER element.  The format string can
contain the following characters:

'a'     Octet string.  A char ** argument MUST be supplied.  Memory is
        allocated, filled with the contents of the octet string, zero-
        terminated, and the pointer to the string is stored in the argu-
        ment.  The returned value SHOULD be freed using ldap_memfree.
        The tag of the element MUST indicate the primitive form
        (constructed strings are not supported) but is otherwise ignored
        and discarded during the decoding.  This format cannot be used
        with octet strings which could contain null bytes.        
        
'O'     Octet string.  A struct berval ** argument MUST be supplied,
        which upon return points to an allocated struct berval contain-
        ing the octet string and its length.  ber_bvfree() SHOULD be
        called to free the allocated memory.  The tag of the element
        MUST indicate the primitive form (constructed strings are not
        supported) but is otherwise ignored during the decoding.

'b'     Boolean.  A pointer to a ber_int_t MUST be supplied. The
        ber_int_t value stored will be 0 for FALSE or nonzero for TRUE.
        The tag of the element MUST indicate the primitive form but is
        otherwise ignored during the decoding.

'e'     Enumerated.  A pointer to a ber_int_t MUST be supplied. The
        enumerated value stored will be in host byte order.  The tag of
        the element MUST indicate the primitive form but is otherwise
        ignored during the decoding.  ber_scanf() will return an error
        if the value of the enumerated value cannot be stored in a
        ber_int_t.

'i'     Integer.  A pointer to a ber_int_t MUST be supplied. The
        ber_int_t value stored will be in host byte order.  The tag of
        the element MUST indicate the primitive form but is otherwise
        ignored during the decoding.  ber_scanf() will return an error
        if the integer cannot be stored in a ber_int_t.

'B'     Bitstring.  A char ** argument MUST be supplied which will point
        to the allocated bits, followed by a ber_len_t * argument, which
        will point to the length (in bits) of the bitstring returned.
        ldap_memfree SHOULD be called to free the bitstring.  The tag of
        the element MUST indicate the primitive form (constructed bit-
        strings are not supported) but is otherwise ignored during the
        decoding.

'n'     Null.  No argument is needed.  The element is verified to have a
        zero-length value and is skipped.  The tag is ignored.

'v'     Several octet strings.  A char *** argument MUST be supplied,
        which upon return points to an allocated NULL-terminated array
        of char *'s containing the octet strings.  NULL is stored if the
        sequence is empty.  ldap_memfree SHOULD be called to free each
        element of the array and the array itself.  The tag of the
        sequence and of the octet strings are ignored.

'V'     Several octet strings (which could contain null bytes).  A
        struct berval *** MUST be supplied, which upon return points to
        a allocated NULL-terminated array of struct berval *'s contain-
        ing the octet strings and their lengths.  NULL is stored if the
        sequence is empty. ber_bvecfree() can be called to free the
        allocated memory.  The tag of the sequence and of the octet
        strings are ignored.

'x'     Skip element.  The next element is skipped.  No argument is
        needed.

'{'     Begin sequence.  No argument is needed.  The initial sequence
        tag and length are skipped.

'}'     End sequence.  No argument is needed.

'['     Begin set.  No argument is needed.  The initial set tag and
        length are skipped.

']'     End set.  No argument is needed.

*/

WINBERAPI ULONG BERAPI ber_scanf( BerElement *pBerElement, __in PCHAR fmt, ... );


#ifdef __cplusplus
}
#endif


#endif  // _WINBER_DEFINED_

