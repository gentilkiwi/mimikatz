/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globals.h"

typedef struct _RPCE_COMMON_TYPE_HEADER {
	UCHAR Version;
	UCHAR Endianness;
	USHORT CommonHeaderLength;
	ULONG Filler;
} RPCE_COMMON_TYPE_HEADER, *PRPCE_COMMON_TYPE_HEADER;

typedef struct _RPCE_PRIVATE_HEADER {
	ULONG ObjectBufferLength;
	ULONG Filler;
} RPCE_PRIVATE_HEADER, *PRPCE_PRIVATE_HEADER;

typedef ULONG32 RPCEID;