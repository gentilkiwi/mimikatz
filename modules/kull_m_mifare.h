/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"

#define MIFARE_CLASSIC_KEY_SIZE						6
#define MIFARE_CLASSIC_SECTORS						16
#define MIFARE_CLASSIC_BLOCKS_PER_SECTOR			4
#define MIFARE_CLASSIC_BLOCK_SIZE					16
#define MIFARE_CLASSIC_UID_SIZE						4	// ok, I know about 7 or 10 too...

#define MIFARE_CLASSIC_CMD_REQUEST					0x26	// 7b, ISO/IEC 1443 -> REQA
#define MIFARE_CLASSIC_CMD_WAKEUP					0x52	// 7b, ISO/IEC 1443 -> WUPA
#define MIFARE_CLASSIC_CMD_ANTICOL_CL1				0x93, 0x20
#define MIFARE_CLASSIC_CMD_SELECT_CL1				0x93, 0x70
#define MIFARE_CLASSIC_CMD_ANTICOL_CL2				0x95, 0x20
#define MIFARE_CLASSIC_CMD_SELECT_CL2				0x95, 0x70
#define MIFARE_CLASSIC_CMD_HALT						0x50, 0x00
#define MIFARE_CLASSIC_CMD_AUTH_KEY_A				0x60
#define MIFARE_CLASSIC_CMD_AUTH_KEY_B				0x61
#define MIFARE_CLASSIC_CMD_PERSONALIZE_UID_USAGE	0x40
#define MIFARE_CLASSIC_CMD_SET_MOD_TYPE				0x43
#define MIFARE_CLASSIC_CMD_READ						0x30
#define MIFARE_CLASSIC_CMD_WRITE					0xa0
#define MIFARE_CLASSIC_CMD_DECREMENT				0xc0
#define MIFARE_CLASSIC_CMD_INCREMENT				0xc1
#define MIFARE_CLASSIC_CMD_RESTORE					0xc2
#define MIFARE_CLASSIC_CMD_TRANSFER					0xb0

#define MIFARE_ULTRALIGHT_WRITE_4B					0xa2

typedef struct _MIFARE_CLASSIC_ACCESS_BITS {
	unsigned not_c1_0: 1;
	unsigned not_c1_1: 1;
	unsigned not_c1_2: 1;
	unsigned not_c1_3: 1;
	unsigned not_c2_0: 1;
	unsigned not_c2_1: 1;
	unsigned not_c2_2: 1;
	unsigned not_c2_3: 1;
	unsigned not_c3_0: 1;
	unsigned not_c3_1: 1;
	unsigned not_c3_2: 1;
	unsigned not_c3_3: 1;
	unsigned c1_0: 1;
	unsigned c1_1: 1;
	unsigned c1_2: 1;
	unsigned c1_3: 1;
	unsigned c2_0: 1;
	unsigned c2_1: 1;
	unsigned c2_2: 1;
	unsigned c2_3: 1;
	unsigned c3_0: 1;
	unsigned c3_1: 1;
	unsigned c3_2: 1;
	unsigned c3_3: 1;

	unsigned data: 8;
} MIFARE_CLASSIC_ACCESS_BITS, *PMIFARE_CLASSIC_ACCESS_BITS;


typedef struct _MIFARE_CLASSIC_RAW_BLOCK {
	BYTE data[MIFARE_CLASSIC_BLOCK_SIZE];
} MIFARE_CLASSIC_RAW_BLOCK, *PMIFARE_CLASSIC_RAW_BLOCK;

typedef struct _MIFARE_CLASSIC_RAW_SECTOR {
	MIFARE_CLASSIC_RAW_BLOCK blocks[MIFARE_CLASSIC_BLOCKS_PER_SECTOR];
} MIFARE_CLASSIC_RAW_SECTOR, *PMIFARE_CLASSIC_RAW_SECTOR;

typedef struct _MIFARE_CLASSIC_RAW_CARD {
	MIFARE_CLASSIC_RAW_SECTOR sectors[MIFARE_CLASSIC_SECTORS];
} MIFARE_CLASSIC_RAW_CARD, *PMIFARE_CLASSIC_RAW_CARD;