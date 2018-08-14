/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_string.h"

#define PN532_MAX_LEN					265

#define PN532_Host_PN532				0xd4
#define PN532_PN532_Host				0xd5

// Miscellaneous
#define PN532_CMD_Diagnose				0x00 // it
#define PN532_CMD_GetFirmwareVersion	0x02 // it
#define PN532_CMD_GetGeneralStatus		0x04 // it
#define PN532_CMD_ReadRegister			0x06 // it
#define PN532_CMD_WriteRegister			0x08 // it
#define PN532_CMD_ReadGPIO				0x0c // it
#define PN532_CMD_WriteGPIO				0x0e // it
#define PN532_CMD_SetSerialBaudRate		0x10 // it
#define PN532_CMD_SetParameters			0x12 // it
#define PN532_CMD_SAMConfiguration		0x14 // it
#define PN532_CMD_PowerDown				0x16 // it

// RF communication
#define PN532_CMD_RFConfiguration		0x32 // it
#define PN532_CMD_RFRegulationTest		0x58 // it

// Initiator
#define PN532_CMD_InJumpForDEP			0x56 // i
#define PN532_CMD_InJumpForPSL			0x46 // i
#define PN532_CMD_InListPassiveTarget	0x4a // i
#define PN532_CMD_InATR					0x50 // i
#define PN532_CMD_InPSL					0x4e // i
#define PN532_CMD_InDataExchange		0x40 // i
#define PN532_CMD_InCommunicateThru		0x42 // i
#define PN532_CMD_InDeselect			0x44 // i
#define PN532_CMD_InRelease				0x52 // i
#define PN532_CMD_InSelect				0x54 // i
#define PN532_CMD_InAutoPoll			0x60 // i

// Target
#define PN532_CMD_TgInitAsTarget		0x8c // t
#define PN532_CMD_TgSetGeneralBytes		0x92 // t
#define PN532_CMD_TgGetData				0x86 // t
#define PN532_CMD_TgSetData				0x8e // t
#define PN532_CMD_TgSetMetaData			0x94 // t
#define PN532_CMD_TgGetInitiatorCommand	0x88 // t
#define PN532_CMD_TgResponseToInitiator	0x90 // t
#define PN532_CMD_TgGetTargetStatus		0x8a // t


#define PN532_CMD_Diagnose_CommunicationLineTest	0x00
#define PN532_CMD_Diagnose_RomTest					0x01
#define PN532_CMD_Diagnose_RamTest					0x02
#define PN532_CMD_Diagnose_PollingTestToTarget		0x04
#define PN532_CMD_Diagnose_EchoBackTest				0x05
#define PN532_CMD_Diagnose_AttentionRequestTest		0x06
#define PN532_CMD_Diagnose_SelfAntennaTest			0x07


typedef BOOL (CALLBACK * PKULL_M_PN532_COMM_CALLBACK) (const BYTE *pbData, const UINT16 cbData, BYTE *pbResult, UINT16 *cbResult, LPVOID suppdata);

typedef struct _PN532_TARGET_TYPE_A {
	BYTE Tg;
	UINT16 SENS_RES;
	BYTE SEL_RES;
	BYTE NFCIDLength;
	PBYTE NFCID1;
	BYTE ATSLength;
	PBYTE ATS;
} PN532_TARGET_TYPE_A, *PPN532_TARGET_TYPE_A;

typedef struct _PN532_TARGET {
	BYTE Tg;
	BYTE BrTy;
	union {
		PN532_TARGET_TYPE_A TypeA;
	} Target;
} PN532_TARGET, *PPN532_TARGET;

typedef struct _KULL_M_PN532_COMM {
	PKULL_M_PN532_COMM_CALLBACK communicator;
	LPVOID suppdata;
	BOOL descr;
} KULL_M_PN532_COMM, *PKULL_M_PN532_COMM;

void kull_m_pn532_init(PKULL_M_PN532_COMM_CALLBACK communicator, LPVOID suppdata, BOOL descr, PKULL_M_PN532_COMM comm);
BOOL kull_m_pn532_Diagnose(PKULL_M_PN532_COMM comm /*, ...*/);
BOOL kull_m_pn532_GetFirmware(PKULL_M_PN532_COMM comm, BYTE firmwareInfo[4]);
BOOL kull_m_pn532_GetGeneralStatus(PKULL_M_PN532_COMM comm /*, ...*/);

BOOL kull_m_pn532_InListPassiveTarget(PKULL_M_PN532_COMM comm, const BYTE MaxTg, const BYTE BrTy, const BYTE *pbInit, UINT16 cbInit, BYTE *NbTg, PPN532_TARGET *Targets);
BOOL kull_m_pn532_InRelease(PKULL_M_PN532_COMM comm, const BYTE Tg);

void kull_m_pn532_TgInitAsTarget(PKULL_M_PN532_COMM comm);
void kull_m_pn532_TgGetInitiatorCommand(PKULL_M_PN532_COMM comm);
void kull_m_pn532_TgResponseToInitiator(PKULL_M_PN532_COMM comm);
void kull_m_pn532_TgGetData(PKULL_M_PN532_COMM comm);