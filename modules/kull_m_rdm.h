/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_string.h"
#include "kull_m_hid.h" // to adapt

#define RDM_SLEEP_BEFORE_SEND				10
#define RDM_SLEEP_BEFORE_RECV				10


#define RDM_IOCTL_14443A_REQ						0x03
#define RDM_IOCTL_14443A_ANTICOLL					0x04
#define RDM_IOCTL_14443A_SELECT						0x05
#define RDM_IOCTL_14443A_HALT						0x06

#define RDM_IOCTL_14443B_REQ						0x09
#define RDM_IOCTL_14443B_ANTICOLL					0x0a
#define RDM_IOCTL_14443B_ATTRIB						0x0b
#define RDM_IOCTL_14443B_RESET						0x0c

#define RDM_IOCTL_14443_DIRECT						0x0d // ISO14443_TypeB_Transfer_Command (MF_TypeATransCOSCmd in code ?)

#define RDM_IOCTL_15693_INVENTORY					0x10
#define RDM_IOCTL_15693_READ						0x11
#define RDM_IOCTL_15693_WRITE						0x12
#define RDM_IOCTL_15693_LOCK_BLOCK					0x13
#define RDM_IOCTL_15693_STAY_QUIET					0x14
#define RDM_IOCTL_15693_SELECT						0x15
#define RDM_IOCTL_15693_RESET_TO_READY				0x16
#define RDM_IOCTL_15693_WRITE_AFI					0x17
#define RDM_IOCTL_15693_LOCK_AFI					0x18
#define RDM_IOCTL_15693_WRITE_DSFID					0x19
#define RDM_IOCTL_15693_LOCK_DSFID					0x1a
#define RDM_IOCTL_15693_GET_INFORMATION				0x1b
#define RDM_IOCTL_15693_GET_MULTIPLE_BLOCK_SECURITY	0x1c
#define RDM_IOCTL_15693_DIRECT						0x1d


#define RDM_IOCTL_MF_READ							0x20
#define RDM_IOCTL_MF_WRITE							0x21
#define RDM_IOCTL_MF_INIT_VALUE						0x22
#define RDM_IOCTL_MF_DEC							0x23
#define RDM_IOCTL_MF_INC							0x24
#define RDM_IOCTL_MF_GET_SNR						0x25

#define RDM_IOCTL_MF_RESTORE						0x28 // ISO14443_TypeA_Transfer_Command(0X28) ?

// SYSTEM COMMANDS
#define RDM_IOCTL_SET_ADDRESS						0x80
#define RDM_IOCTL_SET_BAUDRATE						0x81
#define RDM_IOCTL_SET_SER_NUM						0x82
#define RDM_IOCTL_GET_SER_NUM						0x83
#define RDM_IOCTL_SET_USER_INFO						0x84
#define RDM_IOCTL_GET_USER_INFO						0x85
#define RDM_IOCTL_GET_VERSION						0x86
#define RDM_IOCTL_CONTROL_LED1						0x87
#define RDM_IOCTL_CONTROL_LED2						0x88
#define RDM_IOCTL_CONTROL_BUZZER					0x89


typedef struct _RDM_DEVICE {
	struct _RDM_DEVICE * next;
	DWORD id;
	PWCHAR DevicePath;
	HIDD_ATTRIBUTES hidAttributes;
	HIDP_CAPS hidCaps;
	HANDLE hDevice;
} RDM_DEVICE, *PRDM_DEVICE;

BOOL rdm_get_version(HANDLE hFile, PSTR *version);

BOOL rdm_send_receive(HANDLE hFile, BYTE ctl, LPCVOID in, BYTE szIn, LPBYTE *out, BYTE *szOut);
BOOL rdm_devices_get(PRDM_DEVICE *devices, DWORD *count);
void rdm_devices_free(PRDM_DEVICE devices);