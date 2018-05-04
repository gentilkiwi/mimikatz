/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_string.h"
#include "kull_m_hid.h"

#define SR98_SLEEP_BEFORE_SEND				100
#define SR98_SLEEP_BEFORE_RECV				100

#define SR98_RATE_RF_32						0
#define SR98_RATE_RF_64						1

#define SR98_T5577_LOCKBIT_MASK				0x80


#define SR98_IOCTL_SUPPORT_CARD				0
#define SR98_IOCTL_TEST_DEVICE				1
#define SR98_IOCTL_BEEP						3

#define SR98_IOCTL_EEPROM_READ				4
#define SR98_IOCTL_EEPROM_WRITE				5
#define SR98_IOCTL_EEPROM_GET				6
#define SR98_IOCTL_EEPROM_SET				7

#define SR98_IOCTL_EMID_READ				16

#define SR98_IOCTL_T5577					18
#define SR98_SUB_IOCTL_T5577_RESET				0
#define SR98_SUB_IOCTL_T5577_READ_CURRENT		1
#define SR98_SUB_IOCTL_T5577_READ_PAGE			2
#define SR98_SUB_IOCTL_T5577_READ_BLOCK			3
#define SR98_SUB_IOCTL_T5577_WRITE_BLOCK		4
#define SR98_SUB_IOCTL_T5577_READ_BLOCK_PASS	5
#define SR98_SUB_IOCTL_T5577_WRITE_BLOCK_PASS	6
#define SR98_SUB_IOCTL_T5577_WAKEUP				7

#define SR98_IOCTL_EM4305					19
#define SR98_SUB_IOCTL_EM4305_WRITE_WORD		1
#define SR98_SUB_IOCTL_EM4305_READ_WORD			2
#define SR98_SUB_IOCTL_EM4305_LOGIN				3
#define SR98_SUB_IOCTL_EM4305_PROTECT			4
#define SR98_SUB_IOCTL_EM4305_DISABLE			5

#define SR98_IOCTL_EL8625A					20
#define SR98_SUB_IOCTL_EL8625A_RESET			0				
#define SR98_SUB_IOCTL_EL8625A_WRITE_EMID		1
#define SR98_SUB_IOCTL_EL8625A_RF_STOP			2
#define SR98_SUB_IOCTL_EL8625A_RF_START			3
#define SR98_SUB_IOCTL_EL8625A_WRITE_EMID_PASS	4

#define SR98_IOCTL_MF1_PCD_RESET			32
#define SR98_IOCTL_MF1_TYPEA_GET_UID		33
#define SR98_IOCTL_MF1_TYPEA_REQUEST		34
#define SR98_IOCTL_MF1_TYPEA_ANTICOLL		35
#define SR98_IOCTL_MF1_TYPEA_SELECT			36
#define SR98_IOCTL_MF1_TYPEA_HOST_AUTHKEY	37
#define SR98_IOCTL_MF1_TYPEA_BLOCK_READ		38
#define SR98_IOCTL_MF1_TYPEA_BLOCK_WRITE	39
#define SR98_IOCTL_MF1_TYPEA_HALT			40
#define SR98_IOCTL_MF1_ANTENNA				41
#define SR98_IOCTL_MF1_PCD_TRANSCEIVE_BYTES	42
#define SR98_IOCTL_MF1_PCD_TRANSCEIVE_BITS	43

typedef struct _SR98_DEVICE {
	struct _SR98_DEVICE * next;
	DWORD id;
	PWCHAR DevicePath;
	HIDD_ATTRIBUTES hidAttributes;
	HIDP_CAPS hidCaps;
	HANDLE hDevice;
} SR98_DEVICE, *PSR98_DEVICE;

BOOL sr98_test_device(HANDLE hFile);
BOOL sr98_beep(HANDLE hFile, BYTE duration);
BOOL sr98_read_emid(HANDLE hFile, BYTE emid[5]);

BOOL sr98_t5577_reset(HANDLE hFile, BYTE DataRate);
BOOL sr98_t5577_write_block(HANDLE hFile, BYTE page, BYTE block, DWORD data, BYTE isPassword, DWORD password/*, BYTE lockBit*/);
BOOL sr98_t5577_wipe(HANDLE hFile, BOOL resetAfter);

BOOL sr98_send_receive(HANDLE hFile, BYTE ctl, LPCVOID in, BYTE szIn, LPBYTE *out, BYTE *szOut);
BOOL sr98_devices_get(PSR98_DEVICE *devices, DWORD *count);
void sr98_devices_free(PSR98_DEVICE devices);