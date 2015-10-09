/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <hidsdi.h>
#include <setupapi.h>

#define BUSYLIGHT_CAP_INPUTEVENT	0x01
#define BUSYLIGHT_CAP_LIGHT			0x02
#define BUSYLIGHT_CAP_SOUND			0x04
#define BUSYLIGHT_CAP_JINGLECLIPS	0x08

typedef struct _BUSYLIGHT_DEVICE_ID {
	USHORT	Vid;
	USHORT	Pid;
	UCHAR	Capabilities;
	PCWSTR	Description;
} BUSYLIGHT_DEVICE_ID, *PBUSYLIGHT_DEVICE_ID;
typedef const BUSYLIGHT_DEVICE_ID *PCBUSYLIGHT_DEVICE_ID;

typedef struct _BUSYLIGHT_DPI {
	BYTE box_sensivity;
	BYTE box_timeout;
	BYTE box_triggertime;
} BUSYLIGHT_DPI, *PBUSYLIGHT_DPI;
typedef const BUSYLIGHT_DPI *PCBUSYLIGHT_DPI;

typedef struct _BUSYLIGHT_INFO {
	BYTE status;
	CHAR ProductId[4]; // 3 + NULL;
	CHAR CostumerId[9]; // 8 + NULL;
	CHAR Model[5]; // 4 + NULL;
	CHAR Serial[9]; // 8 + NULL;
	CHAR Mfg_ID[9]; // 8 + NULL;
	CHAR Mfg_Date[9]; // 8 + NULL;
	CHAR swrelease[7]; // 6 + NULL;
} BUSYLIGHT_INFO, *PBUSYLIGHT_INFO;

typedef struct _BUSYLIGHT_DEVICE {
	struct _BUSYLIGHT_DEVICE * next;
	DWORD id;
	HIDD_ATTRIBUTES hidAttributes;
	HIDP_CAPS hidCaps;
	PCBUSYLIGHT_DEVICE_ID deviceId;
	BUSYLIGHT_DPI dpi;
	HANDLE hBusy;
	BUSYLIGHT_INFO info;
	DWORD ThreadDelay;
	HANDLE hThread;
} BUSYLIGHT_DEVICE, *PBUSYLIGHT_DEVICE;

typedef struct _BUSYLIGHT_COLOR {
	BYTE red;
	BYTE green;
	BYTE blue;
} BUSYLIGHT_COLOR, *PBUSYLIGHT_COLOR;
typedef const BUSYLIGHT_COLOR *PCBUSYLIGHT_COLOR;

typedef struct _BUSYLIGHT_COMMAND_STEP {
	BYTE NextStep;
	BYTE RepeatInterval;
	BUSYLIGHT_COLOR color;
	BYTE OnTimeSteps;
	BYTE OffTimeSteps;
	BYTE AudioByte;
} BUSYLIGHT_COMMAND_STEP, *PBUSYLIGHT_COMMAND_STEP;

PCBUSYLIGHT_DEVICE_ID kull_m_busylight_getDeviceIdFromAttributes(PHIDD_ATTRIBUTES attributes);
BOOL kull_m_busylight_getDevices(PBUSYLIGHT_DEVICE *devices, DWORD *count, DWORD mask);
BOOL kull_m_busylight_sendRawRequest(PBUSYLIGHT_DEVICE device, const BYTE * request, DWORD size);
DWORD WINAPI kull_m_busylight_keepAliveThread(LPVOID lpThreadParameter);
void kull_m_busylight_start();
void kull_m_busylight_stop();