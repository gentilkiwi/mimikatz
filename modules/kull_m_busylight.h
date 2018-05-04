/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_hid.h"

#define BUSYLIGHT_INPUT_REPORT_SIZE				65
#define BUSYLIGHT_OUTPUT_REPORT_SIZE			65

#define BUSYLIGHT_CAP_INPUTEVENT				0x01
#define BUSYLIGHT_CAP_LIGHT						0x02
#define BUSYLIGHT_CAP_SOUND						0x04
#define BUSYLIGHT_CAP_JINGLE_CLIPS				0x08

#define BUSYLIGHT_MEDIA_MASK					0x80
typedef enum _BUSYLIGHT_MEDIA_VOLUME {
	BUSYLIGHT_MEDIA_VOLUME_0_MUTE =				0,
	BUSYLIGHT_MEDIA_VOLUME_1_MIN =				1,
	BUSYLIGHT_MEDIA_VOLUME_2 =					2,
	BUSYLIGHT_MEDIA_VOLUME_3 =					3,
	BUSYLIGHT_MEDIA_VOLUME_4_MEDIUM =			4,
	BUSYLIGHT_MEDIA_VOLUME_5 =					5,
	BUSYLIGHT_MEDIA_VOLUME_6 =					6,
	BUSYLIGHT_MEDIA_VOLUME_7_MAX =				7,
} BUSYLIGHT_MEDIA_VOLUME, *PBUSYLIGHT_MEDIA_VOLUME;
typedef const BUSYLIGHT_MEDIA_VOLUME *PCBUSYLIGHT_MEDIA_VOLUME;

typedef enum _BUSYLIGHT_MEDIA_SOUND_JINGLE {
	BUSYLIGHT_MEDIA_SOUND_MUTE =				(0  << 3),
	BUSYLIGHT_MEDIA_SOUND_OPENOFFICE =			(1  << 3),
	BUSYLIGHT_MEDIA_SOUND_QUIET =				(2  << 3),
	BUSYLIGHT_MEDIA_SOUND_FUNKY =				(3  << 3),
	BUSYLIGHT_MEDIA_SOUND_FAIRYTALE =			(4  << 3),
	BUSYLIGHT_MEDIA_SOUND_KUANDOTRAIN =			(5  << 3),
	BUSYLIGHT_MEDIA_SOUND_TELEPHONENORDIC =		(6  << 3),
	BUSYLIGHT_MEDIA_SOUND_TELEPHONEORIGINAL =	(7  << 3),
	BUSYLIGHT_MEDIA_SOUND_TELEPHONEPICKMEUP =	(8  << 3),
	BUSYLIGHT_MEDIA_JINGLE_IM1 =				(9  << 3),
	BUSYLIGHT_MEDIA_JINGLE_IM2 =				(10 << 3),
} BUSYLIGHT_MEDIA_SOUND_JINGLE, *PBUSYLIGHT_MEDIA_SOUND_JINGLE;
typedef const BUSYLIGHT_MEDIA_SOUND_JINGLE *PCBUSYLIGHT_MEDIA_SOUND_JINGLE;
#define BUSYLIGHT_MEDIA(sound, volume) (BUSYLIGHT_MEDIA_MASK | (sound) | (volume))
#define BUSYLIGHT_MEDIA_MUTE BUSYLIGHT_MEDIA(BUSYLIGHT_MEDIA_SOUND_MUTE, BUSYLIGHT_MEDIA_VOLUME_0_MUTE)

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
	PWCHAR DevicePath;
	HIDD_ATTRIBUTES hidAttributes;
	HIDP_CAPS hidCaps;
	PCBUSYLIGHT_DEVICE_ID deviceId;
	BUSYLIGHT_DPI dpi;
	HANDLE hBusy;
	DWORD dKeepAliveThread;
	HANDLE hKeepAliveThread;
	DWORD dWorkerThread;
	HANDLE hWorkerThread;
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
typedef const BUSYLIGHT_COMMAND_STEP *PCBUSYLIGHT_COMMAND_STEP;

const BUSYLIGHT_COLOR
	BUSYLIGHT_COLOR_OFF,
	BUSYLIGHT_COLOR_RED,
	BUSYLIGHT_COLOR_ORANGE,
	BUSYLIGHT_COLOR_YELLOW,
	BUSYLIGHT_COLOR_CHARTREUSE_GREEN,
	BUSYLIGHT_COLOR_GREEN,
	BUSYLIGHT_COLOR_SPRING_GREEN,
	BUSYLIGHT_COLOR_CYAN,
	BUSYLIGHT_COLOR_AZURE,
	BUSYLIGHT_COLOR_BLUE,
	BUSYLIGHT_COLOR_VIOLET,
	BUSYLIGHT_COLOR_MAGENTA,
	BUSYLIGHT_COLOR_ROSE,
	BUSYLIGHT_COLOR_WHITE
;

PCBUSYLIGHT_DEVICE_ID kull_m_busylight_devices_getIdFromAttributes(PHIDD_ATTRIBUTES attributes);
BOOL kull_m_busylight_devices_get(PBUSYLIGHT_DEVICE *devices, DWORD *count, DWORD mask, BOOL bAutoThread);
void kull_m_busylight_devices_free(PBUSYLIGHT_DEVICE devices, BOOL instantOff);

//BOOL kull_m_busylight_request_create(PBUSYLIGHT_COMMAND_STEP commands, DWORD count, PCBUSYLIGHT_DPI dpi, PBYTE *data, DWORD *size);
BOOL kull_m_busylight_request_create(PCBUSYLIGHT_COMMAND_STEP commands, DWORD count, PBYTE *data, DWORD *size);
BOOL kull_m_busylight_device_send_raw(PBUSYLIGHT_DEVICE device, LPCVOID request, DWORD size);
BOOL kull_m_busylight_device_read_raw(PBUSYLIGHT_DEVICE device, LPVOID *data, DWORD *size);

DWORD WINAPI kull_m_busylight_keepAliveThread(LPVOID lpThreadParameter);

BOOL kull_m_busylight_device_read_infos(PBUSYLIGHT_DEVICE device, BUSYLIGHT_INFO *info);
BOOL kull_m_busylight_request_send(PBUSYLIGHT_DEVICE device, PCBUSYLIGHT_COMMAND_STEP commands, DWORD count, BOOL all);
BOOL kull_m_busylight_request_send_keepalive(PBUSYLIGHT_DEVICE device, BOOL all);
BOOL kull_m_busylight_request_send_off(PBUSYLIGHT_DEVICE device, BOOL all);

BOOL kull_m_busylight_request_single_send(PBUSYLIGHT_DEVICE device, const BUSYLIGHT_COLOR * color, BYTE sound, BYTE volume, BOOL all);