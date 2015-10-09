/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_busylight.h"

PBUSYLIGHT_DEVICE kull_m_busylight_devices = NULL;

const BUSYLIGHT_DEVICE_ID KULL_M_BUSYLIGHT_CATALOG[] = {
	{0x27bb, 0x3bca, BUSYLIGHT_CAP_LIGHT | BUSYLIGHT_CAP_SOUND | BUSYLIGHT_CAP_JINGLECLIPS, L"Busylight Lync model (with bootloader)"},
	{0x27bb, 0x3bcb, BUSYLIGHT_CAP_LIGHT | BUSYLIGHT_CAP_SOUND, L"Busylight UC model"},
	{0x27bb, 0x3bcc, BUSYLIGHT_CAP_INPUTEVENT, L"kuandoBOX"},
	{0x27bb, 0x3bcd, BUSYLIGHT_CAP_LIGHT | BUSYLIGHT_CAP_SOUND | BUSYLIGHT_CAP_JINGLECLIPS, L"Busylight Omega model"},
	{0x04d8, 0xf848, BUSYLIGHT_CAP_LIGHT | BUSYLIGHT_CAP_SOUND, L"Busylight Lync model"},
	{0x0bf8, 0x1020, BUSYLIGHT_CAP_LIGHT, L"Fujitsu MMM2"},
};
const BYTE BUSYLIGHT_RAW_KEEPALIVE[] =		{0x00, 0x8f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x03, 0x8c,};
const BYTE BUSYLIGHT_RAW_RENE_COTY_HACK[] = {0x00, 0x11, 0x00, 0x00, 0x00, 0x07, 0x07, 0x00, 0x80, 0x12, 0x00, 0x07, 0x07, 0x07, 0x07, 0x00, 0x80, 0x10, 0x00, 0x07, 0x00, 0x00, 0x07, 0x0a, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x04, 0xf2,};
const BYTE BUSYLIGHT_RAW_KIWI_HACK[] =		{0x00, 0x11, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x80, 0x12, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x80, 0x13, 0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x80, 0x14, 0x00, 0x00, 0x07, 0x00, 0x02, 0x00, 0x80, 0x15, 0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x80, 0x10, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x06, 0x8b,};
const BYTE BUSYLIGHT_RAW_OFF[] =			{0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x03, 0x8d,};

PCBUSYLIGHT_DEVICE_ID kull_m_busylight_getDeviceIdFromAttributes(PHIDD_ATTRIBUTES attributes)
{
	DWORD i;
	for(i = 0; i < ARRAYSIZE(KULL_M_BUSYLIGHT_CATALOG); i++)
		if((KULL_M_BUSYLIGHT_CATALOG[i].Vid == attributes->VendorID) && (KULL_M_BUSYLIGHT_CATALOG[i].Pid == attributes->ProductID))
			return &KULL_M_BUSYLIGHT_CATALOG[i];
	return NULL;
}

BOOL kull_m_busylight_getDevices(PBUSYLIGHT_DEVICE *devices, DWORD *count, DWORD mask)
{
	PBUSYLIGHT_DEVICE *next = devices;
	GUID guidHid;
	HDEVINFO hDevInfo;
	SP_DEVICE_INTERFACE_DATA DeviceInterfaceData;
	BOOL enumStatus;
	DWORD enumIndex, dwRequired, id = 0;
	PSP_DEVICE_INTERFACE_DETAIL_DATA DeviceInterfaceDetailData;
	HANDLE deviceHandle;
	HIDD_ATTRIBUTES attributes;
	PCBUSYLIGHT_DEVICE_ID deviceId;
	PHIDP_PREPARSED_DATA PreparsedData;

	*next = NULL;
	HidD_GetHidGuid(&guidHid);
	hDevInfo = SetupDiGetClassDevs(&guidHid, NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
	if(hDevInfo != INVALID_HANDLE_VALUE)
	{
		for(enumIndex = 0, enumStatus = TRUE; enumStatus; enumIndex++)
		{
			DeviceInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
			if(enumStatus = SetupDiEnumDeviceInterfaces(hDevInfo, NULL, &guidHid, enumIndex, &DeviceInterfaceData))
			{
				dwRequired = 0;
				if(!SetupDiGetDeviceInterfaceDetail(hDevInfo, &DeviceInterfaceData, NULL, 0, &dwRequired, NULL) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
				{
					if(DeviceInterfaceDetailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA) LocalAlloc(LPTR, dwRequired))
					{
						DeviceInterfaceDetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
						if(SetupDiGetDeviceInterfaceDetail(hDevInfo, &DeviceInterfaceData, DeviceInterfaceDetailData, dwRequired, &dwRequired, NULL))
						{
							deviceHandle = CreateFile(DeviceInterfaceDetailData->DevicePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
							if(deviceHandle != INVALID_HANDLE_VALUE)
							{
								attributes.Size = sizeof(HIDD_ATTRIBUTES);
								if(HidD_GetAttributes(deviceHandle, &attributes))
								{
									if(deviceId = kull_m_busylight_getDeviceIdFromAttributes(&attributes))
									{
										if((deviceId->Capabilities & mask) == mask)
										{
											if(*next = (PBUSYLIGHT_DEVICE) LocalAlloc(LPTR, sizeof(BUSYLIGHT_DEVICE)))
											{
												if(HidD_GetPreparsedData(deviceHandle, &PreparsedData))
												{
													if(!NT_SUCCESS(HidP_GetCaps(PreparsedData, &(*next)->hidCaps)))
														PRINT_ERROR(L"HidP_GetCaps\n");
													HidD_FreePreparsedData(PreparsedData);
												}
												(*next)->hidAttributes = attributes;
												(*next)->deviceId = deviceId;
												//(*next)->dpi.box_sensivity = 6;
												//(*next)->dpi.box_timeout = 4;
												//(*next)->dpi.box_triggertime = 85;
												(*next)->id = id;
												(*next)->hBusy = CreateFile(DeviceInterfaceDetailData->DevicePath, GENERIC_WRITE /*| GENERIC_READ*/, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
												(*next)->ThreadDelay = 5000;

												if((*next)->hBusy != INVALID_HANDLE_VALUE)
												{
													next = &(*next)->next;
													id++;
												}
												else
												{
													PRINT_ERROR_AUTO(L"CreateFile (hBusy)");
													LocalFree(*next);
												}
											}
										}
									}
								}
								CloseHandle(deviceHandle);
							}
							else PRINT_ERROR_AUTO(L"CreateFile (deviceHandle)");
						}
						LocalFree(DeviceInterfaceDetailData);
					}
				}
			}
		}
		SetupDiDestroyDeviceInfoList(hDevInfo);
	}
	else PRINT_ERROR_AUTO(L"SetupDiGetClassDevs");

	if(count)
		*count = id;
	return (id > 0);
}

void kull_m_busylight_freeDevices(PBUSYLIGHT_DEVICE devices)
{
	PBUSYLIGHT_DEVICE tmp;
	while(devices)
	{
		if(devices->hBusy)
		{
			//if(devices->hBusy != INVALID_HANDLE_VALUE)
			//	kull_m_busylight_sendRawRequest(devices, BUSYLIGHT_RAW_OFF, sizeof(BUSYLIGHT_RAW_OFF));
			CloseHandle(devices->hBusy);
			devices->hBusy = NULL;
		}
		devices->ThreadDelay = 0;
		if(devices->hThread)
			TerminateThread(devices->hThread, ERROR_SUCCESS);
		tmp = devices->next;
		LocalFree(devices);
		devices = tmp;
	}
}

BOOL kull_m_busylight_sendRawRequest(PBUSYLIGHT_DEVICE device, const BYTE * request, DWORD size)
{
	BOOL status = FALSE;
	DWORD readed;
	if(device && device->hBusy && (device->hBusy != INVALID_HANDLE_VALUE))
	{
		status = WriteFile(device->hBusy, request, size, &readed, NULL);
		if(!status)
			PRINT_ERROR(L"[device %u] WriteFile (0x%08x)\n", device->id, GetLastError());
	}
	else PRINT_ERROR(L"[device %u] Invalid Device/Busy Handle\n", device->id);
	return status;
}

DWORD WINAPI kull_m_busylight_keepAliveThread(LPVOID lpThreadParameter)
{
	PBUSYLIGHT_DEVICE device = (PBUSYLIGHT_DEVICE) lpThreadParameter;
	while(device->hThread && device->hBusy)
	{
		kull_m_busylight_sendRawRequest(device, BUSYLIGHT_RAW_KEEPALIVE, sizeof(BUSYLIGHT_RAW_KEEPALIVE));
		Sleep(device->ThreadDelay);
	};
	return ERROR_SUCCESS;
}

void kull_m_busylight_start()
{
	BOOL isFR = (((((DWORD) GetKeyboardLayout(0)) & 0xffff0000) >> 16) == 0x40c);
	if(kull_m_busylight_getDevices(&kull_m_busylight_devices, NULL, BUSYLIGHT_CAP_LIGHT)) // only deal with 1 device in this case.
	{
		kull_m_busylight_sendRawRequest(kull_m_busylight_devices, BUSYLIGHT_RAW_KEEPALIVE, sizeof(BUSYLIGHT_RAW_KEEPALIVE));
		kull_m_busylight_devices->hThread = CreateThread(NULL, 0, kull_m_busylight_keepAliveThread, kull_m_busylight_devices, 0, NULL); 
		kull_m_busylight_sendRawRequest(kull_m_busylight_devices, isFR ? BUSYLIGHT_RAW_KIWI_HACK : BUSYLIGHT_RAW_RENE_COTY_HACK, isFR ? sizeof(BUSYLIGHT_RAW_KIWI_HACK) : sizeof(BUSYLIGHT_RAW_RENE_COTY_HACK));
	}
}

void kull_m_busylight_stop()
{
	kull_m_busylight_freeDevices(kull_m_busylight_devices);
}