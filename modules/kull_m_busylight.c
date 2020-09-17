/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_busylight.h"

const BUSYLIGHT_DEVICE_ID KULL_M_BUSYLIGHT_CATALOG[] = {
	{0x27bb, 0x3bca, BUSYLIGHT_CAP_LIGHT | BUSYLIGHT_CAP_SOUND | BUSYLIGHT_CAP_JINGLE_CLIPS,	L"Busylight Lync model (with bootloader)"},
	{0x27bb, 0x3bcb, BUSYLIGHT_CAP_LIGHT | BUSYLIGHT_CAP_SOUND,									L"Busylight UC model"},
	{0x27bb, 0x3bcc, BUSYLIGHT_CAP_INPUTEVENT,													L"kuandoBOX"},
	{0x27bb, 0x3bcd, BUSYLIGHT_CAP_LIGHT | BUSYLIGHT_CAP_SOUND | BUSYLIGHT_CAP_JINGLE_CLIPS,	L"Busylight Omega model"},
	{0x04d8, 0xf848, BUSYLIGHT_CAP_LIGHT | BUSYLIGHT_CAP_SOUND,									L"Busylight Lync model (Microchip Id)"},
	{0x0bf8, 0x1020, BUSYLIGHT_CAP_LIGHT,														L"Fujitsu MMM2"},
};

const BUSYLIGHT_COLOR
	BUSYLIGHT_COLOR_OFF					= {0,	0,		0},
	BUSYLIGHT_COLOR_RED					= {100,	0,		0},
	BUSYLIGHT_COLOR_ORANGE				= {100,	50,		0},
	BUSYLIGHT_COLOR_YELLOW				= {100,	100,	0},
	BUSYLIGHT_COLOR_CHARTREUSE_GREEN	= {50,	100,	0},
	BUSYLIGHT_COLOR_GREEN				= {0,	100,	0},
	BUSYLIGHT_COLOR_SPRING_GREEN		= {0,	100,	50},
	BUSYLIGHT_COLOR_CYAN				= {0,	100,	100},
	BUSYLIGHT_COLOR_AZURE				= {0,	50,		100},
	BUSYLIGHT_COLOR_BLUE				= {0,	0,		100},
	BUSYLIGHT_COLOR_VIOLET				= {50,	0,		100},
	BUSYLIGHT_COLOR_MAGENTA				= {100,	0,		100},
	BUSYLIGHT_COLOR_ROSE				= {100,	0,		50},
	BUSYLIGHT_COLOR_WHITE				= {100, 100,	100}
;

PCBUSYLIGHT_DEVICE_ID kull_m_busylight_devices_getIdFromAttributes(PHIDD_ATTRIBUTES attributes)
{
	DWORD i;
	if(attributes)
		for(i = 0; i < ARRAYSIZE(KULL_M_BUSYLIGHT_CATALOG); i++)
			if((KULL_M_BUSYLIGHT_CATALOG[i].Vid == attributes->VendorID) && (KULL_M_BUSYLIGHT_CATALOG[i].Pid == attributes->ProductID))
				return &KULL_M_BUSYLIGHT_CATALOG[i];
	return NULL;
}

BOOL kull_m_busylight_devices_get(PBUSYLIGHT_DEVICE *devices, DWORD *count, DWORD mask, BOOL bAutoThread)
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
	NTSTATUS status;

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
									if(deviceId = kull_m_busylight_devices_getIdFromAttributes(&attributes))
									{
										if((deviceId->Capabilities & mask) == mask)
										{
											if(*next = (PBUSYLIGHT_DEVICE) LocalAlloc(LPTR, sizeof(BUSYLIGHT_DEVICE)))
											{
												if(HidD_GetPreparsedData(deviceHandle, &PreparsedData))
												{
													status = HidP_GetCaps(PreparsedData, &(*next)->hidCaps);
													if(!NT_SUCCESS(status))
														PRINT_ERROR(L"HidP_GetCaps (%08x)\n", status);
													HidD_FreePreparsedData(PreparsedData);
												}
												(*next)->DevicePath = _wcsdup(DeviceInterfaceDetailData->DevicePath);
												(*next)->hidAttributes = attributes;
												(*next)->deviceId = deviceId;
												(*next)->dpi.box_sensivity = 4;
												(*next)->dpi.box_timeout = 4;
												(*next)->dpi.box_triggertime = 85;
												(*next)->id = id;
												(*next)->hBusy = CreateFile(DeviceInterfaceDetailData->DevicePath, FILE_READ_DATA | FILE_WRITE_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
												
												if((*next)->hBusy && ((*next)->hBusy != INVALID_HANDLE_VALUE))
												{
													if(bAutoThread)
													{
														(*next)->dKeepAliveThread = 5000;
														if((*next)->hKeepAliveThread = CreateThread(NULL, 0, kull_m_busylight_keepAliveThread, *next, 0, NULL))
														{
															next = &(*next)->next;
															id++;
														}
														else
														{
															PRINT_ERROR_AUTO(L"CreateThread (hKeepAliveThread)");
															CloseHandle((*next)->hBusy);
															LocalFree(*next);
														}
													}
													else
													{
														next = &(*next)->next;
														id++;
													}
												}
												else
												{
													PRINT_ERROR_AUTO(L"CreateFile (hBusy)");
													*next = (PBUSYLIGHT_DEVICE) LocalFree(*next);
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

void kull_m_busylight_devices_free(PBUSYLIGHT_DEVICE devices, BOOL instantOff)
{
	PBUSYLIGHT_DEVICE tmp;
	while(devices)
	{
		if(devices->hBusy)
		{
			if(instantOff && (devices->hBusy != INVALID_HANDLE_VALUE))
				kull_m_busylight_request_send_off(devices, FALSE);
			CloseHandle(devices->hBusy);
			devices->hBusy = NULL;
		}
		devices->dKeepAliveThread = 0;
		if(devices->hKeepAliveThread)
		{
			TerminateThread(devices->hKeepAliveThread, ERROR_SUCCESS);
			devices->hKeepAliveThread = NULL;
		}
		devices->dWorkerThread = 0;
		if(devices->hWorkerThread)
		{
			TerminateThread(devices->hWorkerThread, ERROR_SUCCESS);
			devices->hWorkerThread = NULL;
		}
		if(devices->DevicePath)
			free(devices->DevicePath);
		tmp = devices->next;
		LocalFree(devices);
		devices = tmp;
	}
}

BOOL kull_m_busylight_request_create(PCBUSYLIGHT_COMMAND_STEP commands, DWORD count, PBYTE *data, DWORD *size)
{
	BOOL status = FALSE;
	DWORD i;
	USHORT sum;

	*size = BUSYLIGHT_OUTPUT_REPORT_SIZE;
	if(*data = (PBYTE) LocalAlloc(LPTR, *size))
	{
		if(count >=7)
			PRINT_ERROR(L"count=%u (max is 7)\n", count);
		for(i = 0; i < min(count, 7); i++)
		{
			(*data)[i * 8 + 1] = (commands[i].NextStep & 0xf0) ? commands[i].NextStep : (commands[i].NextStep | 0x10);
			(*data)[i * 8 + 2] = commands[i].RepeatInterval;
			// TODO avoid color (or not ?)
			(*data)[i * 8 + 3] = commands[i].color.red;
			(*data)[i * 8 + 4] = commands[i].color.green;
			(*data)[i * 8 + 5] = commands[i].color.blue;

			(*data)[i * 8 + 6] = commands[i].OnTimeSteps;
			(*data)[i * 8 + 7] = commands[i].OffTimeSteps;
			(*data)[i * 8 + 8] = commands[i].AudioByte;
		}
		(*data)[57] = 4;
		(*data)[58] = 4;
		(*data)[59] = 85;

		(*data)[60] = (*data)[61] = (*data)[62] = 0xff;
		
		for(i = 1, sum = 0; i < (*size - 2); i++)
			sum += (*data)[i];
		(*data)[63] = (BYTE) (sum / 256);
		(*data)[64] = (BYTE) (sum % 256);

		status = TRUE; // TODO add checks
		if(!status)
		{
			*data = (PBYTE) LocalFree(*data);
			*size = 0;
		}
	}
	return status;
}

BOOL kull_m_busylight_device_send_raw(PBUSYLIGHT_DEVICE device, LPCVOID request, DWORD size)
{
	BOOL status = FALSE;
	DWORD writed;
	if(device && device->hBusy && (device->hBusy != INVALID_HANDLE_VALUE))
	{
		if(size <= device->hidCaps.OutputReportByteLength)
		{
			status = WriteFile(device->hBusy, request, size, &writed, NULL);
			if(!status)
				PRINT_ERROR(L"[device %u] WriteFile (0x%08x)\n", device->id, GetLastError());
		}
		else PRINT_ERROR(L"[device %u] Size is not valide (siz = %u, max = %u)\n", device->id, size, device->hidCaps.OutputReportByteLength);
	}
	else PRINT_ERROR(L"[device %u] Invalid Device/Busy Handle\n", device->id);
	return status;
}

BOOL kull_m_busylight_device_read_raw(PBUSYLIGHT_DEVICE device, LPVOID *data, DWORD *size)
{
	BOOL status = FALSE;
	DWORD toRead;
	if(device && device->hBusy && (device->hBusy != INVALID_HANDLE_VALUE))
	{
		toRead = device->hidCaps.InputReportByteLength;
		if(*data = LocalAlloc(LPTR, toRead))
		{
			status = ReadFile(device->hBusy, *data, toRead, size, NULL);
			if(!status || (status && (*size != toRead)))
			{
				if(!status)
					PRINT_ERROR(L"[device %u] ReadFile (0x%08x)\n", device->id, GetLastError());
				else
					PRINT_ERROR(L"[device %u] %u byte(s) readed, %u wanted\n", *size, toRead);
				*data = LocalFree(*data);
				*size = 0;
			}
		}
	}
	else PRINT_ERROR(L"[device %u] Invalid Device/Busy Handle\n", device->id);
	return status;
}

DWORD WINAPI kull_m_busylight_keepAliveThread(LPVOID lpThreadParameter)
{
	PBUSYLIGHT_DEVICE device = (PBUSYLIGHT_DEVICE) lpThreadParameter;
	while(device && device->hKeepAliveThread && device->dKeepAliveThread && device->hBusy)
	{
		if(kull_m_busylight_request_send_keepalive(device, FALSE))
			Sleep(device->dKeepAliveThread);
		else
		{
			CloseHandle(device->hBusy);
			device->hBusy = NULL;
			device->dKeepAliveThread = 0;
			device->hKeepAliveThread = NULL;
			break;
		}
	};
	return ERROR_SUCCESS;
}

BOOL kull_m_busylight_device_read_infos(PBUSYLIGHT_DEVICE device, BUSYLIGHT_INFO *info)
{
	BOOL status = FALSE;
	LPBYTE data;
	DWORD size;
	if(kull_m_busylight_request_send_keepalive(device, FALSE))
	{
		if(kull_m_busylight_device_read_raw(device, (LPVOID *) &data, &size))
		{
			RtlZeroMemory(info, sizeof(BUSYLIGHT_INFO));
			if(status = !data[0])
			{
				info->status = data[1];
				RtlCopyMemory(info->ProductId, data + 2, 3);
				RtlCopyMemory(info->CostumerId, data + 5, 8);
				RtlCopyMemory(info->Model, data + 13, 4);
				RtlCopyMemory(info->Serial, data + 17, 8);
				RtlCopyMemory(info->Mfg_ID, data + 25, 8);
				RtlCopyMemory(info->Mfg_Date, data + 33, 8);
				RtlCopyMemory(info->swrelease, data + 41, 6);
			}
			else PRINT_ERROR(L"[device %u] data[0] is not NULL (0x%02x)\n", data[0]);
			LocalFree(data);
		}
	}
	return status;
}

BOOL kull_m_busylight_request_send(PBUSYLIGHT_DEVICE device, PCBUSYLIGHT_COMMAND_STEP commands, DWORD count, BOOL all)
{
	BOOL status = FALSE;
	PBUSYLIGHT_DEVICE cur;
	LPBYTE data;
	DWORD size;
	if(status = kull_m_busylight_request_create(commands, count, &data, &size))
	{
		for(cur = device; cur; cur = all ? cur->next : NULL)
			status &= kull_m_busylight_device_send_raw(cur, data, size);
		LocalFree(data);
	}
	return status;
}

BOOL kull_m_busylight_request_send_keepalive(PBUSYLIGHT_DEVICE device, BOOL all)
{
	BUSYLIGHT_COMMAND_STEP mdl = {0x8f, 0, {0, 0, 0}, 0, 0, 0};
	return kull_m_busylight_request_send(device, &mdl, 1, all);
}

BOOL kull_m_busylight_request_send_off(PBUSYLIGHT_DEVICE device, BOOL all)
{
	PBUSYLIGHT_DEVICE cur;
	BUSYLIGHT_COMMAND_STEP mdl = {0, 0, {0, 0, 0}, 0, 0, BUSYLIGHT_MEDIA_MUTE};

	for(cur = device; cur; cur = all ? cur->next : NULL)
	{
		cur->dWorkerThread = 0;
		if(cur->hWorkerThread)
		{
			TerminateThread(cur->hWorkerThread, ERROR_SUCCESS);
			cur->hWorkerThread = NULL;
		}
	}
	return kull_m_busylight_request_send(device, &mdl, 1, all);
}

BOOL kull_m_busylight_request_single_send(PBUSYLIGHT_DEVICE device, const BUSYLIGHT_COLOR * color, BYTE sound, BYTE volume, BOOL all)
{
	BUSYLIGHT_COMMAND_STEP mdl = {0, 0, {color->red, color->green, color->blue}, 0, 0, BUSYLIGHT_MEDIA(sound, volume)};
	return kull_m_busylight_request_send(device, &mdl, 1, all);
}