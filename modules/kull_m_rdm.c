/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_rdm.h"

BOOL rdm_get_version(HANDLE hFile, PSTR *version)
{
	BOOL status = FALSE;
	BYTE *data, szData;

	if(rdm_send_receive(hFile, RDM_IOCTL_GET_VERSION, NULL, 0, &data, &szData))
	{
		if(data)
		{
			if(*version = (PSTR) LocalAlloc(LPTR, szData + 1))
			{
				RtlCopyMemory(*version, data, szData);
				status = TRUE;
			}
			LocalFree(data);
		}
	}
	return status;
}

BOOL rdm_send_receive(HANDLE hFile, BYTE ctl, LPCVOID in, BYTE szIn, LPBYTE *out, BYTE *szOut)
{
	BOOL status = FALSE;
	BYTE i, crc, data[0x100] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 6 + szIn, 0x00, 0xaa, 0x00 /*addr*/, 1 + szIn, ctl, /* data[..], crc, 0xbb */};
	USHORT bigSize;
	LPCWCHAR error;

	if(szIn <= 242)
	{
		if(szIn)
			RtlCopyMemory(data + 12, in, szIn);
		for(i = 0, crc = 0; i < (szIn + 2); i++)
			crc ^= data[10 + i];
		data[12 + szIn] = crc;
		data[12 + szIn + 1] = 0xbb;
		kprintf(L">> "); kull_m_string_wprintf_hex(data, 14 + szIn, 1); kprintf(L"\n");
		Sleep(RDM_SLEEP_BEFORE_SEND);
		if(HidD_SetFeature(hFile, data, sizeof(data)))
		{
			Sleep(RDM_SLEEP_BEFORE_RECV);
			if(HidD_GetFeature(hFile, data, sizeof(data)))
			{
				if(data[0] == 0x03)
				{
					bigSize = *(PUSHORT) (data + 6);
					if((bigSize >= 6) && (bigSize <= (242 + 6)))
					{
						kprintf(L"<< "); kull_m_string_wprintf_hex(data, bigSize + 8, 1); kprintf(L"\n");
						szIn = (BYTE) (bigSize - 6);
						if(data[8] == 0xaa)
						{
							if((data[10] - 1) == szIn)
							{
								for(i = 0, crc = 0; i < (szIn + 2); i++)
									crc ^= data[10 + i];
								if(crc == data[12 + szIn])
								{
									if(data[12 + szIn + 1] = 0xbb)
									{
										switch(data[11])
										{
										case 0x00: // command OK
										case 0xff:
											status = TRUE;
											if(out && szOut)
											{
												*out = NULL;
												*szOut = 0;
												if(szIn)
												{
													if(*out = (PBYTE) LocalAlloc(LPTR, szIn))
													{
														RtlCopyMemory(*out, data + 12, szIn);
														*szOut = szIn;
													}
													else status = FALSE;
												}
											}
											error = NULL;
											break;
										case 0x01: // command failure
											if(szIn == 1)
											{
												switch(data[12])
												{
												case 0x80: error = L"set OK"; break;
												case 0x81: error = L"set failure"; break;
												case 0x82: error = L"reader reply timeout"; break;
												case 0x83: error = L"card does not exist"; break;
												case 0x84: error = L"data response from the card"; break;
												case 0x85: error = L"format or parameter of the command"; break;
												case 0x87: error = L"unknown internal error"; break;
												case 0x8a: error = L"initVal process"; break;
												case 0x8b: error = L"wrong SNR during anticollision"; break;
												case 0x8c: error = L"authentication failure"; break;
												case 0x8f: error = L"reader received unknown command"; break;
												case 0x90: error = L"card does not support this command"; break;
												case 0x91: error = L"format of the command"; break;
												case 0x92: error = L"does not support option mode"; break;
												case 0x93: error = L"block does not exist"; break;
												case 0x94: error = L"object has been locked"; break;
												case 0x95: error = L"lock operation did not succeed"; break;
												case 0x96: error = L"operation did not succeed"; break;
												default: L"unknow error code!";
												}
												PRINT_ERROR(L"Command failure: 0x%02x - %s\n", data[12], error);
											}
											else PRINT_ERROR(L"data size is not 1 when dealing when an error status (%hhu)\n", szIn);
											error = NULL;
											break;
										case 0x02: error = L"checksum"; break;
										case 0x03: error = L"not COM port selected"; break;
										case 0x04: error = L"timeout reply"; break;
										case 0x05: error = L"check sequence"; break;
										case 0x07: error = L"receive"; break;
										case 0x0a: error = L"parameter value out of range"; break;
										default: error = L"unknow error code!";
										}
										if(error)
											PRINT_ERROR(L"Status failure: 0x%02x - %s\n", data[11], error);
									}
									else PRINT_ERROR(L"Bad China footer (0x%02x)\n", data[12 + szIn + 1]);
								}
								else PRINT_ERROR(L"Bad CRC (0x%02x -- 0x%02x)\n", crc, data[12 + szIn]);
							}
							else PRINT_ERROR(L"Bad HID size vs Data size (0x%02x -- 0x%02x)\n", szIn, data[10] - 1);
						}
						else PRINT_ERROR(L"Bad China header (0x%02x)\n", data[8]);
					}
					else PRINT_ERROR(L"Bad HID size (%hhu)\n", bigSize);
				}
				else PRINT_ERROR(L"Bad HID header (0x%02x)\n", data[0]);
			}
			else PRINT_ERROR_AUTO(L"HidD_GetFeature");
		}
		else PRINT_ERROR_AUTO(L"HidD_SetFeature");
	}
	else PRINT_ERROR(L"Size >= 242 (%hhu)\n", szIn);
	return status;
}

BOOL rdm_devices_get(PRDM_DEVICE *devices, DWORD *count)
{
	PRDM_DEVICE *next = devices;
	GUID guidHid;
	HDEVINFO hDevInfo;
	SP_DEVICE_INTERFACE_DATA DeviceInterfaceData;
	BOOL enumStatus;
	DWORD enumIndex, dwRequired, id = 0;
	PSP_DEVICE_INTERFACE_DETAIL_DATA DeviceInterfaceDetailData;
	HANDLE deviceHandle;
	HIDD_ATTRIBUTES attributes;
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
									if((attributes.VendorID == 0xffff) && (attributes.ProductID == 0x0035))
									{
										if(*next = (PRDM_DEVICE) LocalAlloc(LPTR, sizeof(RDM_DEVICE)))
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
											(*next)->id = id;
											(*next)->hDevice = CreateFile(DeviceInterfaceDetailData->DevicePath, FILE_READ_DATA | FILE_WRITE_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

											if((*next)->hDevice && ((*next)->hDevice != INVALID_HANDLE_VALUE))
											{
												next = &(*next)->next;
												id++;
											}
											else
											{
												if(GetLastError() != ERROR_ACCESS_DENIED)
													PRINT_ERROR_AUTO(L"CreateFile (hDevice)");
												LocalFree(*next);
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

void rdm_devices_free(PRDM_DEVICE devices)
{
	PRDM_DEVICE tmp;
	while(devices)
	{
		if(devices->hDevice)
		{
			CloseHandle(devices->hDevice);
			devices->hDevice = NULL;
		}
		if(devices->DevicePath)
			free(devices->DevicePath);
		tmp = devices->next;
		LocalFree(devices);
		devices = tmp;
	}
}