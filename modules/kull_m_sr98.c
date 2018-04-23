/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_sr98.h"

BOOL sr98_test_device(HANDLE hFile)
{
	BOOL status = FALSE;
	USHORT temoin = 'BB';
	BYTE *out, szOut;
	if(sr98_send_receive(hFile, SR98_IOCTL_TEST_DEVICE, &temoin, sizeof(temoin), &out, &szOut))
	{
		if(szOut == sizeof(USHORT))
		{
			if(!(status = *((PUSHORT) out) == (temoin | 0x0100)))
				PRINT_ERROR(L"Received data is not origin+1 (0x%04x)\n", _byteswap_ushort(*((PUSHORT) out)));
		}
		else PRINT_ERROR(L"Received size is not 2 (0x%02x)\n", szOut);
		LocalFree(out);
	}
	return status;
}

BOOL sr98_beep(HANDLE hFile, BYTE duration)
{
	if(duration > 9)
		duration = 9;
	return sr98_send_receive(hFile, SR98_IOCTL_BEEP, &duration, 1, NULL, NULL);
}

BOOL sr98_read_emid(HANDLE hFile, BYTE emid[5])
{
	BOOL status = FALSE;
	BYTE *out, szOut;
	if(sr98_send_receive(hFile, SR98_IOCTL_EMID_READ, NULL, 0, &out, &szOut))
	{
		if(status = (szOut == 6))
			RtlCopyMemory(emid, out + 1, 5);
		else PRINT_ERROR(L"Received size is not 6 (0x%02x)\n", szOut);
		LocalFree(out);
	}
	return status;
}

BOOL sr98_t5577_write_block(HANDLE hFile, BYTE page, BYTE block, DWORD data, BYTE isPassword, DWORD password/*, BYTE lockBit*/)
{
	BOOL status = FALSE;
	BYTE blockContent[11], *out, szOut;

	blockContent[0] = SR98_SUB_IOCTL_T5577_WRITE_BLOCK;
	blockContent[1] = page & 1;
	//if(lockBit) // ????
	//	blockContent[1] |= SR98_T5577_LOCKBIT_MASK

	*(PDWORD) (blockContent + 2) = data;
	blockContent[6] = block & 7;

	if(isPassword)
	{
		blockContent[0] = SR98_SUB_IOCTL_T5577_WRITE_BLOCK_PASS;
		*(PDWORD) (blockContent + 7) = password;
	}

	if(sr98_send_receive(hFile, SR98_IOCTL_T5577, blockContent, isPassword ? sizeof(blockContent) : sizeof(blockContent) - sizeof(DWORD), &out, &szOut))
	{
		if(szOut == 1)
		{
			if(!(status = (*out == sizeof(DWORD))))
				PRINT_ERROR(L"Received data size is not 4 (0x%02x)\n", *out);
		}
		else PRINT_ERROR(L"Received size is not 1 (0x%02x)\n", szOut);
		LocalFree(out);
	}
	return status;
}

BOOL sr98_t5577_reset(HANDLE hFile, BYTE DataRate)
{
	BYTE inBuffer[5] = {SR98_SUB_IOCTL_T5577_RESET, DataRate & 0x0b}, *out, szOut;
	if(sr98_send_receive(hFile, SR98_IOCTL_T5577, inBuffer, sizeof(inBuffer), &out, &szOut))
	{
		if(szOut == 1)
		{
			if(*out)
				PRINT_ERROR(L"Data size is not 0 (0x%02x)\n", *out);
		}
		else PRINT_ERROR(L"Received size is not 1 (0x%02x)\n", szOut);
	}
	return FALSE;
}

BOOL sr98_t5577_wipe(HANDLE hFile, BOOL resetAfter)
{
	BOOL status;
	BYTE i;
	status = sr98_t5577_write_block(hFile, 0, 0, 0x40800800, FALSE, 0);
	for(i = 1; i < 8; i++)
		sr98_t5577_write_block(hFile, 0, i, 0x00000000, FALSE, 0);
	if(status && resetAfter)
		sr98_t5577_reset(hFile, SR98_RATE_RF_32);
	return status;
}

BOOL sr98_send_receive(HANDLE hFile, BYTE ctl, LPCVOID in, BYTE szIn, LPBYTE *out, BYTE *szOut)
{
	BOOL status = FALSE;
	BYTE i, crc, inBuffer[24] = {0x03, 0x01, 5 + szIn}, outBuffer[256] = {0}, szBuffer;
	DWORD ret;

	//kprintf(L">  ");
	//kull_m_string_wprintf_hex(in, szIn, 1);
	//kprintf(L"\n");
	if(szIn < (24 - 6))
	{
		inBuffer[3] = ctl;
		RtlCopyMemory(inBuffer + 4, in, szIn);
		for(i = 0, crc = 0; i < (3 + szIn); i++)
			crc ^= inBuffer[i + 1];
		
		inBuffer[4 + szIn] = crc;
		inBuffer[5 + szIn] = 0x04;
		
		//kprintf(L">> ");
		//kull_m_string_wprintf_hex(inBuffer, sizeof(inBuffer), 1);
		//kprintf(L"\n");
		PurgeComm(hFile, PURGE_TXCLEAR | PURGE_RXCLEAR);
		Sleep(SR98_SLEEP_BEFORE_SEND);
		if(WriteFile(hFile, inBuffer, sizeof(inBuffer), &ret, NULL) && (ret == sizeof(inBuffer)))
		{
			ClearCommError(hFile, NULL, NULL);
			Sleep(SR98_SLEEP_BEFORE_RECV);
			if(ReadFile(hFile, outBuffer, sizeof(outBuffer), &ret, NULL))
			{
				//kprintf(L"<< ");
				//kull_m_string_wprintf_hex(outBuffer, ret, 1 | (16 << 16));
				//kprintf(L"\n");
				if(ret >= 6)
				{
					if((outBuffer[0] == 0x05) && (outBuffer[1] == 0x01))
					{
						if((outBuffer[2] >= 5) && (outBuffer[3] == (ctl | 0x80)))
						{
							szBuffer = outBuffer[2] - 5;

							for(i = 0, crc = 0; i < (3 + szBuffer); i++)
								crc ^= outBuffer[i + 1];
							if((outBuffer[4 + szBuffer] == crc) && (outBuffer[5 + szBuffer] == 0x04))
							{
								status = TRUE;
								if(szBuffer && out && szOut)
								{
									*szOut = szBuffer;
									if(*out = (PBYTE) LocalAlloc(LPTR, szBuffer))
										RtlCopyMemory(*out, outBuffer + 4, szBuffer);
									else status = FALSE;
								}
								//kprintf(L"<  ");
								//kull_m_string_wprintf_hex(outBuffer + 4, szBuffer, 1);
								//kprintf(L"\n");
							}
							else PRINT_ERROR(L"Bad CRC/data\n");
						}
						else PRINT_ERROR(L"Bad data size/ctl code\n");
					}
					else PRINT_ERROR(L"Bad header\n");
				}
				else PRINT_ERROR(L"Read size = %u\n", ret);
			}
			else PRINT_ERROR_AUTO(L"ReadFile");
		}
		else PRINT_ERROR_AUTO(L"WriteFile");
	}
	return status;
}

BOOL sr98_devices_get(PSR98_DEVICE *devices, DWORD *count)
{
	PSR98_DEVICE *next = devices;
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
									if((attributes.VendorID == 0x6688) && ((attributes.ProductID >= 0x6850) && (attributes.ProductID <= 0x6868)))
									{
										if(*next = (PSR98_DEVICE) LocalAlloc(LPTR, sizeof(SR98_DEVICE)))
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

void sr98_devices_free(PSR98_DEVICE devices)
{
	PSR98_DEVICE tmp;
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