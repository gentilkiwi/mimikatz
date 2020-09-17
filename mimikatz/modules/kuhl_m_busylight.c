/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_busylight.h"

BOOL isBusyLight = FALSE;
PBUSYLIGHT_DEVICE kuhl_m_busylight_devices = NULL;

const KUHL_M_C kuhl_m_c_busylight[] = {
	{kuhl_m_busylight_list,			L"list",		L""},
	{kuhl_m_busylight_status,		L"status",		L""},
	{kuhl_m_busylight_single,		L"single",		L""},
	{kuhl_m_busylight_off,			L"off",			L""},
	{kuhl_m_busylight_test,			L"test",		L""},

};

const KUHL_M kuhl_m_busylight = {
	L"busylight", L"BusyLight Module", NULL,
	ARRAYSIZE(kuhl_m_c_busylight), kuhl_m_c_busylight, kuhl_m_busylight_init, kuhl_m_busylight_clean
};

const BUSYLIGHT_COMMAND_STEP kuhl_m_busylight_steps_KiwiHack[] = {
	{1, 0, {0,   10,  0  }, 1, 0,  BUSYLIGHT_MEDIA_MUTE},
	{2, 0, {0,   25,  0  }, 1, 0,  BUSYLIGHT_MEDIA_MUTE},
	{3, 0, {0,   75,  0  }, 1, 0,  BUSYLIGHT_MEDIA_MUTE},
	{4, 0, {0,   100, 0  }, 1, 0,  BUSYLIGHT_MEDIA_MUTE},
	{5, 0, {0,   75,  0  }, 1, 0,  BUSYLIGHT_MEDIA_MUTE},
	{0, 0, {0,   25,  0  }, 1, 0,  BUSYLIGHT_MEDIA_MUTE},
},
kuhl_m_busylight_steps_ReneCotyHack[] = {
	{1, 0, {0,   0,   100}, 10, 0,  BUSYLIGHT_MEDIA_MUTE},
	{2, 0, {100, 100, 100}, 10, 0,  BUSYLIGHT_MEDIA_MUTE},
	{3, 0, {100, 0,   0  }, 10, 10, BUSYLIGHT_MEDIA_MUTE},

	{4, 0, {0,   0,   100}, 2, 0,  BUSYLIGHT_MEDIA_MUTE},
	{5, 0, {100, 100, 100}, 2, 0,  BUSYLIGHT_MEDIA_MUTE},
	{0, 0, {100, 0,   0  }, 2, 20, BUSYLIGHT_MEDIA_MUTE},
};

NTSTATUS kuhl_m_busylight_init()
{
	PBUSYLIGHT_DEVICE cur;
	BOOL isKbFR = (PtrToUlong(GetKeyboardLayout(0)) >> 16) == 0x40c, isKiwi = FALSE;
	if(isBusyLight = kull_m_busylight_devices_get(&kuhl_m_busylight_devices, NULL, BUSYLIGHT_CAP_LIGHT, TRUE))
	{
		for(cur = kuhl_m_busylight_devices; cur; cur = cur->next)
		{
			isKiwi = ((!(cur->id % 2) && isKbFR) || ((cur->id % 2) && !isKbFR));
			kull_m_busylight_request_send(cur, isKiwi ? kuhl_m_busylight_steps_KiwiHack : kuhl_m_busylight_steps_ReneCotyHack, isKiwi ? ARRAYSIZE(kuhl_m_busylight_steps_KiwiHack) : ARRAYSIZE(kuhl_m_busylight_steps_ReneCotyHack), FALSE);
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_busylight_clean()
{
	kull_m_busylight_devices_free(kuhl_m_busylight_devices, TRUE);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_busylight_off(int argc, wchar_t * argv[])
{
	if(isBusyLight)
		kull_m_busylight_request_send_off(kuhl_m_busylight_devices, TRUE);
	else PRINT_ERROR(L"No BusyLight\n");
	return STATUS_SUCCESS;
}

const PCWCHAR kuhl_m_busylight_capabilities_to_String[] = {L"INPUTEVENT", L"LIGHT", L"SOUND", L"JINGLE_CLIPS"};
NTSTATUS kuhl_m_busylight_status(int argc, wchar_t * argv[])
{
	PBUSYLIGHT_DEVICE cur;
	DWORD i;
	BUSYLIGHT_INFO info;

	if(isBusyLight)
	{
		kprintf(L"BusyLight detected\n");
		for(cur = kuhl_m_busylight_devices; cur; cur = cur->next)
		{
			kprintf(L"\n[%3u] %s\n"
				L"  Vendor: 0x%04x, Product: 0x%04x, Version: 0x%04x\n"
				L"  Description   : %s\n"
				L"  Capabilities  : 0x%02x ( "
				, cur->id, cur->DevicePath, cur->hidAttributes.VendorID, cur->hidAttributes.ProductID, cur->hidAttributes.VersionNumber, cur->deviceId->Description, cur->deviceId->Capabilities);
			for(i = 0; i < ARRAYSIZE(kuhl_m_busylight_capabilities_to_String); i++)
			{
				if((cur->deviceId->Capabilities >> i) & 1)
					kprintf(L"%s, ", kuhl_m_busylight_capabilities_to_String[i]);
			}
			kprintf(L")\n");

			kprintf(L"  Device Handle: 0x%p\n", cur->hBusy);
			if(cur->hBusy)
			{
				if(kull_m_busylight_device_read_infos(cur, &info))
				{
					kprintf(L"    Status     : 0x%02x\n", info.status);
					kprintf(L"    ProductId  : %S\n", info.ProductId);
					kprintf(L"    CostumerId : %S\n", info.CostumerId);
					kprintf(L"    Model      : %S\n", info.Model);
					kprintf(L"    Serial     : %S\n", info.Serial);
					kprintf(L"    Mfg_ID     : %S\n", info.Mfg_ID);
					kprintf(L"    Mfg_Date   : %S\n", info.Mfg_Date);
					kprintf(L"    swrelease  : %S\n", info.swrelease);
				}
			}
			kprintf(L"  KeepAlive Thread: 0x%p (%u ms)\n"
					L"  Worker Thread   : 0x%p (%u ms)\n"
					, cur->hKeepAliveThread, cur->dKeepAliveThread, cur->hWorkerThread, cur->dWorkerThread);
		}
	}
	else PRINT_ERROR(L"No BusyLight\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_busylight_list(int argc, wchar_t * argv[])
{
	PBUSYLIGHT_DEVICE cur;
	DWORD i;

	if(isBusyLight)
	{
		for(cur = kuhl_m_busylight_devices; cur; cur = cur->next)
		{
			kprintf(L"[%3u] %s ( ", cur->id, cur->deviceId->Description);
			for(i = 0; i < ARRAYSIZE(kuhl_m_busylight_capabilities_to_String); i++)
			{
				if((cur->deviceId->Capabilities >> i) & 1)
					kprintf(L"%s, ", kuhl_m_busylight_capabilities_to_String[i]);
			}
			kprintf(L")\n");
		}
	}
	else PRINT_ERROR(L"No BusyLight\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_busylight_single(int argc, wchar_t * argv[])
{
	PCWCHAR szColor;
	DWORD dwColor;
	BUSYLIGHT_COMMAND_STEP mdl = {0, 1, {0, 0, 0}, 1, 0, BUSYLIGHT_MEDIA_MUTE};
	
	mdl.color = BUSYLIGHT_COLOR_CYAN;
	if(isBusyLight)
	{
		mdl.AudioByte = BUSYLIGHT_MEDIA(kull_m_string_args_byName(argc, argv, L"sound", NULL, NULL) ? BUSYLIGHT_MEDIA_SOUND_OPENOFFICE : BUSYLIGHT_MEDIA_JINGLE_IM2, BUSYLIGHT_MEDIA_VOLUME_4_MEDIUM);
		if(kull_m_string_args_byName(argc, argv, L"color", &szColor, NULL))
		{
			dwColor = wcstoul(szColor, NULL, 0);
			mdl.color.red   = (BYTE) ((dwColor & 0x00ff0000) >> 16);
			mdl.color.green = (BYTE) ((dwColor & 0x0000ff00) >> 8);
			mdl.color.blue  = (BYTE) (dwColor & 0x000000ff);
		}
		kull_m_busylight_request_send(kuhl_m_busylight_devices, &mdl, 1, TRUE);
	}
	else PRINT_ERROR(L"No BusyLight\n");
	return STATUS_SUCCESS;
}

BUSYLIGHT_COLOR adaptColor(PCBUSYLIGHT_COLOR color, BYTE percent)
{
	BUSYLIGHT_COLOR rColor = {
		(BYTE) (((DWORD) color->red * percent) / 100),
		(BYTE) (((DWORD) color->green * percent) / 100),
		(BYTE) (((DWORD) color->blue * percent) / 100)
	};
	if(!rColor.red && percent && color->red)
		rColor.red = 1;
	if(!rColor.green && percent && color->green)
		rColor.green = 1;
	if(!rColor.blue && percent && color->blue)
		rColor.blue = 1;
	return rColor;
}

DWORD WINAPI kuhl_m_busylight_gradientThread(LPVOID lpThreadParameter)
{
	PBUSYLIGHT_DEVICE device = (PBUSYLIGHT_DEVICE) lpThreadParameter;
	BUSYLIGHT_COMMAND_STEP mdl = {0, 1, {100, 0, 0}, 1, 0, BUSYLIGHT_MEDIA_MUTE};
	PBYTE toInc = &mdl.color.green, toDec = NULL;
	BYTE step = 10;
	while(device && device->hWorkerThread && device->dWorkerThread && device->hBusy)
	{
		if(kull_m_busylight_request_send(device, &mdl, 1, FALSE))
		{
			if(toInc)
			{
				*toInc += step;
				if(*toInc >= 100)
				{
					if(toInc == &mdl.color.green)
						toDec = &mdl.color.red;
					else if(toInc == &mdl.color.blue)
						toDec = &mdl.color.green;
					else if(toInc == &mdl.color.red)
						toDec = &mdl.color.blue;
					toInc = NULL;
				}
			}
			else if(toDec)
			{
				*toDec -= step;
				if(!*toDec)
				{
					if(toDec == &mdl.color.green)
						toInc = &mdl.color.red;
					else if(toDec == &mdl.color.blue)
						toInc = &mdl.color.green;
					else if(toDec == &mdl.color.red)
						toInc = &mdl.color.blue;
					toDec = NULL;
				}
			}
			Sleep(device->dWorkerThread);
		}
		else
		{
			CloseHandle(device->hBusy);
			device->hBusy = NULL;
			device->dWorkerThread = 0;
			device->hWorkerThread = NULL;
			break;
		}
	};
	return ERROR_SUCCESS;
}

NTSTATUS kuhl_m_busylight_test(int argc, wchar_t * argv[])
{
	PBUSYLIGHT_DEVICE cur;
	BOOL all = TRUE;
	for(cur = kuhl_m_busylight_devices; cur; cur = all ? cur->next : NULL)
	{
		cur->dWorkerThread = 100;
		cur->hWorkerThread = CreateThread(NULL, 0, kuhl_m_busylight_gradientThread, cur, 0, NULL); 
	}
	return STATUS_SUCCESS;
}