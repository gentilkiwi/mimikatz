/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sr98.h"

const KUHL_M_C kuhl_m_c_sr98[] = {
	{kuhl_m_sr98_beep,		L"beep",	NULL},
	{kuhl_m_sr98_raw,		L"raw",		NULL},
	{kuhl_m_sr98_b0,		L"b0",		NULL},
	{kuhl_m_sr98_list,		L"list",	NULL},
	{kuhl_m_sr98_hid26,		L"hid",		NULL},
	{kuhl_m_sr98_em4100,	L"em4100",	NULL},
};
const KUHL_M kuhl_m_sr98 = {
	L"sr98", L"RF module for SR98 device and T5577 target", NULL,
	ARRAYSIZE(kuhl_m_c_sr98), kuhl_m_c_sr98, NULL, NULL
};

NTSTATUS kuhl_m_sr98_beep(int argc, wchar_t * argv[])
{
	PSR98_DEVICE devices, cur;
	ULONG count, duration = 9;
	if(argc)
		duration = wcstoul(argv[0], NULL, 0);
	if(sr98_devices_get(&devices, &count))
	{
		for(cur = devices; cur; cur = cur->next)
			sr98_beep(cur->hDevice, (BYTE) duration);
		sr98_devices_free(devices);
	}
	else PRINT_ERROR(L"No device found\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sr98_raw(int argc, wchar_t * argv[])
{
	KUHL_M_SR98_RAW_BLOCK blocks[8];
	PSR98_DEVICE devices;
	ULONG count;
	PCWCHAR szBlock;
	UCHAR i;
	BOOLEAN isBlock = FALSE, isWipe = kull_m_string_args_byName(argc, argv, L"wipe", NULL, NULL);
	
	if(isBlock |= (blocks[0].toProg = kull_m_string_args_byName(argc, argv, L"b0", &szBlock, NULL)))
	{
		blocks[0].data = wcstoul(szBlock, NULL, 0);
		kuhl_m_sr98_b0_descr(blocks[0].data);
	}
	if(isBlock |= (blocks[1].toProg = kull_m_string_args_byName(argc, argv, L"b1", &szBlock, NULL)))
		blocks[1].data = wcstoul(szBlock, NULL, 0);
	if(isBlock |= (blocks[2].toProg = kull_m_string_args_byName(argc, argv, L"b2", &szBlock, NULL)))
		blocks[2].data = wcstoul(szBlock, NULL, 0);
	if(isBlock |= (blocks[3].toProg = kull_m_string_args_byName(argc, argv, L"b3", &szBlock, NULL)))
		blocks[3].data = wcstoul(szBlock, NULL, 0);
	if(isBlock |= (blocks[4].toProg = kull_m_string_args_byName(argc, argv, L"b4", &szBlock, NULL)))
		blocks[4].data = wcstoul(szBlock, NULL, 0);
	if(isBlock |= (blocks[5].toProg = kull_m_string_args_byName(argc, argv, L"b5", &szBlock, NULL)))
		blocks[5].data = wcstoul(szBlock, NULL, 0);
	if(isBlock |= (blocks[6].toProg = kull_m_string_args_byName(argc, argv, L"b6", &szBlock, NULL)))
		blocks[6].data = wcstoul(szBlock, NULL, 0);
	if(isBlock |= (blocks[7].toProg = kull_m_string_args_byName(argc, argv, L"b7", &szBlock, NULL)))
	{
		blocks[7].data = wcstoul(szBlock, NULL, 0);
		if(blocks[0].toProg && (blocks[0].data & 0x10)) // check PWD
			kprintf(L"\n> blocks[0] indicates PWD, blocks[7] will be the password (0x%08x)\n", blocks[7].data);
	}

	if(isBlock || isWipe)
	{
		if(sr98_devices_get(&devices, &count))
		{
			if(count == 1)
			{
				if(isWipe)
				{
					kprintf(L"\n * Wipe T5577 tag...\n");
					sr98_t5577_wipe(devices->hDevice, TRUE);
				}
				if(isBlock)
				{
					kprintf(L"\n * Write operations...\n");
					for(i = 0; i < ARRAYSIZE(blocks); i++)
					{
						if(blocks[i].toProg)
						{
							kprintf(L"   [%hhu] 0x%08x\n", i, blocks[i].data);
							sr98_t5577_write_block(devices->hDevice, 0, i, _byteswap_ulong(blocks[i].data), FALSE, 0);
						}
					}
				}
			}
			else PRINT_ERROR(L"Reader device is not unique (%u)\n", count);
			sr98_devices_free(devices);
		}
	}
	else PRINT_ERROR(L"No operation\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sr98_b0(int argc, wchar_t * argv[])
{
	PCWCHAR szB0;
	if(argc)
	{
		if(!kull_m_string_args_byName(argc, argv, L"b0", &szB0, NULL))
			szB0 = argv[0];
		kuhl_m_sr98_b0_descr(wcstoul(szB0, NULL, 0));
	}
	else PRINT_ERROR(L"[/b0:]0x........ argument is needed\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sr98_list(int argc, wchar_t * argv[])
{
	PSR98_DEVICE devices, cur;
	ULONG count;
	if(sr98_devices_get(&devices, &count))
	{
		for(cur = devices; cur; cur = cur->next)
			kprintf(L"\n[%3u] %s\n  Vendor: 0x%04x, Product: 0x%04x, Version: 0x%04x\n", cur->id, cur->DevicePath, cur->hidAttributes.VendorID, cur->hidAttributes.ProductID, cur->hidAttributes.VersionNumber);
		sr98_devices_free(devices);
	}
	else PRINT_ERROR(L"No device found\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sr98_hid26(int argc, wchar_t * argv[])
{
	PCWCHAR szNumber;
	UCHAR FacilityCode;
	USHORT CardNumber;
	ULONG Number, blocks[4];
	ULONGLONG Wiegand;

	kprintf(L"\nHID (26 bits) encoder\n\n");
	if(kull_m_string_args_byName(argc, argv, L"fc", &szNumber, NULL))
	{
		Number = wcstoul(szNumber, NULL, 0);
		if(Number < 0x100)
		{
			FacilityCode = (UCHAR) Number;
			kprintf(L" * FacilityCode: %hhu (0x%02x)\n", FacilityCode, FacilityCode);
			if(kull_m_string_args_byName(argc, argv, L"cn", &szNumber, NULL))
			{
				Number = wcstoul(szNumber, NULL, 0);
				if(Number < 0x10000)
				{
					CardNumber = (USHORT) Number;
					kprintf(L" * CardNumber  : %hu (0x%04x)\n", CardNumber, CardNumber);
					kuhl_m_sr98_hid26_blocks(blocks, FacilityCode, CardNumber, &Wiegand);
					kprintf(L" * Wiegand     : %I64u (0x%I64x)\n", Wiegand, Wiegand);
					kuhl_m_sr98_sendBlocks(blocks, ARRAYSIZE(blocks));
				}
				else PRINT_ERROR(L"CardNumber (/cn) must be in the [0;65535] range - it was %u (0x%08x)", Number, Number);
			}
			else PRINT_ERROR(L"CardNumber (/cn) is needed\n");
		}
		else PRINT_ERROR(L"FacilityCode (/fc) must be in the [0;255] range - it was %u (0x%08x)", Number, Number);
	}
	else PRINT_ERROR(L"FacilityCode (/fc) is needed\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sr98_em4100(int argc, wchar_t * argv[])
{
	PCWCHAR szNumber;
	ULONGLONG Number;
	ULONG blocks[3];

	kprintf(L"\nEM4100 encoder\n\n");
	if(kull_m_string_args_byName(argc, argv, L"id", &szNumber, NULL))
	{
		Number = _wcstoui64(szNumber, NULL, 0);
		if((Number < 0x10000000000))
		{
			kprintf(L" * Tag ID      : %I64u (0x%I64x)\n", Number, Number);
			kuhl_m_sr98_em4100_blocks(blocks, Number);
			kprintf(L" * EM4100      : 0x%08x%08x\n", blocks[1], blocks[2]);
			kuhl_m_sr98_sendBlocks(blocks, ARRAYSIZE(blocks));
		}
		else PRINT_ERROR(L"Tag Id (/id) must be in the [0;255] range - it was %I64u (0x%I64x)", Number, Number);
	}
	else PRINT_ERROR(L"Tag Id (/id) is needed\n");
	return STATUS_SUCCESS;
}

BOOL kuhl_m_sr98_sendBlocks(ULONG *blocks, UCHAR nb)
{
	BOOL status = FALSE;
	PSR98_DEVICE devices;
	ULONG count;
	UCHAR i;
	if(sr98_devices_get(&devices, &count))
	{
		if(count == 1)
		{
			kprintf(L" * T5577 blocks:\n");
			for(i = 0; i < nb; i++)
				kprintf(L"   [%hhu] 0x%08x\n", i, blocks[i]);
			kprintf(L" * Write operations...\n");
			for(i = 0, status = TRUE; (i < nb) && status; i++)
				status &= sr98_t5577_write_block(devices->hDevice, 0, i, _byteswap_ulong(blocks[i]), FALSE, 0);
		}
		else PRINT_ERROR(L"Reader device is not unique (%u)\n", count);
		sr98_devices_free(devices);
	}
	return status;
}

const UCHAR kuhl_m_sr98_b0_descr_basic_rf[] = {8, 16, 32, 40, 50, 64, 100, 128};
const PCWCHAR kuhl_m_sr98_b0_descr_pskcf_rf[] = {L"RF/2", L"RF/4", L"RF/8", L"Reserved"};
void kuhl_m_sr98_b0_descr(ULONG b0)
{
	UCHAR XMode = (b0 >> 17) & 1, n = (b0 >> 28) & 0xf, i;
	BOOLEAN isMasterKey69 = (n == 6) || (n == 9), isExtended = XMode && isMasterKey69;
	PCWCHAR pModulation;

	kprintf(L"\nT5577 Config block\n==================\nBlock[0]             : 0x%08x\nTest mode            : %s\nExtended mode        : %s\n\nMaster Key           : %hhu (0x%1x)\n", b0, (n == 6) ? L"DISABLED" : L"ENABLED", isExtended ? L"YES" : L"NO", n, n);
	if(isExtended)
	{
		if((b0 >> 24) & 0xf)
			PRINT_ERROR(L"Invalid configuration bits in [5-8]\n");
		n = ((b0 >> 18) & 0x3f);
		kprintf(L"Data Bit Rate        : RF/%hhu (%hhu)\n", 2*n+2, n);
	}
	else
	{
		if((b0 >> 21) & 0x7f)
			PRINT_ERROR(L"Invalid configuration bits in [5-11]\n");
		n = (b0 >> 18) & 0x7;
		kprintf(L"Data Bit Rate        : RF/%hhu (%hhu)\n", kuhl_m_sr98_b0_descr_basic_rf[n], n);
	}
	kprintf(L"X-Mode               : %s\n", XMode ? L"YES" : L"NO");
	if(XMode && !isExtended)
		PRINT_ERROR(L"X-mode bit is set, but not in Extended mode (because of the Master Key)\n");
	n = (b0 >> 12) & 0x1f;
	switch(n)
	{
	case 0: pModulation = L"Direct"; break;
	case 1: pModulation = L"PSK1"; break;
	case 2: pModulation = L"PSK2"; break;
	case 3: pModulation = L"PSK3"; break;
	case 4: pModulation = L"FSK1"; break;
	case 5: pModulation = L"FSK2"; break;
	case 6: pModulation = L"FSK1a"; break;
	case 7: pModulation = L"FSK2a"; break;
	case 8: pModulation = L"Manchester"; break;
	case 16: pModulation = L"Bi-phase"; break;
	case 24: pModulation = L"Differential bi-phase"; break;
	default: pModulation = L"INVALID";
	}
	kprintf(L"Modulation           : %s (%hhu)\n", pModulation, n);
	if(((n == 24) && !isExtended) || (((n == 6) || (n == 7)) && isExtended))
		PRINT_ERROR(L"Invalid Modulation in this mode\n");
	i = (b0 >> 10) & 0x3;
	n = (b0 >> 5) & 0x7;
	kprintf(L"PSK Clock Frequency  : %s (%hhu)\nAnswer On Request    : %s\nOne Time Password    : %s\nMaxblock             : %hhu ( ", kuhl_m_sr98_b0_descr_pskcf_rf[i], i, ((b0 >> 9) & 1) ? L"YES" : L"NO", ((b0 >> 8) & 1) ? L"YES" : L"NO", n);
	for(i = 1; i <= n; i++)
		kprintf(L"B[%hhu] ", i);
	i = ((b0 >> 4) & 1);
	kprintf(L")\nPassword             : %s\n", i ? L"YES" : L"NO");
	if(i && (n == 7))
		PRINT_ERROR(L"Password can be transmitted on the wire because of Maxblock\n");
	if(isExtended)
		kprintf(L"Sequence Start Marker: %s\nFast Downlink        : %s\nInverse Data         : %s\n", ((b0 >> 3) & 1) ? L"YES" : L"NO", ((b0 >> 2) & 1) ? L"YES" : L"NO", ((b0 >> 1) & 1) ? L"YES" : L"NO");
	else
	{
		kprintf(L"Sequence Terminator  : %s\n", ((b0 >> 3) & 1) ? L"YES" : L"NO");
		if((b0 >> 1) & 0x3)
			PRINT_ERROR(L"Invalid configuration bits in [30-31]\n");
	}
	n = b0 & 1;
	kprintf(L"Init Delay           : %s\n", n ? L"YES" : L"NO");
	if(n & !isMasterKey69)
		PRINT_ERROR(L"Init Delay bit is set, but was disabled (because of the Master Key)\n");
}

UCHAR kuhl_m_sr98_hid26_Manchester_4bits(UCHAR data4)
{
	UCHAR i, r;
	for(i = r = 0; i < 4; i++)
		r |= (1 << ((data4 >> i) & 1)) << (i * 2);
	return r;
}

void kuhl_m_sr98_hid26_blocks(ULONG blocks[4], UCHAR FacilityCode, USHORT CardNumber, PULONGLONG pWiegand)
{
	UCHAR i, s1, s2;
	ULONGLONG Wiegand = 0x2004000000 | (FacilityCode << 17) | (CardNumber << 1);
	for(i = s1 = s2 = 0; i < 12; i++)
	{
		s1 ^= (Wiegand >> (i + 12 + 1)) & 1;
		s2 ^= (Wiegand >> (i + 1)) & 1;
	}
	Wiegand |= ((s1 & 1) << 25) | (!s2 & 1);
	if(pWiegand)
		*pWiegand = Wiegand;
	blocks[0] = 0x90625062; // RF/50, FSK2, [1-3], inverted
	blocks[1] = (0x1d << 24) | (kuhl_m_sr98_hid26_Manchester_4bits((UCHAR) (Wiegand >> 40)) << 16) | (kuhl_m_sr98_hid26_Manchester_4bits((UCHAR) (Wiegand >> 36)) << 8) | kuhl_m_sr98_hid26_Manchester_4bits((UCHAR) (Wiegand >> 32));
	blocks[2] = (kuhl_m_sr98_hid26_Manchester_4bits((UCHAR) (Wiegand >> 28)) << 24) | (kuhl_m_sr98_hid26_Manchester_4bits((UCHAR) (Wiegand >> 24)) << 16) | (kuhl_m_sr98_hid26_Manchester_4bits((UCHAR) (Wiegand >> 20)) << 8) | kuhl_m_sr98_hid26_Manchester_4bits((UCHAR) (Wiegand >> 16));
	blocks[3] = (kuhl_m_sr98_hid26_Manchester_4bits((UCHAR) (Wiegand >> 12)) << 24) | (kuhl_m_sr98_hid26_Manchester_4bits((UCHAR) (Wiegand >> 8)) << 16) | (kuhl_m_sr98_hid26_Manchester_4bits((UCHAR) (Wiegand >> 4)) << 8) | kuhl_m_sr98_hid26_Manchester_4bits((UCHAR) (Wiegand));
}

void kuhl_m_sr98_em4100_blocks(ULONG blocks[3], ULONGLONG CardNumber)
{
	ULONGLONG tmpData = 0xff80000000000000;
	UCHAR data, i, j, tmp, p, pl[4] = {0};
	for(i = 0; i < 10; i++)
	{
		data = (CardNumber >> (36 - (i * 4))) & 0xf;
		for(p = j = 0; j < 4; j++)
		{
			tmp = (data >> j) & 1;
			p ^= tmp;
			pl[j] ^= tmp;
		}
		tmpData |= (ULONGLONG) data << (51 - (i * 5)) | (ULONGLONG) p << (50 - (i * 5));
	}
	tmpData |= pl[3] << 4 | pl[2] << 3 | pl[1] << 2 | pl[0] << 1;
	blocks[0] = 0x00148040; // RF/64, Manchester, [1-2]
	blocks[1] = (ULONG) (tmpData >> 32);
	blocks[2] = (ULONG) tmpData;
}