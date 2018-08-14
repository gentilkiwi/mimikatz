/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_acr.h"

const KUHL_M_C kuhl_m_c_acr[] = {
	{kuhl_m_acr_open,			L"open",		L""},
	{kuhl_m_acr_close,			L"close",		L""},
	
	{kuhl_m_acr_firmware,		L"firmware",		L""},
	{kuhl_m_acr_info,			L"info",		L""},
};

const KUHL_M kuhl_m_acr = {
	L"acr", L"ACR Module", NULL,
	ARRAYSIZE(kuhl_m_c_acr), kuhl_m_c_acr, kuhl_m_acr_init, kuhl_m_acr_clean
};

SCARDCONTEXT kuhl_m_acr_hContext;
KULL_M_ACR_COMM kuhl_m_acr_Comm;
KULL_M_PN532_COMM kuhl_m_acr_pn532Comm;

NTSTATUS kuhl_m_acr_init()
{
	kuhl_m_acr_hContext = 0;
	kuhl_m_acr_Comm.hCard = 0;
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_acr_clean()
{
	kuhl_m_acr_close(0, NULL);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_acr_open(int argc, wchar_t * argv[])
{
	LONG scStatus;
	BOOL isTrace = kull_m_string_args_byName(argc, argv, L"trace", NULL, NULL);

	if(!kuhl_m_acr_hContext)
	{
		scStatus = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &kuhl_m_acr_hContext);
		if(scStatus == SCARD_S_SUCCESS)
		{
			kprintf(L"Opening ACR  : ");
			if(kull_m_acr_init(kuhl_m_acr_hContext, L"ACS ACR122 0", TRUE, NULL, isTrace, &kuhl_m_acr_Comm))
			{
				kprintf(L"OK!\nOpening PN532: ");
				kull_m_pn532_init(kull_m_arcr_SendRecvDirect, &kuhl_m_acr_Comm, isTrace, &kuhl_m_acr_pn532Comm);
				kprintf(L"OK!\n");
			}
			else kuhl_m_acr_close(0, NULL);
		}
	}
	else PRINT_ERROR(L"Already opened, close it first\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_acr_close(int argc, wchar_t * argv[])
{
	kull_m_acr_finish(&kuhl_m_acr_Comm);
	if(kuhl_m_acr_hContext)
	{
		SCardReleaseContext(kuhl_m_acr_hContext);
		kuhl_m_acr_hContext = 0;
	}
	return STATUS_SUCCESS;
}


const PCWCHAR KUHL_M_ACR_FIRMWARE_PN532_SUPPORT[] = {L"ISO/IEC 14443 Type A", L"ISO/IEC 14443 Type B", L"ISO 18092"};
NTSTATUS kuhl_m_acr_firmware(int argc, wchar_t * argv[])
{
	BYTE acrFirmware[10];
	BYTE firmwareInfo[4], i;
	UINT16 wOut = sizeof(acrFirmware);

	if(kull_m_acr_sendrecv_ins(&kuhl_m_acr_Comm, 0xff, 0x00, 0x48, 0x00, NULL, 0, acrFirmware, &wOut, FALSE))
		kprintf(L"ACR firmware: %.*S\n", wOut, acrFirmware);
	
	if(kull_m_pn532_GetFirmware(&kuhl_m_acr_pn532Comm, firmwareInfo))
	{
		kprintf(L"PN532 chip\n version    : 0x%02x\n firmware   : %hhu.%hhu\n support    : ", firmwareInfo[0], firmwareInfo[1], firmwareInfo[2]);
		for(i = 0; i < 8; i++)
			if((firmwareInfo[3] >> i) & 1)
				kprintf(L"%s ; ", (i < ARRAYSIZE(KUHL_M_ACR_FIRMWARE_PN532_SUPPORT)) ? KUHL_M_ACR_FIRMWARE_PN532_SUPPORT[i] : L"RFU");
		kprintf(L"\n");
	}
	return STATUS_SUCCESS;
}

const PCWCHAR KUHL_M_ACR_PN532_BrTy[] = {
	L"ISO/IEC 14443 Type A - 106 kbps",
	L"FeliCa - 212 kbps",
	L"FeliCa - 424 kbps",
	L"ISO/IEC 14443 Type B - 106 kbps",
	L"Innovision Jewel - 106 kbps"
};
NTSTATUS kuhl_m_acr_info(int argc, wchar_t * argv[])
{
	BYTE i, NbTg;
	PPN532_TARGET pTargets;

	kull_m_pn532_InRelease(&kuhl_m_acr_pn532Comm, 0);
	if(kull_m_pn532_InListPassiveTarget(&kuhl_m_acr_pn532Comm, 2, 0 /* Type A */, NULL, 0, &NbTg, &pTargets))
	{
		for(i = 0; i < NbTg; i++)
		{
			kprintf(L"\nTarget: %hhu (0x%02x - %s)\n", pTargets[i].Tg, pTargets[i].BrTy, (pTargets[i].BrTy < ARRAYSIZE(KUHL_M_ACR_PN532_BrTy)) ? KUHL_M_ACR_PN532_BrTy[pTargets[i].BrTy] : L"?");
			switch(pTargets[i].BrTy)
			{
			case 0:
				kprintf(L"  SENS_RES: %02x %02x\n  SEL_RES : %02x\n    UID %scomplete\n    PICC %scompliant with ISO/IEC 14443-4\n    PICC %scompliant with ISO/IEC 18092 (NFC)\n",
					((PBYTE) &pTargets[i].Target.TypeA.SENS_RES)[0], ((PBYTE) &pTargets[i].Target.TypeA.SENS_RES)[1], pTargets[i].Target.TypeA.SEL_RES, (pTargets[i].Target.TypeA.SEL_RES & 0x04) ? L"NOT " : L"", (pTargets[i].Target.TypeA.SEL_RES & 0x20) ? L"" : L"NOT ", (pTargets[i].Target.TypeA.SEL_RES & 0x40) ? L"" : L"NOT ");
				if(pTargets[i].Target.TypeA.NFCIDLength && pTargets[i].Target.TypeA.NFCID1)
				{
					kprintf(L"  NFCID1  : ");
					kull_m_string_wprintf_hex(pTargets[i].Target.TypeA.NFCID1, pTargets[i].Target.TypeA.NFCIDLength, 1);
					kprintf(L"\n");
				}
				if(pTargets[i].Target.TypeA.ATSLength && pTargets[i].Target.TypeA.ATS)
				{
					kprintf(L"  ATS     : ");
					kull_m_string_wprintf_hex(pTargets[i].Target.TypeA.ATS, pTargets[i].Target.TypeA.ATSLength, 1);
					kprintf(L"\n");
				}
				break;
			default:
				PRINT_ERROR(L"Only BrTy = 0 (TypeA) at this time\n");
			}
		}
		LocalFree(pTargets);
	}
	kull_m_pn532_InRelease(&kuhl_m_acr_pn532Comm, 0);
	return STATUS_SUCCESS;
}