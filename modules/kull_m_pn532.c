/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_pn532.h"

void kull_m_pn532_init(PKULL_M_PN532_COMM_CALLBACK communicator, LPVOID suppdata, BOOL descr, PKULL_M_PN532_COMM comm)
{
	comm->communicator = communicator;
	comm->suppdata = suppdata;
	comm->descr = descr;
}

BOOL kull_m_pn532_sendrecv(PKULL_M_PN532_COMM comm, const BYTE pn532_cmd, const BYTE *pbData, const UINT16 cbData, BYTE *pbResult, UINT16 *cbResult)
{
	BOOL status = FALSE;
	BYTE buffer[PN532_MAX_LEN];
	UINT16 cbIn = cbData + 2, cbOut = *cbResult + 2;

	if(comm->communicator)
	{
	if((cbIn <= sizeof(buffer)) && (cbOut <= sizeof(buffer)))
	{
		if(!(pn532_cmd & 1))
		{
			buffer[0] = PN532_Host_PN532;
			buffer[1] = pn532_cmd;
			if(cbData)
				RtlCopyMemory(buffer + 2, pbData, cbData);
			if(comm->descr)
			{
				kprintf(L"PN532> ");
				kull_m_string_wprintf_hex(buffer, cbIn, 1);
				kprintf(L"\n");
			}
			if(comm->communicator(buffer, cbIn, buffer, &cbOut, comm->suppdata))
			{
				if(comm->descr)
				{
					kprintf(L"PN532< ");
					kull_m_string_wprintf_hex(buffer, cbOut, 1);
					kprintf(L"\n");
				}

				if(cbOut >= 2)
				{
					*cbResult = cbOut - 2;
					if(buffer[0] == PN532_PN532_Host)
					{
						if(status = (buffer[1] == pn532_cmd + 1))
							RtlCopyMemory(pbResult, buffer + 2, *cbResult);
						else PRINT_ERROR(L"Recv CC is not valid: 0x%02x, expected 0x%02x\n", buffer[1], pn532_cmd + 1);
					}
					else PRINT_ERROR(L"Recv TFI is not valid: 0x%02x, expected 0x%02x\n", buffer[0], PN532_PN532_Host);
				}
				else PRINT_ERROR(L"cbOut = %hu (not long enough)\n", cbOut);
			}
		}
		else PRINT_ERROR(L"pn532_cmd is not even (0x%02x)\n", pn532_cmd);
	}
	else PRINT_ERROR(L"cbIn = %hu / cbOut = %hu (max is %hu)\n", cbIn, cbOut, sizeof(buffer));
	}
	else PRINT_ERROR(L"No communicator\n");
	return status;
}


BOOL kull_m_pn532_Diagnose(PKULL_M_PN532_COMM comm /*, ...*/)
{
	BOOL status = FALSE;
	return status;
}

BOOL kull_m_pn532_GetFirmware(PKULL_M_PN532_COMM comm, BYTE firmwareInfo[4])
{
	BOOL status = FALSE;
	UINT16 wRet = 4;
	if(kull_m_pn532_sendrecv(comm, PN532_CMD_GetFirmwareVersion, NULL, 0, firmwareInfo, &wRet))
		status = (wRet == 4);
	return status;
}

BOOL kull_m_pn532_GetGeneralStatus(PKULL_M_PN532_COMM comm /*, ...*/)
{
	BOOL status = FALSE;
	BYTE ret[3 + 4 + 4 + 1];
	UINT16 wRet = sizeof(ret);
	kull_m_pn532_sendrecv(comm, PN532_CMD_GetGeneralStatus, NULL, 0, ret, &wRet);
	return status;
}

BOOL kull_m_pn532_InListPassiveTarget(PKULL_M_PN532_COMM comm, const BYTE MaxTg, const BYTE BrTy, const BYTE *pbInit, UINT16 cbInit, BYTE *NbTg, PPN532_TARGET *Targets)
{
	BOOL status = FALSE;
	BYTE dataIn[2 + 12] = {MaxTg, BrTy}, dataOut[PN532_MAX_LEN - 14], i, *ptr;
	UINT16 wOut = sizeof(dataOut);

	if(BrTy == 0)
	{
		if(cbInit <= sizeof(dataIn) - 2)
		{
			if(cbInit)
				RtlCopyMemory(dataIn + 2, pbInit, cbInit);
			if(kull_m_pn532_sendrecv(comm, PN532_CMD_InListPassiveTarget, dataIn, cbInit + 2, dataOut, &wOut))
			{
				*NbTg = dataOut[0];
				if(*Targets = (PPN532_TARGET) LocalAlloc(LPTR, *NbTg * sizeof(PN532_TARGET) + wOut - 1)) // not efficient, but...
				{
					ptr = (PBYTE) *Targets + *NbTg * sizeof(PN532_TARGET);
					RtlCopyMemory(ptr, dataOut + 1, wOut - 1);

					for(i = 0; i < dataOut[0]; i++)
					{
						(*Targets)[i].Tg = *ptr++;
						(*Targets)[i].BrTy = BrTy;
						switch(BrTy)
						{
						case 0:
							(*Targets)[i].Target.TypeA.SENS_RES = *(PUINT16) ptr;
							ptr += sizeof((*Targets)[i].Target.TypeA.SENS_RES);
							(*Targets)[i].Target.TypeA.SEL_RES = *ptr++;
							(*Targets)[i].Target.TypeA.NFCIDLength = *ptr++;
							if((*Targets)[i].Target.TypeA.NFCIDLength)
							{
								(*Targets)[i].Target.TypeA.NFCID1 = ptr;
								ptr += (*Targets)[i].Target.TypeA.NFCIDLength;
							}
							if((*Targets)[i].Target.TypeA.SEL_RES & 0x20)
							{
								(*Targets)[i].Target.TypeA.ATSLength = *ptr++;
								if((*Targets)[i].Target.TypeA.ATSLength)
								{
									(*Targets)[i].Target.TypeA.ATS = ptr;
									ptr += (*Targets)[i].Target.TypeA.ATSLength;
								}
							}
							break;
						}
					}
					status = TRUE;
				}
			}
		}
		else PRINT_ERROR(L"cbInit is: %hu, max is %hu\n", cbInit, sizeof(dataIn) - 2);
	}
	else PRINT_ERROR(L"Only BrTy = 0 (TypeA) at this time\n");
	return status;
}

BOOL kull_m_pn532_InRelease(PKULL_M_PN532_COMM comm, const BYTE Tg)
{
	BOOL status = FALSE;
	BYTE ret;
	UINT16 wOut = sizeof(ret);

			if(kull_m_pn532_sendrecv(comm, PN532_CMD_InRelease, &Tg, sizeof(Tg), &ret, &wOut))
			{
	
			}
	return status;
}


const LPCWCHAR TgInitMode[] = {L"Mifare", L"Active mode", L"FeliCa"};
const UINT16 TgInitBaudrate[] = {106, 212, 424};
void kull_m_pn532_TgInitAsTarget(PKULL_M_PN532_COMM comm)
{
	BYTE dataIn[] = {	0x00,
						0x04, 0x00,		0x11, 0x22, 0x33,	0x08,
						
						0x01, 0xfe, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
						0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
						0xff, 0xff,

						0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
						0x00,
						0x00,
	};
	BYTE dataOut[PN532_MAX_LEN - 2];
	UINT16 wOut = sizeof(dataOut);

	if(kull_m_pn532_sendrecv(comm, PN532_CMD_TgInitAsTarget, dataIn, sizeof(dataIn), dataOut, &wOut))
	{
		kull_m_pn532_TgResponseToInitiator(comm);
		if(wOut)
		{
			kprintf(L"Framing Type        : %s\n", ((dataOut[0] & 3) < 3) ? TgInitMode[(dataOut[0] & 3)] : L"?");
			kprintf(L"DEP                 : %s\n", (dataOut[0] & 0x04) ? L"yes": L"no");
			kprintf(L"ISO/IEC 14443-4 PICC: %s\n", (dataOut[0] & 0x08) ? L"yes": L"no");
			kprintf(L"Baudrate            : %hu\n", (((dataOut[0] & 0x70) >> 4) < 3) ? TgInitBaudrate[((dataOut[0] & 0x70) >> 4)] : 0);
			if(wOut > 1)
			{
				kprintf(L"InitiatorCommand    : ");
				kull_m_string_wprintf_hex(dataOut + 1, wOut - 1, 1);
				kprintf(L"\n");
			}
		}
	}
}

void kull_m_pn532_TgGetInitiatorCommand(PKULL_M_PN532_COMM comm)
{
	BYTE dataOut[PN532_MAX_LEN - 2];
	UINT16 wOut = sizeof(dataOut);
	kprintf(L">> " TEXT(__FUNCTION__) L"\n");
	kull_m_pn532_sendrecv(comm, PN532_CMD_TgGetInitiatorCommand, NULL, 0, dataOut, &wOut);
}

void kull_m_pn532_TgResponseToInitiator(PKULL_M_PN532_COMM comm)
{
	BYTE dataIn[3] = {0x01, 0x20, 0x01};
	BYTE dataOut[PN532_MAX_LEN - 2];
	UINT16 wOut = sizeof(dataOut);

	kull_m_pn532_sendrecv(comm, PN532_CMD_TgResponseToInitiator, dataIn, sizeof(dataIn), dataOut, &wOut);
}




void kull_m_pn532_TgGetData(PKULL_M_PN532_COMM comm)
{
	BYTE dataOut[PN532_MAX_LEN - 2];
	UINT16 wOut = sizeof(dataOut);
	kprintf(L">> " TEXT(__FUNCTION__) L"\n");
	kull_m_pn532_sendrecv(comm, PN532_CMD_TgGetData, NULL, 0, dataOut, &wOut);
}