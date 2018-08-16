/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_acr.h"

BOOL kull_m_acr_init(SCARDCONTEXT hContext, LPCWSTR szReaderName, BOOL withoutCard, LPVOID suppdata, BOOL descr, PKULL_M_ACR_COMM comm)
{
	BOOL status = FALSE;
	DWORD dwActiveProtocol;
	LONG scStatus;
	comm->hCard = 0;
	comm->withoutCard = withoutCard;
	comm->suppdata = suppdata;
	comm->descr = descr;
	scStatus = SCardConnect(hContext, szReaderName, withoutCard ? SCARD_SHARE_DIRECT : SCARD_SHARE_SHARED, withoutCard ? SCARD_PROTOCOL_UNDEFINED : SCARD_PROTOCOL_Tx, &comm->hCard, &dwActiveProtocol);
	if(!(status = (scStatus == SCARD_S_SUCCESS)))
		PRINT_ERROR(L"SCardConnect: 0x%08x\n", scStatus);
	return status;
}

void kull_m_acr_finish(PKULL_M_ACR_COMM comm)
{
	LONG scStatus;
	if(comm->hCard)
	{
		scStatus = SCardDisconnect(comm->hCard, SCARD_LEAVE_CARD);
		if(scStatus == SCARD_S_SUCCESS)
			comm->hCard = 0;
		else PRINT_ERROR(L"SCardDisconnect: 0x%08x\n", scStatus);
	}
}

BOOL kull_m_arc_sendrecv(PKULL_M_ACR_COMM comm, const BYTE *pbData, const UINT16 cbData, BYTE *pbResult, UINT16 *cbResult)
{
	BOOL status = FALSE;
	LONG scStatus;
	DWORD ret = *cbResult;

	if(comm->hCard)
	{
		if(cbData <= ACR_MAX_LEN)
		{
			if(comm->descr)
			{
				kprintf(L"ACR  > ");
				kull_m_string_wprintf_hex(pbData, cbData, 1);
				kprintf(L"\n");
			}
			scStatus = comm->withoutCard ?
				SCardControl(comm->hCard, IOCTL_CCID_ESCAPE, pbData, cbData, pbResult, *cbResult, &ret) :
				SCardTransmit(comm->hCard, NULL, pbData, cbData, NULL, pbResult, &ret);

			if(scStatus == SCARD_S_SUCCESS)
			{
				if(comm->descr)
				{
					kprintf(L"ACR  < ");
					kull_m_string_wprintf_hex(pbResult, ret, 1);
					kprintf(L"\n");
				}
				if(status = (ret <= *cbResult))
					*cbResult = (UINT16) ret;
			}
			else PRINT_ERROR(L"%s: 0x%08x\n", comm->withoutCard ? L"SCardControl" : L"SCardTransmit", scStatus);
		}
		else PRINT_ERROR(L"cbData = %hu / cbResult = %hu (max is %hu)\n", cbData, cbResult, ACR_MAX_LEN);
	}
	else PRINT_ERROR(L"No handle to Card\n");
	return status;
}

BOOL kull_m_acr_sendrecv_ins(PKULL_M_ACR_COMM comm, BYTE cla, BYTE ins, BYTE p1, BYTE p2, const BYTE *pbData, const UINT16 cbData, BYTE *pbResult, UINT16 *cbResult, BOOL noLe)
{
	BOOL status = FALSE;
	BYTE buffer[ACR_MAX_LEN], idx = 4;
	//BYTE max = sizeof(buffer) - idx -
	// CHECK SIZES !
	buffer[0] = cla;
	buffer[1] = ins;
	buffer[2] = p1;
	buffer[3] = p2;

	if(cbData)
	{
		buffer[idx++] = (BYTE) cbData;
		RtlCopyMemory(buffer + idx, pbData, cbData);
		idx += cbData;
	}
	if(!noLe && *cbResult)
		buffer[idx++] = (BYTE) *cbResult;
	return kull_m_arc_sendrecv(comm, buffer, idx, pbResult, cbResult);
}

BOOL CALLBACK kull_m_arcr_SendRecvDirect(const BYTE *pbData, const UINT16 cbData, BYTE *pbResult, UINT16 *cbResult, LPVOID suppdata)
{
	BOOL status = FALSE;
	BYTE buffer[ACR_MAX_LEN];
	UINT16 cbOut = *cbResult + 2;

	if(suppdata)
	{
		if(cbOut <= sizeof(buffer))
		{
			if(kull_m_acr_sendrecv_ins((PKULL_M_ACR_COMM) suppdata, 0xff, 0x00, 0x00, 0x00, pbData, cbData, buffer, &cbOut, TRUE))
			{
				if(cbOut >= 2)
				{
					if(*(PUINT16) (buffer + cbOut - 2) == 0x0090)
					{
						cbOut -= 2;
						if(status = (cbOut <= *cbResult))
						{
							RtlCopyMemory(pbResult, buffer, cbOut);
							*cbResult = cbOut;
						}
						else PRINT_ERROR(L"cbResult = %hu (data is %u)\n", *cbResult, cbOut);
					}
					else PRINT_ERROR(L"RET: %02x %02x\n", buffer[cbOut - 2], buffer[cbOut - 1]);
				}
				else PRINT_ERROR(L"cbRetBuffer = %hu (not long enough)\n", cbOut);
			}

		}
		else PRINT_ERROR(L"cbOut = %hu (max is %hu)\n", cbOut, sizeof(buffer));
	}
	else PRINT_ERROR(L"No suppdata (ACR_COMM)\n");
	return status;
}