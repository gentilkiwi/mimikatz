/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_string.h"

#define IOCTL_CCID_ESCAPE SCARD_CTL_CODE(3500)

#define ACR_MAX_LEN					255

typedef struct _KULL_M_ACR_COMM {
	//SCARDCONTEXT hContext;
	SCARDHANDLE hCard;
	BOOL withoutCard;
	LPVOID suppdata;
	BOOL descr;
} KULL_M_ACR_COMM, *PKULL_M_ACR_COMM;

BOOL kull_m_acr_init(SCARDCONTEXT hContext, LPCWSTR szReaderName, BOOL withoutCard, LPVOID suppdata, BOOL descr, PKULL_M_ACR_COMM comm);
void kull_m_acr_finish(PKULL_M_ACR_COMM comm);
BOOL kull_m_arc_sendrecv(PKULL_M_ACR_COMM comm, const BYTE *pbData, const UINT16 cbData, BYTE *pbResult, UINT16 *cbResult);
BOOL kull_m_acr_sendrecv_ins(PKULL_M_ACR_COMM comm, BYTE cla, BYTE ins, BYTE p1, BYTE p2, const BYTE *pbData, const UINT16 cbData, BYTE *pbResult, UINT16 *cbResult, BOOL noLe);
BOOL CALLBACK kull_m_arcr_SendRecvDirect(const BYTE *pbData, const UINT16 cbData, BYTE *pbResult, UINT16 *cbResult, LPVOID suppdata);