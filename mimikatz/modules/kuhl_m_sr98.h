/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "../../modules/kull_m_sr98.h"

const KUHL_M kuhl_m_sr98;

NTSTATUS kuhl_m_sr98_beep(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sr98_raw(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sr98_b0(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sr98_list(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sr98_hid26(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_sr98_em4100(int argc, wchar_t * argv[]);

typedef struct _KUHL_M_SR98_RAW_BLOCK {
	UCHAR toProg;
	ULONG data;
} KUHL_M_SR98_RAW_BLOCK, *PKUHL_M_SR98_RAW_BLOCK;

BOOL kuhl_m_sr98_sendBlocks(ULONG *blocks, UCHAR nb);
void kuhl_m_sr98_b0_descr(ULONG b0);

UCHAR kuhl_m_sr98_hid26_Manchester_4bits(UCHAR data4);
void kuhl_m_sr98_hid26_blocks(ULONG blocks[4], UCHAR FacilityCode, USHORT CardNumber, PULONGLONG pWiegand);

void kuhl_m_sr98_em4100_blocks(ULONG blocks[3], ULONGLONG CardNumber);