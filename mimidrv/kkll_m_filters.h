/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kkll_m_modules.h"

typedef enum _KIWI_MF_INDEX {
	CallbackOffset				= 0,
	CallbackPreOffset			= 1,
	CallbackPostOffset			= 2,
	CallbackVolumeNameOffset	= 3,

	MF_MAX						= 4,
} KIWI_MF_INDEX, *PKIWI_MF_INDEX;

NTSTATUS kkll_m_filters_list(PKIWI_BUFFER outBuffer);
NTSTATUS kkll_m_minifilters_list(PKIWI_BUFFER outBuffer);