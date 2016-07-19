/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_rpc_ms-pac.h"

BOOL kuhl_m_pac_DecodeValidationInformation(PVOID data, DWORD size, PKERB_VALIDATION_INFO *pObject);
void kuhl_m_pac_FreeValidationInformation(PKERB_VALIDATION_INFO *pObject);
BOOL kuhl_m_pac_EncodeValidationInformation(PKERB_VALIDATION_INFO pObject, PVOID *data, DWORD *size);