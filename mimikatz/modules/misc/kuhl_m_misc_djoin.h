/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m_misc.h"
#include "../../../modules/kull_m_crypto.h"
#include "../../../modules/rpc/kull_m_rpc_ms-odj.h"

void kuhl_m_misc_djoin(int argc, wchar_t* argv[]);

void kuhl_m_misc_djoin_ODJ_PROVISION_DATA_descr(DWORD level, ULONG cbBlob, PBYTE pBlob);

void kuhl_m_misc_djoin_ODJ_WIN7BLOB_descr(DWORD level, ULONG cbBlob, PBYTE pBlob);
void kuhl_m_misc_djoin_OP_PACKAGE_descr(DWORD level, ULONG cbBlob, PBYTE pBlob);
void kuhl_m_misc_djoin_OP_PACKAGE_PART_COLLECTION_descr(DWORD level, ULONG cbBlob, PBYTE pBlob);
void kuhl_m_misc_djoin_OP_PACKAGE_PART_descr(DWORD level, POP_PACKAGE_PART pOpPackagePart);

void kuhl_m_misc_djoin_OP_JOINPROV2_PART_descr(DWORD level, ULONG cbBlob, PBYTE pBlob);
void kuhl_m_misc_djoin_OP_JOINPROV3_PART_descr(DWORD level, ULONG cbBlob, PBYTE pBlob);

void kuhl_m_misc_djoin_OP_CERT_PART_descr(DWORD level, ULONG cbBlob, PBYTE pBlob);
void kuhl_m_misc_djoin_OP_CERT_PFX_STORE_descr(DWORD level, POP_CERT_PFX_STORE pPfxStore);
void kuhl_m_misc_djoin_OP_CERT_SST_STORE_descr(DWORD level, POP_CERT_SST_STORE pSstStore);

void kuhl_m_misc_djoin_OP_POLICY_PART_descr(DWORD level, ULONG cbBlob, PBYTE pBlob);
void kuhl_m_misc_djoin_OP_POLICY_ELEMENT_LIST_descr(DWORD level, POP_POLICY_ELEMENT_LIST pElementList);
void kuhl_m_misc_djoin_OP_POLICY_ELEMENT_descr(DWORD level, POP_POLICY_ELEMENT pElement);