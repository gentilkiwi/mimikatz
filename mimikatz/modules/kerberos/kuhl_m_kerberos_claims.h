/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../modules/rpc/kull_m_rpc_ms-claims.h"

PCLAIMS_SET kuhl_m_kerberos_claims_createFromString(LPCWCHAR string);
void kuhl_m_kerberos_claims_free(PCLAIMS_SET claimsSet);
void kuhl_m_kerberos_claims_displayClaimsSet(PCLAIMS_SET claimsSet);
BOOL kuhl_m_kerberos_claims_encode_ClaimsSet(PCLAIMS_SET claimsSet, PVOID *encoded, DWORD *dwEncoded);