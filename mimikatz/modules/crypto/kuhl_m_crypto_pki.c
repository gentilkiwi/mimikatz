/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_crypto_pki.h"

BOOL kuhl_m_crypto_c_sc_auth_quickEncode(__in LPCSTR lpszStructType, __in const void *pvStructInfo, PDATA_BLOB data)
{
	BOOL status = FALSE;
	data->cbData = 0;
	data->pbData = NULL;
	if(CryptEncodeObject(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, lpszStructType, pvStructInfo, NULL, &data->cbData))
	{
		if(data->pbData = (PBYTE) LocalAlloc(LPTR, data->cbData))
		{
			if(!(status = CryptEncodeObject(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, lpszStructType, pvStructInfo, data->pbData, &data->cbData)))
			{
				PRINT_ERROR_AUTO(L"CryptEncodeObject (data)");
				LocalFree(data->pbData);
			}
		}
	}
	else PRINT_ERROR_AUTO(L"CryptEncodeObject (init)");
	return status;
}

BOOL kuhl_m_crypto_c_sc_auth_Ext_AltUPN(PCERT_EXTENSION pCertExtension, LPCWSTR upn)
{
	BOOL status = FALSE;
	CERT_NAME_VALUE otherNameValue = {CERT_RDN_UTF8_STRING, (DWORD) wcslen(upn) * sizeof(wchar_t), (PBYTE) upn};
	CERT_OTHER_NAME otherName = {szOID_NT_PRINCIPAL_NAME, {0, NULL}};
	CERT_ALT_NAME_ENTRY altName = {CERT_ALT_NAME_OTHER_NAME, &otherName};
	CERT_ALT_NAME_INFO AltName = {1, &altName};
	pCertExtension->pszObjId = szOID_SUBJECT_ALT_NAME2;
	pCertExtension->fCritical = FALSE;
	if(kuhl_m_crypto_c_sc_auth_quickEncode(X509_UNICODE_ANY_STRING, &otherNameValue, &otherName.Value))
	{
		status = kuhl_m_crypto_c_sc_auth_quickEncode(pCertExtension->pszObjId, &AltName, &pCertExtension->Value);
		LocalFree(otherName.Value.pbData);
	}
	return status;
}

BOOL kuhl_m_crypto_c_sc_auth_Ext_KU(PCERT_EXTENSION pCertExtension, BOOL isCritical, WORD bits)
{
	CRYPT_BIT_BLOB bit = {sizeof(bits), (PBYTE) &bits, 5};
	pCertExtension->pszObjId = szOID_KEY_USAGE;
	pCertExtension->fCritical = isCritical;
	return kuhl_m_crypto_c_sc_auth_quickEncode(pCertExtension->pszObjId, &bit, &pCertExtension->Value);
}

BOOL kuhl_m_crypto_c_sc_auth_Ext_EKU(PCERT_EXTENSION pCertExtension, DWORD count, ...)
{
	BOOL status = FALSE;
	DWORD i;
	va_list vaList;
	CERT_ENHKEY_USAGE usage = {count, NULL};
	pCertExtension->pszObjId = szOID_ENHANCED_KEY_USAGE;
	pCertExtension->fCritical = FALSE;
	if(usage.rgpszUsageIdentifier = (LPSTR *) LocalAlloc(LPTR, sizeof(LPSTR) * count))
	{
		va_start(vaList, count); 
		for(i = 0; i < count; i++)
			usage.rgpszUsageIdentifier[i] =  va_arg(vaList, LPSTR);
		va_end(vaList);
		status = kuhl_m_crypto_c_sc_auth_quickEncode(pCertExtension->pszObjId, &usage, &pCertExtension->Value);
		LocalFree(usage.rgpszUsageIdentifier);
	}
	return status;
}

__inline void kuhl_m_crypto_c_sc_auth_Ext_Free(PCERT_EXTENSION pCertExtension)
{
	if(pCertExtension->Value.pbData)
		LocalFree(pCertExtension->Value.pbData);
}

BOOL giveski(PCERT_EXTENSION pCertExtension, PCERT_PUBLIC_KEY_INFO info)
{
	SHA_CTX ctx;
	SHA_DIGEST dgst;
	CRYPT_DATA_BLOB bit = {sizeof(dgst.digest), dgst.digest};
	A_SHAInit(&ctx);
	A_SHAUpdate(&ctx, info->PublicKey.pbData, info->PublicKey.cbData);
	A_SHAFinal(&ctx, &dgst);
	pCertExtension->pszObjId = szOID_SUBJECT_KEY_IDENTIFIER;
	pCertExtension->fCritical = FALSE;
	return kuhl_m_crypto_c_sc_auth_quickEncode(pCertExtension->pszObjId, &bit, &pCertExtension->Value);
}

BOOL giveaki(PCERT_EXTENSION pCertExtension, PCERT_PUBLIC_KEY_INFO info)
{
	SHA_CTX ctx;
	SHA_DIGEST dgst;
	CERT_AUTHORITY_KEY_ID2_INFO ainfo = {{sizeof(dgst.digest), dgst.digest}, {0, NULL}, {0, NULL}};
	A_SHAInit(&ctx);
	A_SHAUpdate(&ctx, info->PublicKey.pbData, info->PublicKey.cbData);
	A_SHAFinal(&ctx, &dgst);
	pCertExtension->pszObjId = szOID_AUTHORITY_KEY_IDENTIFIER2;
	pCertExtension->fCritical = FALSE;
	return kuhl_m_crypto_c_sc_auth_quickEncode(pCertExtension->pszObjId, &ainfo, &pCertExtension->Value);
}

BOOL kuhl_m_crypto_c_sc_auth_Ext_CDP(PCERT_EXTENSION pCertExtension, DWORD count, ...)
{
	BOOL status = FALSE;
	CRL_DIST_POINT point = {{CRL_DIST_POINT_FULL_NAME, {count, NULL}}, {0, NULL, 0}, {0, NULL}};
	CRL_DIST_POINTS_INFO crl = {1, &point};
	va_list vaList;
	DWORD i;
	pCertExtension->pszObjId = szOID_CRL_DIST_POINTS;
	pCertExtension->fCritical = FALSE;
	if(point.DistPointName.FullName.rgAltEntry = (PCERT_ALT_NAME_ENTRY) LocalAlloc(LPTR, sizeof(CERT_ALT_NAME_ENTRY) * count))
	{
		va_start(vaList, count); 
		for(i = 0; i < count; i++)
		{
			point.DistPointName.FullName.rgAltEntry[i].dwAltNameChoice = CERT_ALT_NAME_URL;
			point.DistPointName.FullName.rgAltEntry[i].pwszURL = va_arg(vaList, LPWSTR);
		}
		va_end(vaList);
		status = kuhl_m_crypto_c_sc_auth_quickEncode(pCertExtension->pszObjId, &crl, &pCertExtension->Value);
		LocalFree(point.DistPointName.FullName.rgAltEntry);
	}
	return status;
}

BOOL givebc2(PCERT_EXTENSION pCertExtension, PCERT_BASIC_CONSTRAINTS2_INFO info)
{
	pCertExtension->pszObjId = szOID_BASIC_CONSTRAINTS2;
	pCertExtension->fCritical = info->fCA; // :)
	return kuhl_m_crypto_c_sc_auth_quickEncode(pCertExtension->pszObjId, info, &pCertExtension->Value);
}

BOOL genRdnAttr(PCERT_RDN_ATTR attr, LPSTR oid, LPCWSTR name)
{
	BOOL status = FALSE;
	if(attr && name && oid)
	{
		attr->pszObjId = oid;
		attr->dwValueType = CERT_RDN_UNICODE_STRING;
		attr->Value.cbData = lstrlenW(name) * sizeof(wchar_t);
		attr->Value.pbData = (PBYTE) name;
		status = TRUE;
	}
	return status;
}

PCERT_PUBLIC_KEY_INFO getPublicKeyInfo(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hProv, DWORD dwKeySpec)
{
	PCERT_PUBLIC_KEY_INFO info = NULL;
	DWORD cbInfo;
	if(CryptExportPublicKeyInfo(hProv, dwKeySpec, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, NULL, &cbInfo))
	{
		if(info = (PCERT_PUBLIC_KEY_INFO) LocalAlloc(LPTR, cbInfo))
		{
			if(!CryptExportPublicKeyInfo(hProv, dwKeySpec, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, info, &cbInfo))
			{
				PRINT_ERROR_AUTO(L"CryptExportPublicKeyInfo (data)");
				info = (PCERT_PUBLIC_KEY_INFO) LocalFree(info);
			}
		}
	}
	else PRINT_ERROR_AUTO(L"CryptExportPublicKeyInfo (init)");
	return info;
}

BOOL makePin(HCRYPTPROV hProv, BOOL isHw, LPSTR pin)
{
	BOOL status = FALSE;
	if(isHw && pin)
	{
		if(!(status = CryptSetProvParam(hProv, PP_KEYEXCHANGE_PIN, (const BYTE *) pin, 0)))
		{
			PRINT_ERROR_AUTO(L"CryptSetProvParam(PP_KEYEXCHANGE_PIN)");
			if(!(status = CryptSetProvParam(hProv, PP_SIGNATURE_PIN, (const BYTE *) pin, 0)))
				PRINT_ERROR_AUTO(L"CryptSetProvParam(PP_SIGNATURE_PIN)");
		}
	}
	else status = TRUE;
	return status;
}

BOOL makeSN(LPCWCHAR szSn, PCRYPT_INTEGER_BLOB sn)
{
	BOOL status = FALSE;
	if(szSn)
	{
		status = kull_m_string_stringToHexBuffer(szSn, &sn->pbData, &sn->cbData);
		if(!status)
			PRINT_ERROR(L"Unable to use \'%s\' as a HEX string\n", szSn);
	}
	else
	{
		sn->cbData = 20;
		if(sn->pbData = (PBYTE) LocalAlloc(LPTR, sn->cbData))
		{
			status = NT_SUCCESS(CDGenerateRandomBits(sn->pbData, sn->cbData));
			if(!status)
				LocalFree(sn->pbData);
		}
	}
	return status;
}

BOOL getCertificate(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hProv, DWORD dwKeySpec, LPCSTR type, const void *pvStructInfo, PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm, PBYTE *Certificate, DWORD *cbCertificate)
{
	BOOL status = FALSE;
	if(CryptSignAndEncodeCertificate(hProv, dwKeySpec, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, type, pvStructInfo, pSignatureAlgorithm, NULL, NULL, cbCertificate))
	{
		if(*Certificate = (PBYTE) LocalAlloc(LPTR, *cbCertificate))
		{
			if(!(status = CryptSignAndEncodeCertificate(hProv, dwKeySpec, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, type, pvStructInfo, pSignatureAlgorithm, NULL, *Certificate, cbCertificate)))
			{
				PRINT_ERROR_AUTO(L"CryptSignAndEncodeCertificate (data)");
				*Certificate = (PBYTE) LocalFree(*Certificate);
			}
		}
	}
	else PRINT_ERROR_AUTO(L"CryptSignAndEncodeCertificate (init)");
	return status;
}

PWSTR kuhl_m_crypto_pki_getCertificateName(PCERT_NAME_BLOB blob)
{
	PWSTR ret = NULL;
	DWORD dwSizeNeeded = CertNameToStr(X509_ASN_ENCODING, blob, CERT_X500_NAME_STR, NULL, 0);
	if(dwSizeNeeded)
	{
		if(ret = (PWSTR) LocalAlloc(LPTR, dwSizeNeeded * sizeof(wchar_t)))
		{
			if(!CertNameToStr(X509_ASN_ENCODING, blob, CERT_X500_NAME_STR, ret, dwSizeNeeded))
				ret = (PWSTR) LocalFree(ret);
		}
	}
	return ret;
}

void getDate(PFILETIME s, PFILETIME e, PVOID certOrCrlinfo, PCCERT_CONTEXT signer, PKIWI_SIGNER dSigner)
{
	PFILETIME *info = (PFILETIME *) certOrCrlinfo;
	if(info[0])
		*s = *info[0];
	else
	{
		if(signer && *(PULONG) &signer->pCertInfo->NotBefore)
			*s = signer->pCertInfo->NotBefore;
		else if(dSigner && *(PULONG) &dSigner->NotBefore)
			*s = dSigner->NotBefore;
		else GetSystemTimeAsFileTime(s);
	}
	if(info[1])
		*e = *info[1];
	else
	{
		if(signer && *(PULONG) &signer->pCertInfo->NotAfter)
			*e = signer->pCertInfo->NotAfter;
		else if(dSigner && *(PULONG) &dSigner->NotAfter)
			*e = dSigner->NotAfter;
		else
		{
			*e = *s;
			*(PULONGLONG) e += (ULONGLONG) 10000000 * 60 * 60 * 24 * 365 * 10;
		}
	}
}

BOOL closeHprov(BOOL bFreeKey, DWORD dwSpec, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hProv)
{
	BOOL status = !bFreeKey;
	if(hProv && bFreeKey)
	{
		if(dwSpec != CERT_NCRYPT_KEY_SPEC)
			status = CryptReleaseContext(hProv, 0);
		else
		{
			__try
			{
				status = (NCryptFreeObject(hProv) == ERROR_SUCCESS);
			}
			__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND)
			{
				PRINT_ERROR(L"CNG key without functions?\n");
			}
		}
	}
	return status;
}

BOOL getFromSigner(PCCERT_CONTEXT signer, PKIWI_SIGNER dSigner, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE *hSigner, DWORD *dwSignerKeySpec, BOOL *bFreeSignerKey, PCERT_EXTENSION aki, CERT_NAME_BLOB *nameIssuer)
{
	BOOL status = FALSE;
	DWORD dwSizeNeeded;
	PCRYPT_KEY_PROV_INFO pBuffer;
	PCERT_PUBLIC_KEY_INFO pbSignerPublicKeyInfo;

	if(signer)
	{
		*nameIssuer = signer->pCertInfo->Subject;
		if(CertGetCertificateContextProperty(signer, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSizeNeeded))
		{
			if(pBuffer = (PCRYPT_KEY_PROV_INFO) LocalAlloc(LPTR, dwSizeNeeded))
			{
				if(CertGetCertificateContextProperty(signer, CERT_KEY_PROV_INFO_PROP_ID, pBuffer, &dwSizeNeeded))
					kprintf(L" [i.key ] provider : %s\n [i.key ] container: %s\n", pBuffer->pwszProvName, pBuffer->pwszContainerName);
				LocalFree(pBuffer);
			}
		}
		if(CryptAcquireCertificatePrivateKey(signer, CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, NULL, hSigner, dwSignerKeySpec, bFreeSignerKey))
		{
			if(pbSignerPublicKeyInfo = getPublicKeyInfo(*hSigner, *dwSignerKeySpec))
			{
				status = giveaki(aki, pbSignerPublicKeyInfo);
				LocalFree(pbSignerPublicKeyInfo);
			}
			if(!status)
				closeHprov(*bFreeSignerKey, *dwSignerKeySpec, *hSigner);
		}
		else PRINT_ERROR_AUTO(L"CryptAcquireCertificatePrivateKey(signer)");
	}
	else if(dSigner)
	{
		*nameIssuer = dSigner->Subject;
		*hSigner = dSigner->hProv;
		*dwSignerKeySpec = dSigner->dwKeySpec;
		*bFreeSignerKey = FALSE;
		if(pbSignerPublicKeyInfo = getPublicKeyInfo(*hSigner, *dwSignerKeySpec))
		{
			status = giveaki(aki, pbSignerPublicKeyInfo);
			LocalFree(pbSignerPublicKeyInfo);
		}
	}

	if(!status)
	{
		*hSigner = 0;
		*bFreeSignerKey = FALSE;
	}
	return status;
}

BOOL generateCrl(PKIWI_CRL_INFO ci, PCCERT_CONTEXT signer, PKIWI_SIGNER dSigner, PBYTE *Crl, DWORD *cbCrl)
{
	BOOL status = FALSE, isHw = FALSE, bFreeSignerKey;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hSigner = 0;
	DWORD dwSignerKeySpec;

	CERT_EXTENSION Extensions[2] = {0}; // AKI, CRL Number
	CRL_INFO CrlInfo = {0};
	PWSTR dn;

	CrlInfo.dwVersion = CRL_V2;
	CrlInfo.cExtension = ARRAYSIZE(Extensions);
	CrlInfo.rgExtension = Extensions;
	CrlInfo.SignatureAlgorithm.pszObjId = ci->algorithm ? ci->algorithm : szOID_RSA_SHA1RSA;

	getDate(&CrlInfo.ThisUpdate, &CrlInfo.NextUpdate, ci, signer, dSigner);

	CrlInfo.rgExtension[0].pszObjId = szOID_CRL_NUMBER;
	CrlInfo.rgExtension[0].fCritical = FALSE;
	if(kuhl_m_crypto_c_sc_auth_quickEncode(CrlInfo.rgExtension[0].pszObjId, &ci->crlnumber, &CrlInfo.rgExtension[0].Value))
	{
		kprintf(L"[s.crl ] algorithm : %S\n", CrlInfo.SignatureAlgorithm.pszObjId);
		kprintf(L"[s.crl ] validity  : ");
		kull_m_string_displayLocalFileTime(&CrlInfo.ThisUpdate);
		kprintf(L" -> ");
		kull_m_string_displayLocalFileTime(&CrlInfo.NextUpdate);
		kprintf(L"\n");

		if(getFromSigner(signer, dSigner, &hSigner, &dwSignerKeySpec, &bFreeSignerKey, &CrlInfo.rgExtension[1], &CrlInfo.Issuer))
		{
			if(dn = kuhl_m_crypto_pki_getCertificateName(&CrlInfo.Issuer))
			{
				kprintf(L" [i.cert] subject  : %s\n", dn);
				LocalFree(dn);
			}
			kprintf(L"[s.crl ] signature : ");
			if(status = getCertificate(hSigner, dwSignerKeySpec, X509_CERT_CRL_TO_BE_SIGNED, &CrlInfo, &CrlInfo.SignatureAlgorithm, Crl, cbCrl))
				kprintf(L"OK\n");
			closeHprov(bFreeSignerKey, dwSignerKeySpec, hSigner);
			LocalFree(CrlInfo.rgExtension[1].Value.pbData);
		}
		LocalFree(CrlInfo.rgExtension[0].Value.pbData);
	}
	else PRINT_ERROR(L"Unable to create CRL Number\n");
	return status;
}

BOOL generateCertificate(PKIWI_KEY_INFO ki, PKIWI_CERT_INFO ci, PCCERT_CONTEXT signer, PKIWI_SIGNER dSigner, PBYTE *Certificate, DWORD *cbCertificate, PKIWI_SIGNER oSigner)
{
	BOOL status = FALSE, isHw = FALSE, bFreeSignerKey;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hSigner;
	HCRYPTKEY hKey;
	DWORD dwImplType, dwSignerKeySpec;

	PCERT_PUBLIC_KEY_INFO pbPublicKeyInfo;
	CERT_RDN_ATTR rgNameAttr[4];
	CERT_RDN rgRDN[4] = {{1, NULL}, {1, NULL}, {1, NULL}, {1, NULL}};
	CERT_NAME_INFO Name = {0, rgRDN};
	CERT_BASIC_CONSTRAINTS2_INFO bc2 = {ci->isAC, FALSE, 0}; // no len constraint
	CERT_EXTENSION Extensions[7] = {0}, *pAki = NULL; // KU, SKI, BC2, [AKI, EKU, CRLDP, SAN]
	CERT_INFO CertInfo = {0};

	PWSTR dn;
	PCCRYPT_OID_INFO info;

	CertInfo.dwVersion = CERT_V3;
	CertInfo.cExtension = 3; // KU, SKI, BC2
	CertInfo.rgExtension = Extensions;
	CertInfo.SignatureAlgorithm.pszObjId = ci->algorithm ? ci->algorithm : szOID_RSA_SHA1RSA;

	if(genRdnAttr(&rgNameAttr[0], szOID_COMMON_NAME, ci->cn))
		rgRDN[Name.cRDN++].rgRDNAttr = &rgNameAttr[0];
	if(genRdnAttr(&rgNameAttr[1], szOID_ORGANIZATIONAL_UNIT_NAME, ci->ou))
		rgRDN[Name.cRDN++].rgRDNAttr = &rgNameAttr[1];
	if(genRdnAttr(&rgNameAttr[2], szOID_ORGANIZATION_NAME, ci->o))
		rgRDN[Name.cRDN++].rgRDNAttr = &rgNameAttr[2];
	if(genRdnAttr(&rgNameAttr[3], szOID_COUNTRY_NAME, ci->c))
		rgRDN[Name.cRDN++].rgRDNAttr = &rgNameAttr[3];

	getDate(&CertInfo.NotBefore, &CertInfo.NotAfter, ci, signer, dSigner);

	if(kuhl_m_crypto_c_sc_auth_quickEncode(X509_NAME, &Name, &CertInfo.Subject))
	{
		if(dn = kuhl_m_crypto_pki_getCertificateName(&CertInfo.Subject))
		{
			kprintf(L"[s.cert] subject   : %s\n", dn);
			LocalFree(dn);
		}
		if(makeSN(ci->sn, &CertInfo.SerialNumber))
		{
			kprintf(L"[s.cert] serial    : ");
			kull_m_string_wprintf_hex(CertInfo.SerialNumber.pbData, CertInfo.SerialNumber.cbData, 0);
			kprintf(L"\n");

			if(kuhl_m_crypto_c_sc_auth_Ext_KU(&CertInfo.rgExtension[0], TRUE, ci->ku))
			{
				if(givebc2(&CertInfo.rgExtension[1], &bc2))
				{
					if(ci->eku)
						CertInfo.rgExtension[CertInfo.cExtension++] = *ci->eku;
					if(ci->san)
						CertInfo.rgExtension[CertInfo.cExtension++] = *ci->san;
					if(ci->cdp)
						CertInfo.rgExtension[CertInfo.cExtension++] = *ci->cdp;

					kprintf(L"[s.cert] algorithm : %S", CertInfo.SignatureAlgorithm.pszObjId);
					if(info = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, CertInfo.SignatureAlgorithm.pszObjId, CRYPT_OID_DISABLE_SEARCH_DS_FLAG))
						kprintf(L" (%s)", info->pwszName);
					kprintf(L"\n[s.cert] validity  : ");
					kull_m_string_displayLocalFileTime(&CertInfo.NotBefore);
					kprintf(L" -> ");
					kull_m_string_displayLocalFileTime(&CertInfo.NotAfter);
					kprintf(L"\n");

					kprintf(L"[s.key ] provider  : %s\n", ki->keyInfos.pwszProvName);
					if(ki->keyInfos.pwszContainerName = kull_m_string_getRandomGUID())
					{
						kprintf(L"[s.key ] container : %s\n", ki->keyInfos.pwszContainerName);
						if(CryptAcquireContext(&ki->hProv, NULL, ki->keyInfos.pwszProvName, ki->keyInfos.dwProvType, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
						{
							if(kull_m_crypto_CryptGetProvParam(ki->hProv, PP_IMPTYPE, FALSE, NULL, NULL, &dwImplType))
								isHw = dwImplType & CRYPT_IMPL_HARDWARE;
							if(isHw)
							{
								ki->keyInfos.dwFlags &= ~CRYPT_SILENT;
								ki->dwKeyFlags &= ~CRYPT_EXPORTABLE;
								makePin(ki->hProv, isHw, ki->pin);
							}
							CryptReleaseContext(ki->hProv, 0);
						}

						if(CryptAcquireContext(&ki->hProv, ki->keyInfos.pwszContainerName, ki->keyInfos.pwszProvName, ki->keyInfos.dwProvType, CRYPT_NEWKEYSET | ki->keyInfos.dwFlags))
						{
							makePin(ki->hProv, isHw, ki->pin);
							kprintf(L"[s.key ] gen (%4hu): ", ki->wKeySize);
							if(CryptGenKey(ki->hProv, ki->keyInfos.dwKeySpec, ki->dwKeyFlags | (ki->wKeySize << 16), &hKey))
							{
								kprintf(L"OK\n");
								if(pbPublicKeyInfo = getPublicKeyInfo(ki->hProv, ki->keyInfos.dwKeySpec))
								{
									CertInfo.SubjectPublicKeyInfo = *pbPublicKeyInfo;
									if(giveski(&CertInfo.rgExtension[2], pbPublicKeyInfo))
									{
										if(getFromSigner(signer, dSigner, &hSigner, &dwSignerKeySpec, &bFreeSignerKey, &CertInfo.rgExtension[CertInfo.cExtension], &CertInfo.Issuer))
										{
											pAki = &CertInfo.rgExtension[CertInfo.cExtension++];
											if(dn = kuhl_m_crypto_pki_getCertificateName(&CertInfo.Issuer))
											{
												kprintf(L" [i.cert] subject  : %s\n", dn);
												LocalFree(dn);
											}
										}
										else CertInfo.Issuer = CertInfo.Subject;

										kprintf(L"[s.cert] signature : ");
										if(status = getCertificate(hSigner ? hSigner : ki->hProv, hSigner ? dwSignerKeySpec : ki->keyInfos.dwKeySpec, X509_CERT_TO_BE_SIGNED, &CertInfo, &CertInfo.SignatureAlgorithm, Certificate, cbCertificate))
										{
											kprintf(L"OK\n");
											if(isHw)
											{
												kprintf(L"[s.key ] cert.assoc: ");
												if(CryptSetKeyParam(hKey, KP_CERTIFICATE, *Certificate, 0))
													kprintf(L"OK\n");
												else PRINT_ERROR_AUTO(L"CryptSetKeyParam(KP_CERTIFICATE)");
											}
											if(oSigner)
											{
												oSigner->hProv = ki->hProv;
												oSigner->dwKeySpec = ki->keyInfos.dwKeySpec;
												oSigner->NotBefore = CertInfo.NotBefore;
												oSigner->NotAfter = CertInfo.NotAfter;
												oSigner->Subject.cbData = CertInfo.Subject.cbData;
												if(oSigner->Subject.pbData = (PBYTE) LocalAlloc(LPTR, oSigner->Subject.cbData))
													RtlCopyMemory(oSigner->Subject.pbData, CertInfo.Subject.pbData, oSigner->Subject.cbData);
												else status = FALSE;
											}
										}
										
										if(pAki)
											LocalFree(pAki->Value.pbData);
										
										closeHprov(bFreeSignerKey, dwSignerKeySpec, hSigner);
										LocalFree(&CertInfo.rgExtension[2].Value.pbData);
									}
									else PRINT_ERROR(L"Unable to create SKI\n");
								}
								CryptDestroyKey(hKey);
							}
							else PRINT_ERROR_AUTO(L"CryptGenKey");
							if(!status)
								CryptReleaseContext(ki->hProv, 0);
						}
						else PRINT_ERROR_AUTO(L"CryptAcquireContext(CRYPT_NEWKEYSET)");
						if(!status)
							LocalFree(ki->keyInfos.pwszContainerName);
					}
					else PRINT_ERROR(L"Unable to generate a container name\n");
					LocalFree(&CertInfo.rgExtension[1].Value.pbData);
				}
				else PRINT_ERROR(L"Unable to create BC2\n");
				LocalFree(&CertInfo.rgExtension[0].Value.pbData);
			}
			else PRINT_ERROR(L"Unable to create KU\n");
			LocalFree(CertInfo.SerialNumber.pbData);
		}
		else PRINT_ERROR(L"Unable to create SN\n");
		LocalFree(CertInfo.Subject.pbData);
	}
	else PRINT_ERROR(L"Unable to create Subject\n");
	return status;
}

NTSTATUS kuhl_m_crypto_c_sc_auth(int argc, wchar_t * argv[])
{
	LPCWSTR szStoreCA, szNameCA = NULL, szHashCA, szPfx = NULL, szKeySize, szPin, szCrlDp, szUPN;
	HCERTSTORE hCertStoreCA;
	PCCERT_CONTEXT pCertCtxCA;
	BOOL isExported = FALSE, noUserStore = FALSE, findHash = FALSE;
	CERT_EXTENSION eku = {0}, san = {0}, cdp = {0};
	DWORD szCertificate = 0;
	PBYTE Certificate = NULL;
	KIWI_KEY_INFO ki = {{NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_SILENT, 0, NULL, AT_KEYEXCHANGE}, NULL, CRYPT_EXPORTABLE, 2048};
	KIWI_CERT_INFO ci = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERT_KEY_ENCIPHERMENT_KEY_USAGE, szOID_RSA_SHA256RSA, FALSE, &eku, &san, NULL};
	BYTE hashB[SHA_DIGEST_LENGTH] = {0};
	CRYPT_HASH_BLOB hash = {sizeof(hashB), hashB};

	if(kull_m_string_args_byName(argc, argv, L"hw", NULL, NULL))
	{
		kull_m_string_args_byName(argc, argv, L"csp", &ki.keyInfos.pwszProvName, MS_SCARD_PROV);
		if(kull_m_string_args_byName(argc, argv, L"pin", &szPin, NULL))
			ki.pin = kull_m_string_unicode_to_ansi(szPin);
	}
	noUserStore = kull_m_string_args_byName(argc, argv, L"nostore", NULL, NULL);
	kull_m_string_args_byName(argc, argv, L"castore", &szStoreCA, L"LOCAL_MACHINE");
	
	if(kull_m_string_args_byName(argc, argv, L"sha1", NULL, NULL))
		ci.algorithm = szOID_OIWSEC_sha1RSASign;

	if(kull_m_string_args_byName(argc, argv, L"keysize", &szKeySize, NULL))
		ki.wKeySize = (WORD) wcstoul(szKeySize, NULL, 0);

	kull_m_string_args_byName(argc, argv, L"caname", &szNameCA, NULL);
	if(kull_m_string_args_byName(argc, argv, L"cahash", &szHashCA, NULL))
	{
		findHash = kull_m_string_stringToHex(szHashCA, hash.pbData, hash.cbData);
		if(!findHash)
			PRINT_ERROR(L"/cahash needs a SHA1 in hex (40chars for 20bytes)\n");
	}

	if(szNameCA || findHash)
	{
		if(kull_m_string_args_byName(argc, argv, L"upn", &szUPN, NULL))
		{
			kull_m_string_args_byName(argc, argv, L"cn", &ci.cn, szUPN);
			kull_m_string_args_byName(argc, argv, L"o", &ci.o, MIMIKATZ);
			kull_m_string_args_byName(argc, argv, L"ou", &ci.ou, NULL);
			kull_m_string_args_byName(argc, argv, L"c", &ci.c, L"FR");

			kprintf(L"CA store       : %s\n", szStoreCA);
			if(hCertStoreCA = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, (HCRYPTPROV_LEGACY) NULL, kull_m_crypto_system_store_to_dword(szStoreCA) | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"My"))
			{
				if(findHash)
				{
					kprintf(L"CA hash (sha1) : ");
					kull_m_string_wprintf_hex(hash.pbData, hash.cbData, 0);
					kprintf(L"\n");
				}
				else kprintf(L"CA name        : %s\n", szNameCA);
				if(pCertCtxCA = CertFindCertificateInStore(hCertStoreCA, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, findHash ? CERT_FIND_SHA1_HASH : CERT_FIND_SUBJECT_STR, findHash ? (LPVOID) &hash : (LPVOID) szNameCA, NULL))
				{
					if(kuhl_m_crypto_c_sc_auth_Ext_EKU(&eku, 2, szOID_KP_SMARTCARD_LOGON, szOID_PKIX_KP_CLIENT_AUTH))
					{
						if(kuhl_m_crypto_c_sc_auth_Ext_AltUPN(&san, szUPN))
						{
							if(kull_m_string_args_byName(argc, argv, L"crldp", &szCrlDp, NULL))
								if(kuhl_m_crypto_c_sc_auth_Ext_CDP(&cdp, 1, szCrlDp))
									ci.cdp = &cdp;

							if(generateCertificate(&ki, &ci, pCertCtxCA, NULL, &Certificate, &szCertificate, NULL))
							{
								if(kull_m_string_args_byName(argc, argv, L"pfx", &szPfx, NULL))
								{
									isExported = kull_m_crypto_DerAndKeyInfoToPfx(Certificate, szCertificate, &ki.keyInfos, szPfx);
									kprintf(L"Private Export : %s - %s\n", szPfx, isExported ? L"OK" : L"KO");
								}
								else if(!noUserStore)
								{
									isExported = kull_m_crypto_DerAndKeyInfoToStore(Certificate, szCertificate, &ki.keyInfos, CERT_SYSTEM_STORE_CURRENT_USER, L"My", FALSE);
									kprintf(L"Private Store  : CERT_SYSTEM_STORE_CURRENT_USER/My - %s\n", isExported ? L"OK" : L"KO");
								}

								if(!isExported || szPfx)
									kull_m_crypto_close_hprov_delete_container(ki.hProv);
								else
									CryptReleaseContext(ki.hProv, 0);
								LocalFree(Certificate);
							}
							if(ci.cdp)
								kuhl_m_crypto_c_sc_auth_Ext_Free(ci.cdp);
							kuhl_m_crypto_c_sc_auth_Ext_Free(&san);
						}
						else PRINT_ERROR_AUTO(L"Unable to generate SAN extension - kuhl_m_crypto_c_sc_auth_Ext_AltUPN");
						kuhl_m_crypto_c_sc_auth_Ext_Free(&eku);
					}
					else PRINT_ERROR_AUTO(L"Unable to generate EKU extension - kuhl_m_crypto_c_sc_auth_Ext_EKU");
					CertFreeCertificateContext(pCertCtxCA);
				}
				else PRINT_ERROR_AUTO(L"CertFindCertificateInStore");
				CertCloseStore(hCertStoreCA, CERT_CLOSE_STORE_FORCE_FLAG);
			}
			else PRINT_ERROR_AUTO(L"CertOpenStore");
		}
		else PRINT_ERROR(L"/upn:user@domain.local needed\n");
	}
	else PRINT_ERROR(L"/caname:CA-KIWI or /cahash:SHA1 needed\n");

	if(ki.pin)
		LocalFree(ki.pin);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_crypto_c_pkiwi(int argc, wchar_t * argv[])
{
	KIWI_KEY_INFO CaKi = {{NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_SILENT, 0, NULL, AT_SIGNATURE}, NULL, CRYPT_EXPORTABLE, 4096};
	return STATUS_SUCCESS;
}