/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_asn1.h"

ASN1module_t hASN1Module = NULL;
ASN1encoding_t ASN1enc = NULL;
ASN1decoding_t ASN1dec = NULL;

void kull_m_asn1_BitStringFromULONG(BerElement * pBer, ULONG data)
{
	BYTE flagBuffer[5] = {0};
	*(PDWORD) (flagBuffer + 1) = _byteswap_ulong(data);
	ber_printf(pBer, "X", flagBuffer, sizeof(flagBuffer));
}

void kull_m_asn1_GenTime(BerElement * pBer, PFILETIME localtime)
{
	SYSTEMTIME st;
	char buffer[4 + 2 + 2 + 2 + 2 + 2 + 1 + 1];
	if(FileTimeToSystemTime(localtime, &st))
		if(sprintf_s(buffer, sizeof(buffer), "%04hu%02hu%02hu%02hu%02hu%02huZ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond) > 0)
			ber_printf(pBer, "to", DIRTY_ASN1_ID_GENERALIZED_TIME, buffer, sizeof(buffer) - 1);
}

void kull_m_asn1_GenString(BerElement * pBer, PCUNICODE_STRING String)
{
	ANSI_STRING aString;
	if(NT_SUCCESS(RtlUnicodeStringToAnsiString(&aString, String, TRUE)))
	{
		ber_printf(pBer, "to", DIRTY_ASN1_ID_GENERAL_STRING, aString.Buffer, aString.Length);
		RtlFreeAnsiString(&aString);
	}
}

static const ASN1GenericFun_t kull_m_asn1_encdecfreefntab[] = {NULL};
static const ASN1uint32_t kull_m_asn1_sizetab[] = {0};
BOOL kull_m_asn1_init()
{
	BOOL status = FALSE;
	int ret;
	if(hASN1Module = ASN1_CreateModule(ASN1_THIS_VERSION, ASN1_BER_RULE_DER, ASN1FLAGS_NOASSERT, 1, kull_m_asn1_encdecfreefntab, kull_m_asn1_encdecfreefntab, (const ASN1FreeFun_t *) kull_m_asn1_encdecfreefntab, kull_m_asn1_sizetab, 'iwik'))
	{
		ret = ASN1_CreateEncoder(hASN1Module, &ASN1enc, NULL, 0, NULL);
		if(ASN1_FAILED(ret))
		{
			PRINT_ERROR(L"ASN1_CreateEncoder: %i\n", ret);
			ASN1enc = NULL;
		}
		else
		{
			ret = ASN1_CreateDecoder(hASN1Module, &ASN1dec, NULL, 0, NULL);
			if(ASN1_FAILED(ret))
			{
				PRINT_ERROR(L"ASN1_CreateDecoder: %i\n", ret);
				ASN1dec = NULL;
			}
		}
	}
	else PRINT_ERROR(L"ASN1_CreateModule\n");

	status = hASN1Module && ASN1enc && ASN1dec;
	if(!status)
		kull_m_asn1_term();
	return status;
}

void kull_m_asn1_term()
{
	if(ASN1dec)
	{
		ASN1_CloseDecoder(ASN1dec);
		ASN1dec = NULL;
	}
	if(ASN1enc)
	{
		ASN1_CloseEncoder(ASN1enc);
		ASN1enc = NULL;
	}
	if(hASN1Module)
	{
		ASN1_CloseModule(hASN1Module);
		hASN1Module = NULL;
	}
}

BOOL kull_m_asn1_DotVal2Eoid(__in const ASN1char_t *dotOID, __out OssEncodedOID *encodedOID)
{
	BOOL status = FALSE;
	if(ASN1enc && dotOID && encodedOID)
	{
		encodedOID->length = 0;
		encodedOID->value = NULL;
		status = ASN1BERDotVal2Eoid(ASN1enc, dotOID, encodedOID);
	}
	return status;
}

void kull_m_asn1_freeEnc(void *pBuf)
{
	if(ASN1enc && pBuf)
		ASN1_FreeEncoded(ASN1enc, pBuf);
}

BOOL kull_m_asn1_Eoid2DotVal(__in const OssEncodedOID *encodedOID, __out ASN1char_t **dotOID)
{
	BOOL status = FALSE;
	if(ASN1dec && encodedOID && dotOID)
	{
		*dotOID = NULL;
		status = ASN1BEREoid2DotVal(ASN1dec, encodedOID, dotOID);
	}
	return status;
}

void kull_m_asn1_freeDec(void *pBuf)
{
	if(pBuf)
		ASN1Free(pBuf);
}