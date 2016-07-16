/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_asn1.h"

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