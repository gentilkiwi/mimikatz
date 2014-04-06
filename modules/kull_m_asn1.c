/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kull_m_asn1.h"

DWORD kull_m_asn1_getSize(PDIRTY_ASN1_SEQUENCE_EASY sequence)
{
	DWORD size;
	if(sequence->seq2.sizeSize & DIRTY_ASN1_MASK_HIGH_SIZE)
		size = _byteswap_ushort(sequence->seq2.size) + sizeof(DIRTY_ASN1_SEQUENCE_2);
	else
		size = sequence->seq1.size + sizeof(DIRTY_ASN1_SEQUENCE_1);
	return size;
}

void kull_m_asn1_append(PDIRTY_ASN1_SEQUENCE_EASY * parent, PDIRTY_ASN1_SEQUENCE_EASY child)
{
	BOOL result =  FALSE;
	PDIRTY_ASN1_SEQUENCE_EASY buffer = NULL;
	DWORD szParent, szChild, szTotal;

	if(child)
	{
		szParent = kull_m_asn1_getSize(*parent);
		szChild = kull_m_asn1_getSize(child);
	
		if((*parent)->seq2.sizeSize & DIRTY_ASN1_MASK_HIGH_SIZE)
		{
			if(buffer = (PDIRTY_ASN1_SEQUENCE_EASY) LocalAlloc(LPTR, szParent + szChild))
			{
				RtlCopyMemory(buffer, *parent, szParent);
				RtlCopyMemory((PBYTE) buffer + szParent, child, szChild);
				buffer->seq2.size = _byteswap_ushort((USHORT) (_byteswap_ushort(buffer->seq2.size) + szChild));
			}
		}
		else
		{
			szTotal = szChild + (*parent)->seq1.size;
			if(szTotal > 0x7f)
			{
				if(buffer = (PDIRTY_ASN1_SEQUENCE_EASY) LocalAlloc(LPTR, sizeof(DIRTY_ASN1_SEQUENCE_2) + szTotal))
				{
					RtlCopyMemory((PBYTE) buffer + sizeof(DIRTY_ASN1_SEQUENCE_2), (PBYTE) (*parent) + sizeof(DIRTY_ASN1_SEQUENCE_1), (*parent)->seq1.size);
					RtlCopyMemory((PBYTE) buffer + sizeof(DIRTY_ASN1_SEQUENCE_2) + (*parent)->seq1.size, child, szChild);
					buffer->seq2.type = (*parent)->seq1.type;
					buffer->seq2.sizeSize = DIRTY_ASN1_MASK_HIGH_SIZE | 2;
					buffer->seq2.size = _byteswap_ushort((USHORT) szTotal);
				}
			}
			else
			{
				if(buffer = (PDIRTY_ASN1_SEQUENCE_EASY) LocalAlloc(LPTR, szParent + szChild))
				{
					RtlCopyMemory(buffer, *parent, szParent);
					RtlCopyMemory((PBYTE) buffer + szParent, child, szChild);
					buffer->seq1.size += (UCHAR) szChild;
				}
			}
		}
		if(buffer)
		{
			LocalFree(child);
			LocalFree(*parent);
			*parent = buffer;
		}
	}
}

PDIRTY_ASN1_SEQUENCE_EASY kull_m_asn1_create(UCHAR type, LPCVOID data, DWORD size, PDIRTY_ASN1_SEQUENCE_EASY *parent)
{
	PDIRTY_ASN1_SEQUENCE_EASY buffer = NULL;
	if(size > 0x7f)
	{
		if(buffer = (PDIRTY_ASN1_SEQUENCE_EASY) LocalAlloc(LPTR, sizeof(DIRTY_ASN1_SEQUENCE_2) + size))
		{
			buffer->seq2.type = type;
			buffer->seq2.sizeSize = DIRTY_ASN1_MASK_HIGH_SIZE | 2;
			buffer->seq2.size = _byteswap_ushort((USHORT) size);
			if(data)
				RtlCopyMemory((PBYTE) buffer + sizeof(DIRTY_ASN1_SEQUENCE_2), data, size);
		}
	}
	else
	{
		if(buffer = (PDIRTY_ASN1_SEQUENCE_EASY) LocalAlloc(LPTR, sizeof(DIRTY_ASN1_SEQUENCE_1) + size))
		{
			buffer->seq1.type = type;
			buffer->seq1.size = (UCHAR) size;
			if(data)
				RtlCopyMemory((PBYTE) buffer + sizeof(DIRTY_ASN1_SEQUENCE_1), data, size);
		}
	}
	
	if(parent)
	{
		kull_m_asn1_append(parent, buffer);
		buffer = NULL;
	}
	return buffer;
}

PDIRTY_ASN1_SEQUENCE_EASY kull_m_asn1_GenTime(PFILETIME localtime)
{
	BOOL status = FALSE;
	SYSTEMTIME st;
	char buffer[4 + 2 + 2 + 2 + 2 + 2 + 1 + 1];
	
	if(FileTimeToSystemTime(localtime, &st))
	{
		if(status = (sprintf_s(buffer, sizeof(buffer), "%04hu%02hu%02hu%02hu%02hu%02huZ",  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond) > 0))
			return kull_m_asn1_create(DIRTY_ASN1_ID_GENERALIZED_TIME, buffer, sizeof(buffer) - 1, NULL);
	}
	return NULL;
}

PDIRTY_ASN1_SEQUENCE_EASY kull_m_asn1_GenString(PCUNICODE_STRING String)
{
	ANSI_STRING aString;
	PDIRTY_ASN1_SEQUENCE_EASY GeneralString = NULL;
	if(NT_SUCCESS(RtlUnicodeStringToAnsiString(&aString, String, TRUE)))
	{
		GeneralString = kull_m_asn1_create(DIRTY_ASN1_ID_GENERAL_STRING, aString.Buffer, aString.Length, NULL);
		RtlFreeAnsiString(&aString);
	}
	return GeneralString;
}

PDIRTY_ASN1_SEQUENCE_EASY kull_m_asn1_BitStringFromULONG(ULONG data)
{
	BYTE flagBuffer[5] = {0};
	*(PDWORD) (flagBuffer + 1) = _byteswap_ulong(data);
	return kull_m_asn1_create(DIRTY_ASN1_ID_BIT_STRING, flagBuffer, sizeof(flagBuffer), NULL);
}