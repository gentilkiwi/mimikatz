/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_minidump.h"

BOOL kull_m_minidump_open(IN HANDLE hFile, OUT PKULL_M_MINIDUMP_HANDLE *hMinidump)
{
	BOOL status = FALSE;

	*hMinidump = (PKULL_M_MINIDUMP_HANDLE) LocalAlloc(LPTR, sizeof(KULL_M_MINIDUMP_HANDLE));
	if(*hMinidump)
	{
		(*hMinidump)->hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if((*hMinidump)->hFileMapping)
		{
			if((*hMinidump)->pMapViewOfFile = MapViewOfFile((*hMinidump)->hFileMapping, FILE_MAP_READ, 0, 0, 0))
				status = (((PMINIDUMP_HEADER) (*hMinidump)->pMapViewOfFile)->Signature  == MINIDUMP_SIGNATURE) && ((WORD) (((PMINIDUMP_HEADER) (*hMinidump)->pMapViewOfFile)->Version) == MINIDUMP_VERSION);
		}
		if(!status)
			kull_m_minidump_close(*hMinidump);
	}
	return status;
}

BOOL kull_m_minidump_close(IN PKULL_M_MINIDUMP_HANDLE hMinidump)
{
	if(hMinidump->pMapViewOfFile)
		UnmapViewOfFile(hMinidump->pMapViewOfFile);
	if(hMinidump->hFileMapping)
		CloseHandle(hMinidump->hFileMapping);
	return TRUE;
}

LPVOID kull_m_minidump_RVAtoPTR(IN PKULL_M_MINIDUMP_HANDLE hMinidump, RVA64 rva)
{
	return (PBYTE) (hMinidump->pMapViewOfFile) + rva;
}

LPVOID kull_m_minidump_stream(IN PKULL_M_MINIDUMP_HANDLE hMinidump, MINIDUMP_STREAM_TYPE type, OUT OPTIONAL DWORD *pSize)
{
	ULONG32 i;
	PMINIDUMP_DIRECTORY pStreamDirectory =  (PMINIDUMP_DIRECTORY) kull_m_minidump_RVAtoPTR(hMinidump, ((PMINIDUMP_HEADER) (hMinidump->pMapViewOfFile))->StreamDirectoryRva);
	
	for(i = 0; i < ((PMINIDUMP_HEADER) (hMinidump->pMapViewOfFile))->NumberOfStreams; i++)
	{
		if(pStreamDirectory[i].StreamType == type)
		{
			if(pSize)
				*pSize = pStreamDirectory[i].Location.DataSize;
			return kull_m_minidump_RVAtoPTR(hMinidump, pStreamDirectory[i].Location.Rva);
		}
	}
	return NULL;
}

BOOL kull_m_minidump_copy(IN PKULL_M_MINIDUMP_HANDLE hMinidump, OUT VOID *Destination, IN VOID *Source, IN SIZE_T Length)
{
	BOOL status = FALSE;
	PMINIDUMP_MEMORY64_LIST myDir = NULL;
	//MINIDUMP_STREAM_TYPE types[] = {Memory64ListStream, MemoryListStream};
	
	PBYTE ptr;
	ULONG64 nMemory64;
	PMINIDUMP_MEMORY_DESCRIPTOR64 memory64;
	ULONG64 offsetToRead, offsetToWrite, lengthToRead, lengthReaded = 0;
				
	if(myDir = (PMINIDUMP_MEMORY64_LIST) kull_m_minidump_stream(hMinidump, Memory64ListStream, NULL))
	{
		ptr = (PBYTE) kull_m_minidump_RVAtoPTR(hMinidump, myDir->BaseRva);
		for(nMemory64 = 0; nMemory64 < myDir->NumberOfMemoryRanges; nMemory64++, ptr += memory64->DataSize)
		{
			memory64 = &(myDir->MemoryRanges[nMemory64]);
			if(	
				(((ULONG64) Source >= memory64->StartOfMemoryRange) && ((ULONG64) Source < (memory64->StartOfMemoryRange + memory64->DataSize))) ||
				(((ULONG64) Source + Length >= memory64->StartOfMemoryRange) && ((ULONG64) Source + Length < (memory64->StartOfMemoryRange + memory64->DataSize))) ||
				(((ULONG64) Source < memory64->StartOfMemoryRange) && ((ULONG64) Source + Length > (memory64->StartOfMemoryRange + memory64->DataSize)))
				)
			{
				if((ULONG64) Source < memory64->StartOfMemoryRange)
				{
					offsetToRead	= 0;
					offsetToWrite	= memory64->StartOfMemoryRange - (ULONG64) Source;
				}
				else
				{
					offsetToRead	= (ULONG64) Source - memory64->StartOfMemoryRange;
					offsetToWrite	= 0;
				}
				lengthToRead = Length - offsetToWrite;
				if(offsetToRead + lengthToRead > memory64->DataSize)
					lengthToRead = memory64->DataSize - offsetToRead;

				RtlCopyMemory((PBYTE) Destination + offsetToWrite, ptr + offsetToRead, (SIZE_T) lengthToRead);
				lengthReaded += lengthToRead;
			}
		}
		status = (lengthReaded == Length);
	}
	return status;
}

LPVOID kull_m_minidump_remapVirtualMemory64(IN PKULL_M_MINIDUMP_HANDLE hMinidump, IN VOID *Source, IN SIZE_T Length)
{
	BOOL status = FALSE;
	LPVOID myDir;
	PBYTE startPtr = NULL, ptr;
	ULONG64 nMemory64, previousPtr = 0, previousSize = 0, size = 0;
	PMINIDUMP_MEMORY_DESCRIPTOR64 memory64;

	myDir = kull_m_minidump_stream(hMinidump, Memory64ListStream, NULL);
	if(myDir)
	{
		ptr = (PBYTE) kull_m_minidump_RVAtoPTR(hMinidump, ((PMINIDUMP_MEMORY64_LIST) myDir)->BaseRva);
		for(nMemory64 = 0; nMemory64 < ((PMINIDUMP_MEMORY64_LIST) myDir)->NumberOfMemoryRanges; nMemory64++, ptr += memory64->DataSize)
		{
			memory64 = &(((PMINIDUMP_MEMORY64_LIST) myDir)->MemoryRanges[nMemory64]);
			if(((ULONG64) Source >= memory64->StartOfMemoryRange) && ((ULONG64) Source < memory64->StartOfMemoryRange + memory64->DataSize))
			{
				startPtr = ptr;
				previousPtr = memory64->StartOfMemoryRange;
				previousSize = memory64->DataSize;
				size = (memory64->StartOfMemoryRange + memory64->DataSize) - (ULONG64) Source;
			}
			else if(((ULONG64) Source < memory64->StartOfMemoryRange))
			{
				if(startPtr && (memory64->StartOfMemoryRange == previousPtr + previousSize))
				{
					previousPtr = memory64->StartOfMemoryRange;
					previousSize = memory64->DataSize;
					size += memory64->DataSize;
				}
				else break;
			}

			if(size >= Length)
				return startPtr;
		}
	}
	return NULL;
}