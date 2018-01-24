/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_cabinet.h"

int DIAMONDAPI fnFilePlaced(PCCAB pccab, IN LPSTR pszFile, long cbFile, BOOL fContinuation, void FAR *pv)
{
	return 0;
}

void HUGE * FAR DIAMONDAPI fnMemAlloc(ULONG cb)
{
	return LocalAlloc(LPTR, cb);
}

void FAR DIAMONDAPI fnMemFree(void HUGE *memory)
{
	LocalFree(memory);
}

INT_PTR FAR DIAMONDAPI fnFileOpen(IN LPSTR pszFile, int oflag, int pmode, int FAR *err, void FAR *pv)
{
	HANDLE hFile;
	DWORD dwDesiredAccess;
	if(oflag & _O_RDWR)
		dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
	else if(oflag & _O_WRONLY)
		dwDesiredAccess = GENERIC_WRITE;
	else dwDesiredAccess = GENERIC_READ;
	hFile = CreateFileA(pszFile, dwDesiredAccess, FILE_SHARE_READ, NULL, (oflag & _O_CREAT) ? CREATE_ALWAYS : OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
		*err = GetLastError();
	return (INT_PTR) hFile;
}

UINT FAR DIAMONDAPI fnFileRead(INT_PTR hf, void FAR *memory, UINT cb, int FAR *err, void FAR *pv)
{
	DWORD dwBytesRead;
	if(!ReadFile((HANDLE) hf, memory, cb, &dwBytesRead, NULL))
	{
		dwBytesRead = (DWORD) -1;
		*err = GetLastError();
	}
	return dwBytesRead;
}

UINT FAR DIAMONDAPI fnFileWrite(INT_PTR hf, void FAR *memory, UINT cb, int FAR *err, void FAR *pv)
{
	DWORD dwBytesWritten;
	if(!WriteFile((HANDLE) hf, memory, cb, &dwBytesWritten, NULL))
	{
		dwBytesWritten = (DWORD)-1;
		*err = GetLastError();
	}
	return dwBytesWritten;
}

int FAR DIAMONDAPI fnFileClose(INT_PTR hf, int FAR *err, void FAR *pv)
{
	INT iResult = 0; 
	if(!CloseHandle((HANDLE) hf))
	{
		*err = GetLastError();
		iResult = -1;
	}
	return iResult;
}

long FAR DIAMONDAPI fnFileSeek(INT_PTR hf, long dist, int seektype, int FAR *err, void FAR *pv)
{
	INT iResult = 0;
	iResult = SetFilePointer((HANDLE) hf, dist, NULL, seektype);
	if(iResult == INVALID_SET_FILE_POINTER)
		*err = GetLastError();
	return iResult;
}

 int FAR DIAMONDAPI fnFileDelete(IN LPSTR pszFile, int FAR *err, void FAR *pv)
{
	INT iResult = 0;
	if(!DeleteFileA(pszFile))
	{
		*err = GetLastError();
		iResult = -1;
	}
	return iResult;
}

BOOL DIAMONDAPI fnGetTempFileName(OUT char *pszTempName, IN int cbTempName, void FAR *pv)
{
	BOOL bSucceeded = FALSE;
	CHAR pszTempPath[MAX_PATH], pszTempFile[MAX_PATH];
	if(GetTempPathA(MAX_PATH, pszTempPath))
	{
		if(GetTempFileNameA(pszTempPath, "CABINET", 0, pszTempFile) != 0)
		{
			DeleteFileA(pszTempFile);
			bSucceeded = SUCCEEDED(StringCbCopyA(pszTempName, cbTempName, pszTempFile));
		}
	}
	return bSucceeded;
}

BOOL DIAMONDAPI fnGetNextCabinet(PCCAB pccab, ULONG cbPrevCab, void FAR *pv)
{
	return SUCCEEDED(StringCchPrintfA(pccab->szCab, ARRAYSIZE(pccab->szCab), "%s_%02d.cab", pv, pccab->iCab));
}

long DIAMONDAPI fnStatus(UINT typeStatus, ULONG cb1, ULONG cb2, void FAR *pv)
{
	return 0;
}

INT_PTR DIAMONDAPI fnGetOpenInfo(IN LPSTR pszName, USHORT *pdate, USHORT *ptime, USHORT *pattribs, int FAR *err, void FAR *pv)
{
	HANDLE hFile;
	FILETIME fileTime;
	BY_HANDLE_FILE_INFORMATION fileInfo;
	hFile = (HANDLE) fnFileOpen(pszName, _O_RDONLY, 0, err, pv);
	if (hFile != INVALID_HANDLE_VALUE) 
	{
		if(GetFileInformationByHandle(hFile, &fileInfo) && FileTimeToLocalFileTime(&fileInfo.ftCreationTime, &fileTime) && FileTimeToDosDateTime(&fileTime, pdate, ptime))
		{
			*pattribs = (USHORT) fileInfo.dwFileAttributes;
			*pattribs &= (_A_RDONLY | _A_HIDDEN | _A_SYSTEM | _A_ARCH);
		}
		else
		{
			fnFileClose((INT_PTR) hFile, err, pv);
			hFile = INVALID_HANDLE_VALUE;
		}
	}
	return (INT_PTR) hFile;
}

LPCSTR FCIErrorToString(FCIERROR err)
{
	switch (err)
	{
	case FCIERR_NONE:
		return "No error";
	case FCIERR_OPEN_SRC:
		return "Failure opening file to be stored in cabinet";
	case FCIERR_READ_SRC:
		return "Failure reading file to be stored in cabinet";
	case FCIERR_ALLOC_FAIL:
		return "Insufficient memory in FCI";
	case FCIERR_TEMP_FILE:
		return "Could not create a temporary file";
	case FCIERR_BAD_COMPR_TYPE:
		return "Unknown compression type";
	case FCIERR_CAB_FILE:
		return "Could not create cabinet file";
	case FCIERR_USER_ABORT:
		return "Client requested abort";
	case FCIERR_MCI_FAIL:
		return "Failure compressing data";
	default:
		return "Unknown error";
	}
}

PKIWI_CABINET kull_m_cabinet_create(LPSTR cabinetName)
{
	PKIWI_CABINET cab = NULL;
	if(cab = (PKIWI_CABINET) LocalAlloc(LPTR, sizeof(KIWI_CABINET)))
	{
		cab->ccab.cb = 0x4000000;
		cab->ccab.cbFolderThresh = 0x4000000;
		cab->ccab.setID = 42;
		cab->ccab.iCab = 0;
		cab->ccab.iDisk = 0;
		if(fnGetNextCabinet(&cab->ccab, 0, cabinetName))
		{
			if(GetCurrentDirectoryA(ARRAYSIZE(cab->ccab.szCabPath), cab->ccab.szCabPath))
				if(SUCCEEDED(StringCchCatA(cab->ccab.szCabPath, ARRAYSIZE(cab->ccab.szCabPath), "\\")))
					if(!(cab->hfci = FCICreate(&cab->erf, fnFilePlaced, fnMemAlloc, fnMemFree, fnFileOpen, fnFileRead, fnFileWrite, fnFileClose, fnFileSeek, fnFileDelete, fnGetTempFileName, &cab->ccab, cabinetName)))
						PRINT_ERROR(L"FCICreate failed with error code %d: %S\n", cab->erf.erfOper, FCIErrorToString((FCIERROR) cab->erf.erfOper));
		}
		else PRINT_ERROR(L"Failed to initialize the cabinet information structure.\n");
		if(!cab->hfci)
			cab = (PKIWI_CABINET) LocalFree(cab);
	}
	return cab;
}

BOOL kull_m_cabinet_add(PKIWI_CABINET cab, LPSTR sourceFile, OPTIONAL LPSTR destFile)
{
	BOOL status = FALSE;
	if(!destFile)
	{
		destFile = strrchr(sourceFile, '\\');
		if(destFile)
			destFile++;
		else destFile = sourceFile;
	}
	if(!(status = FCIAddFile(cab->hfci, sourceFile, destFile, FALSE, fnGetNextCabinet, fnStatus, fnGetOpenInfo, TCOMPfromLZXWindow(21))))
		PRINT_ERROR(L"FCIAddFile failed with error code %d: %S (%S -> %S)\n", cab->erf.erfOper, FCIErrorToString((FCIERROR) cab->erf.erfOper), sourceFile, destFile);
	return status;
}

BOOL kull_m_cabinet_close(PKIWI_CABINET cab)
{
	BOOL status = FALSE;
	if(!(status = FCIFlushCabinet(cab->hfci, FALSE, fnGetNextCabinet, fnStatus)))
		PRINT_ERROR(L"FCIFlushCabinet failed with error code %d: %S\n", cab->erf.erfOper, FCIErrorToString((FCIERROR) cab->erf.erfOper));
	if(!FCIDestroy(cab->hfci))
		PRINT_ERROR(L"FCIDestroy failed with error code %d: %S\n", cab->erf.erfOper, FCIErrorToString((FCIERROR) cab->erf.erfOper));
	LocalFree(cab);
	return status;
}
