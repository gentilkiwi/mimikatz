/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_pipe.h"

BOOL kull_m_pipe_server(LPCWCHAR pipeName, HANDLE *phPipe)
{
	BOOL status = FALSE;
	*phPipe = CreateNamedPipe(pipeName,  PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 0, 0, NMPWAIT_USE_DEFAULT_WAIT, NULL);
	if(!(status = (*phPipe && (*phPipe != INVALID_HANDLE_VALUE))))
		PRINT_ERROR_AUTO(L"CreateNamedPipe");
	return status;
}

BOOL kull_m_pipe_server_connect(HANDLE hPipe)
{
	BOOL status = FALSE;
	if(!(status = (ConnectNamedPipe(hPipe, NULL) || (GetLastError() == ERROR_PIPE_CONNECTED))))
		PRINT_ERROR_AUTO(L"ConnectNamedPipe");
	return status;
}

BOOL kull_m_pipe_client(LPCWCHAR pipeName, PHANDLE phPipe)
{
	BOOL status = FALSE;
	DWORD dwMode = PIPE_READMODE_MESSAGE | PIPE_WAIT;
	if(WaitNamedPipe(pipeName, NMPWAIT_USE_DEFAULT_WAIT))
	{
		*phPipe = CreateFile(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if(*phPipe && (*phPipe != INVALID_HANDLE_VALUE))
		{
			if(!(status = SetNamedPipeHandleState(*phPipe, &dwMode, NULL, NULL)))
				PRINT_ERROR_AUTO(L"SetNamedPipeHandleState");
		}
		else PRINT_ERROR_AUTO(L"CreateFile");
	}
	else PRINT_ERROR_AUTO(L"WaitNamedPipe");
	return status;
}

BOOL kull_m_pipe_read(HANDLE hPipe, LPBYTE *buffer, DWORD *size)
{
	BOOL status = FALSE;
	DWORD szReaded, szBuffer = 0;
	BYTE * tmpBuffer = NULL; DWORD szTmpBuffer = 0;

	*size = 0;
	*buffer = NULL;
	do
	{
		if(*buffer)
		{
			tmpBuffer = *buffer;
			szTmpBuffer = szBuffer;
		}
	
		szBuffer += 2048;
		if(*buffer = (BYTE *) LocalAlloc(LPTR, szBuffer))
		{
			if(tmpBuffer)
			{
				RtlCopyMemory(*buffer, tmpBuffer, szTmpBuffer);
				tmpBuffer = (BYTE *) LocalFree(tmpBuffer);
			}

			if(status = ReadFile(hPipe, *buffer + szTmpBuffer, 2048, &szReaded, NULL))
			{
				*size = szTmpBuffer + szReaded;
				break;
			}
		}
	} while(GetLastError() == ERROR_MORE_DATA);

	if(!status)
	{
		PRINT_ERROR_AUTO(L"ReadFile");
		*buffer = (BYTE *) LocalFree(*buffer);
		*size = 0;
	}
	return status;
}

BOOL kull_m_pipe_write(HANDLE hPipe, LPCVOID buffer, DWORD size)
{
	BOOL status = FALSE;
	DWORD nbWritten;
	if(WriteFile(hPipe, buffer, size, &nbWritten, NULL) && (size == nbWritten))
	{
		if(!(status = FlushFileBuffers(hPipe)))
			PRINT_ERROR_AUTO(L"FlushFileBuffers");
	}
	else PRINT_ERROR_AUTO(L"WriteFile");
	return status;
}

BOOL kull_m_pipe_close(PHANDLE phPipe)
{
	BOOL status = FALSE;
	DWORD flags = 0;
	if(*phPipe && (*phPipe != INVALID_HANDLE_VALUE))
	{
		if(GetNamedPipeInfo(*phPipe, &flags, NULL, NULL, NULL) || (GetLastError() == ERROR_PIPE_NOT_CONNECTED))
		{
			if(flags & PIPE_SERVER_END)
			{
				if(!DisconnectNamedPipe(*phPipe))
					PRINT_ERROR_AUTO(L"DisconnectNamedPipe");
			}
			if(status = CloseHandle(*phPipe))
				*phPipe = INVALID_HANDLE_VALUE;
			else PRINT_ERROR_AUTO(L"CloseHandle");
		}
		else PRINT_ERROR_AUTO(L"GetNamedPipeInfo");
	}
	return status;
}