/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "utils.h"

void CALLBACK kappfree_startW(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow)
{
	HANDLE monToken, monSuperToken;
	PROCESS_INFORMATION mesInfosProcess;
	STARTUPINFO mesInfosDemarrer;

	RtlZeroMemory(&mesInfosProcess, sizeof(PROCESS_INFORMATION));
	RtlZeroMemory(&mesInfosDemarrer, sizeof(STARTUPINFO));
	mesInfosDemarrer.cb = sizeof(STARTUPINFO);

	if(OpenProcessToken(GetCurrentProcess(), TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY, &monToken))
	{
		if(CreateRestrictedToken(monToken, SANDBOX_INERT, 0, NULL, 0, NULL, 0, NULL, &monSuperToken))
		{
			if(CreateProcessAsUser(monSuperToken, NULL, lpszCmdLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &mesInfosDemarrer, &mesInfosProcess))
			{
				CloseHandle(mesInfosProcess.hThread);
				CloseHandle(mesInfosProcess.hProcess);
			}
			CloseHandle(monSuperToken);
		}
		CloseHandle(monToken);
	}
}