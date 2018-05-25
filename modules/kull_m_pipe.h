/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"

BOOL kull_m_pipe_server(LPCWCHAR pipeName, HANDLE *phPipe);
BOOL kull_m_pipe_server_connect(HANDLE hPipe);
BOOL kull_m_pipe_client(LPCWCHAR pipeName, PHANDLE phPipe);
BOOL kull_m_pipe_read(HANDLE hPipe, LPBYTE *buffer, DWORD *size);
BOOL kull_m_pipe_write(HANDLE hPipe, LPCVOID buffer, DWORD size);
BOOL kull_m_pipe_close(PHANDLE phPipe);