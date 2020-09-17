/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"

typedef NTSTATUS (* PKUHL_M_C_FUNC) (int argc, wchar_t * args[]);
typedef NTSTATUS (* PKUHL_M_C_FUNC_INIT) ();

typedef struct _KUHL_M_C {
	const PKUHL_M_C_FUNC pCommand;
	const wchar_t * command;
	const wchar_t * description;
} KUHL_M_C, *PKUHL_M_C;

typedef struct _KUHL_M {
	const wchar_t * shortName;
	const wchar_t * fullName;
	const wchar_t * description;
	const unsigned short nbCommands;
	const KUHL_M_C * commands;
	const PKUHL_M_C_FUNC_INIT pInit;
	const PKUHL_M_C_FUNC_INIT pClean;
} KUHL_M, *PKUHL_M;
