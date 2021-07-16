/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com

	Vincent LE TOUX
	http://pingcastle.com / http://mysmartlogon.com
	vincent.letoux@gmail.com

	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "utils.h"
#include <SubAuth.h>

NTSTATUS NTAPI ksub_Msv1_0SubAuthenticationRoutine(IN NETLOGON_LOGON_INFO_CLASS LogonLevel, IN PVOID LogonInformation, IN ULONG Flags, IN PUSER_ALL_INFORMATION UserAll, OUT PULONG WhichFields, OUT PULONG UserFlags, OUT PBOOLEAN Authoritative, OUT PLARGE_INTEGER LogoffTime, OUT PLARGE_INTEGER KickoffTime);