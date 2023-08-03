/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include <ntstatus.h>
#define WIN32_NO_STATUS
#define SECURITY_WIN32
#define CINTERFACE
#define COBJMACROS
#include <windows.h>
#include <sspi.h>
#include <sddl.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>
#include <stdio.h>
#include <wchar.h>
#include "../modules/kull_m_output.h"
//#define KERBEROS_TOOLS
//#define SERVICE_INCONTROL
#define NET_MODULE
#if defined(_M_ARM64)
	#define MIMIKATZ_ARCH L"arm64"
#elif defined(_M_X64)
	#define MIMIKATZ_ARCH L"x64"
#elif defined(_M_IX86)
	#define MIMIKATZ_ARCH L"x86"
#endif

#define MIMIKATZ				L"mimikatz"
#define MIMIKATZ_VERSION		L"2.2.0"
#define MIMIKATZ_CODENAME		L"A La Vie, A L\'Amour"
#define MIMIKATZ_MAX_WINBUILD	L"19041"
#define MIMIKATZ_FULL			MIMIKATZ L" " MIMIKATZ_VERSION L" (" MIMIKATZ_ARCH L") #" MIMIKATZ_MAX_WINBUILD L" " TEXT(__DATE__) L" " TEXT(__TIME__)
#define MIMIKATZ_SECOND			L"\"" MIMIKATZ_CODENAME L"\""
#define MIMIKATZ_DEFAULT_LOG	MIMIKATZ L".log"
#define MIMIKATZ_DRIVER			L"mimidrv"
#define MIMIKATZ_KERBEROS_EXT	L"kirbi"
#define MIMIKATZ_SERVICE		MIMIKATZ L"svc"

#if defined(_WINDLL)
	#define MIMIKATZ_AUTO_COMMAND_START		0
#else
	#define MIMIKATZ_AUTO_COMMAND_START		1
#endif

#if defined(_POWERKATZ)
	#define MIMIKATZ_AUTO_COMMAND_STRING	L"powershell"
#else
	#define MIMIKATZ_AUTO_COMMAND_STRING	L"commandline"
#endif

#if !defined(NT_SUCCESS)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#if !defined(PRINT_ERROR)
#define PRINT_ERROR(...) (kprintf(L"ERROR " TEXT(__FUNCTION__) L" ; " __VA_ARGS__))
#endif

#if !defined(PRINT_ERROR_AUTO)
#define PRINT_ERROR_AUTO(func) (kprintf(L"ERROR " TEXT(__FUNCTION__) L" ; " func L" (0x%08x)\n", GetLastError()))
#endif

#if !defined(W00T)
#define W00T(...) (kprintf(TEXT(__FUNCTION__) L" w00t! ; " __VA_ARGS__))
#endif

DWORD MIMIKATZ_NT_MAJOR_VERSION, MIMIKATZ_NT_MINOR_VERSION, MIMIKATZ_NT_BUILD_NUMBER;

#if !defined(MS_ENH_RSA_AES_PROV_XP)
#define MS_ENH_RSA_AES_PROV_XP	L"Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)"
#endif

#if !defined(MS_PLATFORM_CRYPTO_PROVIDER)
#define MS_PLATFORM_CRYPTO_PROVIDER	L"Microsoft Platform Crypto Provider"
#endif

#if !defined(NCRYPT_PCP_PLATFORM_TYPE_PROPERTY)
#define NCRYPT_PCP_PLATFORM_TYPE_PROPERTY    L"PCP_PLATFORM_TYPE"
#endif

#if !defined(TPM_RSA_SRK_SEAL_KEY)
#define TPM_RSA_SRK_SEAL_KEY			L"MICROSOFT_PCP_KSP_RSA_SEAL_KEY_3BD1C4BF-004E-4E2F-8A4D-0BF633DCB074"
#endif

#if !defined(NCRYPT_SEALING_FLAG)
#define NCRYPT_SEALING_FLAG				0x00000100
#endif

#if !defined(SCARD_PROVIDER_CARD_MODULE)
#define SCARD_PROVIDER_CARD_MODULE 0x80000001
#endif

#define RtlEqualGuid(L1, L2) (RtlEqualMemory(L1, L2, sizeof(GUID)))

#define SIZE_ALIGN(size, alignment)	(size + ((size % alignment) ? (alignment - (size % alignment)) : 0))
#define KIWI_NEVERTIME(filetime)	(*(PLONGLONG) filetime = MAXLONGLONG)

#define LM_NTLM_HASH_LENGTH	16

#define KULL_M_WIN_BUILD_XP		2600
#define KULL_M_WIN_BUILD_2K3	3790
#define KULL_M_WIN_BUILD_VISTA	6000
#define KULL_M_WIN_BUILD_7		7600
#define KULL_M_WIN_BUILD_8		9200
#define KULL_M_WIN_BUILD_BLUE	9600
#define KULL_M_WIN_BUILD_10_1507	10240
#define KULL_M_WIN_BUILD_10_1511	10586
#define KULL_M_WIN_BUILD_10_1607	14393
#define KULL_M_WIN_BUILD_10_1703	15063
#define KULL_M_WIN_BUILD_10_1709	16299
#define KULL_M_WIN_BUILD_10_1803	17134
#define KULL_M_WIN_BUILD_10_1809	17763
#define KULL_M_WIN_BUILD_10_1903	18362
#define KULL_M_WIN_BUILD_10_1909	18363
#define KULL_M_WIN_BUILD_10_2004	19041
#define KULL_M_WIN_BUILD_10_20H2	19042
#define KULL_M_WIN_BUILD_10_21H2	19044
#define KULL_M_WIN_BUILD_2022		20348
#define KULL_M_WIN_BUILD_11_22H2	22621

#define KULL_M_WIN_MIN_BUILD_XP		2500
#define KULL_M_WIN_MIN_BUILD_2K3	3000
#define KULL_M_WIN_MIN_BUILD_VISTA	5000
#define KULL_M_WIN_MIN_BUILD_7		7000
#define KULL_M_WIN_MIN_BUILD_8		8000
#define KULL_M_WIN_MIN_BUILD_BLUE	9400
#define KULL_M_WIN_MIN_BUILD_10		9800
#define KULL_M_WIN_MIN_BUILD_11		22000

/* mimikatz 3 transition */
#define PRINT_ERROR_NUMBER(func, error)	PRINT_ERROR(func L": 0x%08x\n", error)

#define GET_CLI_ARG(name, var) (kull_m_string_args_byName(argc, argv, name, var, NULL))
#define GET_CLI_ARG_DEF(name, var, def) (kull_m_string_args_byName(argc, argv, name, var, def))
#define GET_CLI_ARG_PRESENT(name) (kull_m_string_args_byName(argc, argv, name, NULL, NULL))

#define kprintf_level(subject, ...)	kprintf(L"%*s" subject, level << 1, L"", __VA_ARGS__)

#define kprinthex(lpData, cbData) kull_m_string_wprintf_hex(lpData, (DWORD) cbData, 0); kprintf(L"\n")
#define kprinthex16(lpData, cbData) kull_m_string_wprintf_hex(lpData, (DWORD) cbData, 1 | (16 << 16)); kprintf(L"\n")

#define kull_m_cli_guid(pGuid, bNewLine) kull_m_string_displayGUID(pGuid); if(bNewLine) kprintf(L"\n")
#define kull_m_cli_sid(pSid, bNewLine) kull_m_string_displaySID(pSid); if(bNewLine) kprintf(L"\n")

#define kull_m_crypto_Base64StringToBinary kull_m_string_quick_base64_to_Binary