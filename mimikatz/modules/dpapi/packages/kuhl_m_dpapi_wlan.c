/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi_wlan.h"

NTSTATUS kuhl_m_dpapi_wifi(int argc, wchar_t * argv[])
{
	PBYTE pFile, hex, dataOut;
	DWORD dwData, lenHex, lenDataOut;
	LPWSTR dataU, dataSSID, dataF, dataAuth;
	LPCWSTR infile;

	if(kull_m_string_args_byName(argc, argv, L"in", &infile, NULL))
	{
		if(kull_m_file_readData(infile, &pFile, &dwData))
		{
			if(dataU = kull_m_string_qad_ansi_to_unicode((const char *) pFile))
			{
				if(kull_m_string_quickxml_simplefind(dataU, L"name", &dataF))
				{
					kprintf(L"Profile \'%s\'\n\n", dataF);
					LocalFree(dataF);
				}
				if(kull_m_string_quickxml_simplefind(dataU, L"SSID", &dataSSID))
				{
					kprintf(L" * SSID ");
					if(kull_m_string_quickxml_simplefind(dataSSID, L"name", &dataF))
					{
						kprintf(L"name     : %s\n", dataF);
						LocalFree(dataF);
					}
					else if(kull_m_string_quickxml_simplefind(dataSSID, L"hex", &dataF))
					{
						kprintf(L"hex      : %s\n", dataF);
						LocalFree(dataF);
					}
					else kprintf(L"?\n");
					LocalFree(dataSSID);
				}
				if(kull_m_string_quickxml_simplefind(dataU, L"authentication", &dataAuth))
				{
					kprintf(L" * Authentication: %s\n", dataAuth);
					if(kull_m_string_quickxml_simplefind(dataU, L"encryption", &dataF))
					{
						kprintf(L" * Encryption    : %s\n", dataF);
						LocalFree(dataF);
					}
					if(kull_m_string_quickxml_simplefind(dataU, L"keyMaterial", &dataF))
					{
						if(kull_m_string_stringToHexBuffer(dataF, &hex, &lenHex))
						{
							kprintf(L"\n");
							kull_m_dpapi_blob_quick_descr(0, hex);
							if(kuhl_m_dpapi_unprotect_raw_or_blob(hex, lenHex, NULL, argc, argv, NULL, 0, (LPVOID *) &dataOut, &lenDataOut, NULL))
							{
								kprintf(L" * Key Material  : ");
								if(_wcsicmp(dataAuth, L"WEP") == 0)
								{
									kprintf(L"(hex) ");
									kull_m_string_wprintf_hex(dataOut, lenDataOut, 0);
								}
								else
									kprintf(L"%.*S", lenDataOut, dataOut);
								kprintf(L"\n");
								LocalFree(dataOut);
							}
							LocalFree(hex);
						}
						LocalFree(dataF);
					}
					LocalFree(dataAuth);
				}
				LocalFree(dataU);
			}
			LocalFree(pFile);
		}
		else PRINT_ERROR_AUTO(L"kull_m_file_readData");
	}
	else PRINT_ERROR(L"Input Wlan XML profile needed (/in:file)\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_dpapi_wwan(int argc, wchar_t * argv[])
{
	PBYTE pFile, hex, dataOut;
	DWORD dwData, lenHex, lenDataOut;
	LPWSTR dataU, dataF;
	LPCWSTR infile;

	if(kull_m_string_args_byName(argc, argv, L"in", &infile, NULL))
	{
		if(kull_m_file_readData(infile, &pFile, &dwData))
		{
			if(dataU = kull_m_string_qad_ansi_to_unicode((const char *) pFile))
			{
				if(kull_m_string_quickxml_simplefind(dataU, L"Name", &dataF))
				{
					kprintf(L"Profile \'%s\'\n\n", dataF);
					LocalFree(dataF);
				}
				if(kull_m_string_quickxml_simplefind(dataU, L"AccessString", &dataF))
				{
					kprintf(L" * AccessString    : %s\n", dataF);
					LocalFree(dataF);
				}
				if(kull_m_string_quickxml_simplefind(dataU, L"SubscriberID", &dataF))
				{
					if(kull_m_string_stringToHexBuffer(dataF, &hex, &lenHex))
					{
						kprintf(L"\n");
						kull_m_dpapi_blob_quick_descr(0, hex);
						if(kuhl_m_dpapi_unprotect_raw_or_blob(hex, lenHex, NULL, argc, argv, NULL, 0, (LPVOID *) &dataOut, &lenDataOut, NULL))
						{
							kprintf(L" * SubscriberID  : ");
							kull_m_string_wprintf_hex(dataOut, lenDataOut, 0);
							kprintf(L"\n");
							kprintf(L"%.*s", lenDataOut / sizeof(wchar_t), dataOut);
							LocalFree(dataOut);
						}
						LocalFree(hex);
					}
					LocalFree(dataF);
				}
				LocalFree(dataU);
			}
			LocalFree(pFile);
		}
		else PRINT_ERROR_AUTO(L"kull_m_file_readData");
	}
	else PRINT_ERROR(L"Input Wwan XML profile needed (/in:file)\n");
	return STATUS_SUCCESS;
}