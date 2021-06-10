/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sysenvvalue.h"

const KUHL_M_C kuhl_m_c_sysenv[] = {
	{kuhl_m_sysenv_list,		L"list",	L"List ..."},
	{kuhl_m_sysenv_get,			L"get",		L"Get ..."},
	{kuhl_m_sysenv_set,			L"set",		L"Set ..."},
	{kuhl_m_sysenv_del,			L"del",		L"Del ..."},
};
const KUHL_M kuhl_m_sysenv = {
	L"sysenv",	L"System Environment Value module", NULL,
	ARRAYSIZE(kuhl_m_c_sysenv), kuhl_m_c_sysenv, NULL, NULL
};


NTSTATUS kuhl_m_sysenv_list(int argc, wchar_t * argv[])
{
	NTSTATUS status;
	PVARIABLE_NAME_AND_VALUE buffer;
	DWORD bufferLen = 0;

	status = NtEnumerateSystemEnvironmentValuesEx(VARIABLE_INFORMATION_VALUES, NULL, &bufferLen);
	if((status == STATUS_BUFFER_TOO_SMALL) && bufferLen)
	{
		if(buffer = (PVARIABLE_NAME_AND_VALUE) LocalAlloc(LPTR, bufferLen))
		{
			status = NtEnumerateSystemEnvironmentValuesEx(VARIABLE_INFORMATION_VALUES, buffer, &bufferLen);
			if(NT_SUCCESS(status))
			{
				for(; buffer; buffer = buffer->NextEntryOffset ? (PVARIABLE_NAME_AND_VALUE) ((PBYTE) buffer + buffer->NextEntryOffset) : NULL)
				{
					kprintf(L"Name       : %s\nVendor GUID: ", buffer->Name);
					kuhl_m_sysenv_display_vendorGuid(&buffer->VendorGuid);
					kprintf(L"\nAttributes : %08x (", buffer->Attributes);
					kuhl_m_sysenv_display_attributes(buffer->Attributes);
					kprintf(L")\nLength     : %u\nData       : ", buffer->ValueLength);
					if(buffer->ValueLength && buffer->ValueOffset)
						kull_m_string_wprintf_hex((PBYTE) buffer + buffer->ValueOffset, buffer->ValueLength, 1);
					kprintf(L"\n\n");
				}
			}
			else PRINT_ERROR(L"NtEnumerateSystemEnvironmentValuesEx(data): 0x%08x\n", status);
			LocalFree(buffer);
		}
	}
	else PRINT_ERROR(L"NtEnumerateSystemEnvironmentValuesEx(size): 0x%08x\n", status);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sysenv_get(int argc, wchar_t * argv[])
{
	NTSTATUS status;
	LPCWSTR szName, szGuid;
	UNICODE_STRING uName, uGuid;
	GUID guid;
	DWORD bufferLen = 0, attributes;
	PVOID buffer;

	kull_m_string_args_byName(argc, argv, L"name", &szName, L"Kernel_Lsa_Ppl_Config");
	kull_m_string_args_byName(argc, argv, L"guid", &szGuid, L"{77fa9abd-0359-4d32-bd60-28f4e78f784b}");
	RtlInitUnicodeString(&uName, szName);
	RtlInitUnicodeString(&uGuid, szGuid);

	status = RtlGUIDFromString(&uGuid, &guid);
	if(NT_SUCCESS(status))
	{
		kprintf(L"Name       : %wZ\nVendor GUID: ", &uName);
		kuhl_m_sysenv_display_vendorGuid(&guid);
		kprintf(L"\n");
		status = NtQuerySystemEnvironmentValueEx(&uName, &guid, NULL, &bufferLen, &attributes);
		if((status == STATUS_BUFFER_TOO_SMALL) && bufferLen)
		{
			if(buffer = LocalAlloc(LPTR, bufferLen))
			{
				status = NtQuerySystemEnvironmentValueEx(&uName, &guid, buffer, &bufferLen, &attributes);
				if(NT_SUCCESS(status))
				{
					kprintf(L"Attributes : %08x (", attributes);
					kuhl_m_sysenv_display_attributes(attributes);
					kprintf(L")\nLength     : %u\nData       : ", bufferLen);
					kull_m_string_wprintf_hex(buffer, bufferLen, 1);
					kprintf(L"\n");
				}
				else PRINT_ERROR(L"NtQuerySystemEnvironmentValueEx(data): 0x%08x\n", status);
				LocalFree(buffer);
			}
		}
		else if(status == STATUS_VARIABLE_NOT_FOUND)
			PRINT_ERROR(L"System Environment Variable not found.\n");
		else PRINT_ERROR(L"NtQuerySystemEnvironmentValueEx(size): 0x%08x\n", status);
	}
	else PRINT_ERROR(L"RtlGUIDFromString: 0x%08x\n", status);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sysenv_set(int argc, wchar_t * argv[])
{
	NTSTATUS status;
	LPCWSTR szName, szGuid, szAttributes, szData;
	UNICODE_STRING uName, uGuid;
	GUID guid;
	LPBYTE hex;
	DWORD size, attributes;

	kull_m_string_args_byName(argc, argv, L"name", &szName, MIMIKATZ);
	kull_m_string_args_byName(argc, argv, L"guid", &szGuid, L"{b16b00b5-cafe-babe-0ee0-dabadabad000}");
	kull_m_string_args_byName(argc, argv, L"attributes", &szAttributes, L"1");
	kull_m_string_args_byName(argc, argv, L"data", &szData, L"410020004c00610020005600690065002c002000410020004c00270041006d006f00750072000000");

	RtlInitUnicodeString(&uName, szName);
	RtlInitUnicodeString(&uGuid, szGuid);
	attributes = wcstoul(szAttributes, NULL, 0);

	status = RtlGUIDFromString(&uGuid, &guid);
	if(NT_SUCCESS(status))
	{
		kprintf(L"Name       : %wZ\nVendor GUID: ", &uName);
		kuhl_m_sysenv_display_vendorGuid(&guid);
		kprintf(L"\nAttributes : %08x (", attributes);
		kuhl_m_sysenv_display_attributes(attributes);
		kprintf(L")\n");
		if(kull_m_string_stringToHexBuffer(szData, &hex, &size))
		{
			kprintf(L"Length     : %u\nData       : ", size);
			kull_m_string_wprintf_hex(hex, size, 1);
			kprintf(L"\n\n");
			status = NtSetSystemEnvironmentValueEx(&uName, &guid, hex, size, attributes);
			if(NT_SUCCESS(status))
				kprintf(L"> OK!\n");
			else PRINT_ERROR(L"NtSetSystemEnvironmentValueEx(data): 0x%08x\n", status);
			LocalFree(hex);
		}
	}
	else PRINT_ERROR(L"RtlGUIDFromString: 0x%08x\n", status);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sysenv_del(int argc, wchar_t * argv[])
{
	NTSTATUS status;
	LPCWSTR szName, szGuid, szAttributes;
	UNICODE_STRING uName, uGuid;
	GUID guid;
	DWORD attributes;

	kull_m_string_args_byName(argc, argv, L"name", &szName, MIMIKATZ);
	kull_m_string_args_byName(argc, argv, L"guid", &szGuid, L"{b16b00b5-cafe-babe-0ee0-dabadabad000}");
	kull_m_string_args_byName(argc, argv, L"attributes", &szAttributes, L"1");

	RtlInitUnicodeString(&uName, szName);
	RtlInitUnicodeString(&uGuid, szGuid);
	attributes = wcstoul(szAttributes, NULL, 0);

	status = RtlGUIDFromString(&uGuid, &guid);
	if(NT_SUCCESS(status))
	{
		kprintf(L"Name       : %wZ\nVendor GUID: ", &uName);
		kuhl_m_sysenv_display_vendorGuid(&guid);
		kprintf(L"\nAttributes : %08x (", attributes);
		kuhl_m_sysenv_display_attributes(attributes);
		kprintf(L")\n");

		status = NtSetSystemEnvironmentValueEx(&uName, &guid, NULL, 0, attributes);
		if(NT_SUCCESS(status))
			kprintf(L"> OK!\n");
		else if(status == STATUS_VARIABLE_NOT_FOUND)
			PRINT_ERROR(L"System Environment Variable not found.\n");
		else PRINT_ERROR(L"NtSetSystemEnvironmentValueEx(data): 0x%08x\n", status);
	}
	else PRINT_ERROR(L"RtlGUIDFromString: 0x%08x\n", status);
	return STATUS_SUCCESS;
}

const wchar_t * KUHL_M_SYSENV_ATTRIBUTES[] = {
	L"NON_VOLATILE", L"BOOTSERVICE_ACCESS", L"RUNTIME_ACCESS", L"HARDWARE_ERROR_RECORD", L"AUTHENTICATED_WRITE_ACCESS", L"TIME_BASED_AUTHENTICATED_WRITE_ACCESS", L"APPEND_WRITE",
};
void kuhl_m_sysenv_display_attributes(DWORD attributes)
{
	DWORD i;
	for(i = 0; i < ARRAYSIZE(KUHL_M_SYSENV_ATTRIBUTES); i++)
		if((1 << i) & attributes)
			kprintf(L"%s, ", KUHL_M_SYSENV_ATTRIBUTES[i]);
}

KUHL_M_SYSENV_GUID_STORE KUHL_M_SYSENV_GUIDSTORE[] = {
	{{0xb16b00b5, 0xcafe, 0xbabe, {0x0e, 0xe0, 0xda, 0xba, 0xda, 0xba, 0xd0, 0x00}}, L"KiwiEfiVariables"},
	{{0x8be4df61, 0x93ca, 0x11d2, {0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}}, L"EfiBootVariables"},
	{{0x77fa9abd, 0x0359, 0x4d32, {0xbd, 0x60, 0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b}}, L"ExpSecureBootVendor"},
};
void kuhl_m_sysenv_display_vendorGuid(LPCGUID guid)
{
	DWORD i;
	for(i = 0; i < ARRAYSIZE(KUHL_M_SYSENV_GUIDSTORE); i++)
	{
		if(RtlEqualGuid(guid, &KUHL_M_SYSENV_GUIDSTORE[i].guid))
		{
			kprintf(L"%s - ", KUHL_M_SYSENV_GUIDSTORE[i].name);
			break;
		}
	}
	kull_m_string_displayGUID(guid);
}