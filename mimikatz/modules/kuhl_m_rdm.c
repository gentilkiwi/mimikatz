/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_rdm.h"

const KUHL_M_C kuhl_m_c_rdm[] = {
	{kuhl_m_rdm_version,	L"version",	NULL},
	{kuhl_m_rdm_list,		L"list", NULL},
};
const KUHL_M kuhl_m_rdm = {
	L"rdm", L"RF module for RDM(830 AL) device", NULL,
	ARRAYSIZE(kuhl_m_c_rdm), kuhl_m_c_rdm, NULL, NULL
};

NTSTATUS kuhl_m_rdm_version(int argc, wchar_t * argv[])
{
	PRDM_DEVICE devices, cur;
	ULONG count;
	PSTR version;

	if(rdm_devices_get(&devices, &count))
	{
		for(cur = devices; cur; cur = cur->next)
		{
			kprintf(L"[%3u] ", cur->id);
			if(rdm_get_version(cur->hDevice, &version))
			{
				kprintf(L"%S\n", version);
				LocalFree(version);
			}
		}
		rdm_devices_free(devices);
	}
	else PRINT_ERROR(L"No device found\n");
	return STATUS_SUCCESS;
}


NTSTATUS kuhl_m_rdm_list(int argc, wchar_t * argv[])
{
	PRDM_DEVICE devices, cur;
	ULONG count;
	if(rdm_devices_get(&devices, &count))
	{
		for(cur = devices; cur; cur = cur->next)
			kprintf(L"\n[%3u] %s\n  Vendor: 0x%04x, Product: 0x%04x, Version: 0x%04x\n", cur->id, cur->DevicePath, cur->hidAttributes.VendorID, cur->hidAttributes.ProductID, cur->hidAttributes.VersionNumber);
		rdm_devices_free(devices);
	}
	else PRINT_ERROR(L"No device found\n");
	return STATUS_SUCCESS;
}