/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kkll_m_filters.h"

const ULONG MF_OffSetTable[KiwiOsIndex_MAX][MF_MAX] =
{
				/* CallbackOffset, CallbackPreOffset, CallbackPostOffset, CallbackVolumeNameOffset */
#ifdef _M_IX86
/* UNK	*/	{0},
/* XP	*/	{0x007c, 0x000c, 0x0010, 0x002c},
/* 2K3	*/	{0x007c, 0x000c, 0x0010, 0x002c},
/* VISTA*/	{0x004c, 0x000c, 0x0010, 0x0030},
/* 7	*/	{0x004c, 0x000c, 0x0010, 0x0030},
/* 8	*/	{0x004c, 0x000c, 0x0010, 0x0030},
/* BLUE	*/	{0x004c, 0x000c, 0x0010, 0x0030},
/* 10_1507*/{0x004c, 0x000c, 0x0010, 0x0040},
/* 10_1511*/{0x004c, 0x000c, 0x0010, 0x0040},
/* 10_1607*/{0x004c, 0x000c, 0x0010, 0x0040},
/* 10_1703*/{0x004c, 0x000c, 0x0010, 0x0040},
/* 10_1709*/{0x004c, 0x000c, 0x0010, 0x0040},
/* 10_1803*/{0x004c, 0x000c, 0x0010, 0x0040},
/* 10_1809*/{0x004c, 0x000c, 0x0010, 0x0040},
#else
/* UNK	*/	{0},
/* XP	*/	{0},
/* 2K3	*/	{0x00e8, 0x0018, 0x0020, 0x0048},
/* VISTA*/	{0x0090, 0x0018, 0x0020, 0x0050},
/* 7	*/	{0x0090, 0x0018, 0x0020, 0x0050},
/* 8	*/	{0x0090, 0x0018, 0x0020, 0x0050},
/* BLUE	*/	{0x0090, 0x0018, 0x0020, 0x0050},
/* 10_1507*/{0x0090, 0x0018, 0x0020, 0x0060},
/* 10_1511*/{0x0090, 0x0018, 0x0020, 0x0060},
/* 10_1607*/{0x0090, 0x0018, 0x0020, 0x0060},
/* 10_1703*/{0x0090, 0x0018, 0x0020, 0x0060},
/* 10_1709*/{0x0090, 0x0018, 0x0020, 0x0060},
/* 10_1803*/{0x0090, 0x0018, 0x0020, 0x0060},
/* 10_1809*/{0x0090, 0x0018, 0x0020, 0x0060},
#endif
};

NTSTATUS kkll_m_filters_list(PKIWI_BUFFER outBuffer)
{
	NTSTATUS status;
	ULONG ActualNumberDriverObjects, sizeOfDriverObjects;
	PDRIVER_OBJECT * DriverObjectList = NULL;
	ULONG i;

	status = IoEnumerateRegisteredFiltersList(NULL, 0, &ActualNumberDriverObjects);
	if((status == STATUS_BUFFER_TOO_SMALL) && ActualNumberDriverObjects)
	{
		sizeOfDriverObjects = sizeof(PDRIVER_OBJECT) * ActualNumberDriverObjects;
		if(DriverObjectList = (PDRIVER_OBJECT *) ExAllocatePoolWithTag(NonPagedPool, sizeOfDriverObjects, POOL_TAG))
		{
			status = IoEnumerateRegisteredFiltersList(DriverObjectList, sizeOfDriverObjects, &ActualNumberDriverObjects);
			for(i = 0; NT_SUCCESS(status) && (i < ActualNumberDriverObjects); i++)
			{
				status = kprintf(outBuffer, L"[%.2u] %wZ\n",i , &(DriverObjectList[i]->DriverName));
				ObDereferenceObject(DriverObjectList[i]);
			}
			ExFreePoolWithTag(DriverObjectList, POOL_TAG);
		}
	}
	return status;
}

const WCHAR *irpToName[] = {
	L"CREATE",
	L"CREATE_NAMED_PIPE",
	L"CLOSE",
	L"READ",
	L"WRITE",
	L"QUERY_INFORMATION",
	L"SET_INFORMATION",
	L"QUERY_EA",
	L"SET_EA",
	L"FLUSH_BUFFERS",
	L"QUERY_VOLUME_INFORMATION",
	L"SET_VOLUME_INFORMATION",
	L"DIRECTORY_CONTROL",
	L"FILE_SYSTEM_CONTROL",
	L"DEVICE_CONTROL",
	L"INTERNAL_DEVICE_CONTROL",
	L"SHUTDOWN",
	L"LOCK_CONTROL",
	L"CLEANUP",
	L"CREATE_MAILSLOT",
	L"QUERY_SECURITY",
	L"SET_SECURITY",
	L"POWER",
	L"SYSTEM_CONTROL",
	L"DEVICE_CHANGE",
	L"QUERY_QUOTA",
	L"SET_QUOTA",
	L"PNP",
};

NTSTATUS kkll_m_minifilters_list(PKIWI_BUFFER outBuffer)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG NumberFiltersReturned, NumberInstancesReturned, sizeOfBuffer;
	PFLT_FILTER *FilterList = NULL;
	PFLT_INSTANCE *InstanceList = NULL;
	PFLT_VOLUME Volume = NULL;
	PFILTER_FULL_INFORMATION myFilterFullInformation = NULL;
	PVOID pCallBack, preCallBack, postCallBack;
	ULONG i, j, k;

	status = FltEnumerateFilters(NULL, 0, &NumberFiltersReturned); 
	if((status == STATUS_BUFFER_TOO_SMALL) && NumberFiltersReturned)
	{
		sizeOfBuffer = sizeof(PFLT_FILTER) * NumberFiltersReturned;
		if(FilterList = (PFLT_FILTER *) ExAllocatePoolWithTag(NonPagedPool, sizeOfBuffer, POOL_TAG))
		{
			status = FltEnumerateFilters(FilterList, sizeOfBuffer, &NumberFiltersReturned); 
			for(i = 0; NT_SUCCESS(status) && (i < NumberFiltersReturned); i++)
			{
				status = FltGetFilterInformation(FilterList[i], FilterFullInformation, NULL, 0, &sizeOfBuffer);
				if((status == STATUS_BUFFER_TOO_SMALL) && sizeOfBuffer)
				{
					if(myFilterFullInformation = (PFILTER_FULL_INFORMATION) ExAllocatePoolWithTag(NonPagedPool, sizeOfBuffer, POOL_TAG))
					{
						status = FltGetFilterInformation(FilterList[i], FilterFullInformation, myFilterFullInformation, sizeOfBuffer, &sizeOfBuffer);
						if(NT_SUCCESS(status))
						{
							status = kprintf(outBuffer, L"[%.2u] %.*s\n", i, myFilterFullInformation->FilterNameLength/sizeof(WCHAR), myFilterFullInformation->FilterNameBuffer);
							if(NT_SUCCESS(status))
							{
								status = FltEnumerateInstances(NULL, FilterList[i], NULL, 0, &NumberInstancesReturned);
								if((status == STATUS_BUFFER_TOO_SMALL) && NumberInstancesReturned)
								{
									if(InstanceList = (PFLT_INSTANCE *) ExAllocatePoolWithTag(NonPagedPool, sizeof(PFLT_INSTANCE) * NumberInstancesReturned, POOL_TAG))
									{
										status = FltEnumerateInstances(NULL, FilterList[i], InstanceList, NumberInstancesReturned, &NumberInstancesReturned);
										for(j = 0; NT_SUCCESS(status) && (j < NumberInstancesReturned); j++)
										{
											if(NT_SUCCESS(FltGetVolumeFromInstance(InstanceList[j], &Volume)))
											{
												status = kprintf(outBuffer, L"  [%.2u] %wZ\n", j, (PUNICODE_STRING) (((ULONG_PTR) Volume) + MF_OffSetTable[KiwiOsIndex][CallbackVolumeNameOffset]));
												FltObjectDereference (Volume);
											}
											else
											{
												status = kprintf(outBuffer, L"  [%.2u] /\n", j);;
											}
											for(k = 0x16; NT_SUCCESS(status) && (k < 0x32); k++)
											{
												if(pCallBack = (PVOID) *(PULONG_PTR) (( ((ULONG_PTR) InstanceList[j] )+ MF_OffSetTable[KiwiOsIndex][CallbackOffset]) + sizeof(PVOID)*k))
												{
													preCallBack = (PVOID) *(PULONG_PTR) (((ULONG_PTR) pCallBack) + MF_OffSetTable[KiwiOsIndex][CallbackPreOffset]);
													postCallBack = (PVOID) *(PULONG_PTR) (((ULONG_PTR) pCallBack) + MF_OffSetTable[KiwiOsIndex][CallbackPostOffset]);
													if(preCallBack || postCallBack)
													{
														status = kprintf(outBuffer, L"    [0x%2x] %s\n", k, irpToName[k - 0x16]);
														if(NT_SUCCESS(status) && preCallBack)
														{
															status = kprintf(outBuffer, L"      PreCallback  : ");
															if(NT_SUCCESS(status))
																status = kkll_m_modules_fromAddr(outBuffer, preCallBack);
														}
														if(NT_SUCCESS(status) && postCallBack)
														{
															status = kprintf(outBuffer, L"      PostCallback : ");
															if(NT_SUCCESS(status))
																status = kkll_m_modules_fromAddr(outBuffer, postCallBack);
														}
													}
												}
											}
											FltObjectDereference (InstanceList[j]);
										}
										ExFreePoolWithTag(InstanceList, POOL_TAG);
									}
								}
							}
						}
						ExFreePoolWithTag(myFilterFullInformation, POOL_TAG);
					}
				}
				FltObjectDereference (FilterList[i]);
			}
			ExFreePoolWithTag(FilterList, POOL_TAG);
		}
	}
	return status;
}