/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kkll_m_process.h"
#include "kkll_m_modules.h"
#include "kkll_m_ssdt.h"
#include "kkll_m_notify.h"
#include "kkll_m_filters.h"

extern PSHORT	NtBuildNumber;

DRIVER_INITIALIZE	DriverEntry;
DRIVER_UNLOAD		DriverUnload;

DRIVER_DISPATCH		UnSupported;
__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)		DRIVER_DISPATCH MimiDispatchDeviceControl;

KIWI_OS_INDEX getWindowsIndex();