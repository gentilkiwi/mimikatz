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
#include <initguid.h>

typedef struct _CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
	ULONG ulAuthenticationPackage;
	GUID clsidCredentialProvider;
	ULONG cbSerialization;
	/* [size_is] */ byte *rgbSerialization;
} CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION;

typedef struct ICredentialProviderCredentialVtbl {
    BEGIN_INTERFACE
    HRESULT (STDMETHODCALLTYPE *QueryInterface)();
    ULONG (STDMETHODCALLTYPE *AddRef)();
    ULONG (STDMETHODCALLTYPE *Release)();
    HRESULT (STDMETHODCALLTYPE *Advise)();
    HRESULT (STDMETHODCALLTYPE *UnAdvise)();
    HRESULT (STDMETHODCALLTYPE *SetSelected)();
    HRESULT (STDMETHODCALLTYPE *SetDeselected)();
    HRESULT (STDMETHODCALLTYPE *GetFieldState)();
    HRESULT (STDMETHODCALLTYPE *GetStringValue)();
    HRESULT (STDMETHODCALLTYPE *GetBitmapValue)();
    HRESULT (STDMETHODCALLTYPE *GetCheckboxValue)();
    HRESULT (STDMETHODCALLTYPE *GetSubmitButtonValue)();
    HRESULT (STDMETHODCALLTYPE *GetComboBoxValueCount)();
    HRESULT (STDMETHODCALLTYPE *GetComboBoxValueAt)();
    HRESULT (STDMETHODCALLTYPE *SetStringValue)();
    HRESULT (STDMETHODCALLTYPE *SetCheckboxValue)();
    HRESULT (STDMETHODCALLTYPE *SetComboBoxSelectedValue)();
    HRESULT (STDMETHODCALLTYPE *CommandLinkClicked)();
    HRESULT (STDMETHODCALLTYPE *GetSerialization)(IUnknown * This, /* [out] */ PVOID pcpgsr, /* [out] */ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs, /* [out] */ LPWSTR *ppszOptionalStatusText, /* [out] */ PVOID pcpsiOptionalStatusIcon);
    HRESULT (STDMETHODCALLTYPE *ReportResult)();
    END_INTERFACE
} ICredentialProviderCredentialVtbl;

typedef struct ICredentialProviderCredential {
    CONST_VTBL struct ICredentialProviderCredentialVtbl *lpVtbl;
} ICredentialProviderCredential;

typedef struct ICredentialProviderVtbl {
    BEGIN_INTERFACE
    HRESULT (STDMETHODCALLTYPE *QueryInterface)();
    ULONG (STDMETHODCALLTYPE *AddRef)();
    ULONG (STDMETHODCALLTYPE *Release )(PVOID object );
    HRESULT (STDMETHODCALLTYPE *SetUsageScenario)();
    HRESULT (STDMETHODCALLTYPE *SetSerialization)(IUnknown * This, /* [in] */ const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs);
    HRESULT (STDMETHODCALLTYPE *Advise)();
    HRESULT (STDMETHODCALLTYPE *UnAdvise)();
    HRESULT (STDMETHODCALLTYPE *GetFieldDescriptorCount)();
    HRESULT (STDMETHODCALLTYPE *GetFieldDescriptorAt)();
    HRESULT (STDMETHODCALLTYPE *GetCredentialCount)(IUnknown * This, /* [out] */ DWORD *pdwCount, /* [out] */ DWORD *pdwDefault, /* [out] */ BOOL *pbAutoLogonWithDefault);
    HRESULT (STDMETHODCALLTYPE *GetCredentialAt)(IUnknown * This, /* [in] */ DWORD dwIndex, /* [out] */ ICredentialProviderCredential **ppcpc);
    END_INTERFACE
} ICredentialProviderVtbl;

typedef struct ICredentialProvider {
    CONST_VTBL struct ICredentialProviderVtbl *lpVtbl;
} ICredentialProvider;

typedef BOOL (WINAPI CredUnPackAuthenticationBufferWFct) (DWORD dwFlags, PVOID pAuthBuffer, DWORD cbAuthBuffer, LPWSTR pszUserName, DWORD* pcchMaxUserName, LPWSTR pszDomainName, DWORD* pcchMaxDomainName, LPWSTR pszPassword, DWORD* pcchMaxPassword);
typedef BOOL (WINAPI CredIsProtectedWFct) (LPWSTR pszProtectedCredentials, CRED_PROTECTION_TYPE* pProtectionType);
typedef BOOL (WINAPI CredUnprotectWFct) (BOOL fAsSelf, LPWSTR pszProtectedCredentials, DWORD cchProtectedCredentials, LPWSTR pszCredentials, DWORD* pcchMaxChars);

typedef HRESULT (STDMETHODCALLTYPE* GetSerializationType) (IUnknown* This, /* [out] */ PVOID pcpgsr, /* [out] */ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, /* [out] */ LPWSTR* ppszOptionalStatusText, /* [out] */ PVOID pcpsiOptionalStatusIcon);
typedef HRESULT (STDMETHODCALLTYPE* GetCredentialAtType) (IUnknown* This, DWORD dwIndex, ICredentialProviderCredential** ppcpc);

typedef struct _CClassFactory {
	CONST_VTBL struct IClassFactoryVtbl* lpVtbl;
	LONG _cRef;
} CClassFactory;