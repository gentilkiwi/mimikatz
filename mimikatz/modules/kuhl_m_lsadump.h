/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "kuhl_m.h"
#include "kerberos/kuhl_m_kerberos.h"
#include "../modules/kull_m_process.h"
#include "../modules/kull_m_service.h"
#include "../modules/kull_m_memory.h"
#include "../modules/kull_m_patch.h"
#include "../modules/kull_m_registry.h"
#include "../modules/kull_m_crypto_system.h"
#include "../modules/kull_m_string.h"
#include "../modules/kull_m_samlib.h"
#include "../modules/kull_m_net.h"
#include "lsadump/kuhl_m_lsadump_dc.h"
#include "kuhl_m_lsadump_remote.h"
#include "kuhl_m_crypto.h"
#include "dpapi/kuhl_m_dpapi_oe.h"
#include "sekurlsa/kuhl_m_sekurlsa.h"

#define	SYSKEY_LENGTH	16
#define	SAM_KEY_DATA_SALT_LENGTH	16
#define	SAM_KEY_DATA_KEY_LENGTH		16

typedef struct _SAM_ENTRY {
	DWORD offset;
	DWORD lenght;
	DWORD unk;
} SAM_ENTRY, *PSAM_SENTRY;

typedef struct _KIWI_BACKUP_KEY {
	DWORD version;
	DWORD keyLen;
	DWORD certLen;
	BYTE data[ANYSIZE_ARRAY];
} KIWI_BACKUP_KEY, *PKIWI_BACKUP_KEY;

typedef struct _NTDS_LSA_AUTH_INFORMATION {
    LARGE_INTEGER LastUpdateTime;
    ULONG AuthType;
    ULONG AuthInfoLength;
	UCHAR AuthInfo[ANYSIZE_ARRAY]; //
} NTDS_LSA_AUTH_INFORMATION, *PNTDS_LSA_AUTH_INFORMATION;

typedef struct _NTDS_LSA_AUTH_INFORMATIONS {
	DWORD count; // or version ?
	DWORD offsetToAuthenticationInformation;	// PLSA_AUTH_INFORMATION
	DWORD offsetToPreviousAuthenticationInformation;	// PLSA_AUTH_INFORMATION
	// ...
} NTDS_LSA_AUTH_INFORMATIONS, *PNTDS_LSA_AUTH_INFORMATIONS;

const KUHL_M kuhl_m_lsadump;

NTSTATUS kuhl_m_lsadump_init();

NTSTATUS kuhl_m_lsadump_sam(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_lsa(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_secrets(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_cache(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_trust(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_secretsOrCache(int argc, wchar_t * argv[], BOOL secretsOrCache);
NTSTATUS kuhl_m_lsadump_bkey(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_rpdata(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_setntlm(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_changentlm(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_netsync(int argc, wchar_t * argv[]);
NTSTATUS kuhl_m_lsadump_packages(int argc, wchar_t * argv[]);

BOOL kuhl_m_lsadump_getSids(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN LPCWSTR littleKey, IN LPCWSTR prefix);
BOOL kuhl_m_lsadump_getComputerAndSyskey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hSystemBase, OUT LPBYTE sysKey);
BOOL kuhl_m_lsadump_getUsersAndSamKey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hSAMBase, IN LPBYTE sysKey);

BOOL kuhl_m_lsadump_getCurrentControlSet(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hSystemBase, PHKEY phCurrentControlSet);
BOOL kuhl_m_lsadump_getSyskey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hLSA, LPBYTE sysKey);
BOOL kuhl_m_lsadump_getSamKey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hAccount, LPCBYTE sysKey, LPBYTE samKey);
BOOL kuhl_m_lsadump_getHash(PSAM_SENTRY pSamHash, LPCBYTE pStartOfData, LPCBYTE samKey, DWORD rid, BOOL isNtlm, BOOL isHistory);

void kuhl_m_lsadump_lsa_user(SAMPR_HANDLE DomainHandle, PSID DomainSid, DWORD rid, PUNICODE_STRING name, PKULL_M_MEMORY_ADDRESS aRemoteThread);
BOOL kuhl_m_lsadump_lsa_getHandle(PKULL_M_MEMORY_HANDLE * hMemory, DWORD Flags);
void kuhl_m_lsadump_trust_authinformation(PLSA_AUTH_INFORMATION info, DWORD count, PNTDS_LSA_AUTH_INFORMATION infoNtds, PCWSTR prefix, PCUNICODE_STRING from, PCUNICODE_STRING dest);

NTSTATUS kuhl_m_lsadump_LsaRetrievePrivateData(PCWSTR systemName, PCWSTR secretName, PUNICODE_STRING secret, BOOL isSecret);
void kuhl_m_lsadump_analyzeKey(LPCGUID guid, PKIWI_BACKUP_KEY secret, DWORD size, BOOL isExport);
NTSTATUS kuhl_m_lsadump_getKeyFromGUID(LPCGUID guid, BOOL isExport, LPCWSTR systemName, BOOL isSecret);

typedef  enum _DOMAIN_SERVER_ROLE
{
	DomainServerRoleBackup = 2,
	DomainServerRolePrimary = 3
} DOMAIN_SERVER_ROLE, *PDOMAIN_SERVER_ROLE;

typedef  enum _DOMAIN_SERVER_ENABLE_STATE
{
	DomainServerEnabled = 1,
	DomainServerDisabled
} DOMAIN_SERVER_ENABLE_STATE, *PDOMAIN_SERVER_ENABLE_STATE;

typedef struct _OLD_LARGE_INTEGER {
	ULONG LowPart;
	LONG HighPart;
} OLD_LARGE_INTEGER, *POLD_LARGE_INTEGER;

typedef struct _SAM_KEY_DATA {
	DWORD Revision;
	DWORD Length;
	BYTE Salt[SAM_KEY_DATA_SALT_LENGTH];
	BYTE Key[SAM_KEY_DATA_KEY_LENGTH];
	BYTE CheckSum[MD5_DIGEST_LENGTH];
	DWORD unk0;
	DWORD unk1;
} SAM_KEY_DATA, *PSAM_KEY_DATA;

//BYTE samKeyAES[] = {
//	/* Flags/Rev ? */	0x02, 0x00, 0x00, 0x00,
//	/* Struct Size */	0x70, 0x00, 0x00, 0x00,
//						
//						0x30, 0x00, 0x00, 0x00,
//						0x20, 0x00, 0x00, 0x00,
//						
//						0x30, 0x00, 0x00, 0x00,
//						0x20, 0x00, 0x00, 0x00,
//	/* IV */			0x92, 0xC2, 0x72, 0xF0, 0x42, 0xF2, 0x73, 0x7E, 0x8D, 0x62, 0x1F, 0x5A, 0x0C, 0xF9, 0x91, 0xBD,
//						
//	/* Data */			0x2D, 0x12, 0x3C, 0x86, 0x97, 0xD9, 0x19, 0x5B, 0x82, 0x8D, 0x94, 0x18, 0x0B, 0x48, 0xF6, 0xEA,
//						0x1B, 0xD7, 0xC9, 0x65, 0x7A, 0x75, 0x90, 0x72, 0xE5, 0x68, 0xAD, 0x88, 0x27, 0xE5, 0x58, 0xFC,
//						
//						0x48, 0x05, 0x59, 0xE3, 0x91, 0x2A, 0x0E, 0xD2, 0x83, 0xEE, 0x17, 0xD9, 0x8D, 0xDB, 0xC4, 0xB7,
//						0xBB, 0xB5, 0xE6, 0x75, 0x9E, 0x86, 0xAB, 0x55, 0x49, 0x42, 0x6C, 0x48, 0x87, 0xAC, 0x36, 0x89,
//						0x6B, 0xD9, 0x66, 0x23, 0xB1, 0xA8, 0x1E, 0x6C  /* .. ??? */
//};
typedef struct _SAM_KEY_DATA_AES {
	DWORD Revision; // 2
	DWORD Length;
	DWORD CheckLen;
	DWORD DataLen;
	BYTE Salt[SAM_KEY_DATA_SALT_LENGTH];
	BYTE data[ANYSIZE_ARRAY]; // Data, then Check
} SAM_KEY_DATA_AES, *PSAM_KEY_DATA_AES;

typedef struct _DOMAIN_ACCOUNT_F {
	WORD Revision;
	WORD unk0;
	DWORD unk1;
	OLD_LARGE_INTEGER CreationTime;
	OLD_LARGE_INTEGER DomainModifiedCount;
	OLD_LARGE_INTEGER MaxPasswordAge;
	OLD_LARGE_INTEGER MinPasswordAge;
	OLD_LARGE_INTEGER ForceLogoff;
	OLD_LARGE_INTEGER LockoutDuration;
	OLD_LARGE_INTEGER LockoutObservationWindow;
	OLD_LARGE_INTEGER ModifiedCountAtLastPromotion;
	DWORD NextRid;
	DWORD PasswordProperties;
	WORD MinPasswordLength;
	WORD PasswordHistoryLength;
	WORD LockoutThreshold;
	DOMAIN_SERVER_ENABLE_STATE ServerState;
	DOMAIN_SERVER_ROLE ServerRole;
	BOOL UasCompatibilityRequired;
	DWORD unk2;
	SAM_KEY_DATA keys1;
	SAM_KEY_DATA keys2;
	DWORD unk3;
	DWORD unk4;
} DOMAIN_ACCOUNT_F, *PDOMAIN_ACCOUNT_F;

typedef struct _USER_ACCOUNT_V {
	SAM_ENTRY unk0_header;
	SAM_ENTRY Username;
	SAM_ENTRY Fullname;
	SAM_ENTRY Comment;
	SAM_ENTRY UserComment;
	SAM_ENTRY unk1;
	SAM_ENTRY Homedir;
	SAM_ENTRY HomedirConnect;
	SAM_ENTRY ScriptPath;
	SAM_ENTRY ProfilePath;
	SAM_ENTRY Workstations;
	SAM_ENTRY HoursAllowed;
	SAM_ENTRY unk2;
	SAM_ENTRY LMHash;
	SAM_ENTRY NTLMHash;
	SAM_ENTRY NTLMHistory;
	SAM_ENTRY LMHistory;
	BYTE datas[ANYSIZE_ARRAY];
} USER_ACCOUNT_V, *PUSER_ACCOUNT_V;

typedef struct _SAM_HASH_AES {
	WORD PEKID;
	WORD Revision;
	DWORD dataOffset;
	BYTE Salt[SAM_KEY_DATA_SALT_LENGTH];
	BYTE data[ANYSIZE_ARRAY]; // Data
} SAM_HASH_AES, *PSAM_HASH_AES;

typedef struct _SAM_HASH {
	WORD PEKID;
	WORD Revision;
	BYTE data[ANYSIZE_ARRAY];
} SAM_HASH, *PSAM_HASH;

typedef struct _POL_REVISION {
	USHORT Minor;
	USHORT Major;
} POL_REVISION, *PPOL_REVISION;

typedef struct _NT6_CLEAR_SECRET {
	DWORD SecretSize;
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	BYTE  Secret[ANYSIZE_ARRAY];
} NT6_CLEAR_SECRET, *PNT6_CLEAR_SECRET;

#define LAZY_NT6_IV_SIZE	32
typedef struct _NT6_HARD_SECRET {
	DWORD version;
	GUID KeyId;
	DWORD algorithm;
	DWORD flag;
	BYTE lazyiv[LAZY_NT6_IV_SIZE];
	union {
		NT6_CLEAR_SECRET clearSecret;
		BYTE encryptedSecret[ANYSIZE_ARRAY];
	};
} NT6_HARD_SECRET, *PNT6_HARD_SECRET;

typedef struct _NT6_SYSTEM_KEY {
	GUID KeyId;
	DWORD KeyType;
	DWORD KeySize;
	BYTE Key[ANYSIZE_ARRAY];
} NT6_SYSTEM_KEY, *PNT6_SYSTEM_KEY;

typedef struct _NT6_SYSTEM_KEYS {
	DWORD unkType0;
	GUID CurrentKeyID;
	DWORD unkType1;
	DWORD nbKeys;
	NT6_SYSTEM_KEY Keys[ANYSIZE_ARRAY];
} NT6_SYSTEM_KEYS, *PNT6_SYSTEM_KEYS;

typedef struct _NT5_HARD_SECRET {
	DWORD encryptedStructSize;
	DWORD unk0;
	DWORD unk1; // it's a trap, it's PTR !
	BYTE encryptedSecret[ANYSIZE_ARRAY];
} NT5_HARD_SECRET, *PNT5_HARD_SECRET;

typedef struct _NT5_SYSTEM_KEY {
	BYTE key[16];
} NT5_SYSTEM_KEY, *PNT5_SYSTEM_KEY;

#define LAZY_IV_SIZE	16
typedef struct _NT5_SYSTEM_KEYS {
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	NT5_SYSTEM_KEY keys[3];
	BYTE lazyiv[LAZY_IV_SIZE];
} NT5_SYSTEM_KEYS, *PNT5_SYSTEM_KEYS;

typedef struct _MSCACHE_ENTRY {
	WORD szUserName;
	WORD szDomainName;
	WORD szEffectiveName;
	WORD szFullName;
	WORD szlogonScript;
	WORD szprofilePath;
	WORD szhomeDirectory;
	WORD szhomeDirectoryDrive;
	DWORD userId;
	DWORD primaryGroupId;
	DWORD groupCount;
	WORD szlogonDomainName;
	WORD unk0;
	FILETIME lastWrite;
	DWORD revision;
	DWORD sidCount;
	DWORD flags;
	DWORD unk1;
	DWORD logonPackage;
	WORD szDnsDomainName;
	WORD szupn;
	BYTE iv[LAZY_IV_SIZE];
	BYTE cksum[MD5_DIGEST_LENGTH];
	BYTE enc_data[ANYSIZE_ARRAY];
} MSCACHE_ENTRY, *PMSCACHE_ENTRY;

typedef struct _MSCACHE_ENTRY_PTR {
	UNICODE_STRING UserName;
	UNICODE_STRING Domain;
	UNICODE_STRING DnsDomainName;
	UNICODE_STRING Upn;
	UNICODE_STRING EffectiveName;
	UNICODE_STRING FullName;

	UNICODE_STRING LogonScript;
	UNICODE_STRING ProfilePath;
	UNICODE_STRING HomeDirectory;
	UNICODE_STRING HomeDirectoryDrive;

	PGROUP_MEMBERSHIP Groups;

	UNICODE_STRING LogonDomainName;

} MSCACHE_ENTRY_PTR, *PMSCACHE_ENTRY_PTR;

typedef struct _MSCACHE_DATA {
	BYTE mshashdata[LM_NTLM_HASH_LENGTH];
	BYTE unkhash[LM_NTLM_HASH_LENGTH];
	DWORD unk0;
	DWORD szSC;
	DWORD unkLength;
	DWORD unk2;
	DWORD unk3;
	DWORD unk4;
	DWORD unk5;
	DWORD unk6;
	DWORD unk7;
	DWORD unk8;
} MSCACHE_DATA, *PMSCACHE_DATA;

typedef struct _KIWI_ENC_SC_DATA {
	BYTE toSign[32];
	BYTE toHash[32];
	BYTE toDecrypt[ANYSIZE_ARRAY];
} KIWI_ENC_SC_DATA, *PKIWI_ENC_SC_DATA;

typedef struct _KIWI_ENC_SC_DATA_NEW {
	BYTE Header[8]; // SuppData
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	DWORD dataSize;
	KIWI_ENC_SC_DATA data;
} KIWI_ENC_SC_DATA_NEW, *PKIWI_ENC_SC_DATA_NEW;

typedef struct _NTLM_SUPPLEMENTAL_CREDENTIAL_V4 {
	ULONG Version;
	ULONG Flags;
	ULONG unk;
	UCHAR NtPassword[LM_NTLM_HASH_LENGTH];
} NTLM_SUPPLEMENTAL_CREDENTIAL_V4, *PNTLM_SUPPLEMENTAL_CREDENTIAL_V4;

typedef struct _WDIGEST_CREDENTIALS {
	BYTE	Reserverd1;
	BYTE	Reserverd2;
	BYTE	Version;
	BYTE	NumberOfHashes;
	BYTE	Reserverd3[12];
	BYTE	Hash[ANYSIZE_ARRAY][MD5_DIGEST_LENGTH];
} WDIGEST_CREDENTIALS, *PWDIGEST_CREDENTIALS;

typedef struct _KERB_KEY_DATA {
	USHORT	Reserverd1;
	USHORT	Reserverd2;
	ULONG	Reserverd3;
	LONG	KeyType;
	ULONG	KeyLength;
	ULONG	KeyOffset;
} KERB_KEY_DATA, *PKERB_KEY_DATA;

typedef struct _KERB_STORED_CREDENTIAL {
	USHORT	Revision;
	USHORT	Flags;
	USHORT	CredentialCount;
	USHORT	OldCredentialCount;
	USHORT	DefaultSaltLength;
	USHORT	DefaultSaltMaximumLength;
	ULONG	DefaultSaltOffset;
	//KERB_KEY_DATA	Credentials[ANYSIZE_ARRAY];
	//KERB_KEY_DATA	OldCredentials[ANYSIZE_ARRAY];
	//BYTE	DefaultSalt[ANYSIZE_ARRAY];
	//BYTE	KeyValues[ANYSIZE_ARRAY];
} KERB_STORED_CREDENTIAL, *PKERB_STORED_CREDENTIAL;

typedef struct _KERB_KEY_DATA_NEW {
	USHORT	Reserverd1;
	USHORT	Reserverd2;
	ULONG	Reserverd3;
	ULONG	IterationCount;
	LONG	KeyType;
	ULONG	KeyLength;
	ULONG	KeyOffset;
} KERB_KEY_DATA_NEW, *PKERB_KEY_DATA_NEW;

typedef struct _KERB_STORED_CREDENTIAL_NEW {
	USHORT	Revision;
	USHORT	Flags;
	USHORT	CredentialCount;
	USHORT	ServiceCredentialCount;
	USHORT	OldCredentialCount;
	USHORT	OlderCredentialCount;
	USHORT	DefaultSaltLength;
	USHORT	DefaultSaltMaximumLength;
	ULONG	DefaultSaltOffset;
	ULONG	DefaultIterationCount;
	//KERB_KEY_DATA_NEW	Credentials[ANYSIZE_ARRAY];
	//KERB_KEY_DATA_NEW	ServiceCredentials[ANYSIZE_ARRAY];
	//KERB_KEY_DATA_NEW	OldCredentials[ANYSIZE_ARRAY];
	//KERB_KEY_DATA_NEW	OlderCredentials[ANYSIZE_ARRAY];
	//BYTE	DefaultSalt[ANYSIZE_ARRAY];
	//BYTE	KeyValues[ANYSIZE_ARRAY];
} KERB_STORED_CREDENTIAL_NEW, *PKERB_STORED_CREDENTIAL_NEW;

typedef struct _LSA_SUPCREDENTIAL {
	DWORD	type;
	DWORD	size;
	DWORD	offset;
	DWORD	Reserved;
} LSA_SUPCREDENTIAL, *PLSA_SUPCREDENTIAL;

typedef struct _LSA_SUPCREDENTIALS {
	DWORD	count;
	DWORD	Reserved;
} LSA_SUPCREDENTIALS, *PLSA_SUPCREDENTIALS;

typedef struct _LSA_SUPCREDENTIALS_BUFFERS {
	LSA_SUPCREDENTIAL credential;
	NTSTATUS status;
	PVOID Buffer;
} LSA_SUPCREDENTIALS_BUFFERS, *PLSA_SUPCREDENTIALS_BUFFERS;

typedef struct _KUHL_LSADUMP_DCC_CACHE_DATA {
	LPCWSTR username;
	BYTE ntlm[LM_NTLM_HASH_LENGTH];
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hProv;
	DWORD keySpec;
} KUHL_LSADUMP_DCC_CACHE_DATA, *PKUHL_LSADUMP_DCC_CACHE_DATA;

typedef struct _KIWI_LSA_PRIVATE_DATA {
	DWORD DataType;
	WORD LmLength;
	WORD LmMaximumLength;
	DWORD Unused1;
	BYTE LmHash[LM_NTLM_HASH_LENGTH];
	WORD NtLength;
	WORD NtMaximumLength;
	DWORD Unused2;
	BYTE NtHash[LM_NTLM_HASH_LENGTH];
	WORD LmHistoryLength;
	WORD LmHistoryMaximumLength;
	DWORD Unused3;
	WORD NtHistoryLength;
	WORD NtHistoryMaximumLength;
	DWORD Unused4;
	BYTE Data[ANYSIZE_ARRAY];
	// NtHistoryArray
	// LmHistoryArray
} KIWI_LSA_PRIVATE_DATA, *PKIWI_LSA_PRIVATE_DATA;

typedef struct _TBAL_UNICODE_STRING_F32 {
	DWORD  Buffer;
	USHORT Length;
	USHORT MaximumLength;
} TBAL_UNICODE_STRING_F32, *PTBAL_UNICODE_STRING_F32;

typedef struct _KIWI_TBAL_MSV {
	DWORD unk0;
	DWORD structLen;
	DWORD flags;
	DWORD unkD; // why not ?
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH]; 
	BYTE DPAPIProtected[LM_NTLM_HASH_LENGTH];
	DWORD unk1;
	TBAL_UNICODE_STRING_F32 DomainName;
	TBAL_UNICODE_STRING_F32 UserName;
} KIWI_TBAL_MSV, *PKIWI_TBAL_MSV;

BOOL kuhl_m_lsadump_getLsaKeyAndSecrets(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecurityBase, IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN LPBYTE sysKey, IN BOOL secretsOrCache, IN PKUHL_LSADUMP_DCC_CACHE_DATA pCacheData);
BOOL kuhl_m_lsadump_getSecrets(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, PNT6_SYSTEM_KEYS lsaKeysStream, PNT5_SYSTEM_KEY lsaKeyUnique);
BOOL kuhl_m_lsadump_getNLKMSecretAndCache(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN HKEY hSecurityBase, PNT6_SYSTEM_KEYS lsaKeysStream, PNT5_SYSTEM_KEY lsaKeyUnique, IN PKUHL_LSADUMP_DCC_CACHE_DATA pCacheData);
void kuhl_m_lsadump_printMsCache(PMSCACHE_ENTRY entry, CHAR version);
BOOL kuhl_m_lsadump_decryptSCCache(PBYTE data, DWORD size, HCRYPTPROV hProv, DWORD keySpec);
void kuhl_m_lsadump_getInfosFromServiceName(IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN PCWSTR serviceName);
BOOL kuhl_m_lsadump_decryptSecret(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecret, IN LPCWSTR KeyName, IN PNT6_SYSTEM_KEYS lsaKeysStream, IN PNT5_SYSTEM_KEY lsaKeyUnique, IN PVOID * pBufferOut, IN PDWORD pSzBufferOut);
void kuhl_m_lsadump_candidateSecret(DWORD szBytesSecrets, PVOID bufferSecret, PCWSTR prefix, PCWSTR secretName);
BOOL kuhl_m_lsadump_sec_aes256(PNT6_HARD_SECRET hardSecretBlob, DWORD hardSecretBlobSize, PNT6_SYSTEM_KEYS lsaKeysStream, PBYTE sysKey);

PKERB_KEY_DATA kuhl_m_lsadump_lsa_keyDataInfo(PVOID base, PKERB_KEY_DATA keys, USHORT Count, PCWSTR title);
PKERB_KEY_DATA_NEW kuhl_m_lsadump_lsa_keyDataNewInfo(PVOID base, PKERB_KEY_DATA_NEW keys, USHORT Count, PCWSTR title);
void kuhl_m_lsadump_lsa_DescrBuffer(DWORD type, DWORD rid, PVOID Buffer, DWORD BufferSize);

typedef wchar_t * LOGONSRV_HANDLE;
typedef struct _NETLOGON_CREDENTIAL {
	CHAR data[8]; 
} NETLOGON_CREDENTIAL, *PNETLOGON_CREDENTIAL; 

typedef struct _NETLOGON_AUTHENTICATOR {
	NETLOGON_CREDENTIAL Credential;
	DWORD Timestamp;
} NETLOGON_AUTHENTICATOR, *PNETLOGON_AUTHENTICATOR;

typedef  enum _NETLOGON_SECURE_CHANNEL_TYPE{
	NullSecureChannel = 0,
	MsvApSecureChannel = 1,
	WorkstationSecureChannel = 2,
	TrustedDnsDomainSecureChannel = 3,
	TrustedDomainSecureChannel = 4,
	UasServerSecureChannel = 5,
	ServerSecureChannel = 6,
	CdcServerSecureChannel = 7
} NETLOGON_SECURE_CHANNEL_TYPE;

#define SECRET_SET_VALUE	0x00000001L
#define SECRET_QUERY_VALUE	0x00000002L

#define SECRET_ALL_ACCESS	(STANDARD_RIGHTS_REQUIRED | SECRET_SET_VALUE | SECRET_QUERY_VALUE)
#define SECRET_READ			(STANDARD_RIGHTS_READ | SECRET_QUERY_VALUE)
#define SECRET_WRITE		(STANDARD_RIGHTS_WRITE | SECRET_SET_VALUE)
#define SECRET_EXECUTE		(STANDARD_RIGHTS_EXECUTE)

extern NTSTATUS WINAPI I_NetServerReqChallenge(IN LOGONSRV_HANDLE PrimaryName, IN wchar_t * ComputerName, IN PNETLOGON_CREDENTIAL ClientChallenge, OUT PNETLOGON_CREDENTIAL ServerChallenge);
extern NTSTATUS WINAPI I_NetServerAuthenticate2(IN LOGONSRV_HANDLE PrimaryName, IN wchar_t * AccountName, IN NETLOGON_SECURE_CHANNEL_TYPE SecureChannelType, IN wchar_t * ComputerName, IN PNETLOGON_CREDENTIAL ClientCredential, OUT PNETLOGON_CREDENTIAL ServerCredential, IN OUT ULONG * NegotiateFlags);
extern NTSTATUS WINAPI I_NetServerTrustPasswordsGet(IN LOGONSRV_HANDLE TrustedDcName, IN wchar_t* AccountName, IN NETLOGON_SECURE_CHANNEL_TYPE SecureChannelType, IN wchar_t* ComputerName, IN PNETLOGON_AUTHENTICATOR Authenticator, OUT PNETLOGON_AUTHENTICATOR ReturnAuthenticator, OUT PENCRYPTED_NT_OWF_PASSWORD EncryptedNewOwfPassword, OUT PENCRYPTED_NT_OWF_PASSWORD EncryptedOldOwfPassword);
extern NTSTATUS NTAPI LsaOpenSecret(__in LSA_HANDLE PolicyHandle, __in PLSA_UNICODE_STRING SecretName, __in ACCESS_MASK DesiredAccess, __out PLSA_HANDLE SecretHandle);
extern NTSTATUS NTAPI LsaSetSecret(__in LSA_HANDLE SecretHandle, __in_opt PLSA_UNICODE_STRING CurrentValue, __in_opt PLSA_UNICODE_STRING OldValue);
extern NTSTATUS NTAPI LsaQuerySecret(__in LSA_HANDLE SecretHandle, __out_opt OPTIONAL PLSA_UNICODE_STRING *CurrentValue, __out_opt PLARGE_INTEGER CurrentValueSetTime, __out_opt PLSA_UNICODE_STRING *OldValue, __out_opt PLARGE_INTEGER OldValueSetTime);

NTSTATUS kuhl_m_lsadump_netsync_NlComputeCredentials(PBYTE input, PBYTE output, PBYTE key);
void kuhl_m_lsadump_netsync_AddTimeStampForAuthenticator(PNETLOGON_CREDENTIAL Credential, DWORD TimeStamp, PNETLOGON_AUTHENTICATOR Authenticator, BYTE sessionKey[MD5_DIGEST_LENGTH]);