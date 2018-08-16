/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kull_m_string.h"
#include "kull_m_crypto_system.h"
#include "kull_m_file.h"

#define CALG_CRC32	(ALG_CLASS_HASH | ALG_TYPE_ANY | 0)

#define AES_256_KEY_SIZE	(256/8)
#define AES_128_KEY_SIZE	(128/8)
#define AES_BLOCK_SIZE		16

typedef struct _GENERICKEY_BLOB {
	BLOBHEADER Header;
	DWORD dwKeyLen;
} GENERICKEY_BLOB, *PGENERICKEY_BLOB;

typedef struct _RSA_GENERICKEY_BLOB {
	BLOBHEADER Header;
	RSAPUBKEY RsaKey; // works with RSA2 ;)
} RSA_GENERICKEY_BLOB, *PRSA_GENERICKEY_BLOB;

#define PVK_FILE_VERSION_0				0
#define PVK_MAGIC						0xb0b5f11e // bob's file
#define PVK_NO_ENCRYPT					0
#define PVK_RC4_PASSWORD_ENCRYPT		1
#define PVK_RC2_CBC_PASSWORD_ENCRYPT	2

#ifndef IPSEC_FLAG_CHECK
#define IPSEC_FLAG_CHECK 0xf42a19b6
#endif

#ifndef CNG_RSA_PRIVATE_KEY_BLOB
#define CNG_RSA_PRIVATE_KEY_BLOB (LPCSTR) 83
#endif

typedef struct _PVK_FILE_HDR {
	DWORD	dwMagic;
	DWORD	dwVersion;
	DWORD	dwKeySpec;
	DWORD	dwEncryptType;
	DWORD	cbEncryptData;
	DWORD	cbPvk;
} PVK_FILE_HDR, *PPVK_FILE_HDR;

typedef struct _KIWI_HARD_KEY {
	ULONG cbSecret;
	BYTE data[ANYSIZE_ARRAY]; // etc...
} KIWI_HARD_KEY, *PKIWI_HARD_KEY;

typedef struct _KIWI_BCRYPT_KEY {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG bits;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY, *PKIWI_BCRYPT_KEY;

BOOL kull_m_crypto_hash(ALG_ID algid, LPCVOID data, DWORD dataLen, LPVOID hash, DWORD hashWanted);
BOOL kull_m_crypto_hkey(HCRYPTPROV hProv, ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hKey, HCRYPTPROV *hSessionProv);
BOOL kull_m_crypto_hmac(DWORD calgid, LPCVOID key, DWORD keyLen, LPCVOID message, DWORD messageLen, LPVOID hash, DWORD hashWanted);
BOOL kull_m_crypto_pkcs5_pbkdf2_hmac(DWORD calgid, LPCVOID password, DWORD passwordLen, LPCVOID salt, DWORD saltLen, DWORD iterations, BYTE *key, DWORD keyLen, BOOL isDpapiInternal);
BOOL kull_m_crypto_aesCTSEncryptDecrypt(DWORD aesCalgId, PVOID data, DWORD szData, PVOID key, DWORD szKey, PVOID pbIV, BOOL encrypt);
BOOL kull_m_crypto_DeriveKeyRaw(ALG_ID hashId, LPVOID hash, DWORD hashLen, LPVOID key, DWORD keyLen);
BOOL kull_m_crypto_close_hprov_delete_container(HCRYPTPROV hProv);
BOOL kull_m_crypto_hkey_session(ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hSessionKey, HCRYPTPROV *hSessionProv);
DWORD kull_m_crypto_hash_len(ALG_ID hashId);
DWORD kull_m_crypto_cipher_blocklen(ALG_ID hashId);
DWORD kull_m_crypto_cipher_keylen(ALG_ID hashId);
NTSTATUS kull_m_crypto_get_dcc(PBYTE dcc, PBYTE ntlm, PUNICODE_STRING Username, DWORD realIterations);
BOOL kull_m_crypto_genericAES128Decrypt(LPCVOID pKey, LPCVOID pIV, LPCVOID pData, DWORD dwDataLen, LPVOID *pOut, DWORD *dwOutLen);

BOOL kull_m_crypto_exportPfx(HCERTSTORE hStore, LPCWSTR filename);
BOOL kull_m_crypto_DerAndKeyToPfx(LPCVOID der, DWORD derLen, LPCVOID key, DWORD keyLen, BOOL isPvk, LPCWSTR filename);
BOOL kull_m_crypto_DerAndKeyInfoToPfx(LPCVOID der, DWORD derLen, PCRYPT_KEY_PROV_INFO pInfo, LPCWSTR filename);
BOOL kull_m_crypto_DerAndKeyInfoToStore(LPCVOID der, DWORD derLen, PCRYPT_KEY_PROV_INFO pInfo, DWORD systemStore, LPCWSTR store, BOOL force);

typedef struct _KULL_M_CRYPTO_DUAL_STRING_DWORD {
	PCWSTR	name;
	DWORD	id;
} KULL_M_CRYPTO_DUAL_STRING_DWORD, *PKULL_M_CRYPTO_DUAL_STRING_DWORD;

typedef struct _KULL_M_CRYPTO_DUAL_STRING_STRING {
	PCWSTR	name;
	PCWSTR	realname;
} KULL_M_CRYPTO_DUAL_STRING_STRING, *PKULL_M_CRYPTO_DUAL_STRING_STRING;

#define CERT_cert_file_element	32
#define CERT_crl_file_element	33
#define CERT_ctl_file_element	34
#define CERT_keyid_file_element	35

DWORD kull_m_crypto_system_store_to_dword(PCWSTR name);
DWORD kull_m_crypto_provider_type_to_dword(PCWSTR name);
PCWSTR kull_m_crypto_provider_type_to_name(const DWORD dwProvType);
PCWCHAR kull_m_crypto_provider_to_realname(PCWSTR name);
PCWCHAR kull_m_crypto_keytype_to_str(const DWORD keyType);
PCWCHAR kull_m_crypto_algid_to_name(ALG_ID algid);
ALG_ID kull_m_crypto_name_to_algid(PCWSTR name);
PCWCHAR kull_m_crypto_cert_prop_id_to_name(const DWORD propId);
void kull_m_crypto_kp_permissions_descr(const DWORD keyPermissions);
PCWCHAR kull_m_crypto_kp_mode_to_str(const DWORD keyMode);
PCWCHAR kull_m_crypto_bcrypt_interface_to_str(const DWORD interf);
PCWCHAR kull_m_crypto_bcrypt_cipher_alg_to_str(const DWORD alg);
PCWCHAR kull_m_crypto_bcrypt_asym_alg_to_str(const DWORD alg);
PCWCHAR kull_m_crypto_bcrypt_mode_to_str(const DWORD keyMode);


typedef struct _MIMI_PUBLICKEY
{
	ALG_ID sessionType;
	DWORD cbPublicKey;
	BYTE *pbPublicKey;
} MIMI_PUBLICKEY, *PMIMI_PUBLICKEY;

typedef struct _KIWI_DH {
	HCRYPTPROV hProvParty;
	HCRYPTKEY hPrivateKey;
	MIMI_PUBLICKEY publicKey;
	HCRYPTKEY hSessionKey;
} KIWI_DH, *PKIWI_DH;

PKIWI_DH kull_m_crypto_dh_Delete(PKIWI_DH dh);
PKIWI_DH kull_m_crypto_dh_Create(ALG_ID targetSessionKeyType);
BOOL kull_m_crypto_dh_CreateSessionKey(PKIWI_DH dh, PMIMI_PUBLICKEY publicKey);
BOOL kull_m_crypto_dh_simpleEncrypt(HCRYPTKEY key, LPVOID data, DWORD dataLen, LPVOID *out, DWORD *outLen);
BOOL kull_m_crypto_dh_simpleDecrypt(HCRYPTKEY key, LPVOID data, DWORD dataLen, LPVOID *out, DWORD *outLen);

#define IOCTL_GET_FEATURE_REQUEST			SCARD_CTL_CODE(3400)
#define IOCTL_CCID_ESCAPE					SCARD_CTL_CODE(3500)

// ACS
#define IOCTL_SMARTCARD_DIRECT					SCARD_CTL_CODE(2050)
#define IOCTL_SMARTCARD_SELECT_SLOT				SCARD_CTL_CODE(2051)
#define IOCTL_SMARTCARD_DRAW_LCDBMP				SCARD_CTL_CODE(2052)
#define IOCTL_SMARTCARD_DISPLAY_LCD				SCARD_CTL_CODE(2053)
#define IOCTL_SMARTCARD_CLR_LCD					SCARD_CTL_CODE(2054)
#define IOCTL_SMARTCARD_READ_KEYPAD				SCARD_CTL_CODE(2055)
#define IOCTL_SMARTCARD_READ_MAGSTRIP			SCARD_CTL_CODE(2056)
#define IOCTL_SMARTCARD_READ_RTC				SCARD_CTL_CODE(2057)
#define IOCTL_SMARTCARD_SET_RTC					SCARD_CTL_CODE(2058)
#define IOCTL_SMARTCARD_SET_OPTION				SCARD_CTL_CODE(2059)
#define IOCTL_SMARTCARD_SET_LED					SCARD_CTL_CODE(2060)
#define IOCTL_SMARTCARD_USE_ENCRYPTION			SCARD_CTL_CODE(2061)
#define IOCTL_SMARTCARD_LOAD_KEY				SCARD_CTL_CODE(2062)
#define IOCTL_SMARTCARD_COMPUTE_MAC				SCARD_CTL_CODE(2063)
#define IOCTL_SMARTCARD_DECRYPT_MAC				SCARD_CTL_CODE(2064)
#define IOCTL_SMARTCARD_READ_EEPROM				SCARD_CTL_CODE(2065)
#define IOCTL_SMARTCARD_WRITE_EEPROM			SCARD_CTL_CODE(2066)
#define IOCTL_SMARTCARD_GET_VERSION				SCARD_CTL_CODE(2067)
#define IOCTL_SMARTCARD_DUKPT_INIT_KEY			SCARD_CTL_CODE(2069)
#define IOCTL_SMARTCARD_ABORD_DUKPT_PIN			SCARD_CTL_CODE(2070)
#define IOCTL_SMARTCARD_SET_USB_VIDPID			SCARD_CTL_CODE(2071)
#define IOCTL_SMARTCARD_ACR128_ESCAPE_COMMAND	SCARD_CTL_CODE(2079)

#define IOCTL_SMARTCARD_GET_READER_INFO			SCARD_CTL_CODE(2051)
#define IOCTL_SMARTCARD_SET_CARD_TYPE			SCARD_CTL_CODE(2060)

// CYBERJACK
#define CJPCSC_VEN_IOCTRL_ESCAPE				SCARD_CTL_CODE(3103)
#define CJPCSC_VEN_IOCTRL_VERIFY_PIN_DIRECT		SCARD_CTL_CODE(3506)
#define CJPCSC_VEN_IOCTRL_MODIFY_PIN_DIRECT		SCARD_CTL_CODE(3507)
#define CJPCSC_VEN_IOCTRL_MCT_READERDIRECT		SCARD_CTL_CODE(3508)
#define CJPCSC_VEN_IOCTRL_MCT_READERUNIVERSAL	SCARD_CTL_CODE(3509)
#define CJPCSC_VEN_IOCTRL_EXECUTE_PACE			SCARD_CTL_CODE(3532)
#define CJPCSC_VEN_IOCTRL_SET_NORM				SCARD_CTL_CODE(3154)

// OMNIKEY
#define CM_IOCTL_GET_FW_VERSION					SCARD_CTL_CODE(3001)
#define CM_IOCTL_GET_LIB_VERSION				SCARD_CTL_CODE(3041) // not in doc
#define CM_IOCTL_SIGNAL							SCARD_CTL_CODE(3058)
#define CM_IOCTL_RFID_GENERIC					SCARD_CTL_CODE(3105)
#define CM_IOCTL_SET_OPERATION_MODE				SCARD_CTL_CODE(3107)
#define CM_IOCTL_GET_MAXIMUM_RFID_BAUDRATE		SCARD_CTL_CODE(3208)
#define CM_IOCTL_SET_RFID_CONTROL_FLAGS			SCARD_CTL_CODE(3213)
#define CM_IOCTL_GET_SET_RFID_BAUDRATE			SCARD_CTL_CODE(3215)

// GEMALTO
#define IOCTL_VENDOR_IFD_EXCHANGE				SCARD_CTL_CODE(2058)
#define IOCTL_SMARTCARD_PC_SC_VERIFY_PIN		SCARD_CTL_CODE(2060)
#define IOCTL_SMARTCARD_PC_SC_MODIFY_PIN		SCARD_CTL_CODE(2061)

#define FEATURE_VERIFY_PIN_START			0x01
#define FEATURE_VERIFY_PIN_FINISH			0x02
#define FEATURE_MODIFY_PIN_START			0x03
#define FEATURE_MODIFY_PIN_FINISH			0x04
#define FEATURE_GET_KEY_PRESSED				0x05
#define FEATURE_VERIFY_PIN_DIRECT			0x06
#define FEATURE_MODIFY_PIN_DIRECT			0x07
#define FEATURE_MCT_READER_DIRECT			0x08
#define FEATURE_MCT_UNIVERSAL				0x09
#define FEATURE_IFD_PIN_PROP				0x0a
#define FEATURE_ABORT						0x0b
#define FEATURE_SET_SPE_MESSAGE				0x0c
#define FEATURE_VERIFY_PIN_DIRECT_APP_ID	0x0d
#define FEATURE_MODIFY_PIN_DIRECT_APP_ID	0x0e
#define FEATURE_WRITE_DISPLAY				0x0f
#define FEATURE_GET_KEY						0x10
#define FEATURE_IFD_DISPLAY_PROPERTIES		0x11
#define FEATURE_GET_TLV_PROPERTIES			0x12
#define FEATURE_CCID_ESC_COMMAND			0x13
#define FEATURE_EXECUTE_PACE				0x20

#pragma pack(push, 1)
typedef struct _KIWI_TLV_FEATURE {
	BYTE Tag;
	BYTE Length; // 4
	DWORD ControlCode; // BE
} KIWI_TLV_FEATURE, *PKIWI_TLV_FEATURE;
#pragma pack(pop)