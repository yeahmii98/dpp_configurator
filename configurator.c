
#include "aes_siv.h"
#include "hkdf.h"


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <arpa/inet.h>



#include <pcap.h>
#include <string.h> //strncpy
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h> //ifreq
#include <unistd.h> //close

#include <json-c/json.h>

#include "ieee80211/ieee80211.h"
#include "ieee80211/ieee80211_radiotap.h"



#define SUCCESS 1
#define FAIL 0
#define PACKET_MAX_LENGTH 1500
#define KID_LENGTH 43
#define QR_EPUBKEY_LENGTH 125
#define CURVE NID_X9_62_prime256v1
#define KEY_SIZE 32
#define AD1_LEN 6
#define AD2_LEN1 36
#define AD2_LEN2 74
#define AD2_LEN3 41
#define AD2_LEN4 68
#define NONCE_SIZE 16
#define TL_LEN 4
#define CONF_CAP_LEN 1
#define KEY_PMK_LENGTH 32
#define KEY_PRF_RANDOM_LENGTH 32
#define KEY_PRF_INIT "Init Counter\0"
#define KEY_PRF_INIT_LENGTH 13 + ETH_ALEN + sizeof(struct tm)
#define KEY_NONCE_LENGTH 32
#define KEY_MIC_LENGTH 16
#define KEY_IV_LENGTH 16
#define KEY_PKE_LENGTH 100
#define KEY_PTK_LENGTH 80
#define KEY_LENGTH 16
#define KEY_GMK_LENGTH 32
#define KEY_GTK_LENGTH 16
#define PACKED __attribute__((packed))

typedef unsigned char u8;
typedef unsigned short int u16;
typedef unsigned int u32;
typedef unsigned long int u64;

#pragma push(pack)

typedef struct PACKED _AES_SIV_Info
{
    u_int8_t Nonce_Info[NONCE_SIZE + TL_LEN];
    u_int8_t Capability_Info[CONF_CAP_LEN + TL_LEN];
    u_int8_t AD1[AD1_LEN];
    u_int8_t AD2[AD2_LEN1 + AD2_LEN2];
    u_int8_t raw_data[25];

} AESInfo;

typedef struct PACKED _Key_Gen_Attribute
{
    EC_GROUP *ecGroup;

} KeyGenAttr;

typedef struct PACKED _BootstrapingKey_Info
{
    EC_KEY *Key;
    EC_POINT *pubKey;
    BIGNUM *pubKeyX;
    BIGNUM *pubKeyY;
    BIGNUM *privKey;
    unsigned char SHA256_HASH[SHA256_DIGEST_LENGTH];

} BootstrapingKeyInfo;

typedef struct PACKED _EAPOL_KEY
{
    uint8_t pke[KEY_PKE_LENGTH];
    uint8_t ptk[KEY_PTK_LENGTH];
    uint8_t kek[16];
    uint8_t kck[16];
    uint8_t tk[16];
    uint8_t gtk[KEY_GTK_LENGTH];

} eapolKey;

typedef struct PACKED _ProtocolKey_Info
{
    EC_KEY *Key;
    EC_POINT *pubKey;
    BIGNUM *pubKeyX;
    unsigned char pubKeyX_char[KEY_SIZE];
    unsigned char pubKeyY_char[KEY_SIZE];
    //TODO: unsigned char pubKeyX_b64[256];
    char pubKeyX_b64[256];
    char pubKeyY_b64[256];
    BIGNUM *pubKeyY;
    BIGNUM *privKey;
    unsigned char SHA256_HASH[SHA256_DIGEST_LENGTH];
} ProtocolKeyInfo;

typedef struct PACKED _ECDSAKey_Info
{
    EC_KEY *Key;
    EC_POINT *pubKey;
    BIGNUM *pubKeyX;
    BIGNUM *pubKeyY;
    BIGNUM *privKey;
    //TODO: unsigned char pubKeyX_char[KEY_SIZE]; 4 KEY
    char pubKeyX_char[KEY_SIZE];
    char pubKeyY_char[KEY_SIZE];
    char pubKeyX_b64[256];
    char pubKeyY_b64[256];
    //TODO: unsigned char kid[KID_LENGTH];
    char kid[KID_LENGTH];
} ECDSAKeyInfo;

typedef struct PACKED _PPKey_Info
{
    EC_KEY *Key;
    EC_POINT *pubKey;
    BIGNUM *pubKeyX;
    //TODO: unsigned char pubKeyX_char[KEY_SIZE];
    char pubKeyX_char[KEY_SIZE];
    char pubKeyY_char[KEY_SIZE];
    char pubKeyX_b64[256];
    char pubKeyY_b64[256];
    BIGNUM *pubKeyY;
    BIGNUM *privKey;
    unsigned char SHA256_HASH[SHA256_DIGEST_LENGTH];
} PPKeyInfo;

typedef struct PACKED _Key_Info
{
    EC_POINT *M;
    EC_POINT *N;
    BIGNUM *Mx;
    BIGNUM *My;
    BIGNUM *Nx;
    BIGNUM *Ny;
    u_int8_t k1[32];
    u_int8_t k2[32];
    u_int8_t bk[32];
    u_int8_t ke[32];

} KeyInfo;

typedef struct PACKED _Configuration_Req_Object
{
    char *fullData;
    char netRole[10];
    char wifiTech[10];
} ConReqObject;

typedef struct PACKED _Configurator_Info
{
    BootstrapingKeyInfo BootstrapingKey;
    ProtocolKeyInfo ProtocolKey;
    ECDSAKeyInfo ECDSAKey;
    KeyInfo Key;
    PPKeyInfo PPKey;
    KeyGenAttr KeyAttr;
    eapolKey eapolkey;
    // TODO: unsigned char NIC[20];
    char NIC[20];
    unsigned char MACAddr[IEEE80211_ADDR_LEN];
    u_int8_t Nonce[16];
    u_int8_t Auth[32];
    u_int8_t OUI[3];
    u_int8_t tempPacket[PACKET_MAX_LENGTH];
    //TODO: uint8_t JWS[1024];
    char JWS[1024];
    u_int8_t Sign[1024];
    u_int8_t ConfResObj[PACKET_MAX_LENGTH];
    u_int8_t PMK[32];
    char SSID[20];
    char PASS[20];
    u_int8_t Snonce[NONCE_SIZE];

} ConfiguratorInfo;

typedef struct PACKED _Peer_Info
{
    BootstrapingKeyInfo BootstrapingKey;
    ProtocolKeyInfo ProtocolKey;
    unsigned char MACAddr[IEEE80211_ADDR_LEN];
    uint8_t encodedKey[QR_EPUBKEY_LENGTH];
    u_int8_t Nonce[16];
    u_int8_t Auth[32];
    unsigned char wrapped_data[TL_LEN * 4 + NONCE_SIZE * 2 + CONF_CAP_LEN + (TL_LEN + KEY_SIZE + AES_BLOCK_SIZE) + AES_BLOCK_SIZE];
    unsigned char unwrapped_data[TL_LEN * 4 + NONCE_SIZE * 2 + CONF_CAP_LEN + (TL_LEN + KEY_SIZE + AES_BLOCK_SIZE)];
    u_int16_t DPP_STATUS_ID;
    u_int8_t Enonce[NONCE_SIZE];
    u_int8_t Anonce[NONCE_SIZE];
    ConReqObject reqObj;

} PeerInfo;

struct gas_config_frame
{
    uint8_t category;
    uint8_t public_Action;
    uint8_t dToken;
    uint8_t APE[3];
    uint8_t API[7];
    uint16_t query_reqlen;
} __attribute__((packed));

struct gas_config_res_frame
{
    uint8_t category;
    uint8_t public_Action;
    uint8_t dToken;
    uint16_t statusCode;
    uint16_t delay;
    uint8_t APE[3];
    uint8_t API[7];
    uint16_t query_reslen;
} __attribute__((packed));

//PACKET
typedef enum _DPP_SUBTYPE_LIST
{
    DPP_AUTHENTICATION_REQUEST = 00,
    DPP_PRESENCE_ANNOUNCEMENT = 13,
    DPP_AUTHENTICATION_CONFIRM = 0X02,
    DPP_AUTHENTICATION_RESPONSE = 1,
    DPP_CONFIGURATION_REQUEST = 0X0A,
    DPP_CONFIGURATION_RESPONSE = 0X0B
} DPPSubType;

typedef struct PACKED _DPP_Fixed_Parameter
{
    u_int8_t categoryCode;
    u_int8_t publicAction;
    u_int8_t OUI[3];
    u_int8_t WFASubtype;
    u_int8_t cryptoSuite;
    u_int8_t DPPSubtype;
} FixedParam;

typedef enum _DPP_UTIL
{
    TRANSACTION_ID = 0x05,
    DPP_VERSION = 0X02,
    DPP_GENERIC = 0X0151

} DPPUTIL;

typedef enum _DPP_ATTRIBUTE_SIZE
{
    SIZE_DPP_GENERIC = 0x0002,
    SIZE_STATUS = 0x0001,

} DPPAttrSize;

typedef enum _DPP_ATTRIBUTE_LIST
{
    ATTR_STATUS = 0x1000,
    ATTR_INITIATOR_BOOTS_KEY_HASH = 0x1001,
    ATTR_RESPONDER_BOOTS_KEY_HASH = 0x1002,
    ATTR_INITIATOR_PROTOCOL_KEY = 0X1003,
    ATTR_DPP_GENERIC = 0x1018,
    ATTR_WRAPPED_DATA = 0X1004,
    ATTR_ENONCE = 0X1014,
    ATTR_CONFIG_REQUEST_OBJECT = 0X100E,
    ATTR_CONFIG_OBJECT = 0X100C,
    ATTR_DPP_CONNECTOR = 0X100D
} DPPAttrType;

typedef struct PACKED _DPP_Attribute
{
    u_int16_t attrID;
    u_int16_t attrLen;
} Attribute;

typedef struct PACKED _Radiotap_Header
{
    u_int8_t Header_revision;
    u_int8_t Header_Pad;
    u_int16_t Header_Len;
    u_int8_t Present_Flags[4];
    u_int8_t flags;

} RadiotapHeader;
//Authentication(Open)
typedef struct PACKED _Auth_Fixed_Param
{
    u_int16_t Auth_Algorithm;
    u_int16_t Auth_SEQ;
    u_int16_t Status_Code;

} AuthFixedParam;

typedef struct PACKED _Tagged_Param
{
    u_int8_t Tag_Num;
    u_int8_t Tag_Length;
    u_int8_t OUI[3];
    u_int8_t OUI_Type;
    u_int8_t OUI_Data[10];
} AuthTaggedParam;

typedef struct PACKED _Tag_Param_SSID
{
    u_int8_t Tag_Num;
    u_int8_t Tag_Length;
} TagParamSSID;

typedef struct PACKED _Tag_Param_RSN
{
    u_int8_t Tag_Num;
    u_int8_t Tag_Length;
    u_int16_t RSN_Version;
    u_int8_t Group_CipherSuite_OUI[3];
    u_int8_t Group_CipherSuite_Type;
    u_int16_t Pairwise_CipherSuite_Cnt;
    u_int8_t Pairwise_CipherSuite_OUI[3];
    u_int8_t Pairwise_CipherSuite_Type;
    u_int16_t AKM_Suite_Cnt;
    u_int8_t AKM_Suite_OUI[3];
    u_int8_t AKM_Suite_Type;
    u_int16_t RSN_Capabilities;
    u_int16_t PMK_Cnt;
    u_int8_t Group_Manager_CipherSuite_OUI[3];
    u_int8_t Group_Manager_CipherSuite_Type;

} TagParamRSN;

typedef struct PACKED _Tag_Supported_Rates
{
    u_int8_t Tag_Num;
    u_int8_t Tag_Length;
    u_int8_t rates1;
    u_int8_t rates2;
    u_int8_t rates5;
    u_int8_t rates11;

} TagParamSupportedRates;

typedef struct PACKED _Tag_Supported_Channels
{
    u_int8_t Tag_Num;
    u_int8_t Tag_Length;
    u_int8_t First_SupportedChannel;
    u_int8_t SupporteChannel_Range;

} TagParamSupportedChannels;
 
typedef struct PACKED _Tag_Extend
{
    u_int8_t Tag_Num;
    u_int8_t Tag_Length;
    u_int8_t octet1;
    u_int8_t octet2;
    u_int8_t octet3;
    u_int8_t octet4;
    u_int8_t octet5;
    u_int8_t octet6;
    u_int8_t octet7;
    u_int16_t octet89;
    u_int8_t octet10;
} TagExtend;

//Association
typedef struct PACKED _AssoReq_Fixed_Param
{
    u_int16_t Capabilities_Info;
    u_int16_t Listen_Interval;
} AssoReqFixedParam;

typedef struct PACKED _AssoRes_Fixed_Param
{
    u_int16_t Capabilities_Info;
    u_int16_t StatusCode;
    u_int16_t Association_ID;
} AssoResFixedParam;

//4WAY - 1
typedef struct PACKED _Logical_Link_Control
{
    u8 DSAP;
    u8 SSAP;
    u8 ControlField;
    u8 OriginCode[3];
    u16 Type;
} LLC;

typedef struct PACKED _IEEE80211_Authentication
{
    u8 Version;
    u8 Type;
    u16 Length;
    u8 Key_Descriptor_Type;
    u16 Key_Info;
    u16 Key_Length;
    // TODO: counter plus
    u64 Replay_Counter;
    u8 WPA_Key_Nonce[32];
    u8 Key_IV[16];
    u8 WPA_Key_RSC[8];
    u8 WPA_Key_ID[8];
    u8 WPA_Key_MIC[16];
    u16 WPA_Key_DataLen;
} IEEE80211Auth;

typedef struct PACKED _RNS_PMKID
{
    u8 Tag_Number;
    u8 Tag_Length;
    u8 OUI[3];
    u8 Vendor_Specific_OUI;
    u8 PMKID[16];
} RSN_PMKID;

typedef struct PACKED _RSN
{
    u8 oui[3];
    u8 type;
} RSN;

typedef struct PACKED _RSN_INFO
{
    u8 id;
    u8 len;
    u16 version;
    RSN group;
    u16 pairCount;
    RSN pair;
    u16 authCount;
    RSN auth;
    u16 cap;
} RSN_INFO;

typedef struct PACKED _RSN_GTK
{
    u8 id;
    u8 len;
    RSN rsn;
    u8 keyid;
    u8 reserved;
    u8 gtk[16];
} RSN_GTK;

#pragma pop()

//Init
static int
Generate_EC_key(EC_KEY **_tKey)
{
    EC_KEY *tKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (tKey == NULL)
    {
        printf("[ERROR] EC_KEY_new_by_curve_name\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    if (EC_KEY_generate_key(tKey) == FAIL)
    {
        printf("[ERROR] EC_KEY_generate_key\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    *_tKey = tKey;

    return SUCCESS;
}

int base64urlencode(unsigned char *burl, unsigned char *data, int len)
{
    int octets, i;

    /*
     * b64 the data, replace the non-URL safe characters, and get rid of padding
     */
    octets = EVP_EncodeBlock(burl, data, len);
    for (i = 0; i < octets; i++)
    {
        if (burl[i] == '+')
        {
            burl[i] = '-';
        }
        else if (burl[i] == '/')
        {
            burl[i] = '_';
        }
    }
    while (burl[octets - 1] == '=')
    {
        burl[octets - 1] = '\0';
        octets--;
    }
    return octets;
}

static int
get_kid_from_point(unsigned char *kid, const EC_GROUP *group, const EC_POINT *pt, BN_CTX *bnctx)
{
    BIGNUM *x = NULL, *y = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int burllen = -1, bnlen, nid, offset;
    unsigned char *bn = NULL, *ptr;

    if (((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) ||
        ((mdctx = EVP_MD_CTX_new()) == NULL))
    {
        return FAIL;
    }
    nid = EC_GROUP_get_curve_name(group);
    bnlen = 32;

    //get the x- and y-coordinates of the point

    if (!EC_POINT_get_affine_coordinates_GFp(group, pt, x, y, bnctx))
    {
        return FAIL;
    }

    //then make it "uncompressed form"....

    bn = (unsigned char *)malloc(2 * bnlen + 1);
    memset(bn, 0, (2 * bnlen + 1));
    bn[0] = 0x04;
    ptr = &bn[1];
    int temp = BN_num_bytes(x);
    offset = bnlen - BN_num_bytes(x);
    BN_bn2bin(x, ptr + offset);
    ptr = &bn[1 + bnlen];
    offset = bnlen - BN_num_bytes(y);
    BN_bn2bin(y, ptr + offset);

    //hash it all up with SHA256

    EVP_DigestInit(mdctx, EVP_sha256());
    EVP_DigestUpdate(mdctx, bn, 2 * bnlen + 1);
    EVP_DigestFinal(mdctx, digest, &mdlen);

    //and the kid is the base64url of that hash

    if ((burllen = base64urlencode(kid, digest, mdlen)) < 0)
    {
        return FAIL;
    }
    kid[burllen] = '\0';


    return burllen;
}

static int
Generate_ECDSA_Key(ECDSAKeyInfo *_ecdsaKey)
{
    if (Generate_EC_key(&_ecdsaKey->Key) == FAIL)
        return FAIL;

    EC_POINT *tPoint = (EC_POINT *)EC_KEY_get0_public_key(_ecdsaKey->Key);
    if (tPoint == NULL)
    {
        printf("[ERROR] EC_KEY_get0_public_key\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    _ecdsaKey->pubKey = tPoint;

    printf("\n\n");

    // TODO : Error Handling
    BIGNUM *tX = BN_new(), *tY = BN_new();
    if (tX == NULL || tY == NULL)
    {
        printf("[ERROR] BN_new\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    EC_GROUP *tGroup = (EC_GROUP *)EC_KEY_get0_group(_ecdsaKey->Key);
    if (tGroup == NULL)
    {
        printf("[ERROR] EC_KEY_get0_group\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(tGroup, tPoint, tX, tY, NULL))
    {
        printf("[ERROR] EC_POINT_get_affine_coordinates_GFp\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    printf("[KEYGEN] ECDSA Public Key X Coordinate : ");
    BN_print_fp(stdout, tX);
    printf("\n\n");
    _ecdsaKey->pubKeyX = tX;

    printf("[KEYGEN] ECDSA Public Key Y Coordinate : ");
    BN_print_fp(stdout, tY);
    printf("\n\n");
    _ecdsaKey->pubKeyY = tY;

    BIGNUM *tPriv = (BIGNUM *)EC_KEY_get0_private_key(_ecdsaKey->Key);
    if (tPriv == NULL)
    {
        printf("[ERROR] EC_KEY_get0_private_key\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    printf("[KEYGEN] ECDSA Private Key : ");
    BN_print_fp(stdout, tPriv);
    printf("\n\n");
    _ecdsaKey->privKey = tPriv;

    BN_CTX *bnctx = NULL;
    unsigned char csign_kid[KID_LENGTH];
    int kid_len = get_kid_from_point(csign_kid, tGroup, tPoint, NULL);
    if (kid_len < 0)
    {
        printf("error!\n");
    }
    printf("[KEYGEN] KID : ");
    for (int i = 0; i < kid_len; i++)
    {
        printf("%c", csign_kid[i]);
    }
    printf("\n\n");
    memcpy(&_ecdsaKey->kid, &csign_kid, kid_len);

    return SUCCESS;
}

static int
Generate_Bootstraping_Key(BootstrapingKeyInfo *_bootsKeyInfo)
{
    if (Generate_EC_key(&_bootsKeyInfo->Key) == FAIL)
        return FAIL;

    EC_POINT *tPoint = (EC_POINT *)EC_KEY_get0_public_key(_bootsKeyInfo->Key);
    if (tPoint == NULL)
    {
        printf("[ERROR] EC_KEY_get0_public_key\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }
    _bootsKeyInfo->pubKey = tPoint;

    // TODO : Error Handling
    BIGNUM *tX = BN_new(), *tY = BN_new();
    if (tX == NULL || tY == NULL)
    {
        printf("[ERROR] BN_new\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    EC_GROUP *tGroup = (EC_GROUP *)EC_KEY_get0_group(_bootsKeyInfo->Key);
    if (tGroup == NULL)
    {
        printf("[ERROR] EC_KEY_get0_group\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(tGroup, tPoint, tX, tY, NULL))
    {
        printf("[ERROR] EC_POINT_get_affine_coordinates_GFp\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    printf("[KEYGEN] Bootstraping Public Key X Coordinate : ");
    BN_print_fp(stdout, tX);
    printf("\n\n");
    _bootsKeyInfo->pubKeyX = tX;

    printf("[KEYGEN] Bootstraping Public Key Y Coordinate : ");
    BN_print_fp(stdout, tY);
    printf("\n\n");
    _bootsKeyInfo->pubKeyY = tY;

    BIGNUM *tPriv = (BIGNUM *)EC_KEY_get0_private_key(_bootsKeyInfo->Key);
    if (tPriv == NULL)
    {
        printf("[ERROR] EC_KEY_get0_private_key\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    printf("[KEYGEN] Bootstraping Private Key : ");
    BN_print_fp(stdout, tPriv);
    printf("\n\n");
    _bootsKeyInfo->privKey = tPriv;

    return SUCCESS;
}

static int Init(ConfiguratorInfo *_configurator)
{
    // if (Generate_ECDSA_Key(&_configurator->ECDSAKey) == FAIL)
    //     return FAIL;
    // printf("[SUCCESS] Generate_ECDSA_Key\n\n");

    if (Generate_Bootstraping_Key(&_configurator->BootstrapingKey) == FAIL)
        return FAIL;
    printf("[SUCCESS] Generate_Bootstraping_Key\n\n");
}
//Bootstraping
static int
Scanning_QR_Code(PeerInfo *peerInfo)
{
    char QRInfo[] = "DPP:I:SN=4774LH2b4044;M:705DCCF662CA;V:2;K:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4iUrbRr/3M4uWTrmvTFspsbYqTTiPrqFdcxt6VtSbnzUwNHW+StQXEqmFndP+ulj2oBUZOIsrTIca93scMkQKw==;;";

    char *tempArr[10] = {
        NULL,
    };
    int i = 0, asn1len = 0;
    unsigned char keyasn1[1024] = {0};
    char *ptr = strtok(QRInfo, ";");
    char *ptr1 = {NULL};
    while (ptr != NULL)
    {
        tempArr[i] = ptr;
        i++;
        ptr = strtok(NULL, ";");
    }

    for (int i = 0; i < 4; i++)
    {
        if (tempArr[i] != NULL)
            ptr1 = strrchr(tempArr[i], ':');
        tempArr[i] = ptr1 + 1;
    }
    memcpy(peerInfo->encodedKey, tempArr[3], strlen(tempArr[3]));
    int enSize = strlen(tempArr[3]);

    //TODO: int decodeLen = EVP_DecodeBlock(keyasn1, peerInfo->encodedKey, strlen(peerInfo->encodedKey));
    //pubkey decoding
    int decodeLen = EVP_DecodeBlock(keyasn1, peerInfo->encodedKey, enSize);

    printf("[CHECK] DER ASN.1 : ");
    for (int i = 0; i < decodeLen; i++)
        printf("%02x ", keyasn1[i]);

    printf("\n\n");
    const unsigned char *tAsn1 = keyasn1;

    EC_KEY *tKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    tKey = d2i_EC_PUBKEY(NULL, &tAsn1, decodeLen);

    peerInfo->BootstrapingKey.Key = tKey;
    peerInfo->BootstrapingKey.pubKey = (EC_POINT *)EC_KEY_get0_public_key(peerInfo->BootstrapingKey.Key);

    BIGNUM *tX = BN_new(), *tY = BN_new();
    if (tX == NULL || tY == NULL)
    {
        printf("[ERROR] BN_new\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    EC_GROUP *tGroup = (EC_GROUP *)EC_KEY_get0_group(peerInfo->BootstrapingKey.Key);
    if (tGroup == NULL)
    {
        printf("[ERROR] EC_KEY_get0_group\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(tGroup, peerInfo->BootstrapingKey.pubKey, tX, tY, NULL))
    {
        printf("[ERROR] EC_POINT_get_affine_coordinates_GFp\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    printf("[KEYGEN] Peer's Bootstraping Public Key X Coordinate : ");
    BN_print_fp(stdout, tX);
    printf("\n\n");
    peerInfo->BootstrapingKey.pubKeyX = tX;

    printf("[KEYGEN] Peer's Bootstraping Public Key Y Coordinate : ");
    BN_print_fp(stdout, tY);
    printf("\n\n");
    peerInfo->BootstrapingKey.pubKeyY = tY;

    printf("[STORE] Store Peer's MAC Address : ");

    int j = 0;
    for (int i = 0; i < IEEE80211_ADDR_LEN * 2; i = i + 2)
    {
        char temp[3] = {tempArr[1][i], tempArr[1][i + 1], '\0'};
        peerInfo->MACAddr[j] = strtol(temp, NULL, 16);
        printf("%02X ", peerInfo->MACAddr[j++]);
    }
    printf("\n\n");

    return SUCCESS;
}

//TODO: Select_Device(pcap_t **_adhandle, unsigned char *_NIC)
static int
Select_Device(pcap_t **_adhandle, char *_NIC)
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    struct pcap_addr *a;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;
    int no;

    if (pcap_findalldevs(&alldevs, errbuf) < 0)
    {
        printf("pcap_findalldevs error\n");
        return -1;
    }

    for (d = alldevs; d; d = d->next)
        printf("%d : %s\n", ++i, (d->name));

    printf("\n[CHECK] Monitoring NIC number : ");
    // scanf("%d", &no);
    no = 4;

    if (!(no > 0 && no <= i))
    {
        printf("number error\n");
        return -1;
    }

    for (d = alldevs, i = 0; d; d = d->next)
    {
        if (no == ++i)
        {
            break;
        }
    }
    printf("%s\n\n", d->name);

    if (!(*_adhandle = pcap_open_live(d->name, BUFSIZ, 0, 100, errbuf)))
    {
        printf("pcap_open_live error %s\n", d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }
    memcpy(_NIC, d->name, strlen(d->name));
    pcap_freealldevs(alldevs);

    return 0;
}

void Get_My_MACAddr(ConfiguratorInfo *_configurator)
{
    int fd;
    struct ifreq ifr;
    //TODO: char *iface = _configurator->NIC;
    char *iface = _configurator->NIC;
    unsigned char *mac;
    unsigned char tmac[12];
    unsigned int *hex_mac;
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    close(fd);
    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    memcpy(_configurator->MACAddr, ifr.ifr_hwaddr.sa_data, IEEE80211_ADDR_LEN);

    printf("Mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int
Generate_Chirp_Bootspubkey_Hash(EC_KEY *key, unsigned char _digest[])
{
    int asn1len;
    BIO *bio;
    EVP_MD_CTX *mdctx;
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
    unsigned char *asn1;
    unsigned char digest[SHA256_DIGEST_LENGTH];

    memset(digest, 0, SHA256_DIGEST_LENGTH);

    if ((bio = BIO_new(BIO_s_mem())) == NULL)
    {
        return FAIL;
    }
    if ((mdctx = EVP_MD_CTX_new()) == NULL)
    {
        BIO_free(bio);
        return FAIL;
    }
    (void)i2d_EC_PUBKEY_bio(bio, key);
    (void)BIO_flush(bio);
    asn1len = BIO_get_mem_data(bio, &asn1);

    EVP_DigestInit(mdctx, EVP_sha256());
    EVP_DigestUpdate(mdctx, "chirp", strlen("chirp"));
    EVP_DigestUpdate(mdctx, asn1, asn1len);
    EVP_DigestFinal(mdctx, digest, &mdlen);

    BIO_free(bio);
    EVP_MD_CTX_free(mdctx);

    printf("[CHECK] Chirp Bootspubkey Hash :  ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02X ", digest[i]);
    printf("\n\n");

    memcpy(_digest, digest, SHA256_DIGEST_LENGTH);

    return SUCCESS;
}

static int
is_equal(u_int8_t com1[], u_int8_t com2[], int len)
{
    for (int i = 0; i < len; i++)
    {
        if (com1[i] != com2[i])
        {
            return FAIL;
        }
    }
    return SUCCESS;
}

static int
Verify_Peer_BootsPubkey(const unsigned char *_packet, EC_KEY *_pubkey)
{
    unsigned char *packet = (unsigned char *)_packet;
    //Parse hash value
    Attribute *attr = (Attribute *)packet;

    unsigned char *data = (unsigned char *)(packet + sizeof(*attr));

    printf("[CHECK] Get Peer's Chirp Key Hash : ");
    for (int i = 0; i < attr->attrLen; i++)
        printf("%02X ", *(data + i));
    printf("\n\n");

    //Gen HASH
    unsigned char digest[SHA256_DIGEST_LENGTH] = {0};
    Generate_Chirp_Bootspubkey_Hash(_pubkey, digest);
    // Verify

    printf("[CHECK] Chirp Hash Generated by Configurator : ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        printf("%02x", digest[i]);
    }
    printf("\n\n");

    printf("[CHECK] Chirp Hash Generated by Peer : ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n\n");

    if (is_equal(digest, data, SHA256_DIGEST_LENGTH) == SUCCESS)
    {
        printf("[INFO] Peer Bootstrap Public Key Validated!!\n\n");
        return SUCCESS;
    }
    else
    {
        printf("[INFO] Peer Bootstrap Public Key Fail to Validate..\n\n");
        return FAIL;
    }
}

static int
is_dpp(pcap_t *adhandle, PeerInfo *peer)
{
    struct pcap_pkthdr *header;
    const unsigned char *packet;

    int result = pcap_next_ex(adhandle, &header, &packet);
    int dataPointer = 0;

    struct ieee80211_radiotap_header *tRadio = (struct ieee80211_radiotap_header *)packet;
    dataPointer += tRadio->it_len;

    struct ieee80211_frame *fh = (struct ieee80211_frame *)(packet + dataPointer);
    dataPointer += sizeof(*fh);

    u_int8_t type = fh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    u_int8_t subtype = fh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    if (is_equal(fh->i_addr2, peer->MACAddr, ETH_ALEN))
    {
        // ! del!
        if (type == IEEE80211_FC0_TYPE_MGT && subtype == 0xD0)
        {
            FixedParam *fp = (FixedParam *)(packet + dataPointer);
            dataPointer += sizeof(*fp);

            if (fp->categoryCode == 0x04 && fp->WFASubtype == 26)
            {
                if (fp->DPPSubtype == DPP_PRESENCE_ANNOUNCEMENT)
                {
                    //Attribute *attr = (Attribute *)(packet + dataPointer);
                    // dataPointer += sizeof(*attr);

                    printf("[CHECK] DPP Presence Announcement\n\n");
                    for (int i = 0; i < dataPointer; i++)
                    {
                        printf("%02X ", packet[i]);
                        if (!((i + 1) % 8))
                            printf("  ");
                        if (!((i + 1) % 16))
                            printf("\n");
                    }
                    printf("\n\n");
                    printf("[INFO] This Packet Type is DPP!!\n\n");

                    if (Verify_Peer_BootsPubkey(packet + dataPointer, peer->BootstrapingKey.Key) == FAIL)
                    {
                        return FAIL;
                    }

                    return SUCCESS;
                }
                else
                {
                    return FAIL;
                }
            }
            else
            {
                return FAIL;
            }
        }
        else
        {
            return FAIL;
        }
    }
    else
    {
        return FAIL;
    }
}

static int Check_Configuration_Req(ConfiguratorInfo *_configurator, PeerInfo *_peer, pcap_t *_adhandle);

static int Bootstraping(ConfiguratorInfo *_configurator, PeerInfo *_peer, pcap_t *_adhandle)
{

    //scanning qr
    if (Scanning_QR_Code(_peer) == FAIL)
    {
        printf("[STATUS] Scanning_QR_Code Fail..\n\n");
        return FAIL;
    }
    else
    {
        printf("[STATUS] Scanning_QR_Code Success!!\n\n");
        while (1)
        {
            if (is_dpp(_adhandle, _peer) == SUCCESS)
            {
                break;
            }
        }

        return SUCCESS;
    }
}

static int Init_Key(ConfiguratorInfo *_configurator, PeerInfo *_peer)
{
    printf("[INFO] Init_Key\n\n");
    _configurator->KeyAttr.ecGroup = EC_GROUP_new_by_curve_name(CURVE);
    //peer
    // _peer->BootstrapingKey.Key = (EC_KEY *)EC_POINT_new(_configurator->KeyAttr.ecGroup);
    // _peer->BootstrapingKey.pubKeyX = BN_new();
    // _peer->BootstrapingKey.pubKeyY = BN_new();
    _peer->ProtocolKey.Key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    _peer->ProtocolKey.pubKeyX = BN_new();
    _peer->ProtocolKey.pubKeyY = BN_new();
    _peer->ProtocolKey.pubKey = EC_POINT_new(_configurator->KeyAttr.ecGroup);

    //SharedKey
    _configurator->Key.M = EC_POINT_new(_configurator->KeyAttr.ecGroup);
    _configurator->Key.Mx = BN_new();
    _configurator->Key.My = BN_new();
    _configurator->Key.N = EC_POINT_new(_configurator->KeyAttr.ecGroup);
    _configurator->Key.Nx = BN_new();
    _configurator->Key.Ny = BN_new();

    //memset
    memset(_configurator->Key.k1, 0, KEY_SIZE);
    memset(_configurator->Key.k2, 0, KEY_SIZE);
    memset(_configurator->Key.bk, 0, KEY_SIZE);
    memset(_configurator->Key.ke, 0, KEY_SIZE);
    memset(_configurator->Nonce, 0, KEY_SIZE);
    memset(_configurator->Auth, 0, KEY_SIZE);
    memset(_peer->Nonce, 0, KEY_SIZE);
    memset(_peer->Auth, 0, KEY_SIZE);

    printf("[INFO] Init_Key Done!\n\n");

    return SUCCESS;
}

static int
Init_Packet(unsigned char _SrcMAC[], unsigned char _DstMAC[], DPPSubType _type, unsigned char _packet[])
{
    int dataPointer = 0;

    //radiotap header
    unsigned char radiotap[] = {0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(_packet, radiotap, sizeof(radiotap));
    dataPointer += sizeof(radiotap);

    //ieee80211 action frame
    struct ieee80211_frame fh;
    fh.i_fc[0] = IEEE80211_FC0_SUBTYPE_ACK | IEEE80211_FC0_TYPE_MGT;
    fh.i_fc[1] = 0;
    fh.i_dur[0] = 0x00;
    fh.i_dur[1] = 0x00;
    memcpy(fh.i_addr1, _DstMAC, IEEE80211_ADDR_LEN);
    memcpy(fh.i_addr2, _SrcMAC, IEEE80211_ADDR_LEN);
    memcpy(fh.i_addr3, _DstMAC, IEEE80211_ADDR_LEN);

    memcpy(_packet + dataPointer, &fh, sizeof(fh));
    dataPointer += sizeof(fh);

    //dpp
    FixedParam fp;
    fp.categoryCode = 0x04;
    fp.publicAction = 0x09;
    fp.OUI[0] = 0x50;
    fp.OUI[1] = 0x6f;
    fp.OUI[2] = 0x9a;
    fp.WFASubtype = 0x1a;
    fp.cryptoSuite = 0x01;
    fp.DPPSubtype = _type;

    memcpy(_packet + dataPointer, &fp, sizeof(fp));
    dataPointer += sizeof(fp);

    return dataPointer;
}

static int Generate_Attribute(DPPAttrType _ID, int _AttrLen, uint8_t *_Value, unsigned char _packet[], int ex_dataPointer)
{
    int dataPointer = ex_dataPointer;

    Attribute da;
    da.attrID = _ID;
    da.attrLen = _AttrLen;

    memcpy(_packet + dataPointer, &da, sizeof(da));
    dataPointer += sizeof(da);

    memcpy(_packet + dataPointer, _Value, _AttrLen);
    dataPointer += _AttrLen;

    printf("[Generate Packet]\n\n");
    for (int i = 0; i < dataPointer; i++)
    {
        printf("%02X ", _packet[i]);
        if (!((i + 1) % 8))
            printf("  ");
        if (!((i + 1) % 16))
            printf("\n");
    }
    printf("\n\n");

    return dataPointer;
}

void SHA256_hash(uint8_t input[], char hash_string[], size_t len)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input, len);
    SHA256_Final(digest, &ctx);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(&hash_string[i * 2], "%02x", (unsigned int)digest[i]);
}

void stringtohex(const char *string, uint8_t *output, size_t len)
{
    const char *pos = string;
    for (size_t count = 0; count < len; count++)
    {
        sscanf(pos, "%2hhx", &output[count]);
        pos += 2;
    }
}

static int pubKey_to_SHA256(EC_KEY *_key, unsigned char _digest[])
{
    int asn1len;
    unsigned char data[1024];
    BIO *bio2;
    // EVP_MD_CTX *mdctx;
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
    unsigned char *asn1;
    unsigned char digest[SHA256_DIGEST_LENGTH];

    memset(digest, 0, SHA256_DIGEST_LENGTH);

    if ((bio2 = BIO_new(BIO_s_mem())) == NULL)
    {
        return FAIL;
    }

    (void)i2d_EC_PUBKEY_bio(bio2, _key);
    (void)BIO_flush(bio2);
    asn1len = BIO_get_mem_data(bio2, &asn1);
    int encodeLen = EVP_EncodeBlock(data, asn1, asn1len);

    printf("[INFO] Encoded Bootstrapping Public Key(ASN.1) : ");
    for (int i = 0; i < asn1len - KEY_SIZE; i++)
        printf("%02x", asn1[i]);
    printf("\n\n");

    // Hash BR_Hash
    char BR_hash_string[SHA256_DIGEST_LENGTH * 2 + 1];
    SHA256_hash(asn1, BR_hash_string, asn1len - KEY_SIZE);
    stringtohex(BR_hash_string, digest, SHA256_DIGEST_LENGTH);

    printf("[CHECK] PubKey -> SHA256 : ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02X ", digest[i]);
    printf("\n\n");

    memcpy(_digest, digest, SHA256_DIGEST_LENGTH);

    return SUCCESS;
}

static int
Generate_Protocol_Key(ProtocolKeyInfo *_procotolKey)
{
    if (Generate_EC_key(&_procotolKey->Key) == FAIL)
        return FAIL;

    EC_POINT *tPoint = (EC_POINT *)EC_KEY_get0_public_key(_procotolKey->Key);
    if (tPoint == NULL)
    {
        printf("[ERROR] EC_KEY_get0_public_key\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }
    _procotolKey->pubKey = tPoint;

    // TODO : Error Handling
    BIGNUM *tX = BN_new(), *tY = BN_new();
    if (tX == NULL || tY == NULL)
    {
        printf("[ERROR] BN_new\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    EC_GROUP *tGroup = (EC_GROUP *)EC_KEY_get0_group(_procotolKey->Key);
    if (tGroup == NULL)
    {
        printf("[ERROR] EC_KEY_get0_group\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(tGroup, tPoint, tX, tY, NULL))
    {
        printf("[ERROR] EC_POINT_get_affine_coordinates_GFp\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    printf("[KEYGEN] Protocol Public Key X Coordinate : ");
    BN_print_fp(stdout, tX);
    printf("\n\n");
    _procotolKey->pubKeyX = tX;

    printf("[KEYGEN] Protocol Public Key Y Coordinate : ");
    BN_print_fp(stdout, tY);
    printf("\n\n");
    _procotolKey->pubKeyY = tY;

    _procotolKey->privKey = (BIGNUM *)EC_KEY_get0_private_key(_procotolKey->Key);
    if (_procotolKey->privKey == NULL)
    {
        printf("[ERROR] EC_KEY_get0_private_key\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }
    printf("[KEYGEN] Protocol Private Key : ");
    BN_print_fp(stdout, _procotolKey->privKey);
    printf("\n\n");
    // _procotolKey->privKey = tPriv;

    return SUCCESS;
}

void PRNG(uint8_t *in, int len)
{
    int retVal = 0;
    RAND_status();

    retVal = RAND_bytes(in, len);
    if (retVal <= 0)
    {
        printf("error count!\n");
        exit(1);
    }
}

void Init_AES_SIV(ConfiguratorInfo *_configurator, PeerInfo *_peer, AESInfo *_aes)
{
    u_int8_t tempCap[CONF_CAP_LEN + TL_LEN] = {0x06, 0x10, 0x01, 0x00, 0x02};
    memcpy(_aes->Capability_Info, tempCap, CONF_CAP_LEN + TL_LEN);

    printf("[CHECK] Configurator Capability Info : ");
    for (int i = 0; i < CONF_CAP_LEN + TL_LEN; i++)
    {
        printf("%02x", _aes->Capability_Info[i]);
    }
    printf("\n\n");

    u_int8_t tempNonce[TL_LEN] = {0x05, 0x10, 0x10, 0x00};
    memcpy(_aes->Nonce_Info, tempNonce, TL_LEN);
    PRNG(_configurator->Nonce, NONCE_SIZE);
    printf("[CHECK] Configurator Nonce : ");
    for (int i = 0; i < NONCE_SIZE; i++)
    {
        printf("%02x", _configurator->Nonce[i]);
    }
    printf("\n\n");

    memcpy(_aes->Nonce_Info + TL_LEN, _configurator->Nonce, NONCE_SIZE);
    printf("[CHECK] Configurator Nonce Info : ");
    for (int i = 0; i < NONCE_SIZE + TL_LEN; i++)
    {
        printf("%02x", _aes->Nonce_Info[i]);
    }
    printf("\n\n");

    memcpy(_aes->raw_data, _aes->Nonce_Info, NONCE_SIZE + TL_LEN);
    memcpy(_aes->raw_data + NONCE_SIZE + TL_LEN, _aes->Capability_Info, CONF_CAP_LEN + TL_LEN);
    printf("[CHECK] Raw Data(for encryption) : ");
    for (int i = 0; i < 25; i++)
    {
        printf("%02x", _aes->raw_data[i]);
    }
    printf("\n\n");
}

static int Generate_Authentication_Req(ConfiguratorInfo *_configurator, PeerInfo *_peer)
{
    u_int8_t packet[PACKET_MAX_LENGTH] = {0};
    u_int8_t AD2[AD2_LEN1 + AD2_LEN2] = {0};
    int tempBuff = 0;
    int init_dataPointer = Init_Packet(_configurator->MACAddr, _peer->MACAddr, DPP_AUTHENTICATION_REQUEST, packet);
    // BR HASH
    pubKey_to_SHA256(_peer->BootstrapingKey.Key, _peer->BootstrapingKey.SHA256_HASH);

    int dataPointer = Generate_Attribute(ATTR_RESPONDER_BOOTS_KEY_HASH, SHA256_DIGEST_LENGTH, _peer->BootstrapingKey.SHA256_HASH, packet, init_dataPointer);

    //ad2 - boot hash
    memcpy(AD2, packet + (dataPointer - TL_LEN - SHA256_DIGEST_LENGTH), TL_LEN + SHA256_DIGEST_LENGTH);
    tempBuff += TL_LEN + SHA256_DIGEST_LENGTH;
    // Generate Protocol Key
    if (Generate_Protocol_Key(&_configurator->ProtocolKey) == FAIL)
        return FAIL;

    BN_print_fp(stdout, _configurator->ProtocolKey.privKey);
    printf("\n\n");

    // Generate shared M
    if (EC_POINT_mul(_configurator->KeyAttr.ecGroup, _configurator->Key.M, NULL, _peer->BootstrapingKey.pubKey, _configurator->ProtocolKey.privKey, NULL) == FAIL)
    {
        printf("[STATUS] Fail to generate Shared M..\n\n");
        return FAIL;
    }

    if (EC_POINT_get_affine_coordinates_GFp(_configurator->KeyAttr.ecGroup,
                                            _configurator->Key.M,
                                            _configurator->Key.Mx,
                                            _configurator->Key.My, NULL) == FAIL)
    {
        printf("[STATUS] Fail to EC_POINT_get_affine_coordinates_GFp..\n\n");
        printf("\t%s\n\n", ERR_error_string(ERR_get_error(), NULL));
        return FAIL;
    }

    printf("[KEYGEN] Shared Key M X Coordinate : ");
    BN_print_fp(stdout, _configurator->Key.Mx);
    printf("\n\n");

    printf("[KEYGEN] Shared Key M Y Coordinate : ");
    BN_print_fp(stdout, _configurator->Key.My);
    printf("\n\n");

    // Generate K1
    //TODO: unsigned char *k1_info = "first intermediate key";
    char *k1_info = "first intermediate key";
    uint8_t tempM[KEY_SIZE] = {0};
    BN_bn2bin(_configurator->Key.Mx, tempM);

    //TODO: HMAC(EVP_sha256(), tempM, KEY_SIZE, k1_info, strlen(k1_info), _configurator->Key.k1, NULL);
    HMAC(EVP_sha256(), tempM, KEY_SIZE, (const unsigned char *)k1_info, strlen(k1_info), _configurator->Key.k1, NULL);

    printf("[KEYGEN] K1 : ");
    for (int i = 0; i < KEY_SIZE; i++)
    {
        printf("%02x", _configurator->Key.k1[i]);
    }
    printf("\n\n");

    // Protocol Key(Configurator)
    BN_bn2bin(_configurator->ProtocolKey.pubKeyX, _configurator->ProtocolKey.pubKeyX_char);
    BN_bn2bin(_configurator->ProtocolKey.pubKeyY, _configurator->ProtocolKey.pubKeyY_char);

    printf("[CHECK] Configurator's Protocol Public Key(X) : ");
    for (int i = 0; i < KEY_SIZE; i++)
    {
        printf("%02x", _configurator->ProtocolKey.pubKeyX_char[i]);
    }
    printf("\n\n");

    printf("[CHECK] Configurator's Protocol Public Key(Y) : ");
    for (int i = 0; i < KEY_SIZE; i++)
    {
        printf("%02x", _configurator->ProtocolKey.pubKeyY_char[i]);
    }
    printf("\n\n");

    unsigned char tempChar[KEY_SIZE + KEY_SIZE] = {0};
    memcpy(tempChar, _configurator->ProtocolKey.pubKeyX_char, KEY_SIZE);
    memcpy(tempChar + KEY_SIZE, _configurator->ProtocolKey.pubKeyY_char, KEY_SIZE);

    printf("[CHECK] Configurator's Protocol Public Key(X | Y) : ");
    for (int i = 0; i < KEY_SIZE * 2; i++)
    {
        printf("%02x", tempChar[i]);
    }
    printf("\n\n");

    dataPointer = Generate_Attribute(ATTR_INITIATOR_PROTOCOL_KEY, KEY_SIZE * 2, tempChar, packet, dataPointer);
    //ad2 - protocol pub eky
    memcpy(AD2 + tempBuff, packet + (dataPointer - TL_LEN - KEY_SIZE * 2), TL_LEN + KEY_SIZE * 2);
    tempBuff += TL_LEN + KEY_SIZE * 2;

    u_int8_t generic = htons(0x5101);
    dataPointer = Generate_Attribute(ATTR_DPP_GENERIC, SIZE_DPP_GENERIC, &generic, packet, dataPointer);
    //ad2 - protocol pub eky
    memcpy(AD2 + tempBuff, packet + (dataPointer - TL_LEN - 2), TL_LEN + 2);
    tempBuff += TL_LEN + 2;

    // Encrypt(KEY, )
    AESInfo _aes = {0};
    siv_ctx ctx;
    siv_init(&ctx, _configurator->Key.k1, SIV_256);

    Init_AES_SIV(_configurator, _peer, &_aes);

    _configurator->OUI[0] = 0x50;
    _configurator->OUI[1] = 0x6f;
    _configurator->OUI[2] = 0x9a;

    u_int8_t AD1[AD1_LEN] = {0};
    unsigned char tempOUI[3] = {0x50, 0x6f, 0x9a};
    memcpy(AD1, tempOUI, 3);
    tempBuff = 3;
    unsigned char tempAD1[] = {0x1a, 0x01, 0x00};
    memcpy(AD1 + tempBuff, tempAD1, 3);

    printf("[CHECK] REQ WRAP - AD1 : ");
    for (int i = 0; i < AD1_LEN; i++)
    {
        printf("%02x", AD1[i]);
    }
    printf("\n\n");

    printf("[CHECK] REQ WRAP - AD2 : ");
    for (int i = 0; i < AD2_LEN1 + AD2_LEN2; i++)
    {
        printf("%02x", AD2[i]);
    }
    printf("\n\n");

    u_int8_t wrapped_data[CONF_CAP_LEN + TL_LEN + NONCE_SIZE + TL_LEN + AES_BLOCK_SIZE] = {0};
    siv_encrypt(
        &ctx,
        _aes.raw_data,
        wrapped_data + AES_BLOCK_SIZE,
        CONF_CAP_LEN + TL_LEN + NONCE_SIZE + TL_LEN,
        wrapped_data,
        2,
        AD1,
        sizeof(AD1),
        AD2,
        sizeof(AD2));

    printf("[CHECK] REQ WRAP - ENCRYPTED DATA : ");
    for (int i = 0; i < CONF_CAP_LEN + TL_LEN + NONCE_SIZE + TL_LEN + AES_BLOCK_SIZE; i++)
    {
        printf("%02x", wrapped_data[i]);
    }
    printf("\n\n");

    dataPointer = Generate_Attribute(ATTR_WRAPPED_DATA, CONF_CAP_LEN + TL_LEN + NONCE_SIZE + TL_LEN + AES_BLOCK_SIZE, wrapped_data, packet, dataPointer);
    memcpy(_configurator->tempPacket, &packet, sizeof(packet));

    return dataPointer;
}

static int Check_Authentication_Resp(pcap_t *_adhandle, ConfiguratorInfo *_configurator, PeerInfo *_peer)
{
    KeyGenAttr *keyAttr;
    AESInfo *aes;
    struct pcap_pkthdr *header;
    const unsigned char *_packet;

    int result = pcap_next_ex(_adhandle, &header, &_packet);

    unsigned char *packet = (unsigned char *)_packet;
    int dataPointer = 0;

    struct ieee80211_radiotap_header *tRadio = (struct ieee80211_radiotap_header *)packet;
    // dataPointer += ntohs(tRadio->it_len);
    dataPointer += tRadio->it_len;
    struct ieee80211_frame *fh = (struct ieee80211_frame *)(packet + dataPointer);
    dataPointer += sizeof(*fh);

    u_int8_t type = fh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    u_int8_t subtype = fh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    if (is_equal(_configurator->MACAddr, fh->i_addr1, IEEE80211_ADDR_LEN) && is_equal(_peer->MACAddr, fh->i_addr2, IEEE80211_ADDR_LEN))
    {
        if (type == IEEE80211_FC0_TYPE_MGT && subtype == IEEE80211_FC0_SUBTYPE_ACK)
        {
            FixedParam *fp = (FixedParam *)(packet + dataPointer);
            dataPointer += sizeof(*fp);
            if (fp->categoryCode == 0x04 && fp->WFASubtype == 26)
            {
                if (fp->DPPSubtype == DPP_AUTHENTICATION_RESPONSE)
                {
                    printf("[INFO]This Packet Type is DPP Authentication Response Packet!!\n\n");
                    Attribute *attr0 = (Attribute *)(packet + dataPointer);
                    dataPointer += sizeof(*attr0);
                    unsigned char *status = (unsigned char *)(packet + dataPointer);
                    dataPointer += attr0->attrLen;

                    Attribute *attr1 = (Attribute *)(packet + dataPointer);
                    dataPointer += TL_LEN;
                    unsigned char *Peer_BootsHash = (unsigned char *)(packet + dataPointer);
                    dataPointer += SHA256_DIGEST_LENGTH;
                    printf("[CHECK] Peer's Bootstraping Key Hash(Local) : ");
                    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
                    {
                        printf("%02x", _peer->BootstrapingKey.SHA256_HASH[i]);
                    }
                    printf("\n\n");

                    printf("[CHECK] Peer's Bootstraping Key Hash(From Packet) : ");
                    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
                    {
                        printf("%02x", Peer_BootsHash[i]);
                    }
                    printf("\n\n");

                    if (is_equal(_peer->BootstrapingKey.SHA256_HASH, Peer_BootsHash, SHA256_DIGEST_LENGTH))
                    {
                        Attribute *attr2 = (Attribute *)(packet + dataPointer);
                        dataPointer += TL_LEN;
                        unsigned char *Peer_ProtoPubkey = (unsigned char *)(packet + dataPointer);
                        dataPointer += 64;
                        // memcpy(_peer->AD2_Dynamic, Peer_ProtoPubkey, attr2->attrLen);

                        memcpy(_peer->ProtocolKey.pubKeyX_char, Peer_ProtoPubkey, KEY_SIZE);
                        printf("[CHECK] Peer's Protocol Public Key X(char) : ");
                        for (int i = 0; i < KEY_SIZE; i++)
                        {
                            printf("%02x", _peer->ProtocolKey.pubKeyX_char[i]);
                        }
                        printf("\n\n");
                        memcpy(_peer->ProtocolKey.pubKeyY_char, Peer_ProtoPubkey + KEY_SIZE, KEY_SIZE);
                        printf("[CHECK] Peer's Protocol Public Key Y(char) : ");
                        for (int i = 0; i < KEY_SIZE; i++)
                        {
                            printf("%02x", _peer->ProtocolKey.pubKeyY_char[i]);
                        }
                        printf("\n\n");
                        BN_bin2bn(_peer->ProtocolKey.pubKeyX_char, KEY_SIZE, _peer->ProtocolKey.pubKeyX);
                        BN_bin2bn(_peer->ProtocolKey.pubKeyY_char, KEY_SIZE, _peer->ProtocolKey.pubKeyY);
                        printf("[CHECK] Peer's Protocol Public Key X : ");
                        BN_print_fp(stdout, _peer->ProtocolKey.pubKeyX);
                        printf("\n\n");
                        printf("[CHECK] Peer's Protocol Public Key Y : ");
                        BN_print_fp(stdout, _peer->ProtocolKey.pubKeyY);
                        printf("\n\n");

                        // EC_POINT *tempPubKey = EC_POINT_new(_configurator->KeyAttr.ecGroup);

                        if (EC_POINT_set_affine_coordinates_GFp(
                                _configurator->KeyAttr.ecGroup,
                                _peer->ProtocolKey.pubKey,
                                _peer->ProtocolKey.pubKeyX,
                                _peer->ProtocolKey.pubKeyY, NULL) == FAIL)
                        {
                            printf("[ERROR] : %s\n\n", ERR_error_string(ERR_get_error(), NULL));
                            return FAIL;
                        }

                        // Attribute *attr3 = (Attribute *)(packet + dataPointer);
                        // dataPointer += TL_LEN;
                        // unsigned char *generic = (unsigned char *)(packet + dataPointer);
                        // dataPointer += attr3->attrLen;

                        Attribute *attr4 = (Attribute *)(packet + dataPointer);
                        dataPointer += TL_LEN;
                        unsigned char *wrappedData = (unsigned char *)(packet + dataPointer);
                        memcpy(_peer->wrapped_data, wrappedData, attr4->attrLen);
                        printf("[CHECK] Wrapped Data : ");
                        for (int i = 0; i < attr4->attrLen; i++)
                        {
                            printf("%02x", _peer->wrapped_data[i]);
                        }
                        printf("\n\n");

                        if (EC_GROUP_check(_configurator->KeyAttr.ecGroup, NULL) == FAIL)
                        {
                            printf("[ERROR %d] : %s\n\n", __LINE__, ERR_error_string(ERR_get_error(), NULL));
                            return FAIL;
                        }
                        //BN_print_fp(stdout,_configurator->Key.N);
                        // if(EC_POINT_is_at_infinity(_configurator->KeyAttr.ecGroup, _peer->ProtocolKey.pubKey) == FAIL)
                        // {
                        //     printf("[ERROR %d] : %s\n\n", __LINE__,ERR_error_string(ERR_get_error(), NULL));
                        //     return FAIL;
                        // }

                        //decrypt
                        if (EC_POINT_mul(_configurator->KeyAttr.ecGroup, _configurator->Key.N, NULL, _peer->ProtocolKey.pubKey, _configurator->ProtocolKey.privKey, NULL) == FAIL)
                        {
                            printf("[ERROR] : %s\n\n", ERR_error_string(ERR_get_error(), NULL));
                            return FAIL;
                        }

                        if (EC_POINT_get_affine_coordinates_GFp(_configurator->KeyAttr.ecGroup,
                                                                _configurator->Key.N,
                                                                _configurator->Key.Nx,
                                                                _configurator->Key.Ny, NULL) == FAIL)
                        {
                            printf("[ERROR] : %s\n\n", ERR_error_string(ERR_get_error(), NULL));
                            return FAIL;
                        }

                        printf("[KEYGEN] Shared Key N X Coordinate : ");
                        BN_print_fp(stdout, _configurator->Key.Nx);
                        printf("\n\n");

                        printf("[KEYGEN] Shared Key N Y Coordinate : ");
                        BN_print_fp(stdout, _configurator->Key.Ny);
                        printf("\n\n");

                        //K2 CREATE
                        const EVP_MD *temp = EVP_sha256();
                        //TODO: unsigned char *k2_info = "second intermediate key";
                        char *k2_info = "second intermediate key";
                        uint8_t tempN[KEY_SIZE] = {0};
                        BN_bn2bin(_configurator->Key.Nx, tempN);
                        //TODO: k2_info
                        HMAC(EVP_sha256(), tempN, KEY_SIZE, (const unsigned char *)k2_info, strlen(k2_info), _configurator->Key.k2, NULL);
                        printf("[KEYGEN] K2 : ");
                        for (int i = 0; i < KEY_SIZE; i++)
                        {
                            printf("%02x", _configurator->Key.k2[i]);
                        }
                        printf("\n\n");

                        //BK CREATE
                        u_int8_t mn_X[KEY_SIZE * 2];
                        BN_bn2bin(_configurator->Key.Mx, mn_X);
                        BN_bn2bin(_configurator->Key.Nx, mn_X + KEY_SIZE);

                        u_int8_t AD1[AD1_LEN] = {0};
                        memcpy(AD1, fp->OUI, 3);
                        int tempBuff = 3;
                        unsigned char tempAD1[] = {0x1a, 0x01, 0x01};
                        memcpy(AD1 + tempBuff, tempAD1, 3);

                        printf("[CHECK] AD1 : ");
                        for (int i = 0; i < AD1_LEN; i++)
                        {
                            printf("%02x", AD1[i]);
                        }
                        printf("\n\n");

                        u_int8_t AD2[AD2_LEN3 + AD2_LEN4] = {0};
                        tempBuff = 0;
                        memcpy(AD2, attr0, TL_LEN);
                        tempBuff += TL_LEN;
                        memcpy(AD2 + tempBuff, status, attr0->attrLen);
                        tempBuff += attr0->attrLen;
                        memcpy(AD2 + tempBuff, attr1, TL_LEN);
                        tempBuff += TL_LEN;
                        memcpy(AD2 + tempBuff, Peer_BootsHash, attr1->attrLen);
                        tempBuff += attr1->attrLen;
                        memcpy(AD2 + tempBuff, attr2, TL_LEN);
                        tempBuff += TL_LEN;
                        memcpy(AD2 + tempBuff, Peer_ProtoPubkey, attr2->attrLen);

                        printf("[CHECK] AD2 : ");
                        for (int i = 0; i < AD2_LEN3 + AD2_LEN4; i++)
                        {
                            printf("%02x", AD2[i]);
                        }
                        printf("\n\n");

                        siv_ctx ctx;
                        siv_init(&ctx, _configurator->Key.k2, SIV_256);

                        uint8_t dec[TL_LEN * 4 + NONCE_SIZE * 2 + CONF_CAP_LEN + (TL_LEN + KEY_SIZE + AES_BLOCK_SIZE)] = {0};

                        int ret = siv_decrypt(
                            &ctx,
                            (_peer->wrapped_data + AES_BLOCK_SIZE),
                            dec,
                            TL_LEN * 4 + NONCE_SIZE * 2 + CONF_CAP_LEN + (TL_LEN + KEY_SIZE + AES_BLOCK_SIZE) + AES_BLOCK_SIZE - AES_BLOCK_SIZE,
                            _peer->wrapped_data,
                            2,
                            AD1,
                            sizeof(AD1),
                            AD2,
                            sizeof(AD2));

                        printf("[CHECK] Raw Data : ");
                        for (int i = 0; i < TL_LEN * 4 + NONCE_SIZE * 2 + CONF_CAP_LEN + (TL_LEN + KEY_SIZE + AES_BLOCK_SIZE); i++)
                        {
                            printf("%02x", dec[i]);
                        }
                        printf("\n\n");
                        if (ret == FAIL)
                        {
                            printf("[INFO] Decryption Failed..\n\n");
                        }
                        memcpy(_peer->Nonce, dec + TL_LEN, NONCE_SIZE);

                        //NONCE CHECK
                        u_int8_t Inonce[NONCE_SIZE];
                        memcpy(Inonce, dec + TL_LEN + NONCE_SIZE + TL_LEN, NONCE_SIZE);

                        if (!is_equal(_configurator->Nonce, Inonce, NONCE_SIZE))
                        {
                            printf("[INFO] Different I_nonce..\n\n");
                            return FAIL;
                        }

                        u_int8_t IR_nonce[NONCE_SIZE * 2];
                        memcpy(IR_nonce, _configurator->Nonce, NONCE_SIZE);
                        memcpy(IR_nonce + NONCE_SIZE, _peer->Nonce, NONCE_SIZE);
                        printf("[CHECK] IR Nonce : ");
                        for (int i = 0; i < NONCE_SIZE * 2; i++)
                        {
                            printf("%02x", IR_nonce[i]);
                        }
                        printf("\n\n");

                        if (!hkdf_extract(EVP_sha256(), IR_nonce, sizeof(IR_nonce), mn_X, sizeof(mn_X), _configurator->Key.bk))
                        {
                            return FAIL;
                        }

                        printf("[KEYGEN] BK : ");
                        for (int i = 0; i < KEY_SIZE; i++)
                        {
                            printf("%02x", _configurator->Key.bk[i]);
                        }
                        printf("\n\n");

                        //KE CREATE
                        char *ke_string = "DPP Key";
                        if (!hkdf_expand(temp, _configurator->Key.bk, sizeof(_configurator->Key.bk), (unsigned char *)ke_string, strlen(ke_string), _configurator->Key.ke, sizeof(_configurator->Key.ke)))
                        {
                            return FAIL;
                        }

                        printf("[KEYGEN] ke : ");
                        for (int i = 0; i < KEY_SIZE; i++)
                        {
                            printf("%02x", _configurator->Key.ke[i]);
                        }
                        printf("\n\n");

                        //R-auth create
                        int total = NONCE_SIZE * 2 + KEY_SIZE * 3 + 1;
                        int R_auth_len = 0;
                        uint8_t R_auth_t[total];
                        uint8_t PI_x[KEY_SIZE] = {0};
                        uint8_t PR_x[KEY_SIZE] = {0};
                        uint8_t BR_x[KEY_SIZE] = {0};

                        memcpy(R_auth_t, IR_nonce, NONCE_SIZE * 2);
                        R_auth_len += NONCE_SIZE * 2;
                        BN_bn2bin(_configurator->ProtocolKey.pubKeyX, PI_x);
                        memcpy(R_auth_t + R_auth_len, PI_x, KEY_SIZE);
                        R_auth_len += KEY_SIZE;
                        BN_bn2bin(_peer->ProtocolKey.pubKeyX, PR_x);
                        memcpy(R_auth_t + R_auth_len, PR_x, KEY_SIZE);
                        R_auth_len += KEY_SIZE;
                        BN_bn2bin(_peer->BootstrapingKey.pubKeyX, BR_x);
                        memcpy(R_auth_t + R_auth_len, BR_x, KEY_SIZE);
                        printf("[CHECK] PI_x : ");
                        for (int i = 0; i < KEY_SIZE; i++)
                        {
                            printf("%02x", PI_x[i]);
                        }
                        printf("\n\n");
                        printf("[CHECK] PR_x : ");
                        for (int i = 0; i < KEY_SIZE; i++)
                        {
                            printf("%02x", PR_x[i]);
                        }
                        printf("\n\n");
                        printf("[CHECK] BR : ");
                        BN_print_fp(stdout, _peer->BootstrapingKey.pubKeyX);
                        printf("\n\n");
                        printf("[CHECK] BR_x : ");
                        for (int i = 0; i < KEY_SIZE; i++)
                        {
                            printf("%02x", BR_x[i]);
                        }
                        printf("\n\n");

                        R_auth_len += KEY_SIZE;
                        R_auth_t[R_auth_len] = 0x00;
                        printf("[CHECK] R_auth_t : ");
                        for (int i = 0; i < total; i++)
                        {
                            printf("%02x", R_auth_t[i]);
                        }
                        printf("\n\n");

                        char R_auth_hash_string[SHA256_DIGEST_LENGTH * 2 + 1];
                        SHA256_hash(R_auth_t, R_auth_hash_string, sizeof(R_auth_t));
                        stringtohex(R_auth_hash_string, _peer->Auth, sizeof(_peer->Auth) / sizeof(*_peer->Auth));

                        printf("[CHECK] Configurator's R-Auth : ");
                        for (int i = 0; i < SHA256_DIGEST_LENGTH * 2 + 1; i++)
                        {
                            printf("%02x", _peer->Auth[i]);
                        }
                        printf("\n\n");

                        uint8_t wrapped_Rauth[TL_LEN + KEY_SIZE + AES_BLOCK_SIZE];
                        memcpy(wrapped_Rauth, dec + (TL_LEN * 4 + NONCE_SIZE * 2 + CONF_CAP_LEN), TL_LEN + KEY_SIZE + AES_BLOCK_SIZE);

                        printf("[CHECK] Peer's Wrapped R-Auth : ");
                        for (int i = 0; i < TL_LEN + KEY_SIZE + AES_BLOCK_SIZE; i++)
                        {
                            printf("%02x", wrapped_Rauth[i]);
                        }
                        printf("\n\n");

                        siv_ctx ctx2;
                        siv_init(&ctx2, _configurator->Key.ke, SIV_256);

                        uint8_t R_auth_tag[TL_LEN + KEY_SIZE] = {0};
                        int ret2 = siv_decrypt(
                            &ctx2,
                            (wrapped_Rauth + AES_BLOCK_SIZE),
                            R_auth_tag,
                            sizeof(wrapped_Rauth) - AES_BLOCK_SIZE,
                            wrapped_Rauth,
                            2,
                            AD1,
                            AD1_LEN,
                            AD2,
                            AD2_LEN3 + AD2_LEN4);

                        printf("[CHECK] Peer's R-Auth : ");
                        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
                        {
                            printf("%02x", R_auth_tag[i]);
                        }
                        printf("\n\n");

                        if (!is_equal(_peer->Auth, R_auth_tag + TL_LEN, KEY_SIZE))
                        {
                            printf("[INFO] Different R_Auth_tag..\n\n");
                            return FAIL;
                        }

                        return SUCCESS;
                    }
                    else
                        return FAIL;
                }
                else
                    return FAIL;
            }
            else
                return FAIL;
        }
        else
            return FAIL;
    }
    else
        return FAIL;
}

static int Generate_Authentication_confirm(ConfiguratorInfo *_configurator, PeerInfo *_peer)
{
    //create Iauth Tag
    uint8_t RI_nonce[NONCE_SIZE * 2];
    memcpy(RI_nonce, _peer->Nonce, NONCE_SIZE);
    memcpy(RI_nonce + NONCE_SIZE, _configurator->Nonce, NONCE_SIZE);

    printf("[CHECK] RI Nonce : ");
    for (int i = 0; i < NONCE_SIZE * 2; i++)
    {
        printf("%02x", RI_nonce[i]);
    }
    printf("\n\n");

    int total = NONCE_SIZE * 2 + KEY_SIZE * 3 + 1;
    int I_auth_l = 0;
    uint8_t I_auth_t[total];
    memcpy(I_auth_t, RI_nonce, NONCE_SIZE * 2);
    I_auth_l += NONCE_SIZE * 2;
    uint8_t PI_x[KEY_SIZE] = {0};
    uint8_t PR_x[KEY_SIZE] = {0};
    uint8_t BR_x[KEY_SIZE] = {0};
    BN_bn2bin(_peer->ProtocolKey.pubKeyX, PR_x);
    memcpy(I_auth_t + I_auth_l, PR_x, KEY_SIZE);
    I_auth_l += KEY_SIZE;
    BN_bn2bin(_configurator->ProtocolKey.pubKeyX, PI_x);
    memcpy(I_auth_t + I_auth_l, PI_x, KEY_SIZE);
    I_auth_l += KEY_SIZE;
    BN_bn2bin(_peer->BootstrapingKey.pubKeyX, BR_x);
    memcpy(I_auth_t + I_auth_l, BR_x, KEY_SIZE);
    I_auth_l += KEY_SIZE;
    I_auth_t[I_auth_l] = 0x01;

    printf("[CHECK] I-Auth T : ");
    for (int i = 0; i < NONCE_SIZE * 2 + KEY_SIZE * 3 + 1; i++)
    {
        printf("%02x", I_auth_t[i]);
    }
    printf("\n\n");

    char I_auth_hash_string[SHA256_DIGEST_LENGTH * 2 + 1];
    SHA256_hash(I_auth_t, I_auth_hash_string, sizeof(I_auth_t));
    stringtohex(I_auth_hash_string, _configurator->Auth, sizeof(_configurator->Auth) / sizeof(*_configurator->Auth));

    printf("[CHECK] I-Auth Tag : ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        printf("%02x", _configurator->Auth[i]);
    }
    printf("\n\n");

    u_int8_t packet[PACKET_MAX_LENGTH] = {0};

    int init_dataPointer = Init_Packet(_configurator->MACAddr, _peer->MACAddr, DPP_AUTHENTICATION_CONFIRM, packet);

    u_int8_t AD1[AD1_LEN] = {0};
    unsigned char tempOUI[3] = {0x50, 0x6f, 0x9a};
    memcpy(AD1, tempOUI, 3);
    int tempBuff = 3;
    unsigned char tempAD1[] = {0x1a, 0x01, 0x02};
    memcpy(AD1 + tempBuff, tempAD1, 3);

    printf("[CHECK] AD1 : ");
    for (int i = 0; i < AD1_LEN; i++)
    {
        printf("%02x", AD1[i]);
    }
    printf("\n\n");

    u_int8_t AD2[AD2_LEN3] = {0};
    uint8_t tempStatus[] = {0x00, 0X00};
    int dataPointer = Generate_Attribute(ATTR_STATUS, SIZE_STATUS, tempStatus, packet, init_dataPointer);
    tempBuff = 0;

    memcpy(AD2, packet + (dataPointer - 5), 5);
    tempBuff += TL_LEN + 1;

    dataPointer = Generate_Attribute(ATTR_RESPONDER_BOOTS_KEY_HASH, SHA256_DIGEST_LENGTH, _peer->BootstrapingKey.SHA256_HASH, packet, dataPointer);
    memcpy(AD2 + tempBuff, packet + (dataPointer - TL_LEN - SHA256_DIGEST_LENGTH), TL_LEN + SHA256_DIGEST_LENGTH);

    printf("[CHECK] AD2 : ");
    for (int i = 0; i < AD2_LEN3; i++)
    {
        printf("%02x", AD2[i]);
    }
    printf("\n\n");

    u_int8_t Iauth_tag[TL_LEN + KEY_SIZE] = {0X0a, 0x10, 0x20, 0x00};
    u_int8_t tag_enc[sizeof(Iauth_tag) + AES_BLOCK_SIZE] = {0};
    memcpy(Iauth_tag + TL_LEN, _configurator->Auth, KEY_SIZE);

    printf("[CHECK] I-auth : ");
    for (int i = 0; i < TL_LEN + KEY_SIZE; i++)
    {
        printf("%02x", Iauth_tag[i]);
    }
    printf("\n\n");

    siv_ctx ctx;
    siv_init(&ctx, _configurator->Key.ke, SIV_256);

    siv_encrypt(
        &ctx,
        Iauth_tag,
        tag_enc + AES_BLOCK_SIZE,
        sizeof(Iauth_tag),
        tag_enc,
        2,
        AD1,
        AD1_LEN,
        AD2,
        AD2_LEN3);

    printf("[CHECK] Encrypted I-auth : ");
    for (int i = 0; i < sizeof(Iauth_tag) + AES_BLOCK_SIZE; i++)
    {
        printf("%02x", tag_enc[i]);
    }
    printf("\n\n");

    dataPointer = Generate_Attribute(ATTR_WRAPPED_DATA, sizeof(tag_enc), tag_enc, packet, dataPointer);
    memset(_configurator->tempPacket, 0, sizeof(_configurator->tempPacket));
    memcpy(_configurator->tempPacket, &packet, dataPointer);

    return dataPointer;
}

static int Authentication(ConfiguratorInfo *_configurator, PeerInfo *_peer, pcap_t *_adhandle)
{
    if (Init_Key(_configurator, _peer) == SUCCESS)
    {
        printf("[INFO] Initiate Key !!\n\n");
    }

    int dataPointer = 0;

    printf("\n\n");

    int result = 0;

    printf("[INFO] Generate Authentication Request Packet!!\n\n");
    while (1)
    {

        dataPointer = Generate_Authentication_Req(_configurator, _peer);
        if (pcap_sendpacket(_adhandle, _configurator->tempPacket, dataPointer))
        {
            printf("send error\n");
            break;
        }

        int startTime = clock();

        while (1)
        {
            int currentTime = clock();
            if (Check_Authentication_Resp(_adhandle, _configurator, _peer) == SUCCESS)
            {
                printf("Finish to check all of Authentication Response Packet !!\n\n");
                result = SUCCESS;
                break;
            }
            if (currentTime >= startTime + 1000)
                break;
        }
        if (result == SUCCESS)
        {
            break;
            // return SUCCESS;
        }
    }

    dataPointer = Generate_Authentication_confirm(_configurator, _peer);
    printf("[INFO] Generate Authentication Confirm Packet!!\n\n");
    printf("[INFO] Complete sending Authentication Confirm Packet!!\n\n");

    result = 0;

    while (1)
    {
        if (pcap_sendpacket(_adhandle, _configurator->tempPacket, dataPointer))
        {
            printf("send error\n");
            break;
        }

        int startTime = clock();
        while (1)
        {
            int currentTime = clock();
            if (Check_Configuration_Req(_configurator, _peer, _adhandle) == SUCCESS)
            {
                result = SUCCESS;
                break;
                // return SUCCESS;
            }
            if (currentTime >= startTime + 1000)
                break;
        }
        if (result == SUCCESS)
        {
            break;
            // return SUCCESS;
        }
    }
    return SUCCESS;

    //TODO: Error
}

static void Unwrapped_Data(unsigned char *in, int wrapSize, unsigned char *out, unsigned char *ke)
{
    //DECRYPT
    siv_ctx ctx;
    siv_init(&ctx, ke, SIV_256);

    siv_decrypt(
        &ctx,
        (in + AES_BLOCK_SIZE),
        out,
        wrapSize - AES_BLOCK_SIZE,
        in, 0);

    printf("  ");
}

static void Process_Req_Json_Data(char *in, PeerInfo *_peer)
{
    json_object *json = json_tokener_parse(in);
    json_object *tech_obj = json_object_object_get(json, "wi-fi_tech");
    json_object *role_obj = json_object_object_get(json, "netRole");

    const char *_tech = json_object_get_string(tech_obj);
    const char *_role = json_object_get_string(role_obj);

    char tech[strlen(_tech) + 1];
    memset(tech, 0, strlen(_tech));
    memcpy(tech, _tech, strlen(_tech));

    tech[strlen(_tech)] = '\0';

    char role[strlen(_role) + 1];
    memset(role, 0, strlen(_role));
    memcpy(role, _role, strlen(_role));
    role[strlen(_role)] = '\0';

    memcpy(_peer->reqObj.netRole, role, strlen(role)); 
    memcpy(_peer->reqObj.wifiTech, tech, strlen(tech));

    // _peer->reqObj.netRole = role;
    // _peer->reqObj.wifiTech = tech;
    printf("[CHECK] Get Wi-Fi tech : %s\n\n", _peer->reqObj.wifiTech);
    printf("[CHECK] Get netRole : %s\n\n", _peer->reqObj.netRole);
}

static int Check_Configuration_Req(ConfiguratorInfo *_configurator, PeerInfo *_peer, pcap_t *_adhandle)
{
    struct pcap_pkthdr *header;
    const unsigned char *_packet;

    int result = pcap_next_ex(_adhandle, &header, &_packet);

    unsigned char *packet = (unsigned char *)_packet;
    int dataPointer = 0;

    struct ieee80211_radiotap_header *tRadio = (struct ieee80211_radiotap_header *)packet;
    // dataPointer += ntohs(tRadio->it_len);
    dataPointer += tRadio->it_len;
    struct ieee80211_frame *fh = (struct ieee80211_frame *)(packet + dataPointer);
    dataPointer += sizeof(*fh);

    u_int8_t type = fh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    u_int8_t subtype = fh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    // unsigned char PeerMAC[IEEE80211_ADDR_LEN] = {0X88, 0x36, 0x6c, 0xf8, 0xa5, 0x0c};
    if (is_equal(_configurator->MACAddr, fh->i_addr1, IEEE80211_ADDR_LEN) && is_equal(_peer->MACAddr, fh->i_addr2, IEEE80211_ADDR_LEN))
    {
        if (type == IEEE80211_FC0_TYPE_MGT && subtype == IEEE80211_FC0_SUBTYPE_ACK)
        {
            struct gas_config_frame *reqGas = (struct gas_config_frame *)(packet + dataPointer);
            dataPointer += sizeof(*reqGas);

            if (reqGas->category == 0x04 && reqGas->public_Action == 0x0a && reqGas->API[5] == 0x1a && reqGas->API[6] == 0x01)
            {
                Attribute *attr1 = (Attribute *)(packet + dataPointer);
                dataPointer += sizeof(*attr1);

                if (attr1->attrID == ATTR_WRAPPED_DATA)
                {
                    int wrapSize = attr1->attrLen;
                    // unsigned char *wrappedText = (unsigned char *)malloc(wrapSize);
                    unsigned char wrappedText[wrapSize];

                    memcpy(wrappedText, (packet + dataPointer), wrapSize);

                    printf("[CHECK] Config-Req Wrapped Data : ");
                    for (int i = 0; i < wrapSize; i++)
                        printf("%02X ", wrappedText[i]);
                    printf("\n\n");

                    //DECRYPT
                    // unsigned char *unwrappedText = (unsigned char *)malloc(wrapSize - AES_BLOCK_SIZE);
                    unsigned char unwrappedText[wrapSize - AES_BLOCK_SIZE];
                    Unwrapped_Data(wrappedText, wrapSize, unwrappedText, _configurator->Key.ke);

                    // < by. shin >
                    // free(wrappedText);

                    printf("[CHECK] Config-Req Unwrapped Data : ");
                    for (int i = 0; i < wrapSize - AES_BLOCK_SIZE; i++)
                        printf("%02X ", unwrappedText[i]);
                    printf("\n\n");

                    Attribute *attr2 = (Attribute *)(unwrappedText);
                    int new_dataPointer = sizeof(Attribute);

                    if (attr2->attrID == ATTR_ENONCE)
                    {
                        memcpy(_peer->Enonce, unwrappedText + new_dataPointer, NONCE_SIZE);
                        new_dataPointer += attr2->attrLen;

                        printf("[CHECK] Get Enonce : ");
                        for (int i = 0; i < NONCE_SIZE; i++)
                        {
                            printf("%02x", _peer->Enonce[i]);
                        }
                        printf("\n\n");

                        Attribute *attr3 = (Attribute *)(unwrappedText + new_dataPointer);
                        new_dataPointer += sizeof(Attribute);
                        if (attr3->attrID == ATTR_CONFIG_REQUEST_OBJECT)
                        {
                            // char *tempData = (char *)malloc(attr3->attrLen + 1);
                            char tempData[attr3->attrLen + 1];
                            memcpy(tempData, unwrappedText + new_dataPointer, attr3->attrLen);
                            tempData[attr3->attrLen] = '\0';

                            printf("[CHECK] Get Req Json : %s\n\n", tempData);
                            Process_Req_Json_Data(tempData, _peer);
                            
                            
                            printf("%s \n\n", _peer->reqObj.netRole);


                            printf("[CHECK] Finish to check all of Configurator Req!\n\n");

                            //<by. shin>
                            // free(unwrappedText);
                            // free(tempData);
                            return SUCCESS;
                        }
                        else
                            return FAIL;
                    }
                    else
                        return FAIL;
                }
                else
                    return FAIL;
            }
            else
                return FAIL;
        }
        else
            return FAIL;
    }
    else
        return FAIL;
}

static int Preprocess_Protocol_Key(PeerInfo *_peer, ConfiguratorInfo *_configurator)
{
    //unsigned char *proto_binx = (unsigned char *)(BN_num_bytes(_peer->ProtocolKey.pubKeyX));
    unsigned char proto_binx[KEY_SIZE];
    BN_bn2bin(_peer->ProtocolKey.pubKeyX, proto_binx);

    unsigned char proto_b64x[256] = {0};
    // int b64 = base64urlencode(proto_b64x, proto_binx, BN_num_bytes(_peer->ProtocolKey.pubKeyX));
    int b64 = base64urlencode(proto_b64x, proto_binx, KEY_SIZE);
    proto_b64x[b64] = '\0';
    printf("[CHECK] Converted Proto(Access) PubKey b64x : %s\n\n", proto_b64x);
    memcpy(_peer->ProtocolKey.pubKeyX_b64, proto_b64x, b64);
    printf("[CHECK] Copied Proto(Access) PubKey b64x : %s\n\n", _peer->ProtocolKey.pubKeyX_b64);

    unsigned char proto_biny[KEY_SIZE];
    BN_bn2bin(_peer->ProtocolKey.pubKeyY, proto_biny);

    unsigned char proto_b64y[256] = {0};
    b64 = base64urlencode(proto_b64y, proto_biny, KEY_SIZE);
    proto_b64y[b64] = '\0';
    printf("[CHECK] Converted Proto(Access) PubKey b64y : %s\n\n", proto_b64y);
    memcpy(_peer->ProtocolKey.pubKeyY_b64, proto_b64y, b64);
    printf("[CHECK] Copied Proto(Access) PubKey b64y : %s\n\n", _peer->ProtocolKey.pubKeyY_b64);

    unsigned char sig_binx[KEY_SIZE];
    BN_bn2bin(_configurator->ECDSAKey.pubKeyX, sig_binx);

    unsigned char sig_b64x[256] = {0};
    b64 = base64urlencode(sig_b64x, sig_binx, KEY_SIZE);
    sig_b64x[b64] = '\0';
    printf("[CHECK] Converted ECDSA PubKey b64x : %s\n\n", sig_b64x);
    memcpy(_configurator->ECDSAKey.pubKeyX_b64, sig_b64x, b64);
    printf("[CHECK] Copied ECDSA PubKey b64x : %s\n\n", _configurator->ECDSAKey.pubKeyX_b64);

    unsigned char sig_biny[KEY_SIZE];
    BN_bn2bin(_configurator->ECDSAKey.pubKeyY, sig_biny);
    unsigned char sig_b64y[256] = {0};
    b64 = base64urlencode(sig_b64y, sig_biny, KEY_SIZE);
    sig_b64y[b64] = '\0';
    printf("[CHECK] Converted ECDSA PubKey b64y : %s\n\n", sig_b64y);
    memcpy(_configurator->ECDSAKey.pubKeyY_b64, sig_b64y, b64);
    printf("[CHECK] Copied ECDSA PubKey b64y : %s\n\n", _configurator->ECDSAKey.pubKeyY_b64);

    EC_KEY *pp = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(pp);
    _configurator->PPKey.Key = pp;

    EC_POINT *pp_pub = (EC_POINT *)EC_KEY_get0_public_key(pp);
    BIGNUM *pp_x = BN_new(), *pp_y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(pp), pp_pub, pp_x, pp_y, NULL);
    printf("[CHECK] PP PubKey X : ");
    _configurator->PPKey.pubKeyX = pp_x;
    BN_print_fp(stdout, _configurator->PPKey.pubKeyX);
    printf("\n\n[CHECK]PP PubKey Y : ");
    _configurator->PPKey.pubKeyY = pp_y;
    BN_print_fp(stdout, _configurator->PPKey.pubKeyY);

    //unsigned char *pp_binx = (unsigned char *)malloc(BN_num_bytes(pp_x));
    unsigned char pp_binx[KEY_SIZE];
    BN_bn2bin(pp_x, pp_binx);

    unsigned char pp_b64x[256] = {0};
    b64 = base64urlencode(pp_b64x, pp_binx, KEY_SIZE);
    pp_b64x[b64] = '\0';
    printf("[CHECK] PPKey b64x : %s\n\n", pp_b64x);
    memcpy(_configurator->PPKey.pubKeyX_b64, pp_b64x, b64);
    printf("[CHECK] Copied PPKey b64x : %s\n\n", _configurator->PPKey.pubKeyX_b64);

    unsigned char pp_biny[KEY_SIZE];
    BN_bn2bin(pp_y, pp_biny);

    unsigned char pp_b64y[256] = {0};
    b64 = base64urlencode(pp_b64y, pp_biny, KEY_SIZE);
    pp_b64y[b64] = '\0';
    printf("[CHECK] PPKey b64y : %s\n\n", pp_b64y);
    memcpy(_configurator->PPKey.pubKeyY_b64, pp_b64y, b64);
    printf("[CHECK] Copied PPKey b64x : %s\n\n", _configurator->PPKey.pubKeyY_b64);
}

static const char *generate_header(const char *_kid)
{
    json_object *header = json_object_new_object();

    json_object_object_add(header, "typ", json_object_new_string("dppCon"));
    json_object_object_add(header, "kid", json_object_new_string(_kid));
    json_object_object_add(header, "alg", json_object_new_string("ES256"));

    return json_object_to_json_string(header);
}

static const char *Generate_connector(const char *_dev, const char *_tech, const char *_x, const char *_y, const char *_expiry)
{
    json_object *connector = json_object_new_object(),
                *group = json_object_new_object(),
                *groups = json_object_new_array(),
                *netAccessKey = json_object_new_object(),
                *expiry = json_object_new_object();

    json_object_object_add(group, "groupId", json_object_new_string(_tech));
    json_object_object_add(group, "netRole", json_object_new_string(_dev));
    json_object_array_add(groups, group);

    json_object_object_add(netAccessKey, "kty", json_object_new_string("EC"));
    json_object_object_add(netAccessKey, "crv", json_object_new_string("P-256"));
    json_object_object_add(netAccessKey, "x", json_object_new_string(_x));
    json_object_object_add(netAccessKey, "y", json_object_new_string(_y));

    json_object_object_add(connector, "groups", groups);
    json_object_object_add(connector, "netAccessKey", netAccessKey);
    json_object_object_add(connector, "expiry", json_object_new_string(_expiry));

    return json_object_to_json_string(connector);
}

static int Generate_ConfResObj_Attr(ConfiguratorInfo *_configurator, PeerInfo *_peer)
{
    Preprocess_Protocol_Key(_peer, _configurator);

    unsigned char jws[1024] = {0};
    const char *header = generate_header(_configurator->ECDSAKey.kid);
    printf("[CHECK] Generate Header : %s\n\n", header);

    const char *connector = Generate_connector(_peer->reqObj.netRole, _peer->reqObj.wifiTech, _peer->ProtocolKey.pubKeyX_b64, _peer->ProtocolKey.pubKeyY_b64, "2019-01-31T22:00:00+02:00");
    printf("[CHECK] Generate Connector : %s\n\n", connector);

    int jwsPointer = base64urlencode(jws, (unsigned char *)header, strlen(header));
    jws[jwsPointer++] = '.';

    int tPointer = base64urlencode(jws + jwsPointer, (unsigned char *)connector, strlen(connector));
    jwsPointer += tPointer;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit(mdctx, EVP_sha256());
    EVP_DigestUpdate(mdctx, jws, jwsPointer);
    jws[jwsPointer++] = '.';

    printf("[CHECK] jws : ");
    for (int i = 0; i < jwsPointer; i++)
    {
        printf("%02x", jws[i]);
    }
    printf("\n\n");

    unsigned char digest[SHA512_DIGEST_LENGTH];
    unsigned int mdlen = SHA256_DIGEST_LENGTH;
    EVP_DigestFinal(mdctx, digest, &mdlen);

    if (EC_KEY_check_key(_configurator->ECDSAKey.Key) == FAIL)
    {
        printf("fuck\n\n");
    }
    ECDSA_SIG *ecsig = ECDSA_do_sign_ex(digest, mdlen, NULL, NULL, _configurator->ECDSAKey.Key);
    printf("[Sig Digest] : ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02X ", digest[i]);
    printf("\n\n");
    const BIGNUM *r = BN_new(), *s = BN_new();
    ECDSA_SIG_get0(ecsig, &r, &s);
    printf("[Sig r] : ");
    BN_print_fp(stdout, r);
    printf("\n\n");

    printf("[Sig s] : ");
    BN_print_fp(stdout, s);
    printf("\n\n");

    //TODO: unsigned char sig[140] = {0};
    unsigned char sig[140] = {0};
    BN_bn2bin(r, sig);
    BN_bn2bin(s, sig + BN_num_bytes(s));

    printf("[CHECK] ECDSA Signed Connector : ");
    for (int i = 0; i < BN_num_bytes(s) * 2; i++)
        printf("%02X ", sig[i]);
    printf("\n\n");

    //TODO: memcpy(_configurator->Sign, sig, strlen(sig));
    memcpy(_configurator->Sign, sig, BN_num_bytes(s) * 2);

    base64urlencode(jws + jwsPointer, sig, BN_num_bytes(s) * 2);
    printf("[CHECK] Full Connector : %s\n\n", jws);
    //TODO: Changed a lot
    int t = jwsPointer+BN_num_bytes(s) * 2;
    char tempJWS[t];
    memcpy(tempJWS, jws, jwsPointer+BN_num_bytes(s) * 2);
    //TODO: memcpy(_configurator->JWS, jws, strlen(jws));
    memcpy(_configurator->JWS, tempJWS, jwsPointer+BN_num_bytes(s) * 2);
}

const char *Generate_ConfigResObj(const char *_netrole,
                                  const char *_tech,
                                  const char *_ssid,
                                  const char *_password,
                                  const char *_sig,
                                  const char *_x, const char *_y, const char *_kid,
                                  const char *_ppx, const char *_ppy)
{
    json_object *configurationObject, *discovery, *cred, *csign, *pp;
    configurationObject = json_object_new_object();
    discovery = json_object_new_object();
    cred = json_object_new_object();
    csign = json_object_new_object();
    pp = json_object_new_object();

    //discovery(ssid)
    json_object_object_add(discovery, "ssid", json_object_new_string(_ssid));

    //cred(akm, signedConnector, csign(JWK))
    if (strstr(_netrole, "ap"))
    {
        json_object_object_add(cred, "akm", json_object_new_string("dpp+psk+sae"));
        json_object_object_add(cred, "pass", json_object_new_string(_password));
    }
    else if (strstr(_netrole, "sta"))
    {
        json_object_object_add(cred, "akm", json_object_new_string("dpp"));
    }

    json_object_object_add(cred, "signedConnector", json_object_new_string(_sig));
    //csign
    json_object_object_add(csign, "kty", json_object_new_string("EC"));
    json_object_object_add(csign, "crv", json_object_new_string("P-256"));
    json_object_object_add(csign, "x", json_object_new_string(_x));
    json_object_object_add(csign, "y", json_object_new_string(_y));
    json_object_object_add(csign, "kid", json_object_new_string(_kid));
    json_object_object_add(cred, "csign", csign);

    json_object_object_add(pp, "kty", json_object_new_string("EC"));
    json_object_object_add(pp, "crv", json_object_new_string("P-256"));
    json_object_object_add(pp, "x", json_object_new_string(_ppx));
    json_object_object_add(pp, "y", json_object_new_string(_ppy));
    json_object_object_add(cred, "ppKey", pp);

    //configurationObject
    json_object_object_add(configurationObject, "wi-fi_tech", json_object_new_string(_tech));
    json_object_object_add(configurationObject, "discovery", discovery);
    json_object_object_add(configurationObject, "cred", cred);

    return json_object_to_json_string(configurationObject);
}

void print_BN(BIGNUM *_t, const char *_s)
{
    printf("[%s] : ", _s);
    BN_print_fp(stdout, _t);
    printf("\n\n");
}


void Set_ECDSA_Key(ConfiguratorInfo *_configurator)
{   

    _configurator->KeyAttr.ecGroup = EC_GROUP_new_by_curve_name(CURVE);
    _configurator->ECDSAKey.Key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    _configurator->ECDSAKey.pubKeyX = BN_new();
    _configurator->ECDSAKey.pubKeyY = BN_new();
    _configurator->ECDSAKey.privKey = BN_new();
    _configurator->ECDSAKey.pubKey = EC_POINT_new(_configurator->KeyAttr.ecGroup);


    const char *pubKeyX = "FC05E4140FFD3ACA438F838937C286A3531C151684BD5A5C8B4E1AC61E189C6C";
    const char *pubKeyY = "CA7C5FB3538E6A58E060B9EC23EF6CF9D9DD3F60982992E3EA24797165398762";
    const char *privKey = "E329F70A027FEBEAD5471435B36D9D52DEC6258C69D487E89CD2D03D58C9527B";

    BN_hex2bn(&_configurator->ECDSAKey.pubKeyX, pubKeyX);
    BN_hex2bn(&_configurator->ECDSAKey.pubKeyY, pubKeyY);
    BN_hex2bn(&_configurator->ECDSAKey.privKey, privKey);

    print_BN(_configurator->ECDSAKey.pubKeyX, "Pubkey X");
    print_BN(_configurator->ECDSAKey.pubKeyY, "Pubkey Y");
    print_BN(_configurator->ECDSAKey.privKey, "PrivKey");

    EC_POINT_set_affine_coordinates_GFp(_configurator->KeyAttr.ecGroup, _configurator->ECDSAKey.pubKey, _configurator->ECDSAKey.pubKeyX, _configurator->ECDSAKey.pubKeyY, NULL);
    EC_KEY_set_public_key(_configurator->ECDSAKey.Key, _configurator->ECDSAKey.pubKey);
    EC_KEY_set_private_key(_configurator->ECDSAKey.Key, _configurator->ECDSAKey.privKey);

    if (!EC_KEY_check_key(_configurator->ECDSAKey.Key))
    {
        printf("key error\n");
    }
}

static int Generate_Configuration_Resp(ConfiguratorInfo *_configurator, PeerInfo *_peer)
{
    u_int8_t packet[PACKET_MAX_LENGTH] = {0};
    siv_ctx ctx;
    siv_init(&ctx, _configurator->Key.ke, SIV_256);
    // if (is_equal(_peer->reqObj.netRole, "ap", strlen("ap")))
    // {
    //     if (Generate_ECDSA_Key(&_configurator->ECDSAKey) == FAIL)
    //         return FAIL;

    //     printf("[SUCCESS] Generate_ECDSA_Key\n\n");
    // }
    // else{
    //     printf("We dont't need to generate ECDSA Key !\n\n");
    // }

    Set_ECDSA_Key(_configurator);
    Generate_ConfResObj_Attr(_configurator, _peer);

    const char *res = Generate_ConfigResObj(_peer->reqObj.netRole, _peer->reqObj.wifiTech, "infolab420", "infolab420", _configurator->JWS, _configurator->ECDSAKey.pubKeyX_b64, _configurator->ECDSAKey.pubKeyY_b64, _configurator->ECDSAKey.kid, _configurator->PPKey.pubKeyX_b64, _configurator->PPKey.pubKeyY_b64);
    memcpy(_configurator->SSID, "infolab420", strlen("infolab420"));
    memcpy(_configurator->PASS, "infolab420", strlen("infolab420"));

    int resSize = strlen(res);
    printf("[CHECK] Confifugration Response Object Json] : %s\n\n", res);
    memcpy(_configurator->ConfResObj, res, strlen(res));

    int pPointer = 0;
    // unsigned char *pText = (unsigned char *)malloc((TL_LEN * 2) + NONCE_SIZE + resSize);
    unsigned char pText[(TL_LEN * 2) + NONCE_SIZE + resSize];
    Attribute attr = {0};
    attr.attrID = ATTR_ENONCE;
    attr.attrLen = NONCE_SIZE;
    memcpy(pText, &attr, sizeof(Attribute));
    pPointer += sizeof(Attribute);

    memcpy(pText + pPointer, _peer->Enonce, NONCE_SIZE);
    pPointer += NONCE_SIZE;

    attr.attrID = ATTR_CONFIG_OBJECT;
    attr.attrLen = resSize;
    memcpy(pText + pPointer, &attr, sizeof(Attribute));
    pPointer += sizeof(Attribute);

    memcpy(pText + pPointer, res, resSize);
    pPointer += resSize;

    // int pPointer = 0;
    // int TdataPointer = Generate_Attribute(ATTR_ENONCE, NONCE_SIZE, _peer->Enonce, pText, pPointer);
    // pPointer += TdataPointer;

    // TdataPointer = Generate_Attribute(ATTR_CONFIG_OBJECT, resSize, res, pText, pPointer);
    // pPointer += TdataPointer;

    printf("[CHECK] Plain-Text : ");
    for (int i = 0; i < pPointer; i++)
        printf("%02X", pText[i]);
    printf("\n\n");

    //unsigned char *eText = (unsigned char *)malloc((4 * 2) + NONCE_SIZE + resSize + AES_BLOCK_SIZE);
    unsigned char eText[(4 * 2) + NONCE_SIZE + resSize + AES_BLOCK_SIZE];
    siv_encrypt(
        &ctx,
        pText,
        eText + AES_BLOCK_SIZE,
        4 + NONCE_SIZE + 4 + resSize,
        eText, 0);

    // free(pText);

    pPointer += AES_BLOCK_SIZE;
    printf("[CHECK] Enc-Text : ");
    for (int i = 0; i < pPointer; i++)
        printf("%02X", eText[i]);
    printf("\n\n");

    unsigned char TempPText[] = {0};
    Unwrapped_Data(eText, pPointer, TempPText, _configurator->Key.ke);
    printf("[CHECK] DECYt : ");
    for (int i = 0; i < (pPointer - AES_BLOCK_SIZE); i++)
        printf("%02X", TempPText[i]);
    printf("\n\n");

    // int init_dataPointer = Init_Packet(_configurator->MACAddr, _peer->MACAddr, DPP_CONFIGURATION_RESPONSE, packet);
    //radiotap header
    unsigned char radiotap[] = {0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(packet, radiotap, sizeof(radiotap));
    int dataPointer = 0;
    dataPointer += sizeof(radiotap);

    //ieee80211 action frame
    struct ieee80211_frame fh;
    fh.i_fc[0] = IEEE80211_FC0_SUBTYPE_ACK | IEEE80211_FC0_TYPE_MGT;
    fh.i_fc[1] = 0x00;
    fh.i_dur[0] = 0x00;
    fh.i_dur[1] = 0x00;
    memcpy(fh.i_addr1, _peer->MACAddr, IEEE80211_ADDR_LEN);
    memcpy(fh.i_addr2, _configurator->MACAddr, IEEE80211_ADDR_LEN);
    memcpy(fh.i_addr3, _peer->MACAddr, IEEE80211_ADDR_LEN);

    memcpy(packet + dataPointer, &fh, sizeof(fh));
    dataPointer += sizeof(fh);

    struct gas_config_res_frame gas = {0};
    gas.category = 0x04;
    gas.public_Action = 0x0b;
    gas.dToken = 0x01;
    gas.statusCode = 0x00;
    gas.delay = htons(0x1000);
    gas.query_reslen = pPointer + 4;

    uint8_t dpp_gas_element[3] = {0x6c, 0x08, 0x00};
    uint8_t dpp_gas_proto_id[7] = {0xdd, 0x05, 0x50, 0x6f, 0x9a, 0x1a, 0x01};
    memcpy(gas.APE, dpp_gas_element, 3);
    memcpy(gas.API, dpp_gas_proto_id, 7);

    memcpy(packet + dataPointer, &gas, sizeof(struct gas_config_res_frame));
    dataPointer += sizeof(struct gas_config_res_frame);

    dataPointer = Generate_Attribute(ATTR_WRAPPED_DATA, pPointer, eText, packet, dataPointer);

    memset(_configurator->tempPacket, 0, sizeof(_configurator->tempPacket));
    memcpy(_configurator->tempPacket, packet, dataPointer);

    return dataPointer;
}

static int Check_Configuration_Result(ConfiguratorInfo *_configurator, PeerInfo *_peer, pcap_t *_adhandle)
{
    struct pcap_pkthdr *header;
    const unsigned char *_packet;

    int result = pcap_next_ex(_adhandle, &header, &_packet);
    unsigned char *packet = (unsigned char *)_packet;

    int dataPointer = 0;

    struct ieee80211_radiotap_header *tRadio = (struct ieee80211_radiotap_header *)packet;
    // dataPointer += ntohs(tRadio->it_len);
    dataPointer += tRadio->it_len;
    struct ieee80211_frame *fh = (struct ieee80211_frame *)(packet + dataPointer);
    dataPointer += sizeof(*fh);

    u_int8_t type = fh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    u_int8_t subtype = fh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    if (is_equal(_configurator->MACAddr, fh->i_addr1, IEEE80211_ADDR_LEN) && is_equal(_peer->MACAddr, fh->i_addr2, IEEE80211_ADDR_LEN))
    {
        if (type == IEEE80211_FC0_TYPE_MGT && subtype == IEEE80211_FC0_SUBTYPE_ACK)
        {
            FixedParam *fp = (FixedParam *)(packet + dataPointer);
            dataPointer += sizeof(*fp);

            if (fp->categoryCode == 0x04 && fp->publicAction == 0x09 && fp->WFASubtype == 26 && fp->DPPSubtype == 0x0b)
            {
                Attribute *attr1 = (Attribute *)(packet + dataPointer);
                dataPointer += sizeof(*attr1);

                if (attr1->attrID == ATTR_WRAPPED_DATA)
                {
                    int wrapSize = attr1->attrLen;
                    // unsigned char *wrappedText = (unsigned char *)malloc(wrapSize);
                    unsigned char wrappedText[wrapSize];

                    memcpy(wrappedText, (packet + dataPointer), wrapSize);

                    printf("[CHECK] Config-Result Wrapped Data : ");
                    for (int i = 0; i < wrapSize; i++)
                        printf("%02X ", wrappedText[i]);
                    printf("\n\n");

                    //DECRYPT
                    // unsigned char *unwrappedText = (unsigned char *)malloc(wrapSize - AES_BLOCK_SIZE);
                    unsigned char unwrappedText[wrapSize - AES_BLOCK_SIZE];
                    Unwrapped_Data(wrappedText, wrapSize, unwrappedText, _configurator->Key.ke);
                    printf("[CHECK] Config-Result Unwrapped Data : ");
                    for (int i = 0; i < wrapSize - AES_BLOCK_SIZE; i++)
                        printf("%02X ", unwrappedText[i]);
                    printf("\n\n");

                    Attribute *attr2 = (Attribute *)(unwrappedText + 6);
                    int new_dataPointer = sizeof(Attribute) + 6;

                    if (attr2->attrID == ATTR_ENONCE)
                    {
                        unsigned char tempNonce[NONCE_SIZE] = {0};
                        memcpy(tempNonce, unwrappedText + new_dataPointer, NONCE_SIZE);
                        new_dataPointer += attr2->attrLen;

                        printf("[CHECK] Get Enonce : ");
                        for (int i = 0; i < NONCE_SIZE; i++)
                        {
                            printf("%02x", tempNonce[i]);
                        }
                        printf("\n\n");

                        if (is_equal(tempNonce, _peer->Enonce, NONCE_SIZE))
                        {
                            printf("[INFO] Same ENONCE!\n\n");
                            printf("[INFO] Configuration Done!\n\n");
                            return SUCCESS;
                        }
                        else
                        {
                            printf("[INFO] Different Enonce..\n\n");
                            return FAIL;
                        }
                    }
                    else
                        return FAIL;
                }
                else
                    return FAIL;
            }
            else
                return FAIL;
        }
        else
            return FAIL;
    }
    else
        return FAIL;
}

static int Configuration(ConfiguratorInfo *_configurator, PeerInfo *_peer, pcap_t *_adhandle)
{
    // Receive Configuration Request
    // int result = 0;
    // while (1)
    // {
    //     int startTime = clock();
    //     while (1)
    //     {
    //         int currentTime = clock();
    //         if (Check_Configuration_Req(_configurator, _peer, _adhandle))
    //         {
    //             result = SUCCESS;
    //             break;
    //         }
    //         if (currentTime >= startTime + 5)
    //             break;
    //     }
    //     if (result == SUCCESS)
    //         break;
    // }
    // Send Configuration Response
    int result = 0;
    int dataPointer = Generate_Configuration_Resp(_configurator, _peer);
    printf("[CHECK] Complete Configuration Resp!\n\n");
    printf("[CHECK] Send Configuration Resp..\n\n");
    while (1)
    {
        if (pcap_sendpacket(_adhandle, _configurator->tempPacket, dataPointer))
        {
            printf("send error\n");
            break;
        }

        // Receive Configuration Result
        int startTime = clock();
        while (1)
        {
            int currentTime = clock();
            if (Check_Configuration_Result(_configurator, _peer, _adhandle) == SUCCESS)
            {
                result = SUCCESS;
                break;
            }
            if (currentTime >= startTime + 5)
                break;
        }
        if (result == SUCCESS)
        {
            break;
            return SUCCESS;
        }
    }
}

static int Generate_WPA2_Authentication_Req(ConfiguratorInfo *_configurator, PeerInfo *_peer)
{
    uint8_t packet[PACKET_MAX_LENGTH] = {0};
    int dataPointer = 0;

    //radiotap header
    RadiotapHeader rh;

    rh.Header_revision = 0x0000;
    rh.Header_Len = 18;
    rh.flags = 0x00;
    rh.Present_Flags[0] = 0x2e;
    rh.Present_Flags[1] = 0x48;
    rh.Present_Flags[2] = 0x00;
    rh.Present_Flags[3] = 0x00;

    memcpy(packet, &rh, rh.Header_Len);
    dataPointer += rh.Header_Len;

    //ieee80211 action frame
    struct ieee80211_frame fh;
    fh.i_fc[0] = IEEE80211_FC0_SUBTYPE_AUTH | IEEE80211_FC0_TYPE_MGT;
    fh.i_fc[1] = 0x00;
    fh.i_dur[0] = 0x00;
    fh.i_dur[1] = 0x00;
    memcpy(fh.i_addr1, _peer->MACAddr, IEEE80211_ADDR_LEN);
    memcpy(fh.i_addr2, _configurator->MACAddr, IEEE80211_ADDR_LEN);
    memcpy(fh.i_addr3, _peer->MACAddr, IEEE80211_ADDR_LEN);

    memcpy(packet + dataPointer, &fh, sizeof(fh));
    dataPointer += sizeof(fh);

    AuthFixedParam authfp;
    authfp.Auth_Algorithm = 0x00;
    authfp.Auth_SEQ = 1;
    authfp.Status_Code = 0x0000;

    memcpy(packet + dataPointer, &authfp, sizeof(authfp));
    dataPointer += sizeof(authfp);

    unsigned char temp[] = {0xdd, 0x0b, 0x00, 0x17, 0xf2, 0x0a, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x09, 0x00, 0x10, 0x18, 0x02, 0x00, 0x00, 0x10, 0x00, 0x00};

    memcpy(packet + dataPointer, temp, sizeof(temp));
    dataPointer += sizeof(temp);

    printf("[Generate Packet]\n");
    for (int i = 0; i < dataPointer; i++)
    {
        printf("%02X ", packet[i]);
        if (!((i + 1) % 8))
            printf("  ");
        if (!((i + 1) % 16))
            printf("\n");
    }
    printf("\n\n");

    memset(_configurator->tempPacket, 0, 1500);
    memcpy(_configurator->tempPacket, packet, dataPointer);
    return dataPointer;
}

static int
Check_WPA2_Authentication_Res(pcap_t *adhandle, ConfiguratorInfo *_configurator, PeerInfo *_peer)
{
    struct pcap_pkthdr *header;
    const unsigned char *_packet;

    int result = pcap_next_ex(adhandle, &header, &_packet);

    unsigned char *packet = (unsigned char *)_packet;

    int dataPointer = 0;

    RadiotapHeader *tRadio = (RadiotapHeader *)packet;
    dataPointer += tRadio->Header_Len;

    struct ieee80211_frame *fh = (struct ieee80211_frame *)(packet + dataPointer);
    dataPointer += sizeof(*fh);

    memcpy(_peer->MACAddr, fh->i_addr2, IEEE80211_ADDR_LEN);
    u_int8_t type = fh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    u_int8_t subtype = fh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    if (is_equal(_configurator->MACAddr, fh->i_addr1, IEEE80211_ADDR_LEN))
    {
        if (type == IEEE80211_FC0_TYPE_MGT && subtype == IEEE80211_FC0_SUBTYPE_AUTH)
        {
            AuthFixedParam *Authfp = (AuthFixedParam *)(packet + dataPointer);
            dataPointer += sizeof(*Authfp);

            if (Authfp->Auth_Algorithm == 0x0000 && Authfp->Auth_SEQ == 2)
            {

                if (Authfp->Status_Code == 0x00)
                {
                    //
                    printf("[Check Packet]\n");
                    for (int i = 0; i < dataPointer; i++)
                    {
                        printf("%02X ", packet[i]);
                        if (!((i + 1) % 8))
                            printf("  ");
                        if (!((i + 1) % 16))
                            printf("\n");
                    }
                    printf("\n\n");
                    printf("This Packet Type is WPA2 Authentication Response Packet!!!\n\n");

                    //version
                    return SUCCESS;
                }
            }
            else
                return FAIL;
        }
        else
            return FAIL;
    }
}

static int Generate_WPA2_Association_Req(ConfiguratorInfo *_configurator, PeerInfo *_peer)
{
    uint8_t packet[1500] = {0};
    int dataPointer = 0;

    //radiotap header
    RadiotapHeader rh;

    rh.Header_revision = 0x0000;
    rh.Header_Len = 18;
    rh.flags = 0x00;
    rh.Present_Flags[0] = 0x2e;
    rh.Present_Flags[1] = 0x48;
    rh.Present_Flags[2] = 0x00;
    rh.Present_Flags[3] = 0x00;

    memcpy(packet, &rh, rh.Header_Len);
    dataPointer += rh.Header_Len;

    //ieee80211 action frame
    struct ieee80211_frame fh;
    fh.i_fc[0] = IEEE80211_FC0_SUBTYPE_ASSOC_REQ;
    fh.i_fc[1] = IEEE80211_FC0_TYPE_MGT;
    fh.i_dur[0] = 0x00;
    fh.i_dur[1] = 0x00;
    memcpy(fh.i_addr1, _peer->MACAddr, IEEE80211_ADDR_LEN);
    memcpy(fh.i_addr2, _configurator->MACAddr, IEEE80211_ADDR_LEN);
    memcpy(fh.i_addr3, _peer->MACAddr, IEEE80211_ADDR_LEN);

    memcpy(packet + dataPointer, &fh, sizeof(fh));
    dataPointer += sizeof(fh);

    AssoReqFixedParam AssoReqfp;
    AssoReqfp.Capabilities_Info = htons(0x3104);
    AssoReqfp.Listen_Interval = htons(0x0014);

    memcpy(packet + dataPointer, &AssoReqfp, sizeof(AssoReqfp));
    dataPointer += sizeof(AssoReqfp);

    TagParamSSID tagssid;

    tagssid.Tag_Num = 0x00;
    char temp[] = "infolap420";
    tagssid.Tag_Length = strlen(temp);

    memcpy(packet + dataPointer, &tagssid, sizeof(tagssid));
    dataPointer += sizeof(tagssid);

    memcpy(packet + dataPointer, temp, strlen(temp));
    dataPointer += tagssid.Tag_Length;

    printf("%ld\n", sizeof(TagParamSSID));
    printf("%ld\n", strlen(temp));

    TagParamSupportedRates tagrates;

    tagrates.Tag_Num = 0x01;
    tagrates.Tag_Length = 4;
    tagrates.rates1 = 0x02;
    tagrates.rates2 = 0x04;
    tagrates.rates5 = 0x0b;
    tagrates.rates11 = 0x16;

    memcpy(packet + dataPointer, &tagrates, sizeof(tagrates));
    dataPointer += sizeof(tagrates);

    printf("[Generate Packet]\n");
    for (int i = 0; i < dataPointer; i++)
    {
        printf("%02X ", packet[i]);
        if (!((i + 1) % 8))
            printf("  ");
        if (!((i + 1) % 16))
            printf("\n");
    }
    printf("\n\n");

    TagParamRSN tagrsn;

    tagrsn.Tag_Num = 48;
    tagrsn.Tag_Length = 26;
    tagrsn.RSN_Version = 0x0001;
    tagrsn.Group_CipherSuite_OUI[0] = 0x00;
    tagrsn.Group_CipherSuite_OUI[1] = 0x0f;
    tagrsn.Group_CipherSuite_OUI[2] = 0xac;
    tagrsn.Group_CipherSuite_Type = 0x04;
    tagrsn.Pairwise_CipherSuite_Cnt = 1;
    tagrsn.Pairwise_CipherSuite_OUI[0] = 0x00;
    tagrsn.Pairwise_CipherSuite_OUI[1] = 0x0f;
    tagrsn.Pairwise_CipherSuite_OUI[2] = 0xac;
    tagrsn.Pairwise_CipherSuite_Type = 0x04;

    tagrsn.AKM_Suite_Cnt = 1;
    tagrsn.AKM_Suite_OUI[0] = 0x50;
    tagrsn.AKM_Suite_OUI[1] = 0x6F;
    tagrsn.AKM_Suite_OUI[2] = 0x9A;
    tagrsn.AKM_Suite_Type = 0x02;
    tagrsn.RSN_Capabilities = htons(0x00c0);
    tagrsn.PMK_Cnt = 0x00;

    tagrsn.Group_Manager_CipherSuite_OUI[0] = 0x00;
    tagrsn.Group_Manager_CipherSuite_OUI[1] = 0x0f;
    tagrsn.Group_Manager_CipherSuite_OUI[2] = 0xac;
    tagrsn.Group_Manager_CipherSuite_Type = 0x04;

    memcpy(packet + dataPointer, &tagrsn, sizeof(tagrsn));
    dataPointer += sizeof(tagrsn);

    TagExtend tagextend;
    tagextend.Tag_Num = 127;
    tagextend.Tag_Length = 10;
    tagextend.octet1 = 0x0a;
    tagextend.octet2 = 0x0a;
    tagextend.octet3 = 0x0a;
    tagextend.octet4 = 0x02;
    tagextend.octet5 = 0x01;
    tagextend.octet6 = 0x40;
    tagextend.octet7 = 0x00;
    tagextend.octet89 = htons(0x0040);
    tagextend.octet10 = 0x01;

    memcpy(packet + dataPointer, &tagextend, sizeof(tagextend));
    dataPointer += sizeof(tagextend);

    printf("[Generate Packet]\n");
    for (int i = 0; i < dataPointer; i++)
    {
        printf("%02X ", packet[i]);
        if (!((i + 1) % 8))
            printf("  ");
        if (!((i + 1) % 16))
            printf("\n");
    }
    printf("\n\n");

    memset(_configurator->tempPacket, 0, 1500);
    memcpy(_configurator->tempPacket, packet, dataPointer);

    return dataPointer;
}

static int
Check_WPA2_Association_Res(pcap_t *adhandle, ConfiguratorInfo *_myinfo, PeerInfo *_peerinfo)
{
    struct pcap_pkthdr *header;
    const unsigned char *_packet;

    int result = pcap_next_ex(adhandle, &header, &_packet);

    unsigned char *packet = (unsigned char *)_packet;

    int dataPointer = 0;

    RadiotapHeader *tRadio = (RadiotapHeader *)packet;
    dataPointer += tRadio->Header_Len;

    struct ieee80211_frame *fh = (struct ieee80211_frame *)(packet + dataPointer);
    dataPointer += sizeof(*fh);

    u_int8_t type = fh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    u_int8_t subtype = fh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    if (is_equal(_myinfo->MACAddr, fh->i_addr1, IEEE80211_ADDR_LEN))
    {
        if (is_equal(_peerinfo->MACAddr, fh->i_addr2, IEEE80211_ADDR_LEN))
        {
            if (type == IEEE80211_FC0_TYPE_MGT && subtype == IEEE80211_FC0_SUBTYPE_ASSOC_RESP)
            {
                AssoResFixedParam *AssoResfp = (AssoResFixedParam *)(packet + dataPointer);
                dataPointer += sizeof(*AssoResfp);

                if (AssoResfp->StatusCode == 0x0000)
                {
                    // memcpy(_peerinfo->SSID, (unsigned char*)packet+dataPointer, TagSSID->Tag_Length);
                    // dataPointer += TagSSID -> Tag_Length;

                    // TagParamSupportedRates *TagRates = (TagParamSupportedRates *)(packet+dataPointer);
                    // dataPointer += sizeof(TagRates);

                    // TagParamRSN *TagRSN = (TagParamRSN *)(packet+dataPointer);
                    // dataPointer += sizeof(TagRSN);

                    // memcpy(_peerinfo->Group_CipherSuite_OUI, TagRSN->Group_CipherSuite_OUI, 3);
                    // _peerinfo->Group_CipherSuite_Type = TagRSN->Group_CipherSuite_Type;
                    // memcpy(_peerinfo->Pairwise_CipherSuite_OUI, TagRSN->Pairwise_CipherSuite_OUI, 3);
                    // _peerinfo->Pairwise_CipherSuite_Type = TagRSN->Pairwise_CipherSuite_Type;
                    // memcpy(_peerinfo->AKM_Suite_OUI, TagRSN->AKM_Suite_OUI, 3);
                    // _peerinfo->AKM_Suite_Type = TagRSN->AKM_Suite_Type;
                    // memcpy(_peerinfo->Group_Manager_CipherSuite_OUI, TagRSN->Group_Manager_CipherSuite_OUI, 3);
                    // _peerinfo->Group_Manager_CipherSuite_Type = TagRSN->Group_Manager_CipherSuite_Type;

                    printf("[Check Packet]\n");
                    for (int i = 0; i < dataPointer; i++)
                    {
                        printf("%02X ", packet[i]);
                        if (!((i + 1) % 8))
                            printf("  ");
                        if (!((i + 1) % 16))
                            printf("\n");
                    }
                    printf("\n\n");
                    printf("This Packet Type is WPA2 Association Response Packet!!!\n\n");

                    printf("[INFO] Generate PMK\n\n");
                    printf("[CHECK] PASS : ");
                    printf("%s \n\n", _myinfo->PASS);
                    printf("[CHECK] SSID : ");
                    printf("%s \n\n", _myinfo->SSID);

                    PKCS5_PBKDF2_HMAC_SHA1(_myinfo->PASS, strlen(_myinfo->PASS), (const unsigned char *)_myinfo->SSID, strlen(_myinfo->SSID), 4096, 32, _myinfo->PMK);

                    printf("[CHECK] Generate PMK : \n\n");
                    for (int i = 0; i < KEY_PMK_LENGTH; i++)
                    {
                        printf("%02x", _myinfo->PMK[i]);
                    }
                    printf("\n\n");

                    return SUCCESS;
                }
                else
                    return FAIL;
            }
            else
                return FAIL;
        }
        else
            return FAIL;
    }
}

static int Check_WPA2_EAPOL1(pcap_t *adhandle, ConfiguratorInfo *_myInfo, PeerInfo *_peerInfo)
{
    struct pcap_pkthdr *header;
    const unsigned char *_packet;

    int result = pcap_next_ex(adhandle, &header, &_packet);

    unsigned char *packet = (unsigned char *)_packet;

    int dataPointer = 0;

    RadiotapHeader *tRadio = (RadiotapHeader *)packet;
    dataPointer += tRadio->Header_Len;

    struct ieee80211_qosframe *qf = (struct ieee80211_qosframe *)(packet + dataPointer);
    dataPointer += sizeof(*qf);

    u_int8_t type = qf->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    u_int8_t subtype = qf->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    if (is_equal(_myInfo->MACAddr, qf->i_addr1, IEEE80211_ADDR_LEN) && is_equal(_peerInfo->MACAddr, qf->i_addr2, IEEE80211_ADDR_LEN))
    {
        if (type == IEEE80211_FC0_TYPE_DATA && subtype == IEEE80211_FC0_SUBTYPE_QOS)
        {
            LLC *llc = (LLC *)(packet + dataPointer);
            dataPointer += sizeof(*llc);

            IEEE80211Auth *auth = (IEEE80211Auth *)(packet + dataPointer);
            dataPointer += sizeof(*auth);
            if (auth->Key_Info == ntohs(0x008a))
            {
                printf("[INFO] Anonce Copied!! \n\n");
                memcpy(_peerInfo->Anonce, auth->WPA_Key_Nonce, KEY_NONCE_LENGTH);
                printf("[CHECK] Check Anonce(AP)] : ");
                for (int i = 0; i < KEY_NONCE_LENGTH; i++)
                    printf("%02X", _peerInfo->Anonce[i]);
                printf("\n\n");

                RSN_PMKID *pmkid = (RSN_PMKID *)(packet + dataPointer);
                dataPointer += sizeof(*pmkid);

                printf("[Check Packet]\n");
                for (int i = 0; i < dataPointer; i++)
                {
                    printf("%02X ", packet[i]);
                    if (!((i + 1) % 8))
                        printf("  ");
                    if (!((i + 1) % 16))
                        printf("\n");
                }
                printf("\n\n");
                printf("This Packet Type is EAPOL Message 1!!!\n\n");

                return SUCCESS;
            }
            else
            {
                return FAIL;
            }
        }
        else
        {
            return FAIL;
        }
    }
    else
    {
        return FAIL;
    }
}

void generate_WPA2_nonce(uint8_t *_nonce, uint8_t *_addr)
{
    uint8_t rb[KEY_PRF_RANDOM_LENGTH] = {0};
    if (!RAND_bytes(rb, KEY_PRF_RANDOM_LENGTH))
    {
        printf("[error] RAND_bytes");
    }

    time_t timer;
    struct tm *t;
    timer = time(NULL);
    t = localtime(&timer);

    //TODO: uint8_t current[100] = {0};
    char current[100] = {0};
    sprintf(current, "%d%d%d%d%d%d\n", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

    uint8_t init[KEY_PRF_INIT_LENGTH] = {0};
    int intiSize = 0;
    memcpy(init, KEY_PRF_INIT, strlen(KEY_PRF_INIT));
    intiSize += strlen(KEY_PRF_INIT) + 1;

    memcpy(init + intiSize, _addr, ETH_ALEN);
    intiSize += ETH_ALEN;

    memcpy(init + intiSize, current, strlen(current) - 1);
    intiSize += strlen(current) - 1;

    HMAC(EVP_sha256(), rb, KEY_PRF_RANDOM_LENGTH, init, intiSize, _nonce, NULL);
}

void Generate_EAPOL_Key(ConfiguratorInfo *_myInfo, PeerInfo *_peerInfo)
{
    //SNONCE
    uint8_t snonce[KEY_NONCE_LENGTH];
    generate_WPA2_nonce(snonce, _myInfo->MACAddr);
    memcpy(_myInfo->Snonce, snonce, KEY_NONCE_LENGTH);
    printf("[NONCE] Generate Snonce(STA)] : ");
    for (int i = 0; i < KEY_NONCE_LENGTH; i++)
        printf("%02X", _myInfo->Snonce[i]);
    printf("\n\n");

    //PKE
    uint8_t temp_pke[KEY_PKE_LENGTH] = {0};
    memcpy(temp_pke, "Pairwise key expansion", 23);

    if (memcmp(_myInfo->MACAddr, _peerInfo->MACAddr, ETH_ALEN) < 0)
    {
        memcpy(temp_pke + 23, _myInfo->MACAddr, ETH_ALEN);
        memcpy(temp_pke + 29, _peerInfo->MACAddr, ETH_ALEN);
    }
    else
    {
        memcpy(temp_pke + 23, _peerInfo->MACAddr, ETH_ALEN);
        memcpy(temp_pke + 29, _myInfo->MACAddr, ETH_ALEN);
    }

    if (memcmp(_myInfo->Snonce, _peerInfo->Anonce, KEY_NONCE_LENGTH) < 0)
    {
        memcpy(temp_pke + 35, _myInfo->Snonce, KEY_NONCE_LENGTH);
        memcpy(temp_pke + 67, _peerInfo->Anonce, KEY_NONCE_LENGTH);
    }
    else
    {
        memcpy(temp_pke + 35, _peerInfo->Anonce, KEY_NONCE_LENGTH);
        memcpy(temp_pke + 67, _myInfo->Snonce, KEY_NONCE_LENGTH);
    }
    memcpy(_myInfo->eapolkey.pke, temp_pke, KEY_PKE_LENGTH);
    //PTK
    uint8_t temp_ptk[KEY_PTK_LENGTH] = {0};

    for (int i = 0; i < 4; i++)
    {
        temp_pke[99] = i;
        HMAC(EVP_sha1(), _myInfo->PMK, KEY_PMK_LENGTH, temp_pke, 100, temp_ptk + i * 20, NULL);
    }
    memcpy(_myInfo->eapolkey.ptk, temp_ptk, KEY_PTK_LENGTH);
    //KCK KEK TK
    uint8_t temp_kck[KEY_LENGTH] = {0}, temp_kek[KEY_LENGTH] = {0}, temp_tk[KEY_LENGTH] = {0};
    for (int i = 0; i < KEY_LENGTH; i++)
    {
        temp_kck[i] = temp_ptk[i];
        temp_kek[i] = temp_ptk[i + 16];
        temp_tk[i] = temp_ptk[i + 32];
    }

    memcpy(_myInfo->eapolkey.kck, temp_kck, KEY_LENGTH);
    memcpy(_myInfo->eapolkey.kek, temp_kek, KEY_LENGTH);
    memcpy(_myInfo->eapolkey.tk, temp_tk, KEY_LENGTH);

    printf("[KEYGEN] Calc KCK : ");
    for (int i = 0; i < KEY_LENGTH; i++)
        printf("%02X", _myInfo->eapolkey.kck[i]);
    printf("\n\n");

    printf("[KEYGEN] Calc KEK : ");
    for (int i = 0; i < KEY_LENGTH; i++)
        printf("%02X", _myInfo->eapolkey.kek[i]);
    printf("\n\n");

    printf("[KEYGEN] Calc TK : ");
    for (int i = 0; i < KEY_LENGTH; i++)
        printf("%02X", _myInfo->eapolkey.tk[i]);
    printf("\n\n");
}
static int Generate_WPA2_EAPOL2(ConfiguratorInfo *_myInfo, PeerInfo *_peerInfo)
{
    u_int8_t packet[1500] = {0};
    int dataPointer = 0;

    //radiotap header
    u8 radiotap[] = {0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(packet, radiotap, sizeof(radiotap));
    dataPointer += sizeof(radiotap);

    //ieee80211 action frame
    struct ieee80211_qosframe qf = {0};
    qf.i_fc[0] = IEEE80211_FC0_SUBTYPE_QOS | IEEE80211_FC0_TYPE_DATA;
    qf.i_fc[1] = 0x00;
    memcpy(qf.i_addr1, _peerInfo->MACAddr, IEEE80211_ADDR_LEN);
    memcpy(qf.i_addr2, _myInfo->MACAddr, IEEE80211_ADDR_LEN);
    memcpy(qf.i_addr3, _peerInfo->MACAddr, IEEE80211_ADDR_LEN);

    memcpy(packet + dataPointer, &qf, sizeof(qf));
    dataPointer += sizeof(qf);

    //llc
    LLC llc = {0};
    llc.DSAP = 0xaa;
    llc.SSAP = 0xaa;
    llc.ControlField = 0x03;
    llc.OriginCode[0] = 0;
    llc.OriginCode[1] = 0;
    llc.OriginCode[2] = 0;
    llc.Type = htons(0x888e);
    memcpy(packet + dataPointer, &llc, sizeof(llc));
    dataPointer += sizeof(llc);

    // auth
    IEEE80211Auth auth = {0};
    auth.Version = 0x01;
    auth.Type = 0x03;
    // Key Descriptor Type ~ End
    auth.Length = htons(sizeof(IEEE80211Auth) + sizeof(RSN_PMKID) - 4);

    auth.Key_Descriptor_Type = 0x02;
    

    auth.Key_Info = htons(0x010a);

    // TK Length
    auth.Key_Length = htons(0x0010);

    // generate nonce & key
    Generate_EAPOL_Key(_myInfo, _peerInfo);
    memcpy(auth.WPA_Key_Nonce, _myInfo->Snonce, KEY_NONCE_LENGTH);

    // MIC
    memset(auth.Key_IV, 0, 16);
    memset(auth.WPA_Key_RSC, 0, 8);
    memset(auth.WPA_Key_ID, 0, 8);
    memset(auth.WPA_Key_MIC, 0, 16);
    auth.WPA_Key_DataLen = htons(sizeof(RSN_INFO));

    // uint8_t *tempData = (uint8_t *)calloc(0, sizeof(IEEE80211Auth) + 1);
    uint8_t tempData[1000] = {0};
    memcpy(tempData, &auth, sizeof(IEEE80211Auth));

    uint8_t tempMIC[KEY_MIC_LENGTH] = {0};
    HMAC(EVP_sha1(), _myInfo->eapolkey.kck, KEY_LENGTH, tempData, sizeof(IEEE80211Auth), tempMIC, NULL);

    memcpy(auth.WPA_Key_MIC, tempMIC, KEY_MIC_LENGTH);
    printf("[CHECK] Check MIC : ");
    for (int i = 0; i < KEY_MIC_LENGTH; i++)
        printf("%02X", auth.WPA_Key_MIC[i]);
    printf("\n\n");

    memcpy(packet + dataPointer, &auth, sizeof(auth));
    dataPointer += sizeof(auth);

    // auth data(rsn info)
    RSN_INFO rsn = {0};
    rsn.id = 0x30;

    // RSN Version ~ END
    rsn.len = sizeof(RSN_INFO) - 2;
    rsn.version = htons(0x1000);

    u8 oui[3] = {0x00, 0x0f, 0xac};
    memcpy(rsn.group.oui, oui, 3);
    rsn.group.type = 0x04;

    rsn.pairCount = htons(0x0100);
    memcpy(rsn.pair.oui, oui, 3);
    rsn.pair.type = 0x03;

    rsn.authCount = htons(0x0100);
    memcpy(rsn.auth.oui, oui, 3);
    rsn.auth.type = 0x02;

    rsn.cap = htons(0x0c00);

    memcpy(packet + dataPointer, &rsn, sizeof(rsn));
    dataPointer += sizeof(rsn);

    printf("[Generate Packet]\n");
    for (int i = 0; i < dataPointer; i++)
    {
        printf("%02X ", packet[i]);
        if (!((i + 1) % 8))
            printf("  ");
        if (!((i + 1) % 16))
            printf("\n");
    }
    printf("\n\n");

    memset(_myInfo->tempPacket, 0, 1500);
    memcpy(_myInfo->tempPacket, packet, dataPointer);

    return dataPointer;
}

static int Check_WPA2_EAPOL3(pcap_t *adhandle, ConfiguratorInfo *_myInfo, PeerInfo *_peerInfo)
{
    struct pcap_pkthdr *header;
    const unsigned char *_packet;

    int result = pcap_next_ex(adhandle, &header, &_packet);

    unsigned char *packet = (unsigned char *)_packet;

    int dataPointer = 0;

    RadiotapHeader *tRadio = (RadiotapHeader *)packet;
    dataPointer += tRadio->Header_Len;

    struct ieee80211_qosframe *qf = (struct ieee80211_qosframe *)(packet + dataPointer);
    dataPointer += sizeof(*qf);

    u_int8_t type = qf->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    u_int8_t subtype = qf->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    if (is_equal(_myInfo->MACAddr, qf->i_addr1, IEEE80211_ADDR_LEN) && is_equal(_peerInfo->MACAddr, qf->i_addr2, IEEE80211_ADDR_LEN))
    {
        if (type == IEEE80211_FC0_TYPE_DATA && subtype == IEEE80211_FC0_SUBTYPE_QOS)
        {
            LLC *llc = (LLC *)(packet + dataPointer);
            dataPointer += sizeof(*llc);

            IEEE80211Auth *auth = (IEEE80211Auth *)(packet + dataPointer);
            dataPointer += sizeof(*auth);
            if (auth->Key_Info == ntohs(0x13ca))
            {
                if (is_equal(auth->WPA_Key_Nonce, _peerInfo->Anonce, KEY_NONCE_LENGTH))
                {
                    printf("[CHECK] Check Anonce(AP)] : ");
                    for (int i = 0; i < KEY_NONCE_LENGTH; i++)
                        printf("%02X", _peerInfo->Anonce[i]);
                    printf("\n\n");

                    //MIC CHECK
                    uint8_t peerMIC[KEY_MIC_LENGTH] = {0};
                    memcpy(peerMIC, auth->WPA_Key_MIC, KEY_MIC_LENGTH);

                    memset(auth->WPA_Key_MIC, 0, KEY_MIC_LENGTH);
                    // uint8_t *tempData = (uint8_t *)calloc(0, sizeof(IEEE80211Auth));
                    uint8_t tempData[1000] = {0};
                    memcpy(tempData, auth, sizeof(IEEE80211Auth));

                    uint8_t tempMIC[KEY_MIC_LENGTH] = {0};
                    HMAC(EVP_sha1(), _myInfo->eapolkey.kck, KEY_LENGTH, tempData, sizeof(IEEE80211Auth), tempMIC, NULL);

                    printf("[CHECK] Calc check MIC : ");
                    for (int i = 0; i < KEY_MIC_LENGTH; i++)
                        printf("%02X", tempMIC[i]);
                    printf("\n\n");

                    if (!is_equal(peerMIC, tempMIC, KEY_MIC_LENGTH))
                    {
                        printf("[INFO] MIC Check Fail..\n\n ");
                        return FAIL;
                    }
                    else
                    {
                        printf("[INFO] MIC Checked!!!\n\n ");
                    }

                    // decrypt

                    unsigned char *wrappedData = (unsigned char *)(packet + dataPointer);
                    unsigned char temp[100] = {0};
                    memcpy(temp, wrappedData, 56);
                    AES_KEY tkey;
                    u8 testData[100] = {0};
                    AES_set_decrypt_key(_myInfo->eapolkey.kek, 128, &tkey);

                    int tSize = AES_unwrap_key(&tkey, NULL, testData, temp, 56);
                    if (tSize == 0)
                    {
                        printf("[INFO] Decryption Fail..\n\n");
                        return FAIL;
                    }
                    printf("[CHECK] Decryption Data \n");
                    for (int i = 0; i < tSize; i++)
                    {
                        printf("%02X ", testData[i]);
                        if (!((i + 1) % 8))
                            printf("  ");
                        if (!((i + 1) % 16))
                            printf("\n");
                    }
                    printf("\n\n");

                    dataPointer += 56;

                    printf("[Check Packet]\n");
                    for (int i = 0; i < dataPointer; i++)
                    {
                        printf("%02X ", packet[i]);
                        if (!((i + 1) % 8))
                            printf("  ");
                        if (!((i + 1) % 16))
                            printf("\n");
                    }
                    printf("\n\n");
                    printf("This Packet Type is EAPOL Message 3!!!\n\n");

                    return SUCCESS;
                }
                else
                {
                    return FAIL;
                }
            }
            else
            {
                return FAIL;
            }
        }
        else
        {
            return FAIL;
        }
    }
    else
    {
        return FAIL;
    }
}

void Generate_GMK(ConfiguratorInfo *_myInfo, PeerInfo *_peerInfo)
{
    u_int8_t gmk[KEY_GMK_LENGTH] = {0};
    if (!RAND_bytes(gmk, KEY_GMK_LENGTH))
    {
        printf("[error] RAND_bytes");
    }

    printf("[KEYGEN] Generate GMK : ");
    for (int i = 0; i < KEY_GMK_LENGTH; i++)
        printf("%02X", gmk[i]);
    printf("\n\n");

    u_int8_t gnonce[KEY_NONCE_LENGTH] = {0};
    generate_WPA2_nonce(gnonce, _myInfo->MACAddr);

    printf("[NONCE] Generate Gnonce(Group)] : ");
    for (int i = 0; i < KEY_NONCE_LENGTH; i++)
        printf("%02X", gnonce[i]);
    printf("\n\n");

    time_t timer;
    struct tm *t;
    timer = time(NULL);
    t = localtime(&timer);

    //TODO: uint8_t current[100] = {0};
    char current[100] = {0};
    sprintf(current, "%d%d%d%d%d%d\n", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

    uint8_t gpke[KEY_PKE_LENGTH] = {0};
    memcpy(gpke, "Group key expansion", 20);
    memcpy(gpke + 20, _myInfo->MACAddr, IEEE80211_ADDR_LEN);
    memcpy(gpke + 20 + IEEE80211_ADDR_LEN, current, strlen(current));

    uint8_t gtk[KEY_GTK_LENGTH] = {0};
    HMAC(EVP_sha256(), gmk, KEY_GMK_LENGTH, gpke, 20 + IEEE80211_ADDR_LEN + strlen(current), gtk, NULL);

    memcpy(_myInfo->eapolkey.gtk, gtk, KEY_GTK_LENGTH);
    printf("[KEYGEN] Calc GTK : ");
    for (int i = 0; i < KEY_GTK_LENGTH; i++)
        printf("%02X", gtk[i]);
    printf("\n\n");

    printf("[KEYGEN] Calc GTK(copied) : ");
    for (int i = 0; i < KEY_GTK_LENGTH; i++)
        printf("%02X", _myInfo->eapolkey.gtk[i]);
    printf("\n\n");
}

static int Generate_WPA2_EAPOL4(ConfiguratorInfo *_myInfo, PeerInfo *_peerInfo)
{
    int dataPointer = 0;
    u_int8_t packet[1500] = {0};
    Generate_GMK(_myInfo, _peerInfo);

    //radiotap header
    u8 radiotap[] = {0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(packet, radiotap, sizeof(radiotap));
    dataPointer += sizeof(radiotap);

    //ieee80211 action frame
    struct ieee80211_qosframe qf = {0};
    qf.i_fc[0] = IEEE80211_FC0_SUBTYPE_QOS | IEEE80211_FC0_TYPE_DATA;
    qf.i_fc[1] = 0x00;
    memcpy(qf.i_addr1, _peerInfo->MACAddr, IEEE80211_ADDR_LEN);
    memcpy(qf.i_addr2, _myInfo->MACAddr, IEEE80211_ADDR_LEN);
    memcpy(qf.i_addr3, _peerInfo->MACAddr, IEEE80211_ADDR_LEN);

    memcpy(packet + dataPointer, &qf, sizeof(qf));
    dataPointer += sizeof(qf);

    //llc
    LLC llc = {0};
    llc.DSAP = 0xaa;
    llc.SSAP = 0xaa;
    llc.ControlField = 0x03;
    llc.OriginCode[0] = 0;
    llc.OriginCode[1] = 0;
    llc.OriginCode[2] = 0;
    llc.Type = htons(0x888e);
    memcpy(packet + dataPointer, &llc, sizeof(llc));
    dataPointer += sizeof(llc);

    // auth
    IEEE80211Auth auth = {0};
    auth.Version = 0x01;
    auth.Type = 0x03;

    // Key Descriptor Type ~ End
    auth.Length = htons(sizeof(IEEE80211Auth) - 4);

    auth.Key_Descriptor_Type = 0x02;
    auth.Key_Info = htons(0x030A);

    // TK Length
    auth.Key_Length = htons(0x0010);

    //NONCE
    memset(auth.WPA_Key_Nonce, 0, KEY_NONCE_LENGTH);

    //IV
    memset(auth.Key_IV, 0, 16);

    //EXTRA
    memset(auth.WPA_Key_RSC, 0, 8);
    memset(auth.WPA_Key_ID, 0, 8);
    memset(auth.WPA_Key_MIC, 0, 16);
    auth.WPA_Key_DataLen = 0;

    // MIC
    // uint8_t *tempData = (uint8_t *)calloc(0, sizeof(IEEE80211Auth) + 1);
    uint8_t tempData[1000] = {0};
    memcpy(tempData, &auth, sizeof(IEEE80211Auth));

    uint8_t tempMIC[KEY_MIC_LENGTH * 2] = {0};
    HMAC(EVP_sha1(), _myInfo->eapolkey.kck, KEY_LENGTH, tempData, sizeof(IEEE80211Auth), tempMIC, NULL);

    memcpy(auth.WPA_Key_MIC, tempMIC, KEY_MIC_LENGTH);
    printf("[CHECK] Check MIC : ");
    for (int i = 0; i < KEY_MIC_LENGTH; i++)
        printf("%02X", auth.WPA_Key_MIC[i]);
    printf("\n\n");

    memcpy(packet + dataPointer, &auth, sizeof(auth));
    dataPointer += sizeof(auth);

    printf("[Generate Packet]\n");
    for (int i = 0; i < dataPointer; i++)
    {
        printf("%02X ", packet[i]);
        if (!((i + 1) % 8))
            printf("  ");
        if (!((i + 1) % 16))
            printf("\n");
    }
    printf("\n\n");

    memset(_myInfo->tempPacket, 0, 1500);
    memcpy(_myInfo->tempPacket, packet, dataPointer);
    return dataPointer;
}

static int WPA2_PSK(ConfiguratorInfo *_configurator, PeerInfo *_peer, pcap_t *_adhandle)
{
    int dataPointer = Generate_WPA2_Authentication_Req(_configurator, _peer);
    int result = 0;
    while (1)
    {
        if (pcap_sendpacket(_adhandle, _configurator->tempPacket, dataPointer))
        {
            printf("send error\n");
            break;
        }
        int startTime = clock();
        while (1)
        {
            int currentTime = clock();
            if (Check_WPA2_Authentication_Res(_adhandle, _configurator, _peer))
            {
                result = SUCCESS;
                break;
            }
            if (currentTime >= startTime + 1000)
                break;
        }
        if (result == SUCCESS)
            break;
    }
    // Send Configuration Response
    result = 0;
    dataPointer = Generate_WPA2_Association_Req(_configurator, _peer);
    printf("[CHECK] Complete WPA2_Association_Req!\n\n");
    printf("[CHECK] Send WPA2_Association_Req..\n\n");
    while (1)
    {
        if (pcap_sendpacket(_adhandle, _configurator->tempPacket, dataPointer))
        {
            printf("send error\n");
            break;
        }

        // Receive Configuration Result
        int startTime = clock();
        while (1)
        {
            int currentTime = clock();
            if (Check_WPA2_Association_Res(_adhandle, _configurator, _peer) == SUCCESS)
            { //pmk generate
                result = SUCCESS;
                break;
            }
            if (currentTime >= startTime + 1000)
                break;
        }
        if (result == SUCCESS)
        {
            break;
            return SUCCESS;
        }
    }
    result = 0;
    while (1)
    {
        // Receive Configuration Result
        int startTime = clock();
        while (1)
        {
            int currentTime = clock();
            if (Check_WPA2_EAPOL1(_adhandle, _configurator, _peer) == SUCCESS)
            {
                result = SUCCESS;
                break;
            }
            if (currentTime >= startTime + 1000)
                break;
        }
        if (result == SUCCESS)
        {
            break;
            return SUCCESS;
        }
    }
    result = 0;
    dataPointer = Generate_WPA2_EAPOL2(_configurator, _peer);
    printf("[CHECK] Complete WPA2_EAPOL2!\n\n");
    printf("[CHECK] Send WPA2_EAPOL2..\n\n");
    while (1)
    {
        if (pcap_sendpacket(_adhandle, _configurator->tempPacket, dataPointer))
        {
            printf("send error\n");
            break;
        }

        // Receive Configuration Result
        int startTime = clock();
        while (1)
        {
            int currentTime = clock();
            if (Check_WPA2_EAPOL3(_adhandle, _configurator, _peer) == SUCCESS)
            {
                result = SUCCESS;
                break;
            }
            if (currentTime >= startTime + 1000)
                break;
        }
        if (result == SUCCESS)
        {
            break;
            return SUCCESS;
        }
    }
    result = 0;
    dataPointer = Generate_WPA2_EAPOL4(_configurator, _peer);
    printf("[CHECK] Complete WPA2_EAPOL4!\n\n");
    printf("[CHECK] Send WPA2_EAPOL4..\n\n");
    for (int i = 0; i < 4; i++)
    {
        if (pcap_sendpacket(_adhandle, _configurator->tempPacket, dataPointer))
        {
            printf("send error\n");
            break;
        }
        sleep(2);
    }
    return SUCCESS;
}

int main()
{
    pcap_t *adhandle;

    ConfiguratorInfo configurator = {0};
    PeerInfo peer = {0};
    Select_Device(&adhandle, configurator.NIC);
    Get_My_MACAddr(&configurator);

    if (Init(&configurator) == FAIL)
    {
        printf("[STATUS] Init Fail..\n\n");
    }

    if (Bootstraping(&configurator, &peer, adhandle) == FAIL)
    {
        printf("[STATUS] Bootstraping Fail..\n\n");
    }

    if (Authentication(&configurator, &peer, adhandle) == FAIL)
    {
        printf("[STATUS] Authentication Fail..\n\n");
    }

    printf("[INFO] Authentication Done!\n\n");

    if (Configuration(&configurator, &peer, adhandle) == FAIL)
    {
        printf("[STATUS] Configuration Fail..\n\n");
    }

    //TODO: if(is_equal(&peer.reqObj.netRole ,"ap", strlen("ap")))
    unsigned char tempAP[] = "ap";
    if(is_equal((uint8_t *)&peer.reqObj.netRole ,tempAP, 2))
    {
        if (WPA2_PSK(&configurator, &peer, adhandle) == FAIL)
        {
            printf("[STATUS] Configuration Fail..\n\n");
        }
        printf("[STATUS] All Process is done with AP!\n\n");
    }
    else
    {
        printf("[STATUS] All Process is done with IoT!\n\n");
    }

    return 0;
}
