// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.h"
#include "pubkey.h"
#include "utilstrencodings.h"
#include "primitives/block.h"
#include "poc.h"

#include "pkcs11/pkcs11.h"
#include <secp256k1.h>

bool fSmartCardUnlocked = false;

extern "C" CK_RV C_UnloadModule(void *module);
extern "C" void *C_LoadModule(const char *mspec, CK_FUNCTION_LIST_PTR_PTR funcs);
static void *module = NULL;
static CK_FUNCTION_LIST_PTR p11 = NULL;
static CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
static CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
static CK_MECHANISM mech;
static CPubKey smartCardPubKey;

#if defined(WIN32)
static std::string defaultPkcs11ModulePath = "";
#elif defined(MAC_OSX)
static std::string defaultPkcs11ModulePath = "";
#else
static std::string defaultPkcs11ModulePath = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so";
#endif

static void cleanup_p11()
{
    if (p11)
        p11->C_Finalize(NULL_PTR);
    if (module)
        C_UnloadModule(module);
}

static unsigned char * getEC_POINT(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount)
{
    CK_ATTRIBUTE attr = { CKA_EC_POINT, NULL, 0 };
    CK_RV rv;

    rv = p11->C_GetAttributeValue(sess, obj, &attr, 1);
    if (rv == CKR_OK) {
        if (!(attr.pValue = calloc(1, attr.ulValueLen + 1))) {
            LogPrintf("getEC_POINT: out of memory in getEC_PONIT\n");
            return NULL;
        }
        rv = p11->C_GetAttributeValue(sess, obj, &attr, 1);
        if (pulCount)
            *pulCount = attr.ulValueLen;
    } else {
        LogPrintf("getEC_POINT: ERROR, C_GetAttributeValue %u\n", rv);
    }
    return (unsigned char *)attr.pValue;
}

static int find_object(CK_SESSION_HANDLE sess, CK_OBJECT_CLASS cls,
        CK_OBJECT_HANDLE_PTR ret,
        const unsigned char *id, size_t id_len, int obj_index)
{
    CK_ATTRIBUTE attrs[2];
    unsigned int nattrs = 0;
    CK_ULONG count;
    CK_RV rv;
    int i;

    attrs[0].type = CKA_CLASS;
    attrs[0].pValue = &cls;
    attrs[0].ulValueLen = sizeof(cls);
    nattrs++;
    if (id) {
        attrs[nattrs].type = CKA_ID;
        attrs[nattrs].pValue = (void *) id;
        attrs[nattrs].ulValueLen = id_len;
        nattrs++;
    }

    rv = p11->C_FindObjectsInit(sess, attrs, nattrs);
    if (rv != CKR_OK) {
        std::cout << "C_FindObjectsInit" << std::endl;
        goto done;
    }

    for (i = 0; i < obj_index; i++) {
        rv = p11->C_FindObjects(sess, ret, 1, &count);
        if (rv != CKR_OK) {
            LogPrintf("C_FindObjects\n");
            goto done;
        }
        if (count == 0)
            goto done;
    }
    rv = p11->C_FindObjects(sess, ret, 1, &count);
    if (rv != CKR_OK) {
        LogPrintf("C_FindObjects\n");
        goto done;
    }

done:
    if (count == 0)
        *ret = CK_INVALID_HANDLE;

    p11->C_FindObjectsFinal(sess);

    return count;
}

bool CvnSignWithSmartCard(const uint256& hashUnsignedBlock, CCvnSignature& signature, const CCvnInfo& cvnInfo)
{
    CK_ULONG nSigLen = 64;
    secp256k1_ecdsa_signature sig;

    if (cvnInfo.vPubKey != smartCardPubKey) {
        LogPrintf("CvnSignWithSmartCard : key does not match node ID\n  CVN pubkey: %s\n CARD pubkey: %s\n", HexStr(cvnInfo.vPubKey), HexStr(smartCardPubKey));
        return false;
    }

    CK_RV rv = p11->C_SignInit(session, &mech, key);
    if (rv != CKR_OK) {
        LogPrintf("CvnSignWithSmartCard : ERROR, could not create signature with smart card(init): %08x\n", (unsigned int)rv);
        return false;
    }

    rv =  p11->C_Sign(session,
            (unsigned char*) hashUnsignedBlock.begin(), hashUnsignedBlock.size(),
            (unsigned char*) &sig, &nSigLen);

    if (rv != CKR_OK) {
        LogPrintf("CvnSignWithSmartCard : ERROR, could not create signature with smart card: %08x\n", (unsigned int)rv);
        return false;
    }

    std::reverse(sig.data, sig.data + 32);
    std::reverse(&sig.data[32], &sig.data[32] + 32);

    size_t nSigLenDER = 72;
    signature.vSignature.resize(72);

    secp256k1_context* tmp_secp256k1_context_sign = NULL;
    secp256k1_ecdsa_signature_serialize_der(tmp_secp256k1_context_sign, &signature.vSignature[0], &nSigLenDER, &sig);

    signature.vSignature.resize(nSigLenDER);

    if (!CvnVerifySignature(hashUnsignedBlock, signature)) {
        LogPrintf("CvnSignWithSmartCard : ERROR: created invalid signature\n");
        return false;
    }

#if POC_DEBUG
    LogPrintf("CvnSignWithSmartCard : OK\n  Hash: %s\n  node: 0x%08x\n  pubk: %s\n   sig: %s\n",
            hashUnsignedBlock.ToString(), signature.nSignerId,
            HexStr(cvnInfo.vPubKey),
            HexStr(signature.vSignature));
#endif
    return true;
}

void InitSmartCard()
{
    CK_OBJECT_HANDLE tmpPubKey = CK_INVALID_HANDLE;
    CK_BYTE opt_object_id[1];
    CK_RV rv;

    std::string pkcs11module = GetArg("-pkcs11module", defaultPkcs11ModulePath);
    static const char * opt_module = pkcs11module.c_str();

    module = C_LoadModule(opt_module, &p11);
    if (module == NULL) {
        LogPrintf("Failed to load pkcs11 module\n");
        return;
    }

    rv = p11->C_Initialize(NULL);
    if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        LogPrintf("library has already been initialized\n");
    } else if (rv != CKR_OK) {
        LogPrintf("error initializing pkcs11 framework\n");
        return;
    }

    LogPrintf("OpenSC successfully initialized using pkcs11 module at %s\n", opt_module);

    rv = p11->C_OpenSession(GetArg("-cvnslot", 0), CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK) {
        LogPrintf("ERROR: could not open session: %04x\n", (unsigned int)rv);
        cleanup_p11();
        return;
    }

    rv = p11->C_Login(session, CKU_USER,(CK_UTF8CHAR *) GetArg("-cvnpin", "").c_str(), 6);
    if (rv != CKR_OK) {
        LogPrintf("ERROR: could not log into card (is the supplied pin correct?)\n");
        cleanup_p11();
        return;
    }

    opt_object_id[0] = GetArg("-cvnkeyid", 1);
    if (find_object(session, CKO_PRIVATE_KEY, &key, opt_object_id, 1, 0) != 1){
        LogPrintf("ERROR: Private key not found on card (is the -cvnkeyid correct?)\n");
        cleanup_p11();
        return;
    }

    if (find_object(session, CKO_PUBLIC_KEY, &tmpPubKey, opt_object_id, 1, 0) != 1){
        LogPrintf("ERROR: Public key not found on card (is the -cvnkeyid correct?)\n");
        cleanup_p11();
        return;
    }

    CK_ULONG nPubKeySize = 0;
    unsigned char *pPubKey = getEC_POINT(session, tmpPubKey, &nPubKeySize);

    if (!pPubKey) {
        LogPrintf("ERROR: Public key not found on card (is the -cvnkeyid correct?)\n");
        cleanup_p11();
        return;
    }

    smartCardPubKey.Set(&pPubKey[2], pPubKey + nPubKeySize);
    free(pPubKey);

    memset(&mech, 0, sizeof(mech));
    mech.mechanism = CKM_ECDSA;
    fSmartCardUnlocked = true;

    LogPrintf("Successfully logged into smart card\n");
}