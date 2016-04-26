// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.h"
#include "poc.h"
#include "main.h"
#include "timedata.h"
#include "utilstrencodings.h"
#include "base58.h"
#include "net.h"
#include "miner.h"

#include <boost/thread.hpp>
#include <stdio.h>
#include <set>

uint32_t nCvnNodeId = 0;

CCriticalSection cs_mapCVNs;
CvnMapType mapCVNs;

CCriticalSection cs_mapCvnSigs;
CvnSigMapType mapCvnSigs;

bool fSmartCardUnlocked = false;

#ifdef USE_OPENSC
#include "pkcs11/pkcs11.h"
#include <secp256k1.h>

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

unsigned char * getEC_POINT(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount)
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
            printf("C_FindObjects\n");
            goto done;
        }
        if (count == 0)
            goto done;
    }
    rv = p11->C_FindObjects(sess, ret, 1, &count);
    if (rv != CKR_OK) {
        printf("C_FindObjects\n");
        goto done;
    }

done:
    if (count == 0)
        *ret = CK_INVALID_HANDLE;

    p11->C_FindObjectsFinal(sess);

    return count;
}

bool static CvnSignWithSmartCard(const uint256& hashUnsignedBlock, CCvnSignature& signature, const CCvnInfo& cvnInfo)
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

    LogPrintf("CvnSignWithSmartCard : OK\n  Hash: %s\n  node: 0x%08x\n  pubk: %s\n   sig: %s\n",
            hashUnsignedBlock.ToString(), signature.nSignerId,
            HexStr(cvnInfo.vPubKey),
            HexStr(signature.vSignature));

    return true;
}

#endif // USE_OPENSC

bool static CvnSignWithKey(const uint256& hashUnsignedBlock, const std::string strCvnPrivKey, CCvnSignature& signature, const CCvnInfo& cvnInfo)
{
    CBitcoinSecret secret;

    if (!secret.SetString(strCvnPrivKey)) {
        LogPrint("cvn", "CvnSignWithKey : private key is invalid\n");
        return false;
    }

    CKey key = secret.GetKey();

    if (cvnInfo.vPubKey != key.GetPubKey()) {
        LogPrint("cvn", "CvnSignWithKey : key does not match node ID\n");
        return false;
    }

    if (!key.Sign(hashUnsignedBlock, signature.vSignature)) {
        LogPrint("cvn", "CvnSignWithKey : could not create block signature\n");
        return false;
    }

    if (!CvnVerifySignature(hashUnsignedBlock, signature)) {
        LogPrint("cvn", "CvnSignWithKey : created invalid signature\n");
        return false;
    }

    LogPrintf("CvnSignWithKey : OK\n  Hash: %s\n  node: 0x%08x\n  pubk: %s\n   sig: %s\n",
            hashUnsignedBlock.ToString(), signature.nSignerId,
            HexStr(cvnInfo.vPubKey),
            HexStr(signature.vSignature));

    return true;
}

bool CvnSign(const uint256& hashBlock, CCvnSignature& signature, const uint32_t& nNodeId)
{
    if (!nNodeId) {
        LogPrint("cvn", "CvnSign : CVN node not initialized\n");
        return false;
    }

    signature.nSignerId = nNodeId;

    CvnMapType::iterator it = mapCVNs.find(signature.nSignerId);
    if (it == mapCVNs.end()) {
        LogPrintf("CvnSign : could not find CvnInfo for signer ID 0x%08x\n", signature.nSignerId);
        return false;
    }

    if (GetBoolArg("-usesmartcard", false)) {
#ifdef USE_OPENSC
        if (!fSmartCardUnlocked)
            LogPrint("cvn", "SignBlock : ERROR, smart card not unlocked. Make sure that -cvnpin, -cvnslot and -cvnkeyid are set correctly\n");
        return CvnSignWithSmartCard(hashBlock, signature, it->second);
#else
        LogPrintf("CvnSign : ERROR, this wallet was not compiled with smart card support\n");
        return false;
#endif
    } else {
        std::string strCvnPrivKey = GetArg("-cvnprivkey", "");

        if (strCvnPrivKey.size() != 51) {
            LogPrint("cvn", "CvnSign : ERROR, invalid private key supplied or -cvnprivkey is missing\n");
            return false;
        }

        return CvnSignWithKey(hashBlock, strCvnPrivKey, signature, it->second);
    }

    return false;
}

bool CvnVerifySignature(const uint256 &hash, const CCvnSignature &sig)
{
    CvnMapType::iterator it = mapCVNs.find(sig.nSignerId);

    if (it == mapCVNs.end()) {
        LogPrintf("ERROR: could not find CvnInfo for signer ID 0x%08x\n", sig.nSignerId);
        return false;
    }

    CPubKey pubKey = CPubKey(it->second.vPubKey);

    bool ret = pubKey.Verify(hash, sig.vSignature);

    if (!ret)
        LogPrintf("could not verify sig %s for hash %s for node Id 0x%08x\n", HexStr(sig.vSignature), hash.ToString(), sig.nSignerId);

    return ret;
}

void RelayCvnSignature(const CCvnSignatureMsg& signature)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << signature;

    CInv inv(MSG_CVN_SIGNATURE, signature.GetHash());
    {
        LOCK(cs_mapRelay);
        // Expire old relay messages
        while (!vRelayExpiration.empty() && vRelayExpiration.front().first < GetTime())
        {
            mapRelay.erase(vRelayExpiration.front().second);
            vRelayExpiration.pop_front();
        }

        // Save original serialized message so newer versions are preserved
        mapRelay.insert(std::make_pair(inv, ss));
        vRelayExpiration.push_back(std::make_pair(GetTime() + dynParams.nBlockSpacing * 60, inv));
    }

    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if(!pnode->fRelayTxes) // same TX rules apply to block sig messages
            continue;
        pnode->PushInventory(inv);
    }
}

bool AddCvnSignature(const CCvnSignature& signature, const uint256& hashPrevBlock, const uint32_t nCreatorId)
{
    if (!CvnValidateSignature(signature, hashPrevBlock, nCreatorId)) {
        LogPrintf("AddCvnSignature : invalid signature received %u\n", signature.nSignerId);
        return false;
    }

    LOCK(cs_mapCvnSigs);
    CvnSigEntryType& mapCvnForhashPrev = mapCvnSigs[hashPrevBlock];
    if (mapCvnForhashPrev.count(signature.nSignerId)) // already have this, no error
        return true;

    LogPrintf("AddCvnSignature : add sig for %u by %u, hash %s\n", nCreatorId, signature.nSignerId, hashPrevBlock.ToString());
    mapCvnForhashPrev[signature.nSignerId] = signature;

    return true;
}

bool CvnValidateSignature(const CCvnSignature& signature, const uint256& hashPrevBlock, const uint32_t nCreatorId)
{
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << hashPrevBlock << nCreatorId << signature.nSignerId;

    return CvnVerifySignature(hasher.GetHash(), signature);
}

void SendCVNSignature(const CBlockIndex *pindexNew)
{
    if (IsInitialBlockDownload())
        return;

    uint32_t nNextCreator = CheckNextBlockCreator(chainActive.Tip(), pindexNew->nTime + 1);

    if (!nNextCreator) {
        LogPrintf("SendCVNSignature : could not find next block creator\n");
        return;
    }

    uint256 hashPrevBlock = pindexNew->GetBlockHash();
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << hashPrevBlock << nNextCreator << nCvnNodeId;

    CCvnSignature signature;
    if (!CvnSign(hasher.GetHash(), signature, nCvnNodeId)) {
        LogPrintf("SendCVNSignature : could not sign block\n");
        return;
    }

    LogPrintf("SendCVNSignature : created CVN signature for block hash %s, nNextCreator: %u and nCvnNodeId: %u\n",
            hashPrevBlock.ToString(), nNextCreator, nCvnNodeId);

    CCvnSignatureMsg msg;
    msg.nVersion   = signature.nVersion;
    msg.nSignerId  = signature.nSignerId;
    msg.vSignature = signature.vSignature;
    msg.hashPrev   = hashPrevBlock;
    msg.nCreatorId = nNextCreator;

    if (AddCvnSignature(signature, msg.hashPrev, nNextCreator))
        RelayCvnSignature(msg);
}

void PrintAllCVNs()
{
    BOOST_FOREACH(const CvnMapType::value_type& cvn, mapCVNs) {
        LogPrintf("%s\n", cvn.second.ToString());
    }
}

void UpdateCvnInfo(const CBlock* pblock)
{
    LogPrint("cvn", "UpdateCvnInfo : updating CVN data\n");

    if (!pblock->HasCvnInfo()) {
        LogPrint("cvn", "UpdateCvnInfo : ERROR, block is not of type CVN\n");
        return;
    }

    LOCK(cs_mapCVNs);

    mapCVNs.clear();

    BOOST_FOREACH(CCvnInfo cvnInfo, pblock->vCvns) {
        mapCVNs.insert(std::make_pair(cvnInfo.nNodeId, cvnInfo));
    }

    //PrintAllCVNs();
}

bool CheckDynamicChainParameters(const CDynamicChainParams& params)
{
    if (params.nBlockSpacing > MAX_BLOCK_SPACING || params.nBlockSpacing < MIN_BLOCK_SPACING) {
        LogPrintf("CheckChainParameters : ERROR, block spacing %u exceeds limit\n", params.nBlockSpacing);
        return false;
    }

    if (params.nDustThreshold > MAX_DUST_THRESHOLD || params.nDustThreshold < MIN_DUST_THRESHOLD) {
        LogPrintf("CheckChainParameters : ERROR, dust threshold %u exceeds limit\n", params.nDustThreshold);
        return false;
    }

    if (!params.nMinCvnSigners || params.nMinCvnSigners > params.nMaxCvnSigners) {
        LogPrintf("CheckChainParameters : ERROR, number of CVN signers %u/%u exceeds limit\n", params.nMinCvnSigners, params.nMaxCvnSigners);
        return false;
    }

    return true;
}

void UpdateChainParameters(const CBlock* pblock)
{
    LogPrint("cvn", "UpdateChainParameters : updating dynamic block chain parameters\n");

    if (!pblock->HasChainParameters()) {
        LogPrintf("UpdateChainParameters : ERROR, block is not of type 'chain parameter'\n");
        return;
    }

    CheckDynamicChainParameters(pblock->dynamicChainParams);

    dynParams.nBlockSpacing              = pblock->dynamicChainParams.nBlockSpacing;
    dynParams.nDustThreshold             = pblock->dynamicChainParams.nDustThreshold;
    dynParams.nMaxCvnSigners             = pblock->dynamicChainParams.nMaxCvnSigners;
    dynParams.nMinCvnSigners             = pblock->dynamicChainParams.nMinCvnSigners;
    dynParams.nMinSuccessiveSignatures   = pblock->dynamicChainParams.nMinSuccessiveSignatures;
}

bool CheckProofOfCooperation(const CBlockHeader& block, const Consensus::Params& params)
{
    uint256 hashBlock = block.GetHash();

    if (!block.vSignatures.size())
        return error("block %s has no signatures", hashBlock.ToString());

    BOOST_FOREACH(CCvnSignature signature, block.vSignatures) {
        if (!CvnValidateSignature(signature, block.hashPrevBlock, block.nCreatorId))
            return error("signature is invalid: %s", signature.ToString());
    }

    if (!mapBlockIndex.count(block.hashPrevBlock))
        return error("block hash no hashPrevBlock: %s", block.GetHash().ToString());

    uint32_t nBlockCreator = (hashBlock == params.hashGenesisBlock) ?
            block.nCreatorId :
            CheckNextBlockCreator(mapBlockIndex[block.hashPrevBlock], block.nTime);

    if (!nBlockCreator)
        return error("FATAL: can not determine block creator for %s", hashBlock.ToString());

    if (nBlockCreator != block.nCreatorId)
        return error("block %s can not be created by %u but by %u", hashBlock.ToString(), block.nCreatorId);

    LogPrint("cvn", "CheckProofOfCooperation : checked %u signatures of block %d %s by 0x%08x\n",
            block.vSignatures.size(), block.nHeight, hashBlock.ToString(), block.nCreatorId);

    return true;
}

bool CheckForDuplicateCvns(const CBlock& block)
{
    std::set<uint32_t> sNodeIds;

    BOOST_FOREACH(const CCvnInfo &cvn, block.vCvns)
    {
        if (!sNodeIds.insert(cvn.nNodeId).second)
            return error("detected duplicate CVN Id: 0x%08x", cvn.nNodeId);
    };

    return true;
}

#ifdef USE_OPENSC
void static InitSmartCard()
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

    CK_ULONG nPubKeySize;
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
#endif //USE_OPENSC

void static CCVNSignerThread(const CChainParams& chainparams, const uint32_t& nNodeId)
{
    LogPrintf("CVN signer thread started for node ID 0x%08x\n", nNodeId);
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("CVN-signer");

#ifdef USE_OPENSC
    if (GetBoolArg("-usesmartcard", false))
        InitSmartCard();
    else
        fSmartCardUnlocked = true;
#else
    fSmartCardUnlocked = true;
#endif

    try {
        /* Get
         *
         */
        while (true) {
            MilliSleep(2000000000);

            int64_t adjustedTime = GetAdjustedTime();
            int64_t lastBlockTime = pindexBestHeader->GetBlockTime();

//            if ((int64_t)(lastBlockTime + chainparams.BlockSpacing() - 10) > adjustedTime)
//                continue;

            LogPrintf("CVN signer assuming Phase 2\n");

            // find the node with the highest time weight
            CBlockIndex *pBlockIndex = chainActive.Tip();
            int nBlockCount = 1;
            unsigned int nCreatorId = pBlockIndex->nCreatorId;

            do
            {
                pBlockIndex = pBlockIndex->pprev;
                if (pBlockIndex != NULL)
                    LogPrintf("test: %u 0x%08x\n", pBlockIndex->nHeight, pBlockIndex->nCreatorId);
            }
            while (pBlockIndex != NULL);
        }
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("CVN signer thread terminated\n");
        throw;
    }
    catch (const std::runtime_error &e)
    {
        LogPrintf("CCVNSignerThread runtime error: %s\n", e.what());
        return;
    }
}

void RunCVNSignerThread(const CChainParams& chainparams, const uint32_t& nNodeId)
{
    static boost::thread_group* signerThreads = NULL;

    if (signerThreads != NULL)
    {
        signerThreads->interrupt_all();
        delete signerThreads;
        signerThreads = NULL;

        return;
    }

    signerThreads = new boost::thread_group();
    signerThreads->create_thread(boost::bind(&CCVNSignerThread, boost::cref(chainparams), boost::cref(nNodeId)));
}
