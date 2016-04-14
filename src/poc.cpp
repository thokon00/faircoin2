// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.h"
#include "poc.h"
#include "main.h"
#include "timedata.h"
#include "utilstrencodings.h"
#include "base58.h"

#include <boost/thread.hpp>
#include <stdio.h>

#ifdef USE_OPENSC
#include "pkcs11/pkcs11.h"

extern "C" CK_RV C_UnloadModule(void *module);
extern "C" void *C_LoadModule(const char *mspec, CK_FUNCTION_LIST_PTR_PTR funcs);
static void *module = NULL;
static CK_FUNCTION_LIST_PTR p11 = NULL;

#if defined(WIN32)
static std::string defaultPkcs11ModulePath = "";
#elif defined(MAC_OSX)
static std::string defaultPkcs11ModulePath = "";
#else
static std::string defaultPkcs11ModulePath = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so";
#endif

bool fSmartCardUnlocked = false;

bool SignBlockWithSmartCard(const uint256& hashUnsignedBlock, const Consensus::Params& params, CBlockSignature& signature)
{
    throw "TBI";
}

#endif // USE_OPENSC

CCriticalSection cs_mapCVNs;
uint32_t nCvnNodeId = 0;

bool SignBlockWithKey(const uint256& hashUnsignedBlock, const Consensus::Params& params, const std::string strCvnPrivKey, CBlockSignature& signature)
{
    CBitcoinSecret secret;
    secret.SetString(strCvnPrivKey);
    CKey key = secret.GetKey();

    if (!key.Sign(hashUnsignedBlock, signature.vSignature)) {
        LogPrint("cvn", "SignBlockWithKey : could not create block signature\n");
        return false;
    }

    if (!signature.IsValid(params, hashUnsignedBlock, nCvnNodeId)) {
        LogPrint("cvn", "SignBlockWithKey : created invalid signature\n");
        return false;
    }

    LogPrintf("SignBlockWithKey : OK\n  Hash: %s\n  node: 0x%08x\n  pubk: %s\n   sig: %s\n",
            hashUnsignedBlock.ToString(), nCvnNodeId,
            HexStr(params.mapCVNs.find(nCvnNodeId)->second.vPubKey),
            HexStr(signature.vSignature));

    return true;
}

bool SignBlock(const uint256& hashUnsignedBlock, const Consensus::Params& params, CBlockSignature& signature)
{
    if (!nCvnNodeId) {
        LogPrint("cvn", "SignBlock : CVN node not initialized\n");
        return false;
    }

    signature.nSignerId = nCvnNodeId;

    if (GetBoolArg("-usesmartcard", false)) {
#ifdef USE_OPENSC
        return SignBlockWithSmartCard(hashUnsignedBlock, params, signature);
#else
        LogPrintf("SignBlock : ERROR, this wallet was not compile with smart card support\n");
        return false;
#endif
    } else {
        std::string strCvnPrivKey = GetArg("-cvnprivkey", "");

        if (strCvnPrivKey.size() != 51) {
            LogPrint("cvn", "SignBlock : ERROR, invalid private key supplied or -cvnprivkey is missing\n");
            return false;
        }

        return SignBlockWithKey(hashUnsignedBlock, params, strCvnPrivKey, signature);
    }

    return false;
}

void UpdateCvnInfo(const CBlock* pblock)
{
    if (!pblock->HasCvnInfo()) {
        LogPrint("cvn", "UpdateCvnInfo : ERROR, block is not of type CVN\n");
        return;
    }

    LOCK(cs_mapCVNs);

    std::map<uint32_t, CCvnInfo> mapCVNs = Params().GetConsensus().mapCVNs;
    mapCVNs.clear();

    BOOST_FOREACH(CCvnInfo cvnInfo, pblock->vCvns) {
        mapCVNs.insert(std::make_pair(cvnInfo.nNodeId, cvnInfo));
    }
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
    if (!pblock->HasChainParameters()) {
        LogPrintf("UpdateChainParameters : ERROR, block is not of type 'chain parameter'\n");
        return;
    }

    CheckDynamicChainParameters(pblock->dynamicChainParams);

    dynParams.nBlockSpacing = pblock->dynamicChainParams.nBlockSpacing;
    dynParams.nDustThreshold = pblock->dynamicChainParams.nDustThreshold;
    dynParams.nMaxCvnSigners = pblock->dynamicChainParams.nMaxCvnSigners;
    dynParams.nMinCvnSigners = pblock->dynamicChainParams.nBlockSpacing;
}

bool CheckProofOfCooperation(const CBlockHeader& block, const Consensus::Params& params)
{
    uint256 unsignedHash = block.GetUnsignedHash();

    LogPrint("cvn", "CheckProofOfCooperation : checking signatures\n");

    uint32_t i = 0;
    BOOST_FOREACH(CBlockSignature signature, block.vSignatures) {
        if (!block.vSignatures[i++].IsValid(params, unsignedHash, nCvnNodeId))
            return error("signature %u : %s is invalid\n", i, HexStr(block.vSignatures[i - 1].vSignature));
    }

    return true;
}

void static CCVNSignerThread(const CChainParams& chainparams)
{
    LogPrintf("CVN signer thread started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("CVN-signer");

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

void RunCVNSignerThread(const CChainParams& chainparams)
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
    signerThreads->create_thread(boost::bind(&CCVNSignerThread, boost::cref(chainparams)));
}
