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

#ifdef USE_OPENSC
#include "smartcard.h"
#endif

#include <boost/thread.hpp>
#include <stdio.h>
#include <set>

uint32_t nCvnNodeId = 0;

CCriticalSection cs_mapChainAdmins;
ChainAdminMapType mapChainAdmins;

CCriticalSection cs_mapCVNs;
CvnMapType mapCVNs;

CCriticalSection cs_mapCvnSigs;
CvnSigMapType mapCvnSigs;

CCriticalSection cs_mapChainData;
ChainDataMapType mapChainData;

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

#if POC_DEBUG
    LogPrintf("CvnSignWithKey : OK\n  Hash: %s\n  node: 0x%08x\n  pubk: %s\n   sig: %s\n",
            hashUnsignedBlock.ToString(), signature.nSignerId,
            HexStr(cvnInfo.vPubKey),
            HexStr(signature.vSignature));
#endif
    return true;
}

static bool CvnSignRaw(const uint256& hashToSign, CCvnSignature& signature, const uint32_t& nNodeId)
{
    if (!nNodeId) {
        LogPrintf("CvnSign : CVN node not initialized\n");
        return false;
    }

    if (!mapCVNs.count(nNodeId)) {
        LogPrintf("CvnSign : could not find CvnInfo for signer ID 0x%08x\n", nNodeId);
        return false;
    }

    signature.nSignerId = nNodeId;
    CCvnInfo cvnInfo = mapCVNs[nNodeId];

    if (GetBoolArg("-usesmartcard", false)) {
#ifdef USE_OPENSC
        if (!fSmartCardUnlocked) {
            LogPrint("cvn", "SignBlock : ERROR, smart card not unlocked. Make sure that -cvnpin, -cvnslot and -cvnkeyid are set correctly\n");
            return false;
        }
        return CvnSignWithSmartCard(hashToSign, signature, cvnInfo);
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

        return CvnSignWithKey(hashToSign, strCvnPrivKey, signature, cvnInfo);
    }

    return false;
}

bool CvnSign(const uint256& hashBlock, CCvnSignature& signature, const uint32_t& nNextCreator, const uint32_t& nNodeId)
{
    CHashWriter hasher(SER_GETHASH, 0);
    hasher << hashBlock << nNextCreator << nNodeId;

    return CvnSignRaw(hasher.GetHash(), signature, nNodeId);
}

bool CvnSignBlock(CBlock& block)
{
    CCvnSignature signature;
    if (!CvnSignRaw(block.GetHash(), signature, block.nCreatorId)) {
        return false;
    }

    block.vCreatorSignature = signature.vSignature;
    return true;
}

bool CvnVerifySignature(const uint256 &hash, const CCvnSignature &sig)
{
    if (!mapCVNs.count(sig.nSignerId)) {
        LogPrintf("ERROR: could not find CvnInfo for signer ID 0x%08x\n", sig.nSignerId);
        return false;
    }

    CPubKey pubKey = CPubKey(mapCVNs[sig.nSignerId].vPubKey);

    bool ret = pubKey.Verify(hash, sig.vSignature);

    if (!ret)
        LogPrintf("could not verify sig %s for hash %s for node Id 0x%08x\n", HexStr(sig.vSignature), hash.ToString(), sig.nSignerId);

    return ret;
}

bool CvnVerifyAdminSignature(const uint256 &hash, const CCvnSignature &sig)
{
    if (!mapChainAdmins.count(sig.nSignerId)) {
        LogPrintf("ERROR: could not find CvnInfo for signer ID 0x%08x\n", sig.nSignerId);
        return false;
    }

    CPubKey pubKey = CPubKey(mapChainAdmins[sig.nSignerId].vPubKey);

    if (!pubKey.IsFullyValid()) {
        LogPrintf("FATAL: invalid key found for admin Id 0x%08x\n", HexStr(mapChainAdmins[sig.nSignerId].vPubKey), hash.ToString(), sig.nSignerId);
        return false;
    }

    bool ret = pubKey.Verify(hash, sig.vSignature);

    if (!ret)
        LogPrintf("could not verify admin sig %s for hash %s for admin Id 0x%08x\n", HexStr(sig.vSignature), hash.ToString(), sig.nSignerId);

    return ret;
}

void RelayChainData(const CChainDataMsg& msg)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << msg;

    CInv inv(MSG_POC_CHAIN_DATA, msg.GetHash());
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
        if(!pnode->fRelayTxes) // same TX rules apply to chain data messages
            continue;
        pnode->PushInventory(inv);
    }
}

bool CheckAdminSignatures(const uint256 hashAdminData, const vector<CCvnSignature> vAdminSignatures)
{
    // first check the admin sigs
    BOOST_FOREACH(const CCvnSignature& sig, vAdminSignatures) {
        if (!CvnVerifyAdminSignature(hashAdminData, sig)) {
            LogPrintf("ERROR: could not verify admin signature ID 0x%08x\n", sig.nSignerId);
            return false;
        }
    }

    return true;
}

bool AddChainData(const CChainDataMsg& msg)
{
    if (!CheckAdminSignatures(msg.GetHash(), msg.vAdminSignatures))
        return false;

    uint256 hashBlock = msg.hashPrevBlock;

    LOCK(cs_mapChainData);
    if (mapChainData.count(hashBlock)) {
        LogPrintf("received duplicate chain data for block %s: %s\n", hashBlock.ToString(), msg.ToString());
        return false;
    }

    mapChainData.insert(std::make_pair(hashBlock, msg));

    LogPrintf("AddChainData : signed by %u (minimum %u) admins of %u to be added after blockHash %s\n",
            msg.vAdminSignatures.size(), dynParams.nMinCvnSigners, dynParams.nMaxCvnSigners, hashBlock.ToString());

    return true;
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

    CCvnSignature signature;
    if (!CvnSign(pindexNew->GetBlockHash(), signature, nNextCreator, nCvnNodeId)) {
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

void PrintAllChainAdmins()
{
    BOOST_FOREACH(const ChainAdminMapType::value_type& adm, mapChainAdmins) {
        LogPrintf("%s\n", adm.second.ToString());
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

void UpdateChainAdmins(const CBlock* pblock)
{
    LogPrint("cvn", "UpdateChainAdmins : updating chain admins\n");

    if (!pblock->HasChainAdmins()) {
        LogPrintf("UpdateChainAdmins : ERROR, block has no CHAIN_ADMINS_PAYLOAD\n");
        return;
    }

    LOCK(cs_mapChainAdmins);

    mapChainAdmins.clear();

    BOOST_FOREACH(CChainAdmin admin, pblock->vChainAdmins) {
        mapChainAdmins.insert(std::make_pair(admin.nAdminId, admin));
    }

    //PrintAllChainAdmins();
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
    dynParams.nBlockSpacingGracePeriod   = pblock->dynamicChainParams.nBlockSpacingGracePeriod;
    dynParams.nDustThreshold             = pblock->dynamicChainParams.nDustThreshold;
    dynParams.nMaxCvnSigners             = pblock->dynamicChainParams.nMaxCvnSigners;
    dynParams.nMinCvnSigners             = pblock->dynamicChainParams.nMinCvnSigners;
    dynParams.nMinSuccessiveSignatures   = pblock->dynamicChainParams.nMinSuccessiveSignatures;
}

bool CheckProofOfCooperation(const CBlockHeader& block, const Consensus::Params& params)
{
    uint256 hashBlock = block.GetHash();

    // check block signatures from the CVNs
    if (!block.vSignatures.size())
        return error("block %s has no signatures", hashBlock.ToString());

    BOOST_FOREACH(CCvnSignature signature, block.vSignatures) {
        if (!CvnValidateSignature(signature, block.hashPrevBlock, block.nCreatorId))
            return error("signature is invalid: %s", signature.ToString());
    }

    // check if creator ID matches consensus rules
    if (!mapBlockIndex.count(block.hashPrevBlock) && hashBlock != params.hashGenesisBlock)
        return error("block has no hashPrevBlock: %s", block.GetHash().ToString());

    uint32_t nBlockCreator = (hashBlock == params.hashGenesisBlock) ?
            block.nCreatorId :
            CheckNextBlockCreator(mapBlockIndex[block.hashPrevBlock], block.nTime);

    if (!nBlockCreator)
        return error("FATAL: can not determine block creator for %s", hashBlock.ToString());

    if (nBlockCreator != block.nCreatorId)
        return error("block %s can not be created by %u but by %u", hashBlock.ToString(), block.nCreatorId);

    LogPrint("cvn", "CheckProofOfCooperation : checked %u signatures of block %s created by 0x%08x\n",
            block.vSignatures.size(), hashBlock.ToString(), block.nCreatorId);

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

bool CheckForDuplicateChainAdmins(const CBlock& block)
{
    std::set<uint32_t> sNodeIds;

    BOOST_FOREACH(const CChainAdmin &adm, block.vChainAdmins)
    {
        if (!sNodeIds.insert(adm.nAdminId).second)
            return error("detected duplicate chain admin Id: 0x%08x", adm.nAdminId);
    };

    return true;
}

static uint32_t FindNewlyAddedCVN()
{
    return 0;
}

static uint32_t FindCandidateOffset(const uint64_t nPrevBlockTime, const int64_t nTimeToTest)
{
    int nOverdue = nTimeToTest - nPrevBlockTime - dynParams.nBlockSpacing;

    if (nOverdue < (int)dynParams.nBlockSpacingGracePeriod)
        return 0;

    return nOverdue / dynParams.nBlockSpacingGracePeriod;
}

typedef boost::unordered_set<uint32_t> TimeWeightSetType;
typedef std::vector<uint32_t>::reverse_iterator CandidateIterator;

static void AddToSigSets(std::vector<TimeWeightSetType>& vLastSignatures, const std::vector<CCvnSignature>& vSignatures)
{
    TimeWeightSetType signers;

    BOOST_FOREACH(const CCvnSignature& sig, vSignatures) {
        signers.insert(sig.nSignerId);
    }

    vLastSignatures.push_back(signers);
}

static bool HasSignedLastBlocks(const std::vector<TimeWeightSetType>& vLastSignatures, const uint32_t& nCreatorCandidate, const uint32_t& nMinSuccessiveSignatures)
{
    uint32_t nSignatures = 0;

    BOOST_FOREACH(const TimeWeightSetType& signers, vLastSignatures) {
        if (signers.count(nCreatorCandidate)) {
            nSignatures++;
        } else {
            if (nSignatures < nMinSuccessiveSignatures)
                return false;
        }
    }

    return (nSignatures >= nMinSuccessiveSignatures);
}

#if 0
static const string CreateSignerIdList(const std::vector<CCvnSignature>& vSignatures)
{
    std::stringstream s;

    BOOST_FOREACH(const CCvnSignature& sig, vSignatures) {
        s << strprintf("%s%08x", (s.tellp() > 0) ? "," : "", sig.nSignerId);
    }

    return s.str();
}
#endif

/**
 * The rules are as follows:
 * 1. If there is any newly added CVN it is its turn
 * 1. Find the node with the highest time-weight. That's the
 *    node that created its last block the furthest in the past.
 * 2. It must have co-signed the last nCreatorMinSignatures blocks
 *    to proof it's cooperation.
 */
uint32_t CheckNextBlockCreator(const CBlockIndex* pindexStart, const int64_t nTimeToTest)
{
    uint32_t nNextCreatorId = FindNewlyAddedCVN();

    if (nNextCreatorId)
        return nNextCreatorId;

    TimeWeightSetType sCheckedNodes;
    sCheckedNodes.reserve(mapCVNs.size());
    std::vector<uint32_t> vCreatorCandidates;
    std::vector<TimeWeightSetType> vLastSignatures;
    uint32_t nMinSuccessiveSignatures = dynParams.nMinSuccessiveSignatures;

    // first create a list of creator candidates
    for (const CBlockIndex* pindex = pindexStart; pindex; pindex = pindex->pprev) {
        if (!(pindex->nVersion & CBlock::TX_PAYLOAD)) // we only consider blocks with transactions
            continue;

        if (sCheckedNodes.insert(pindex->nCreatorId).second)
            vCreatorCandidates.push_back(pindex->nCreatorId);

        if (nMinSuccessiveSignatures) {
            nMinSuccessiveSignatures--;
            AddToSigSets(vLastSignatures, pindex->vSignatures);
        }
    }
    nMinSuccessiveSignatures = dynParams.nMinSuccessiveSignatures; // reset

    // the last in the list has the highest time-weight
    CandidateIterator itCandidates = vCreatorCandidates.rbegin();

    if (!vCreatorCandidates.size()) {
        LogPrintf("CheckNextBlockCreator : ERROR, could not find any creator node candidates\n");
        return 0;
    }

    uint32_t nCandidateOffset = FindCandidateOffset(pindexStart->nTime, nTimeToTest);
    if (nCandidateOffset > vCreatorCandidates.size()) {
        LogPrintf("CheckNextBlockCreator : WARN, CandidateOffset exceeds limits: %u > %u\n", nCandidateOffset, vCreatorCandidates.size());
        nCandidateOffset = vCreatorCandidates.size() - 1;
    }

    do {
        uint32_t nCreatorCandidate = *(itCandidates += nCandidateOffset);

        // check if the candidate signed the last nMinSuccessiveSignatures blocks
        if (HasSignedLastBlocks(vLastSignatures, nCreatorCandidate, nMinSuccessiveSignatures)) {
            nNextCreatorId = nCreatorCandidate;
            break;
        }

        // if we did not find a candidate who signed enough successive blocks we lower
        // our requirement to avoid the block chain become stalled
        if (itCandidates == vCreatorCandidates.rend()) {
            nMinSuccessiveSignatures--;
            LogPrintf("CheckNextBlockCreator: WARNING, could not find a CVN that signed enough successive blocks. Lowering number of required sigs to %u\n", nMinSuccessiveSignatures);
        }
    } while(nMinSuccessiveSignatures);

    if (nNextCreatorId)
        LogPrintf("NODE ID 0x%08x should create the next block #%u\n", nNextCreatorId, pindexStart->nHeight + 1);
    else
        LogPrintf("ERROR, could not find any Node ID that should create the next block #%u\n", pindexStart->nHeight + 1);

    return nNextCreatorId;
}

void static CCVNSignerThread(const CChainParams& chainparams, const uint32_t& nNodeId)
{
    LogPrintf("CVN signer thread started for node ID 0x%08x\n", nNodeId);
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("CVN-signer");

    try {
        /* Get
         *
         */
        while (true) {
            MilliSleep(2000000000);

//            int64_t adjustedTime = GetAdjustedTime();
//            int64_t lastBlockTime = pindexBestHeader->GetBlockTime();

//            if ((int64_t)(lastBlockTime + chainparams.BlockSpacing() - 10) > adjustedTime)
//                continue;

            LogPrintf("CVN signer assuming Phase 2\n");

            // find the node with the highest time weight
            CBlockIndex *pBlockIndex = chainActive.Tip();
            //int nBlockCount = 1;
            //uint32_t nCreatorId = pBlockIndex->nCreatorId;

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
