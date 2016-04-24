// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"

#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "hash.h"
#include "main.h"
#include "net.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validationinterface.h"
#include "key.h"
#include "keystore.h"
#include "init.h"
#include "wallet/wallet.h"
#include "base58.h"
#include "poc.h"

#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>
#include <queue>
#include <map>

using namespace std;

//////////////////////////////////////////////////////////////////////////////
//
// CertifiedValidationNode
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;

class ScoreCompare
{
public:
    ScoreCompare() {}

    bool operator()(const CTxMemPool::txiter a, const CTxMemPool::txiter b)
    {
        return CompareTxMemPoolEntryByScore()(*b,*a); // Convert to less than
    }
};

static CBlockTemplate* CreateNewBlock(const CChainParams& chainparams, const CScript& scriptPubKeyIn)
{
    // Create new block
    auto_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if(!pblocktemplate.get())
        return NULL;
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = GetArg("-blockversion", pblock->nVersion);

    // Set block type TX_BLOCK
    pblock->nVersion |= CBlock::TX_BLOCK;

    // Create coinbase tx
    CMutableTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    txNew.vout[0].scriptPubKey = scriptPubKeyIn;

    // Add dummy coinbase tx as first transaction
    pblock->vtx.push_back(CTransaction());
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
    // Limit to between 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", DEFAULT_BLOCK_MIN_SIZE);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Collect memory pool transactions into the block
    CTxMemPool::setEntries inBlock;
    CTxMemPool::setEntries waitSet;

    // This vector will be sorted into a priority queue:
    vector<TxCoinAgePriority> vecPriority;
    TxCoinAgePriorityCompare pricomparer;
    std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash> waitPriMap;
    typedef std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash>::iterator waitPriIter;
    double actualPriority = -1;

    std::priority_queue<CTxMemPool::txiter, std::vector<CTxMemPool::txiter>, ScoreCompare> clearedTxs;
    bool fPrintPriority = GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    uint64_t nBlockSize = 1000;
    uint64_t nBlockTx = 0;
    unsigned int nBlockSigOps = 100;
    int lastFewTxs = 0;
    CAmount nFees = 0;

    {
        LOCK2(cs_main, mempool.cs);
        CBlockIndex* pindexPrev = chainActive.Tip();
        const int nHeight = pindexPrev->nHeight + 1;
        pblock->nTime = GetAdjustedTime();
        const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

        int64_t nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                                ? nMedianTimePast
                                : pblock->GetBlockTime();

        bool fPriorityBlock = nBlockPrioritySize > 0;
        if (fPriorityBlock) {
            vecPriority.reserve(mempool.mapTx.size());
            for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
                 mi != mempool.mapTx.end(); ++mi)
            {
                double dPriority = mi->GetPriority(nHeight);
                CAmount dummy;
                mempool.ApplyDeltas(mi->GetTx().GetHash(), dPriority, dummy);
                vecPriority.push_back(TxCoinAgePriority(dPriority, mi));
            }
            std::make_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
        }

        CTxMemPool::indexed_transaction_set::nth_index<3>::type::iterator mi = mempool.mapTx.get<3>().begin();
        CTxMemPool::txiter iter;

        while (mi != mempool.mapTx.get<3>().end() || !clearedTxs.empty())
        {
            bool priorityTx = false;
            if (fPriorityBlock && !vecPriority.empty()) { // add a tx from priority queue to fill the blockprioritysize
                priorityTx = true;
                iter = vecPriority.front().second;
                actualPriority = vecPriority.front().first;
                std::pop_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                vecPriority.pop_back();
            }
            else if (clearedTxs.empty()) { // add tx with next highest score
                iter = mempool.mapTx.project<0>(mi);
                mi++;
            }
            else {  // try to add a previously postponed child tx
                iter = clearedTxs.top();
                clearedTxs.pop();
            }

            if (inBlock.count(iter))
                continue; // could have been added to the priorityBlock

            const CTransaction& tx = iter->GetTx();

            bool fOrphan = false;
            BOOST_FOREACH(CTxMemPool::txiter parent, mempool.GetMemPoolParents(iter))
            {
                if (!inBlock.count(parent)) {
                    fOrphan = true;
                    break;
                }
            }
            if (fOrphan) {
                if (priorityTx)
                    waitPriMap.insert(std::make_pair(iter,actualPriority));
                else
                    waitSet.insert(iter);
                continue;
            }

            unsigned int nTxSize = iter->GetTxSize();
            if (fPriorityBlock &&
                (nBlockSize + nTxSize >= nBlockPrioritySize || !AllowFree(actualPriority))) {
                fPriorityBlock = false;
                waitPriMap.clear();
            }
            if (!priorityTx &&
                (iter->GetModifiedFee() < ::minRelayTxFee.GetFee(nTxSize) && nBlockSize >= nBlockMinSize)) {
                break;
            }
            if (nBlockSize + nTxSize >= nBlockMaxSize) {
                if (nBlockSize >  nBlockMaxSize - 100 || lastFewTxs > 50) {
                    break;
                }
                // Once we're within 1000 bytes of a full block, only look at 50 more txs
                // to try to fill the remaining space.
                if (nBlockSize > nBlockMaxSize - 1000) {
                    lastFewTxs++;
                }
                continue;
            }

            if (!IsFinalTx(tx, nHeight, nLockTimeCutoff))
                continue;

            unsigned int nTxSigOps = iter->GetSigOpCount();
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS) {
                if (nBlockSigOps > MAX_BLOCK_SIGOPS - 2) {
                    break;
                }
                continue;
            }

            CAmount nTxFees = iter->GetFee();
            // Added
            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            if (fPrintPriority)
            {
                double dPriority = iter->GetPriority(nHeight);
                CAmount dummy;
                mempool.ApplyDeltas(tx.GetHash(), dPriority, dummy);
                LogPrintf("priority %.1f fee %s txid %s\n",
                          dPriority , CFeeRate(iter->GetModifiedFee(), nTxSize).ToString(), tx.GetHash().ToString());
            }

            inBlock.insert(iter);

            // Add transactions that depend on this one to the priority queue
            BOOST_FOREACH(CTxMemPool::txiter child, mempool.GetMemPoolChildren(iter))
            {
                if (fPriorityBlock) {
                    waitPriIter wpiter = waitPriMap.find(child);
                    if (wpiter != waitPriMap.end()) {
                        vecPriority.push_back(TxCoinAgePriority(wpiter->second,child));
                        std::push_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                        waitPriMap.erase(wpiter);
                    }
                }
                else {
                    if (waitSet.count(child)) {
                        clearedTxs.push(child);
                        waitSet.erase(child);
                    }
                }
            }
        }
        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;
        LogPrintf("CreateNewBlock(): total size %u txs: %u fees: %ld sigops %d\n", nBlockSize, nBlockTx, nFees, nBlockSigOps);

        // Compute final coinbase transaction.
        txNew.vout[0].nValue = nFees;
        txNew.vin[0].scriptSig = CScript() << nHeight << OP_0;
        pblock->vtx[0] = txNew;
        pblocktemplate->vTxFees[0] = -nFees;

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        pblock->nCreatorId     = nCvnNodeId;
        pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]);

        CValidationState state;
        if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
            throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
        }
    }

    return pblocktemplate.release();
}

static void UpdateCoinbase(CBlock* pblock, const CBlockIndex* pindexPrev, const uint32_t nExtraNonce)
{
    uint32_t nHeight = pindexPrev->nHeight + 1; // Height first in coinbase
    CMutableTransaction txCoinbase(pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << nExtraNonce) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = txCoinbase;
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}

static bool ProcessCVNBlock(const CBlock* pblock, const CChainParams& chainparams)
{
    LogPrintf("%s\n", pblock->ToString());
    LogPrintf("fees collected: %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue));

    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash())
            return error("CertifiedValidationNode: generated block is stale");
    }

    // Inform about the new block
    GetMainSignals().BlockFound(pblock->GetHash());

    // Process this block the same as if we had received it from another node
    CValidationState state;
    if (!ProcessNewBlock(state, chainparams, NULL, pblock, true, NULL))
        return error("CertifiedValidationNode: ProcessNewBlock, block not accepted");

    return true;
}

typedef boost::unordered_set<uint32_t> TimeWeightSetType;
typedef vector<uint32_t>::reverse_iterator CandidateIterator;

static void AddToSigSets(vector<TimeWeightSetType>& vLastSignatures, const vector<CCvnSignature>& vSignatures)
{
    TimeWeightSetType signers;

    BOOST_FOREACH(const CCvnSignature& sig, vSignatures) {
        signers.insert(sig.nSignerId);
    }

    vLastSignatures.push_back(signers);
}

static bool HasSignedLastBlocks(const vector<TimeWeightSetType>& vLastSignatures, const uint32_t& nCreatorCandidate, const uint32_t& nMinSuccessiveSignatures)
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
 * 1. Find the node with the highest time-weight. That's the
 *    node that created its last block the furthest in the past.
 * 2. It must have cosigned the last nCreatorMinSignatures blocks
 *    to proof it's cooperation.
 */
uint32_t CheckNextBlockCreator()
{
    TimeWeightSetType setCheckedNodes;
    setCheckedNodes.reserve(mapCVNs.size());
    vector<uint32_t> vCreatorCandidates;
    vector<TimeWeightSetType> vLastSignatures;
    uint32_t nMinSuccessiveSignatures = dynParams.nMinSuccessiveSignatures;

    // first create a list of creator candidates
    for (CBlockIndex* pindex = chainActive.Tip(); pindex; pindex = pindex->pprev) {
        if (!(pindex->nVersion & CBlock::TX_BLOCK)) // we only consider blocks with transactions
            continue;

#if 0
        if (nMinSuccessiveSignatures)
            LogPrintf("BLOCK #%06u was created by 0x%08x and signed by %s (%u)\n", pindex->nHeight, pindex->nCreatorId, CreateSignerIdList(pindex->vSignatures), nMinSuccessiveSignatures);
#endif
        if (setCheckedNodes.insert(pindex->nCreatorId).second)
            vCreatorCandidates.push_back(pindex->nCreatorId);

        if (nMinSuccessiveSignatures) {
            nMinSuccessiveSignatures--;
            AddToSigSets(vLastSignatures, pindex->vSignatures);
        }
    }
    nMinSuccessiveSignatures = dynParams.nMinSuccessiveSignatures; // re-initialize

    // the last in the list has the highest time-weight
    CandidateIterator itCandidates = vCreatorCandidates.rbegin();

    if (!vCreatorCandidates.size()) {
        LogPrintf("CheckNextBlockCreator : ERROR, could not find any creator node candidates\n");
        return 0;
    }

    uint32_t nNextCreatorId = 0;

    do {
        uint32_t nCreatorCandidate = *(itCandidates++);

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
        LogPrintf("NODE ID 0x%08x should create the next block #%u\n", nNextCreatorId, chainActive.Tip()->nHeight + 1);
    else
        LogPrintf("ERROR, could not find any Node ID that should create the next block #%u\n", chainActive.Tip()->nHeight + 1);

    return nNextCreatorId;
}

void static CertifiedValidationNode(const CChainParams& chainparams, const uint32_t& nNodeId)
{
    SetThreadPriority(THREAD_PRIORITY_NORMAL);
    RenameThread("certified-validation-node");
    RunCVNSignerThread(chainparams, nNodeId);
    bool fBoostrap = chainActive.Tip()->GetBlockHash() == chainparams.GetConsensus().hashGenesisBlock;

    if (fBoostrap) {
        CHashWriter hasher(SER_GETHASH, 0);
        hasher << chainparams.GetConsensus().hashGenesisBlock << 0xc001d00d << 0xc001d00d;

        CCvnSignature signature;
        if (!CvnSign(hasher.GetHash(), signature, nCvnNodeId)) {
            LogPrintf("SendCVNSignature : could not sign block\n");
            return;
        }

        AddCvnSignature(signature, chainparams.GetConsensus().hashGenesisBlock);
    }

    while (!fSmartCardUnlocked || (IsInitialBlockDownload() && !fBoostrap))
        MilliSleep(1000); // give some time to start up everything

    LogPrintf("Certified validation node started for node ID 0x%08x\n", nNodeId);

    uint32_t nExtraNonce = 0;

    boost::shared_ptr<CReserveScript> coinbaseScript;
    GetMainSignals().ScriptForMining(coinbaseScript);

    try {
        // Throw an error if no script was provided.  This can happen
        // due to some internal error but also if the keypool is empty.
        // In the latter case, already the pointer is NULL.
        if (!coinbaseScript || coinbaseScript->reserveScript.empty())
            throw std::runtime_error("No coinbase script available (PoC requires a wallet)");

        while (true) {
            if (chainparams.MiningRequiresPeers()) {
                // Busy-wait for the network to come online so we don't waste time mining
                // on an obsolete chain. In regtest mode we expect to fly solo.
                do {
                    bool fvNodesEmpty;
                    {
                        LOCK(cs_vNodes);
                        fvNodesEmpty = vNodes.empty();
                    }
                    if (!fvNodesEmpty && !IsInitialBlockDownload())
                        break;
                    MilliSleep(1000);
                } while (true);
            }

            uint32_t nWait = 5 * 2; // 5 seconds

            while (nWait--) {
                MilliSleep(500);
            }

            CvnSigEntryType sigsForHashPrev = mapCvnSigs[chainActive.Tip()->GetBlockHash()];
            if (!sigsForHashPrev.count(nCvnNodeId)) {
                LogPrintf("could not find current signature, resending...\n");
                SendCVNSignature(chainActive.Tip()->GetBlockHash());
            }

            if (CheckNextBlockCreator() != nNodeId) {
                nExtraNonce++; // create some 'randomness' for the coinbase
                continue;
            }

            // wait for block spacing
            if (chainActive.Tip()->nTime + dynParams.nBlockSpacing > GetAdjustedTime())
                continue;

            //
            // This node is potentially the next to advance the chain
            //
            CBlockIndex* pindexPrev = chainActive.Tip();

            auto_ptr<CBlockTemplate> pblocktemplate(CreateNewBlock(chainparams, coinbaseScript->reserveScript));
            if (!pblocktemplate.get())
            {
                LogPrintf("Error in CertifiedValidationNode: Keypool ran out, please call keypoolrefill before restarting the CVN thread\n");
                return;
            }
            CBlock *pblock = &pblocktemplate->block;
            UpdateCoinbase(pblock, pindexPrev, nExtraNonce);

            pblock->nCreatorId = nNodeId;
            pblock->nHeight = pindexPrev->nHeight + 1;

            uint256 hashBlock = pblock->hashPrevBlock;
            {
                LOCK(cs_mapCvnSigs);
                CvnSigEntryType sigsForHashPrev = mapCvnSigs[hashBlock];
                LogPrintf("# of sig available: %u (total: %u)\n  hash: %s\n", sigsForHashPrev.size(), mapCvnSigs.size(), hashBlock.ToString());
                BOOST_FOREACH(CvnSigEntryType::value_type& cvn, sigsForHashPrev)
                {
                    if (!CvnValidateSignature(*pblock, cvn.second))
                        LogPrintf("ERROR: could not add signature to block: %s\n", cvn.second.ToString());
                    else
                        pblock->vSignatures.push_back(cvn.second);
                }
            }

            LogPrintf("creating block with %u transactions, %u CvnInfo (%u bytes)\n", pblock->vtx.size(), pblock->vCvns.size(),
                ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

            if (ProcessCVNBlock(pblock, chainparams))
            {
                LOCK(cs_mapCvnSigs);
                mapCvnSigs.erase(hashBlock);
            } else
                LogPrintf("ERROR: block not accepted %s\n", pblock->GetHash().ToString());

            coinbaseScript->KeepScript();

            // In regression test mode, stop after a block is created.
            if (chainparams.MineBlocksOnDemand())
                throw boost::thread_interrupted();
        }
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("Certified validation node 0x%08x terminated\n", nNodeId);
        throw;
    }
    catch (const std::runtime_error &e)
    {
        LogPrintf("CertifiedValidationNode 0x%08x runtime error: %s\n", nNodeId, e.what());
        return;
    }
}

void RunCertifiedValidationNode(bool fGenerate, const CChainParams& chainparams, uint32_t& nNodeId)
{
    static boost::thread_group* minerThreads = NULL;

    if (minerThreads != NULL)
    {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = NULL;
    }

    if (!fGenerate)
        return;

    if (!nNodeId) {
        LogPrintf("Not starting CVN thread. CVN not configured.\n");
        return;
    }

    minerThreads = new boost::thread_group();
    minerThreads->create_thread(boost::bind(&CertifiedValidationNode, boost::cref(chainparams), boost::cref(nNodeId)));
}
