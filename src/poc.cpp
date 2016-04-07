// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.h"
#include "poc.h"
#include "main.h"
#include "timedata.h"
#include "utilstrencodings.h"

#include <boost/thread.hpp>
#include <stdio.h>

bool CheckProofOfCooperation(const CBlockHeader& block, const Consensus::Params&)
{
    LogPrintf("CheckProofOfCooperation : impelement checks\n");

//    BOOST_FOREACH(CCVNVote vote, block.vVotes) {
//    	if (vote.nCreatorId != block.nCreatorId)
//    		return error("%s: vote creator id %u does not match block id %u (%s)", __func__, vote.nCreatorId, block.nCreatorId, block.GetHash().ToString());

        //TODO: use prevHash instead of nHeight
//    	if (vote.nHeight != (uint32_t)pindexBestHeader->nHeight)
//    		return error("%s: vote height %u does not match best height %u (%s)", __func__, vote.nHeight, pindexBestHeader->nHeight, block.GetHash().ToString());
//    }

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
            MilliSleep(2000);

            int64_t adjustedTime = GetAdjustedTime();
            int64_t lastBlockTime = pindexBestHeader->GetBlockTime();

            if ((int64_t)(lastBlockTime + chainparams.BlockSpacing() - 10) > adjustedTime)
                continue;

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
