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
    uint256 unsignedHash = block.GetUnsignedHash();

    LogPrint("cvn", "CheckProofOfCooperation : checking signatures\n");
    uint32_t i = 0;
    BOOST_FOREACH(CBlockSignature signature, block.vSignatures) {
        if (!block.vSignatures[i++].IsValid(Params(), unsignedHash, block.HasCvnInfo()))
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
