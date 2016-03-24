// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.h"
#include "poc.h"
#include "main.h"

#include <stdio.h>

bool CheckProofOfCooperation(const CBlockHeader& block, const Consensus::Params&)
{
    LogPrintf("CheckProofOfCooperation : Please implement Proof-Of-Cooperation checks\n");

    BOOST_FOREACH(CCVNVote vote, block.vVotes) {
    	if (vote.nCreatorId != block.nCreatorId)
    		return error("%s: vote creator id %u does not match block id %u (%s)", __func__, vote.nCreatorId, block.nCreatorId, block.GetHash().ToString());

        //TODO: use prevHash instead of nHeight
//    	if (vote.nHeight != (uint32_t)pindexBestHeader->nHeight)
//    		return error("%s: vote height %u does not match best height %u (%s)", __func__, vote.nHeight, pindexBestHeader->nHeight, block.GetHash().ToString());
    }

    return true;
}
