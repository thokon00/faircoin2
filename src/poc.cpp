// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.h"
#include "poc.h"

bool CheckProofOfCooperation(const CBlockHeader& block, const Consensus::Params&)
{
	LogPrintf("CheckProofOfCooperation : Please implement Proof-Of-Cooperation checks\n");
	return true;
}
