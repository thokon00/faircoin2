// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POC_H
#define BITCOIN_POC_H

#include "consensus/params.h"
#include "primitives/block.h"
#include "chainparams.h"
#include "sync.h"

#include <stdint.h>

#define MAX_BLOCK_SPACING 600
#define MIN_BLOCK_SPACING 30
#define MAX_DUST_THRESHOLD 1 * COIN
#define MIN_DUST_THRESHOLD 1000


extern uint32_t nCvnNodeId;
extern CCriticalSection cs_mapCVNs;

bool SignBlock(const CBlockHeader& block, const Consensus::Params& params, CBlockSignature& signature);

/** Check whether a block hash satisfies the proof-of-cooperation requirements */
bool CheckProofOfCooperation(const CBlockHeader& block, const Consensus::Params&);

void UpdateCvnInfo(const CBlock* pblock);

void UpdateChainParameters(const CBlock* pblock);

bool CheckDynamicChainParameters(const CDynamicChainParams& params);

/** strart the CVN voter thread */
void RunCVNSignerThread(const CChainParams& chainparams);

#endif // BITCOIN_POC_H
