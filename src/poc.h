// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POC_H
#define BITCOIN_POC_H

#include "consensus/params.h"
#include "primitives/block.h"

#include <stdint.h>

/** Check whether a block hash satisfies the proof-of-cooperation requirements */
bool CheckProofOfCooperation(const CBlockHeader& block, const Consensus::Params&);

#endif // BITCOIN_POC_H
