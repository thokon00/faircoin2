// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/vote.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"

std::string CCVNVote::ToString() const
{
    std::stringstream s;
    s << strprintf("CCVNVotes(signerNodeId=%u, creatorNodeId=%u, nHeight=%u)\n",
        nSignerNodeId,
        nCreatorNodeId,
        nHeight);
    return s.str();
}

uint256 CCVNVote::GetHash() const
{
    return SerializeHash(*this);
}
