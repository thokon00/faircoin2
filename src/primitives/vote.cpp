// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/vote.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"

#include <stdio.h>

uint256 CCVNVote::GetHash() const
{
    return SerializeHash(*this);
}

std::string CSignedCVNVote::GetHex() const
{
    int size = vSignature.size();

	char psz[size * 2 + 1];
    for (unsigned int i = 0; i < size; i++)
        sprintf(psz + i * 2, "%02x", vSignature[size - i - 1]);
    return std::string(psz, psz + size * 2);
}

std::string CSignedCVNVote::ToString() const
{
    std::stringstream s;
    s << strprintf("CSignedCVNVote(signerNodeId=%u, creatorNodeId=%u, nHeight=%u, signature=%s)\n",
        nSignerNodeId,
        nCreatorNodeId,
        nHeight, GetHex());
    return s.str();
}
