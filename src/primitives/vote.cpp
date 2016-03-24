// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/vote.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"

#include <stdio.h>

uint256 CUnsignedCVNVote::GetHash() const
{
    return SerializeHash(*this);
}

std::string CCVNVote::GetSignatureHex() const
{
    size_t size = vSignature.size();

	char psz[size * 2 + 1];
    for (unsigned int i = 0; i < size; i++)
        sprintf(psz + i * 2, "%02x", vSignature[size - i - 1]);
    return std::string(psz, psz + size * 2);
}

std::string CCVNVote::ToString() const
{
    std::stringstream s;
    s << strprintf("CCVNVote(signerId=%u, creatorId=%u, nHeight=%u, sig=%s)",
        nSignerId,
        nCreatorId,
        nHeight, GetSignatureHex());
    return s.str();
}
