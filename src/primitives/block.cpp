// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdio.h>

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"

uint256 CUnsignedBlockHeader::GetUnsignedHash() const
{
    return SerializeHash(*this);
}

uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

std::string CBlockSignature::GetSignatureHex() const
{
    size_t size = vSignature.size();

    char psz[size * 2 + 1];
    for (unsigned int i = 0; i < size; i++)
        sprintf(psz + i * 2, "%02x", vSignature[size - i - 1]);
    return std::string(psz, psz + size * 2);
}

std::string CBlockSignature::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlockSignature(signerId=%u, ver=%d, sig=%s)",
        nSignerId,
        nVersion,
        GetSignatureHex());
    return s.str();
}


std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s(%u), ver=%d, hashPrevBlock=%s, unsignedHash=%s, hashMerkleRoot=%s, nTime=%u, nCreatorId=%u, signatures=%u, vtx=%u)\n",
        GetHash().ToString(), nHeight,
        nVersion,
        hashPrevBlock.ToString(),
        GetUnsignedHash().ToString(),
        hashMerkleRoot.ToString(),
        nTime, nCreatorId, vSignatures.size(),
        vtx.size());
    for (unsigned int i = 0; i < vSignatures.size(); i++)
    {
        s << "  " << vSignatures[i].ToString() << "\n";
    }
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i].ToString() << "\n";
    }
    return s.str();
}
