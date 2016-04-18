// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdio.h>

#include "primitives/block.h"
extern std::map<uint32_t, CCvnInfo> mapCVNs;

#include "hash.h"
#include "util.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"
#include "pubkey.h"
#include "consensus/params.h"


uint256 CUnsignedBlockHeader::GetUnsignedHash() const
{
    return SerializeHash(*this);
}

uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CCvnInfo::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CBlock::HashCVNs() const
{
    return SerializeHash(this->vCvns);
}

uint256 CDynamicChainParams::GetHash() const
{
    return SerializeHash(*this);
}

std::string CBlockSignature::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlockSignature(signerId=%u, ver=%d, sig=%s)",
        nSignerId,
        nVersion,
        HexStr(vSignature)); //TODO: limit again .substr(0, 30));
    return s.str();
}

std::string CCvnInfo::ToString() const
{
    std::stringstream s;
    s << strprintf("CCvnInfo(nodeId=%u, pubkey=%s)",
        nNodeId,
        HexStr(vPubKey));
    return s.str();
}

std::string CBlock::ToString() const
{
    std::stringstream s, payload;

    if (HasTx())
        payload << "tx";
    if (HasCvnInfo())
        payload << strprintf("%scvninfo", (payload.tellp() > 0) ? "," : "");
    if (HasChainParameters())
        payload << strprintf("%sparams", (payload.tellp() > 0) ? "," : "");

    s << strprintf("CBlock(%u)(hash=%s, ver=%d, payload=%s, hashPrevBlock=%s, unsignedHash=%s, hashMerkleRoot=%s, nTime=%u, nCreatorId=%u, signatures=%u, vtx=%u)\n",
        nHeight, GetHash().ToString(),
        nVersion & 0xff, payload.str(),
        hashPrevBlock.ToString(),
        GetUnsignedHash().ToString(),
        hashMerkleRoot.ToString(),
        nTime, nCreatorId, vSignatures.size(),
        vtx.size());
    for (unsigned int i = 0; i < vSignatures.size(); i++)
    {
        s << "  " << vSignatures[i].ToString() << "\n";
    }
    if (HasCvnInfo())
    {
        for (unsigned int i = 0; i < vCvns.size(); i++)
        {
            s << "  " << vCvns[i].ToString() << "\n";
        }
    }
    if (HasChainParameters())
    {
        s << strprintf("TBI(%u): print out dynamic chain parameter information\n", nVersion);
    }
    if (HasTx())
    {
        for (unsigned int i = 0; i < vtx.size(); i++)
        {
            s << "  " << vtx[i].ToString() << "\n";
        }
    }
    return s.str();
}
