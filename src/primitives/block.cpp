// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdio.h>

#include "primitives/block.h"

#include "hash.h"
#include "util.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"
#include "pubkey.h"
#include "consensus/params.h"


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

uint256 CBlock::HashChainAdmins() const
{
    return SerializeHash(this->vChainAdmins);
}

uint256 CDynamicChainParams::GetHash() const
{
    return SerializeHash(*this);
}

std::string CDynamicChainParams::ToString() const
{
	std::stringstream s;
	    s << strprintf("CDynamicChainParams(ver=%d, minCvnSigners=%u, maxCvnSigners=%u, blockSpacing=%u, blockSpacingGracePeriod=%u, dustThreshold=%u, minSuccessiveSignatures=%u)",
	        nVersion,
			nMinCvnSigners, nMaxCvnSigners,
			nBlockSpacing, nBlockSpacingGracePeriod,
			nDustThreshold,
			nMinSuccessiveSignatures
		);
	return s.str();
}

uint256 CCvnSignatureMsg::GetHash() const
{
    return SerializeHash(*this);
}

std::string CCvnSignature::ToString() const
{
    std::stringstream s;
    s << strprintf("CCvnSignature(signerId=%u, ver=%d, sig=%s)",
        nSignerId,
        nVersion,
        HexStr(vSignature)); //TODO: limit again .substr(0, 30));
    return s.str();
}

std::string CCvnInfo::ToString() const
{
    std::stringstream s;
    s << strprintf("CCvnInfo(nodeId=%u, heightAdded=%u, pubkey=%s)",
        nNodeId, nHeightAdded,
        HexStr(vPubKey));
    return s.str();
}

std::string CChainAdmin::ToString() const
{
    std::stringstream s;
    s << strprintf("CChainAdmin(adminId=%u, pubkey=%s)",
        nAdminId,
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
    if (HasChainAdmins())
        payload << strprintf("%sadmins", (payload.tellp() > 0) ? "," : "");

    s << strprintf("CBlock(hash=%s, ver=%d, payload=%s, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nCreatorId=%u, signatures=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion & 0xff, payload.str(),
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nCreatorId, vSignatures.size(),
        vtx.size());
    s << "  CreatorSignature: " << HexStr(vCreatorSignature) << "\n";

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
        s << dynamicChainParams.ToString() << "\n";
    }
    if (HasChainAdmins())
    {
        for (unsigned int i = 0; i < vChainAdmins.size(); i++)
        {
            s << "  " << vChainAdmins[i].ToString() << "\n";
        }
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
