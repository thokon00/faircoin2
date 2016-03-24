// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_VOTE_H
#define BITCOIN_PRIMITIVES_VOTE_H

#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"

class CUnsignedCVNVote
{
public:
    static const int32_t CURRENT_VERSION=1;
    int32_t nVersion;
    uint32_t nSignerId;
    uint32_t nCreatorId;
    uint32_t nHeight;

    CUnsignedCVNVote()
    {
        SetNull();
    }

    CUnsignedCVNVote(const uint32_t nSignerNodeId, const uint32_t nCreatorNodeId, const uint32_t nHeight, const int32_t nVersion = CUnsignedCVNVote::CURRENT_VERSION)
    {
        this->nVersion = nVersion;
        this->nSignerId = nSignerNodeId;
        this->nCreatorId = nCreatorNodeId;
        this->nHeight = nHeight;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nSignerId);
        READWRITE(nCreatorId);
        READWRITE(nHeight);
    }

    void SetNull()
    {
        nVersion = CUnsignedCVNVote::CURRENT_VERSION;
        nSignerId = 0;
        nCreatorId = 0;
        nHeight = 0;
    }

    uint256 GetHash() const;
};

class CCVNVote : public CUnsignedCVNVote
{
public:
    std::vector<unsigned char> vSignature;

    CCVNVote()
    {
        SetNull();
    }

    CCVNVote(const uint32_t nSignerNodeId, const uint32_t nCreatorNodeId, const uint32_t nHeight, const int32_t nVersion = CUnsignedCVNVote::CURRENT_VERSION)
    : CUnsignedCVNVote(nSignerNodeId, nCreatorNodeId, nHeight, nVersion)
	{
        vSignature.clear();
	}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(*(CUnsignedCVNVote*)this);
        READWRITE(vSignature);
    }

    void SetNull()
    {
        CUnsignedCVNVote::SetNull();
        vSignature.clear();
    }

    std::string GetSignatureHex() const;

    std::string ToString() const;
};

#endif // BITCOIN_PRIMITIVES_VOTE_H
