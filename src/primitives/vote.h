// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_VOTE_H
#define BITCOIN_PRIMITIVES_VOTE_H

#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"

class CCVNVote
{
public:
    static const int32_t CURRENT_VERSION=1;
    int32_t nVersion;
    uint32_t nSignerNodeId;
	uint32_t nCreatorNodeId;
	uint32_t nHeight;

	ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
    	READWRITE(this->nVersion);
    	nVersion = this->nVersion;
    	READWRITE(nSignerNodeId);
        READWRITE(nCreatorNodeId);
        READWRITE(nHeight);
    }

    CCVNVote()
    {
    	SetNull();
    }

    CCVNVote(const uint32_t nSignerNodeId, const uint32_t nCreatorNodeId, const uint32_t nHeight, const int32_t nVersion = CCVNVote::CURRENT_VERSION)
	{
		this->nVersion = nVersion;
    	this->nSignerNodeId = nSignerNodeId;
		this->nCreatorNodeId = nCreatorNodeId;
		this->nHeight = nHeight;
	}

    void SetNull()
    {
    	nVersion = CCVNVote::CURRENT_VERSION;
    	nSignerNodeId = 0;
    	nCreatorNodeId = 0;
    	nHeight = 0;
    }

    uint256 GetHash() const;

    std::string ToString() const;
};

class CSignedCVNVote : CCVNVote
{
public:
	std::vector<unsigned char> signature;

	ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
    	READWRITE(*(CBlockHeader*)this);
    	READWRITE(signature);
    }

    CSignedCVNVote()
    {
    	SetNull();
    }

//    CCVNVote(const uint32_t nSignerNodeId, const uint32_t nCreatorNodeId, const uint32_t nHeight, const int32_t nVersion = CCVNVote::CURRENT_VERSION)
//	{
//		this->nVersion = nVersion;
//    	this->nSignerNodeId = nSignerNodeId;
//		this->nCreatorNodeId = nCreatorNodeId;
//		this->nHeight = nHeight;
//	}

    void SetNull()
    {
    	CCVNVote::SetNull();
    	signature.clear();
    }
};

#endif // BITCOIN_PRIMITIVES_VOTE_H
