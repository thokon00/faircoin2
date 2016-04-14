// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"
#include "consensus/params.h"

/** CVNs send this signature to the creator of the next block
 * to proof consensus about the block. The GetUnsignedHash() hash
 * of the next block is signed.
 */
class CBlockSignature
{
public:
    static const int32_t CURRENT_VERSION=1;
    int32_t nVersion;
    uint32_t nSignerId;
    std::vector<unsigned char> vSignature;

    CBlockSignature()
    {
        SetNull();
    }

    CBlockSignature(const uint32_t nSignerNodeId, const int32_t nVersion = CBlockSignature::CURRENT_VERSION)
    {
        this->nVersion = nVersion;
        this->nSignerId = nSignerNodeId;
        this->vSignature.clear();
    }

    CBlockSignature(const uint32_t nSignerNodeId, std::vector<unsigned char> vSignature, const int32_t nVersion = CBlockSignature::CURRENT_VERSION)
    {
        this->nVersion = nVersion;
        this->nSignerId = nSignerNodeId;
        this->vSignature = vSignature;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nSignerId);
        READWRITE(vSignature);
    }

    void SetNull()
    {
        nVersion = CBlockSignature::CURRENT_VERSION;
        nSignerId = 0;
        vSignature.clear();
    }

    std::string GetSignatureHex() const;

    std::string ToString() const;

    bool IsValid(const Consensus::Params& params, const uint256 hash, const uint32_t nCvnNodeId) const;
};

class CCvnInfo
{
public:

    uint32_t nNodeId;
    std::vector<unsigned char> vPubKey;

    CCvnInfo()
    {
        SetNull();
    }

    CCvnInfo(const uint32_t nNodeId, const std::vector<unsigned char> vPubKey)
    {
        this->nNodeId = nNodeId;
        this->vPubKey = vPubKey;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nNodeId);
        READWRITE(vPubKey);
    }

    void SetNull()
    {
        nNodeId = 0;
        vPubKey.clear();
    }

    uint256 GetHash() const;
};

class CDynamicChainParams
{
public:
    static const uint32_t CURRENT_VERSION = 1;
    uint32_t nVersion;
    uint32_t nMinCvnSigners;
    uint32_t nMaxCvnSigners;
    uint32_t nBlockSpacing; // in seconds
    uint32_t nDustThreshold; // in seconds
    std::vector<unsigned char> vPubKey;

    CDynamicChainParams()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nMinCvnSigners);
        READWRITE(nMaxCvnSigners);
        READWRITE(nBlockSpacing);
        READWRITE(nDustThreshold);
        READWRITE(vPubKey);
    }

    void SetNull()
    {
        nVersion = CDynamicChainParams::CURRENT_VERSION;
        nMaxCvnSigners = 0;
        nMinCvnSigners = 0;
        nBlockSpacing = 0;
        nDustThreshold = 0;
        vPubKey.clear();
    }

    uint256 GetHash() const;
};

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CUnsignedBlockHeader
{
public:
    // header
    static const int32_t       CURRENT_VERSION = 1;
    static const int32_t              TX_BLOCK = 1 << 8;
    static const int32_t             CVN_BLOCK = 1 << 9;
    static const int32_t CHAIN_PARAMETER_BLOCK = 1 << 10;
    static const int32_t        BLOCKTYPE_MASK = TX_BLOCK | CVN_BLOCK | CHAIN_PARAMETER_BLOCK;
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nCreatorId;
    int nHeight;

    CUnsignedBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nCreatorId);
        READWRITE(nHeight);
    }

    void SetNull()
    {
        nVersion = CUnsignedBlockHeader::CURRENT_VERSION;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nCreatorId = 0;
        nHeight = 0;
    }

    bool IsNull() const
    {
        return (nCreatorId == 0);
    }

    uint256 GetUnsignedHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    bool HasCvnInfo() const
    {
        return (nVersion & CVN_BLOCK);
    }

    bool HasChainParameters() const
    {
        return (nVersion & CHAIN_PARAMETER_BLOCK);
    }

    bool HasTx() const
    {
        return (nVersion & TX_BLOCK);
    }
};

class CBlockHeader : public CUnsignedBlockHeader
{
public:
    // header
    std::vector<CBlockSignature> vSignatures;

    CBlockHeader()
    {
        SetNull();
    }

    void SetNull()
    {
        CUnsignedBlockHeader::SetNull();
        vSignatures.clear();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(*(CUnsignedBlockHeader*)this);
        READWRITE(vSignatures);
    }

    uint256 GetHash() const;
};

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransaction> vtx;
    std::vector<CCvnInfo> vCvns;
    CDynamicChainParams dynamicChainParams;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(*(CBlockHeader*)this);

        if (HasTx())
            READWRITE(vtx);
        if (HasCvnInfo())
            READWRITE(vCvns);
        if (HasChainParameters())
            READWRITE(dynamicChainParams);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        vCvns.clear();
        dynamicChainParams = CDynamicChainParams();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nCreatorId     = nCreatorId;
        block.nHeight        = nHeight;
        block.vSignatures    = vSignatures;
        return block;
    }

    std::string ToString() const;

    uint256 HashCVNs() const;
};


/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
