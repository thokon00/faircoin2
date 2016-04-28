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
 * to proof consensus about the block.
 */
class CCvnSignature
{
public:
    static const int32_t CURRENT_VERSION=1;
    int32_t nVersion;
    uint32_t nSignerId;
    std::vector<unsigned char> vSignature;

    CCvnSignature()
    {
        SetNull();
    }

    CCvnSignature(const uint32_t nSignerNodeId, const int32_t nVersion = CCvnSignature::CURRENT_VERSION)
    {
        this->nVersion = nVersion;
        this->nSignerId = nSignerNodeId;
        this->vSignature.clear();
    }

    CCvnSignature(const uint32_t nSignerNodeId, std::vector<unsigned char> vSignature, const int32_t nVersion = CCvnSignature::CURRENT_VERSION)
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
        nVersion = CCvnSignature::CURRENT_VERSION;
        nSignerId = 0;
        vSignature.clear();
    }

    std::string ToString() const;
};

class CCvnSignatureMsg : public CCvnSignature
{
public:
    uint256 hashPrev;
    uint32_t nCreatorId; // the cvn node ID of the creator of the next block

    CCvnSignatureMsg()
    {
        SetNull();
    }

    void SetNull()
    {
        CCvnSignature::SetNull();
        hashPrev.SetNull();
        nCreatorId = 0;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(*(CCvnSignature*)this);
        READWRITE(hashPrev);
        READWRITE(nCreatorId);
    }

    CCvnSignature GetCvnSignature() const
    {
        CCvnSignature msg;
        msg.nVersion   = nVersion;
        msg.nSignerId  = nSignerId;
        msg.vSignature = vSignature;
        return msg;
    }

    uint256 GetHash() const;
};

class CCvnInfo
{
public:

    uint32_t nNodeId;
    uint32_t nHeightAdded;
    std::vector<unsigned char> vPubKey;

    CCvnInfo()
    {
        SetNull();
    }

    CCvnInfo(const uint32_t nNodeId, const uint32_t nHeightAdded, const std::vector<unsigned char> vPubKey)
    {
        this->nNodeId = nNodeId;
        this->nHeightAdded = nHeightAdded;
        this->vPubKey = vPubKey;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nNodeId);
        READWRITE(nHeightAdded);
        READWRITE(vPubKey);
    }

    void SetNull()
    {
        nNodeId = 0;
        nHeightAdded = 0;
        vPubKey.clear();
    }

    uint256 GetHash() const;

    std::string ToString() const;
};

class CChainAdmin
{
public:

    uint32_t nAdminId;
    std::vector<unsigned char> vPubKey;

    CChainAdmin()
    {
        SetNull();
    }

    CChainAdmin(const uint32_t nAdminId, const std::vector<unsigned char> vPubKey)
    {
        this->nAdminId = nAdminId;
        this->vPubKey = vPubKey;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(nAdminId);
        READWRITE(vPubKey);
    }

    void SetNull()
    {
        nAdminId = 0;
        vPubKey.clear();
    }

    uint256 GetHash() const;

    std::string ToString() const;
};

class CDynamicChainParams
{
public:
    static const uint32_t CURRENT_VERSION = 1;
    uint32_t nVersion;
    uint32_t nMinCvnSigners;
    uint32_t nMaxCvnSigners;
    uint32_t nBlockSpacing; // in seconds
    uint32_t nBlockSpacingGracePeriod; // in seconds
    uint32_t nDustThreshold; // in µFAIR
    // for a node to create the next block it needs to have co-signed
    // the last nMinSuccessiveSignatures blocks
    uint32_t nMinSuccessiveSignatures;
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
        READWRITE(nBlockSpacingGracePeriod);
        READWRITE(nDustThreshold);
        READWRITE(nMinSuccessiveSignatures);
        READWRITE(vPubKey);
    }

    void SetNull()
    {
        nVersion = CDynamicChainParams::CURRENT_VERSION;
        nMaxCvnSigners = 0;
        nMinCvnSigners = 0;
        nBlockSpacing = 0;
        nBlockSpacingGracePeriod = 0;
        nDustThreshold = 0;
        nMinSuccessiveSignatures = 0;
        vPubKey.clear();
    }

    uint256 GetHash() const;

    std::string ToString() const;
};

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    static const int32_t          CURRENT_VERSION = 1;
    static const int32_t               TX_PAYLOAD = 1 << 8;
    static const int32_t              CVN_PAYLOAD = 1 << 9;
    static const int32_t CHAIN_PARAMETERS_PAYLOAD = 1 << 10;
    static const int32_t     CHAIN_ADMINS_PAYLOAD = 1 << 11;
    static const int32_t           PAYLOAD_MASK = TX_PAYLOAD | CVN_PAYLOAD | CHAIN_PARAMETERS_PAYLOAD | CHAIN_ADMINS_PAYLOAD;
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nCreatorId;
    std::vector<CCvnSignature> vSignatures;

    CBlockHeader()
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
        READWRITE(vSignatures);
    }

    void SetNull()
    {
        nVersion = CBlockHeader::CURRENT_VERSION;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nCreatorId = 0;
        vSignatures.clear();
    }

    bool IsNull() const
    {
        return (nCreatorId == 0);
    }

    uint256 GetHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    bool HasCvnInfo() const
    {
        return (nVersion & CVN_PAYLOAD);
    }

    bool HasChainParameters() const
    {
        return (nVersion & CHAIN_PARAMETERS_PAYLOAD);
    }

    bool HasTx() const
    {
        return (nVersion & TX_PAYLOAD);
    }

    bool HasChainAdmins() const
    {
        return (nVersion & CHAIN_ADMINS_PAYLOAD);
    }
};

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<unsigned char> vCreatorSignature;
    std::vector<CTransaction> vtx;
    std::vector<CCvnInfo> vCvns;
    std::vector<CChainAdmin> vChainAdmins;
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
        READWRITE(vCreatorSignature);

        if (HasTx())
            READWRITE(vtx);
        if (HasCvnInfo())
            READWRITE(vCvns);
        if (HasChainParameters())
            READWRITE(dynamicChainParams);
        if (HasChainAdmins())
            READWRITE(vChainAdmins);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        vCvns.clear();
        vCreatorSignature.clear();
        dynamicChainParams = CDynamicChainParams();
        vChainAdmins.clear();
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
        block.vSignatures    = vSignatures;
        return block;
    }

    std::string ToString() const;

    uint256 HashCVNs() const;

    uint256 HashChainAdmins() const;
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
