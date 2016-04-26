// Copyright (c) 2016 The FairCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POC_H
#define BITCOIN_POC_H

#include "consensus/params.h"
#include "primitives/block.h"
#include "chainparams.h"
#include "chain.h"
#include "sync.h"

#include <stdint.h>

typedef std::map<uint32_t, CCvnInfo> CvnMapType;
typedef std::map<uint32_t, CCvnSignature> CvnSigEntryType;
typedef std::map<uint256, CvnSigEntryType> CvnSigMapType;

#define MAX_BLOCK_SPACING 3600
#define MIN_BLOCK_SPACING 30
#define MAX_DUST_THRESHOLD 1 * COIN
#define MIN_DUST_THRESHOLD 1000

#define __DBG_ LogPrintf("DEBUG: In file %s in function %s in line %d\n", __FILE__, __func__, __LINE__);

extern uint32_t nCvnNodeId;
extern CCriticalSection cs_mapCVNs;
extern CvnMapType mapCVNs;
extern CCriticalSection cs_mapCvnSigs;
extern CvnSigMapType mapCvnSigs;
extern bool fSmartCardUnlocked;

bool CvnSign(const uint256& hashUnsignedBlock, CCvnSignature& signature, const uint32_t& nNodeId);
bool CvnVerifySignature(const uint256 &hash, const CCvnSignature &sig);
bool CheckForDuplicateCvns(const CBlock& block);
void SendCVNSignature(const CBlockIndex *pindexNew);
bool AddCvnSignature(const CCvnSignature& signature, const uint256& hashPrevBlock, const uint32_t nCreatorId);
bool CvnValidateSignature(const CCvnSignature& signature, const uint256& hashPrevBlock, const uint32_t nCreatorId);

/** Check whether a block hash satisfies the proof-of-cooperation requirements */
bool CheckProofOfCooperation(const CBlockHeader& block, const Consensus::Params&);

void UpdateCvnInfo(const CBlock* pblock);

void UpdateChainParameters(const CBlock* pblock);

bool CheckDynamicChainParameters(const CDynamicChainParams& params);

/** strart the CVN voter thread */
void RunCVNSignerThread(const CChainParams& chainparams, const uint32_t& nNodeId);

#endif // BITCOIN_POC_H
