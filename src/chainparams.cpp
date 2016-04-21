// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "primitives/block.h"
#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "key.h"
#include "poc.h"
#include "base58.h"
#include "chainparamsseeds.h"

#include <stdio.h>
#include <assert.h>
#include <boost/assign/list_of.hpp>

CDynamicChainParams dynParams;

//#define SHOW_HASHES 1

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nCreatorId, const CDynamicChainParams& dynamicChainParams)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 0xc001d00d;
    txNew.vout[0].nValue = MAX_MONEY; // the take over from FairCoin1
    txNew.vout[0].scriptPubKey = CScript() << ParseHex("04e27d35f6f56ab5a1974cc9bd59a9e0a130d5269487a5c061c15ce837e188b8a9f85bab72168c1a1570d5fdffa3c0acc04f4824446919f96be90a007738040c88") << OP_CHECKSIG;

    CBlock genesis;
    genesis.nVersion   = CBlock::CURRENT_VERSION | CBlock::TX_BLOCK | CBlock::CVN_BLOCK | CBlock::CHAIN_PARAMETER_BLOCK;
    genesis.nTime      = nTime;
    genesis.nCreatorId = nCreatorId;
    genesis.hashPrevBlock.SetNull();
    genesis.vtx.push_back(txNew);
    genesis.dynamicChainParams = dynamicChainParams;
    return genesis;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

std::string GetHex(std::vector<unsigned char> data)
{
    char psz[sizeof(data) * 2 + 1];
    for (unsigned int i = 0; i < sizeof(data); i++)
        sprintf(psz + i * 2, "%02x", data[sizeof(data) - i - 1]);
    return std::string(psz, psz + sizeof(data) * 2);
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        /** 
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        vAlertPubKey = ParseHex("04b06af4982ca3edc2c040cc2cde05fa5b33264af4a98712ceb29d196e7390b4753eb7264dc5f383f29a44d63e70dbbd8d9e46a0a60f80ef62fd1911291ec388e4");
        nDefaultPort = 40404;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;

        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing = 3 * 60;
        dynParams.nMaxCvnSigners = 1;
        dynParams.nMinCvnSigners = 1;
        dynParams.nDustThreshold = 10000; // µFAIR
        dynParams.nMinSuccessiveSignatures = 1;

        genesis = CreateGenesisBlock(1461248303, 0xC001D00D, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(0xC001D00D, ParseHex("04e27d35f6f56ab5a1974cc9bd59a9e0a130d5269487a5c061c15ce837e188b8a9f85bab72168c1a1570d5fdffa3c0acc04f4824446919f96be90a007738040c88"));

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

        CBlockSignature genesisSignature(0xC001D00D, ParseHex("3045022100816ecd9220bac31c7372bffe0c4f89f22c25b3a2319c926440d59e6cd6207b8c022004333e8409c28fabc37d5783c3a65ead0a7292de4041cd8f090953d8661cc878"));
        genesis.vSignatures.push_back(genesisSignature); // genesis signature

        consensus.hashGenesisBlock = genesis.GetHash();
        printf("genesis block main net:\n%s\n", genesis.ToString().c_str());

#ifdef SHOW_HASHES
        printf("%s parameters\nhash: %s\nmerkle: %s\nunsigned hash: %s\n",strNetworkID.c_str(),
                consensus.hashGenesisBlock.ToString().c_str(),
                genesis.hashMerkleRoot.ToString().c_str(),
                genesis.GetUnsignedHash().ToString().c_str());
#else
        assert(consensus.hashGenesisBlock == uint256S("4a8e424b6405a934cb26eefed3d3317430918403ec43fe9e56349a93c8afa567"));
        assert(genesis.hashMerkleRoot == uint256S("109163d7eca9f3deb276e60e5670ac714f0841d2c74c3ff25f3a551a7b4d2422"));
#endif
        vSeeds.push_back(CDNSSeedData("1.fair-coin.org", "faircoin2-seed1.fair-coin.org")); // Thomas König
        vSeeds.push_back(CDNSSeedData("2.fair-coin.org", "faircoin2-seed2.fair-coin.org")); // Thomas König

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,95);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,36);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,223);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = false; //TODO: set to true again
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("533750216f308c0744579a1fda884d0a56da828da6552b0b67fbbd7431ac3792")),
            1458643274, // * UNIX timestamp of last checkpoint block
            0,   // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.0     // * estimated number of transactions per day after checkpoint
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        vAlertPubKey = ParseHex("045894f38e9dd72b6f210c261d40003eb087030c42b102d3b238b396256d02f5a380ff3b7444d306d9e118fa1fc7b2b7594875f4eb64bbeaa31577391d85eb5a8a");
        nDefaultPort = 41404;
        nMaxTipAge = 0x7fffffff;
        nPruneAfterHeight = 1000;
        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing = 3 * 60;
        dynParams.nMaxCvnSigners = 1;
        dynParams.nMinCvnSigners = 1;
        dynParams.nDustThreshold = 10000; // µFAIR

        genesis = CreateGenesisBlock(1458643274, 0xC001D00D, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(0xC001D00D, ParseHex("04e27d35f6f56ab5a1974cc9bd59a9e0a130d5269487a5c061c15ce837e188b8a9f85bab72168c1a1570d5fdffa3c0acc04f4824446919f96be90a007738040c88"));

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

        CBlockSignature genesisSignature(0xC001CAFE);
        genesis.vSignatures.push_back(genesisSignature); // genesis signature

        consensus.hashGenesisBlock = genesis.GetHash();
#ifdef SHOW_HASHES
        printf("%s parameters\nhash: %s\nmerkle: %s\nunsigned hash: %s\n",strNetworkID.c_str(),
                consensus.hashGenesisBlock.ToString().c_str(),
                genesis.hashMerkleRoot.ToString().c_str(),
                genesis.GetUnsignedHash().ToString().c_str());
#else
        assert(consensus.hashGenesisBlock == uint256S("abdc463cf781e266c91ea25a43fbce67261654102767ae3bb305442ae28866b0"));
        assert(genesis.hashMerkleRoot == uint256S("9f470d4e6fb2b61a55589cdb16edf747d467465a26eb6e242ebb5a5b28d92d34"));
#endif
        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("1.fair-coin.org", "faircoin2-seed1.fair-coin.org")); // Thomas König
        vSeeds.push_back(CDNSSeedData("2.fair-coin.org", "faircoin2-seed2.fair-coin.org")); // Thomas König

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("0x61d9f3c05a04e3aaea24466ab27d56ca7c4ee76b6ca0f509f824eb18962b53ce")),
            1458643274,
            1488,
            300
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nMaxTipAge = 24 * 60 * 60;
        nDefaultPort = 42404;
        nPruneAfterHeight = 1000;
        CDynamicChainParams dynParams;
        dynParams.nBlockSpacing = 1 * 60;
        dynParams.nMaxCvnSigners = 1;
        dynParams.nMinCvnSigners = 1;
        dynParams.nDustThreshold = 10000; // µFAIR

        genesis = CreateGenesisBlock(1458643274, 0xC001D00D, dynParams);

        genesis.vCvns.resize(1);
        genesis.vCvns[0] = CCvnInfo(0xC001D00D, ParseHex("04e27d35f6f56ab5a1974cc9bd59a9e0a130d5269487a5c061c15ce837e188b8a9f85bab72168c1a1570d5fdffa3c0acc04f4824446919f96be90a007738040c88"));

        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);

        CBlockSignature genesisSignature(0xCAFEBABE);
        genesis.vSignatures.push_back(genesisSignature); // genesis signature

        consensus.hashGenesisBlock = genesis.GetHash();
#ifdef SHOW_HASHES
        printf("%s parameters\nhash: %s\nmerkle: %s\nunsigned hash: %s\n",strNetworkID.c_str(),
                consensus.hashGenesisBlock.ToString().c_str(),
                genesis.hashMerkleRoot.ToString().c_str(),
                genesis.GetUnsignedHash().ToString().c_str());
#else
        assert(consensus.hashGenesisBlock == uint256S("c80274f7aad1ca3266f267e207e57ca24df83545e9184d877886f815df70262a"));
        assert(genesis.hashMerkleRoot == uint256S("96f0414d09a85fe992b38e33389bca2d2a795279a69f3323eacf12cdaa218e23"));
#endif
        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x5daec43cedbd536e7bd5f8a9112eb8c76fd11a275300ffa24e429dcfa6f36a28")),
            0,
            0,
            0
        };
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}
