// Copyright (c) 2016 by Thomas König
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "streams.h"
#include "hash.h"
#include "random.h"
#include "cvn.h"
#include "key.h"
#include "util.h"
#include "clientversion.h"
#include "chainparams.h"
#include "ui_interface.h"

#include <boost/foreach.hpp>
#include <stddef.h>
#include <map>

extern CClientUIInterface uiInterface;

CCvnMan cvnman;

void DumpCVNs()
{
    int64_t nStart = GetTimeMillis();

    CCvnDB cvns;
    cvns.Write(cvnman);

    LogPrint("cvn", "Flushed %d CVNs to cvn.dat  %dms\n", cvnman.size(), GetTimeMillis() - nStart);
}

void ReadCVNs(boost::thread_group& threadGroup, CScheduler& scheduler)
{
    uiInterface.InitMessage(_("Loading CVNs..."));
    // Load addresses for cvn.dat
    int64_t nStart = GetTimeMillis();
    {
        CCvnDB adb;
        if (!adb.Read(cvnman))
            LogPrintf("Invalid or missing cvn.dat recreating\n");
    }

    LogPrintf("Loaded %i CVNs from cvn.dat  %dms\n", cvnman.size(), GetTimeMillis() - nStart);

    // Dump network addresses
    scheduler.scheduleEvery(&DumpCVNs, DUMP_CVNS_INTERVAL);
}

CCvnInfo* CCvnMan::Find(const uint32_t& nodeId)
{
    std::map<uint32_t, CCvnInfo>::iterator it = mapCvns.find(nodeId);
    if (it == mapCvns.end())
        return NULL;

    return &(*it).second;
}

void CCvnMan::Add(const CCvnInfo &info)
{
    LOCK(cs);

    cvnman.mapCvns.insert(std::pair<uint32_t, CCvnInfo>(info.nNodeId, info));
    LogPrint("cvnman", "Added CVN with node ID 0x%08x\n", info.nNodeId);
}

void CCvnMan::Delete(const uint32_t& nodeId)
{
    LOCK(cs);

    cvnman.mapCvns.erase(nodeId);
    LogPrint("cvnman", "Removed CVN with node ID 0x%08x\n", nodeId);
}

uint256 CCvnInfo::GetHash() const
{
    return SerializeHash(*this);
}

//! Relay an entry
bool CSignedCvnInfo::RelayTo(CNode* pnode) const
{
    // don't relay to nodes which haven't sent their version message
    if (pnode->nVersion == 0)
        return false;
    // returns true if wasn't already contained in the set
    if (pnode->setKnownCVNs.insert(nNodeId).second)
    {
        pnode->PushMessage(NetMsgType::ADDCVN, *this);
        return true;
    }
    return false;
}

//! Relay removal of an entry
bool CSignedCvnInfo::RelayRemoveTo(CNode* pnode) const
{
    // don't relay to nodes which haven't sent their version message
    if (pnode->nVersion == 0)
        return false;
    // returns >0 if it was contained in the set
    if (pnode->setKnownCVNs.erase(nNodeId))
    {
        pnode->PushMessage(NetMsgType::REMOVECVN, *this);
        return true;
    }
    return false;
}

bool CSignedCvnInfo::CheckSignatures(const CChainParams& params) const
{
    if (vSignatures.size() < (uint32_t)params.MinAdminSigners())
        return error("CSignedCVNInfo::CheckSignatures(): not enough signers %d/%d", params.MinAdminSigners(), params.MaxAdminSigners());

    uint256 hashTmp = GetHash();

    int i = 1;
    // verify stored checksum matches input data
    BOOST_FOREACH (CCvnAdminSignature sig, vSignatures)
    {
        if (!sig.IsValid(params, hashTmp))
            return error("CSignedCVNInfo::CheckSignatures(): verify signature #%d failed", i);

        i++;
    }

    return true;
}

bool CSignedCvnInfo::CheckCvnInfo(const CChainParams& params, const bool fRemove) const
{
    if (!CheckSignatures(params))
        return false;

    if (fRemove)
        cvnman.Delete(nNodeId);
    else
        cvnman.Add((CCvnInfo&) *this);

    LogPrint("cvn", "accepted %s certified validation node 0x%08x\n", fRemove ? "removal of" : "new", nNodeId);
    return true;
}

CCvnDB::CCvnDB()
{
    pathCvns = GetDataDir() / "cvn.dat";
}

bool CCvnDB::Write(const CCvnMan& cvns)
{
    // Generate random temporary filename
    unsigned short randv = 0;
    GetRandBytes((unsigned char*)&randv, sizeof(randv));
    std::string tmpfn = strprintf("cvn.dat.%04x", randv);

    // serialize CVNs, checksum data up to that point, then append csum
    CDataStream ssCVNs(SER_DISK, CLIENT_VERSION);
    ssCVNs << FLATDATA(Params().MessageStart());
    ssCVNs << cvns;
    uint256 hash = Hash(ssCVNs.begin(), ssCVNs.end());
    ssCVNs << hash;

    // open temp output file, and associate with CAutoFile
    boost::filesystem::path pathTmp = GetDataDir() / tmpfn;
    FILE *file = fopen(pathTmp.string().c_str(), "wb");
    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: Failed to open file %s", __func__, pathTmp.string());

    // Write and commit header, data
    try {
        fileout << ssCVNs;
    }
    catch (const std::exception& e) {
        return error("%s: Serialize or I/O error - %s", __func__, e.what());
    }
    FileCommit(fileout.Get());
    fileout.fclose();

    // replace existing peers.dat, if any, with new peers.dat.XXXX
    if (!RenameOver(pathTmp, pathCvns))
        return error("%s: Rename-into-place failed", __func__);

    return true;
}

bool CCvnDB::Read(CCvnMan& addr)
{
    // open input file, and associate with CAutoFile
    FILE *file = fopen(pathCvns.string().c_str(), "rb");
    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: Failed to open file %s", __func__, pathCvns.string());

    // use file size to size memory buffer
    uint64_t fileSize = boost::filesystem::file_size(pathCvns);
    uint64_t dataSize = 0;
    // Don't try to resize to a negative number if file is small
    if (fileSize >= sizeof(uint256))
        dataSize = fileSize - sizeof(uint256);
    std::vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try {
        filein.read((char *)&vchData[0], dataSize);
        filein >> hashIn;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }
    filein.fclose();

    CDataStream ssCVNs(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssCVNs.begin(), ssCVNs.end());
    if (hashIn != hashTmp)
        return error("%s: Checksum mismatch, data corrupted", __func__);

    unsigned char pchMsgTmp[4];
    try {
        // de-serialize file header (network specific magic number) and ..
        ssCVNs >> FLATDATA(pchMsgTmp);

        // ... verify the network matches ours
        if (memcmp(pchMsgTmp, Params().MessageStart(), sizeof(pchMsgTmp)))
            return error("%s: Invalid network magic number", __func__);

        // de-serialize address data into one CAddrMan object
        ssCVNs >> addr;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    return true;
}

bool CCvnAdminSignature::IsValid(const CChainParams& params, const uint256 hashTmp) const
{
    CCvnAdminSigner signer = params.GetAdminSigners()[nSignerId - 1];
    CPubKey key(signer.vPubKey);

    return key.Verify(hashTmp, vSignature);
}
