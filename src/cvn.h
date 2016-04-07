// Copyright (c) 2016 by Thomas König
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FAIRCOIN_CVN_H
#define FAIRCOIN_CVN_H

#include "chainparams.h"
#include "net.h"
#include "scheduler.h"

#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

void DumpCVNs();
void ReadCVNs(boost::thread_group& threadGroup, CScheduler& scheduler);

class CCvnMan;
extern CCvnMan cvnman;

// Dump CVNs to cvn.dat every hour (3600s)
#define DUMP_CVNS_INTERVAL 3600

class CCvnInfo
{
public:

	uint32_t nNodeId;
	std::vector<unsigned char> vPubKey;
	//std::vector<unsigned char> vCertificate;

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

class CSignedCvnInfo : public CCvnInfo
{
public:
	std::vector< std::vector<unsigned char> > vSignatures;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
    	READWRITE(*(CCvnInfo*)this);
    	READWRITE(vSignatures);
    }

    CSignedCvnInfo()
    {
        SetNull();
    }

    CSignedCvnInfo(const uint32_t nNodeId, const std::vector<unsigned char> vPubKey) :
        CCvnInfo(nNodeId, vPubKey)
    {
        vSignatures.clear();
    }

    void SetNull()
    {
    	CCvnInfo::SetNull();
    	vSignatures.clear();
    }

    //! Relay an entry
    bool RelayTo(CNode* pnode) const;

    //! check the integrity of a received CVNInfo
    bool CheckCvnInfo(const CChainParams& params) const;

    //! check the signatures
    bool CheckSignatures(const CChainParams& params) const;
};

class CCvnMan
{
private:
    //! critical section to protect the inner data structures
    mutable CCriticalSection cs;

    //! table with information about all nIds
    std::map<uint32_t, CCvnInfo> mapCvns;

public:

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
    	LOCK(cs);

    	READWRITE(mapCvns);
    }

    //! Find an entry.
    CCvnInfo* Find(const uint32_t& nodeId);

    //! Create an entry
    void Add(const CCvnInfo &info);

    //! Delete an entry.
    void Delete(const uint32_t& nodeId);

    size_t size() const
	{
		return mapCvns.size();
	}

    void Clear()
    {
        mapCvns.clear();
    }

    CCvnMan()
    {
        Clear();
    }
};


/** Access to the certified validation nodes database (cvn.dat) */
class CCvnDB
{
private:
    boost::filesystem::path pathCvns;
public:
    CCvnDB();
    bool Write(const CCvnMan& cvns);
    bool Read(CCvnMan& cvns);
};

#endif // FAIRCOIN_CVN_H
