// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "consensus/consensus.h"
#include "wn8_params.h"
#include "crypto/scrypt.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "bitcoin_bignum/bignum.h"
#include "blacklists.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"
#include "arith_uint256.h"

using namespace secp_primitives;

static CBlock CreateGenesisBlock(const char *pszTimestamp, const CScript &genesisOutputScript, uint32_t nTime, uint32_t nNonce,
        uint32_t nBits, int32_t nVersion, const CAmount &genesisReward,
        std::vector<unsigned char> extraNonce) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 504365040 << CBigNum(4).getvch() << std::vector < unsigned char >
    ((const unsigned char *) pszTimestamp, (const unsigned char *) pszTimestamp + strlen(pszTimestamp)) << extraNonce;
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount &genesisReward,
                   std::vector<unsigned char> extraNonce) {
    //btzc: firo timestamp
	const char *pszTimestamp = "WSJ at 3 June 2022: 100 Days In, Russia’s Claims of Success in Ukraine Face Hard Test of Reality";
    const CScript genesisOutputScript = CScript();
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward,
                              extraNonce);
}

static CBlock FindNewGenesisBlock(const Consensus::Params& params, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount &genesisReward,
								std::vector<unsigned char> extraNonce)
{

	//btzc: firo timestamp
	const char *pszTimestamp = "WSJ at 3 June 2022: 100 Days In, Russia’s Claims of Success in Ukraine Face Hard Test of Reality";
	const CScript genesisOutputScript = CScript();
	CBlock newBlock = CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward,
							  extraNonce);

	printf("Mainnet block.GetHash = %s\n", newBlock.GetHash().ToString().c_str());

	if (newBlock.GetHash() != uint256S("0x"))
		{
			printf("Searching for main genesis block...\n");
			arith_uint256 hashTarget;
			hashTarget.SetCompact(newBlock.nBits);

			uint256 powHash;
			scrypt_N_1_1_256(BEGIN(newBlock.nVersion), BEGIN(powHash), params.nMinNFactor);

			while(UintToArith256(powHash) > hashTarget)
			{
				++newBlock.nNonce;
				scrypt_N_1_1_256(BEGIN(newBlock.nVersion), BEGIN(powHash), params.nMinNFactor);
				if (newBlock.nNonce == 0)
				{
					printf("Mainnet NONCE WRAPPED, incrementing time");
					std::cout << std::string("Mainnet NONCE WRAPPED, incrementing time:\n");
					++newBlock.nTime;
				}
			}

			printf("Mainnet PoW Hash = %s\n", powHash.ToString().c_str());
			printf("Mainnet Target Hash = %s\n", ArithToUint256(hashTarget).ToString().c_str());
			printf("Mainnet block.nTime = %u \n", newBlock.nTime);
			printf("Mainnet block.nNonce = %u \n", newBlock.nNonce);
			printf("Mainnet block.GetHash = %s\n", newBlock.GetHash().ToString().c_str());
			printf("Mainnet block.hashMerkleRoot: %s\n", newBlock.hashMerkleRoot.ToString().c_str());
		}

	return newBlock;
}

// this one is for testing only
static Consensus::LLMQParams llmq5_60 = {
        .type = Consensus::LLMQ_5_60,
        .name = "llmq_5_60",
        .size = 5,
        .minSize = 3,
        .threshold = 3,

        .dkgInterval = 24, // one DKG per hour
        .dkgPhaseBlocks = 2,
        .dkgMiningWindowStart = 10, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 18,
        .dkgBadVotesThreshold = 8,

        .signingActiveQuorumCount = 2, // just a few ones to allow easier testing

        .keepOldConnections = 3,
};

// to use on testnet
static Consensus::LLMQParams llmq10_70 = {
        .type = Consensus::LLMQ_10_70,
        .name = "llmq_10_70",
        .size = 10,
        .minSize = 8,
        .threshold = 7,

        .dkgInterval = 24, // one DKG per hour
        .dkgPhaseBlocks = 2,
        .dkgMiningWindowStart = 10, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 18,
        .dkgBadVotesThreshold = 8,

        .signingActiveQuorumCount = 2, // just a few ones to allow easier testing

        .keepOldConnections = 3,
};

static Consensus::LLMQParams llmq50_60 = {
        .type = Consensus::LLMQ_50_60,
        .name = "llmq_50_60",
        .size = 50,
        .minSize = 40,
        .threshold = 30,

        .dkgInterval = 18, // one DKG per 90 minutes
        .dkgPhaseBlocks = 2,
        .dkgMiningWindowStart = 10, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 16,
        .dkgBadVotesThreshold = 40,

        .signingActiveQuorumCount = 16, // a full day worth of LLMQs

        .keepOldConnections = 17,
};

static Consensus::LLMQParams llmq400_60 = {
        .type = Consensus::LLMQ_400_60,
        .name = "llmq_400_60",
        .size = 400,
        .minSize = 300,
        .threshold = 240,

        .dkgInterval = 12 * 12, // one DKG every 12 hours
        .dkgPhaseBlocks = 4,
        .dkgMiningWindowStart = 20, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 28,
        .dkgBadVotesThreshold = 300,

        .signingActiveQuorumCount = 4, // two days worth of LLMQs

        .keepOldConnections = 5,
};

// Used for deployment and min-proto-version signalling, so it needs a higher threshold
static Consensus::LLMQParams llmq400_85 = {
        .type = Consensus::LLMQ_400_85,
        .name = "llmq_400_85",
        .size = 400,
        .minSize = 350,
        .threshold = 340,

        .dkgInterval = 12 * 24, // one DKG every 24 hours
        .dkgPhaseBlocks = 4,
        .dkgMiningWindowStart = 20, // dkgPhaseBlocks * 5 = after finalization
        .dkgMiningWindowEnd = 48, // give it a larger mining window to make sure it is mined
        .dkgBadVotesThreshold = 300,

        .signingActiveQuorumCount = 4, // two days worth of LLMQs

        .keepOldConnections = 5,
};


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

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";

        consensus.chainType = Consensus::chainMain;

		// WN8 Params

		// 3 month after start
		consensus.nFirstSubsidyHalvingEndPeriod = 1666483200; // Sun Oct 23 2022 00:00:00 GMT+0000
		consensus.nFirstSubsidyHalvingValue = 20;

		// 9 month
		consensus.nSecondSubsidyHalvingEndPeriod = 1682208000; // Sun Apr 23 2023 00:00:00 GMT+0000
		consensus.nSecondSubsidyHalvingValue = 10;

		// 15 month
		consensus.nThirdSubsidyHalvingEndPeriod = 1698019200; // Mon Oct 23 2023 00:00:00 GMT+0000
		consensus.nThirdSubsidyHalvingValue = 5;

		consensus.nSubsidyHalvingMinersShare = 80;
		consensus.nSubsidyHalvingNodesShare = 20;
		consensus.nSubsidyHalvingDevelopShare = 50;

		consensus.subsidyDevelopFundAddress = "WTGiQc32gpkB4UnAuJsR6cb8UFhRpnnj92";

		// end of WN8 Params

		consensus.nStartDuplicationCheck = 1;

        consensus.nMinNFactor = 10;
        consensus.nMaxNFactor = 30;

        consensus.powLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 60 * 60; // 60 minutes between retargets
		consensus.nPowTargetSpacing = 2.5 * 60; // 2.5 minute blocks
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
		consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0; // January 1, 2008
		consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 0; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
		consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0; // May 1st, 2016
		consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
		consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0; // November 15th, 2016.
		consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0; // November 15th, 2017.

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000708f98bf623f02e");

        // By default assume that the signatures in ancestors of this block are valid.
		consensus.defaultAssumeValid.SetNull();

        // evo znodes
		consensus.DIP0003Height = 2; // Approximately June 22 2020, 12:00 UTC
		consensus.DIP0003EnforcementHeight = 2; // Approximately July 13 2020, 12:00 UTC
		consensus.DIP0003EnforcementHash.SetNull();
		consensus.DIP0008Height = 1; // Approximately Jan 28 2021, 11:00 UTC
        consensus.nEvoZnodeMinimumConfirmations = 15;

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_50_60] = llmq50_60;
        consensus.llmqs[Consensus::LLMQ_400_60] = llmq400_60;
        consensus.llmqs[Consensus::LLMQ_400_85] = llmq400_85;
        consensus.nLLMQPowTargetSpacing = 5*60;
        consensus.llmqChainLocks = Consensus::LLMQ_400_60;
        consensus.llmqForInstantSend = Consensus::LLMQ_50_60;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 24;
		consensus.nInstantSendBlockFilteringStartHeight = INT_MAX;   // Approx Nov 2 2021 06:00:00 GMT+0000

		consensus.nMTPSwitchTime = INT_MAX;
		consensus.nFixedDifficulty = 0x1e0ffff0;

        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour
		strZnodePaymentsPubKey = "045bc08840a8d8531d1034a1178c5f6287d5164e8a214fbc5c579af3c3cfcefd0b6f2f8c2a6ca81a0f8f60c76dd9086cd9f94a8e60c04950b152fce3394d30bee2";

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
       `  * a large 32-bit integer with any alignment.
         */

        //btzc: update firo pchMessage
		pchMessageStart[0] = 0xf3;
		pchMessageStart[1] = 0xe9;
		pchMessageStart[2] = 0xee;
		pchMessageStart[3] = 0xe1;

        nDefaultPort = 8168;
        nPruneAfterHeight = 100000;
        /**
         * btzc: firo init genesis block
         * nBits = 0x1e0ffff0
         * nTime = 1414776286
         * nNonce = 142392
         * genesisReward = 0 * COIN
         * nVersion = 2
         * extraNonce
         */
        std::vector<unsigned char> extraNonce(4);
        extraNonce[0] = 0x82;
        extraNonce[1] = 0x3f;
        extraNonce[2] = 0x00;
        extraNonce[3] = 0x00;

		//FindNewGenesisBlock(consensus, ZC_GENESIS_BLOCK_TIME, 1131195, 0x1e0ffff0, 2, 0 * COIN, extraNonce);

		genesis = CreateGenesisBlock(ZC_GENESIS_BLOCK_TIME, 1131195, 0x1e0ffff0, 2, 0 * COIN, extraNonce);

		//const std::string s = genesis.GetHash().ToString();
        consensus.hashGenesisBlock = genesis.GetHash();
		assert(consensus.hashGenesisBlock == uint256S("0x92c629049199da08fb0dfb97ff70a9bc80d9b3d0c871b03006ac435ff4ee8458"));
		assert(genesis.hashMerkleRoot == uint256S("0x4259fb7aa840ddbe19be3bd58e0de87373888adc137bb2d587ea4f4e2b973b56"));
		vFixedSeeds.clear();
		vSeeds.clear();

		vSeeds.push_back(CDNSSeedData("176.57.208.134", "176.57.208.134", false));
		vSeeds.push_back(CDNSSeedData("176.57.214.165", "176.57.214.165", false));
		vSeeds.push_back(CDNSSeedData("176.57.214.204", "176.57.214.204", false));
		vSeeds.push_back(CDNSSeedData("109.68.215.87", "109.68.215.87", false));

		vSeeds.push_back(CDNSSeedData("109.68.214.148", "109.68.214.148", false));
		vSeeds.push_back(CDNSSeedData("109.68.214.156", "109.68.214.156", false));
		vSeeds.push_back(CDNSSeedData("109.68.214.31", "109.68.214.31", false));

        // Note that of those with the service bits flag, most only support a subset of possible options
		base58Prefixes[PUBKEY_ADDRESS] = std::vector < unsigned char > (1, 73);
		base58Prefixes[SCRIPT_ADDRESS] = std::vector < unsigned char > (1, 53);
		base58Prefixes[SECRET_KEY] = std::vector < unsigned char > (1, 210);
		base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container < std::vector < unsigned char > > ();
		base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container < std::vector < unsigned char > > ();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

		fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fAllowMultiplePorts = false;

        checkpointData = (CCheckpointData) {
                boost::assign::map_list_of
				(0, uint256S("0x0"))
        };

        chainTxData = ChainTxData{
				ZC_GENESIS_BLOCK_TIME, // * UNIX timestamp of last checkpoint block
				0,     // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
				0.001       // * estimated number of transactions per second after checkpoint
        };

        // Sigma related values.
		consensus.nSigmaStartBlock = INT_MAX;
		consensus.nSigmaPaddingBlock = INT_MAX;
		consensus.nDisableUnpaddedSigmaBlock = INT_MAX;
		consensus.nStartSigmaBlacklist = INT_MAX;
		consensus.nRestartSigmaWithBlacklistCheck = INT_MAX;
		consensus.nOldSigmaBanBlock = 0;

		consensus.nLelantusStartBlock = INT_MAX;
		consensus.nLelantusFixesStartBlock = 0;

        consensus.nMaxSigmaInputPerBlock = ZC_SIGMA_INPUT_LIMIT_PER_BLOCK;
        consensus.nMaxValueSigmaSpendPerBlock = ZC_SIGMA_VALUE_SPEND_LIMIT_PER_BLOCK;
        consensus.nMaxSigmaInputPerTransaction = ZC_SIGMA_INPUT_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueSigmaSpendPerTransaction = ZC_SIGMA_VALUE_SPEND_LIMIT_PER_TRANSACTION;
        consensus.nMaxLelantusInputPerBlock = ZC_LELANTUS_INPUT_LIMIT_PER_BLOCK;
        consensus.nMaxValueLelantusSpendPerBlock = ZC_LELANTUS_VALUE_SPEND_LIMIT_PER_BLOCK;
        consensus.nMaxLelantusInputPerTransaction = ZC_LELANTUS_INPUT_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueLelantusSpendPerTransaction = ZC_LELANTUS_VALUE_SPEND_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueLelantusMint = ZC_LELANTUS_MAX_MINT;
        consensus.nZerocoinToSigmaRemintWindowSize = 50000;

        for (const auto& str : lelantus::lelantus_blacklist) {
            GroupElement coin;
            try {
                coin.deserialize(ParseHex(str).data());
            } catch (...) {
                continue;
            }
            consensus.lelantusBlacklist.insert(coin);
        }

        for (const auto& str : sigma::sigma_blacklist) {
            GroupElement coin;
            try {
                coin.deserialize(ParseHex(str).data());
            } catch (...) {
                continue;
            }
            consensus.sigmaBlacklist.insert(coin);
        }

		consensus.evoSporkKeyID = "";
		consensus.nEvoSporkStartBlock = 1;
		consensus.nEvoSporkStopBlock = INT_MAX;  // two years after lelantus
        consensus.nEvoSporkStopBlockExtensionVersion = 140903;
		consensus.nEvoSporkStopBlockPrevious = 0; // one year after lelantus
        consensus.nEvoSporkStopBlockExtensionGracefulPeriod = 24*12*14; // two weeks

        // reorg
        consensus.nMaxReorgDepth = 5;
		consensus.nMaxReorgDepthEnforcementBlock = INT_MAX;

        // whitelist
		//consensus.txidWhitelist.insert(uint256S("3ecea345c7b174271bbdcde8cad6097d9a3dc420259743d52cc9cf1945aaba03"));

        // Dandelion related values.
        consensus.nDandelionEmbargoMinimum = DANDELION_EMBARGO_MINIMUM;
        consensus.nDandelionEmbargoAvgAdd = DANDELION_EMBARGO_AVG_ADD;
        consensus.nDandelionMaxDestinations = DANDELION_MAX_DESTINATIONS;
        consensus.nDandelionShuffleInterval = DANDELION_SHUFFLE_INTERVAL;
        consensus.nDandelionFluff = DANDELION_FLUFF;

        // Bip39
		consensus.nMnemonicBlock = 1;

        // moving lelantus data to v3 payload
		consensus.nLelantusV3PayloadStartBlock = INT_MAX;
    }
    virtual bool SkipUndoForBlock(int nHeight) const
    {
		return false;
    }
    virtual bool ApplyUndoForTxout(int nHeight, uint256 const & txid, int n) const
    {
        // We only apply first 23 tx inputs UNDOs for the tx 7702 in block 293526
		/*if (!SkipUndoForBlock(nHeight)) {
            return true;
        }
        static std::map<uint256, int> const txs = { {uint256S("7702eaa0e042846d39d01eeb4c87f774913022e9958cfd714c5c2942af380569"), 22} };
        std::map<uint256, int>::const_iterator const itx = txs.find(txid);
        if (itx == txs.end()) {
            return false;
        }
        if (n <= itx->second) {
            return true;
		}*/
        return false;
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

        consensus.chainType = Consensus::chainTestnet;

		// 1 day after start
		consensus.nFirstSubsidyHalvingEndPeriod = ZC_GENESIS_BLOCK_TIME;
		consensus.nFirstSubsidyHalvingValue = 20;

		// 2 day
		consensus.nSecondSubsidyHalvingEndPeriod = ZC_GENESIS_BLOCK_TIME + 3 * 60 * 60;
		consensus.nSecondSubsidyHalvingValue = 10;

		// 3 day
		consensus.nThirdSubsidyHalvingEndPeriod = ZC_GENESIS_BLOCK_TIME + 6 * 60 * 60;
		consensus.nThirdSubsidyHalvingValue = 5;

		consensus.nSubsidyHalvingMinersShare = 80;
		consensus.nSubsidyHalvingNodesShare = 20;
		consensus.nSubsidyHalvingDevelopShare = 50;

		consensus.subsidyDevelopFundAddress = "wLfc3v5iSKbL172oyyN6ZD2LiP13AdHkRD";

		// wn8 end

		consensus.nStartDuplicationCheck = 1;
        consensus.nMinNFactor = 10;
        consensus.nMaxNFactor = 30;

        consensus.powLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 60 * 60; // 60 minutes between retargets
		consensus.nPowTargetSpacing = 2.5 * 60; // 5 minute blocks
		consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
		consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0; // January 1, 2008
		consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 0; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
		consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0; // March 1st, 2016
		consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
		consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0; // May 1st 2016
		consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0; // May 1st 2017

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000708f98bf623f02e");

        // By default assume that the signatures in ancestors of this block are valid.
		consensus.defaultAssumeValid.SetNull();

        // Znode params testnet
        //consensus.nZnodePaymentsIncreaseBlock = 360; // not used for now, probably later
        //consensus.nZnodePaymentsIncreasePeriod = 650; // not used for now, probably later
        //consensus.nSuperblockStartBlock = 61000;
        //consensus.nBudgetPaymentsStartBlock = 60000;
        //consensus.nBudgetPaymentsCycleBlocks = 50;
        //consensus.nBudgetPaymentsWindowBlocks = 10;
		nMaxTipAge = 24 * 60 * 60; // allow mining on top of old blocks for testnet

        // evo znodes
		consensus.DIP0003Height = 1;
		consensus.DIP0003EnforcementHeight = 1;
        consensus.DIP0003EnforcementHash.SetNull();

		consensus.DIP0008Height = 1;
		consensus.nEvoZnodeMinimumConfirmations = 15;

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_10_70] = llmq10_70;
        consensus.llmqs[Consensus::LLMQ_50_60] = llmq50_60;
        consensus.llmqs[Consensus::LLMQ_400_60] = llmq400_60;
        consensus.llmqs[Consensus::LLMQ_400_85] = llmq400_85;
        consensus.nLLMQPowTargetSpacing = 20;
        consensus.llmqChainLocks = Consensus::LLMQ_10_70;
        consensus.llmqForInstantSend = Consensus::LLMQ_10_70;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nInstantSendBlockFilteringStartHeight = 48136;

		consensus.nMTPSwitchTime = INT_MAX;
		consensus.nFixedDifficulty = 0x1d016e81;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
		strZnodePaymentsPubKey = "0443d353e99e34f29128f2faee3adc2ec74a6c8d0b8041fa4e07a73f5852de806bb18506ff29f0f40f4273c13d9bda09f0f497f0e64c9e68c5468454afd7a23cd6";

		pchMessageStart[0] = 0xdf;
		pchMessageStart[1] = 0xec;
		pchMessageStart[2] = 0xce;
		pchMessageStart[3] = 0xfa;

        nDefaultPort = 18168;
        nPruneAfterHeight = 1000;

        /**
         * btzc: testnet params
         * nTime: 1414776313
         * nNonce: 1620571
         */
        std::vector<unsigned char> extraNonce(4);
        extraNonce[0] = 0x09;
        extraNonce[1] = 0x00;
        extraNonce[2] = 0x00;
        extraNonce[3] = 0x00;

		//FindNewGenesisBlock(consensus, ZC_GENESIS_BLOCK_TIME + 1, 751902, 0x1e0ffff0, 2, 0 * COIN, extraNonce);

		genesis = CreateGenesisBlock(ZC_GENESIS_BLOCK_TIME + 1, 751902, 0x1e0ffff0, 2, 0 * COIN, extraNonce);

        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock ==
				uint256S("0xc9dbeb282a2f295a1e02f5372a9b1e17a8bb7da4babf42cc91362a8cba9bb724"));
        assert(genesis.hashMerkleRoot ==
				uint256S("0xc624f99113356855bd15a815d7d3af60f61f445962eb915f6805a6e7ffc90c02"));

        vFixedSeeds.clear();
        vSeeds.clear();

		vSeeds.push_back(CDNSSeedData("176.57.208.134", "176.57.208.134", false));
		vSeeds.push_back(CDNSSeedData("176.57.214.165", "176.57.214.165", false));
		vSeeds.push_back(CDNSSeedData("176.57.214.204", "176.57.214.204", false));
		vSeeds.push_back(CDNSSeedData("109.68.215.87", "109.68.215.87", false));

		vSeeds.push_back(CDNSSeedData("109.68.214.148", "109.68.214.148", false));
		vSeeds.push_back(CDNSSeedData("109.68.214.156", "109.68.214.156", false));
		vSeeds.push_back(CDNSSeedData("109.68.214.31", "109.68.214.31", false));

		base58Prefixes[PUBKEY_ADDRESS] = std::vector < unsigned char > (1, 135);
		base58Prefixes[SCRIPT_ADDRESS] = std::vector < unsigned char > (1, 112);
		base58Prefixes[SECRET_KEY] = std::vector < unsigned char > (1, 185);
		base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container < std::vector < unsigned char > > ();
		base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container < std::vector < unsigned char > > ();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

		fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fAllowMultiplePorts = true;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, uint256S("0x"))
        };

        chainTxData = ChainTxData{
			ZC_GENESIS_BLOCK_TIME + 1,
            0,
            0.001
        };

        // Sigma related values.
		consensus.nSigmaStartBlock = INT_MAX;
		consensus.nSigmaPaddingBlock = INT_MAX;
		consensus.nDisableUnpaddedSigmaBlock = INT_MAX;
        consensus.nStartSigmaBlacklist = INT_MAX;
        consensus.nRestartSigmaWithBlacklistCheck = INT_MAX;
		consensus.nOldSigmaBanBlock = 0;

		consensus.nLelantusStartBlock = INT_MAX;
		consensus.nLelantusFixesStartBlock = INT_MAX;

        consensus.nMaxSigmaInputPerBlock = ZC_SIGMA_INPUT_LIMIT_PER_BLOCK;
        consensus.nMaxValueSigmaSpendPerBlock = ZC_SIGMA_VALUE_SPEND_LIMIT_PER_BLOCK;
        consensus.nMaxSigmaInputPerTransaction = ZC_SIGMA_INPUT_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueSigmaSpendPerTransaction = ZC_SIGMA_VALUE_SPEND_LIMIT_PER_TRANSACTION;
        consensus.nMaxLelantusInputPerBlock = ZC_LELANTUS_INPUT_LIMIT_PER_BLOCK;
        consensus.nMaxValueLelantusSpendPerBlock = 1100 * COIN;
        consensus.nMaxLelantusInputPerTransaction = ZC_LELANTUS_INPUT_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueLelantusSpendPerTransaction = 1001 * COIN;
        consensus.nMaxValueLelantusMint = 1001 * COIN;
        consensus.nZerocoinToSigmaRemintWindowSize = 0;

        for (const auto& str : lelantus::lelantus_testnet_blacklist) {
            GroupElement coin;
            try {
                coin.deserialize(ParseHex(str).data());
            } catch (...) {
                continue;
            }
            consensus.lelantusBlacklist.insert(coin);
        }

        consensus.evoSporkKeyID = "TWSEa1UsZzDHywDG6CZFDNdeJU6LzhbbBL";
		consensus.nEvoSporkStartBlock = 1;
		consensus.nEvoSporkStopBlock = INT_MAX;
        consensus.nEvoSporkStopBlockExtensionVersion = 0;

        // reorg
        consensus.nMaxReorgDepth = 4;
        consensus.nMaxReorgDepthEnforcementBlock = 25150;

        // whitelist
		//consensus.txidWhitelist.insert(uint256S("44b3829117bd248544c71b430d585cb88b4ce156a7d4fdb9ef3ae96efa8f09d3"));

        // Dandelion related values.
        consensus.nDandelionEmbargoMinimum = DANDELION_TESTNET_EMBARGO_MINIMUM;
        consensus.nDandelionEmbargoAvgAdd = DANDELION_TESTNET_EMBARGO_AVG_ADD;
        consensus.nDandelionMaxDestinations = DANDELION_MAX_DESTINATIONS;
        consensus.nDandelionShuffleInterval = DANDELION_SHUFFLE_INTERVAL;
        consensus.nDandelionFluff = DANDELION_FLUFF;

        // Bip39
        consensus.nMnemonicBlock = 1;

        // moving lelantus data to v3 payload
		consensus.nLelantusV3PayloadStartBlock = INT_MAX;
        
    }
};

static CTestNetParams testNetParams;

/**
 * Devnet (testnet for experimental stuff)
 */
class CDevNetParams : public CChainParams {
public:
    CDevNetParams() {
        strNetworkID = "dev";

        consensus.chainType = Consensus::chainDevnet;

		// 1 day after start
		consensus.nFirstSubsidyHalvingEndPeriod = ZC_GENESIS_BLOCK_TIME + 24 * 60 * 60;
		consensus.nFirstSubsidyHalvingValue = 20;

		// 2 day
		consensus.nSecondSubsidyHalvingEndPeriod = ZC_GENESIS_BLOCK_TIME + 2 * 24 * 60 * 60;
		consensus.nSecondSubsidyHalvingValue = 10;

		// 3 day
		consensus.nThirdSubsidyHalvingEndPeriod = ZC_GENESIS_BLOCK_TIME + 3 * 24 * 60 * 60;
		consensus.nThirdSubsidyHalvingValue = 5;

		consensus.nSubsidyHalvingMinersShare = 80;
		consensus.nSubsidyHalvingNodesShare = 20;
		consensus.nSubsidyHalvingDevelopShare = 50;

		consensus.subsidyDevelopFundAddress = "waXMVL9Dty9msGY5H3K24TuJSXqybojeXk";
		// end wn8

		consensus.nStartDuplicationCheck = 1;

        consensus.nMinNFactor = 10;
        consensus.nMaxNFactor = 30;

        consensus.powLimit = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 60 * 60; // 60 minutes between retargets
		consensus.nPowTargetSpacing = 2.5 * 60; // 5 minute blocks
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
		consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0; // January 1, 2008
		consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 0; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
		consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0; // March 1st, 2016
		consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
		consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0; // May 1st 2016
		consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0; // May 1st 2017

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000708f98bf623f02e");

        // By default assume that the signatures in ancestors of this block are valid.
		consensus.defaultAssumeValid.SetNull();

        // Znode params testnet
		nMaxTipAge = 24 * 60 * 60; // allow mining on top of old blocks for testnet

        // evo znodes
		consensus.DIP0003Height = 2;
		consensus.DIP0003EnforcementHeight = 2;
        consensus.DIP0003EnforcementHash.SetNull();

		consensus.DIP0008Height = 1;
        consensus.nEvoZnodeMinimumConfirmations = 0;

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_5_60] = llmq5_60;
        consensus.llmqs[Consensus::LLMQ_10_70] = llmq10_70;
        consensus.nLLMQPowTargetSpacing = 20;
        consensus.llmqChainLocks = Consensus::LLMQ_5_60;
        consensus.llmqForInstantSend = Consensus::LLMQ_5_60;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nInstantSendBlockFilteringStartHeight = 1000;

		consensus.nMTPSwitchTime = INT_MAX;
		consensus.nFixedDifficulty = 0x1d016e81;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

		pchMessageStart[0] = 0xdf;
		pchMessageStart[1] = 0xec;
		pchMessageStart[2] = 0xae;
		pchMessageStart[3] = 0xdb;

        nDefaultPort = 38168;
        nPruneAfterHeight = 1000;

        std::vector<unsigned char> extraNonce(4);
        extraNonce[0] = 0x0a;
        extraNonce[1] = 0x00;
        extraNonce[2] = 0x00;
        extraNonce[3] = 0x00;

		//FindNewGenesisBlock(consensus, ZC_GENESIS_BLOCK_TIME + 2, 240007, 0x1e0ffff0, 2, 0 * COIN, extraNonce);

		genesis = CreateGenesisBlock(ZC_GENESIS_BLOCK_TIME + 2, 240007, 0x1e0ffff0, 2, 0 * COIN, extraNonce);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
				uint256S("0x8a8db65fb35577268f11b3359cc8db4c646229ab2480a68cf103b4663511556b"));
        assert(genesis.hashMerkleRoot ==
				uint256S("0x4334c59662ec403f0388799f2b6efea9f5ef8fab391828d44ecd357abe8f0cc8"));
        vFixedSeeds.clear();
        vSeeds.clear();

		vSeeds.push_back(CDNSSeedData("176.57.208.134", "176.57.208.134", false));
		vSeeds.push_back(CDNSSeedData("176.57.214.165", "176.57.214.165", false));
		vSeeds.push_back(CDNSSeedData("176.57.214.204", "176.57.214.204", false));
		vSeeds.push_back(CDNSSeedData("109.68.215.87", "109.68.215.87", false));


		vSeeds.push_back(CDNSSeedData("109.68.214.148", "109.68.214.148", false));
		vSeeds.push_back(CDNSSeedData("109.68.214.156", "109.68.214.156", false));
		vSeeds.push_back(CDNSSeedData("109.68.214.31", "109.68.214.31", false));

		base58Prefixes[PUBKEY_ADDRESS] = std::vector < unsigned char > (1, 135);
		base58Prefixes[SCRIPT_ADDRESS] = std::vector < unsigned char > (1, 112);
		base58Prefixes[SECRET_KEY] = std::vector < unsigned char > (1, 186);
		base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xD0).convert_to_container < std::vector < unsigned char > > ();
		base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x95).convert_to_container < std::vector < unsigned char > > ();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_dev, pnSeed6_dev + ARRAYLEN(pnSeed6_dev));

		fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fAllowMultiplePorts = true;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, uint256S("0x"))
        };

        chainTxData = ChainTxData{
            1414776313,
            0,
            0.001
        };

        // Sigma related values.
        consensus.nSigmaStartBlock = 1;
        consensus.nSigmaPaddingBlock = 1;
        consensus.nDisableUnpaddedSigmaBlock = 1;
        consensus.nStartSigmaBlacklist = INT_MAX;
        consensus.nRestartSigmaWithBlacklistCheck = INT_MAX;
        consensus.nOldSigmaBanBlock = 1;

		consensus.nLelantusStartBlock = INT_MAX;
        consensus.nLelantusFixesStartBlock = 1;

        consensus.nMaxSigmaInputPerBlock = ZC_SIGMA_INPUT_LIMIT_PER_BLOCK;
        consensus.nMaxValueSigmaSpendPerBlock = ZC_SIGMA_VALUE_SPEND_LIMIT_PER_BLOCK;
        consensus.nMaxSigmaInputPerTransaction = ZC_SIGMA_INPUT_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueSigmaSpendPerTransaction = ZC_SIGMA_VALUE_SPEND_LIMIT_PER_TRANSACTION;
        consensus.nMaxLelantusInputPerBlock = ZC_LELANTUS_INPUT_LIMIT_PER_BLOCK;
        consensus.nMaxValueLelantusSpendPerBlock = 1100 * COIN;
        consensus.nMaxLelantusInputPerTransaction = ZC_LELANTUS_INPUT_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueLelantusSpendPerTransaction = 1001 * COIN;
        consensus.nMaxValueLelantusMint = 1001 * COIN;
        consensus.nZerocoinToSigmaRemintWindowSize = 0;

        consensus.evoSporkKeyID = "TdxR3tfoHiQUkowcfjEGiMBfk6GXFdajUA";
        consensus.nEvoSporkStartBlock = 1;
		consensus.nEvoSporkStopBlock = INT_MAX;
        consensus.nEvoSporkStopBlockExtensionVersion = 0;

        // reorg
        consensus.nMaxReorgDepth = 4;
        consensus.nMaxReorgDepthEnforcementBlock = 25150;

        // whitelist

        // Dandelion related values.
        consensus.nDandelionEmbargoMinimum = DANDELION_TESTNET_EMBARGO_MINIMUM;
        consensus.nDandelionEmbargoAvgAdd = DANDELION_TESTNET_EMBARGO_AVG_ADD;
        consensus.nDandelionMaxDestinations = DANDELION_MAX_DESTINATIONS;
        consensus.nDandelionShuffleInterval = DANDELION_SHUFFLE_INTERVAL;
        consensus.nDandelionFluff = DANDELION_FLUFF;

        // Bip39
        consensus.nMnemonicBlock = 1;

        // moving lelantus data to v3 payload
		consensus.nLelantusV3PayloadStartBlock = INT_MAX;
    }
};

static CDevNetParams devNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";

        consensus.chainType = Consensus::chainRegtest;

		// 1 day after start
		consensus.nFirstSubsidyHalvingEndPeriod = ZC_GENESIS_BLOCK_TIME + 24 * 60 * 60;
		consensus.nFirstSubsidyHalvingValue = 20;

		// 2 day
		consensus.nSecondSubsidyHalvingEndPeriod = ZC_GENESIS_BLOCK_TIME + 2 * 24 * 60 * 60;
		consensus.nSecondSubsidyHalvingValue = 10;

		// 3 day
		consensus.nThirdSubsidyHalvingEndPeriod = ZC_GENESIS_BLOCK_TIME + 3 * 24 * 60 * 60;
		consensus.nThirdSubsidyHalvingValue = 5;

		consensus.nSubsidyHalvingMinersShare = 80;
		consensus.nSubsidyHalvingNodesShare = 20;
		consensus.nSubsidyHalvingDevelopShare = 50;

		consensus.subsidyDevelopFundAddress = "waXMVL9Dty9msGY5H3K24TuJSXqybojeXk";

		// wn8 end

		consensus.nStartDuplicationCheck = 1;

        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
		consensus.nPowTargetTimespan = 60 * 60; // 60 minutes between retargets
		consensus.nPowTargetSpacing = 2.5 * 60; // 10 minute blocks
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
		consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 0;

        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
		consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0;

        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
		consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
		consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0;

        // Znode code
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin

        // evo znodes
		consensus.DIP0003Height = 2;
		consensus.DIP0003EnforcementHeight = 2;
        consensus.DIP0003EnforcementHash.SetNull();

		consensus.DIP0008Height = 1;
        consensus.nEvoZnodeMinimumConfirmations = 1;

        // long living quorum params
        consensus.llmqs[Consensus::LLMQ_5_60] = llmq5_60;
        consensus.llmqs[Consensus::LLMQ_50_60] = llmq50_60;
        consensus.llmqs[Consensus::LLMQ_400_60] = llmq400_60;
        consensus.llmqs[Consensus::LLMQ_400_85] = llmq400_85;
        consensus.nLLMQPowTargetSpacing = 1;
        consensus.llmqChainLocks = Consensus::LLMQ_5_60;
        consensus.llmqForInstantSend = Consensus::LLMQ_5_60;
        consensus.nInstantSendConfirmationsRequired = 2;
        consensus.nInstantSendKeepLock = 6;
        consensus.nInstantSendBlockFilteringStartHeight = 800;

		consensus.nMTPSwitchTime = INT_MAX;

		consensus.nFixedDifficulty = 0x1d016e81;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
		consensus.defaultAssumeValid.SetNull();

		pchMessageStart[0] = 0xea;
		pchMessageStart[1] = 0xcf;
		pchMessageStart[2] = 0xa5;
		pchMessageStart[3] = 0xea;

        nDefaultPort = 18444;

        nPruneAfterHeight = 1000;

        std::vector<unsigned char> extraNonce(4);
        extraNonce[0] = 0x08;
        extraNonce[1] = 0x00;
        extraNonce[2] = 0x00;
        extraNonce[3] = 0x00;

		//FindNewGenesisBlock(consensus, ZC_GENESIS_BLOCK_TIME + 4, 1, 0x207fffff, 2, 0 * COIN, extraNonce);

        genesis = CreateGenesisBlock(ZC_GENESIS_BLOCK_TIME + 4, 1, 0x207fffff, 2, 0 * COIN, extraNonce);
        consensus.hashGenesisBlock = genesis.GetHash();

		assert(consensus.hashGenesisBlock == uint256S("0x95d012235a4549e1b7fe508a976c756bb02685774ddbe7fdd608d8508993b11f"));
		assert(genesis.hashMerkleRoot == uint256S("0xd8f92d0683130d850a9c85e69182ac435b948f02f68e066ab1a339ac060a1e29"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

		vSeeds.push_back(CDNSSeedData("176.57.208.134", "176.57.208.134", false));
		vSeeds.push_back(CDNSSeedData("176.57.214.165", "176.57.214.165", false));
		vSeeds.push_back(CDNSSeedData("176.57.214.204", "176.57.214.204", false));
		vSeeds.push_back(CDNSSeedData("109.68.215.87", "109.68.215.87", false));

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fAllowMultiplePorts = true;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
			(0, uint256S("0x00"))
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };


		base58Prefixes[PUBKEY_ADDRESS] = std::vector < unsigned char > (1, 135);
		base58Prefixes[SCRIPT_ADDRESS] = std::vector < unsigned char > (1, 112);
		base58Prefixes[SECRET_KEY] = std::vector < unsigned char > (1, 239);
		base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container < std::vector < unsigned char > > ();
		base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container < std::vector < unsigned char > > ();

        // Sigma related values.
		consensus.nSigmaStartBlock = INT_MAX;
		consensus.nSigmaPaddingBlock = INT_MAX;
		consensus.nDisableUnpaddedSigmaBlock = INT_MAX;
        consensus.nStartSigmaBlacklist = INT_MAX;
        consensus.nRestartSigmaWithBlacklistCheck = INT_MAX;
		consensus.nOldSigmaBanBlock = 0;
		consensus.nLelantusStartBlock = INT_MAX;
		consensus.nLelantusFixesStartBlock = INT_MAX;
        consensus.nMaxSigmaInputPerBlock = ZC_SIGMA_INPUT_LIMIT_PER_BLOCK;
        consensus.nMaxValueSigmaSpendPerBlock = ZC_SIGMA_VALUE_SPEND_LIMIT_PER_BLOCK;
        consensus.nMaxSigmaInputPerTransaction = ZC_SIGMA_INPUT_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueSigmaSpendPerTransaction = ZC_SIGMA_VALUE_SPEND_LIMIT_PER_TRANSACTION;
        consensus.nMaxLelantusInputPerBlock = ZC_LELANTUS_INPUT_LIMIT_PER_BLOCK;
        consensus.nMaxValueLelantusSpendPerBlock = ZC_LELANTUS_VALUE_SPEND_LIMIT_PER_BLOCK;
        consensus.nMaxLelantusInputPerTransaction = ZC_LELANTUS_INPUT_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueLelantusSpendPerTransaction = ZC_LELANTUS_VALUE_SPEND_LIMIT_PER_TRANSACTION;
        consensus.nMaxValueLelantusMint = ZC_LELANTUS_MAX_MINT;
        consensus.nZerocoinToSigmaRemintWindowSize = 1000;

        // evo spork
        consensus.evoSporkKeyID = "TSpmHGzQT4KJrubWa4N2CRmpA7wKMMWDg4";  // private key is cW2YM2xaeCaebfpKguBahUAgEzLXgSserWRuD29kSyKHq1TTgwRQ
		consensus.nEvoSporkStartBlock = 1;
		consensus.nEvoSporkStopBlock = INT_MAX;
        consensus.nEvoSporkStopBlockExtensionVersion = 0;

        // reorg
        consensus.nMaxReorgDepth = 4;
        consensus.nMaxReorgDepthEnforcementBlock = 300;

        // Dandelion related values.
        consensus.nDandelionEmbargoMinimum = 0;
        consensus.nDandelionEmbargoAvgAdd = 1;
        consensus.nDandelionMaxDestinations = DANDELION_MAX_DESTINATIONS;
        consensus.nDandelionShuffleInterval = DANDELION_SHUFFLE_INTERVAL;
        consensus.nDandelionFluff = DANDELION_FLUFF;

        // Bip39
		consensus.nMnemonicBlock = 1;

        // moving lelantus data to v3 payload
		consensus.nLelantusV3PayloadStartBlock = INT_MAX;
        
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
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
    else if (chain == CBaseChainParams::DEVNET)
            return devNetParams;
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

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}

