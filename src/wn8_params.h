#ifndef FIRO_PARAMS_H
#define FIRO_PARAMS_H

/** Dust Soft Limit, allowed with additional fee per output */
//static const int64_t DUST_SOFT_LIMIT = 100000; // 0.001 FIRO
/** Dust Hard Limit, ignored as wallet inputs (mininput default) */
static const int64_t DUST_HARD_LIMIT = 1000;   // 0.00001 FIRO mininput

// limit of coins number per id in spend v3.0
#define ZC_SPEND_V3_COINSPERID_LIMIT    16000

// number of mint confirmations needed to spend coin
#define ZC_MINT_CONFIRMATIONS               1

// Genesis block timestamp
#define ZC_GENESIS_BLOCK_TIME               1655870400 //1414776287

#define SWITCH_TO_MTP_BLOCK_HEADER			1655870400 // 2018 December 10th 12:00 UTC

// Number of zerocoin spends allowed per block and per transaction
#define ZC_SPEND_LIMIT         5

// Value of sigma spends allowed per block
#define ZC_SIGMA_VALUE_SPEND_LIMIT_PER_BLOCK  (600 * COIN)

// Amount of sigma spends allowed per block
#define ZC_SIGMA_INPUT_LIMIT_PER_BLOCK         50

// Value of sigma spends allowed per transaction
#define ZC_SIGMA_VALUE_SPEND_LIMIT_PER_TRANSACTION     (500 * COIN)

// Amount of sigma spends allowed per transaction
#define ZC_SIGMA_INPUT_LIMIT_PER_TRANSACTION            35

// Value of lelantus spends allowed per block
#define ZC_LELANTUS_VALUE_SPEND_LIMIT_PER_BLOCK  (5100 * COIN)

// Amount of lelantus spends allowed per block
#define ZC_LELANTUS_INPUT_LIMIT_PER_BLOCK         100

// Value of lelantus spends allowed per transaction
#define ZC_LELANTUS_VALUE_SPEND_LIMIT_PER_TRANSACTION     (5001 * COIN)

// Amount of lelantus spends allowed per transaction
#define ZC_LELANTUS_INPUT_LIMIT_PER_TRANSACTION            50

// Maximum amount of lelantus mint
#define ZC_LELANTUS_MAX_MINT            (5001 * COIN)

// Number of zerocoin mints allowed per transaction
#define ZC_MINT_LIMIT         100

/** Maximum number of outbound peers designated as Dandelion destinations */
#define DANDELION_MAX_DESTINATIONS 2

/** Expected time between Dandelion routing shuffles (in seconds). */
#define DANDELION_SHUFFLE_INTERVAL 600

/** The minimum amount of time a Dandelion transaction is embargoed (seconds) */
#define DANDELION_EMBARGO_MINIMUM 10
#define DANDELION_TESTNET_EMBARGO_MINIMUM 1

/** The average additional embargo time beyond the minimum amount (seconds) */
#define DANDELION_EMBARGO_AVG_ADD 20
#define DANDELION_TESTNET_EMBARGO_AVG_ADD 1

/** Probability (percentage) that a Dandelion transaction enters fluff phase */
#define DANDELION_FLUFF 10

// Versions of zerocoin mint/spend transactions
#define ZEROCOIN_TX_VERSION_3               30
#define ZEROCOIN_TX_VERSION_3_1             31
#define LELANTUS_TX_VERSION_4               40
#define SIGMA_TO_LELANTUS_JOINSPLIT         41
#define LELANTUS_TX_VERSION_4_5             45
#define SIGMA_TO_LELANTUS_JOINSPLIT_FIXED   46
#define LELANTUS_TX_TPAYLOAD                47
#define SIGMA_TO_LELANTUS_TX_TPAYLOAD       48

#define ZEROCOIN_PUBLICKEY_TO_SERIALNUMBER  "PUBLICKEY_TO_SERIALNUMBER"

#endif
