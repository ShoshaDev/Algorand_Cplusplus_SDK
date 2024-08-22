/*
 * Copyright (c) 2021 Vertices Network <cyril@vertices.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef VERTICES_CONFIG_VERTICES_CONFIG_H
#define VERTICES_CONFIG_VERTICES_CONFIG_H

#define ALGOEXPLORER    1
#define PURESTAKE       2
#define LOCAL           3

#ifndef API_PROVIDER
#define API_PROVIDER    ALGOEXPLORER
#endif

#define TESTNET_ALGONODE_API                "https://testnet-api.algonode.cloud"
#define TESTNET_ALGOEXPLORER_API            "https://node.testnet.algoexplorerapi.io"
#define TESTNET_PURESTAKE_API               "https://testnet-algorand.api.purestake.io/ps2"
#define TESTNET_LOCAL_API                   "localhost"

#define TESTNET_ALGONODE_INDEXER_API                "https://testnet-idx.algonode.network"
#define TESTNET_ALGOEXPLORER_INDEXER_API            "https://node.testnet.algoexplorerapi.io"
#define TESTNET_PURESTAKE_INDEXER_API               "https://testnet-algorand.api.purestake.io/idx2"
#define TESTNET_LOCAL_INDEXER_API                   "localhost"

#define TESTNET_ALGONODE_PORT           443
#define TESTNET_ALGOEXPLORER_PORT       0
#define TESTNET_PURESTAKE_PORT          0
#define TESTNET_LOCAL_PORT              8080

#define TESTNET_ALGONODE_AUTH_HEADER        ""
#define TESTNET_ALGOEXPLORER_AUTH_HEADER    ""
#define TESTNET_PURESTAKE_AUTH_HEADER       "x-api-key:"
#define TESTNET_LOCAL_AUTH_HEADER           "X-Algo-API-Token:"

#define  TESTNET_ALGONODE_API_TOKEN        ""
#define  TESTNET_ALGOEXPLORER_API_TOKEN    ""

#if API_PROVIDER==PURESTAKE
#include "private_config.h"

#ifndef TESTNET_PURESTAKE_API_TOKEN
#error Purestake needs a token. Please define TESTNET_PURESTAKE_API_TOKEN in private_config.h
#endif

#define SERVER_URL              TESTNET_PURESTAKE_API
#define SERVER_PORT             TESTNET_PURESTAKE_PORT
#define SERVER_TOKEN_HEADER     (TESTNET_PURESTAKE_AUTH_HEADER TESTNET_PURESTAKE_API_TOKEN)

#elif API_PROVIDER==LOCAL

#include "private_config.h"

#ifndef TESTNET_LOCAL_API_TOKEN
#error Local node needs a token. Please define TESTNET_LOCAL_API_TOKEN in private_config.h
#endif

#define SERVER_URL              TESTNET_LOCAL_API
#define SERVER_PORT             TESTNET_LOCAL_PORT
#define SERVER_TOKEN_HEADER     (TESTNET_LOCAL_AUTH_HEADER TESTNET_LOCAL_API_TOKEN)

#else

// default provider is AlgoExplorer

#define SERVER_NODE_URL              TESTNET_ALGONODE_API
#define SERVER_INDEXER_URL           TESTNET_ALGONODE_INDEXER_API
#define SERVER_PORT             TESTNET_ALGONODE_PORT
#define SERVER_TOKEN_HEADER     (TESTNET_ALGONODE_AUTH_HEADER TESTNET_ALGONODE_API_TOKEN)
#endif

#define ACCOUNT_RECEIVER "LCKVRVM2MJ7RAJZKPAXUCEC4GZMYNTFMLHJTV2KF6UGNXUFQFIIMSXRVM4"
#define ACCOUNT_MANAGER "NBRUQXLMEJDQLHE5BBEFBQ3FF4F3BZYWCUBBQM67X6EOEW2WHGS764OQXE"
#define ACCOUNT_RESERVE "NBRUQXLMEJDQLHE5BBEFBQ3FF4F3BZYWCUBBQM67X6EOEW2WHGS764OQXE"
#define ACCOUNT_FREEZE "NBRUQXLMEJDQLHE5BBEFBQ3FF4F3BZYWCUBBQM67X6EOEW2WHGS764OQXE"
#define ACCOUNT_CLAWBACK "NBRUQXLMEJDQLHE5BBEFBQ3FF4F3BZYWCUBBQM67X6EOEW2WHGS764OQXE"
#define APP_ID      (16037129)
#define WALLET_PASSWORD "shosha_dragon"
#define ALICE_NAME "dragon"
#define BOB_NAME "shosha"

#endif //VERTICES_CONFIG_VERTICES_CONFIG_H
