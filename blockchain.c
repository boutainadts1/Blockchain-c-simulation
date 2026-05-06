#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <openssl/sha.h>

/* =========================================================
   BLOCKCHAIN CONFIGURATION
   ========================================================= */

#define HASH_SIZE 64
#define MAX_TRANSACTIONS 100
#define MAX_NODES 10
#define DIFFICULTY 3

/* =========================================================
   TRANSACTION STRUCTURE
   Each transaction contains:
   - sender
   - receiver
   - amount
   - timestamp
   - transaction hash
   ========================================================= */

typedef struct {

    char sender[50];
    char receiver[50];

    float amount;

    char timestamp[30];

    char hash[HASH_SIZE + 1];

} Transaction;

/* =========================================================
   MERKLE TREE NODE
   Used to verify transaction integrity efficiently
   ========================================================= */

typedef struct MerkleNode {

    char hash[HASH_SIZE + 1];

    struct MerkleNode* left;
    struct MerkleNode* right;

} MerkleNode;

/* =========================================================
   BLOCK STRUCTURE
   Each block contains:
   - transactions
   - previous block hash
   - Merkle root
   - Proof of Work nonce
   ========================================================= */

typedef struct Block {

    int index;

    time_t timestamp;

    char previous_hash[HASH_SIZE + 1];

    char hash[HASH_SIZE + 1];

    char merkle_root[HASH_SIZE + 1];

    int nonce;

    Transaction transactions[MAX_TRANSACTIONS];

    int transaction_count;

    struct Block* next;

} Block;

/* =========================================================
   BLOCKCHAIN STRUCTURE
   ========================================================= */

typedef struct {

    Block* genesis;

    Block* last;

    int block_count;

    pthread_mutex_t lock;

} Blockchain;

/* =========================================================
   NODE STRUCTURE
   Each node owns its own blockchain copy
   ========================================================= */

typedef struct {

    int id;

    bool miner;

    bool malicious;

    bool active;

    Blockchain* blockchain;

    pthread_t thread;

} Node;

/* =========================================================
   GLOBAL VARIABLES
   ========================================================= */

Node nodes[MAX_NODES];

int node_count = 0;

bool shutdown_requested = false;

pthread_mutex_t nodes_lock = PTHREAD_MUTEX_INITIALIZER;

/* =========================================================
   SHA256 HASH FUNCTION
   ========================================================= */

void sha256(const char* str, char output[65]) {

    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256((unsigned char*)str,
           strlen(str),
           hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {

        sprintf(output + (i * 2),
                "%02x",
                hash[i]);
    }

    output[64] = '\0';
}

/* =========================================================
   TRANSACTION HASHING
   ========================================================= */

void hash_transaction(Transaction* tx) {

    char buffer[512];

    sprintf(buffer,
            "%s%s%f%s",
            tx->sender,
            tx->receiver,
            tx->amount,
            tx->timestamp);

    sha256(buffer, tx->hash);
}

/* =========================================================
   MERKLE TREE FUNCTIONS
   ========================================================= */

// Create Merkle node
MerkleNode* create_merkle_node(const char* hash) {

    MerkleNode* node =
        malloc(sizeof(MerkleNode));

    strcpy(node->hash, hash);

    node->left = NULL;
    node->right = NULL;

    return node;
}

// Free Merkle tree
void free_merkle_tree(MerkleNode* root) {

    if (!root)
        return;

    free_merkle_tree(root->left);
    free_merkle_tree(root->right);

    free(root);
}

// Recursive Merkle Tree builder
MerkleNode* build_merkle_tree(char** hashes,
                              int start,
                              int end) {

    if (start > end)
        return NULL;

    if (start == end)
        return create_merkle_node(hashes[start]);

    int mid = (start + end) / 2;

    MerkleNode* left =
        build_merkle_tree(hashes, start, mid);

    MerkleNode* right =
        build_merkle_tree(hashes, mid + 1, end);

    // duplicate node if odd number
    if (!right)
        right = create_merkle_node(left->hash);

    MerkleNode* parent =
        create_merkle_node("");

    char combined[HASH_SIZE * 2 + 1];

    sprintf(combined,
            "%s%s",
            left->hash,
            right->hash);

    sha256(combined, parent->hash);

    parent->left = left;
    parent->right = right;

    return parent;
}

/* =========================================================
   MERKLE ROOT CALCULATION
   ========================================================= */

void calculate_merkle_root(Block* block) {

    if (block->transaction_count == 0) {

        memset(block->merkle_root,
               '0',
               HASH_SIZE);

        block->merkle_root[HASH_SIZE] = '\0';

        return;
    }

    char* hashes[MAX_TRANSACTIONS];

    for (int i = 0;
         i < block->transaction_count;
         i++) {

        hashes[i] =
            block->transactions[i].hash;
    }

    MerkleNode* root =
        build_merkle_tree(
            hashes,
            0,
            block->transaction_count - 1);

    strcpy(block->merkle_root,
           root->hash);

    free_merkle_tree(root);
}

/* =========================================================
   BLOCK HASHING
   ========================================================= */

void hash_block(Block* block) {

    char buffer[2048];

    sprintf(buffer,
            "%d%ld%s%s%d",
            block->index,
            block->timestamp,
            block->previous_hash,
            block->merkle_root,
            block->nonce);

    sha256(buffer, block->hash);
}

/* =========================================================
   BLOCK CREATION
   ========================================================= */

Block* create_block(int index,
                    const char* prev_hash) {

    Block* block =
        malloc(sizeof(Block));

    block->index = index;

    block->timestamp = time(NULL);

    strcpy(block->previous_hash,
           prev_hash);

    block->transaction_count = 0;

    block->nonce = 0;

    block->next = NULL;

    return block;
}

/* =========================================================
   ADD TRANSACTION TO BLOCK
   ========================================================= */

void add_transaction(Block* block,
                     const char* sender,
                     const char* receiver,
                     float amount) {

    if (block->transaction_count >=
        MAX_TRANSACTIONS)
        return;

    Transaction* tx =
        &block->transactions[
            block->transaction_count++];

    strcpy(tx->sender, sender);

    strcpy(tx->receiver, receiver);

    tx->amount = amount;

    time_t now = time(NULL);

    strftime(tx->timestamp,
             sizeof(tx->timestamp),
             "%Y-%m-%d %H:%M:%S",
             localtime(&now));

    hash_transaction(tx);

    calculate_merkle_root(block);

    hash_block(block);
}

/* =========================================================
   PROOF OF WORK
   Mining = searching nonce that starts with zeros
   ========================================================= */

bool mine_block(Block* block) {

    while (true) {

        hash_block(block);

        bool valid = true;

        for (int i = 0;
             i < DIFFICULTY;
             i++) {

            if (block->hash[i] != '0') {

                valid = false;

                break;
            }
        }

        if (valid)
            return true;

        block->nonce++;

        if (shutdown_requested)
            return false;
    }
}

/* =========================================================
   BLOCKCHAIN CREATION
   ========================================================= */

Blockchain* create_blockchain() {

    Blockchain* bc =
        malloc(sizeof(Blockchain));

    Block* genesis =
        create_block(
            0,
            "000000000000000000000000");

    calculate_merkle_root(genesis);

    hash_block(genesis);

    bc->genesis = genesis;

    bc->last = genesis;

    bc->block_count = 1;

    pthread_mutex_init(&bc->lock, NULL);

    return bc;
}

/* =========================================================
   ADD BLOCK TO BLOCKCHAIN
   ========================================================= */

void add_block(Blockchain* bc,
               Block* block) {

    pthread_mutex_lock(&bc->lock);

    bc->last->next = block;

    bc->last = block;

    bc->block_count++;

    pthread_mutex_unlock(&bc->lock);
}

/* =========================================================
   VALIDATION
   validaation simple en vérifiant si le montant est positif
   ========================================================= */

bool validate_transaction(Transaction* tx) {

    return tx->amount > 0;
}

/* =========================================================
   VERIFY BLOCK
   ========================================================= */

bool validate_block(Block* block) {

    for (int i = 0;
         i < block->transaction_count;
         i++) {

        if (!validate_transaction(
            &block->transactions[i]))
            return false;
    }

    return true;
}

/* =========================================================
   CONSENSUS
   Majority validation
   ========================================================= */

bool consensus(Block* block) {

    int accepted = 0;
    int total = 0;

    pthread_mutex_lock(&nodes_lock);

    for (int i = 0; i < node_count; i++) {

        if (nodes[i].active) {

            total++;

            if (validate_block(block))
                accepted++;
        }
    }

    pthread_mutex_unlock(&nodes_lock);

    return accepted > total / 2;
}

/* =========================================================
   BLOCK REPLICATION
   Broadcast mined block to all nodes
   ========================================================= */

void broadcast_block(Block* block,
                     int sender) {

    pthread_mutex_lock(&nodes_lock);

    for (int i = 0; i < node_count; i++) {

        if (nodes[i].id != sender &&
            nodes[i].active) {

            add_block(
                nodes[i].blockchain,
                create_block(
                    block->index,
                    block->hash));
        }
    }

    pthread_mutex_unlock(&nodes_lock);
}

/* =========================================================
   BLOCK MODIFICATION ATTACK
   Simulate malicious modification attempt
   ========================================================= */

void tamper_block(Block* block) {

    if (block->transaction_count == 0)
        return;

    strcpy(block->transactions[0].receiver,
           "Hacker");

    hash_transaction(
        &block->transactions[0]);

    calculate_merkle_root(block);

    hash_block(block);

    printf("\n[ATTACK] Block modified!\n");
}

/* =========================================================
   NODE THREAD
   Each miner mines blocks independently
   ========================================================= */

void* node_work(void* arg) {

    Node* node = (Node*)arg;

    while (!shutdown_requested &&
           node->active) {

        if (node->miner) {

            Block* block =
                create_block(
                    node->blockchain->block_count,
                    node->blockchain->last->hash);

            add_transaction(
                block,
                "Karim",
                "Lina",
                50);

            add_transaction(
                block,
                "Lina",
                "Nassim",
                20);

            if (mine_block(block)) {

                printf("\nNode %d mined block %d\n",
                       node->id,
                       block->index);

                printf("Hash: %s\n",
                       block->hash);

                if (consensus(block)) {

                    add_block(
                        node->blockchain,
                        block);

                    broadcast_block(
                        block,
                        node->id);

                    printf("Consensus accepted block\n");
                }
            }

            // malicious behavior
            if (node->malicious &&
                rand() % 100 < 20) {

                tamper_block(block);
            }
        }

        sleep(1);
    }

    return NULL;
}

/* =========================================================
   CREATE NODE
   ========================================================= */

void create_node(bool miner,
                 bool malicious) {

    Node* node = &nodes[node_count];

    node->id = node_count;

    node->miner = miner;

    node->malicious = malicious;

    node->active = true;

    node->blockchain =
        create_blockchain();

    pthread_create(&node->thread,
                   NULL,
                   node_work,
                   node);

    node_count++;
}

/* =========================================================
   DISPLAY BLOCKCHAIN
   ========================================================= */

void print_blockchain(Blockchain* bc) {

    Block* current = bc->genesis;

    while (current) {

        printf("\n=========================\n");

        printf("BLOCK %d\n",
               current->index);

        printf("Hash : %s\n",
               current->hash);

        printf("Previous : %s\n",
               current->previous_hash);

        printf("Merkle Root : %s\n",
               current->merkle_root);

        printf("Nonce : %d\n",
               current->nonce);

        printf("Transactions : %d\n",
               current->transaction_count);

        for (int i = 0;
             i < current->transaction_count;
             i++) {

            Transaction tx =
                current->transactions[i];

            printf("-> %s sent %.2f to %s\n",
                   tx.sender,
                   tx.amount,
                   tx.receiver);
        }

        current = current->next;
    }
}

/* =========================================================
   MAIN
   ========================================================= */

int main() {

    srand(time(NULL));

    printf("=== Blockchain Simulation ===\n");

    // Honest nodes
    create_node(true, false);
    create_node(true, false);

    // Malicious node
    create_node(true, true);

    sleep(6);

    shutdown_requested = true;

    for (int i = 0;
         i < node_count;
         i++) {

        pthread_join(nodes[i].thread,
                     NULL);
    }

    printf("\n=== FINAL BLOCKCHAIN ===\n");

    print_blockchain(
        nodes[0].blockchain);

    return 0;
}