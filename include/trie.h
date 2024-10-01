#ifndef TRIE_H
#define TRIE_H

#define ALPHABET_SIZE 2
#define ALPHABET "01"
#define NR_BITS_IPV4 32

typedef struct trie_node_t trie_node_t;
struct trie_node_t {
	trie_node_t **children;
	int appearances;
	struct route_table_entry *entries;
};

typedef struct trie_t trie_t;
struct trie_t {
	trie_node_t *root;

	/* Number of keys */
	int size;

	/* Generic Data Structure */
	int data_size;

	/* Trie-Specific, alphabet properties */
	int alphabet_size;
};

trie_node_t *trie_create_node(trie_t *trie);
trie_t *trie_create(int data_size, int alphabet_size);
void trie_insert(trie_t *trie, struct route_table_entry key);

// Verifies if there is a path with the letters given in key.
trie_node_t *trie_search_path(trie_t *trie, int *ip);

// Verifies if there is a complete word with the letters given in key.
trie_node_t *trie_search(trie_t *trie, int *ip);

// Recursively removes the nodes of a word from the last letter until the first,
// or until we find a char that belongs to other words.
void aux_trie_remove(trie_t *trie, char *key, int *found_other_word);
void trie_remove(trie_t *trie, char *key);

// Recursively frees the nodes from the trie.
trie_node_t *trie_free(trie_node_t *node);

int *decimalToBinary(int n);

#endif	// TRIE_H