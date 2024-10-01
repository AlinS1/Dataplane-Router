#include "trie.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib.h"

trie_node_t *trie_create_node(trie_t *trie)
{
	if (!trie)
		return NULL;
	trie_node_t *trie_node = malloc(sizeof(trie_node_t));
	DIE(!trie_node, "malloc failed");
	trie_node->children = NULL;
	trie_node->appearances = 0;
	trie_node->entries = NULL;

	return trie_node;
}

trie_t *trie_create(int data_size, int alphabet_size)
{
	trie_t *trie = malloc(sizeof(trie_t));
	DIE(!trie, "malloc failed");
	trie->root = trie_create_node(trie);
	trie->root->appearances = -1;
	trie->size = 0;
	trie->data_size = data_size;
	trie->alphabet_size = alphabet_size;
	return trie;
}

int *decimalToBinary(int n)
{
	// Calculate the binary representation
	int *v = malloc(sizeof(int) * NR_BITS_IPV4);
	DIE(!v, "malloc failed");

    unsigned int mask = 1 << 31; // Set the mask to check each bit
    
    for (int i = 0; i < 32; i++) {
        v[i] = (n & mask) ? 1 : 0; // Check if the bit is set and assign 1 or 0
        mask >>= 1; // Move the mask to the right
    }

	return v;
}

void trie_insert(trie_t *trie, struct route_table_entry key)
{
	if (!trie)
		return;
	// printf("prefix_insert: %d\n", key.prefix);

	// If the word already exists, we just increment its number of appearances
	int *base2_ip = decimalToBinary((ntohl(key.prefix)) & (ntohl(key.mask)));
	trie_node_t *node = trie_search(trie, base2_ip);
	if (node) {
		node->appearances++;
		struct route_table_entry *aux = realloc(node->entries, node->appearances * sizeof(struct route_table_entry));
		DIE(!aux, "realloc failed");
		node->entries = aux;
		node->entries[node->appearances - 1] = key;
		return;
	}

	trie_node_t *current_node = trie->root;

	for (int i = 0; i < NR_BITS_IPV4; i++) {
		int idx = base2_ip[i];

		if (!current_node->children) {
			current_node->children = malloc(sizeof(trie_node_t *) * trie->alphabet_size);
			DIE(!current_node->children, "malloc failed");

			for (int k = 0; k < trie->alphabet_size; k++)
				current_node->children[k] = NULL;
		}
		if (!current_node->children[idx])
			current_node->children[idx] = trie_create_node(trie);

		current_node = current_node->children[idx];
	}
	// For the last node
	current_node->appearances = 1;
	current_node->entries = malloc(trie->data_size);
	DIE(!current_node->entries, "malloc failed");
	current_node->entries[0] = key;
	free(base2_ip);
}

trie_node_t *trie_search_path(trie_t *trie, int *ip)
{
	if (!trie)
		return NULL;

	trie_node_t *current_node = trie->root;
	for (int i = 0; i < NR_BITS_IPV4; i++) {
		int idx = ip[i];
		if (!current_node->children || !current_node->children[idx])
			return NULL;
		current_node = current_node->children[idx];
	}
	return current_node;
}

trie_node_t *trie_search(trie_t *trie, int *ip)
{
	if (!trie)
		return NULL;

	trie_node_t *current_node = trie->root;
	for (int i = 0; i < NR_BITS_IPV4; i++) {
		int idx = ip[i];
		if (!current_node->children || !current_node->children[idx])
			return NULL;
		current_node = current_node->children[idx];
	}

	// For the last
	if (current_node->entries != NULL)
		return current_node;
	else
		return NULL;
}

trie_node_t *trie_free(trie_node_t *node)
{
	if (!node)
		return NULL;

	if (!node->children) {
		free(node);
		node = NULL;
		return NULL;
	}

	for (int i = 0; i < ALPHABET_SIZE; i++) {
		trie_node_t *current = node->children[i];
		if (current)
			trie_free(current);
	}

	if (node->children) {
		free(node->children);
		node->children = NULL;
	}
	free(node);
	node = NULL;
	return NULL;
}