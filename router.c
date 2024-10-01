#include <arpa/inet.h>
#include <string.h>

#include "lib.h"
#include "protocols.h"
#include "queue.h"
#include "trie.h"

#define MAX_RTABLE_SIZE 80000
#define MAX_ARP_TABLE_SIZE 10
#define IPV4_ETHER_TYPE 0x0800
#define ARP_ETHER_TYPE 0x0806
#define ICMP_PROTOCOL 1
#define TIME_EXCEEDED_ICMP_TYPE 11
#define DESTINATION_UNREACHABLE_ICMP_TYPE 3
#define ECHO_REQUEST_ICMP_TYPE 8
#define ECHO_REQUEST_ICMP_CODE 0
#define ECHO_REPLY_ICMP_TYPE 0
#define ECHO_REPLY_ICMP_CODE 0

static struct route_table_entry *rtable;
static uint32_t rtable_len;

static struct arp_table_entry *arp_table;
static uint32_t arp_table_len;

static trie_t *trie;

// ===========================================
// ============= DEBUG FUNCTIONS =============
// ===========================================

void print_arp()
{
	for (int i = 0; i < arp_table_len; i++) {
		printf("ip: %d mac:", arp_table[i].ip);
		for (int j = 0; j < 6; j++) {
			printf("%u ", arp_table[i].mac[j]);
		}
		printf("\n");
	}
}

void print_mac(uint8_t *mac)
{
	for (int j = 0; j < 6; j++) {
		printf("%u ", mac[j]);
	}
	printf("\n");
}

void print_ip(int *ip)
{
	printf("ip_binary: ");
	for (int i = 0; i < NR_BITS_IPV4; i++) {
		printf("%d", ip[i]);
	}
	printf("\n");
}

// ==========================================
// ========= TRIE ROUTING FUNCTIONS =========
// ==========================================

void create_trie_rtable(char *argv)
{
	trie = trie_create(sizeof(struct route_table_entry), ALPHABET_SIZE);
	for (int i = 0; i < rtable_len; i++) {
		trie_insert(trie, rtable[i]);
	}
}

struct route_table_entry *get_best_route(uint32_t ip_dest)
{
	// Convert the IP to host order and get the array of bits.
	int *ip_binary = decimalToBinary(ntohl(ip_dest));

	printf("ip_dest_n:%d\n", ip_dest);
	print_ip(ip_binary);

	struct route_table_entry *best = NULL;
	trie_node_t *current_node = trie->root;

	// Go through the 0/1 child considering whether the current IP bit is 0/1.
	int i = 0;
	for (i = 0; i < NR_BITS_IPV4; i++) {
		int idx = ip_binary[i];
		if (!current_node->children || !current_node->children[idx])
			break;
		current_node = current_node->children[idx];
		printf("%d", idx);
	}

	// Probably the current IP will correspond exactly until one point. Then, we need to go forward
	// and get the IP with the longest mask, meaning we will go through the 1 child until there are
	// no 1 children left and switch to 0s until we reach 32 bits.
	for (int j = i; j < NR_BITS_IPV4; j++) {
		if (!current_node->children) {
			return NULL;
		}
		if (!current_node->children[0] && !current_node->children[1])
			return NULL;
		if (current_node->children[1]) {
			current_node = current_node->children[1];
		} else if (current_node->children[0]) {
			current_node = current_node->children[0];
		}
		printf("%d", ip_binary[j]);
	}

	// If we got to the end, there is a possibility there were more pairs of (ip, mask) that had the
	// same result, so we need to find the entry with the longest mask.
	if (current_node && current_node->entries) {
		best = &(current_node->entries[0]);
		for (int i = 0; i < current_node->appearances; i++) {
			if (ntohl(best->mask) < ntohl(current_node->entries[i].mask)) {
				best = &(current_node->entries[i]);
			}
		}
	}
	
	if (best) {
		printf("\nBEST ROUTE\n");
		printf("prefix: %d, mask: %d\n", best->prefix, best->mask);
		printf("interface: %d, nextHop: %d\n\n", best->interface, best->next_hop);

		if ((best->prefix & best->mask) == (ip_dest & best->mask))
			return best;
	}
	return NULL;
}

// ===========================================
// ========= ICMP PROTOCOL FUNCTIONS =========
// ===========================================

void router_icmp_echo_reply(struct ether_header *eth_hdr, int interface)
{
	// Verify whether there is an ICMP Echo Request after the IP header.
	struct icmphdr *icmp_hdr_request =
		(struct icmphdr *)((char *)eth_hdr + sizeof(struct ether_header) + sizeof(struct iphdr));
	if (icmp_hdr_request->type != ECHO_REQUEST_ICMP_TYPE ||
		icmp_hdr_request->code != ECHO_REQUEST_ICMP_CODE) {
		printf("the packet is NOT an ICMP Echo Request\n");
		return;
	}

	// Create a new buffer that will hold the new packet.
	char buf[MAX_PACKET_LEN] = {0};
	struct ether_header *new_eth_hdr = (struct ether_header *)buf;

	// Update source and destination MACs from Ethernet header (basically swap them).
	memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
	new_eth_hdr->ether_type = htons(IPV4_ETHER_TYPE);
	memcpy(new_eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));

	// Create the new IP header
	struct iphdr *ip_hdr_old = (struct iphdr *)((char *)eth_hdr + sizeof(struct ether_header));

	struct iphdr *ip_hdr_new = (struct iphdr *)(buf + sizeof(struct ether_header));
	ip_hdr_new->ttl = 8;  // we have a small topology, so 8 hops should be fine.
	ip_hdr_new->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));	 // new IP + ICMP
	ip_hdr_new->saddr = ip_hdr_old->daddr;	// swap IP destination and IP source
	ip_hdr_new->daddr = ip_hdr_old->saddr;
	ip_hdr_new->protocol = ICMP_PROTOCOL;

	// Copy the other fields from the old IP header.
	ip_hdr_new->version = ip_hdr_old->version;
	ip_hdr_new->tos = ip_hdr_old->tos;
	ip_hdr_new->ihl = ip_hdr_old->ihl;
	ip_hdr_new->id = ip_hdr_old->id;
	ip_hdr_new->frag_off = ip_hdr_old->frag_off;

	// Determine the new checksum.
	ip_hdr_new->check = 0;
	ip_hdr_new->check = htons(checksum((uint16_t *)ip_hdr_new, sizeof(struct iphdr)));

	printf("MAC_D: ");
	print_mac(new_eth_hdr->ether_dhost);
	printf("MAC_S: ");
	print_mac(new_eth_hdr->ether_shost);
	printf("IP_D: %d\nIP_S: %d\n", ip_hdr_new->daddr, ip_hdr_new->saddr);

	// Create ICMP header after the new IP header.
	struct icmphdr *icmp_hdr =
		(struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->type = ECHO_REPLY_ICMP_TYPE;
	icmp_hdr->code = ECHO_REPLY_ICMP_CODE;

	// Copy the id and sequence from the ICMP Request into the ICMP Reply.
	icmp_hdr->un.echo.id = icmp_hdr_request->un.echo.id;
	icmp_hdr->un.echo.sequence = icmp_hdr_request->un.echo.sequence;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	// Put the old IP header after ICMP header (add 8 to the size because of the additional 64 bits)
	memcpy(icmp_hdr + sizeof(struct icmphdr), ip_hdr_old, sizeof(struct iphdr) + 8);

	// Debug section
	struct icmphdr *icmp_hdr_test =
		(struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	printf("icmp_type_test: %d code: %d\n", icmp_hdr_test->type, icmp_hdr_test->code);
	// Debug section

	// Send the packet
	int len = sizeof(struct ether_header) + sizeof(struct icmphdr) + 2 * sizeof(struct iphdr) + 8;
	send_to_link(interface, (char *)new_eth_hdr, len);
}

void send_icmp_by_type(struct ether_header *eth_hdr, int interface, int icmp_type)
{
	// We treat separately the case for Echo Request/Echo Reply.
	if (icmp_type == ECHO_REPLY_ICMP_TYPE) {
		router_icmp_echo_reply(eth_hdr, interface);
		return;
	}

	// Create a new buffer that will hold the new packet.
	char buf[MAX_PACKET_LEN] = {0};
	struct ether_header *new_eth_hdr = (struct ether_header *)buf;

	// Update source and destination MACs from Ethernet header (basically swap them).
	memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
	new_eth_hdr->ether_type = htons(IPV4_ETHER_TYPE);
	memcpy(new_eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));

	// Create the new IP header after the Ethernet Header.
	struct iphdr *ip_hdr_old = (struct iphdr *)((char *)eth_hdr + sizeof(struct ether_header));

	struct iphdr *ip_hdr_new = (struct iphdr *)(buf + sizeof(struct ether_header));
	ip_hdr_new->ttl = 8;  // we have a small topology, so 8 hops should be fine.
	ip_hdr_new->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));	 // new IP + ICMP
	ip_hdr_new->saddr = ip_hdr_old->daddr;	// swap IP destination and IP source
	ip_hdr_new->daddr = ip_hdr_old->saddr;
	ip_hdr_new->protocol = ICMP_PROTOCOL;

	// Copy the other fields from the old IP header.
	ip_hdr_new->version = ip_hdr_old->version;
	ip_hdr_new->tos = ip_hdr_old->tos;
	ip_hdr_new->ihl = ip_hdr_old->ihl;
	ip_hdr_new->id = ip_hdr_old->id;
	ip_hdr_new->frag_off = ip_hdr_old->frag_off;

	// Determine the new checksum.
	ip_hdr_new->check = 0;
	ip_hdr_new->check = htons(checksum((uint16_t *)ip_hdr_new, sizeof(struct iphdr)));

	printf("MAC_D: ");
	print_mac(new_eth_hdr->ether_dhost);
	printf("MAC_S: ");
	print_mac(new_eth_hdr->ether_shost);
	printf("IP_D: %d\nIP_S: %d\n", ip_hdr_new->daddr, ip_hdr_new->saddr);

	// Create ICMP header after the new IP header.
	struct icmphdr *icmp_hdr =
		(struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	icmp_hdr->type = icmp_type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	// Put the old IP header after ICMP header (add 8 to the size because of the additional 64 bits)
	memcpy(icmp_hdr + sizeof(struct icmphdr), ip_hdr_old, sizeof(struct iphdr) + 8);

	// Debug section
	struct icmphdr *icmp_hdr_test =
		(struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	printf("icmp_type_test: %d code: %d\n", icmp_hdr_test->type, icmp_hdr_test->code);
	// Debug section

	// Send the packet
	int len = sizeof(struct ether_header) + sizeof(struct icmphdr) + 2 * sizeof(struct iphdr) + 8;
	send_to_link(interface, (char *)new_eth_hdr, len);
}

// =================================
// ========= ARP FUNCTIONS =========
// =================================

struct arp_table_entry *get_arp_entry(uint32_t ip)
{
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip) {
			return &arp_table[i];
		}
	}
	return NULL;
}

// ==========================================
// ========= IPV4 FORWARD FUNCTIONS =========
// ==========================================

void ipv4_forward(struct ether_header *eth_hdr, int interface, size_t len)
{
	//
	printf("sender_mac: ");
	print_mac(eth_hdr->ether_shost);
	printf("\ndest_mac: ");
	print_mac(eth_hdr->ether_dhost);
	printf("\n");
	//

	struct iphdr *ip_hdr = (struct iphdr *)((char *)eth_hdr + sizeof(struct ether_header));

	printf("\nheader_IP_D: %d, IP_S: %d\ninterf_IP_Current: %d\n\n", ip_hdr->daddr, ip_hdr->saddr,
		   inet_addr(get_interface_ip(interface)));

	// 1. We verify if the router is the destination.
	// inet_addr() transforms the address from chars(IPv4 format) to an integer.
	if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
		printf("router is destination\n");	// Could be an Echo Request.
		send_icmp_by_type(eth_hdr, interface, ECHO_REPLY_ICMP_TYPE);
		return;
	}

	// 2. We verify the checksum
	int checksum_origin = ntohs(ip_hdr->check);
	ip_hdr->check = 0;
	int checksum_calculated = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
	if (checksum_origin != checksum_calculated) {
		printf("corrupt packet\n");	 // the packet is thrown.
		return;
	}

	// 3. We verify the TTL
	if (ip_hdr->ttl <= 1) {
		printf("Time exceeded\n");	// Send an ICMP back to the sender.
		send_icmp_by_type(eth_hdr, interface, TIME_EXCEEDED_ICMP_TYPE);
		return;
	} else {
		ip_hdr->ttl--;
	}
	printf("before route\n");

	// 4. In the routing table, we search for the nextHop towards the destination.
	struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
	if (best_route == NULL) {
		printf("Destination unreachable\n");  // Send an ICMP back to the sender.
		send_icmp_by_type(eth_hdr, interface, DESTINATION_UNREACHABLE_ICMP_TYPE);
		return;
	}

	// 5. Update the checksum. (it was put on zero first)
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	// 6. Update the MAC addresses in the Ethernet header
	// The source will be the router's interface from where we send it determined from the routing
	// table.
	get_interface_mac(best_route->interface, eth_hdr->ether_shost);

	// The destination is found in the ARP table.
	struct arp_table_entry *next_hop_arp = get_arp_entry(best_route->next_hop);
	memcpy(eth_hdr->ether_dhost, next_hop_arp->mac, sizeof(next_hop_arp->mac));

	printf("ip_arp: %d mac_arp:", next_hop_arp->ip);
	print_mac(next_hop_arp->mac);
	printf("\n");
	printf("sender_mac_final: ");
	print_mac(eth_hdr->ether_shost);
	printf("\n");
	printf("dest_mac_final: ");
	print_mac(eth_hdr->ether_dhost);
	printf("\n");
	printf("len:%ld \nPACKET SENT\n\n\n", len);

	// 7. Send the packet.
	send_to_link(best_route->interface, (char *)eth_hdr, len);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Reading the initial routing table from the file.
	rtable = malloc(sizeof(struct route_table_entry) * MAX_RTABLE_SIZE);
	rtable_len = read_rtable(argv[1], rtable);

	// Transform the routing table into a trie. The search will be more efficient.
	create_trie_rtable(argv[1]);
	free(rtable);

	// Read ARP table from file.
	arp_table = malloc(MAX_ARP_TABLE_SIZE * sizeof(struct arp_table_entry));
	DIE(!arp_table, "malloc failed");
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	print_arp();

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		printf("\n\nCurrent router: %s\n", argv[1]);

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is
		needed when sending a packet on the link, */

		// ============== IPv4 PART ==============
		printf("start ipv4\n");
		ipv4_forward(eth_hdr, interface, len);
	}

	free(arp_table);
	trie_free(trie->root);
	return 0;
}
