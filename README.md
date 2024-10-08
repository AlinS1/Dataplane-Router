**Similea Alin-Andrei 324CA**

# Dataplane Router



### Implemented parts


###### 1. Forwarding process

Considering the IP is right after the Ethernet header, we can get the IP header.
I followed the basic forwarding steps and treated the special cases:
a. The router is the destination (the destination from the packet is the same
as the router's interface IP).
b. The packet is corrupt (non-corresponding checksums).
c. The TTL is too small to forward the packet(<=1).
d. No route found from the routing table.

Kept in mind that the packet contains information in network order (relevant
for the checksum update).

We update the Ethernet header with the new MAC addresses:
Source - If a route has been found for the next hop, we figure out the router's
interface through which we need to forward the packet.
Destination - We use the ARP Table to get the next hop's MAC address, as it
contains (IP, MAC) pairs.

Finally, we send the packet to the next hop.


###### 2. Efficient Longest Prefix Match

Implemented a trie in order to search in constant time - O(1). The
space complexity is, however, a downside.
Basically, each node has two children corresponding to a bit (0 or 1) from the
result of the LOGIC AND between the IP address and its mask. We will have to do
32 steps in order to find a *routing table entry*, because there are 32 bits in
an IPv4 address.
There may be a case where there are more pairs of (IP, mask) that have the
same result to a LOGIC AND. This exception is dealt with by having an array of
entries that is reallocated when there is a new entry found that corresponds to
that node.


P.S.: There could be a more efficient implementation with fewer steps
if we implement the trie by using bytes and not bits. There will be
256 children for each node and 4 steps to find the *routing
table entry*.


###### 3. ICMP Protocol

Making use of the skel that receives the packet in a buffer, I created the new
packet in a buffer(an array of chars) that has all the elements put initially
on 0 (helps at the fields from the ICMP that shouldn't be filled).

In the case of an ICMP packet, we need to keep in mind that the packet
structure will be the following:
```
New Ethernet header | New IP header | ICMP header | Old IP header + 8
```

That being said, we create new Ethernet and IP headers using the info from the
old ones.
The new Ethernet will have the swapped MACs from the old one. The same for the
IP header regarding the IP addresses.

In the case of an ICMP Reply, we need to keep the ICMP Request id and sequence
fields.

We will append the old IP header to the ICMP header and the next 8 bytes
(64 bits) of information after the old IP header.
In the end, we forward back the package from where it came from.
