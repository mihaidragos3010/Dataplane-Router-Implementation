# Dataplane-Router-Implementation

Implementation of a program that simulates a network router. The program applies classic protocols such as: Ip and Arp.

 - Sending IP Packets: The program receives a packet, checks if it's destined for the router, verifies the checksum and TTL, and modifies them if necessary. It then looks up the destination IP address in the routing table to determine the appropriate interface. If not found, it attempts to send an ICMP packet to inform the source (though this function is not working correctly). If found, it looks up the destination MAC address in the ARP table and sends the packet accordingly.

 - Efficient Routing Table Search: You've implemented sorting of the entire routing table using qsort, sorting it first by prefix and then by mask. When searching the table, you set the target network and perform a binary search, retrieving the interface, prefix, mask, and next hop.

 - For ARP requests received, if the router is the destination, it sends an ARP reply with its MAC address for the respective interface.
If the MAC address is not found in the ARP table, an ARP request is sent on the next-hop interface to discover the MAC address of the destination IP, and the IP message is queued internally for later transmission.
Upon receiving an ARP reply, the MAC address is saved in the table, and the first queued message is sent.
