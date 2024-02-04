#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

typedef struct ArpTable{
    struct arp_entry *arpEntryTable;
		int nrEntryTable;
} ArpTable;

typedef struct RoutingTable{
		struct route_table_entry *routingEntryTable;
		int nrEntryTable;
} RoutingTable;

ArpTable arp_table;
RoutingTable routing_table;
struct route_table_entry targetEntryRoutingTable;
struct route_table_entry packetEntryRouterTable;

//Function check either I was destination and return 1 or I wasn't destination and return 0. 
int checkDestination(int interface,struct ether_header *eth_hdr){

	char* ipInterface = calloc(4,sizeof(char));
	DIE(ipInterface == NULL, "Calloc ipDestination was faild\n");
		
	ipInterface = get_interface_ip(interface);

	/*	If this router has same ip on interface with packet's ip destination it will 
  parsing him. */

		if(memcmp(ipInterface, eth_hdr->ether_dhost, 4) == 0){
			printf("I'm destination of this packet\n");
			return 1;
		}
		return 0;
}

//Function looking for specific network and return 1/-1 if it found them and return with helps argument variable 
int searchNetwork(struct route_table_entry* packetEntryRouterTable,struct iphdr *ip_hdr){

	struct  route_table_entry *routeTable = routing_table.routingEntryTable;
	int nrEntryRouterTable = routing_table.nrEntryTable;
	int ok =-1;
	for(int index = 0; index < nrEntryRouterTable; index++){

			while((ip_hdr->daddr & routeTable[index].mask) == routeTable[index].prefix){

				if(packetEntryRouterTable->mask < routeTable[index].mask){
					packetEntryRouterTable->prefix = routeTable[index].prefix;
					packetEntryRouterTable->mask = routeTable[index].mask;
					packetEntryRouterTable->next_hop = routeTable[index].next_hop;
					packetEntryRouterTable->interface = routeTable[index].interface;
					ok = 1;
					break;
				}
				index++;
			}
		}
		return ok;

}

int compareEntruRoutingElements(const void *elem1,const void *elem2){
	struct route_table_entry *elem1_aux = (struct route_table_entry *)elem1;
	struct route_table_entry *elem2_aux = (struct route_table_entry *)elem2;
	if(htonl(elem1_aux->prefix) > htonl(elem2_aux->prefix))
		return 1;
	if(htonl(elem1_aux->prefix) < htonl(elem2_aux->prefix))
		return -1;
	if(htonl(elem1_aux->prefix) == htonl(elem2_aux->prefix)){
		if(htonl(elem1_aux->mask) > htonl(elem2_aux->mask))
			return 1;
		if(htonl(elem1_aux->mask) < htonl(elem2_aux->mask))
			return -1;
	}
	return 0;
}

//Function search in binary mode a specific network
int searchBinaryNetworkHelper(struct route_table_entry* packetEntryRouterTable,struct iphdr *ip_hdr,struct route_table_entry* targetEntryRoutingTable,int left,int right){
	if (left > right)
			return -1; 
	else{
			int mid = (left + right) / 2 ;
			if(compareEntruRoutingElements((void*)targetEntryRoutingTable,(void*)(&routing_table.routingEntryTable[mid])) == 0){
					packetEntryRouterTable->prefix = routing_table.routingEntryTable[mid].prefix;
					packetEntryRouterTable->next_hop = routing_table.routingEntryTable[mid].next_hop;
					packetEntryRouterTable->mask = routing_table.routingEntryTable[mid].mask;
					packetEntryRouterTable->interface = routing_table.routingEntryTable[mid].interface;
					return mid;
			}
			if(compareEntruRoutingElements((void*)targetEntryRoutingTable,(void*)(&routing_table.routingEntryTable[mid])) > 0)
					return searchBinaryNetworkHelper(packetEntryRouterTable, ip_hdr,targetEntryRoutingTable, mid + 1, right);
			
			if(compareEntruRoutingElements((void*)targetEntryRoutingTable,(void*)(&routing_table.routingEntryTable[mid])) < 0)
					return searchBinaryNetworkHelper(packetEntryRouterTable, ip_hdr,targetEntryRoutingTable, left, mid - 1) ;
	}

	return -1;
}

int searchBinaryNetwork(struct route_table_entry* packetEntryRouterTable,struct iphdr *ip_hdr){

	int left = 0;
	int right = routing_table.nrEntryTable-1;
	return searchBinaryNetworkHelper(packetEntryRouterTable,ip_hdr,&targetEntryRoutingTable,left,right);

}

//Function creates a new ip header
struct iphdr* createIpPacket(uint32_t *ipSource,uint32_t *ipDestination,struct iphdr *ip_hdr){

	struct iphdr* ip_packet = calloc(1,sizeof(struct iphdr));
	DIE(ip_packet == NULL, "Allocated ip_packet was faild");

	memcpy(ip_packet,ip_hdr,sizeof(struct iphdr));
	ip_packet->saddr=*ipSource;
	ip_packet->daddr=*ipDestination;
	return ip_packet;
}

//Function creates a new ether header
struct ether_header* createEtherFrame(uint8_t *macSource,uint8_t *macDestination,int frameType){

	struct ether_header * ether_frame = calloc(1,sizeof(struct ether_header));
	DIE(ether_frame == NULL, "Allocated ether_frame was faild");

	memcpy(ether_frame->ether_dhost,macDestination,6*sizeof(uint8_t));
	memcpy(ether_frame->ether_shost,macSource,6*sizeof(uint8_t));
	ether_frame->ether_type = htons(frameType);

	return ether_frame;
}

//Function creates a Icmp packet and send on given interface
void sendIcmpPacket(int interface,struct ether_header *eth_hdr,struct iphdr *ip_hdr,char* frame,uint8_t typeIcmp){

		
		struct ether_header *eth_icmp = createEtherFrame(eth_hdr->ether_dhost,eth_hdr->ether_shost,0x0800);

		uint32_t *ipInterface = calloc(1,sizeof(uint32_t));
		DIE(ipInterface == NULL, "Allocated ipInterdace was faild");
		inet_pton(AF_INET, get_interface_ip(interface), ipInterface);

		struct iphdr *ip_icmp = createIpPacket(ipInterface,&ip_hdr->saddr,ip_hdr);
		ip_icmp->ttl = 64;
		ip_icmp->check = 0;
		ip_icmp->check = checksum((uint16_t *)ip_icmp, sizeof(struct iphdr));

		struct icmphdr *icmp_packet = calloc(1,sizeof(struct icmphdr));
		DIE(icmp_packet == NULL,"Couldn't allocate icmp_packet\n");

		icmp_packet->type=typeIcmp;
		icmp_packet->checksum = 0;
		icmp_packet->checksum = htons(checksum((uint16_t *)icmp_packet, sizeof(struct icmphdr)));

		char *segment = calloc(1,sizeof(struct ether_header)+2*sizeof(struct iphdr)+sizeof(struct icmphdr)+64);
		DIE(segment == NULL,"Couldn't allocate icmp_packet\n");

		memcpy(segment,eth_icmp,sizeof(struct ether_header));
		memcpy(segment+sizeof(struct ether_header),ip_icmp,sizeof(struct iphdr));
		memcpy(segment+sizeof(struct ether_header)+sizeof(struct iphdr),icmp_packet,sizeof(struct icmphdr));
		memcpy(segment+sizeof(struct ether_header)+sizeof(struct iphdr)+sizeof(struct icmphdr),ip_hdr,sizeof(struct iphdr));
		memcpy(segment+sizeof(struct ether_header)+sizeof(struct iphdr)+sizeof(struct icmphdr)+sizeof(struct iphdr),frame,64);
		
		send_to_link(interface,segment,sizeof(struct ether_header)+2*sizeof(struct iphdr)+sizeof(struct icmphdr)+64);
	return;
}

//Function checks packet's check_sum field and ttl field and return 1/0 either the variables are
//in a right form or doesn't
int checkPacketSum_PacketTTL(struct iphdr *ip_hdr){

	/*	In this block I checked if packet checkkSum is equal with checkSum from the packet. */

		uint16_t checkSumPacket = ip_hdr->check;
		checkSumPacket = ntohs(checkSumPacket);
		ip_hdr->check = 0;

		uint16_t checkSumLocal = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

		if(checkSumLocal != checkSumPacket){
			printf("This packet has different checkSum and I will drop him\n");
			return 1;
		}


	/* In this block I check if TTL is lower than either I will drop him or I will decrease TTL and recalculate checkSum */
		if(ip_hdr->ttl <= 1){
			printf("TTL of packet is lower and I will drop the packet\n");
			return 1;
		}else{
			ip_hdr->ttl--;
			ip_hdr->check = ntohs(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));  //convert checkSum from host order to network order
		}

		return 0;
}

//Function creates an arp header
struct arp_header* creatArpPacket(uint32_t *ipSource,uint32_t *ipDestination,uint8_t *macSource,uint8_t *macDestination,int op){

	struct arp_header* arp_request = calloc(1,sizeof(struct arp_header));
	DIE(arp_request == NULL, "Allocated arp_request was faild");

	arp_request->htype = htons(1);
	arp_request->ptype = htons(0x0800);
	arp_request->hlen = 6;
	arp_request->plen = 4;
	arp_request->op = htons(op); //request=1; relpay=2
	memcpy(arp_request->sha, macSource,6*sizeof(uint8_t));
	arp_request->spa = *ipSource;
	memcpy(arp_request->tha , macDestination,6*sizeof(uint8_t));
	arp_request->tpa = *ipDestination;

	return arp_request;
}

//Function search in arp table based ip for a tpecific mac address
int searchArpTable(struct iphdr *ip_hdr){

	for(int index = 0 ; index < arp_table.nrEntryTable; index++)
		if(ip_hdr->daddr == arp_table.arpEntryTable[index].ip)
			return index;

	return -1;

}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	char pathRouterTable[12] ;  //argv+1;
	memcpy(pathRouterTable,*(argv+1),sizeof(pathRouterTable));

	arp_table.arpEntryTable = calloc(50,sizeof(struct arp_entry));
	arp_table.nrEntryTable = 0;

	queue packetQueue = queue_create();
	
	routing_table.routingEntryTable = calloc(100000, sizeof(struct route_table_entry));
	DIE(routing_table.routingEntryTable == NULL, "Couldn't allocate routingEntryTable");
	routing_table.nrEntryTable = read_rtable(pathRouterTable, routing_table.routingEntryTable);
	qsort(routing_table.routingEntryTable, routing_table.nrEntryTable, sizeof(struct route_table_entry), compareEntruRoutingElements);

	uint32_t *ipInterface = calloc(1,sizeof(uint32_t));
	DIE(ipInterface == NULL, "Allocated ipInterdace was faild");

	uint8_t *macInterface = calloc(6,sizeof(uint8_t));
	DIE(macInterface == NULL, "Allocated macInterface was faild");

	uint8_t *macArdDestination = calloc(6,sizeof(uint8_t));
	DIE(macArdDestination == NULL, "Allocated macArpDestination was faild");

	uint8_t *macEtherDestination = calloc(1,6*sizeof(uint8_t));
	DIE(macEtherDestination == NULL, "Allocated macEtherDestination was faild");

	while (1) {
		size_t len;

		int interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr;
		struct iphdr *ip_hdr;
		struct arp_header *arp_hdr;

		eth_hdr = (struct ether_header *) buf;

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		if(eth_hdr->ether_type == htons(0x0800)){  //cheack Ip area
			
			ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));

			if(checkDestination(interface,eth_hdr) == 1){
				sendIcmpPacket(interface,eth_hdr,ip_hdr,buf,3);
				continue;
			}

			if(checkPacketSum_PacketTTL(ip_hdr) == 1){
				sendIcmpPacket(interface,eth_hdr,ip_hdr,buf,11);
				continue;
			}

			//Looking on routing table for specific network and interface through efficient binary search
			memset(&packetEntryRouterTable,0,sizeof(struct route_table_entry));
			targetEntryRoutingTable.mask = htonl(4294967040);
			targetEntryRoutingTable.prefix = ip_hdr->daddr & targetEntryRoutingTable.mask;
			if(searchBinaryNetwork(&packetEntryRouterTable,ip_hdr)==-1){
				sendIcmpPacket(interface,eth_hdr,ip_hdr,buf,11);
				continue;
			}

			int indexArtTable = searchArpTable(ip_hdr);

			if(indexArtTable >= 0){	//Found in ArpTable

				get_interface_mac(packetEntryRouterTable.interface,macInterface);

				memcpy(eth_hdr->ether_shost,macInterface,6*sizeof(uint8_t));
				memcpy(eth_hdr->ether_dhost,arp_table.arpEntryTable[indexArtTable].mac,6*sizeof(uint8_t));

				send_to_link(packetEntryRouterTable.interface,buf,98);
				continue;

			}else{
				
				//Don't found in ArpTable
				//In the below block of code I know that I didn't find in arp table the mac address and I
				//send on next hop interface an arp request si find them
				char buxAux[MAX_PACKET_LEN];
				memcpy(buxAux,buf,len);
				queue_enq(packetQueue,buxAux);

				inet_pton(AF_INET, get_interface_ip(packetEntryRouterTable.interface), ipInterface);

				get_interface_mac(packetEntryRouterTable.interface,macInterface);

				memset(macArdDestination,0x00,6*sizeof(uint8_t));

				uint32_t ipNextHop = packetEntryRouterTable.next_hop;
				struct arp_header *arp_request = creatArpPacket((uint32_t *)ipInterface,&ipNextHop,macInterface,macArdDestination,1);

				memset(macEtherDestination,0xff,6*sizeof(int8_t));
				struct ether_header  *eth_request = createEtherFrame(macInterface,macEtherDestination,0x0806);

				uint8_t *segmentRequest = calloc(1,sizeof(struct ether_header) + sizeof(struct arp_header));
				DIE(segmentRequest == NULL, "Allocated segmentRequest was faild");

				memcpy(segmentRequest,eth_request,sizeof(struct ether_header));
				memcpy(segmentRequest+sizeof(struct ether_header),arp_request,sizeof(struct arp_header));

				send_to_link(packetEntryRouterTable.interface,(void*)segmentRequest,sizeof(struct ether_header)+sizeof(struct arp_header));
				continue;
			}
			
		}

		if(eth_hdr->ether_type == htons(0x0806)){  //Arp area

			arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));
			
			//In the block below I receive an arp request and I check is for me and build a new arp packet to replay
			if(arp_hdr->op == htons(1)){ //Arp Request
				uint32_t ipInterface;
				inet_pton(AF_INET, get_interface_ip(interface),&ipInterface);

				if(ipInterface == arp_hdr->tpa){

					get_interface_mac(interface,macInterface);
					struct ether_header *ether_replay = createEtherFrame(macInterface,eth_hdr->ether_shost,0x0806);
					
					uint32_t ipDestination = arp_hdr->spa;
					struct arp_header *arp_replay=creatArpPacket(&ipInterface,&ipDestination,macInterface,arp_hdr->sha,2);
					
					uint8_t *segmentReplay = calloc(1,sizeof(struct ether_header)+sizeof(struct arp_header));
					DIE(segmentReplay == NULL,"Couldn't allocate was faild\n");

					memcpy(segmentReplay,ether_replay,sizeof(struct ether_header));
					memcpy(segmentReplay+sizeof(struct ether_header),arp_replay,sizeof(struct arp_header));

					send_to_link(interface,(char*)segmentReplay,sizeof(struct ether_header)+sizeof(struct arp_header));
					continue;
				}else{
					printf("It's Arp request and I'm not target\n");
					continue;
				}

			}

			//In this block I reseave an arp packet and I check queue to send on specific interface the IP packet 
			if(arp_hdr->op == htons(2)){  //Arp Replay
					
				arp_table.arpEntryTable[arp_table.nrEntryTable].ip=arp_hdr->spa;
				memcpy(arp_table.arpEntryTable[arp_table.nrEntryTable].mac,arp_hdr->sha,6*sizeof(uint8_t));
				arp_table.nrEntryTable++;

				if(!queue_empty(packetQueue)){
					memcpy(buf,queue_deq(packetQueue),98);
					eth_hdr = (struct ether_header*)buf;
					ip_hdr = (struct iphdr*)(buf+sizeof(struct ether_header));

					targetEntryRoutingTable.mask = htonl(4294967040);
					targetEntryRoutingTable.prefix = ip_hdr->daddr & targetEntryRoutingTable.mask;
					searchBinaryNetwork(&packetEntryRouterTable,ip_hdr);

					get_interface_mac(packetEntryRouterTable.interface,macInterface);

					int indexArtTable = searchArpTable(ip_hdr);
					eth_hdr = createEtherFrame(macInterface,arp_table.arpEntryTable[indexArtTable].mac,0x0800);

					memcpy(buf,eth_hdr,sizeof(struct ether_header));
					memcpy(buf+sizeof(struct ether_header),ip_hdr,sizeof(struct iphdr));

					send_to_link(packetEntryRouterTable.interface,buf,98);
					continue;
				}
			}
		}
	}

}

