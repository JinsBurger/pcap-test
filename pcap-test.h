#include "./headers.h"


#define TO_MAC_STR(host,result) \
do {\
    snprintf(result, sizeof(result), "%02x:%02x:%02x:%02x:%02x:%02x", host[0], host[1], host[2], host[3], host[4], host[5]); \
} while(0)

E_STATUS is_ipv4_tcp_packet(const u_char* packet) {
    struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr*)packet;
    struct libnet_ipv4_hdr *hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
    if(ntohs(eth_hdr->ether_type) != IPPROTO_IPV4 || hdr->ip_p != IPPROTO_TCP) {
        return IS_NOT_IPV4_TCP;
    }
    return SUCCESS;
}


void dump_ethernet_hdr(struct libnet_ethernet_hdr *eth_hdr) {
    char tmp_mac_str[0x300] = {0,};
    TO_MAC_STR(eth_hdr->ether_shost, tmp_mac_str);
    printf("Source Mac: %s \n", tmp_mac_str);

    TO_MAC_STR(eth_hdr->ether_dhost, tmp_mac_str);
    printf("Destination Mac: %s \n", tmp_mac_str);
}

void dump_ipv4_hdr(struct libnet_ipv4_hdr *ip_hdr) {
    printf("Source ip: %s \n", inet_ntoa(ip_hdr->ip_src));
    printf("Destination ip: %s \n", inet_ntoa(ip_hdr->ip_dst));
}

void dump_tcp_hdr(struct libnet_tcp_hdr *tcp_hdr) {
    printf("Source port: %d \n", ntohs(tcp_hdr->th_sport));
    printf("Destination port: %d \n", ntohs(tcp_hdr->th_dport));
}


void dump_hex(u_char *data, size_t max_size) {
    for(int i=0; i < max_size / 10; i++) {
        for(int j=0; i*10+j < max_size; j++) {
            printf("%02x ", data[i*10+j]);
        }
        printf("\n");
    }
    
}

void dump_ipv4_tcp_packet(const u_char* packet) {
    struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr*)packet;
    struct libnet_ipv4_hdr *ipv4_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
    struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr*)((char*)ipv4_hdr+sizeof(*ipv4_hdr));
    char *data = (char*)tcp_hdr+sizeof(*tcp_hdr);
    printf("\n== TCP PACKET == \n\n");
    printf("- ETHERNET HEADER - \n");
    dump_ethernet_hdr(eth_hdr);
    printf("- IP HEADER - \n");
    dump_ipv4_hdr(ipv4_hdr);
    printf("- TCP HEADER - \n");
    dump_tcp_hdr(tcp_hdr);
    printf("- DATA - \n");
    dump_hex(data, 20);
    printf("\n================\n\n");
    
}