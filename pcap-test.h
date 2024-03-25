#include "./headers.h"

E_STATUS is_ipv4_tcp_packet(const u_char* packet) {
    struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr*)packet;
    struct libnet_ipv4_hdr *hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
    if(eth_hdr->ether_type == IPPROTO_IPV4 && hdr->ip_p == IPPROTO_TCP) {
        return IS_NOT_IPV4_TCP;
    }
    return SUCCESS;
}