#include "filter.h"
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <netinet/ip.h>

void handle_prerouting(uint8_t iface_id, struct iphdr *src_ip){
    //Logic for inbound packet processing
}
void handle_output(uint8_t iface_id, struct iphdr *dst_ip){
    //Logic for outbound packet processing
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
    int queue_id = *(int*)data;  // Which hook this queue represents

    unsigned char *payload;
    struct nfqnl_msg_packet_hdr *ph;
    uint8_t id;

    ph = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(ph->packet_id);

    int ifindex = nfq_get_indev(nfa);  // Incoming interface
    int len = nfq_get_payload(nfa, &payload);

    if (len >= sizeof(struct iphdr)) {
        struct iphdr *ip = (struct iphdr*)payload;
        switch(queue_id){
            case 0:
                if(processPacket(g_config->iface_map->iface[ifindex], ip, true) == permit)
                {
                    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
                }
            case 1:
                if(processPacket(g_config->iface_map->iface[ifindex], ip, false) == permit){
                    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
                }
        }
    fprintf(stderr, "Warning: No valid verdict was taken; Dropping the packet.");
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
}

int main(){
    struct nfq_handle *h;
    struct nfq_q_handle *q0;
    struct nfq_q_handle *q1;

    h = nfq_open();
    nfq_unbind_pf(h, AF_INET);
    nfq_bind_pf(h, AF_INET);

    q0 = nfq_create_queue(h, 0, &cb, NULL);
    q1 = nfq_create_queue(h, 1, &cb, NULL);

    nfq_set_queue_maxlen(q0, 4096);
    nfq_set_queue_maxlen(q1, 4096);

    nfq_set_mode(q0, NFQNL_COPY_PACKET, 0xffff);
    nfq_set_mode(q1, NFQNL_COPY_PACKET, 0xffff);

    int fd = nfq_fd(h);
    char buffer[4096];

    while(true){
        int rv = recv(fd, buffer, sizeof(buffer), 0);
        if(rv > 0){
            nfq_handle_packet(h, buffer, rv); //Callback called with the packet
        }
    }
    return 0;
}