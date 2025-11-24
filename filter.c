#include "filter.h"
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/in.h>

void handle_prerouting(uint8_t iface_id, struct iphdr *src_ip){
    //Logic for inbound packet processing
}
void handle_output(uint8_t iface_id, struct iphdr *dst_ip){
    //Logic for outbound packet processing
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
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
               handle_prerouting(id,ip); //Pass directly into ProccesPacket function by extracting the IP addresses either here or inside the function
            case 1:
                handle_output(id,ip);
        }
    fprintf(stderr, "Warning: No valid verdict was taken; Accepting the packet.");
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
}

int main()
{
    return 0;
}