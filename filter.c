#include "filter.h"
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <netinet/ip.h>


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
    /*
    DROP ANY PACKET EXCEPT FOR LOOPBACK INBOUND AND OUTBOUND PACKETS
    */

    /* ============================
       1) Allocate global config
       ============================ */
    g_config = malloc(sizeof(config));
    if (!g_config) {
        fprintf(stderr, "Error allocating config\n");
        return 1;
    }

    /* ============================
       2) Allocate maps + arrays
       ============================ */
    g_config->iface_map  = calloc(1, sizeof(interface_map));   // All entries NULL
    g_config->interfaces = malloc(sizeof(dynamic_interfaces));
    g_config->accounts   = malloc(sizeof(dynamic_users));

    if (!g_config->interfaces || !g_config->accounts || !g_config->iface_map) {
        fprintf(stderr, "Error allocating internal config arrays\n");
        return 1;
    }

    dynInit_interfaces(g_config->interfaces, 4);  // dynamic array of interfaces
    dynInit_users(g_config->accounts, 8);         // dynamic array of users

    /* ============================
       3) Create one interface: eth0, ifindex=2
       ============================ */
    interface eth0;
    memset(&eth0, 0, sizeof(interface));

    eth0.id = 2;  // ← this MUST match ifindex
    strncpy(eth0.zone_name, "eth0", sizeof(eth0.zone_name)-1);

    /* Example MAC: */
    eth0.mac[0] = 0x00;
    eth0.mac[1] = 0x15;
    eth0.mac[2] = 0x5D;
    eth0.mac[3] = 0x01;
    eth0.mac[4] = 0x02;
    eth0.mac[5] = 0x03;

    /* Example IP network: 192.168.1.10/24 */
    eth0.net = malloc(sizeof(network));
    eth0.net->ip     = make_ip(192,168,1,10);
    eth0.net->subnet = 24;

    /* ============================
       4) Allocate ACLs
       ============================ */
    eth0.aclin  = malloc(sizeof(dynamic_stdacl));
    eth0.aclout = malloc(sizeof(dynamic_stdacl));

    dynInit_stdacl(eth0.aclin,  4);
    dynInit_stdacl(eth0.aclout, 4);

    /* ============================
       5) Add example ACL entries
       ============================ */
    network *allow_loopback = malloc(sizeof(network));
    allow_loopback->ip = make_ip(127,0,0,1);
    allow_loopback->subnet = 32;

    add_rule(eth0.aclin, allow_loopback, permit);   // inbound
    add_rule(eth0.aclout, allow_loopback, permit);  // outbound

    /* ============================
       6) Register in dynamic array (optional)
       ============================ */
    addInterface(g_config, eth0);

    /* ============================
       7) Register in interface_map
       ============================ */
    g_config->iface_map->iface[2] = &g_config->interfaces->data[0];
    // important: use pointer from the dynamic array, not local variable

    printf("Firewall initialized with eth0 (ifindex = 2)\n");

    /* ============================
       8) Continue with NFQUEUE setup...
       ============================ */
    

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