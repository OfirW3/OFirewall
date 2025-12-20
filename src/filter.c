#include "filter.h"
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <signal.h>
#include <net/if.h>
#include <errno.h>

volatile sig_atomic_t stop_program = 0;

int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
        if(!data){
        fprintf(stderr, "Callback: Invalid data parameter, no verdict can be made.\n");
        return 1;
    }
    int queue_id = *(int*)data;  //1 for inbound, 2 for outbound
    unsigned char *payload;
    struct nfqnl_msg_packet_hdr *ph;
    uint32_t id;

    ph = nfq_get_msg_packet_hdr(nfa);
    if(!ph){
        fprintf(stderr,"Callback: Empty packet for %d queue. No verdict can be made.\n",queue_id);
        return 1;
    }
    id = ntohl(ph->packet_id);

    int ifindex = nfq_get_indev(nfa);  // Incoming interface
    if(ifindex < 0 || ifindex > max_ifaces){
        fprintf(stderr,"Callback: ifindex: %d is out of range\n",ifindex);
        return 1;
    }
    if(!g_config->iface_map->iface[ifindex]){
        fprintf(stderr, "Callback: ifindex was not found inside config. Edit config in main.\n");
        return 1;
    }
    int len = nfq_get_payload(nfa, &payload);
    if (len >= sizeof(struct iphdr)) {
        struct iphdr *ip = (struct iphdr*)payload;
        switch(queue_id){
            case 1:
                if(processPacket(g_config->iface_map->iface[ifindex], ip, true) == permit)
                {
                    printf("Callback: a valid rule was found for the inbound packet. Accepting! \n");
                    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
                }
                else{
                    printf("Callback: a valid rule was found for the inbound packet. Dropping! \n");
                    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                }
            case 2:
                if(processPacket(g_config->iface_map->iface[ifindex], ip, false) == permit){
                    printf("Callback: a valid rule was found for the outbound packet. Accepting!\n");
                    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
                }
                else{
                    printf("Callback: a valid rule was found for the inbound packet. Dropping! \n");
                    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                }
                
        }
    fprintf(stderr, "Warning: No valid verdict was taken; Dropping the packet.\n");
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
}

void handle_sigint(int sig){
    stop_program = 1;
    printf("\nSIGINT recived: Waiting for program to terminate...\n");
}

void cleanup_nfqueue(struct nfq_q_handle *q0, struct nfq_q_handle *q1, struct nfq_handle *h) {
    if (q0) nfq_destroy_queue(q0);
    if (q1) nfq_destroy_queue(q1);
    if (h)  nfq_close(h);
}

int main() {
    /*
    drop any packets except for the allowed traffic (client -> host and host -> client)
    */

    //Allocate global config
    g_config = malloc(sizeof(config));
    if (!g_config) {
        fprintf(stderr, "Error allocating config\n");
        return 1;
    }

    //Allocate map and dynamic array for the interfaces
    g_config->iface_map = calloc(1, sizeof(interface_map)); // All entries NULL
    g_config->interfaces = malloc(sizeof(dynamic_interfaces));

    if (!g_config->interfaces || !g_config->iface_map) {
        fprintf(stderr, "Error allocating internal config arrays\n");
        return 1;
    }

    dynInit_interfaces(g_config->interfaces, 4); // dynamic array of interfaces

    //Create veth-host interface
    interface veth1;
    memset(&veth1, 0, sizeof(interface));
    const char *ifname = "veth-host";
    
    veth1.id = if_nametoindex(ifname); 
    if (veth1.id == 0) {
        fprintf(stderr, "Error: the network interface named: %s was not found\n", ifname);
        return 1;
    }
    printf("Detected %s's ifindex: %d\n", ifname, veth1.id);
    strncpy(veth1.zone_name, ifname, sizeof(veth1.zone_name) - 1);

    //Some MAC address
    veth1.mac[0] = 0x00; veth1.mac[1] = 0x15; veth1.mac[2] = 0x5D;
    veth1.mac[3] = 0x01; veth1.mac[4] = 0x02; veth1.mac[5] = 0x03;

    /* Example IP network: 10.200.1.2/24 */
    veth1.net = malloc(sizeof(network));
    veth1.net->ip = make_ip(10, 200, 1, 2); // Client's address
    veth1.net->subnet = 24;

   //Allocate dynamic ACLs
    veth1.aclin = malloc(sizeof(dynamic_stdacl));
    veth1.aclout = malloc(sizeof(dynamic_stdacl));

    dynInit_stdacl(veth1.aclin, 4);
    dynInit_stdacl(veth1.aclout, 4);

    //Add the ACL rules for allowed traffic between the host and client
    network *host_addr = malloc(sizeof(network));
    host_addr->ip = make_ip(10, 200, 1, 1);
    host_addr->subnet = 24;
    
    network *client_addr = malloc(sizeof(network));
    client_addr->ip = veth1.net->ip;
    client_addr->subnet = 24;

    // Add rules
    add_rule(veth1.aclin, host_addr, permit);
    add_rule(veth1.aclout, client_addr, permit);

    //Add veth1 into config
    addInterface(g_config, veth1);

    //Add veth1 into map
    // Ensure we point to the data inside the dynamic array, not the local stack variable
    g_config->iface_map->iface[veth1.id] = &g_config->interfaces->data[0];

    printf("Firewall initialized with veth1 (ifindex = %d)\n", veth1.id);

    //NFQUEUE setup
    struct nfq_handle *h;
    struct nfq_q_handle *q0;
    struct nfq_q_handle *q1;
    int *inbound = (int *)malloc(sizeof(int));
    int *outbound = (int *)malloc(sizeof(int));
    
    *inbound = 1;
    *outbound = 2;

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "Error: failed to open nfq\n");
        return 1;
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error: failed to bind nfq to the program.\nAre you root?\n");
        return 1;
    }

    // Inbound netfilter queue (Queue 0)
    q0 = nfq_create_queue(h, 0, &cb, (void *)inbound);
    if (!q0) {
        fprintf(stderr, "Error: creation of nfq - q0 has failed\n");
        return 1;
    }

    // Outbound netfilter queue (Queue 1)
    q1 = nfq_create_queue(h, 1, &cb, (void *)outbound);
    if (!q1) {
        fprintf(stderr, "Error: creation of nfq - q1 has failed\n");
        return 1;
    }

    // Set Queue lengths
    if (nfq_set_queue_maxlen(q0, 4096) < 0) {
        fprintf(stderr, "Error: setting queue 0 max length has failed.\n");
        return 1;
    }
    if (nfq_set_queue_maxlen(q1, 4096) < 0) {
        fprintf(stderr, "Error: setting queue 1 max length has failed.\n");
        return 1;
    }

    // Set Queue modes (COPY_PACKET required to inspect payload)
    if (nfq_set_mode(q0, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Error: setting queue 0 mode has failed.\n");
        return 1;
    }
    if (nfq_set_mode(q1, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Error: setting queue 1 mode has failed.\n");
        return 1;
    }

    int fd = nfq_fd(h);
    char buffer[4096];
    
    signal(SIGINT, handle_sigint);
    
    printf("Listening for packets...\n");

    while (!stop_program) {
        int rv = recv(fd, buffer, sizeof(buffer), 0);
        if (rv > 0) {
            nfq_handle_packet(h, buffer, rv); // Callback called with the packet
        }
    }

    printf("Exited the program safely!\n");

    // Clean up
    nfq_destroy_queue(q0);
    nfq_destroy_queue(q1);
    nfq_close(h);
    
    free(g_config->iface_map);
    free(g_config->interfaces);
    free(host_addr);
    free(client_addr);
    free(inbound);
    free(outbound);
    free(g_config);

    return 0;
}