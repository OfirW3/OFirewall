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

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
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
    if(ifindex < 0 || ifindex >= max_ifaces){
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
                if(process_packet(g_config->iface_map->iface[ifindex], ip, true) == permit)
                {
                    printf("Callback: a valid rule was found for the inbound packet. Accepting! \n");
                    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
                }
                else{
                    printf("Callback: a valid rule was found for the inbound packet. Dropping! \n");
                    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                }
            case 2:
                if(process_packet(g_config->iface_map->iface[ifindex], ip, false) == permit){
                    printf("Callback: a valid rule was found for the outbound packet. Accepting!\n");
                    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
                }
                else{
                    printf("Callback: a valid rule was found for the inbound packet. Dropping! \n");
                    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                }
        }
    }
    fprintf(stderr, "Warning: No valid verdict was taken; Dropping the packet.\n");
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

static void handle_sigint(int sig){
    stop_program = 1;
    printf("\nSIGINT recived: Waiting for program to terminate...\n");
}

static void cleanup_nfqueue(struct nfq_q_handle *q0, struct nfq_q_handle *q1, struct nfq_handle *h) {
    if (q0) nfq_destroy_queue(q0);
    if (q1) nfq_destroy_queue(q1);
    if (h)  nfq_close(h);
}

int main() {
    /*
    Example execution: Drop any packets except for the allowed traffic (client -> host and host -> client)
    */
    int main_status = 1; //Defult initianlization to error
    //Allocate global config
    g_config = malloc(sizeof(config));
    if (!g_config) {
        fprintf(stderr, "Error allocating config\n");
        return 1;
    }

    //Allocate map for the interfaces
    g_config->iface_map = calloc(1, sizeof(interface_map)); // All entries NULL

    if (!g_config->iface_map) {
        fprintf(stderr, "Error: Allocation of internal config map failed \n");
        goto cleanup_config;
    }

    //Create veth-host interface
    interface veth1;
    memset(&veth1, 0, sizeof(interface));
    const char* ifname = "veth-host";
    
    veth1.id = if_nametoindex(ifname); 
    if (veth1.id == 0) {
        fprintf(stderr, "Error: the network interface named: %s was not found\n", ifname);
        goto cleanup_config;
    }
    printf("Detected %s's ifindex: %d\n", ifname, veth1.id);
    strncpy(veth1.zone_name, ifname, sizeof(veth1.zone_name) - 1);

    //Some MAC address
    veth1.mac[0] = 0x00; veth1.mac[1] = 0x15; veth1.mac[2] = 0x5D;
    veth1.mac[3] = 0x01; veth1.mac[4] = 0x02; veth1.mac[5] = 0x03;

    /* Example IP network: 10.200.1.2/24 */
    veth1.net = malloc(sizeof(network));
    if(!veth1.net){
        fprintf(stderr, "Error: Allocation of veth1's IP address failed \n");
        goto cleanup_config;
    }
    veth1.net->ip = make_ip(10, 200, 1, 2); // Client's address
    veth1.net->subnet = 24;

   //Allocate dynamic ACLs
    veth1.aclin = malloc(sizeof(dynamic_stdacl));
    veth1.aclout = malloc(sizeof(dynamic_stdacl));
    if(!veth1.aclin || !veth1.aclout){
        fprintf(stderr, "Error: Allocation of veth1's ACLs failed \n");
        goto cleanup_veth1;
    }
    dynInit_stdacl(veth1.aclin, 4);
    dynInit_stdacl(veth1.aclout, 4);

    //Add the ACL rules for allowed traffic between the host and client
    network *host_addr = malloc(sizeof(network));
    if(!host_addr){
        fprintf(stderr, "Error: Allocation of hosts's IP address failed \n");
        goto cleanup_veth1;
    }
    host_addr->ip = make_ip(10, 200, 1, 1);
    host_addr->subnet = 24;
    
    network* client_addr = malloc(sizeof(network));
    if(!client_addr){
        fprintf(stderr, "Error: Allocation of client's IP address failed \n");
        goto cleanup_host_addr;
    }
    client_addr->ip = veth1.net->ip;
    client_addr->subnet = 24;

    // Add rules
    // * CHANGE THE RULS AS YOU LIKE *
    add_rule(veth1.aclin, host_addr, drop);
    add_rule(veth1.aclout, client_addr, drop);

    //Add veth1 into map
    g_config->iface_map->iface[veth1.id] = &veth1;

    printf("Firewall initialized with veth1 (ifindex = %d)\n", veth1.id);

    //NFQUEUE setup
    struct nfq_handle *h;
    struct nfq_q_handle *q0;
    struct nfq_q_handle *q1;
    int inbound = 1;
    int outbound = 2;

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
    q0 = nfq_create_queue(h, 0, &cb, (void*)&inbound);
    if (!q0) {
        fprintf(stderr, "Error: creation of nfq - q0 has failed\n");
        return 1;
    }

    // Outbound netfilter queue (Queue 1)
    q1 = nfq_create_queue(h, 1, &cb, (void*)&outbound);
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
    main_status = 0;

    // Clean up
    cleanup_nfqueue(q0, q1, h);
    free(client_addr);
    cleanup_host_addr:
    free(host_addr);
    cleanup_veth1:
    dynFree_stdacl(veth1.aclin);
    dynFree_stdacl(veth1.aclout);
    free(veth1.aclin);
    free(veth1.aclout);
    free(veth1.net);
    cleanup_config:
    free(g_config->iface_map);
    free(g_config);
    return main_status;
}