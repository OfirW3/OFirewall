#pragma once
#include "firewall.h"

struct nfq_q_handle;
struct nfq_handle;
struct nfgenmsg;
struct nfq_data;

void handle_prerouting(uint32_t iface_id, uint32_t ip);
void handle_output(uint32_t iface_id, uint32_t ip);
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
struct nfq_q_handle* create_queue(struct nfq_handle *h, int qnum);
