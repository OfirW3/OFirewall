#pragma once
#include "config.h"

struct nfq_q_handle;
struct nfq_handle;
struct nfgenmsg;
struct nfq_data;


int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
void handle_sigint(int sig);
void cleanup_nfqueue(struct nfq_q_handle *q0, struct nfq_q_handle *q1, struct nfq_handle *h);
int main();