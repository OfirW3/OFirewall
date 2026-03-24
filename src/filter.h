#pragma once
#include "config.h"

struct nfq_q_handle;
struct nfq_handle;
struct nfgenmsg;
struct nfq_data;


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
static void handle_sigint(int sig);
static void cleanup_nfqueue(struct nfq_q_handle *q0, struct nfq_q_handle *q1, struct nfq_handle *h);
int main();