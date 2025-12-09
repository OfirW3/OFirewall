#include <stdint.h>
#include <netinet/ip.h>
#include "config.h"

void configInit(config *cfg);
action processPacket(interface *iface, struct iphdr *ip, bool incoming);

