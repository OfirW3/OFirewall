#include <stdint.h>
#include "config.h"

void configInit(config *cfg);
action processPacket(interface *iface, bool incoming, uint32_t srIP, uint32_t dstIP);
