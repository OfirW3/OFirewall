#include <stdint.h>

typedef struct s_config config;
typedef struct s_interface interface;
typedef enum e_action action;

void configInit(config *cfg);
action processPacket(interface *iface, bool incoming, uint32_t srIP, uint32_t dstIP);
