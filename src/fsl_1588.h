#include "ptpd.h"
#include <linux/net_tstamp.h>
/*************************MACROS*************************/
#ifndef SO_TIMESTAMPING
# define SO_TIMESTAMPING         37
# define SCM_TIMESTAMPING        SO_TIMESTAMPING
#endif

#ifndef SIOCSHWTSTAMP
# define SIOCSHWTSTAMP 0x89b0
#endif

#ifndef CLOCK_INVALID
#define CLOCK_INVALID -1
#endif



/*************************VARIABLES*************************/
clockid_t clkid;
char fsl_1588_if_name[IFACE_NAME_LENGTH];






/*************************FUNCTIONS*************************/
clockid_t get_clockid(int fd);
int clock_adjtime(clockid_t id, struct timex *tx);

void hwtstamp_tx_ctl(NetPath * netPath, Boolean enable);
void hwtstamp_rx_init(NetPath * netPath, Boolean isRecv);
ssize_t hwtstamp_tx_get(Octet * buf, TimeInternal * time, NetPath * netPath);
