#include "fsl_1588.h"

/*************************PTP Clock*************************/
clockid_t get_clockid(int fd)
{
#define CLOCKFD 3
#define FD_TO_CLOCKID(fd)	((~(clockid_t) (fd) << 3) | CLOCKFD)
	return FD_TO_CLOCKID(fd);
}

/* When glibc offers the syscall, this will go away. */
#include <sys/syscall.h>
int clock_adjtime(clockid_t id, struct timex *tx)
{
	return syscall(__NR_clock_adjtime, id, tx);
}





/*************************HW Timestamp*************************/
//select HWTSTAMP_TX_ON or HWTSTAMP_TX_OFF
void hwtstamp_tx_ctl(NetPath * netPath, Boolean enable)
{
	struct ifreq hwtstamp;
	struct hwtstamp_config hwconfig;

	memset(&hwtstamp, 0, sizeof(hwtstamp));
	strncpy(hwtstamp.ifr_name, fsl_1588_if_name, sizeof(hwtstamp.ifr_name));
	hwtstamp.ifr_data = (void *)&hwconfig;
	memset(&hwconfig, 0, sizeof(hwconfig));
	hwconfig.tx_type =
		enable ?
		HWTSTAMP_TX_ON : HWTSTAMP_TX_OFF;
	hwconfig.rx_filter = HWTSTAMP_FILTER_PTP_V1_L4_SYNC;
	if (ioctl(netPath->eventSock, SIOCSHWTSTAMP, &hwtstamp) < 0
		|| ioctl(netPath->generalSock, SIOCSHWTSTAMP, &hwtstamp) < 0)
			printf("error:hwtstamp_tx_ctl\n");
}

//select SOF_TIMESTAMPING_RX_HARDWARE or SOF_TIMESTAMPING_TX_HARDWARE
void hwtstamp_rx_init(NetPath * netPath, Boolean isRecv)
{
	int so_timestamping_flags = 0;

	so_timestamping_flags = isRecv ? SOF_TIMESTAMPING_RX_HARDWARE : SOF_TIMESTAMPING_TX_HARDWARE;
	so_timestamping_flags = so_timestamping_flags | SOF_TIMESTAMPING_RAW_HARDWARE;

	if (setsockopt(netPath->eventSock, SOL_SOCKET, SO_TIMESTAMPING, &so_timestamping_flags, sizeof(so_timestamping_flags)) < 0
		|| setsockopt(netPath->generalSock, SOL_SOCKET, SO_TIMESTAMPING, &so_timestamping_flags, sizeof(so_timestamping_flags)) < 0) {
		printf("error:hwtstamp_rx_init\n");
	}
}

ssize_t
hwtstamp_tx_get(Octet * buf, TimeInternal * time, NetPath * netPath)
{
	ssize_t ret;
	struct msghdr msg;
	struct iovec vec[1];
	struct sockaddr_in from_addr;

	union {
		struct cmsghdr cm;
		char	control[3*CMSG_SPACE(sizeof(struct timeval))];
	}     cmsg_un;

	struct cmsghdr *cmsg;
	struct timespec * ts;

	vec[0].iov_base = buf;
	vec[0].iov_len = PACKET_SIZE;

	memset(&msg, 0, sizeof(msg));
	memset(&from_addr, 0, sizeof(from_addr));
	memset(buf, 0, PACKET_SIZE);
	memset(&cmsg_un, 0, sizeof(cmsg_un));

	msg.msg_name = (caddr_t)&from_addr;
	msg.msg_namelen = sizeof(from_addr);
	msg.msg_iov = vec;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_un.control;
	msg.msg_controllen = sizeof(cmsg_un.control);
	msg.msg_flags = 0;

	if (netSelect(0, netPath) <= 0)
		return 0;

	ret = recvmsg(netPath->eventSock, &msg, MSG_ERRQUEUE);

	if (ret <= 0) {
	printf("error:hwtstamp_tx_get\n");
		if (errno == EAGAIN || errno == EINTR)
			return 0;
		return ret;
	}

	if (msg.msg_controllen <= 0) {
		ERROR("received short ancillary data (%ld/%ld)\n",
		    (long)msg.msg_controllen, (long)sizeof(cmsg_un.control));
		return 0;
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET) {
			if(cmsg->cmsg_type == SCM_TIMESTAMPING) {
				ts = (struct timespec *)CMSG_DATA(cmsg);
				//printf("SO_TIMESTAMPING ");
				//printf("SW %ld.%09ld ",
				//       (long)ts->tv_sec,
				//       (long)ts->tv_nsec);
				ts++;
				//printf("HW transformed %ld.%09ld ",
				//       (long)ts->tv_sec,
				//       (long)ts->tv_nsec);
				ts++;
				//printf("HW raw %ld.%09ld\n",
				//       (long)ts->tv_sec,
				//       (long)ts->tv_nsec);
				time->seconds = ts->tv_sec;
				time->nanoseconds = ts->tv_nsec;
				break;
			}
		}
	}
	return ret;
}
