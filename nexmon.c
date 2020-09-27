/***************************************************************************
 *                                                                         *
 *          ###########   ###########   ##########    ##########           *
 *         ############  ############  ############  ############          *
 *         ##            ##            ##   ##   ##  ##        ##          *
 *         ##            ##            ##   ##   ##  ##        ##          *
 *         ###########   ####  ######  ##   ##   ##  ##    ######          *
 *          ###########  ####  #       ##   ##   ##  ##    #    #          *
 *                   ##  ##    ######  ##   ##   ##  ##    #    #          *
 *                   ##  ##    #       ##   ##   ##  ##    #    #          *
 *         ############  ##### ######  ##   ##   ##  ##### ######          *
 *         ###########    ###########  ##   ##   ##   ##########           *
 *                                                                         *
 *            S E C U R E   M O B I L E   N E T W O R K I N G              *
 *                                                                         *
 * This file is part of NexMon.                                            *
 *                                                                         *
 * Based on:                                                               *
 *                                                                         *
 * This code is based on the ldpreloadhook example by Pau Oliva Fora       *
 * <pofłeslack.org> and the idea of hooking ioctls to fake a monitor mode  *
 * interface, which was presented by Omri Ildis, Yuval Ofir and Ruby       *
 * Feinstein at recon2013.                                                 *
 *                                                                         *
 * Copyright (c) 2016 NexMon Team                                          *
 *                                                                         *
 * NexMon is free software: you can redistribute it and/or modify          *
 * it under the terms of the GNU General Public License as published by    *
 * the Free Software Foundation, either version 3 of the License, or       *
 * (at your option) any later version.                                     *
 *                                                                         *
 * NexMon is distributed in the hope that it will be useful,               *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of          *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           *
 * GNU General Public License for more details.                            *
 *                                                                         *
 * You should have received a copy of the GNU General Public License       *
 * along with NexMon. If not, see <http://www.gnu.org/licenses/>.          *
 *                                                                         *
 **************************************************************************/

#include <stdarg.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <linux/sockios.h>
#include <linux/wireless.h>
#include <monitormode.h>
#include <errno.h>
#include <net/if.h>
#include <nexioctls.h>
#include <string.h>

#define CONFIG_LIBNL

#ifdef CONFIG_LIBNL
#include <linux/nl80211.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/genetlink.h>
#endif // CONFIG_LIBNL

#define __USE_POSIX199309
#define _POSIX_C_SOURCE 199309L
#include <time.h>

typedef unsigned int uint;

#define TYPEDEF_BOOL // define this to make <typedefs.h> not throw an error trying to redefine bool
#include <typedefs.h>
#include <bcmwifi_channels.h>

#define WLC_GET_MONITOR                 107
#define WLC_SET_MONITOR                 108

struct nexio {
    struct ifreq *ifr;
    int sock_rx_ioctl;
    int sock_rx_frame;
    int sock_tx;
};

extern int nex_ioctl(struct nexio *nexio, int cmd, void *buf, int len, bool set);
extern struct nexio *nex_init_ioctl(const char *ifname);

#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *) -1l)
#endif

#define REAL_LIBC RTLD_NEXT
#ifdef CONFIG_LIBNL
#define REAL_LIBNL RTLD_NEXT
#endif // CONFIG_LIBNL

int frequency_to_channel(int);
int nex_set_channel_simple(int);
int nex_set_channel_full(uint32, uint32, uint32, uint32);

typedef int request_t;

typedef void (*sighandler_t)(int);

static struct nexio *nexio = NULL;

static const char *ifname = "wlan0";

static int (*func_sendto) (int, const void *, size_t, int, const struct sockaddr *, socklen_t) = NULL;
static int (*func_ioctl) (int, request_t, void *) = NULL;
static int (*func_socket) (int, int, int) = NULL;
static int (*func_bind) (int, const struct sockaddr *, int) = NULL;
static int (*func_write) (int, const void *, size_t) = NULL;
#ifdef CONFIG_LIBNL
static int (*func_nl_send_auto_complete) (struct nl_sock *, struct nl_msg *) = NULL;
#endif // CONFIG_LIBNL

static void _libmexmon_init() __attribute__ ((constructor));
static void _libmexmon_init() {
    nexio = nex_init_ioctl(ifname);

    if (! func_ioctl)
        func_ioctl = (int (*) (int, request_t, void *)) dlsym (REAL_LIBC, "ioctl");

    if (! func_socket)
        func_socket = (int (*) (int, int, int)) dlsym (REAL_LIBC, "socket");

    if (! func_bind)
        func_bind = (int (*) (int, const struct sockaddr *, int)) dlsym (REAL_LIBC, "bind");

    if (! func_write)
        func_write = (int (*) (int, const void *, size_t)) dlsym (REAL_LIBC, "write");

    if (! func_sendto)
        func_sendto = (int (*) (int, const void *, size_t, int, const struct sockaddr *, socklen_t)) dlsym (REAL_LIBC, "sendto");

#ifdef CONFIG_LIBNL
    if (! func_nl_send_auto_complete)
	func_nl_send_auto_complete = (int (*) (struct nl_sock *, struct nl_msg *)) dlsym(REAL_LIBNL, "nl_send_auto_complete");
#endif // CONFIG_LIBNL
}

#ifdef CONFIG_LIBNL
static int _nl80211_type = 0;
int nl80211_type()
{
	if(_nl80211_type)
	{
		// fprintf(stderr, "cached\n");
		return _nl80211_type;
	}
		
	int rval;
	struct nl_sock *nl_sock = NULL;
	struct nl_cache *nl_cache = NULL;
	struct genl_family *nl80211 = NULL;

	// fprintf(stderr, "beginning\n");
	nl_sock = nl_socket_alloc();
	// fprintf(stderr, "nl_sock=%d\n", nl_sock);
	if(!nl_sock)
		return 0;

	rval = genl_connect(nl_sock);
	// fprintf(stderr, "genl_connect=%d\n", rval);
	if(rval)
	{
		nl_socket_free(nl_sock);
		return 0;
	}

	rval = genl_ctrl_alloc_cache(nl_sock, &nl_cache);
	// fprintf(stderr, "genl_ctrl_allocate_cache=%d\n", rval);
	if(rval)
	{
		nl_socket_free(nl_sock);
		return 0;
	}

	nl80211 = genl_ctrl_search_by_name(nl_cache, "nl80211");
	// fprintf(stderr, "genl_ctrl_search_by_name=%d\n", !!nl80211);

	if(nl80211)
	{
		_nl80211_type = genl_family_get_id(nl80211);
		// fprintf(stderr, "_nl80211_type=%d\n", _nl80211_type);
	}

	nl_cache_free(nl_cache);
	nl_socket_free(nl_sock);
	return _nl80211_type;
}

void handle_nl_msg(struct nl_msg *msg)
{
	int retval;
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct nlattr *attr[NL80211_ATTR_MAX+1];
	struct nla_policy policy[4] = {
		[0] = { .type = NLA_U32 },
		};

	nlh = nlmsg_hdr(msg);


	// if this isn't an nl80211 message, we don't want it                                                                                                             
	if(nlh->nlmsg_type != nl80211_type())                                                                                                                             
		return;                                                                                                                                                   
	if(nlmsg_get_proto(msg) != NETLINK_GENERIC)
		return;

	// fprintf(stderr, "nlmsg_parse\n");
	retval = nlmsg_parse(nlh, GENL_HDRLEN, attr, NL80211_ATTR_MAX, policy);
	// fprintf(stderr, "retval=%d\n", retval);
	if(retval)
		return;

	ghdr = nlmsg_data(nlh);
	if(ghdr->cmd == NL80211_CMD_SET_WIPHY)
	{
		int chan = 0;
		int bandwidth = WL_CHANSPEC_BW_20;
		int offset_chan = 0;
		if(!attr[NL80211_ATTR_IFINDEX])
			return;
		if( nla_get_u32(attr[NL80211_ATTR_IFINDEX]) != if_nametoindex(ifname))
			return;
		// fprintf(stderr, "NL80211_ATTR_IFINDEX = %u\n", nla_get_u32(attr[NL80211_ATTR_IFINDEX]));

		if(attr[NL80211_ATTR_WIPHY_FREQ])
		{
			int freq = nla_get_u32(attr[NL80211_ATTR_WIPHY_FREQ]);
			chan = frequency_to_channel(freq);
			// fprintf(stderr, "NL80211_ATTR_WIPHY_FREQ = %u (%d)\n", freq, chan);
					}
		if(attr[NL80211_ATTR_WIPHY_CHANNEL_TYPE])
		{
			// fprintf(stderr, "NL80211_ATTR_WIPHY_CHANNEL_TYPE = %u\n", nla_get_u32(attr[NL80211_ATTR_WIPHY_CHANNEL_TYPE]));
		}
		if(attr[NL80211_ATTR_CHANNEL_WIDTH])
		{
			// fprintf(stderr, "NL80211_ATTR_CHANNEL_WIDTH = %u\n", nla_get_u32(attr[NL80211_ATTR_CHANNEL_WIDTH]));
		}
		if(attr[NL80211_ATTR_CENTER_FREQ1])
		{
			int freq = nla_get_u32(attr[NL80211_ATTR_CENTER_FREQ1]);
			// fprintf(stderr, "NL80211_ATTR_CENTER_FREQ1 = %u\n", freq, frequency_to_channel(freq));
		}
		// this device doesn't support 80+80 anyway
		// if(attr[NL80211_ATTR_CENTER_FREQ2])
		//	fprintf(stderr, "NL80211_ATTR_CENTER_FREQ2 = %u\n", nla_get_u32(attr[NL80211_ATTR_CENTER_FREQ2]));
		if(chan)
			nex_set_channel_simple(chan);

	}
	if(ghdr->cmd == NL80211_CMD_SET_INTERFACE)
	{
		if(!attr[NL80211_ATTR_IFINDEX])
			return;
		if( nla_get_u32(attr[NL80211_ATTR_IFINDEX]) != if_nametoindex(ifname))
			return;
		// fprintf(stderr, "NL80211_ATTR_IFINDEX = %u\n", nla_get_u32(attr[NL80211_ATTR_IFINDEX]));

		// we should set monitor/managed mode based on this message
		if(attr[NL80211_ATTR_IFTYPE])
		{
			// fprintf(stderr, "NL80211_ATTR_IFTYPE = %u\n", nla_get_u32(attr[NL80211_ATTR_IFTYPE]));
		}
	}

}

// there are several other functions that can send netlink messages, but it looks like airodump-ng and kismet both use this one, so this is good enough for now
int nl_send_auto_complete(struct nl_sock *sk, struct nl_msg *msg)
{
	int ret;

	ret = func_nl_send_auto_complete(sk, msg);

	// fprintf(stderr, "\nnl_send_auto_complete()\n");
	handle_nl_msg(msg);
	return ret;
}
#endif // CONFIG_LIBNL

int frequency_to_channel(int freq_in_MHz)
{
	if(freq_in_MHz == 2484)
		return 14;
	if(freq_in_MHz >= 2412 && freq_in_MHz <= 2472)
		return (freq_in_MHz-2407)/5;
	if(freq_in_MHz >= 5000 && freq_in_MHz <= 6000)
		return (freq_in_MHz-5000)/5;

	return 0;
}

int nex_set_channel_simple(int channel)
{
	int band = ((channel <= CH_MAX_2G_CHANNEL) ? WL_CHANSPEC_BAND_2G : WL_CHANSPEC_BAND_5G);
	return nex_set_channel_full(channel, band, WL_CHANSPEC_BW_20, 0);
}

int nex_set_channel_full(uint32 channel, uint32 band, uint32 bw, uint32 ctl_sb)
{
	char charbuf[13] = "chanspec";
	uint32 *chanspec = (uint32*) &charbuf[9];

	*chanspec = (channel | band | bw | ctl_sb);
	// fprintf(stderr, "setting channel: channel=%08x   band=%08x   bw=%08x  ctl_sb=%08x  chanspec=%08x\n", channel, band, bw, ctl_sb, *chanspec);
	return nex_ioctl(nexio, WLC_SET_VAR, charbuf, 13, true);
}

int
ioctl(int fd, request_t request, ...)
{
    va_list args;
    void *argp;
    int ret;
    
    va_start (args, request);
    argp = va_arg (args, void *);
    va_end (args);

    ret = func_ioctl(fd, request, argp);
    //if (ret < 0) {
    //    fprintf(stderr, "LIBNEXMON: original response: %d, request: 0x%x\n", ret, request);
    //}

    switch (request) {
        case SIOCGIFHWADDR:
            {
                int buf;
                struct ifreq* p_ifr = (struct ifreq *) argp;
                if (!strncmp(p_ifr->ifr_ifrn.ifrn_name, ifname, strlen(ifname))) {
                    nex_ioctl(nexio, WLC_GET_MONITOR, &buf, 4, false);
                    
                    if (buf & MONITOR_IEEE80211) p_ifr->ifr_hwaddr.sa_family = ARPHRD_IEEE80211;
                    else if (buf & MONITOR_RADIOTAP) p_ifr->ifr_hwaddr.sa_family = ARPHRD_IEEE80211_RADIOTAP;
                    else if (buf & MONITOR_DISABLED || buf & MONITOR_LOG_ONLY || buf & MONITOR_DROP_FRM || buf & MONITOR_IPV4_UDP)
                        p_ifr->ifr_hwaddr.sa_family = ARPHRD_ETHER;

                    ret = 0;
                }
            }
            break;

        case SIOCGIWMODE:
            {
                int buf;
                struct iwreq* p_wrq = (struct iwreq*) argp;
                
                if (!strncmp(p_wrq->ifr_ifrn.ifrn_name, ifname, strlen(ifname))) {
                    nex_ioctl(nexio, WLC_GET_MONITOR, &buf, 4, false);

                    if (buf & MONITOR_RADIOTAP || buf & MONITOR_IEEE80211 || buf & MONITOR_LOG_ONLY || buf & MONITOR_DROP_FRM || buf & MONITOR_IPV4_UDP) {
                        p_wrq->u.mode = IW_MODE_MONITOR;
                    }

                    ret = 0;
                }
            }
            break;

        case SIOCSIWMODE:
            {
                int buf;
                struct iwreq* p_wrq = (struct iwreq*) argp;

                if (!strncmp(p_wrq->ifr_ifrn.ifrn_name, ifname, strlen(ifname))) {
                    if (p_wrq->u.mode == IW_MODE_MONITOR) {
                        buf = MONITOR_RADIOTAP;
                    } else {
                        buf = MONITOR_DISABLED;
                    }

                    ret = nex_ioctl(nexio, WLC_SET_MONITOR, &buf, 4, true);
                }
            }
            break;

        case SIOCSIWFREQ: // set channel/frequency (Hz)
            {
                struct iwreq* p_wrq = (struct iwreq*) argp;

                if (!strncmp(p_wrq->ifr_ifrn.ifrn_name, ifname, strlen(ifname))) {
		    char charbuf[13] = "chanspec";
		    uint32 *chanspec = (uint32*) &charbuf[9];
		    int channel = p_wrq->u.freq.m;
		    int exp = p_wrq->u.freq.e;

		    // TODO: test this!
		    // fprintf(stderr, "SIWFREQ: chan/freq: m=%d e=%d\n", channel, exp);
		    // if this is > 500 (or 1000, depending on the source), it's a frequency, not a channel
		    if(channel > 500 || exp > 0)
		    {
			    // convert from Hz to MHz
			    if(exp < 6)
			    {
				    for(int i=0;i<exp; i++)
					    channel *= 10;
				    channel /= 1000000;
			    }
			    else
			    {
				    for(int i=6;i<exp;i++)
					    channel *= 10;
			    }
			    // convert from frequency to channel
			    channel = frequency_to_channel(channel);
		    }

		    // fprintf(stderr, "SIWFREQ: channel=%08x\n", channel);
		    ret = nex_set_channel_simple(channel);

                }

                //if (ret < 0)
                    //fprintf(stderr, "LIBNEXMON: SIOCSIWFREQ not fully implemented\n");
            }
            break;

        case SIOCGIWFREQ: // get channel/frequency (Hz)
            {
		struct iwreq* p_wrq = (struct iwreq*) argp;

		if (!strncmp(p_wrq->ifr_ifrn.ifrn_name, ifname, strlen(ifname))) {
		    char charbuf[9] = "chanspec";
		    uint16 chanspec;
		    int32 channel;
		    ret = nex_ioctl(nexio, WLC_GET_VAR, charbuf, 9, false);
		    if(ret >= 0) {
			chanspec = *(uint16 *) charbuf;
			channel = chanspec & 0xFF;
			p_wrq->u.freq.e = 0;
			p_wrq->u.freq.m = channel;
			// fprintf(stderr, "GIWFREQ: channel=%d\n", channel);
		    }

		}


                //if (ret < 0)
                    //fprintf(stderr, "LIBNEXMON: SIOCGIWFREQ not fully implemented\n");
            }
            break;
    }
    return ret;
}

void
hexdump(const char *desc, const void *addr, int len)
{
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != 0)
        printf ("%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

static char sock_types[][16] = { 
    "SOCK_STREAM", 
    "SOCK_DGRAM", 
    "SOCK_RAW", 
    "SOCK_RDM", 
    "SOCK_SEQPACKET",
};

static char domain_types[][16] = { 
    "AF_UNSPEC", 
    "AF_UNIX", 
    "AF_INET", 
    "AF_AX25", 
    "AF_IPX", 
    "AF_APPLETALK", 
    "AF_NETROM", 
    "AF_BRIDGE",
    "AF_ATMPVC",
    "AF_X25",
    "AF_INET6",
    "AF_ROSE",
    "AF_DECnet",
    "AF_NETBEUI",
    "AF_SECURITY",
    "AF_KEY",
    "AF_NETLINK",
    "AF_PACKET",
    "AF_ASH",
    "AF_ECONET",
    "AF_ATMSVC",
    "AF_RDS",
    "AF_SNA",
    "AF_IRDA",
    "AF_PPPOX",
    "AF_WANPIPE",
    "AF_LLC",
    "AF_IB",
    "AF_MPLS",
    "AF_CAN",
    "AF_TIPC",
    "AF_BLUETOOTH",
    "AF_IUCV",
    "AF_RXRPC",
    "AF_ISDN",
    "AF_PHONET",
    "AF_IEEE802154",
    "AF_CAIF",
    "AF_ALG",
    "AF_NFC",
    "AF_VSOCK",
    "AF_KCM",
    "AF_QIPCRTR",
    "AF_SMC"
};

int socket_to_type[100] = { 0 };
char bound_to_correct_if[100] = { 0 };

int
socket(int domain, int type, int protocol)
{
    int ret;

    ret = func_socket(domain, type, protocol);

    // save the socket type
    if (ret < sizeof(socket_to_type)/sizeof(socket_to_type[0]))
        socket_to_type[ret] = type;

    //if ((type - 1 < sizeof(sock_types)/sizeof(sock_types[0])) && (domain - 1 < sizeof(domain_types)/sizeof(domain_types[0])))
    //    printf("LIBNEXMON: %d = %s(%s(%d), %s(%d), %d)\n", ret, __FUNCTION__, domain_types[domain], domain, sock_types[type - 1], type, protocol);

    return ret;
}

int
bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int ret;
    struct sockaddr_ll *sll = (struct sockaddr_ll *) addr;

    ret = func_bind(sockfd, addr, addrlen);

    char sll_ifname[IF_NAMESIZE] = { 0 };
    if_indextoname(sll->sll_ifindex, sll_ifname);

    if ((sockfd < sizeof(bound_to_correct_if)/sizeof(bound_to_correct_if[0])) && !strncmp(ifname, sll_ifname, sizeof(ifname)))
        bound_to_correct_if[sockfd] = 1;

    //printf("LIBNEXMON: %d = %s(%d, 0x%p, %d) sll_ifindex=%d ifname=%s\n", ret, __FUNCTION__, sockfd, addr, addrlen, sll->sll_ifindex, sll_ifname);

    return ret;    
}

struct inject_frame {
    unsigned short len;
    unsigned char pad;
    unsigned char type;
    char data[];
};

ssize_t
write(int fd, const void *buf, size_t count)
{
    ssize_t ret;

    // check if the user wants to write on a raw socket
    if ((fd > 2) && (fd < sizeof(socket_to_type)/sizeof(socket_to_type[0])) && (socket_to_type[fd] == SOCK_RAW) && (bound_to_correct_if[fd] == 1)) {
        struct inject_frame *buf_dup = (struct inject_frame *) malloc(count + sizeof(struct inject_frame));

        buf_dup->len = count + sizeof(struct inject_frame);
        buf_dup->pad = 0;
        buf_dup->type = 1;
        memcpy(buf_dup->data, buf, count);

	// fprintf(stderr, "injecting!\n");
        nex_ioctl(nexio, NEX_INJECT_FRAME, buf_dup, count + sizeof(struct inject_frame), true);
	free(buf_dup);

	// this is probably frowned on, but it works on the Nexus 6P
	// rate-limiting keeps the driver from crashing when doing aireplay-ng
	struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 50 * 1000000; // 50 ms
        nanosleep(&ts, NULL);

        ret = count;
    } else {
        // otherwise write the regular frame to the socket
        ret = func_write(fd, buf, count);
    }

    return ret;
}

ssize_t
sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
    ssize_t ret;

    // check if the user wants to write on a raw socket
    if ((sockfd > 2) && (sockfd < sizeof(socket_to_type)/sizeof(socket_to_type[0])) && (socket_to_type[sockfd] == SOCK_RAW) && (bound_to_correct_if[sockfd] == 1)) {
        struct inject_frame *buf_dup = (struct inject_frame *) malloc(len + sizeof(struct inject_frame));

        buf_dup->len = len + sizeof(struct inject_frame);
        buf_dup->pad = 0;
        buf_dup->type = 1;
        memcpy(buf_dup->data, buf, len);

        nex_ioctl(nexio, NEX_INJECT_FRAME, buf_dup, len + sizeof(struct inject_frame), true);

        free(buf_dup);

        ret = len;
    } else {
        // otherwise write the regular frame to the socket
        ret = func_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    }

    return ret;
}
