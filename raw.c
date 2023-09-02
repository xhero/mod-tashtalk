/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close

#include <netinet/ether.h>
#include <netatalk/at.h>

#define DEFAULT_IF "lt0"

struct netrange {
	u_char nr_phase;
	u_short nr_firstnet;
	u_short nr_lastnet;
};


int ifconfig( const char *iname, unsigned long cmd, struct sockaddr_at *sa)
{
    struct ifreq	ifr;
    int			s;

    memset(&ifr, 0, sizeof(ifr));
    strcpy( ifr.ifr_name, iname );
    ifr.ifr_addr = *(struct sockaddr *)sa;

    if (( s = socket( AF_APPLETALK, SOCK_RAW, 0 )) < 0 ) {
		perror("socket");
		return( 1 );
    }

    if ( ioctl( s, cmd, &ifr ) < 0 ) {
		perror("ioctl");
		close(s);
		return( 1 );
    }

    close( s );
    if ( cmd == SIOCGIFADDR ) {
		*(struct sockaddr *)sa = ifr.ifr_addr;
    }
    return( 0 );
}

int main(int argc, char *argv[])
{
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int tx_len = 0;
	char sendbuf[128];
	char ifName[IFNAMSIZ];
	socklen_t len;

	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);



	struct netrange	nr;

	struct 	sockaddr_at at_sock_addr;
	at_sock_addr.sat_family = AF_APPLETALK;
	at_sock_addr.sat_port = 0;
	at_sock_addr.sat_addr.s_net = 0;
	at_sock_addr.sat_addr.s_node = 2;

   /* nr.nr_phase = 1;
    nr.nr_firstnet = 0;
    nr.nr_lastnet = 0xFEFF;
	memcpy( at_sock_addr.sat_zero, &nr, sizeof( struct netrange ));
*/
	ifconfig( ifName, SIOCSIFADDR, &at_sock_addr );
	ifconfig( ifName, SIOCGIFADDR, &at_sock_addr );

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_APPLETALK, SOCK_DGRAM, 0)) == -1) {
	    perror("socket");
	}

	int opt = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_DEBUG, (char *)&opt, sizeof(opt));

    /* rest of address should be initialized by the caller */
    if (bind(sockfd, (struct sockaddr *) &at_sock_addr, sizeof( struct sockaddr_at )) < 0 ) {
		perror("bind");
		//return -1;
    }

    /* get the real address from the kernel */
    len = sizeof( struct sockaddr_at);
    if ( getsockname( sockfd, (struct sockaddr *) &at_sock_addr, &len ) != 0 ) {
		perror("getsockname");
		//return -1;
    }

	// Get the index of the interface to send on 
	/*
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);

	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");
	*/

	// Get the MAC address of the interface to send on
	/*
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");
	*/

	/* Construct the Ethernet header */
	memset(sendbuf, 0, 128);
	/*
	sendbuf[0] = 0x00;
	sendbuf[1] = 0x08;
	sendbuf[2] = 0x25;
	sendbuf[3] = 0x01;
	sendbuf[4] = 'C';
	sendbuf[5] = 'i';
	sendbuf[6] = 'a';
	sendbuf[7] = 'o';
	sendbuf[8] = 0x08;
	sendbuf[9] = 0x35;
	*/

	sendbuf[0] = 0x04; // AEP
	sendbuf[1] = 0x01; // REQUEST

	at_sock_addr.sat_family = AF_APPLETALK;
	at_sock_addr.sat_port = 0;
	at_sock_addr.sat_addr.s_net = 0;
	at_sock_addr.sat_addr.s_node = 27;

	/* Send packet */
	if (sendto(sockfd, sendbuf, 2, 0, (struct sockaddr*)&at_sock_addr, sizeof(struct sockaddr_at)) < 0) {
	   perror("pirillo"); 
	   printf("Send failed\n");
	} else {
		printf("sent\n");
	}

	close(sockfd);

	return 0;
}
