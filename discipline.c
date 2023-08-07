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
#include <netinet/ether.h>
#include <netatalk/at.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>          
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <linux/if_slip.h>
# include <termios.h>

#define MY_DEST_MAC0	0x00
#define MY_DEST_MAC1	0x00
#define MY_DEST_MAC2	0x00
#define MY_DEST_MAC3	0x00
#define MY_DEST_MAC4	0x00
#define MY_DEST_MAC5	0x00

#define DEFAULT_IF	"eth0"
#define BUF_SIZ		1024

struct at_addr {
#ifdef s_net
#undef s_net
#endif				/* s_net */
	u_short s_net;
	u_char s_node;
};

struct {
  const char	*speed;
  int	code;
} tty_speeds[] = {			/* table of usable baud rates	*/
  { "50",	B50	}, { "75",	B75  	},	
  { "110",	B110	}, { "300",	B300	},
  { "600",	B600	}, { "1200",	B1200	},
  { "2400",	B2400	}, { "4800",	B4800	},
  { "9600",	B9600	},
#ifdef B14400
  { "14400",	B14400	},
#endif
#ifdef B19200
  { "19200",	B19200	},
#endif
#ifdef B38400
  { "38400",	B38400	},
#endif
#ifdef B57600
  { "57600",	B57600	},
#endif
#ifdef B115200
  { "115200",	B115200	},
  { "500000",	500000	},
#endif
  { NULL,	0	}
};

struct termios	tty_saved,		/* saved TTY device state	*/
		tty_current;		/* current TTY device state	*/
int		tty_sdisc,		/* saved TTY line discipline	*/
		tty_ldisc,		/* current TTY line discipline	*/
		tty_fd = -1;		/* TTY file descriptor		*/
int		opt_c = 0;		/* "command" to run at exit	*/
int		opt_e = 0;		/* "activate only" flag		*/
int		opt_h = 0;		/* "hangup" on carrier loss	*/
#ifdef SIOCSKEEPALIVE
int		opt_k = 0;		/* "keepalive" value		*/
#endif
int		opt_l = 0;		/* "lock it" flag		*/
int		opt_L = 0;		/* 3-wire mode flag		*/
int		opt_m = 0;		/* "set RAW mode" flag		*/
int		opt_n = 0;		/* "set No Mesg" flag		*/
#ifdef SIOCSOUTFILL
int		opt_o = 0;		/* "outfill" value		*/
#endif
int		opt_q = 0;		/* "quiet" flag			*/
int		opt_d = 0;		/* debug flag			*/
int		opt_v = 0;		/* Verbose flag			*/


/* Set the number of stop bits. */
static int
tty_set_stopbits(struct termios *tty, char *stopbits)
{
  if (opt_d) printf("slattach: tty_set_stopbits: %c\n", *stopbits);
  switch(*stopbits) {
	case '1':
		tty->c_cflag &= ~CSTOPB;
		break;

	case '2':
		tty->c_cflag |= CSTOPB;
		break;

	default:
		return(-EINVAL);
  }
  return(0);
}

/* Set the number of data bits. */
static int
tty_set_databits(struct termios *tty, char *databits)
{
  if (opt_d) printf("slattach: tty_set_databits: %c\n", *databits);
  tty->c_cflag &= ~CSIZE;
  switch(*databits) {
	case '5':
		tty->c_cflag |= CS5;
		break;

	case '6':
		tty->c_cflag |= CS6;
		break;

	case '7':
		tty->c_cflag |= CS7;
		break;

	case '8':
		tty->c_cflag |= CS8;
		break;

	default:
		return(-EINVAL);
  }
  return(0);
}

/* Set the type of parity encoding. */
static int
tty_set_parity(struct termios *tty, char *parity)
{
  if (opt_d) printf("slattach: tty_set_parity: %c\n", *parity);
  switch(toupper(*parity)) {
	case 'N':
		tty->c_cflag &= ~(PARENB | PARODD);
		break;  

	case 'O':
		tty->c_cflag &= ~(PARENB | PARODD);
		tty->c_cflag |= (PARENB | PARODD);
		break;

	case 'E':
		tty->c_cflag &= ~(PARENB | PARODD);
		tty->c_cflag |= (PARENB);
		break;

	default:
		return(-EINVAL);
  }
  return(0);
}

/* Find a serial speed code in the table. */
int tty_find_speed(const char *speed)
{
  int i;

  i = 0;
  while (tty_speeds[i].speed != NULL) {
	if (!strcmp(tty_speeds[i].speed, speed)) return(tty_speeds[i].code);
	i++;
  }
  return(-EINVAL);
}

/* Set the line speed of a terminal line. */
static int
tty_set_speed(struct termios *tty, const char *speed)
{
  int code;

  if (opt_d) printf("slattach: tty_set_speed: %s\n", speed);
  if ((code = tty_find_speed(speed)) < 0) return(code);
  tty->c_cflag &= ~CBAUD;
  tty->c_cflag |= code;
  return(0);
}

/* Put a terminal line in a transparent state. */
static int
tty_set_raw(struct termios *tty)
{
  int i;
  int speed;

  for(i = 0; i < NCCS; i++)
		tty->c_cc[i] = '\0';		/* no spec chr		*/
  tty->c_cc[VMIN] = 1;
  tty->c_cc[VTIME] = 0;
  tty->c_iflag = (IGNBRK | IGNPAR);		/* input flags		*/
  tty->c_oflag = (0);				/* output flags		*/
  tty->c_lflag = (0);				/* local flags		*/
  speed = (tty->c_cflag & CBAUD);		/* save current speed	*/
  tty->c_cflag = (HUPCL | CREAD);		/* UART flags		*/
  if (opt_L) 
	tty->c_cflag |= CLOCAL;
  else
	tty->c_cflag |= CRTSCTS;
  tty->c_cflag |= speed;			/* restore speed	*/
  return(0);
}

/* Fetch the state of a terminal. */
int tty_get_state(struct termios *tty)
{
  if (ioctl(tty_fd, TCGETS, tty) < 0) {
	if (opt_q == 0) fprintf(stderr,
		"slattach: tty_get_state: %s\n", strerror(errno));
	return(-errno);
  }
  return(0);
}


/* Set the state of a terminal. */
int tty_set_state(struct termios *tty)
{
  if (ioctl(tty_fd, TCSETS, tty) < 0) {
	if (opt_q == 0) fprintf(stderr,
		"slattach: tty_set_state: %s\n", strerror(errno));
	return(-errno);
  }
  return(0);
}


/* Get the line discipline of a terminal line. */
int tty_get_disc(int *disc)
{
  if (ioctl(tty_fd, TIOCGETD, disc) < 0) {
	if (opt_q == 0) fprintf(stderr,
		"slattach: tty_get_disc: %s\n", strerror(errno));
	return(-errno);
  }
  return(0);
}

/* Set the line discipline of a terminal line. */
int tty_set_disc(int disc)
{
  if (disc == -1) disc = tty_sdisc;

  if (ioctl(tty_fd, TIOCSETD, &disc) < 0) {
	if (opt_q == 0) fprintf(stderr,
		"slattach: tty_set_disc(%d, %d): %s\n", tty_fd,
			disc, strerror(errno));
	return(-errno);
  }
  return(0);
}


/* Fetch the name of the network interface attached to this terminal. */
int tty_get_name(char *name)
{
  if (ioctl(tty_fd, SIOCGIFNAME, name) < 0) {
	if (opt_q == 0) 
	    perror("tty_get_name");
	return(-errno);
  }
  return(0);
}


/* Hangup the line. */
int tty_hangup(void)
{
  struct termios tty;

  tty = tty_current;
  (void) tty_set_speed(&tty, "0");
  if (tty_set_state(&tty) < 0) {
	if (opt_q == 0) fprintf(stderr, ("slattach: tty_hangup(DROP): %s\n"), strerror(errno));
	return(-errno);
  }

  (void) sleep(1);

  if (tty_set_state(&tty_current) < 0) {
	if (opt_q == 0) fprintf(stderr, ("slattach: tty_hangup(RAISE): %s\n"), strerror(errno));
	return(-errno);
  }
  return(0);
}

/* Close down a terminal line. */
int tty_close(void)
{
  (void) tty_set_disc(tty_sdisc);
  (void) tty_hangup();
  return(0);
}

/* Open and initialize a terminal line. */
int tty_open(char *name, const char *speed)
{
  char pathbuf[PATH_MAX];
  register char *path_open, *path_lock;
  int fd;




    if ((fd = open("/dev/ttyS0", O_RDWR|O_NDELAY)) < 0) {
        printf("oops");
        return(-errno);
    }
    tty_fd = fd;

  /* Fetch the current state of the terminal. */
  if (tty_get_state(&tty_saved) < 0) {
	fprintf(stderr, ("slattach: tty_open: cannot get current state!\n"));
	return(-errno);
  }
  tty_current = tty_saved;

  /* Fetch the current line discipline of this terminal. */
  if (tty_get_disc(&tty_sdisc) < 0) {
	fprintf(stderr, ("slattach: tty_open: cannot get current line disc!\n"));
	return(-errno);
  } 
  tty_ldisc = tty_sdisc;

  /* Put this terminal line in a 8-bit transparent mode. */
  if (opt_m == 0) {
	if (tty_set_raw(&tty_current) < 0) {
		fprintf(stderr, ("slattach: tty_open: cannot set RAW mode!\n"));
		return(-errno);
	}

	/* Set the default speed if we need to. */
	if (speed != NULL) {
		if (tty_set_speed(&tty_current, speed) != 0) {
			fprintf(stderr, ("slattach: tty_open: cannot set %s bps!\n"),
						speed);
			return(-errno);
		}
	}

	/* Set up a completely 8-bit clean line. */
	if (tty_set_databits(&tty_current, "8") ||
	    tty_set_stopbits(&tty_current, "1") ||
	    tty_set_parity(&tty_current, "N")) {
		fprintf(stderr, ("slattach: tty_open: cannot set 8N1 mode!\n"));
		return(-errno);
  	}

	/* Set the new line mode. */
	if ((fd = tty_set_state(&tty_current)) < 0) return(fd);
  }

  /* OK, line is open.  Do we need to "silence" it? */
  //(void) tty_nomesg(tty_fd);

  return(0);
}

int
main()
{
  char path_buf[128];
  char *path_dev;
  char buff[128];
  const char *speed = NULL;
  const char *proto = "tash";
  const char *extcmd = NULL;
  int s;

  


  if (tty_open("/dev/ttyS0", "115200") < 0)  { return(3); }


    int disc = N_PPP;
    if (ioctl(tty_fd, TIOCSETD, &disc) < 0) {
	    fprintf(stderr, "SLIP_set_disc(%d): %s\n", disc, strerror(errno));
	    return (-errno);
    }

    int encap = 0;
	/*
    if (ioctl(tty_fd, SIOCSIFENCAP, &encap) < 0) {
	    fprintf(stderr, "SLIP_set_encap(%d): %s\n", encap, strerror(errno));
	    return (-errno);
    }*/

    if (tty_get_name(buff)) { return(3); }
	printf(("%s started"), proto);

	if (path_dev != NULL) printf((" on /dev/ttyS0"));
	printf((" interface %s\n"), buff);
  



  /* Configure keepalive and outfill. */
  /*
  if ((ioctl(tty_fd, SIOCSKEEPALIVE, &opt_k) < 0))
	  fprintf(stderr, "slattach: ioctl(SIOCSKEEPALIVE): %s\n", strerror(errno));

  if ((ioctl(tty_fd, SIOCSOUTFILL, &opt_o) < 0))
	  fprintf(stderr, "slattach: ioctl(SIOCSOUTFILL): %s\n", strerror(errno));
*/


  while(1) {}

  /* Wait until we get killed if hanging on a terminal. 
  if (opt_e == 0) {
	while(1) {
		if(opt_h == 1) {
			int n = 0;

		        ioctl(tty_fd, TIOCMGET, &n);
			if(!(n & TIOCM_CAR))
				break;
			sleep(15);
		}
		else
			sleep(60);
	};

	tty_close();
	if(extcmd)	
		system(extcmd);
  }
  exit(0);
  */
}