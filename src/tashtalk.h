/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tashtalk.h	Define the TashTalk interface
 *
 * Version:	@(#)tasktalk.h	0.1	2023
 *
 * Based on slip.c by
 * Fred N. van Kempen, <waltje@uwalt.nl.mugnet.org>
 *
 * Author: Rodolfo Zitellini
 */
#ifndef _LINUX_TASHTALK_H
#define _LINUX_TASHTALK_H

#include <linux/atalk.h>

/* Max number of channels
 * override with insmod -otash_maxdev=nnn
 */
#define TASH_MAX_CHAN	32
#define TT_MTU		    600		/* FIXME figure out the real mtu	*/

struct slip {
  int			magic;

  /* Various fields. */
  struct tty_struct	*tty;		/* ptr to TTY structure		*/
  struct net_device	*dev;		/* easy for intr handling	*/
  spinlock_t		lock;
  struct work_struct	tx_work;	/* Flushes transmit buffer	*/

  /* These are pointers to the malloc()ed frame buffers. */
  unsigned char		*rbuff;		/* receiver buffer		*/
  int             rcount;   /* received chars counter       */
  unsigned char		*xbuff;		/* transmitter buffer		*/
  unsigned char   *xhead;   /* pointer to next byte to XMIT */
  int             xleft;    /* bytes left in XMIT queue     */
  int			        mtu;		  /* Our mtu (to spot changes!)   */
  int             buffsize; /* Max buffers sizes            */

  unsigned long		flags;		/* Flag values/ mode etc	*/
#define SLF_INUSE	0		      /* Channel in use               */
#define SLF_ESCAPE	1       /* ESC received                 */
#define SLF_ERROR	2         /* Parity, etc. error           */

  unsigned char		mode;		/* really not used */
  pid_t			pid;

  struct atalk_addr node_addr;	/* Full node address */
};

#define TASH_MAGIC 0xFFFA

#endif	/* _LINUX_TASHTALK_H.H */
