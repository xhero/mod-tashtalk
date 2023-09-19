/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tashtalk.h	Define the TashTalk interface
 *
 * Version:	@(#)tasktalk.h	0.1	2023
 *
 * Based on slip.c by
 * Laurence Culhane and Fred N. van Kempen
 *
 * Author: twelvetone12
 */
#ifndef _LINUX_TASHTALK_H
#define _LINUX_TASHTALK_H

#include <linux/atalk.h>

/* Max number of channels
 * override with insmod -otash_maxdev=nnn
 */
#define TASH_MAX_CHAN	32
#define TT_MTU		    605

struct tashtalk {
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
#define TT_FLAG_INUSE	0		  /* Channel in use               */
#define TT_FLAG_ESCAPE 1    /* ESC received                 */
#define TT_FLAG_INFRAME 2   /* We did not finish decoding a frame */

  unsigned char		mode;		/* really not used */
  pid_t			pid;

  struct atalk_addr node_addr;	/* Full node address */
};

#define TASH_MAGIC 0xFDFA

#endif	/* _LINUX_TASHTALK_H.H */
