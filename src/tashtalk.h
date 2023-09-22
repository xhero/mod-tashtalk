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
  wait_queue_head_t addr_wait;
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
  unsigned char		mode;		/* really not used */
  pid_t			pid;

  struct atalk_addr node_addr;	/* Full node address */
};

#define TT_FLAG_INUSE	    0   /* Channel in use                     */
#define TT_FLAG_ESCAPE    1   /* ESC received                       */
#define TT_FLAG_INFRAME   2   /* We did not finish decoding a frame */
#define TT_FLAG_WAITADDR  3   /* We are waiting for an address      */
#define TT_FLAG_GOTACK    4   /* Received an ACK for our ENQ        */

#define TASH_MAGIC  0xFDFA
#define LLAP_CHECK  0xF0B8

#define LLAP_ENQ    0x81
#define LLAP_ACK    0x82
#define LLAP_RTS    0x84
#define LLAP_CTS    0x85

#define LLAP_DST_POS  0
#define LLAP_SRC_POS  1
#define LLAP_TYP_POS  2

#endif	/* _LINUX_TASHTALK_H.H */
