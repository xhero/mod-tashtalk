/* SPDX-License-Identifier: GPL-2.0 */
/*
 * slip.h	Define the SLIP device driver interface and constants.
 *
 * NOTE:	THIS FILE WILL BE MOVED TO THE LINUX INCLUDE DIRECTORY
 *		AS SOON AS POSSIBLE!
 *
 * Version:	@(#)slip.h	1.2.0	03/28/93
 *
 * Fixes:
 *		Alan Cox	: 	Added slip mtu field.
 *		Matt Dillon	:	Printable slip (borrowed from net2e)
 *		Alan Cox	:	Added SL_SLIP_LOTS
 *	Dmitry Gorodchanin	:	A lot of changes in the 'struct slip'
 *	Dmitry Gorodchanin	:	Added CSLIP statistics.
 *	Stanislav Voronyi	:	Make line checking as created by
 *					Igor Chechik, RELCOM Corp.
 *	Craig Schlenter		:	Fixed #define bug that caused
 *					CSLIP telnets to hang in 1.3.61-6
 *
 * Author:	Fred N. van Kempen, <waltje@uwalt.nl.mugnet.org>
 */
#ifndef _LINUX_SLIP_H
#define _LINUX_SLIP_H

/* SLIP configuration. */
#define TASH_MAX_CHAN	32		/* MAX number of SLIP channels;
					   This can be overridden with
					   insmod -oslip_maxdev=nnn	*/
#define SL_MTU		296		/* 296; I am used to 600- FvK	*/

struct slip {
  int			magic;

  /* Various fields. */
  struct tty_struct	*tty;		/* ptr to TTY structure		*/
  struct net_device	*dev;		/* easy for intr handling	*/
  spinlock_t		lock;
  struct work_struct	tx_work;	/* Flushes transmit buffer	*/

  /* These are pointers to the malloc()ed frame buffers. */
  unsigned char		*rbuff;		/* receiver buffer		*/
  int             rcount;         /* received chars counter       */
  unsigned char		*xbuff;		/* transmitter buffer		*/
  unsigned char   *xhead;         /* pointer to next byte to XMIT */
  int             xleft;          /* bytes left in XMIT queue     */
  int			        mtu;		/* Our mtu (to spot changes!)   */
  int             buffsize;       /* Max buffers sizes            */

  unsigned long		flags;		/* Flag values/ mode etc	*/
#define SLF_INUSE	0		/* Channel in use               */
#define SLF_ESCAPE	1               /* ESC received                 */
#define SLF_ERROR	2               /* Parity, etc. error           */

  unsigned char		mode;		/* really not used */
  unsigned char		leased;
  pid_t			pid;

};

#define TASH_MAGIC 0xFFFA

#endif	/* _LINUX_SLIP.H */
