// SPDX-License-Identifier: GPL-2.0-only

/*      tashtalk.c: TashTalk LocalTalk driver for Linux.
 *
 *	Authors:
 *      Rodolfo Zitellini (twelvetone12)
 *
 *      Derived from:
 *      - slip.c: A network driver outline for linux.
 *        written by Laurence Culhane and Fred N. van Kempen
 *
 *      This software may be used and distributed according to the terms
 *      of the GNU General Public License, incorporated herein by reference.
 *
 */

#include <linux/compat.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>

#include <linux/uaccess.h>
#include <linux/bitops.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/in.h>
#include <linux/tty.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include "tashtalk.h"
#include <linux/if_ltalk.h>
#include <linux/atalk.h>

static struct net_device **tastalk_devs;

static int tash_maxdev = TASH_MAX_CHAN;
module_param(tash_maxdev, int, 0);
MODULE_PARM_DESC(tash_maxdev, "Maximum number of tashtalk devices");

#ifndef TASH_DEBUG
#define TASH_DEBUG 0
#endif
static unsigned int tash_debug = TASH_DEBUG;

static void tashtalk_send_ctrl_packet(struct tashtalk *tt, unsigned char dst,
				      unsigned char src, unsigned char type);

static void tash_setbits(struct tashtalk *tt, unsigned char addr)
{
	unsigned char bits[33];
	unsigned int byte, pos;

	// 0, 255 and anything else are invalid
	if (addr == 0 || addr >= 255)
		return;

	memset(bits, 0, sizeof(bits));

	// in theory we can respond to many addresses
	byte = addr / 8 + 1; // skip initial command byte
	pos = (addr % 8);

	if (tash_debug)
		printk(KERN_DEBUG
		       "TashTalk: setting address %i (byte %i bit %i) for you.",
		       addr, byte - 1, pos);

	bits[0] = 0x02; // the command
	bits[byte] = (1 << pos);

	set_bit(TTY_DO_WRITE_WAKEUP, &tt->tty->flags);
	tt->tty->ops->write(tt->tty, bits, sizeof(bits));
}

static u16 tt_crc_ccitt_update(u16 crc, u8 data)
{
	data ^= (u8)(crc) & (u8)(0xFF);
	data ^= data << 4;
	return ((((u16)data << 8) | ((crc & 0xFF00) >> 8)) ^ (u8)(data >> 4) ^
		((u16)data << 3));
}

static u16 tash_crc(const unsigned char *data, int len)
{
	u16 crc = 0xFFFF;

	for (int i = 0; i < len; i++) {
		crc = tt_crc_ccitt_update(crc, data[i]);
	}

	return crc;
}

/* Send one completely decapsulated DDP datagram to the DDP layer. */
static void tt_post_to_netif(struct tashtalk *tt)
{
	struct net_device *dev = tt->dev;
	struct sk_buff *skb;

	// before doing stuff, we need to make sure it is not a control frame
	// Control frames are always 5 bytes long
	if (tt->rcount <= 5)
		return;

	// 0xF0B8 is the magic crc nr
	if (tash_crc(tt->rbuff, tt->rcount) != LLAP_CHECK) {
		printk(KERN_WARNING "TashTalk: invalid CRC, drop packet");
		return;
	}

	tt->rcount -= 2; // Strip away the CRC bytes
	dev->stats.rx_bytes += tt->rcount;

	skb = dev_alloc_skb(tt->rcount);
	if (skb == NULL) {
		printk(KERN_WARNING
		       "%s: unable to allocate memory, drop packet.\n",
		       dev->name);
		dev->stats.rx_dropped++;
		return;
	}

	// skip the CRC bytes at the end
	skb_put_data(skb, tt->rbuff, tt->rcount);
	skb->dev = dev;
	skb->protocol = htons(ETH_P_LOCALTALK);

	// This is for compatibility with the phase1 to phase2 translation
	skb_reset_mac_header(skb); /* Point to entire packet. */
	skb_pull(skb, 3);
	skb_reset_transport_header(skb); /* Point to data (Skip header). */

	netif_rx(skb);
	dev->stats.rx_packets++;
}

/* Encapsulate one DDP datagram and stuff into a TTY queue. */
static void tt_send_frame(struct tashtalk *tt, unsigned char *icp, int len)
{
    unsigned char crc_bytes[2];
	int actual;
	u16 crc;

	crc = tash_crc(icp, len);
	crc_bytes[0] = (crc & 0xFF) ^ 0xFF;
	crc_bytes[1] = (crc >> 8) ^ 0xFF;

	memset(tt->xbuff, 0, sizeof(tt->xbuff));

	tt->xbuff[0] = 0x01; // First byte is te Tash SEND command
	memcpy(&tt->xbuff[1], icp, len); // followed by all the bytes
	memcpy(&tt->xbuff[1 + len], crc_bytes,
	       sizeof(crc_bytes)); // lastly follow with the crc
	len += 3; // We added our own three bytes
	actual = tt->tty->ops->write(tt->tty, tt->xbuff, len);

	// Any bytes left?
	tt->xleft = len - actual;
	// Move the pointer to the correct position
	// see you in tash_transmit_worker
	tt->xhead = tt->xbuff + actual;

	print_hex_dump_bytes("TashTalk: LLAP OUT frame sans CRC: ",
			     DUMP_PREFIX_NONE, icp, len);

	if (tash_debug)
		printk(KERN_DEBUG "TashTalk: transmit actual %i, requested %i",
		       actual, len);

	if (actual == len) {
		clear_bit(TTY_DO_WRITE_WAKEUP, &tt->tty->flags);
		netif_wake_queue(tt->dev);
	} else {
		set_bit(TTY_DO_WRITE_WAKEUP, &tt->tty->flags);
	}
}

/* Write out any remaining transmit buffer. Scheduled when tty is writable */
static void tash_transmit_worker(struct work_struct *work)
{
	struct tashtalk *tt = container_of(work, struct tashtalk, tx_work);
	int actual;

	spin_lock_bh(&tt->lock);
	/* First make sure we're connected. */
	if (!tt->tty || tt->magic != TASH_MAGIC || !netif_running(tt->dev)) {
		spin_unlock_bh(&tt->lock);
		return;
	}

	// We always get here after all transmissions
	// No more data?
	if (tt->xleft <= 0) {
		/* reset the flags for transmission
		and re-wake the netif queue */
		tt->dev->stats.tx_packets++;
		clear_bit(TTY_DO_WRITE_WAKEUP, &tt->tty->flags);
		spin_unlock_bh(&tt->lock);
		netif_wake_queue(tt->dev);
		if (tash_debug)
			printk(KERN_DEBUG
			       "TashTalk: transmission finished, on to next");
		return;
	}

	// Send whatever is there to send
	// This function will be calleg again if xleft <= 0
	if (tash_debug)
		printk(KERN_DEBUG "TashTalk: trasmit remaining bytes %i",
		       tt->xleft);
	actual = tt->tty->ops->write(tt->tty, tt->xhead, tt->xleft);
	tt->xleft -= actual;
	tt->xhead += actual;
	if (tash_debug)
		printk(KERN_DEBUG "TashTalk: Trasmitted actual bytes %i",
		       actual);
	spin_unlock_bh(&tt->lock);
}

/*
 * Called by the driver when there's room for more data.
 * Schedule the transmit.
 */
static void tashtalk_write_wakeup(struct tty_struct *tty)
{
	struct tashtalk *tt;

	rcu_read_lock();
	tt = rcu_dereference(tty->disc_data);
	if (tt)
		schedule_work(&tt->tx_work);
	rcu_read_unlock();
}

static void tt_tx_timeout(struct net_device *dev, unsigned int txqueue)
{
	struct tashtalk *tt = netdev_priv(dev);

	spin_lock(&tt->lock);

	if (netif_queue_stopped(dev)) {
		if (!netif_running(dev) || !tt->tty)
			goto out;
	}
out:
	spin_unlock(&tt->lock);
}

static netdev_tx_t tt_transmit(struct sk_buff *skb, struct net_device *dev)
{
	struct tashtalk *tt = netdev_priv(dev);

	if (skb->len > tt->mtu) {
		printk(KERN_ERR
		       "TashTalk: %s dropping oversized transmit packet %i vs %i!\n",
		       dev->name, skb->len, tt->mtu);
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	if (tash_debug)
		printk(KERN_DEBUG "TashTalk: send data on %s\n", dev->name);

	spin_lock(&tt->lock);
	if (!netif_running(dev)) {
		spin_unlock(&tt->lock);
		printk(KERN_ERR
		       "TashTalk: %s: transmit call when iface is down\n",
		       dev->name);
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}
	if (tt->tty == NULL) {
		spin_unlock(&tt->lock);
		dev_kfree_skb(skb);
		printk(KERN_ERR "TashTalk: %s: TTY not connected\n", dev->name);
		return NETDEV_TX_OK;
	}

	netif_stop_queue(tt->dev);
	dev->stats.tx_bytes += skb->len;
	tt_send_frame(tt, skb->data, skb->len);
	spin_unlock(&tt->lock);

	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

/******************************************
 *   Routines looking at netdevice side.
 ******************************************/

/* Netdevice UP -> DOWN routine */

static int tt_close(struct net_device *dev)
{
	struct tashtalk *tt = netdev_priv(dev);

	spin_lock_bh(&tt->lock);
	if (tt->tty)
		/* TTY discipline is running. */
		clear_bit(TTY_DO_WRITE_WAKEUP, &tt->tty->flags);
	netif_stop_queue(dev);
	tt->rcount = 0;
	tt->xleft = 0;
	spin_unlock_bh(&tt->lock);

	return 0;
}

/* Netdevice DOWN -> UP routine */

static int tt_open(struct net_device *dev)
{
	struct tashtalk *tt = netdev_priv(dev);

	if (tt->tty == NULL) {
		printk(KERN_ERR "TashTalk: %s TTY not open", dev->name);
		return -ENODEV;
	}

	tt->flags &= (1 << TT_FLAG_INUSE);
	netif_start_queue(dev);
	return 0;
}

/* Netdevice get statistics request */

static void tt_get_stats64(struct net_device *dev,
			   struct rtnl_link_stats64 *stats)
{
	struct net_device_stats *devstats = &dev->stats;

	stats->rx_packets = devstats->rx_packets;
	stats->tx_packets = devstats->tx_packets;
	stats->rx_bytes = devstats->rx_bytes;
	stats->tx_bytes = devstats->tx_bytes;
	stats->rx_dropped = devstats->rx_dropped;
	stats->tx_dropped = devstats->tx_dropped;
	stats->tx_errors = devstats->tx_errors;
	stats->rx_errors = devstats->rx_errors;
	stats->rx_over_errors = devstats->rx_over_errors;
}

// This has to be blocking for compatibility with netatalk
unsigned char tt_arbitrate_addr_blocking(struct tashtalk *tt,
					 unsigned char addr)
{
	unsigned char min, max;
	unsigned char rand;
	int i;

	/* This works a bit backwards, we send many ENQs
	   and are happy not to receive ACKs.
	   If we get ACK, we try another addr
	*/

	// Set the ranges, the new address hould stay in the proper one
	if (addr < 129) {
		min = 1;
		max = 128;
	} else {
		min = 129;
		max = 254;
	}

	if (tash_debug)
		printk(KERN_DEBUG
		       "TashTalk: start address arbitration, requested %i",
		       addr);

	set_bit(TT_FLAG_WAITADDR, &tt->flags);

	for (i = 0; i < 10; i++) {
		clear_bit(TT_FLAG_GOTACK, &tt->flags);
		tashtalk_send_ctrl_packet(tt, addr, addr, LLAP_ENQ);

		// Timeout == nobody reclaims our addr
		if (wait_event_timeout(tt->addr_wait,
				       test_bit(TT_FLAG_GOTACK, &tt->flags),
				       msecs_to_jiffies(1))) {
			unsigned char newaddr;
			// Oops! somebody has the same addr as us make up a new one and start over

			get_random_bytes(&rand, 1);
			newaddr = min + rand % (max - min + 1);
			if (tash_debug)
				printk(KERN_DEBUG
				       "TashTalk: addr %i is in use, try %i",
				       addr, newaddr);
			addr = newaddr;
		}
	}

	clear_bit(TT_FLAG_WAITADDR, &tt->flags);
	clear_bit(TT_FLAG_GOTACK, &tt->flags);

	if (tash_debug)
		printk(KERN_DEBUG "TashTalk: arbitrated address is %i", addr);

	return addr;
}

static int tt_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
    struct sockaddr_at *sa = (struct sockaddr_at *)&ifr->ifr_addr;
	struct tashtalk *tt = netdev_priv(dev);
	struct atalk_addr *aa = &tt->node_addr;

	switch (cmd) {
	case SIOCSIFADDR:

		sa->sat_addr.s_node =
			tt_arbitrate_addr_blocking(tt, sa->sat_addr.s_node);

		aa->s_net = sa->sat_addr.s_net;
		aa->s_node = sa->sat_addr.s_node;

		/* Set broardcast address. */
		dev->broadcast[0] = 0xFF;

		/* Set hardware address. */
		dev->addr_len = 1;
		dev_addr_set(dev, &aa->s_node);

		// Setup tashtalk to respond to that addr
		tash_setbits(tt, aa->s_node);

		if (tash_debug)
			printk(KERN_DEBUG "TashTalk: set addr to: %i.%i",
			       aa->s_net, aa->s_node);
		return 0;

	case SIOCGIFADDR:
		sa->sat_addr.s_net = aa->s_net;
		sa->sat_addr.s_node = aa->s_node;
		if (tash_debug)
			printk(KERN_DEBUG "TashTalk: read addr: %i.%i",
			       aa->s_net, aa->s_node);
		return 0;

	default:
		return -EOPNOTSUPP;
	}
}

/* The destructor */
static void tt_free_netdev(struct net_device *dev)
{
	int i = dev->base_addr;

	tastalk_devs[i] = NULL;
}

/* Copied from cops.c, make appletalk happy */
static void tt_set_multicast(struct net_device *dev)
{
	printk(KERN_INFO "TashTalk: %s set_multicast_list executed\n",
	       dev->name);
}

static const struct net_device_ops tt_netdev_ops = {
	.ndo_open = tt_open,
	.ndo_stop = tt_close,
	.ndo_start_xmit = tt_transmit,
	.ndo_get_stats64 = tt_get_stats64,
	.ndo_tx_timeout = tt_tx_timeout,
	.ndo_do_ioctl = tt_ioctl,
	.ndo_set_rx_mode = tt_set_multicast,
};

static void tashtalk_send_ctrl_packet(struct tashtalk *tt, unsigned char dst,
				      unsigned char src, unsigned char type)
{
    unsigned char cmd = 0x01;
	unsigned char buf[5];
	int actual;
	u16 crc;

	buf[LLAP_DST_POS] = dst;
	buf[LLAP_SRC_POS] = src;
	buf[LLAP_TYP_POS] = type;

	crc = tash_crc(buf, 3);
	buf[3] = (crc & 0xFF) ^ 0xFF;
	buf[4] = (crc >> 8) ^ 0xFF;

	actual = tt->tty->ops->write(tt->tty, &cmd, 1);
	actual += tt->tty->ops->write(tt->tty, buf, sizeof(buf));
	printk(KERN_DEBUG "TashTalk: control packet 0x%X sent to %i (%i)", type,
	       dst, actual);
}

static void tashtalk_manage_control_frame(struct tashtalk *tt)
{
	switch (tt->rbuff[LLAP_TYP_POS]) {
	case LLAP_ENQ:

		if (tt->node_addr.s_node != 0 &&
		    tt->rbuff[LLAP_SRC_POS] == tt->node_addr.s_node) {
			if (tash_debug)
				printk(KERN_DEBUG
				       "TashTalk: repply ACK to ENQ from %i",
				       tt->rbuff[LLAP_SRC_POS]);
			//tashtalk_send_ack(tt, tt->rbuff[LLAP_SRC_POS]);
			tashtalk_send_ctrl_packet(tt, tt->rbuff[LLAP_SRC_POS],
						  tt->node_addr.s_node,
						  LLAP_ACK);
		}

		break;

	case LLAP_ACK:
		if (test_bit(TT_FLAG_WAITADDR, &tt->flags)) {
			set_bit(TT_FLAG_GOTACK, &tt->flags);
			wake_up(&tt->addr_wait);
		}
		break;
	}
}

static int tashtalk_is_control_frame(unsigned char *frame)
{
	return (frame[LLAP_TYP_POS] >= LLAP_ENQ &&
		frame[LLAP_TYP_POS] <= LLAP_CTS);
}

static void tashtalk_manage_valid_frame(struct tashtalk *tt)
{
	if (tash_debug)
		printk(KERN_DEBUG "(3) TashTalk done frame, len=%i",
		       tt->rcount);
	// echo 'file tashtalk.c line 403 +p' > /sys/kernel/debug/dynamic_debug/control
	print_hex_dump_bytes("(3a) LLAP IN frame: ", DUMP_PREFIX_NONE,
			     tt->rbuff, tt->rcount);

	// Control frames are not sent to the netif
	if (tt->rcount == 5 && tashtalk_is_control_frame(tt->rbuff))
		tashtalk_manage_control_frame(tt);
	else
		tt_post_to_netif(tt);

	if (tash_debug)
		printk(KERN_DEBUG "(4) TashTalk next frame");
}

static void tashtalk_manage_escape(struct tashtalk *tt, unsigned char seq)
{
	switch (seq) {
	case 0xFD:
		tashtalk_manage_valid_frame(tt);
		break;
	case 0xFE:
		printk(KERN_ERR "TashTalk: frame error");
		break;
	case 0xFA:
		printk(KERN_ERR "TashTalk: frame abort");
		break;
	case 0xFC:
		printk(KERN_ERR "TashTalk: frame crc error");
		break;

	default:
		printk(KERN_ERR "TashTalk: unknown escape sequence %c", seq);
		break;
	}

	tt->rcount = 0;
	clear_bit(TT_FLAG_INFRAME, &tt->flags);
}

/********************************************
  Routines looking at TTY talking to TashTalk
 ********************************************/

static void tashtalk_receive_buf(struct tty_struct *tty,
				 const unsigned char *cp, const char *fp,
				 int count)
{
	struct tashtalk *tt = tty->disc_data;
	int i;

	if (!tt || tt->magic != TASH_MAGIC || !netif_running(tt->dev))
		return;

	if (tash_debug)
		printk(KERN_DEBUG "(1) TashTalk read %i", count);
	print_hex_dump_bytes("Tash read: ", DUMP_PREFIX_NONE, cp, count);

	// Fresh frame
	if (!test_bit(TT_FLAG_INFRAME, &tt->flags)) {
		tt->rcount = 0;
		if (tash_debug)
			printk(KERN_DEBUG "(2) TashTalk start new frame");
	} else if (tash_debug)
		printk(KERN_DEBUG "(2) TashTalk continue frame");

	set_bit(TT_FLAG_INFRAME, &tt->flags);

	for (i = 0; i < count; i++) {
		set_bit(TT_FLAG_INFRAME, &tt->flags);

		if (cp[i] == 0x00) {
			set_bit(TT_FLAG_ESCAPE, &tt->flags);
			continue;
		}

		if (test_and_clear_bit(TT_FLAG_ESCAPE, &tt->flags)) {
			if (cp[i] == 0xFF) {
				tt->rbuff[tt->rcount] = 0x00;
				tt->rcount++;
			} else {
				tashtalk_manage_escape(tt, cp[i]);
			}
		} else {
			tt->rbuff[tt->rcount] = cp[i];
			tt->rcount++;
		}
	}

	if (tash_debug)
		printk(KERN_DEBUG "(5) Done read, pending frame=%i",
		       test_bit(TT_FLAG_INFRAME, &tt->flags));
}

/* Free a channel buffers. */
static void tt_free_bufs(struct tashtalk *tt)
{
	kfree(xchg(&tt->rbuff, NULL));
	kfree(xchg(&tt->xbuff, NULL));
}

static int tt_alloc_bufs(struct tashtalk *tt, int mtu)
{
	int err = -ENOBUFS;
	char *rbuff = NULL;
	char *xbuff = NULL;
	unsigned long len;

	// Make enough space? FIXME I guess
	len = mtu * 2;

	rbuff = kmalloc(len + 4, GFP_KERNEL);
	if (rbuff == NULL)
		goto err_exit;

	xbuff = kmalloc(len + 4, GFP_KERNEL);
	if (xbuff == NULL)
		goto err_exit;

	spin_lock_bh(&tt->lock);
	if (tt->tty == NULL) {
		spin_unlock_bh(&tt->lock);
		err = -ENODEV;
		goto err_exit;
	}

	tt->buffsize = len;
	tt->rcount = 0;
	tt->xleft = 0;

	rbuff = xchg(&tt->rbuff, rbuff);
	xbuff = xchg(&tt->xbuff, xbuff);

	spin_unlock_bh(&tt->lock);
	err = 0;

	/* Cleanup */
err_exit:

	kfree(xbuff);
	kfree(rbuff);
	return err;
}

/* Find a free channel, and link in this `tty' line. */
static struct tashtalk *tt_alloc(void)
{
	struct net_device *dev = NULL;
	struct tashtalk *tt;
	int i;

	for (i = 0; i < tash_maxdev; i++) {
		dev = tastalk_devs[i];
		if (dev == NULL)
			break;
	}

	if (i >= tash_maxdev) {
		printk(KERN_ERR "TashTalk: all slots in use");
		return NULL;
	}

	/* Also assigns the default lt* name */
	dev = alloc_ltalkdev(sizeof(*tt));

	if (!dev) {
		printk(KERN_ERR "TashTalk: could not allocate ltalkdev");
		return NULL;
	}

	dev->base_addr = i;
	tt = netdev_priv(dev);

	/* Initialize channel control data */
	tt->magic = TASH_MAGIC;
	tt->dev = dev;
	tt->mtu = TT_MTU;
	tt->mode = 0; /*Maybe useful in the future? */

	tt->dev->netdev_ops = &tt_netdev_ops;
	tt->dev->type = ARPHRD_LOCALTLK;
	tt->dev->priv_destructor = tt_free_netdev;

	// Initially we have no address
	// so we do not reply to ENQs
	tt->node_addr.s_node = 0;
	tt->node_addr.s_net = 0;

	spin_lock_init(&tt->lock);
	init_waitqueue_head(&tt->addr_wait);
	INIT_WORK(&tt->tx_work, tash_transmit_worker);

	tastalk_devs[i] = dev;
	return tt;
}

/*
 * Open the high-level part of the TashTalk channel.
 * Generally used with an userspave program:
 * sudo ldattach -d -s 1000000 PPP /dev/ttyUSB0
 */

static int tashtalk_open(struct tty_struct *tty)
{
	struct tashtalk *tt;
	int err;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (tty->ops->write == NULL)
		return -EOPNOTSUPP;

	rtnl_lock();

	tt = tty->disc_data;

	err = -EEXIST;
	/* First make sure we're not already connected. */
	if (tt && tt->magic == TASH_MAGIC)
		goto err_exit;

	err = -ENFILE;

	tt = tt_alloc();
	if (tt == NULL)
		goto err_exit;

	tt->tty = tty;
	tty->disc_data = tt;
	tt->pid = current->pid;

	if (!test_bit(TT_FLAG_INUSE, &tt->flags)) {
		set_bit(TT_FLAG_INUSE, &tt->flags);

		err = tt_alloc_bufs(tt, TT_MTU);
		if (err)
			goto err_free_chan;

		err = register_netdevice(tt->dev);
		if (err)
			goto err_free_bufs;

	} else {
		printk(KERN_ERR "TashTalk: Channel is already in use");
	}

	/* Done.  We have linked the TTY line to a channel. */
	rtnl_unlock();
	tty->receive_room = 65536; /* We don't flow control */

	/* TTY layer expects 0 on success */
	printk(KERN_INFO "TashTalk is on port %s", tty->name);
	return 0;

err_free_bufs:
	tt_free_bufs(tt);

err_free_chan:
	printk(KERN_ERR "TashTalk: could not open device");
	tt->tty = NULL;
	tty->disc_data = NULL;
	clear_bit(TT_FLAG_INUSE, &tt->flags);

	/* do not call free_netdev before rtnl_unlock */
	rtnl_unlock();
	free_netdev(tt->dev);
	return err;

err_exit:
	rtnl_unlock();

	/* Count references from TTY module */
	return err;
}

static void tashtalk_close(struct tty_struct *tty)
{
	struct tashtalk *tt = tty->disc_data;

	/* First make sure we're connected. */
	if (!tt || tt->magic != TASH_MAGIC || tt->tty != tty)
		return;

	spin_lock_bh(&tt->lock);
	rcu_assign_pointer(tty->disc_data, NULL);
	tt->tty = NULL;
	spin_unlock_bh(&tt->lock);

	synchronize_rcu();
	flush_work(&tt->tx_work);

	/* Flush network side */
	unregister_netdev(tt->dev);
	/* This will complete via tt_free_netdev */
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
static int tashtalk_hangup(struct tty_struct *tty)
#else
static void tashtalk_hangup(struct tty_struct *tty)
#endif
{
	tashtalk_close(tty);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
	return 0;
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
static int tashtalk_ioctl(struct tty_struct *tty, struct file *file,
			  unsigned int cmd,
#else
static int tashtalk_ioctl(struct tty_struct *tty, unsigned int cmd,
#endif
			  unsigned long arg)
{
	struct tashtalk *tt = tty->disc_data;
	int __user *p = (int __user *)arg;
	unsigned int tmp;

	/* First make sure we're connected. */
	if (!tt || tt->magic != TASH_MAGIC)
		return -EINVAL;

	switch (cmd) {
	case SIOCGIFNAME:
		tmp = strlen(tt->dev->name) + 1;
		if (copy_to_user((void __user *)arg, tt->dev->name, tmp))
			return -EFAULT;
		return 0;

	// do we need mode?
	case SIOCGIFENCAP:
		if (put_user(tt->mode, p))
			return -EFAULT;
		return 0;

	case SIOCSIFENCAP:
		if (get_user(tmp, p))
			return -EFAULT;
		tt->mode = tmp;
		return 0;

	case SIOCSIFHWADDR:
		return -EINVAL;

	default:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
		return tty_mode_ioctl(tty, 0, cmd, arg);
#else
		return tty_mode_ioctl(tty, cmd, arg);
#endif
	}
}

static struct tty_ldisc_ops tashtalk_ldisc = {
	.owner = THIS_MODULE,
	.num = 29, // this is the official one for testing
	.name = "tasktalk",
	.open = tashtalk_open,
	.close = tashtalk_close,
	.hangup = tashtalk_hangup,
	.ioctl = tashtalk_ioctl,
	.receive_buf = tashtalk_receive_buf,
	.write_wakeup = tashtalk_write_wakeup,
};

static int __init tashtalk_init(void)
{
	int status;

	if (tash_maxdev < 1)
		tash_maxdev = 1;

	printk(KERN_INFO "TashTalk Interface (dynamic channels, max=%d)",
	       tash_maxdev);

	tastalk_devs =
		kcalloc(tash_maxdev, sizeof(struct net_device *), GFP_KERNEL);
	if (!tastalk_devs)
		return -ENOMEM;

	/* Fill in our line protocol discipline, and register it */
	status = tty_register_ldisc(&tashtalk_ldisc);
	if (status != 0) {
		printk(KERN_ERR
		       "TaskTalk: can't register line discipline (err = %d)\n",
		       status);
		kfree(tastalk_devs);
	}
	return status;
}

static void __exit tashtalk_exit(void)
{
    unsigned long timeout = jiffies + HZ;
	struct net_device *dev;
	struct tashtalk *tt;
	int busy = 0;
	int i;

	if (tastalk_devs == NULL)
		return;

	/* First of all: check for active disciplines and hangup them. */
	do {
		if (busy)
			msleep_interruptible(100);

		busy = 0;
		for (i = 0; i < tash_maxdev; i++) {
			dev = tastalk_devs[i];
			if (!dev)
				continue;
			tt = netdev_priv(dev);
			spin_lock_bh(&tt->lock);
			if (tt->tty) {
				busy++;
				tty_hangup(tt->tty);
			}
			spin_unlock_bh(&tt->lock);
		}
	} while (busy && time_before(jiffies, timeout));

	/* FIXME: hangup is async so we should wait when doing this second
	   phase */

	for (i = 0; i < tash_maxdev; i++) {
		dev = tastalk_devs[i];
		if (!dev)
			continue;
		tastalk_devs[i] = NULL;

		tt = netdev_priv(dev);
		if (tt->tty) {
			printk(KERN_ERR "%s: tty discipline still running\n",
			       dev->name);
		}

		unregister_netdev(dev);
	}

	kfree(tastalk_devs);
	tastalk_devs = NULL;

	tty_unregister_ldisc(&tashtalk_ldisc);
}

module_init(tashtalk_init);
module_exit(tashtalk_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS_LDISC(N_PPP);
