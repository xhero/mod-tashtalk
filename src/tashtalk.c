// SPDX-License-Identifier: GPL-2.0-only

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
#include <linux/if_slip.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include "tashtalk.h"
#include <linux/if_ltalk.h>
#include <linux/atalk.h>
#ifdef CONFIG_INET
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/slhc_vj.h>
#endif

#define SLIP_VERSION	"0.8.4-NET3.019-NEWTTY"

static struct net_device **slip_devs;

static int slip_maxdev = SL_NRUNIT;
module_param(slip_maxdev, int, 0);
MODULE_PARM_DESC(slip_maxdev, "Maximum number of slip devices");

/* Set the "sending" flag.  This must be atomic hence the set_bit. */
static inline void sl_lock(struct slip *sl)
{
	netif_stop_queue(sl->dev);
}


/* Clear the "sending" flag.  This must be atomic, hence the ASM. */
static inline void sl_unlock(struct slip *sl)
{
	netif_wake_queue(sl->dev);
}

/* Send one completely decapsulated IP datagram to the IP layer. */
static void sl_bump(struct slip *sl)
{
	struct net_device *dev = sl->dev;
	struct sk_buff *skb;
	int count;

	count = sl->rcount;

	dev->stats.rx_bytes += count;

	skb = dev_alloc_skb(count);
	if (skb == NULL) {
		printk(KERN_WARNING "%s: memory squeeze, dropping packet.\n", dev->name);
		dev->stats.rx_dropped++;
		return;
	}

	skb_put_data(skb, sl->rbuff, count);
	skb->dev = dev;
    skb->protocol = htons(ETH_P_LOCALTALK);

	//skb_reset_mac_header(skb);    /* Point to entire packet. */
    //skb_pull(skb,3);
    //skb_reset_transport_header(skb);    /* Point to data (Skip header). */

	netif_rx(skb);
	dev->stats.rx_packets++;
}

/* Encapsulate one IP datagram and stuff into a TTY queue. */
static void sl_encaps(struct slip *sl, unsigned char *icp, int len)
{
	int actual;

	if (len > sl->mtu) {		/* Sigh, shouldn't occur BUT ... */
		printk(KERN_WARNING "%s: truncating oversized transmit packet %i vs %i!\n", sl->dev->name, len, sl->mtu);
		sl->dev->stats.tx_dropped++;
		sl_unlock(sl);
		return;
	}

	/* Order of next two lines is *very* important.
	 * When we are sending a little amount of data,
	 * the transfer may be completed inside the ops->write()
	 * routine, because it's running with interrupts enabled.
	 * In this case we *never* got WRITE_WAKEUP event,
	 * if we did not request it before write operation.
	 *       14 Oct 1994  Dmitry Gorodchanin.
	 */
	set_bit(TTY_DO_WRITE_WAKEUP, &sl->tty->flags);
	actual = sl->tty->ops->write(sl->tty, icp, len);

	printk(KERN_WARNING "Trasmit to TASH %i", actual);
	sl_unlock(sl);
}

/* Write out any remaining transmit buffer. Scheduled when tty is writable */
static void slip_transmit(struct work_struct *work)
{
	struct slip *sl = container_of(work, struct slip, tx_work);
	int actual;

	spin_lock_bh(&sl->lock);
	/* First make sure we're connected. */
	if (!sl->tty || sl->magic != SLIP_MAGIC || !netif_running(sl->dev)) {
		spin_unlock_bh(&sl->lock);
		return;
	}

	if (sl->xleft <= 0)  {
		/* Now serial buffer is almost free & we can start
		 * transmission of another packet */
		sl->dev->stats.tx_packets++;
		clear_bit(TTY_DO_WRITE_WAKEUP, &sl->tty->flags);
		spin_unlock_bh(&sl->lock);
		sl_unlock(sl);
		return;
	}

	actual = sl->tty->ops->write(sl->tty, sl->xhead, sl->xleft);
	sl->xleft -= actual;
	sl->xhead += actual;
	spin_unlock_bh(&sl->lock);
}

/*
 * Called by the driver when there's room for more data.
 * Schedule the transmit.
 */
static void slip_write_wakeup(struct tty_struct *tty)
{
	struct slip *sl;

	rcu_read_lock();
	sl = rcu_dereference(tty->disc_data);
	if (sl)
		schedule_work(&sl->tx_work);
	rcu_read_unlock();
}

static void sl_tx_timeout(struct net_device *dev, unsigned int txqueue)
{
	struct slip *sl = netdev_priv(dev);

	spin_lock(&sl->lock);

	if (netif_queue_stopped(dev)) {
		if (!netif_running(dev) || !sl->tty)
			goto out;
	}
out:
	spin_unlock(&sl->lock);
}


/* Encapsulate an IP datagram and kick it into a TTY queue. */
static netdev_tx_t
sl_xmit(struct sk_buff *skb, struct net_device *dev)
{

	printk(KERN_ERR "%s: le send\n", dev->name);

	struct slip *sl = netdev_priv(dev);

	spin_lock(&sl->lock);
	if (!netif_running(dev)) {
		spin_unlock(&sl->lock);
		printk(KERN_WARNING "%s: xmit call when iface is down\n", dev->name);
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}
	if (sl->tty == NULL) {
		spin_unlock(&sl->lock);
		dev_kfree_skb(skb);
		printk(KERN_WARNING "%s: mumble!\n", dev->name);
		return NETDEV_TX_OK;
	}

	sl_lock(sl);
	dev->stats.tx_bytes += skb->len;
	sl_encaps(sl, skb->data, skb->len);
	spin_unlock(&sl->lock);

	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}


/******************************************
 *   Routines looking at netdevice side.
 ******************************************/

/* Netdevice UP -> DOWN routine */

static int
sl_close(struct net_device *dev)
{
	struct slip *sl = netdev_priv(dev);

	spin_lock_bh(&sl->lock);
	if (sl->tty)
		/* TTY discipline is running. */
		clear_bit(TTY_DO_WRITE_WAKEUP, &sl->tty->flags);
	netif_stop_queue(dev);
	sl->rcount   = 0;
	sl->xleft    = 0;
	spin_unlock_bh(&sl->lock);

	return 0;
}

/* Netdevice DOWN -> UP routine */

static int sl_open(struct net_device *dev)
{

	printk(KERN_ERR "Loaded tash netdevice");

	struct slip *sl = netdev_priv(dev);

	if (sl->tty == NULL)
		return -ENODEV;

	sl->flags &= (1 << SLF_INUSE);
	netif_start_queue(dev);
	return 0;
}


/* Netdevice get statistics request */

static void
sl_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	struct net_device_stats *devstats = &dev->stats;

	stats->rx_packets     = devstats->rx_packets;
	stats->tx_packets     = devstats->tx_packets;
	stats->rx_bytes       = devstats->rx_bytes;
	stats->tx_bytes       = devstats->tx_bytes;
	stats->rx_dropped     = devstats->rx_dropped;
	stats->tx_dropped     = devstats->tx_dropped;
	stats->tx_errors      = devstats->tx_errors;
	stats->rx_errors      = devstats->rx_errors;
	stats->rx_over_errors = devstats->rx_over_errors;
}

static int cops_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
        struct sockaddr_at *sa = (struct sockaddr_at *)&ifr->ifr_addr;

        switch(cmd)
        {
            case SIOCSIFADDR:
				dev->broadcast[0]       = 0xFF;
				dev->addr_len           = 1;
				return 0;

                case SIOCGIFADDR:
                        sa->sat_addr.s_net      = 0;
                        sa->sat_addr.s_node     = 127;
                return 0;

                //default:
                //        return -EOPNOTSUPP;
        }
	return 0;
}

/* Hook the destructor so we can free slip devices at the right point in time */
static void sl_free_netdev(struct net_device *dev)
{
	int i = dev->base_addr;

	slip_devs[i] = NULL;
}

static const struct net_device_ops sl_netdev_ops = {
	.ndo_open		= sl_open,
	.ndo_stop		= sl_close,
	.ndo_start_xmit		= sl_xmit,
	.ndo_get_stats64        = sl_get_stats64,
	.ndo_tx_timeout		= sl_tx_timeout,
	.ndo_do_ioctl           = cops_ioctl,
};



/******************************************
  Routines looking at TTY side.
 ******************************************/


/*
 * Handle the 'receiver data ready' interrupt.
 * This function is called by the 'tty_io' module in the kernel when
 * a block of SLIP data has been received, which can now be decapsulated
 * and sent on to some IP layer for further processing. This will not
 * be re-entered while running but other ldisc functions may be called
 * in parallel
 */

static void slip_receive_buf(struct tty_struct *tty, const unsigned char *cp,
		const char *fp, int count)
{
	struct slip *sl = tty->disc_data;
	struct sk_buff *skb;
	struct net_device *dev = sl->dev;
	int i;

	if (!sl || sl->magic != SLIP_MAGIC || !netif_running(sl->dev))
		return;

	printk(KERN_ERR "Tash read %i", count);
    print_hex_dump_bytes("Tash read: ", DUMP_PREFIX_NONE, cp, count);
	
	// call sl_bump

	for (i = 0; i < count; i++) {
		if (cp[i] == 0x00) {
			i++;

			if (cp[i] == 0xFF) {
				sl->rbuff[sl->rcount] = 0x00;
			} else if (cp[i] == 0xFD) {
				printk(KERN_ERR "Tash done frame %i", sl->rcount);
				sl_bump(sl);
				sl->rcount = 0;
			} else if (cp[i] == 0xFE) {
				printk(KERN_ERR "Tash frame error");
				sl->rcount = 0;
			} else if (cp[i] == 0xFA) {
				printk(KERN_ERR "Tash frame abort");
				sl->rcount = 0;
			} else if (cp[i] == 0xFC) {
				printk(KERN_ERR "Tash frame crc error");
				sl->rcount = 0;
			} else {
				printk(KERN_ERR "Tash escape unknown %c", cp[i]);
			}
		} else {
			sl->rbuff[sl->rcount] = cp[i];
		}

		sl->rcount++;
	}

	
/*
	skb = dev_alloc_skb(count);
	if (skb == NULL) {
		printk(KERN_WARNING "%s: memory squeeze, dropping packet.\n", dev->name);
		dev->stats.rx_dropped++;
		return;
	}

	skb_put_data(skb, cp, count);
	skb->dev = dev;
    skb->protocol = htons(ETH_P_LOCALTALK);

	//skb_reset_mac_header(skb);    // Point to entire packet.
    //skb_pull(skb,3);
    //skb_reset_transport_header(skb);   // Point to data (Skip header).

	netif_rx(skb);
	dev->stats.rx_packets++;
*/
}

/* Free a SLIP channel buffers. */
static void sl_free_bufs(struct slip *sl)
{
	/* Free all SLIP frame buffers. */
	kfree(xchg(&sl->rbuff, NULL));
	kfree(xchg(&sl->xbuff, NULL));
}

static int sl_alloc_bufs(struct slip *sl, int mtu)
{
	int err = -ENOBUFS;
	unsigned long len;
	char *rbuff = NULL;
	char *xbuff = NULL;

	/*
	 * Allocate the SLIP frame buffers:
	 *
	 * rbuff	Receive buffer.
	 * xbuff	Transmit buffer.
	 * cbuff        Temporary compression buffer.
	 */
	len = mtu * 2;

	/*
	 * allow for arrival of larger UDP packets, even if we say not to
	 * also fixes a bug in which SunOS sends 512-byte packets even with
	 * an MSS of 128
	 */
	if (len < 576 * 2)
		len = 576 * 2;
	rbuff = kmalloc(len + 4, GFP_KERNEL);
	if (rbuff == NULL)
		goto err_exit;
	xbuff = kmalloc(len + 4, GFP_KERNEL);
	if (xbuff == NULL)
		goto err_exit;

	spin_lock_bh(&sl->lock);
	if (sl->tty == NULL) {
		spin_unlock_bh(&sl->lock);
		err = -ENODEV;
		goto err_exit;
	}
	sl->mtu	     = mtu;
	sl->buffsize = len;
	sl->rcount   = 0;
	sl->xleft    = 0;
	rbuff = xchg(&sl->rbuff, rbuff);
	xbuff = xchg(&sl->xbuff, xbuff);


	spin_unlock_bh(&sl->lock);
	err = 0;

	/* Cleanup */
err_exit:

	kfree(xbuff);
	kfree(rbuff);
	return err;
}

/* Find a free SLIP channel, and link in this `tty' line. */
static struct slip *sl_alloc(void)
{
	int i;
	char name[IFNAMSIZ];
	struct net_device *dev = NULL;
	struct slip       *sl;

	for (i = 0; i < slip_maxdev; i++) {
		dev = slip_devs[i];
		if (dev == NULL)
			break;
	}
	/* Sorry, too many, all slots in use */
	if (i >= slip_maxdev)
		return NULL;
	
	dev = alloc_ltalkdev(sizeof(*sl));

	if (!dev)
		return NULL;

	dev->base_addr  = i;
	sl = netdev_priv(dev);

	/* Initialize channel control data */
	sl->magic       = SLIP_MAGIC;
	sl->dev	      	= dev;
	sl->mtu = 512;
	sl->mode = 0; // Maybe useful in the future?

	sl->dev->netdev_ops = &sl_netdev_ops;
	sl->dev->type =  ARPHRD_LOCALTLK;
	sl->dev->priv_destructor	= sl_free_netdev;

	spin_lock_init(&sl->lock);
	INIT_WORK(&sl->tx_work, slip_transmit);

	printk(KERN_ERR "dev index is %i", i);
	printk(KERN_ERR "dev pointer is %p", dev);

	slip_devs[i] = dev;
	return sl;
}

/*
 * Open the high-level part of the SLIP channel.
 * This function is called by the TTY module when the
 * SLIP line discipline is called for.  Because we are
 * sure the tty line exists, we only have to link it to
 * a free SLIP channel...
 *
 * Called in process context serialized from other ldisc calls.
 */

static int slip_open(struct tty_struct *tty)
{
	struct slip *sl;
	int err;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (tty->ops->write == NULL)
		return -EOPNOTSUPP;

	printk(KERN_ERR "TashTalk op port %s", tty->name);

	/* RTnetlink lock is misused here to serialize concurrent
	   opens of slip channels. There are better ways, but it is
	   the simplest one.
	 */
	rtnl_lock();

	sl = tty->disc_data;

	err = -EEXIST;
	/* First make sure we're not already connected. */
	if (sl && sl->magic == SLIP_MAGIC)
		goto err_exit;

	/* OK.  Find a free SLIP channel to use. */
	err = -ENFILE;


	sl = sl_alloc();
	if (sl == NULL)
		goto err_exit;


	sl->tty = tty;
	tty->disc_data = sl;
	sl->pid = current->pid;


	set_bit(SLF_INUSE, &sl->flags);

	err = sl_alloc_bufs(sl, SL_MTU);
	if (err)
		goto err_free_chan;

	err = register_netdevice(sl->dev);
	if (err)
		goto err_free_bufs;


	/* Done.  We have linked the TTY line to a channel. */
	rtnl_unlock();
	tty->receive_room = 65536;	/* We don't flow control */

	/* TTY layer expects 0 on success */
	printk(KERN_ERR "TashTalk dono open");
	return 0;


err_free_bufs:
	sl_free_bufs(sl);

err_free_chan:
printk(KERN_ERR "TashTalk OOPS");
	sl->tty = NULL;
	tty->disc_data = NULL;
	clear_bit(SLF_INUSE, &sl->flags);
	
	/* do not call free_netdev before rtnl_unlock */
	rtnl_unlock();
	free_netdev(sl->dev);
	return err;

err_exit:
	rtnl_unlock();

	/* Count references from TTY module */
	return err;
}

/*
 * Close down a SLIP channel.
 * This means flushing out any pending queues, and then returning. This
 * call is serialized against other ldisc functions.
 *
 * We also use this method fo a hangup event
 */

static void slip_close(struct tty_struct *tty)
{
	struct slip *sl = tty->disc_data;

	/* First make sure we're connected. */
	if (!sl || sl->magic != SLIP_MAGIC || sl->tty != tty)
		return;

	spin_lock_bh(&sl->lock);
	rcu_assign_pointer(tty->disc_data, NULL);
	sl->tty = NULL;
	spin_unlock_bh(&sl->lock);

	synchronize_rcu();
	flush_work(&sl->tx_work);


	/* Flush network side */
	unregister_netdev(sl->dev);
	/* This will complete via sl_free_netdev */
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)
static int slip_hangup(struct tty_struct *tty)
#else
static void slip_hangup(struct tty_struct *tty)
#endif
{
	slip_close(tty);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)
	return 0;
#endif
}


/* Perform I/O control on an active SLIP channel. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)
static int slip_ioctl(struct tty_struct *tty, struct file *file, unsigned int cmd,
#else
static int slip_ioctl(struct tty_struct *tty, unsigned int cmd,
#endif
		unsigned long arg)
{
	struct slip *sl = tty->disc_data;
	unsigned int tmp;
	int __user *p = (int __user *)arg;

	/* First make sure we're connected. */
	if (!sl || sl->magic != SLIP_MAGIC)
		return -EINVAL;

	switch (cmd) {
	case SIOCGIFNAME:
		tmp = strlen(sl->dev->name) + 1;
		if (copy_to_user((void __user *)arg, sl->dev->name, tmp))
			return -EFAULT;
		return 0;

	// do we need mode?
	case SIOCGIFENCAP:
		if (put_user(sl->mode, p))
			return -EFAULT;
		return 0;

	case SIOCSIFENCAP:
		if (get_user(tmp, p))
			return -EFAULT;
		sl->mode = tmp;
		return 0;

	case SIOCSIFHWADDR:
		return -EINVAL;

	default:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)
		return tty_mode_ioctl(tty, 0, cmd, arg);
#else
		return tty_mode_ioctl(tty, cmd, arg);
#endif
	}
}



static struct tty_ldisc_ops sl_ldisc = {
	.owner 		= THIS_MODULE,
	.num		= N_PPP,//N_SLIP,
	.name 		= "tasktalk",
	.open 		= slip_open,
	.close	 	= slip_close,
	.hangup	 	= slip_hangup,
	.ioctl		= slip_ioctl,
	.receive_buf	= slip_receive_buf,
	.write_wakeup	= slip_write_wakeup,
};

static int __init slip_init(void)
{
	int status;

	if (slip_maxdev < 4)
		slip_maxdev = 4; /* Sanity */

	printk(KERN_INFO "TashTalk Interface (dynamic channels, max=%d)", slip_maxdev);

	slip_devs = kcalloc(slip_maxdev, sizeof(struct net_device *),
								GFP_KERNEL);
	if (!slip_devs)
		return -ENOMEM;

	/* Fill in our line protocol discipline, and register it */
	status = tty_register_ldisc(&sl_ldisc);
	if (status != 0) {
		printk(KERN_ERR "SLIP: can't register line discipline (err = %d)\n", status);
		kfree(slip_devs);
	}
	return status;
}

static void __exit slip_exit(void)
{
	int i;
	struct net_device *dev;
	struct slip *sl;
	unsigned long timeout = jiffies + HZ;
	int busy = 0;

	if (slip_devs == NULL)
		return;

	/* First of all: check for active disciplines and hangup them.
	 */
	do {
		if (busy)
			msleep_interruptible(100);

		busy = 0;
		for (i = 0; i < slip_maxdev; i++) {
			dev = slip_devs[i];
			if (!dev)
				continue;
			sl = netdev_priv(dev);
			spin_lock_bh(&sl->lock);
			if (sl->tty) {
				busy++;
				tty_hangup(sl->tty);
			}
			spin_unlock_bh(&sl->lock);
		}
	} while (busy && time_before(jiffies, timeout));

	/* FIXME: hangup is async so we should wait when doing this second
	   phase */

	for (i = 0; i < slip_maxdev; i++) {
		dev = slip_devs[i];
		if (!dev)
			continue;
		slip_devs[i] = NULL;

		sl = netdev_priv(dev);
		if (sl->tty) {
			printk(KERN_ERR "%s: tty discipline still running\n",
			       dev->name);
		}

		printk(KERN_ERR "The dev1: %p\n", dev);
		printk(KERN_ERR "The dev2: %p\n", dev);
		unregister_netdev(dev);
		printk(KERN_ERR "unregistered\n");
	}

	kfree(slip_devs);
	slip_devs = NULL;

	tty_unregister_ldisc(&sl_ldisc);
}

module_init(slip_init);
module_exit(slip_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS_LDISC(N_SLIP);
