/*
 * SO2 Tema 4
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/hashtable.h>
#include <net/sock.h>
#include <linux/proc_fs.h>

#include "stp.h"

MODULE_DESCRIPTION("Simple transfer protocol");
MODULE_AUTHOR("Blondutz&Pici");
MODULE_LICENSE("GPL");

DEFINE_HASHTABLE(sk_htable, HASH_LEN);

static struct proc_dir_entry *proc_stp;
static int rxpkts, hdrerr, csumerr, nosock, nobuffs, txpkts;

struct stp_sock {
	struct sock sk;
	struct sockaddr_stp *addr;
	__be16 connect_port;
	__u8 connect_mac[MACADDR_LEN];
	struct hlist_node node;
};

static __u8 checksum(const struct sk_buff *skb, size_t off)
{
	int i;
	__u8 csum = 0;
	
	i = off;
	while (i < skb->len) {
		csum ^= *(skb->data + i++);
	}

	return csum;
}

static int proc_show(struct seq_file *m, void *v)
{ 	
	seq_puts(m, "RxPkts HdrErr CsumErr NoSock NoBuffs TxPkts\n");
	seq_printf(m, "%d %d %d %d %d %d\n", rxpkts, hdrerr, csumerr, nosock,
											nobuffs, txpkts);
	return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_show, NULL);
}

static const struct file_operations proc_fops = {
	.owner = THIS_MODULE,
	.open = proc_open,
	.read = seq_read,
	.release = single_release,
};

static int stp_release(struct socket *sock)
{
	struct stp_sock *sk = (struct stp_sock *)sock->sk;

	if (sk->addr != NULL) {
		hash_del_rcu(&sk->node);
	}
	kfree(sk->addr);
	sock_put(sock->sk);

	return 0;
}

static int stp_bind(struct socket *sock, struct sockaddr *sa,
					int addr_len)
{
	struct stp_sock *sk = (struct stp_sock *)sock->sk;
	struct stp_sock *sock_it;
	struct sockaddr_stp *sa_addr = (struct sockaddr_stp *)sa;
	int found = 0;

	if (sa_addr->sas_family != AF_STP)
		return -EINVAL;

	hash_for_each_possible_rcu(sk_htable, sock_it, node, sa_addr->sas_port) {
	    if (sock_it->addr->sas_port == sa_addr->sas_port
	    			&& (sock_it->addr->sas_ifindex == 0
	    				|| sock_it->addr->sas_ifindex == sa_addr->sas_ifindex
	    				|| sa_addr->sas_ifindex == 0)) {
	        found = 1;
	    }
	}
    if (found)
    	return -EBUSY;

    sk->addr = kmalloc(sizeof(struct sockaddr_stp), GFP_KERNEL);
    if (sk->addr == NULL)
    	return -ENOMEM;

    sk->addr->sas_family = sa_addr->sas_family;
    sk->addr->sas_ifindex = sa_addr->sas_ifindex;
    sk->addr->sas_port = sa_addr->sas_port;
    memcpy(sk->addr->sas_addr, sa_addr->sas_addr, MACADDR_LEN);

    hash_add_rcu(sk_htable, &sk->node, sa_addr->sas_port);

	return 0;
}

static int stp_connect(struct socket *sock, struct sockaddr *saddr,
					int addr_len, int flags)
{
	struct stp_sock *sk = (struct stp_sock *)sock->sk;
	struct sockaddr_stp *sa_addr = (struct sockaddr_stp *)saddr;

	if (sa_addr->sas_family != AF_STP)
		return -EINVAL;

	sk->connect_port = sa_addr->sas_port;
	memcpy(sk->connect_mac, sa_addr->sas_addr, MACADDR_LEN);

	return 0;
}

static int stp_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct stp_sock *sk = (struct stp_sock *)sock->sk;
	struct sockaddr_stp *addr = (struct sockaddr_stp *)msg->msg_name;
	struct net_device *device;
	struct sk_buff *skb;
	struct stp_hdr *hdr;
	int err = 0, offset;
	__u8 *mac_addr;
	__be16 port;

	if (sk->addr->sas_ifindex == 0)
		return -EINVAL;

	device = dev_get_by_index(sock_net(sock->sk), sk->addr->sas_ifindex);
	if (device == NULL)
		return -EINVAL;

	skb = sock_alloc_send_pskb(sock->sk, LL_RESERVED_SPACE(device),
			sizeof(struct stp_hdr) + len, msg->msg_flags & MSG_DONTWAIT,
											&err, 0);
	if (skb == NULL)
		goto out;

	if (sk->connect_port != 0) {
		port = sk->connect_port;
		mac_addr = sk->connect_mac;
	}
	else {
		port = addr->sas_port;
		mac_addr = addr->sas_addr;
	}
	skb_reserve(skb, LL_RESERVED_SPACE(device));
	offset = dev_hard_header(skb, device, ETH_P_STP, mac_addr,
					sk->addr->sas_addr, sizeof(struct stp_hdr) + len);
	if (offset < 0) {
		err = -EINVAL;
		goto out;
	}

	hdr = (struct stp_hdr *)skb_put(skb, sizeof(struct stp_hdr));
	hdr->dst = port;
	hdr->src = sk->addr->sas_port;
	hdr->len = htons(sizeof(struct stp_hdr) + len);
	hdr->csum = 0;

	skb_put(skb, len);
	err = skb_copy_datagram_from_iter(skb, offset + sizeof(struct stp_hdr),
					  					&msg->msg_iter, len);
	if (err)
		goto out;

	hdr->csum = checksum(skb, offset);

	skb->dev = device;
	skb->protocol = htons(ETH_P_STP);
	skb->priority = sock->sk->sk_priority;
	err = dev_queue_xmit(skb);
	if (err)
		goto out;

	txpkts++;

out:
	dev_put(device);
	if (!err)
		return len;
	kfree_skb(skb);
	return err;
}

static int stp_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
						int flags)
{
	struct stp_sock *sk = (struct stp_sock *)sock->sk;
	struct sk_buff *skb;
	struct stp_hdr *hdr;
	int err = -EINVAL;
	__u8 csum;

	skb = skb_recv_datagram(sock->sk, flags, flags & MSG_DONTWAIT, &err);
	if (skb == NULL)
		return err;
	

	hdr = (struct stp_hdr *)skb_put(skb, sizeof(struct stp_hdr));
	csum = hdr->csum;
	hdr->csum = 0;

	if (checksum(skb, 14) != csum) {
		csumerr++;
		skb_free_datagram(sock->sk, skb);
		return -EINVAL;
	}

	err = skb_copy_datagram_iter(skb, sizeof(struct stp_hdr), &msg->msg_iter,
								len);
	if (err != 0) {
		skb_free_datagram(sock->sk, skb);
		return err;
	}

	sock_recv_ts_and_drops(msg, sock->sk, skb);
	rxpkts++;

	return len;
}

static const struct proto_ops stp_ops = {
	.family = PF_STP,
	.owner = THIS_MODULE,
	.release = stp_release,
	.bind =	stp_bind,
	.connect = stp_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname = sock_no_getname,
	.poll =	datagram_poll,
	.ioctl = sock_no_ioctl,
	.listen = sock_no_listen,
	.shutdown =	sock_no_shutdown,
	.setsockopt = sock_no_setsockopt,
	.getsockopt = sock_no_getsockopt,
	.sendmsg = stp_sendmsg,
	.recvmsg = stp_recvmsg,
	.mmap =	sock_no_mmap,
	.sendpage =	sock_no_sendpage,
};

static struct proto stp_proto = {
	.name = STP_PROTO_NAME,
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct stp_sock)
};

static int stp_create(struct net *net, struct socket *sock, int protocol,
						int kern)
{
	struct sock *socket;

	if (sock->type != SOCK_DGRAM || protocol)
		return -ESOCKTNOSUPPORT;

	socket = sk_alloc(net, AF_STP, GFP_KERNEL, &stp_proto, kern);
	if (!socket)
		return -ENOMEM;

	sock->ops = &stp_ops;
	socket->sk_protocol = protocol;
	sock_init_data(sock, socket);
	
	return 0;
}

static const struct net_proto_family stp_family_ops = {
	.family = PF_STP,
	.create = stp_create,
	.owner = THIS_MODULE
};

static int stp_packet_recv(struct sk_buff *skb, struct net_device *dev,
				struct packet_type *pt, struct net_device *orig_dev)
{
	struct stp_sock *sock_it;
	struct stp_hdr *hdr;
	int err = 0, found = 0;

	if (skb->len < sizeof(struct stp_hdr)) {
		hdrerr++;
		err = -EINVAL;
		goto out_err;
	}
	hdr = (struct stp_hdr *)skb->data;
	if (hdr->src == 0 || hdr->dst == 0) {
		hdrerr++;
		err = -EINVAL;
		goto out_err;
	}


	hash_for_each_possible_rcu(sk_htable, sock_it, node, hdr->dst) {
	    if (sock_it->addr->sas_port == hdr->dst) {
	    	found = 1;
	    	break;
	    }
	}
	if (!found) {
		nosock++;
		err = -EINVAL;
		goto out_err;
	}

	err = sock_queue_rcv_skb(&sock_it->sk, skb);
	if (err) {
		nobuffs++;
		goto out_err;
	}

	return 0;

out_err:
	kfree_skb(skb);
	return err;
}

static struct packet_type stp_packet = {
	.type = htons(ETH_P_STP),
	.func = stp_packet_recv
};

static int __init stp_init(void)
{
	int err;

	err = proto_register(&stp_proto, 1);
	if (err)
		goto out_err;

	err = sock_register(&stp_family_ops);
	if (err)
		goto out_free_proto;

	proc_stp = proc_create(STP_PROC_NET_FILENAME, 0, init_net.proc_net,
								&proc_fops);
	if (proc_stp == NULL) {
		err = -ENOMEM;
		goto out_free_socket;
	}
	dev_add_pack(&stp_packet);

	return 0;

out_free_socket:
	sock_unregister(AF_STP);
out_free_proto:
	proto_unregister(&stp_proto);
out_err:
	return err;
}

static void __exit stp_exit(void)
{
	sock_unregister(AF_STP);
	proto_unregister(&stp_proto);
	dev_remove_pack(&stp_packet);
	proc_remove(proc_stp);
}

module_init(stp_init);
module_exit(stp_exit);
