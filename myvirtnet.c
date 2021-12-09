#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_net.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/scatterlist.h>
#include <linux/if_vlan.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/average.h>
#include <linux/filter.h>
#include <linux/kernel.h>
#include <net/route.h>
#include <net/xdp.h>
#include <net/net_failover.h>

/* Amount of XDP headroom to prepend to packets for use by xdp_adjust_head */
#define VIRTIO_XDP_HEADROOM 256

/* Separating two types of XDP xmit */
#define VIRTIO_XDP_TX		BIT(0)
#define VIRTIO_XDP_REDIR	BIT(1)

#define VIRTIO_XDP_FLAG	BIT(0)

/* RX packet size EWMA. The average packet size is used to determine the packet
 * buffer size when refilling RX rings. As the entire RX ring may be refilled
 * at once, the weight is chosen so that the EWMA will be insensitive to short-
 * term, transient changes in packet size.
 */
DECLARE_EWMA(pkt_len, 0, 64)

#define VIRTNET_SQ_STATS_LEN	ARRAY_SIZE(virtnet_sq_stats_desc)
#define VIRTNET_RQ_STATS_LEN	ARRAY_SIZE(virtnet_rq_stats_desc)

struct virtnet_sq_stats {
	struct u64_stats_sync syncp;
	u64 packets;
	u64 bytes;
	u64 xdp_tx;
	u64 xdp_tx_drops;
	u64 kicks;
};

struct virtnet_rq_stats {
	struct u64_stats_sync syncp;
	u64 packets;
	u64 bytes;
	u64 drops;
	u64 xdp_packets;
	u64 xdp_tx;
	u64 xdp_redirects;
	u64 xdp_drops;
	u64 kicks;
};

/* Internal representation of a send virtqueue */
struct send_queue {
	/* Virtqueue associated with this send _queue */
	struct virtqueue *vq;

	/* TX: fragments + linear part + virtio header */
	struct scatterlist sg[MAX_SKB_FRAGS + 2];

	/* Name of the send queue: output.$index */
	char name[40];

	struct virtnet_sq_stats stats;

	struct napi_struct napi;
};

/* Internal representation of a receive virtqueue */
struct receive_queue {
	/* Virtqueue associated with this receive_queue */
	struct virtqueue *vq;

	struct napi_struct napi;

	struct bpf_prog __rcu *xdp_prog;

	struct virtnet_rq_stats stats;

	/* Chain pages by the private ptr. */
	struct page *pages;

	/* Average packet length for mergeable receive buffers. */
	struct ewma_pkt_len mrg_avg_pkt_len;

	/* Page frag for packet buffer allocation. */
	struct page_frag alloc_frag;

	/* RX: fragments + linear part + virtio header */
	struct scatterlist sg[MAX_SKB_FRAGS + 2];

	/* Min single buffer size for mergeable buffers case. */
	unsigned int min_buf_len;

	/* Name of this receive queue: input.$index */
	char name[40];

	struct xdp_rxq_info xdp_rxq;
};

/* Control VQ buffers: protected by the rtnl lock */
struct control_buf {
	struct virtio_net_ctrl_hdr hdr;
	virtio_net_ctrl_ack status;
	struct virtio_net_ctrl_mq mq;
	u8 promisc;
	u8 allmulti;
	__virtio16 vid;
	__virtio64 offloads;
};

struct virtnet_info {
	struct virtio_device *vdev;
	struct virtqueue *cvq;
	struct net_device *dev;
	struct send_queue *sq;
	struct receive_queue *rq;
	unsigned int status;

	/* Max # of queue pairs supported by the device */
	u16 max_queue_pairs;

	/* # of queue pairs currently used by the driver */
	u16 curr_queue_pairs;

	/* # of XDP queue pairs currently used by the driver */
	u16 xdp_queue_pairs;

	/* xdp_queue_pairs may be 0, when xdp is already loaded. So add this. */
	bool xdp_enabled;

	/* I like... big packets and I cannot lie! */
	bool big_packets;

	/* Host will merge rx buffers for big packets (shake it! shake it!) */
	bool mergeable_rx_bufs;

	/* Has control virtqueue */
	bool has_cvq;

	/* Host can handle any s/g split between our header and packet data */
	bool any_header_sg;

	/* Packet virtio header size */
	u8 hdr_len;

	/* Work struct for refilling if we run low on memory. */
	struct delayed_work refill;

	/* Work struct for config space updates */
	struct work_struct config_work;

	/* Does the affinity hint is set for virtqueues? */
	bool affinity_hint_set;

	/* CPU hotplug instances for online & dead */
	struct hlist_node node;
	struct hlist_node node_dead;

	struct control_buf *ctrl;

	/* Ethtool settings */
	u8 duplex;
	u32 speed;

	unsigned long guest_offloads;
	unsigned long guest_offloads_capable;

	/* failover when STANDBY feature enabled */
	struct failover *failover;
};

struct padded_vnet_hdr {
	struct virtio_net_hdr_mrg_rxbuf hdr;
	/*
	 * hdr is in a separate sg buffer, and data sg buffer shares same page
	 * with this header sg. This padding makes next sg 16 byte aligned
	 * after the header.
	 */
	char padding[4];
};

/* when vi->curr_queue_pairs > nr_cpu_ids, the txq/sq is only used for xdp tx on
 * the current cpu, so it does not need to be locked.
 *
 * Here we use marco instead of inline functions because we have to deal with
 * three issues at the same time: 1. the choice of sq. 2. judge and execute the
 * lock/unlock of txq 3. make sparse happy. It is difficult for two inline
 * functions to perfectly solve these three problems at the same time.
 */
#define virtnet_xdp_get_sq(vi) ({                                       \
	struct netdev_queue *txq;                                       \
	typeof(vi) v = (vi);                                            \
	unsigned int qp;                                                \
									\
	if (v->curr_queue_pairs > nr_cpu_ids) {                         \
		qp = v->curr_queue_pairs - v->xdp_queue_pairs;          \
		qp += smp_processor_id();                               \
		txq = netdev_get_tx_queue(v->dev, qp);                  \
		__netif_tx_acquire(txq);                                \
	} else {                                                        \
		qp = smp_processor_id() % v->curr_queue_pairs;          \
		txq = netdev_get_tx_queue(v->dev, qp);                  \
		__netif_tx_lock(txq, raw_smp_processor_id());           \
	}                                                               \
	v->sq + qp;                                                     \
})

#define virtnet_xdp_put_sq(vi, q) {                                     \
	struct netdev_queue *txq;                                       \
	typeof(vi) v = (vi);                                            \
									\
	txq = netdev_get_tx_queue(v->dev, (q) - v->sq);                 \
	if (v->curr_queue_pairs > nr_cpu_ids)                           \
		__netif_tx_release(txq);                                \
	else                                                            \
		__netif_tx_unlock(txq);                                 \
}

#if 1
static void virtnet_poll_cleantx(struct receive_queue *rq) {}

extern int virtnet_receive(struct receive_queue *rq, int budget,
			   unsigned int *xdp_xmit); // { return -1; }
#endif

int virtnet_poll(struct napi_struct *napi, int budget)
{
	struct receive_queue *rq =
		container_of(napi, struct receive_queue, napi);
	struct virtnet_info *vi = rq->vq->vdev->priv;
	struct send_queue *sq;
	unsigned int received;
	unsigned int xdp_xmit = 0;

	virtnet_poll_cleantx(rq);

	received = virtnet_receive(rq, budget, &xdp_xmit);

#if 0
	if (received < budget)
		virtqueue_napi_complete(napi, rq->vq, received);
#endif
	
	if (xdp_xmit & VIRTIO_XDP_REDIR)
		xdp_do_flush();

	if (xdp_xmit & VIRTIO_XDP_TX) {
		sq = virtnet_xdp_get_sq(vi);
		if (virtqueue_kick_prepare(sq->vq) && virtqueue_notify(sq->vq)) {
			u64_stats_update_begin(&sq->stats.syncp);
			sq->stats.kicks++;
			u64_stats_update_end(&sq->stats.syncp);
		}
		virtnet_xdp_put_sq(vi, sq);
	}

	return received;
}
