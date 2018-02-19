/*
 * Copyright (c) 2018, The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <linux/if.h>
#include "wil6210.h"
#include "wmi.h"
#include "slave.h"
#include "slave_i.h"

struct wil_slave_entry {
	struct wil6210_priv *wil;
	void *ctx; /* master driver context */
	char *board_file; /* board file override */
	struct wil_slave_rops rops;
};

static DEFINE_MUTEX(slave_lock);

#define MAX_SLAVES	2

static struct wil_slave_entry slaves[MAX_SLAVES];

static int find_free_slave_entry(void)
{
	int i;

	for (i = 0; i < MAX_SLAVES; i++)
		if (!slaves[i].wil)
			return i;

	return -ENOENT;
}

int wil_register_slave(struct wil6210_priv *wil)
{
	int i, rc = 0;

	mutex_lock(&slave_lock);

	i = find_free_slave_entry();
	if (i < 0) {
		wil_err(wil, "out of slave entries, %s not added\n",
			wil->main_ndev->name);
		rc = -ENOMEM;
		goto out;
	}
	slaves[i].wil = wil;
	slaves[i].ctx = NULL;
	wil->slave_ctx = &slaves[i];
	wil_info(wil, "added slave entry, interface %s\n",
		 wil->main_ndev->name);
out:
	mutex_unlock(&slave_lock);
	return rc;
}

static void wil_slave_clear_master_ctx(struct wil_slave_entry *slave)
{
	struct wil6210_priv *wil = slave->wil;

	lockdep_assert_held(&slave_lock);

	slave->ctx = NULL;
	/* make sure all rops will see the cleared context */
	wmb();
	/* make sure master context is not used */
	if (test_bit(wil_status_napi_en, wil->status)) {
		napi_synchronize(&wil->napi_rx);
		napi_synchronize(&wil->napi_tx);
	}
	flush_work(&wil->wmi_event_worker);
}

void wil_unregister_slave(struct wil6210_priv *wil)
{
	int i;
	struct wil_slave_entry *slave;

	mutex_lock(&slave_lock);

	for (i = 0; i < MAX_SLAVES; i++) {
		slave = &slaves[i];

		if (slave->wil != wil)
			continue;

		if (slave->ctx) {
			mutex_unlock(&slave_lock);
			slave->rops.slave_going_down(slave->ctx);
			mutex_lock(&slave_lock);
			wil_slave_clear_master_ctx(slave);
		}
		slaves[i].wil = NULL;
		kfree(slaves[i].board_file);
		slaves[i].board_file = NULL;
		wil->slave_ctx = NULL;
		goto out;
	}

	wil_err(wil, "failed to remove slave, interface %s\n",
		wil->main_ndev->name);
out:
	mutex_unlock(&slave_lock);
}

static int wil_slave_ioctl(void *dev, u16 code, u8 *req_buf, u16 req_len,
			   u8 *resp_buf, u16 *resp_len)
{
	struct wil_slave_entry *slave = dev;
	struct wil6210_priv *wil = slave->wil;
	struct wil6210_vif *vif = ndev_to_vif(wil->main_ndev);
	struct wmi_internal_fw_ioctl_cmd *cmd;
	struct {
		struct wmi_cmd_hdr wmi;
		struct wmi_internal_fw_ioctl_event evt;
	} __packed * reply;
	u16 cmd_len, reply_len, evt_len;
	int rc;

	wil_dbg_misc(wil, "slave_ioctl, code %d\n", code);

	if (!resp_len)
		return -EINVAL;

	if (req_len > WMI_MAX_IOCTL_PAYLOAD_SIZE) {
		wil_err(wil, "request too large (%d, max %d)\n",
			req_len, WMI_MAX_IOCTL_PAYLOAD_SIZE);
		return -EINVAL;
	}

	cmd_len = sizeof(*cmd) + req_len;
	cmd = kmalloc(cmd_len, GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;
	reply_len = sizeof(*reply) + WMI_MAX_IOCTL_REPLY_PAYLOAD_SIZE;
	reply = kmalloc(reply_len, GFP_KERNEL);
	if (!reply) {
		rc = -ENOMEM;
		goto out_cmd;
	}
	cmd->code = cpu_to_le16(code);
	cmd->length = cpu_to_le16(req_len);
	memcpy(cmd->payload, req_buf, req_len);
	memset(reply, 0, sizeof(*reply));
	reply->evt.status = WMI_FW_STATUS_FAILURE;
	rc = wmi_call(wil, WMI_INTERNAL_FW_IOCTL_CMDID, vif->mid,
		      cmd, cmd_len,
		      WMI_INTERNAL_FW_IOCTL_EVENTID, reply, reply_len,
		      WIL6210_FW_RECOVERY_TO);
	if (rc)
		goto out_reply;
	if (reply->evt.status) {
		wil_err(wil, "ioctl failed with status %d\n",
			reply->evt.status);
		rc = -EINVAL;
		goto out_reply;
	}
	evt_len = le16_to_cpu(reply->evt.length);
	if (evt_len > *resp_len) {
		wil_err(wil, "response buffer too short (have %d need %d)\n",
			*resp_len, evt_len);
		rc = -EINVAL;
		goto out_reply;
	}
	memcpy(resp_buf, &reply->evt.payload, evt_len);
	*resp_len = evt_len;
out_reply:
	kfree(reply);
out_cmd:
	kfree(cmd);
	return rc;
}

static int wil_slave_fw_reload(void *dev, const char *board_file)
{
	struct wil_slave_entry *slave = dev;
	struct wil6210_priv *wil = slave->wil;
	int rc, len;

	wil_dbg_misc(wil, "slave_fw_reload, board_file %s\n", board_file);

	kfree(slave->board_file);
	slave->board_file = NULL;
	if (board_file) {
		len = strlen(board_file) + 1;
		slave->board_file = kmemdup(board_file, len, GFP_KERNEL);
		if (!slave->board_file)
			return -ENOMEM;
	}

	wil_dbg_misc(wil, "resetting interface...\n");
	mutex_lock(&wil->mutex);
	__wil_down(wil);
	rc = __wil_up(wil);
	mutex_unlock(&wil->mutex);

	if (rc)
		wil_err(wil, "failed to reset interface, error %d\n", rc);

	return rc;
}

static void wil_slave_get_mac(void *dev, u8 *mac)
{
	struct wil_slave_entry *slave = dev;
	struct wil6210_priv *wil = slave->wil;

	ether_addr_copy(mac, wil->main_ndev->perm_addr);
}

static netdev_tx_t wil_slave_tx_data(void *dev, u8 cid, struct sk_buff *skb)
{
	struct wil_slave_entry *slave = dev;
	struct wil6210_priv *wil = slave->wil;
	struct net_device *ndev = wil->main_ndev;

	return _wil_start_xmit(skb, ndev);
}

static struct napi_struct *wil_slave_get_napi_rx(void *dev)
{
	struct wil_slave_entry *slave = dev;
	struct wil6210_priv *wil = slave->wil;

	return &wil->napi_rx;
}

static struct wil_slave_ops slave_ops = {
	.api_version = WIL_SLAVE_API_VERSION,
	.ioctl = wil_slave_ioctl,
	.tx_data = wil_slave_tx_data,
	.fw_reload = wil_slave_fw_reload,
	.get_mac = wil_slave_get_mac,
	.get_napi_rx = wil_slave_get_napi_rx,
};

static inline struct wil_slave_entry *
wil_get_slave_ctx(struct wil6210_vif *vif, void **master_ctx_out)
{
	struct wil6210_priv *wil = vif_to_wil(vif);
	struct wil_slave_entry *slave = wil->slave_ctx;
	void *master_ctx;

	if (!slave)
		return NULL;
	if (vif->mid != 0)
		return NULL;
	master_ctx = slave->ctx;
	if (!master_ctx) {
		wil_err(wil, "master not registered for interface %s\n",
			wil->main_ndev->name);
		return NULL;
	}
	*master_ctx_out = master_ctx;
	return slave;
}

void wil_slave_evt_internal_fw_event(struct wil6210_vif *vif,
				     struct wmi_internal_fw_event_event *evt,
				     int len)
{
	struct wil_slave_entry *slave;
	void *master_ctx;

	slave = wil_get_slave_ctx(vif, &master_ctx);
	if (!slave || len < sizeof(struct wmi_internal_fw_event_event))
		return;
	slave->rops.rx_event(master_ctx, le16_to_cpu(evt->id),
			     (u8 *)evt->payload, le16_to_cpu(evt->length));
}

void wil_slave_evt_internal_set_channel(
	struct wil6210_vif *vif,
	struct wmi_internal_fw_set_channel_event *evt,
	int len)
{
	struct wil_slave_entry *slave;
	void *master_ctx;

	slave = wil_get_slave_ctx(vif, &master_ctx);
	if (!slave || len < sizeof(struct wmi_internal_fw_set_channel_event))
		return;
	slave->rops.set_channel(master_ctx, evt->channel_num);
}

void wil_slave_evt_connect(struct wil6210_vif *vif, const u8 *mac, u8 cid)
{
	struct wil_slave_entry *slave;
	void *master_ctx;

	slave = wil_get_slave_ctx(vif, &master_ctx);
	if (!slave)
		return;
	slave->rops.connected(master_ctx, mac, cid);
}

void wil_slave_evt_disconnect(struct wil6210_vif *vif, u8 cid)
{
	struct wil_slave_entry *slave;
	void *master_ctx;

	slave = wil_get_slave_ctx(vif, &master_ctx);
	if (!slave)
		return;
	slave->rops.disconnected(master_ctx, cid);
}

int wil_slave_rx_data(struct wil6210_vif *vif, u8 cid, struct sk_buff *skb)
{
	struct wil6210_priv *wil = vif_to_wil(vif);
	struct wil_slave_entry *slave;
	void *master_ctx;

	slave = wil_get_slave_ctx(vif, &master_ctx);
	if (unlikely(!slave)) {
		dev_kfree_skb(skb);
		return GRO_DROP;
	}

	/* pass security packets to wireless interface */
	if (skb->protocol != cpu_to_be16(ETH_P_PAE))
		return slave->rops.rx_data(master_ctx, cid, skb);
	else
		return napi_gro_receive(&wil->napi_rx, skb);
}

const char *wil_slave_get_board_file(struct wil6210_priv *wil)
{
	struct wil6210_vif *vif = ndev_to_vif(wil->main_ndev);
	struct wil_slave_entry *slave;
	void *master_ctx;

	slave = wil_get_slave_ctx(vif, &master_ctx);
	if (!slave)
		return NULL;
	return slave->board_file;
}

void *wil_register_master(const char *ifname,
			  struct wil_slave_ops *ops,
			  const struct wil_slave_rops *rops, void *ctx)
{
	int i;
	void *ret;
	struct wil_slave_entry *slave = NULL;
	struct wil6210_priv *wil;
	struct net_device *ndev;

	if (!ifname || !ops || !rops)
		return ERR_PTR(-EINVAL);

	mutex_lock(&slave_lock);
	for (i = 0; i < MAX_SLAVES; i++) {
		if (slaves[i].wil) {
			wil = slaves[i].wil;
			ndev = wil->main_ndev;
			if (!strcmp(ndev->name, ifname)) {
				slave = &slaves[i];
				break;
			}
		}
	}

	if (!slave) {
		ret = ERR_PTR(-ENOENT);
		goto out;
	}
	if (ops->api_version != WIL_SLAVE_API_VERSION) {
		wil_err(wil, "mismatched slave API (expected %d have %d)\n",
			WIL_SLAVE_API_VERSION, ops->api_version);
		ret = ERR_PTR(-EINVAL);
		goto out;
	}

	*ops = slave_ops;
	slave->rops = *rops;
	slave->ctx = ctx;
	wil_info(wil, "registered master for interface %s\n", ifname);
	ret = slave;
out:
	mutex_unlock(&slave_lock);
	return ret;
}
EXPORT_SYMBOL(wil_register_master);

void wil_unregister_master(void *dev)
{
	int i;
	struct wil_slave_entry *slave;
	struct wil6210_priv *wil;

	if (!dev)
		return;

	mutex_lock(&slave_lock);
	slave = dev;
	i = slave - &slaves[0];
	if (i < 0 || i >= MAX_SLAVES)
		goto out;

	wil = slave->wil;
	if (!wil)
		goto out;

	wil_slave_clear_master_ctx(slave);

	wil_info(wil, "unregistered master for interface %s\n",
		 wil->main_ndev->name);
out:
	mutex_unlock(&slave_lock);
}
EXPORT_SYMBOL(wil_unregister_master);
