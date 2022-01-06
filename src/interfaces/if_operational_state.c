/*
 * telekom / sysrepo-plugin-interfaces
 *
 * This program is made available under the terms of the
 * BSD 3-Clause license which is available at
 * https://opensource.org/licenses/BSD-3-Clause
 *
 * SPDX-FileCopyrightText: 2021 Deutsche Telekom AG
 * SPDX-FileContributor: Sartura Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <linux/if.h>
#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/ip.h>
#include <linux/limits.h>

#include <netlink/addr.h>
#include <netlink/cache.h>
#include <netlink/errno.h>
#include <netlink/netlink.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/link/inet.h>
#include <netlink/route/link/inet6.h>
#include <netlink/route/link/vlan.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/tc.h>
#include <netlink/socket.h>

#include <libyang/libyang.h>
#include <libyang/tree_data.h>
#include <sysrepo.h>
#include <sysrepo/xpath.h>

#include "if_nic_stats.h"
#include "if_state.h"
#include "if_operational_state.h"
#include "ip_data.h"
#include "link_data.h"
#include "utils/memory.h"

#define BASE_YANG_MODEL "ietf-interfaces"
#define BASE_IP_YANG_MODEL "ietf-ip"

#define SYSREPOCFG_EMPTY_CHECK_COMMAND "sysrepocfg -X -d running -m " BASE_YANG_MODEL

// config data
#define INTERFACES_YANG_MODEL "/" BASE_YANG_MODEL ":interfaces"
#define INTERFACE_LIST_YANG_PATH INTERFACES_YANG_MODEL "/interface"

// other #defines
#define MAC_ADDR_MAX_LENGTH 18
#define MAX_DESCR_LEN 100
#define DATETIME_BUF_SIZE 30
#define CLASS_NET_LINE_LEN 1024
#define ADDR_STR_BUF_SIZE 45 // max ip string length (15 for ipv4 and 45 for ipv6)
#define MAX_IF_NAME_LEN IFNAMSIZ // 16 bytes
#define CMD_LEN 1024

static int get_system_boot_time(char boot_datetime[])
{
	time_t now = 0;
	struct tm *ts = {0};
	struct sysinfo s_info = {0};
	time_t uptime_seconds = 0;

	now = time(NULL);

	ts = localtime(&now);
	if (ts == NULL)
		return -1;

	if (sysinfo(&s_info) != 0)
		return -1;

	uptime_seconds = s_info.uptime;

	time_t diff = now - uptime_seconds;

	ts = localtime(&diff);
	if (ts == NULL)
		return -1;

	/* must satisfy constraint (type yang:date-and-time):
		"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[\+\-]\d{2}:\d{2})"
		TODO: Add support for:
			- 2021-02-09T06:02:39.234+01:00
			- 2021-02-09T06:02:39.234Z
			- 2021-02-09T06:02:39+11:11
	*/

	strftime(boot_datetime, DATETIME_BUF_SIZE, "%FT%TZ", ts);

	return 0;
}

void collect_master_interfaces(struct nl_cache *cache, master_list_t *master_list, interface_data_t *interface_data)
{
	struct rtnl_link *tmp_link = NULL;
	struct rtnl_link *link = (struct rtnl_link *) nl_cache_get_first(cache);
	uint64_t tmp_len = 0;
	int32_t tmp_if_index = 0;

	while (link != NULL) {
		char *slave_name = rtnl_link_get_name(link);

		// higher-layer-if
		tmp_if_index = rtnl_link_get_master(link);
		while (tmp_if_index) {
			tmp_link = rtnl_link_get(cache, tmp_if_index);

			char *master_name = rtnl_link_get_name(tmp_link);

			tmp_len = strlen(master_name);

			interface_data->higher_layer_if.masters[interface_data->higher_layer_if.count] = xstrndup(master_name, tmp_len);

			interface_data->higher_layer_if.count++;

			tmp_if_index = rtnl_link_get_master(tmp_link);
		}

		if (interface_data->higher_layer_if.count > 0) {
			for (uint64_t i = 0; i < interface_data->higher_layer_if.count; i++) {
				char *master_name = interface_data->higher_layer_if.masters[i];

				tmp_len = strlen(slave_name);
				master_list->masters[master_list->count].slave_name = xstrndup(slave_name, tmp_len);

				tmp_len = strlen(master_name);
				master_list->masters[master_list->count].master_names[i] = xstrndup(master_name, tmp_len);
			}

			master_list->masters[master_list->count].count = interface_data->higher_layer_if.count;
			master_list->count++;
		}

		// continue to next link node
		link = (struct rtnl_link *) nl_cache_get_next((struct nl_object *) link);
	}
}

void collect_slave_interfaces(struct nl_cache *cache, slave_list_t *slave_list, master_list_t *master_list)
{
	struct rtnl_link *link = (struct rtnl_link *) nl_cache_get_first(cache);
	uint64_t tmp_len = 0;

	while (link != NULL) {
		// lower-layer-if
		char *if_name = rtnl_link_get_name(link);

		bool break_out = false;
		for (uint64_t i = 0; i < master_list->count; i++) {
			for (uint64_t j = 0; j < master_list->masters[i].count; j++) {
				if (strcmp(master_list->masters[i].slave_name, master_list->masters[i].master_names[j]) == 0) {
					continue;
				}

				if (strcmp(master_list->masters[i].master_names[j], if_name) == 0) {
					SRP_LOG_DBG("Slave of interface %s: %s", if_name, master_list->masters[i].slave_name);

					tmp_len = strlen(if_name);
					slave_list->slaves[slave_list->count].master_name = xstrndup(if_name, tmp_len);

					tmp_len = strlen(master_list->masters[i].slave_name);
					slave_list->slaves[slave_list->count].slave_names[i] = xstrndup(master_list->masters[i].slave_name, tmp_len);

					slave_list->slaves[slave_list->count].count++;

					break_out = true;
					break;
				}
			}
			if (break_out) {
				slave_list->count++;
				break;
			}
		}
		// continue to next link node
		link = (struct rtnl_link *) nl_cache_get_next((struct nl_object *) link);
	}
}

int update_interface_statistics(struct ly_ctx *ly_ctx, struct lyd_node **parent, interface_data_t *interface_data, char *interface_path)
{
	int error = SR_ERR_OK;
	char xpath_buffer[PATH_MAX] = {0};
	char tmp_buffer[PATH_MAX] = {0};
	// stats:
	// discontinuity-time
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/statistics/discontinuity-time", interface_path);
	if (error < 0) {
		goto error_out;
	}
	SRP_LOG_DBG("%s = %s", xpath_buffer, interface_data->statistics.discontinuity_time);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, interface_data->statistics.discontinuity_time, LYD_ANYDATA_STRING, 0);

	// in-octets
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/statistics/in-octets", interface_path);
	if (error < 0) {
		goto error_out;
	}
	snprintf(tmp_buffer, sizeof(tmp_buffer), "%lu", interface_data->statistics.in_octets);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);

	// in-unicast-pkts
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/statistics/in-unicast-pkts", interface_path);
	if (error < 0) {
		goto error_out;
	}
	snprintf(tmp_buffer, sizeof(tmp_buffer), "%lu", interface_data->statistics.in_unicast_pkts);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);

	// in-broadcast-pkts
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/statistics/in-broadcast-pkts", interface_path);
	if (error < 0) {
		goto error_out;
	}
	snprintf(tmp_buffer, sizeof(tmp_buffer), "%lu", interface_data->statistics.in_broadcast_pkts);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);

	// in-multicast-pkts
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/statistics/in-multicast-pkts", interface_path);
	if (error < 0) {
		goto error_out;
	}
	snprintf(tmp_buffer, sizeof(tmp_buffer), "%lu", interface_data->statistics.in_multicast_pkts);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);

	// in-discards
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/statistics/in-discards", interface_path);
	if (error < 0) {
		goto error_out;
	}
	snprintf(tmp_buffer, sizeof(tmp_buffer), "%u", interface_data->statistics.in_discards);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);

	// in-errors
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/statistics/in-errors", interface_path);
	if (error < 0) {
		goto error_out;
	}
	snprintf(tmp_buffer, sizeof(tmp_buffer), "%u", interface_data->statistics.in_errors);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);

	// in-unknown-protos
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/statistics/in-unknown-protos", interface_path);
	if (error < 0) {
		goto error_out;
	}
	snprintf(tmp_buffer, sizeof(tmp_buffer), "%u", interface_data->statistics.in_unknown_protos);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);

	// out-octets
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/statistics/out-octets", interface_path);
	if (error < 0) {
		goto error_out;
	}
	snprintf(tmp_buffer, sizeof(tmp_buffer), "%lu", interface_data->statistics.out_octets);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);

	// out-unicast-pkts
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/statistics/out-unicast-pkts", interface_path);
	if (error < 0) {
		goto error_out;
	}
	snprintf(tmp_buffer, sizeof(tmp_buffer), "%lu", interface_data->statistics.out_unicast_pkts);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);

	// out-broadcast-pkts
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/statistics/out-broadcast-pkts", interface_path);
	if (error < 0) {
		goto error_out;
	}
	snprintf(tmp_buffer, sizeof(tmp_buffer), "%lu", interface_data->statistics.out_broadcast_pkts);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);

	// out-multicast-pkts
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/statistics/out-multicast-pkts", interface_path);
	if (error < 0) {
		goto error_out;
	}
	snprintf(tmp_buffer, sizeof(tmp_buffer), "%lu", interface_data->statistics.out_multicast_pkts);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);

	// out-discards
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/statistics/out-discards", interface_path);
	if (error < 0) {
		goto error_out;
	}
	snprintf(tmp_buffer, sizeof(tmp_buffer), "%u", interface_data->statistics.out_discards);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);

	// out-errors
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/statistics/out-errors", interface_path);
	if (error < 0) {
		goto error_out;
	}
	snprintf(tmp_buffer, sizeof(tmp_buffer), "%u", interface_data->statistics.out_errors);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);

	error = SR_ERR_OK; // set error to OK, since it will be modified by snprintf
	goto out;

error_out:
	error = SR_ERR_CALLBACK_FAILED;
out:
	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

int collect_interface_statistics(interface_data_t *interface_data, struct rtnl_link *link, char *system_boot_time)
{
	int error = SR_ERR_OK;
	// stats:
	
	interface_data->statistics.discontinuity_time = system_boot_time;

	// gather interface statistics that are not accessable via netlink
	nic_stats_t nic_stats = {0};
	error = get_nic_stats(interface_data->name, &nic_stats);
	if (error != 0) {
		SRP_LOG_ERR("get_nic_stats error: %s", strerror(errno));
		//goto out;
	}

	// Rx
	interface_data->statistics.in_octets = rtnl_link_get_stat(link, RTNL_LINK_RX_BYTES);
	interface_data->statistics.in_broadcast_pkts = nic_stats.rx_broadcast;
	interface_data->statistics.in_multicast_pkts = rtnl_link_get_stat(link, RTNL_LINK_MULTICAST);
	interface_data->statistics.in_unicast_pkts = nic_stats.rx_packets - nic_stats.rx_broadcast - interface_data->statistics.in_multicast_pkts;

	interface_data->statistics.in_discards = (uint32_t) rtnl_link_get_stat(link, RTNL_LINK_RX_DROPPED);
	interface_data->statistics.in_errors = (uint32_t) rtnl_link_get_stat(link, RTNL_LINK_RX_ERRORS);
	interface_data->statistics.in_unknown_protos = (uint32_t) rtnl_link_get_stat(link, RTNL_LINK_IP6_INUNKNOWNPROTOS);

	// Tx
	interface_data->statistics.out_octets = rtnl_link_get_stat(link, RTNL_LINK_TX_BYTES);
	interface_data->statistics.out_broadcast_pkts = nic_stats.tx_broadcast;
	interface_data->statistics.out_multicast_pkts = nic_stats.tx_multicast;
	interface_data->statistics.out_unicast_pkts = nic_stats.tx_packets - nic_stats.tx_broadcast - nic_stats.tx_multicast;

	interface_data->statistics.out_discards = (uint32_t) rtnl_link_get_stat(link, RTNL_LINK_TX_DROPPED);
	interface_data->statistics.out_errors = (uint32_t) rtnl_link_get_stat(link, RTNL_LINK_TX_ERRORS);

out:
	return 0; //error; TODO: check error get_nic_stats error: Operation not supported (stats seem to work)
}

int collect_interface_general_info(interface_data_t* interface_data, struct rtnl_tc *tc, struct rtnl_link *link, link_data_list_t *link_data_list, if_state_list_t *if_state_changes, char *system_time)
{
	struct nl_addr *addr = NULL;
	if_state_t *tmp_ifs = NULL;
	const char *OPER_STRING_MAP[] = {
		[IF_OPER_UNKNOWN] = "unknown",
		[IF_OPER_NOTPRESENT] = "not-present",
		[IF_OPER_DOWN] = "down",
		[IF_OPER_LOWERLAYERDOWN] = "lower-layer-down",
		[IF_OPER_TESTING] = "testing",
		[IF_OPER_DORMANT] = "dormant",
		[IF_OPER_UP] = "up",
	};
	interface_data->name = rtnl_link_get_name(link);

	link_data_t *l = data_list_get_by_name(link_data_list, interface_data->name);
	interface_data->description = l->description;

	interface_data->type = rtnl_link_get_type(link);
	interface_data->enabled = rtnl_link_get_operstate(link) == IF_OPER_UP ? "enabled" : "disabled";
	// interface_data.link_up_down_trap_enable = ?
	// interface_data.admin_status = ?
	interface_data->oper_status = OPER_STRING_MAP[rtnl_link_get_operstate(link)];
	interface_data->if_index = rtnl_link_get_ifindex(link);

	// last-change field
	tmp_ifs = if_state_list_get_by_if_name(if_state_changes, interface_data->name);
	interface_data->last_change = (tmp_ifs->last_change != 0) ? localtime(&tmp_ifs->last_change) : NULL;

	// get_system_boot_time will change the struct tm which is held in interface_data.last_change if it's not NULL
	//char system_time[DATETIME_BUF_SIZE] = {0};
	if (interface_data->last_change != NULL) {
		// convert it to human readable format here
		strftime(system_time, sizeof system_time, "%FT%TZ", interface_data->last_change);
	}

	// mac address
	addr = rtnl_link_get_addr(link);
	interface_data->phys_address = xmalloc(sizeof(char) * (MAC_ADDR_MAX_LENGTH + 1));
	nl_addr2str(addr, interface_data->phys_address, MAC_ADDR_MAX_LENGTH);
	interface_data->phys_address[MAC_ADDR_MAX_LENGTH] = 0;

	interface_data->speed = rtnl_tc_get_stat(tc, RTNL_TC_RATE_BPS);

}

int update_interface_general_info(struct ly_ctx *ly_ctx, struct lyd_node **parent, interface_data_t* interface_data, char *interface_path_buffer, master_list_t *master_list, slave_list_t *slave_list, char *system_time, char *system_boot_time)
{
	int error = SR_ERR_OK;
	char tmp_buffer[PATH_MAX] = {0};
	char xpath_buffer[PATH_MAX] = {0};

	// name
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/name", interface_path_buffer);
	if (error < 0) {
		goto error_out;
	}
	SRP_LOG_DBG("%s = %s", xpath_buffer, interface_data->name);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, interface_data->name, LYD_ANYDATA_STRING, 0);

	// description
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/description", interface_path_buffer);
	if (error < 0) {
		goto error_out;
	}
	SRP_LOG_DBG("%s = %s", xpath_buffer, interface_data->description);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, interface_data->description, LYD_ANYDATA_STRING, 0);

	// type
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/type", interface_path_buffer);
	if (error < 0) {
		goto error_out;
	}
	SRP_LOG_DBG("%s = %s", xpath_buffer, interface_data->type);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, interface_data->type, LYD_ANYDATA_STRING, 0);

	// oper-status
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/oper-status", interface_path_buffer);
	if (error < 0) {
		goto error_out;
	}
	SRP_LOG_DBG("%s = %s", xpath_buffer, interface_data->oper_status);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, (char *) interface_data->oper_status, LYD_ANYDATA_STRING, 0);

	// last-change -> only if changed at one point
	if (interface_data->last_change != NULL) {
		error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/last-change", interface_path_buffer);
		if (error < 0) {
			goto error_out;
		}
		SRP_LOG_DBG("%s = %s", xpath_buffer, interface_data->type);
		lyd_new_path(*parent, ly_ctx, xpath_buffer, system_time, LYD_ANYDATA_STRING, 0);
	} else {
		// default value of last-change should be system boot time
		error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/last-change", interface_path_buffer);
		if (error < 0) {
			goto error_out;
		}
		SRP_LOG_DBG("%s = %s", xpath_buffer, interface_data->type);
		lyd_new_path(*parent, ly_ctx, xpath_buffer, system_boot_time, LYD_ANYDATA_STRING, 0);
	}

	// if-index
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/if-index", interface_path_buffer);
	if (error < 0) {
		goto error_out;
	}
	SRP_LOG_DBG("%s = %d", xpath_buffer, interface_data->if_index);
	snprintf(tmp_buffer, sizeof(tmp_buffer), "%u", interface_data->if_index);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);

	// phys-address
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/phys-address", interface_path_buffer);
	if (error < 0) {
		goto error_out;
	}
	SRP_LOG_DBG("%s = %s", xpath_buffer, interface_data->phys_address);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, interface_data->phys_address, LYD_ANYDATA_STRING, 0);

	// speed
	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/speed", interface_path_buffer);
	if (error < 0) {
		goto error_out;
	}
	SRP_LOG_DBG("%s = %s", xpath_buffer, interface_data->speed);
	snprintf(tmp_buffer, sizeof(tmp_buffer), "%lu", interface_data->speed);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);

	// higher-layer-if
	for (uint64_t i = 0; i < master_list->count; i++) {
		if (strcmp(interface_data->name, master_list->masters[i].slave_name) == 0) {
			for (uint64_t j = 0; j < master_list->masters[i].count; j++) {

				error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/higher-layer-if", interface_path_buffer);
				if (error < 0) {
					goto error_out;
				}

				SRP_LOG_DBG("%s += %s", xpath_buffer, master_list->masters[i].master_names[j]);
				lyd_new_path(*parent, ly_ctx, xpath_buffer, master_list->masters[i].master_names[j], LYD_ANYDATA_STRING, 0);

				FREE_SAFE(interface_data->higher_layer_if.masters[i]);
			}
		}
	}

	// lower-layer-if
	for (uint64_t i = 0; i < slave_list->count; i++) {
		if (strcmp(interface_data->name, slave_list->slaves[i].master_name) == 0) {
			for (uint64_t j = 0; j < slave_list->slaves[i].count; j++) {

				error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/lower-layer-if", interface_path_buffer);
				if (error < 0) {
					goto error_out;
				}

				SRP_LOG_DBG("%s += %s", xpath_buffer, slave_list->slaves[i].slave_names[j]);
				lyd_new_path(*parent, ly_ctx, xpath_buffer, slave_list->slaves[i].slave_names[j], LYD_ANYDATA_STRING, 0);
			}
		}
	}

	error = SR_ERR_OK; // set error to OK, since it will be modified by snprintf
	goto out;

error_out:
	error = SR_ERR_CALLBACK_FAILED;
out:
	return error;
}

int update_link_ipv4_info(struct ly_ctx *ly_ctx, struct lyd_node **parent, link_data_t *link_data, unsigned int mtu, char *interface_path_buffer)
{
	int error = SR_ERR_OK;
	char tmp_buffer[PATH_MAX] = {0};
	char xpath_buffer[PATH_MAX] = {0};
	// ietf-ip
	// mtu
	//mtu = rtnl_link_get_mtu(link);
	
	// list of ipv4 addresses

	// enabled
	// TODO

	// forwarding
	uint8_t ipv4_forwarding = link_data->ipv4.forwarding;

	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/ietf-ip:ipv4/forwarding", interface_path_buffer);
	if (error < 0) {
		goto error_out;
	}

	SRP_LOG_DBG("%s = %d", xpath_buffer, ipv4_forwarding);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, ipv4_forwarding == 0 ? "false" : "true", LYD_ANYDATA_STRING, 0);

	uint32_t ipv4_addr_count = link_data->ipv4.addr_list.count;

	for (uint32_t j = 0; j < ipv4_addr_count; j++) {
		if (link_data->ipv4.addr_list.addr[j].ip != NULL) { // in case we deleted an ip address it will be NULL
			char *ip_addr = link_data->ipv4.addr_list.addr[j].ip;

			if (mtu > 0) {
				error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/ietf-ip:ipv4/mtu", interface_path_buffer);
				if (error < 0) {
					goto error_out;
				}
				snprintf(tmp_buffer, sizeof(tmp_buffer), "%u", mtu);
				SRP_LOG_DBG("%s = %s", xpath_buffer, tmp_buffer);
				lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);
			}

			error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/ietf-ip:ipv4/address[ip='%s']/ip", interface_path_buffer, ip_addr);
			if (error < 0) {
				goto error_out;
			}
			// ip
			SRP_LOG_DBG("%s = %s", xpath_buffer, link_data->ipv4.addr_list.addr[j].ip);
			lyd_new_path(*parent, ly_ctx, xpath_buffer, link_data->ipv4.addr_list.addr[j].ip, LYD_ANYDATA_STRING, 0);

			// subnet
			snprintf(tmp_buffer, sizeof(tmp_buffer), "%u", link_data->ipv4.addr_list.addr[j].subnet);

			error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/ietf-ip:ipv4/address[ip='%s']/prefix-length", interface_path_buffer, ip_addr);
			if (error < 0) {
				goto error_out;
			}

			SRP_LOG_DBG("%s = %s", xpath_buffer, tmp_buffer);
			lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);
		}
	}

	// neighbors
	uint32_t ipv4_neigh_count = link_data->ipv4.nbor_list.count;

	for (uint32_t j = 0; j < ipv4_neigh_count; j++) {
		if (link_data->ipv4.nbor_list.nbor[j].ip != NULL) { // in case we deleted an ip address it will be NULL
			char *ip_addr = link_data->ipv4.nbor_list.nbor[j].ip;

			error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/ietf-ip:ipv4/neighbor[ip='%s']/ip", interface_path_buffer, ip_addr);
			if (error < 0) {
				goto error_out;
			}
			// ip
			SRP_LOG_DBG("%s = %s", xpath_buffer, link_data->ipv4.nbor_list.nbor[j].ip);
			lyd_new_path(*parent, ly_ctx, xpath_buffer, link_data->ipv4.nbor_list.nbor[j].ip, LYD_ANYDATA_STRING, 0);

			// link-layer-address
			error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/ietf-ip:ipv4/neighbor[ip='%s']/link-layer-address", interface_path_buffer, ip_addr);
			if (error < 0) {
				goto error_out;
			}

			SRP_LOG_DBG("%s = %s", xpath_buffer, link_data->ipv4.nbor_list.nbor[j].phys_addr);
			lyd_new_path(*parent, ly_ctx, xpath_buffer, link_data->ipv4.nbor_list.nbor[j].phys_addr, LYD_ANYDATA_STRING, 0);
		}
	}
	error = SR_ERR_OK; // set error to OK, since it will be modified by snprintf
	goto out;

error_out:
	error = SR_ERR_CALLBACK_FAILED;
out:
	return error;
}

int update_link_ipv6_info(struct ly_ctx *ly_ctx, struct lyd_node **parent, link_data_t *link_data, unsigned int mtu, char *interface_path_buffer)
{
	int error = SR_ERR_OK;
	char tmp_buffer[PATH_MAX] = {0};
	char xpath_buffer[PATH_MAX] = {0};
	// list of ipv6 addresses

	// enabled
	uint8_t ipv6_enabled = link_data->ipv6.ip_data.enabled;

	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/ietf-ip:ipv6/enabled", interface_path_buffer);
	if (error < 0) {
		goto error_out;
	}

	SRP_LOG_DBG("%s = %d", xpath_buffer, ipv6_enabled);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, ipv6_enabled == 0 ? "false" : "true", LYD_ANYDATA_STRING, 0);

	// forwarding
	uint8_t ipv6_forwarding = link_data->ipv6.ip_data.forwarding;

	error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/ietf-ip:ipv6/forwarding", interface_path_buffer);
	if (error < 0) {
		goto error_out;
	}

	SRP_LOG_DBG("%s = %d", xpath_buffer, ipv6_forwarding);
	lyd_new_path(*parent, ly_ctx, xpath_buffer, ipv6_forwarding == 0 ? "false" : "true", LYD_ANYDATA_STRING, 0);

	uint32_t ipv6_addr_count = link_data->ipv6.ip_data.addr_list.count;

	for (uint32_t j = 0; j < ipv6_addr_count; j++) {
		if (link_data->ipv6.ip_data.addr_list.addr[j].ip != NULL) { // in case we deleted an ip address it will be NULL
			char *ip_addr = link_data->ipv6.ip_data.addr_list.addr[j].ip;

			// mtu
			if (mtu > 0 && ip_addr != NULL) {
				error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/ietf-ip:ipv6/mtu", interface_path_buffer);
				if (error < 0) {
					goto error_out;
				}
				snprintf(tmp_buffer, sizeof(tmp_buffer), "%u", mtu);
				SRP_LOG_DBG("%s = %s", xpath_buffer, tmp_buffer);
				lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);
			}

			error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/ietf-ip:ipv6/address[ip='%s']/ip", interface_path_buffer, ip_addr);
			if (error < 0) {
				goto error_out;
			}
			// ip
			SRP_LOG_DBG("%s = %s", xpath_buffer, link_data->ipv6.ip_data.addr_list.addr[j].ip);
			lyd_new_path(*parent, ly_ctx, xpath_buffer, link_data->ipv6.ip_data.addr_list.addr[j].ip, LYD_ANYDATA_STRING, 0);

			// subnet
			snprintf(tmp_buffer, sizeof(tmp_buffer), "%u", link_data->ipv6.ip_data.addr_list.addr[j].subnet);

			error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/ietf-ip:ipv6/address[ip='%s']/prefix-length", interface_path_buffer, ip_addr);
			if (error < 0) {
				goto error_out;
			}

			SRP_LOG_DBG("%s = %s", xpath_buffer, tmp_buffer);
			lyd_new_path(*parent, ly_ctx, xpath_buffer, tmp_buffer, LYD_ANYDATA_STRING, 0);
		}
	}

	// neighbors
	uint32_t ipv6_neigh_count = link_data->ipv6.ip_data.nbor_list.count;

	for (uint32_t j = 0; j < ipv6_neigh_count; j++) {
		if (link_data->ipv6.ip_data.nbor_list.nbor[j].ip != NULL) { // in case we deleted an ip address it will be NULL
			char *ip_addr = link_data->ipv6.ip_data.nbor_list.nbor[j].ip;

			error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/ietf-ip:ipv6/neighbor[ip='%s']/ip", interface_path_buffer, ip_addr);
			if (error < 0) {
				goto error_out;
			}
			// ip
			SRP_LOG_DBG("%s = %s", xpath_buffer, link_data->ipv6.ip_data.nbor_list.nbor[j].ip);
			lyd_new_path(*parent, ly_ctx, xpath_buffer, link_data->ipv6.ip_data.nbor_list.nbor[j].ip, LYD_ANYDATA_STRING, 0);

			// link-layer-address
			error = snprintf(xpath_buffer, sizeof(xpath_buffer), "%s/ietf-ip:ipv6/neighbor[ip='%s']/link-layer-address", interface_path_buffer, ip_addr);
			if (error < 0) {
				goto error_out;
			}

			SRP_LOG_DBG("%s = %s", xpath_buffer, link_data->ipv6.ip_data.nbor_list.nbor[j].phys_addr);
			lyd_new_path(*parent, ly_ctx, xpath_buffer, link_data->ipv6.ip_data.nbor_list.nbor[j].phys_addr, LYD_ANYDATA_STRING, 0);
		}
	}

	error = SR_ERR_OK; // set error to OK, since it will be modified by snprintf
	goto out;

error_out:
	error = SR_ERR_CALLBACK_FAILED;
out:
	return error;
}

int update_operational_state(struct ly_ctx *ly_ctx, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data, if_state_list_t if_state_changes, link_data_list_t link_data_list)
{
	int error = SR_ERR_OK;
	struct nl_sock *socket = NULL;
	struct nl_cache *cache = NULL;
	struct rtnl_link *link = NULL;
	struct rtnl_tc *tc = NULL;
	struct rtnl_qdisc *qdisc = NULL;

	char interface_path_buffer[PATH_MAX] = {0};

	//if_state_t *tmp_ifs = NULL;

	unsigned int mtu = 0;

	interface_data_t interface_data = {0};
	master_list_t master_list = {0};
	slave_list_t slave_list = {0};

	socket = nl_socket_alloc();
	if (socket == NULL) {
		SRP_LOG_ERRMSG("nl_socket_alloc error: invalid socket");
		goto error_out;
	}

	if ((error = nl_connect(socket, NETLINK_ROUTE)) != 0) {
		SRP_LOG_ERR("nl_connect error (%d): %s", error, nl_geterror(error));
		goto error_out;
	}

	error = rtnl_link_alloc_cache(socket, AF_UNSPEC, &cache);
	if (error != 0) {
		SRP_LOG_ERR("rtnl_link_alloc_cache error (%d): %s", error, nl_geterror(error));
		goto error_out;
	}

	collect_master_interfaces(cache, &master_list, &interface_data);
	collect_slave_interfaces(cache, &slave_list, &master_list);

	link = (struct rtnl_link *) nl_cache_get_first(cache);
	qdisc = rtnl_qdisc_alloc();

	while (link != NULL) {
		// get tc and set the link
		tc = TC_CAST(qdisc);
		rtnl_tc_set_link(tc, link);

		// get_system_boot_time will change the struct tm which is held in interface_data.last_change if it's not NULL
		char system_time[DATETIME_BUF_SIZE] = {0};
		//if (interface_data.last_change != NULL) {
		//	// convert it to human readable format here
		//	strftime(system_time, sizeof system_time, "%FT%TZ", interface_data.last_change);
		//}

		snprintf(interface_path_buffer, sizeof(interface_path_buffer) / sizeof(char), "%s[name=\"%s\"]", INTERFACE_LIST_YANG_PATH, rtnl_link_get_name(link));

		char system_boot_time[DATETIME_BUF_SIZE] = {0};
		error = get_system_boot_time(system_boot_time);
		if (error != 0) {
			SRP_LOG_ERR("get_system_boot_time error: %s", strerror(errno));
			goto out;
		}

		error = collect_interface_general_info(&interface_data, tc, link, &link_data_list, &if_state_changes, system_time);
		if (error) {
			SRP_LOG_ERR("collect_interface_general_info error: %s", strerror(errno));
			goto error_out;
		}
		error = update_interface_general_info(ly_ctx, parent, &interface_data, interface_path_buffer, &master_list, &slave_list, system_time, system_boot_time);
		if (error) {
			SRP_LOG_ERR("update_interface_general_info error: %s", strerror(errno));
			goto error_out;
		}

		error = collect_interface_statistics(&interface_data, link, system_boot_time);
		if (error) {
			SRP_LOG_ERR("collect_interface_statistics error: %s", strerror(errno));
			goto error_out;
		}

		// ietf-ip
		// mtu
		mtu = rtnl_link_get_mtu(link);

		link_data_t *link_data = NULL;
		for (uint32_t i = 0; i < link_data_list.count; i++) {
			if (link_data_list.links[i].name != NULL) { // in case we deleted a link it will be NULL
				if (strcmp(link_data_list.links[i].name, interface_data.name) == 0) {
					link_data = &link_data_list.links[i];
				}
			}
		}
		error = update_link_ipv4_info(ly_ctx, parent, link_data, mtu, interface_path_buffer);
		if (error) {
			SRP_LOG_ERR("update_interface_ipv4_info error: %s", strerror(errno));
			goto error_out;
		}
		error = update_link_ipv6_info(ly_ctx, parent, link_data, mtu, interface_path_buffer);
		if (error) {
			SRP_LOG_ERR("update_interface_ipv6_info error: %s", strerror(errno));
			goto error_out;
		}

		error = update_interface_statistics(ly_ctx, parent, &interface_data, interface_path_buffer);
		if (error) {
			goto error_out;
		}

		// free all allocated data
		FREE_SAFE(interface_data.phys_address);

		// continue to next link node
		link = (struct rtnl_link *) nl_cache_get_next((struct nl_object *) link);
	}

	rtnl_qdisc_put(qdisc);
	nl_cache_free(cache);

	error = SR_ERR_OK; // set error to OK, since it will be modified by snprintf

	goto out;

error_out:
	error = SR_ERR_CALLBACK_FAILED;

out:
	for (uint64_t i = 0; i < master_list.count; i++) {
		for (uint64_t j = 0; j < master_list.masters[i].count; j++) {
			FREE_SAFE(master_list.masters[i].master_names[j]);
		}
		FREE_SAFE(master_list.masters[i].slave_name);
	}

	for (uint64_t i = 0; i < slave_list.count; i++) {
		for (uint64_t j = 0; j < slave_list.slaves[i].count; j++) {
			FREE_SAFE(slave_list.slaves[i].slave_names[j]);
		}
		FREE_SAFE(slave_list.slaves[i].master_name);
	}

	nl_socket_free(socket);
	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}