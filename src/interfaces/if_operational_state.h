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

#ifndef IF_OPERATIONAL_STATE_H_ONCE
#define IF_OPERATIONAL_STATE_H_ONCE

#include "if_state.h"
#include "link_data.h"

typedef struct {
	char *name;
	char *description;
	char *type;
	char *enabled;
	char *link_up_down_trap_enable;
	char *admin_status;
	const char *oper_status;
	struct tm *last_change;
	int32_t if_index;
	char *phys_address;
	struct {
		char *masters[LD_MAX_LINKS];
		uint32_t count;
	} higher_layer_if;
	uint64_t speed;
	struct {
		char *discontinuity_time;
		uint64_t in_octets;
		uint64_t in_unicast_pkts;
		uint64_t in_broadcast_pkts;
		uint64_t in_multicast_pkts;
		uint32_t in_discards;
		uint32_t in_errors;
		uint32_t in_unknown_protos;
		uint64_t out_octets;
		uint64_t out_unicast_pkts;
		uint64_t out_broadcast_pkts;
		uint64_t out_multicast_pkts;
		uint32_t out_discards;
		uint32_t out_errors;
	} statistics;
} interface_data_t;

typedef struct {
	char *slave_name;
	char *master_names[LD_MAX_LINKS];
	uint32_t count;
} master_t;

typedef struct {
	master_t masters[LD_MAX_LINKS];
	uint32_t count;
} master_list_t;


typedef struct {
	char *master_name;
	char *slave_names[LD_MAX_LINKS];
	uint32_t count;
} slave_t;

typedef struct {
	slave_t slaves[LD_MAX_LINKS];
	uint32_t count;
} slave_list_t;

//int interfaces_state_data_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);
int update_operational_state(struct ly_ctx *ly_ctx, const char *module_name, const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data, if_state_list_t if_state_changes, link_data_list_t link_data_list);

#endif /* IF_OPERATIONAL_STATE_H_ONCE */

