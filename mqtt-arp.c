/*
 * mqtt-arp.c - Watch the Linux ARP table to report device presence via MQTT
 *
 * Copyright 2018 Jonathan McDowell <noodles@earth.li>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <mosquitto.h>

#define MQTT_HOST "mqtt-host"
#define MQTT_PORT 8883
#define MQTT_USERNAME "username"
#define MQTT_PASSWORD "password"
#define MQTT_TOPIC "location/by-mac"
#define LOCATION "home"

struct mac_entry {
	bool valid;
	uint8_t mac[6];
	time_t last_seen;
	time_t last_reported;
};

bool debug = false;

struct mac_entry macs[] = {
	{ true, { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, 0, 0 },
	{ true, { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, 0, 0 },
	{ false }
};

bool mac_compare(uint8_t *a, uint8_t *b)
{
	int i;

	for (i = 0; i < 6; i++)
		if (a[i] != b[i])
			return false;

	if (debug)
		printf("Matched: %02x:%02x:%02x:%02x:%02x:%02x\n",
				a[0], a[1], a[2],
				a[3], a[4], a[5]);

	return true;
}

int mqtt_mac_presence(struct mosquitto *mosq, uint8_t *mac, bool present)
{
	char topic[128];
	int ret;
	time_t t;
	int i;

	t = time(NULL);

	i = 0;
	while (macs[i].valid) {
		if (mac_compare(mac, macs[i].mac))
			break;
		i++;
	}

	if (!macs[i].valid)
		return 0;

	macs[i].last_seen = t;
	/* Report no more often than every 2 minutes */
	if (present && macs[i].last_reported + 60 * 2 > t)
		return 0;

	macs[i].last_reported = t;

	snprintf(topic, sizeof(topic),
		"%s/%02X:%02X:%02X:%02X:%02X:%02X",
		MQTT_TOPIC,
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	if (debug)
		printf("Publishing to %s\n", topic);

	if (present)
		ret = mosquitto_publish(mosq, NULL, topic,
				strlen(LOCATION), LOCATION, 0, 0);
	else
		ret = mosquitto_publish(mosq, NULL, topic,
				strlen("unknown"), "unknown", 0, 0);

	return ret;
}

void prune_macs(struct mosquitto *mosq)
{
	time_t t;
	int i;

	t = time(NULL);

	i = 0;
	while (macs[i].valid) {
		/* Expire after 5 minutes */
		if (macs[i].last_seen && macs[i].last_seen + 60 * 5 < t) {
			mqtt_mac_presence(mosq, macs[i].mac, false);
			macs[i].last_seen = 0;
			macs[i].last_reported = 0;
		}
		i++;
	}
}

void mosq_log_callback(struct mosquitto *mosq, void *userdata, int level,
		const char *str)
{
	if (debug)
		printf("%i:%s\n", level, str);
}

int main(int argc, char *argv[])
{
	int ret, sock;
	struct sockaddr_nl group_addr;
	struct nlmsghdr *hdr;
	uint8_t buf[4096];
	ssize_t received;
	struct ndmsg *nd;
	struct nlattr *attr;
	uint8_t *data;
	time_t t;
	struct mosquitto *mosq;

	bzero(&group_addr, sizeof(group_addr));
	group_addr.nl_family = AF_NETLINK;
	group_addr.nl_pid = getpid();
	group_addr.nl_groups = RTMGRP_NEIGH;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		perror("Couldn't open netlink socket");
		exit(EXIT_FAILURE);
	}

	if (bind(sock, (struct sockaddr *) &group_addr,
			sizeof(group_addr)) < 0) {
		perror("Failed to bind to netlink socket");
		exit(EXIT_FAILURE);
	}

	mosquitto_lib_init();
	mosq = mosquitto_new("mqtt-arp", true, NULL);
	if (!mosq) {
		printf("Couldn't allocate mosquitto structure\n");
		exit(EXIT_FAILURE);
	}

	mosquitto_log_callback_set(mosq, mosq_log_callback);

	mosquitto_username_pw_set(mosq, MQTT_USERNAME, MQTT_PASSWORD);
	mosquitto_tls_set(mosq, "/etc/ssl/certs/ca-certificates.crt",
			NULL, NULL, NULL, NULL);

	ret = mosquitto_connect(mosq, MQTT_HOST, MQTT_PORT, 60);
	if (ret) {
		printf("Unable to connect to MQTT server.\n");
		exit(EXIT_FAILURE);
	}

	ret = mosquitto_loop_start(mosq);
	if (ret) {
		printf("Unable to start Mosquitto loop.\n");
		exit(EXIT_FAILURE);
	}

	hdr = (struct nlmsghdr *) buf;
	nd = (struct ndmsg *) (hdr + 1);
	while (1) {
		received = recv(sock, buf, sizeof(buf), 0);
		if (debug) {
			t = time(NULL);
			printf("%sReceived %zd bytes:\n", ctime(&t), received);
			printf("  Len: %d, type: %d, flags: %x, "
				"seq: %d, pid: %d\n",
				hdr->nlmsg_len, hdr->nlmsg_type,
				hdr->nlmsg_flags, hdr->nlmsg_seq,
				hdr->nlmsg_pid);
		}
		switch (hdr->nlmsg_type) {
		case RTM_NEWNEIGH:
			if (debug) {
				printf("  Family: %d, interface: %d, "
					"state: %x, flags: %x, type: %x\n",
					nd->ndm_family, /* AF_INET etc */
					nd->ndm_ifindex,
					nd->ndm_state, /* NUD_REACHABLE etc */
					nd->ndm_flags,
					nd->ndm_type);
			}
			attr = (struct nlattr *) (nd + 1);
			while (attr->nla_len > 0) {
				data = (((uint8_t *) attr) + 4);
				if (attr->nla_type == NDA_LLADDR &&
					nd->ndm_state == NUD_REACHABLE) {
					mqtt_mac_presence(mosq, data, true);
				}
				attr = (struct nlattr *)
					(((uint8_t *) attr) + attr->nla_len);
			}
			break;
		case RTM_DELNEIGH:
		case RTM_GETNEIGH:
		default:
			printf("Unknown message type: %d\n", hdr->nlmsg_type);
		}

		prune_macs(mosq);
	}
}
