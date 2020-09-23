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
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
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

/* Defaults. All overridable from command line. */
#define MQTT_HOST	"mqtt-host"
#define MQTT_PORT	8883
#define MQTT_TOPIC	"location/by-mac"
#define LOCATION	"home"
#define CONFIG_FILE	"/etc/mqtt-arp.conf"

/* How often (in seconds) to report that we see a device */
#define REPORT_INTERVAL	(2 * 60)
/* How long to wait without seeing a device before reporting it's gone */
#define EXPIRY_TIME	(10 * 60)
/* Maximum number of MAC addresses to watch for */
#define MAX_MACS	8

struct mac_entry {
	bool valid;
	uint8_t mac[6];
	time_t last_seen;
	time_t last_reported;
};

struct ma_config {
	char *mqtt_host;
	int mqtt_port;
	char *mqtt_username;
	char *mqtt_password;
	char *mqtt_topic;
	char *location;
	char *capath;
	struct mac_entry macs[MAX_MACS];
};

bool debug = false;
bool want_shutdown = false;

void shutdown_request(int signal)
{
	want_shutdown = true;
}

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

int mqtt_mac_presence(struct ma_config *config, struct mosquitto *mosq,
		uint8_t *mac, bool present)
{
	char topic[128];
	int ret;
	time_t t;
	int i;

	t = time(NULL);

	i = 0;
	while (i < MAX_MACS && config->macs[i].valid) {
		if (mac_compare(mac, config->macs[i].mac))
			break;
		i++;
	}

	if (i >= MAX_MACS || !config->macs[i].valid)
		return 0;

	config->macs[i].last_seen = t;
	/* Report no more often than every 2 minutes */
	if (present && config->macs[i].last_reported + REPORT_INTERVAL > t)
		return 0;

	config->macs[i].last_reported = t;

	snprintf(topic, sizeof(topic),
		"%s/%02X:%02X:%02X:%02X:%02X:%02X",
		config->mqtt_topic,
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	if (debug)
		printf("Publishing to %s\n", topic);

	if (present)
		ret = mosquitto_publish(mosq, NULL, topic,
				strlen(config->location), config->location,
				0, 0);
	else
		ret = mosquitto_publish(mosq, NULL, topic,
				strlen("unknown"), "unknown", 0, 0);

	return ret;
}

void prune_macs(struct ma_config *config, struct mosquitto *mosq)
{
	time_t t;
	int i;

	t = time(NULL);

	i = 0;
	while (i < MAX_MACS && config->macs[i].valid) {
		/* Expire if we haven't seen MAC in EXPIRY_TIME */
		if (config->macs[i].last_seen &&
				config->macs[i].last_seen + EXPIRY_TIME < t) {
			mqtt_mac_presence(config, mosq,
					config->macs[i].mac, false);
			config->macs[i].last_seen = 0;
			config->macs[i].last_reported = 0;
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

void main_loop(struct ma_config *config, struct mosquitto *mosq, int sock)
{
	uint8_t buf[4096];
	uint8_t *data;
	struct nlmsghdr *hdr;
	struct ndmsg *nd;
	struct nlattr *attr;
	ssize_t received;
	time_t t;

	hdr = (struct nlmsghdr *) buf;
	nd = (struct ndmsg *) (hdr + 1);
	while (!want_shutdown) {
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
			while (((uint8_t *) attr - buf) < hdr->nlmsg_len) {
				data = (((uint8_t *) attr) + NLA_HDRLEN);
				if (attr->nla_type == NDA_LLADDR &&
					nd->ndm_state == NUD_REACHABLE) {
					mqtt_mac_presence(config, mosq,
							data, true);
				}
				attr = (struct nlattr *) (((uint8_t *) attr) +
						NLA_ALIGN(attr->nla_len));
			}
			break;
		case RTM_DELNEIGH:
		case RTM_GETNEIGH:
			break;
		default:
			printf("Unknown message type: %d\n", hdr->nlmsg_type);
		}

		prune_macs(config, mosq);
	}

}

struct mosquitto *mqtt_init(struct ma_config *config)
{
	struct mosquitto *mosq;
	int ret;

	mosquitto_lib_init();
	mosq = mosquitto_new("mqtt-arp", true, NULL);
	if (!mosq) {
		printf("Couldn't allocate mosquitto structure\n");
		exit(EXIT_FAILURE);
	}

	mosquitto_log_callback_set(mosq, mosq_log_callback);

	/* DTRT if username is NULL */
	mosquitto_username_pw_set(mosq,
			config->mqtt_username,
			config->mqtt_password);
	if (config->capath)
		mosquitto_tls_set(mosq, config->capath,
				NULL, NULL, NULL, NULL);

	ret = mosquitto_connect(mosq, config->mqtt_host,
			config->mqtt_port, 60);
	if (ret) {
		printf("Unable to connect to MQTT server.\n");
		exit(EXIT_FAILURE);
	}

	ret = mosquitto_loop_start(mosq);
	if (ret) {
		printf("Unable to start Mosquitto loop.\n");
		exit(EXIT_FAILURE);
	}

	return mosq;
}

int netlink_init(void)
{
	int sock;
	struct sockaddr_nl group_addr;

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

	return sock;
}

int read_config(char *file, struct ma_config *config, int *macs)
{
	FILE *f;
	char line[256];
	int i;

	f = fopen(file, "r");
	if (f == NULL)
		return errno;

#define INT_OPTION(opt, var) \
	if (strncmp(line, opt " ", sizeof(opt)) == 0) { \
		var = atoi(&line[sizeof(opt)]);          \
	}
#define STRING_OPTION(opt, var) \
	if (strncmp(line, opt " ", sizeof(opt)) == 0) { \
		var = strdup(&line[sizeof(opt)]);       \
	}

	while (fgets(line, sizeof(line), f) != NULL) {
		for (i = strlen(line) - 1; i >= 0 && isspace(line[i]); i--)
			line[i] = '\0';
		if (line[0] == '\0' || line[0] == '#')
			continue;

		if (strncmp(line, "mac ", 4) == 0) {
			if (*macs >= MAX_MACS) {
				printf("Can only accept %d MAC addresses to"
					" watch for.\n", MAX_MACS);
				exit(EXIT_FAILURE);
			}
			sscanf(&line[4],
				"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
				&config->macs[*macs].mac[0],
				&config->macs[*macs].mac[1],
				&config->macs[*macs].mac[2],
				&config->macs[*macs].mac[3],
				&config->macs[*macs].mac[4],
				&config->macs[*macs].mac[5]);
			config->macs[*macs].valid = true;
			(*macs)++;
		} else
		STRING_OPTION("mqtt_host", config->mqtt_host) else
		INT_OPTION("mqtt_port", config->mqtt_port) else
		STRING_OPTION("mqtt_user", config->mqtt_username) else
		STRING_OPTION("mqtt_pass", config->mqtt_password) else
		STRING_OPTION("mqtt_topic", config->mqtt_topic) else
		STRING_OPTION("location", config->location) else
		STRING_OPTION("capath", config->capath)
	}
	fclose(f);

	return 0;
}

struct option long_options[] = {
	{ "capath", required_argument, 0, 'c' },
	{ "host", required_argument, 0, 'h' },
	{ "location", required_argument, 0, 'l' },
	{ "mac", required_argument, 0, 'm' },
	{ "password", required_argument, 0, 'P' },
	{ "port", required_argument, 0, 'p' },
	{ "topic", required_argument, 0, 't' },
	{ "username", required_argument, 0, 'u' },
	{ "verbose", no_argument, 0, 'v' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	int sock;
	struct mosquitto *mosq;
	struct ma_config config;
	int option_index = 0;
	int macs = 0;
	int c;

	bzero(&config, sizeof(config));
	config.mqtt_port = MQTT_PORT;

	/* Read config before parsing command line */
	read_config(CONFIG_FILE, &config, &macs);

	while (1) {
		c = getopt_long(argc, argv, "c:h:l:m:p:P:t:u:v",
				long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'c':
			config.capath = optarg;
			break;
		case 'h':
			config.mqtt_host = optarg;
			break;
		case 'l':
			config.location = optarg;
			break;
		case 'm':
			if (macs >= MAX_MACS) {
				printf("Can only accept %d MAC addresses to"
					" watch for.\n", MAX_MACS);
				exit(EXIT_FAILURE);
			}
			sscanf(optarg,
				"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
				&config.macs[macs].mac[0],
				&config.macs[macs].mac[1],
				&config.macs[macs].mac[2],
				&config.macs[macs].mac[3],
				&config.macs[macs].mac[4],
				&config.macs[macs].mac[5]);
			config.macs[macs].valid = true;
			macs++;
			break;
		case 'p':
			config.mqtt_port = atoi(optarg);
			break;
		case 'P':
			config.mqtt_password = optarg;
			break;
		case 't':
			config.mqtt_topic = optarg;
			break;
		case 'u':
			config.mqtt_username = optarg;
			break;
		case 'v':
			debug = true;
			break;
		default:
			printf("Unrecognized option: %c\n", c);
			exit(EXIT_FAILURE);
		}
	}

	if (!config.mqtt_host)
		config.mqtt_host = MQTT_HOST;
	if (!config.mqtt_topic)
		config.mqtt_topic = MQTT_TOPIC;
	if (!config.location)
		config.location = LOCATION;

	signal(SIGTERM, shutdown_request);

	sock = netlink_init();
	mosq = mqtt_init(&config);

	main_loop(&config, mosq, sock);

	mosquitto_disconnect(mosq);
	mosquitto_loop_stop(mosq, true);
	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	close(sock);
}
