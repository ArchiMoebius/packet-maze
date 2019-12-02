/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../headers/common_params.h"
#include "../headers/common_user_bpf_xdp.h"
#include "../headers/common_libbpf.h"
#include "../headers/xdp_level_user.h"

const struct bpf_map_info ipv4hashmap = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(__u32),					/* IPv4 Address    */
	.value_size = sizeof(struct userLevelInfo), /* Level struct    */
	.max_entries = 1000,						/* enough :-?      */
	.map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_info info = { 0 };

const char *pin_basedir =  "/sys/fs/bpf/lo";

int main() {
  int fd = open_bpf_map_file(pin_basedir, "ipv4hashmap", &info);

  if (fd < 0) {
    return EXIT_FAIL_BPF;
  }

  /* check map info, e.g. datarec is expected size */
  int err = check_map_fd_info(&info, &ipv4hashmap);
  if (err) {
    fprintf(stderr, "ERR: map via FD not compatible\n");
    return err;
  }

  int nr_cpus = libbpf_num_possible_cpus();

	if (nr_cpus < 0) {
		printf("Failed to get # of possible cpus: '%s'!\n",
		       strerror(-nr_cpus));
		exit(1);
	}

  struct userLevelInfo values[nr_cpus];

  __u32 key = 0;
  __u32 next_key = 0;
  int res = 0;
  int i = 0;
  struct userLevelInfo *value = calloc(1, sizeof(struct userLevelInfo));
  while(1) {
    printf("checking map for keys...\n");
    while(bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        printf("Got key 0x%x\n", key);
        res = bpf_map_lookup_elem(fd, &key, (void*)values);
        if(res == 0) {
          	/* Get values from each CPU */
          	for (i = 0; i < nr_cpus; i++) {
              printf(
                "rxPackets: %u %u %llu\n",
                values[i].key,
                values[i].level,
                values[i].rx_packets
              );
          	}
            //bpf_map_delete_elem(fd, &key);
        }
        key = next_key;
    }
    if (errno == ENOENT) {
      res = bpf_map_lookup_elem(fd, &key, (void*)values);
      if(res == 0) {
          /* Get values from each CPU */
          for (i = 0; i < nr_cpus; i++) {
            printf(
              "rxPackets: %u %u %llu\n",
              values[i].key,
              values[i].level,
              values[i].rx_packets
            );
          }
          //bpf_map_delete_elem(fd, &key);
      }
    }
    key = 0;
    next_key = 0;
    sleep(1);
  }
  close(fd);
  free(value);
  exit(0);
}
