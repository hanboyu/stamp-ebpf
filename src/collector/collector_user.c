/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader and stats program\n"
	" - Allows selecting BPF --progname name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "collector.h"

static const char *default_filename = "collector_kern.o";
static const char *default_progname = "stamp_collector";

const struct bpf_map_info stamp_data_map_expect = { 
	.key_size = sizeof(__u32), 
	.value_size  = sizeof(struct stamp_data),
	.max_entries = STAMP_MAP_SIZE
	};
const struct bpf_map_info counter_map_expect = { 
	.key_size = sizeof(__u32), 
	.value_size  = sizeof(__u32),
	.max_entries = 1
	};

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	struct bpf_map *map;
	int map_fd = -1;

	/* Lesson#3: bpf_object to bpf_map */
	map = bpf_object__find_map_by_name(bpf_obj, mapname);
        if (!map) {
		fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
		goto out;
	}

	map_fd = bpf_map__fd(map);
 out:
	return map_fd;
}

static int __check_map_fd_info(int map_fd, struct bpf_map_info *info,
			       const struct bpf_map_info *exp)
{
	__u32 info_len = sizeof(*info);
	int err;

	if (map_fd < 0)
		return EXIT_FAIL;

        /* BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: %s() can't get info - %s\n",
			__func__,  strerror(errno));
		return EXIT_FAIL_BPF;
	}

	if (exp->key_size && exp->key_size != info->key_size) {
		fprintf(stderr, "ERR: %s() "
			"Map key size(%d) mismatch expected size(%d)\n",
			__func__, info->key_size, exp->key_size);
		return EXIT_FAIL;
	}
	if (exp->value_size && exp->value_size != info->value_size) {
		fprintf(stderr, "ERR: %s() "
			"Map value size(%d) mismatch expected size(%d)\n",
			__func__, info->value_size, exp->value_size);
		return EXIT_FAIL;
	}
	if (exp->max_entries && exp->max_entries != info->max_entries) {
		fprintf(stderr, "ERR: %s() "
			"Map max_entries(%d) mismatch expected size(%d)\n",
			__func__, info->max_entries, exp->max_entries);
		return EXIT_FAIL;
	}
	if (exp->type && exp->type  != info->type) {
		fprintf(stderr, "ERR: %s() "
			"Map type(%d) mismatch expected type(%d)\n",
			__func__, info->type, exp->type);
		return EXIT_FAIL;
	}

	return 0;
}

double ntp2unix(uint32_t seconds_part, uint32_t fractional_part){
	// Calculate the fractional part in seconds as a double
    double fractional_seconds = (double)fractional_part / (double)UINT32_MAX;

    // Calculate the total time in seconds
    double total_seconds = (double)seconds_part + fractional_seconds;

	// Convert to Unix timestamp
	total_seconds -= NTP_UNIX_OFFSET;
	
	return total_seconds;
}

double uptime2unix(uint64_t system_up_ns, double offset){
	double up_s = (double)system_up_ns / NANOSEC_PER_SEC;
	
	return up_s + offset;
}

double calc_timestamp_offset(){
	/* Calculate offset between system uptime and Unix timestamp */ 
	int res;
	struct timespec unix_time;
	res = clock_gettime(CLOCK_REALTIME, &unix_time);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	double current_seconds = (double)unix_time.tv_sec + ((double)unix_time.tv_nsec / NANOSEC_PER_SEC);
	
	struct timespec uptime;
	res = clock_gettime(CLOCK_MONOTONIC, &uptime);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	double up_seconds = (double)uptime.tv_sec + ((double)uptime.tv_nsec / NANOSEC_PER_SEC);
	
	double time_offset = (double)current_seconds - (double)up_seconds;
	printf("Current Unix timestamp: %f, System up seconds: %f, Offset:%f\n", current_seconds, up_seconds, time_offset);

	return time_offset;
}

int save_data(int data_map_fd, __u32 len, FILE *out_file_fd){
	fprintf(out_file_fd, "ssid,seq,test_tx,test_rx,reply_tx,reply_rx\n");
	double offset = calc_timestamp_offset();
	int saved_len = 0;

	for (__u32 i = 0; i < len; i ++){
		struct stamp_data value;
		if ((bpf_map_lookup_elem(data_map_fd, &i, &value)) != 0) {
			perror("Error ");
			return -1;
		}

		// Process data
		uint16_t ssid = value.ssid;
		uint32_t seq = value.seq;
		double test_tx = ntp2unix(value.test_tx[0], value.test_tx[1]);
		double test_rx = ntp2unix(value.test_rx[0], value.test_rx[1]);
		double reply_tx = ntp2unix(value.reply_tx[0], value.reply_tx[1]);
		double reply_rx = uptime2unix(value.reply_rx, offset);

		// Validate data
		if (test_tx < 0){
			continue;
		}
		if (test_rx < 0){
			continue;
		}
		if (reply_tx < 0){
			continue;
		}
		if (reply_rx < 0){
			continue;
		}

		saved_len ++;
		fprintf(out_file_fd, "%u,%u,%f,%f,%f,%f\n", 
			ssid, 
			seq, 
			test_tx,
			test_rx,
			reply_tx,
			reply_rx);	
	}
	
	return saved_len;
}

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"unload",      required_argument,	NULL, 'U' },
	 "Unload XDP program <id> instead of loading", "<id>"},

	{{"unload-all",  no_argument,           NULL,  4  },
	 "Unload all XDP programs on device"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progname",    required_argument,	NULL,  2  },
	 "Load program from function <name> in the ELF file", "<name>"},
	
	{{"out-file", 	 required_argument, NULL,  'o'},
	 "Path to the output csv file <out-file>", "<out-file>", true},
	
	{{"duration",	 required_argument,	NULL, 't' },
	 "Duration of running collector in <seconds>", "<seconds>", true},

	{{0, 0, NULL,  0 }}
};

int main(int argc, char **argv)
{
	struct bpf_map_info info = { 0 };
	struct xdp_program *program;
	int stats_map_fd, counter_fd;
	// int interval = 2;
	char errmsg[1024];
	int err;


	struct config cfg = {
		.ifindex   = -1,
		.do_unload = false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	strncpy(cfg.progname,  default_progname,  sizeof(cfg.progname));
	/* Cmdline options can change progname */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

        /* Unload a program by prog_id, or
         * unload all programs on net device
         */
	if (cfg.do_unload || cfg.unload_all) {
		err = do_unload(&cfg);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Couldn't unload XDP program %d: %s\n",
				cfg.prog_id, errmsg);
			return err;
		}

		printf("Success: Unloading XDP prog name: %s\n", cfg.progname);
		return EXIT_OK;
	}

	program = load_bpf_and_xdp_attach(&cfg);
	if (!program)
		return EXIT_FAIL_BPF;

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		       cfg.filename, cfg.progname);
		printf(" - XDP prog id:%d attached on device:%s(ifindex:%d)\n",
		       xdp_program__id(program), cfg.ifname, cfg.ifindex);
	}

	/* Prepare BPF map */
	printf("\nCollecting stats from BPF map\n");
	
	/* STAMP data map*/
	stats_map_fd = find_map_fd(xdp_program__bpf_obj(program), "stamp_data_map");
	if (stats_map_fd < 0) {
		/* xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0); */
		return EXIT_FAIL_BPF;
	}
	/* check map info for STAMP data*/
	err = __check_map_fd_info(stats_map_fd, &info, &stamp_data_map_expect);
	if (err) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		return err;
	}
	printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
		       " key_size:%d value_size:%d max_entries:%d\n",
		       info.type, info.id, info.name,
		       info.key_size, info.value_size, info.max_entries
		       );

	/* counter map */
	counter_fd = find_map_fd(xdp_program__bpf_obj(program), "counter_map");
	if (counter_fd < 0) {
		/* xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0); */
		return EXIT_FAIL_BPF;
	}
	/* check map info for STAMP data*/
	err = __check_map_fd_info(counter_fd, &info, &counter_map_expect);
	if (err) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		return err;
	}
	printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
		       " key_size:%d value_size:%d max_entries:%d\n",
		       info.type, info.id, info.name,
		       info.key_size, info.value_size, info.max_entries
		       );
	// Setting counter to 0
	__u32 counter = 0;
	__u32 counter_key = COUNTER_KEY;
	if (bpf_map_update_elem(counter_fd, &counter_key, &counter, BPF_EXIST) != 0){
		fprintf(stderr, "ERR: %s\n", strerror(errno));
	}

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");
	printf("\nStarting STAMP Collector\n");

	

	/* Finished setting up eBPF program */
	sleep(cfg.duration);

	printf("Experiment finished\n");

	/* Prepare output file */	
	// char saving_dir[] = "./data/";
	// int saving_dir_len = 7;
	// char exp_name[] = "test";
	// int exp_name_len = 4;
	
	// int out_path_len = saving_dir_len + exp_name_len + 8;
	// char out_path[out_path_len + 1];
	// err = snprintf(out_path, out_path_len + 1, "%s%s%s", saving_dir, exp_name, "_raw.csv");
	// if (err < 0){
	// 	exit(EXIT_FAIL); // file write to buffer
	// }

	FILE *out_fp;
	out_fp = fopen(cfg.out_file, "w");
	if( out_fp == NULL ) {
		perror("Failed open output file: ");
    	exit(EXIT_FAIL);
   }
	
	/* Collect and save data */
	__u32 data_len;
	if ((bpf_map_lookup_elem(counter_fd, &counter_key, &data_len)) != 0) {
		perror("Failed looking up counter map: ");
	}
	printf("Collecting %u data points\n", data_len);
	
	int num_data = save_data(stats_map_fd, data_len, out_fp);

	printf("%d data points saved to '%s'\n", num_data, cfg.out_file);
	fclose(out_fp);
	
	
	// struct stamp_data value;
	// __u32 new_counter;

	// while (1) {
	// 	if ((bpf_map_lookup_elem(counter_fd, &counter_key, &new_counter)) != 0) {
	// 		fprintf(stderr, "ERR: %s\n", strerror(errno));
	// 	}
	// 	printf("new counter: %u\n", new_counter);
		
	// 	if (new_counter > counter){
	// 		for (__u32 i = counter; i < new_counter; i ++){
	// 			if ((bpf_map_lookup_elem(stats_map_fd, &i, &value)) != 0) {
	// 				fprintf(stderr, "ERR: %s\n", strerror(errno));
	// 			}	
			
	// 			printf("[%u]: ssid: %u, seq: %u, tx: %f, rx: %f, RTT: %f\n", i, value.ssid, value.seq, ntp2unix(value.test_tx[0], value.test_tx[1]), uptime2unix(value.reply_rx, time_offset), (uptime2unix(value.reply_rx, time_offset) - ntp2unix(value.test_tx[0], value.test_tx[1])) * 1000);
	// 		}
	// 		counter = new_counter;
	// 	}
		
	// 	sleep(interval);
	// }
	return EXIT_OK;
}
