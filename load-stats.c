/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader and stats program\n"
							 " - Allows selecting BPF section --progsec name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "./common/common_params.h"
#include "./common/common_user_bpf_xdp.h"
#include "./common/common_kern_user.h"
#include "bpf_util.h" /* bpf_num_possible_cpus */

static const char *default_filename = "kernel_main.o";
static const char *default_progsec = "xdp_stats1";

static const struct option_wrapper long_options[] = {
	{{"help", no_argument, NULL, 'h'},
	 "Show help",
	 false},

	{{"dev", required_argument, NULL, 'd'},
	 "Operate on device <ifname>",
	 "<ifname>",
	 true},

	{{"skb-mode", no_argument, NULL, 'S'},
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument, NULL, 'N'},
	 "Install XDP program in native mode"},

	{{"auto-mode", no_argument, NULL, 'A'},
	 "Auto-detect SKB or native mode"},

	{{"force", no_argument, NULL, 'F'},
	 "Force install, replacing existing program on interface"},

	{{"unload", no_argument, NULL, 'U'},
	 "Unload XDP program instead of loading"},

	{{"quiet", no_argument, NULL, 'q'},
	 "Quiet mode (no output)"},

	{{"filename", required_argument, NULL, 1},
	 "Load program from <file>",
	 "<file>"},

	{{"progsec", required_argument, NULL, 2},
	 "Load program in <section> of the ELF file",
	 "<section>"},

	{{0, 0, NULL, 0}}};

                                      
#define MAX_CPUS 11

#ifndef container_of
#define container_of(ptr, type, member)                        \
	(                                                          \
		{                                                      \
			const typeof(((type *)0)->member) *__mptr = (ptr); \
			(type *)((char *)__mptr - offsetof(type, member)); \
		})
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

void getNIC(char *name)
{
	FILE *fp;
	char path[255];

	/* Open the command for reading. */
	fp = popen("ip route get 8.8.8.8| awk '{print $5}'|awk /./", "r");
	if (fp == NULL)
	{
		printf("Failed to run command\n");
		exit(1);
	}

	/* Read the output a line at a time - output it. */
	fgets(path, sizeof(path), fp);
	// path[strcspn(path, "\n") + 1] = 0;
	//   printf("%s", path);
	path[strlen(path) - 1] = 0; // remove weird unneeded character at the end before EOF
	strcpy(name, path);

	/* close */
	pclose(fp);
}

int quit = 0;

static void sign_hdl(int tmp)
{
    quit = 1;
}

int main(int argc, char **argv)
{
	struct bpf_object *bpf_obj;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex = -1,
		.do_unload = false
		//.link_test = 1
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	strncpy(cfg.progsec, default_progsec, sizeof(cfg.progsec));
	/* Cmdline options can change progsec */
	printf("parsing cmdline args\n");
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);
	/* Required option */
	printf("%d\n", cfg.ifindex);

	char ifname[255];
	if (cfg.ifindex == -1)
	{
		getNIC(ifname);
		printf("No --dev given, defaulting to NIC %s\n", ifname);
		cfg.ifindex = if_nametoindex(ifname);
		if (cfg.ifindex == 0)
		{
			fprintf(stderr,
					"ERR: --dev name unknown err(%d):%s\n",
					errno, strerror(errno));
		}
	}
	else
	{
		strcpy(ifname, cfg.ifname);
	}
	if (cfg.do_unload)
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	// Up ulimit before attaching (maximum memory for a kernel program)
	struct rlimit new;
	new.rlim_cur = 65536000000;
	new.rlim_max = 65536000000;
	struct rlimit *newp = &new;
	setrlimit(RLIMIT_MEMLOCK, newp);

	bpf_obj = load_bpf_and_xdp_attach(&cfg);
	if (!bpf_obj)
		return EXIT_FAIL_BPF;

	printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		   cfg.filename, cfg.progsec);
	printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		   cfg.ifname, cfg.ifindex);



    quit = 0;
    signal(SIGINT, sign_hdl);
    signal(SIGTERM, sign_hdl);

	while (!quit)
	{
		// hang the program until sigterm gets called
		sleep(1);
	}

	// End of loop, detach the program and return to normal.
	xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	return EXIT_OK;
}
