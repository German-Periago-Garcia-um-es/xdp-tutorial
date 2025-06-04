/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
	" - Allows selecting BPF program --progname name to XDP-attach to --dev\n";

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
#include "../common/common_libbpf.h"
#include "common_kern_user.h"

static const char *default_filename = "xdp_prog_kern.o";

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

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progname",    required_argument,	NULL,  2  },
	 "Load program from function <name> in the ELF file", "<name>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";
const char *map_name    =  "xdp_stats_map";

/* Pinning maps under /sys/fs/bpf in subdir */
int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, const char *subdir)
{
	char map_filename[PATH_MAX];
	char pin_dir[PATH_MAX];
	int err, len;

	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, subdir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	len = snprintf(map_filename, PATH_MAX, "%s/%s/%s",
		       pin_basedir, subdir, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		return EXIT_FAIL_OPTION;
	}

	/* Existing/previous XDP prog might not have cleaned up */
	if (access(map_filename, F_OK ) != -1 ) {
		if (verbose)
			printf(" - Unpinning (remove) prev maps in %s/\n",
			       pin_dir);

		/* Basically calls unlink(3) on map_filename */
		err = bpf_object__unpin_maps(bpf_obj, pin_dir);
		if (err) {
			fprintf(stderr, "ERR: UNpinning maps in %s\n", pin_dir);
			return EXIT_FAIL_BPF;
		}
	}
	if (verbose)
		printf(" - Pinning maps in %s/\n", pin_dir);

	/* This will pin all maps in our bpf_object */
	err = bpf_object__pin_maps(bpf_obj, pin_dir);
	if (err)
		return EXIT_FAIL_BPF;

	printf("Leaving pin_maps_in_bpf_object...\n");
	return 0;
}

/* Check if pinned map exists and reuse it */
static int reuse_pinned_map(struct bpf_object *bpf_obj, const char *subdir)
{
    char pin_path[PATH_MAX];
    struct bpf_map *map;
    int pinned_fd, len, err;

    /* Construct path to pinned map */
    len = snprintf(pin_path, PATH_MAX, "%s/%s/%s", pin_basedir, subdir, map_name);
    if (len < 0) {
        fprintf(stderr, "ERR: creating pin path\n");
        return -1;
    }

    /* Check if pinned map exists */
    if (access(pin_path, F_OK) != 0) {
        if (verbose)
            printf(" - No existing pinned map found\n");
        return 0; /* No pinned map, continue normally */
    }

    /* Try to open the pinned map */
    pinned_fd = bpf_obj_get(pin_path);
    if (pinned_fd < 0) {
        if (verbose)
            printf(" - Failed to open pinned map: %s\n", strerror(errno));
        return 0; /* Failed to open, continue normally */
    }

    if (verbose)
        printf(" - Found existing pinned map at %s\n", pin_path);

    /* Find the map object in our BPF program */
    map = bpf_object__find_map_by_name(bpf_obj, map_name);
    if (!map) {
        fprintf(stderr, "ERR: cannot find map '%s' in BPF object\n", map_name);
        close(pinned_fd);
        return -1;
    }

    /* Reuse the pinned map */
    err = bpf_map__reuse_fd(map, pinned_fd);
    if (err) {
        fprintf(stderr, "ERR: failed to reuse pinned map: %s\n", strerror(-err));
        close(pinned_fd);
        return -1;
    }

    if (verbose)
        printf(" - Successfully reused pinned map\n");

    /* Don't close pinned_fd - libbpf now owns it */
	printf("Leaving reuse_pinned_map\n");
    return 1; /* Map was reused */
}

/* Load BPF program with map reuse capability */
static struct xdp_program *load_bpf_and_xdp_attach_with_reuse(struct config *cfg)
{
    struct xdp_program *program;
    struct bpf_object *bpf_obj;
    int err, map_reused = 0;

    /* USAR LA MISMA API QUE EL ORIGINAL */
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
    DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);

    xdp_opts.open_filename = cfg->filename;
    xdp_opts.prog_name = cfg->progname;
    xdp_opts.opts = &opts;

    /* Create program object pero SIN cargarlo en kernel aún */
    program = xdp_program__create(&xdp_opts);
    
    err = libxdp_get_error(program);
    if (err) {
        char errmsg[1024];
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "ERR: Failed to create XDP program: %s\n", errmsg);
        goto error;
    }

    bpf_obj = xdp_program__bpf_obj(program);

    /* Try to reuse existing pinned map BEFORE attaching */
    err = reuse_pinned_map(bpf_obj, cfg->ifname);
    if (err > 0) {
        map_reused = 1;
    } else if (err < 0) {
        fprintf(stderr, "ERR: Failed to reuse pinned map\n");
        xdp_program__close(program);
        goto error;
    }

    /* Now attach the program */
    err = xdp_program__attach(program, cfg->ifindex, cfg->attach_mode, 0);
    if (err) {
        fprintf(stderr, "ERR: Failed to attach XDP program\n");
        xdp_program__close(program);
        goto error;
    }

    /* Only pin maps if we didn't reuse existing ones */
    if (!map_reused) {
        err = pin_maps_in_bpf_object(bpf_obj, cfg->ifname);
        if (err) {
            fprintf(stderr, "ERR: pinning maps\n");
        }
    } else {
        if (verbose)
            printf(" - Skipped map pinning (reused existing)\n");
    }

	printf("Leaving load_bpf_and_xdp_attach_with_reuse...\n");
    return program;

	error:
		fprintf(stderr, "ERR: Failed to load and attach XDP program. Leaving load_bpf_and_xdp_attach_with_reuse...\n");
		return NULL;
}

int main(int argc, char **argv)
{
    struct xdp_program *program;

    struct config cfg = {
        .attach_mode = XDP_MODE_NATIVE,
        .ifindex     = -1,
        .do_unload   = false,
    };
    
    /* Set default BPF-ELF object file and BPF program name */
    strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
    /* Cmdline options can change progname */
    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

    /* Required option */
    if (cfg.ifindex == -1) {
        fprintf(stderr, "ERR: required option --dev missing\n\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }
    
    if (cfg.do_unload) {
    }
    
    /* Load program with map reuse capability */
    program = load_bpf_and_xdp_attach_with_reuse(&cfg);
    if (program == NULL)
        return EXIT_FAIL_BPF;

    if (verbose) {
        printf("Success: Loaded BPF-object(%s) and used program(%s)\n",
               cfg.filename, cfg.progname);
        printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
               cfg.ifname, cfg.ifindex);
    }

    return EXIT_OK;
}