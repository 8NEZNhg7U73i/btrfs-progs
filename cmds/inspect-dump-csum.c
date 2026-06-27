/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include "kerncompat.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <uuid/uuid.h>
#include <errno.h>
#include <getopt.h>

#include "kernel-shared/ctree.h"
#include "kernel-shared/disk-io.h"
#include "kernel-shared/print-tree.h"
#include "kernel-shared/transaction.h"
#include "kernel-lib/list.h"
#include "common/utils.h"
#include "cmds/commands.h"
#include "crypto/crc32c.h"
#include "common/help.h"
#include "kernel-shared/volumes.h"

#include "common/messages.h"
#include "common/open-utils.h"
#include <sys/ioctl.h>

static const char *const cmd_inspect_dump_csum_usage[] = {"btrfs inspect-internal dump-csum <path/to/file> <device>", "Get csums for the given file.", NULL};

void print_32_bytes_hex(const uint8_t *bytes, const uint8_t length)
{
	for (uint8_t i = 0; i < length; i++)
	{
		pr_default("%08x", bytes[i]);
	}
	pr_default(" ");
}

static int btrfs_lookup_csums(struct btrfs_trans_handle *trans, struct btrfs_root *root, struct btrfs_path *path, u64 bytenr, int cow, int total_csums)
{
	int ret;
	int i;
	int start_pos = 0;
	struct btrfs_key file_key;
	struct btrfs_key found_key;
	struct btrfs_csum_item *item;
	struct extent_buffer *leaf;
	u64 csum_offset = 0;
	u16 csum_size = btrfs_super_csum_size(root->fs_info->super_copy);
	int csums_in_item = 0;
	uint8_t *tree_csum = calloc(csum_size, sizeof(uint8_t));
	int pending_csums = total_csums;
	static int cnt = 1;

	file_key.objectid = BTRFS_EXTENT_CSUM_OBJECTID;
	file_key.offset = bytenr;
	file_key.type = BTRFS_EXTENT_CSUM_KEY;
	ret = btrfs_search_slot(trans, root, &file_key, path, 0, cow);
	if (ret < 0)
	{
		goto fail;
	}
	while (1)
	{
		leaf = path->nodes[0];
		if (ret > 0)
		{
			ret = 1;
			if (path->slots[0] == 0)
			{
				goto fail;
			}
			path->slots[0]--;
			btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);
			if (found_key.type != BTRFS_EXTENT_CSUM_KEY)
			{
				error("\nInvalid key found.");
				goto fail;
			}

			csum_offset = ((bytenr - found_key.offset) / root->fs_info->sectorsize) * csum_size;
			csums_in_item = btrfs_item_size(leaf, path->slots[0]);
			csums_in_item /= csum_size;
			csums_in_item -= (bytenr - found_key.offset) / root->fs_info->sectorsize;
			start_pos = csum_offset;
		}
		if (path->slots[0] >= btrfs_header_nritems(leaf))
		{
			if (pending_csums > 0)
			{
				ret = btrfs_next_leaf(root, path);
				if (ret == 0)
				{
					continue;
				}
			}
		}
		item = btrfs_item_ptr(leaf, path->slots[0], struct btrfs_csum_item);
		btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);
		if (!ret)
		{
			start_pos = 0;
			csum_offset = (bytenr - found_key.offset) / root->fs_info->sectorsize;
			csums_in_item = btrfs_item_size(leaf, path->slots[0]);
			csums_in_item /= csum_size;
		}
		if (csums_in_item > pending_csums)
		{
			// possibly,some other csums on this item.
			for (i = 0; i < pending_csums; i++, cnt++)
			{
				read_extent_buffer(leaf, &tree_csum, (unsigned long)item + ((i * csum_size) + start_pos), csum_size);
				if (cnt % 8 == 0)
				{
					pr_default("\n");
				}
				print_32_bytes_hex(tree_csum, csum_size);
			}
			pending_csums = 0;
			return 0;
		}
		else
		{
			for (i = 0; i < csums_in_item; i++, cnt++)
			{
				read_extent_buffer(leaf, &tree_csum, (unsigned long)item + ((i * csum_size) + start_pos), csum_size);
				pr_default("%x ", tree_csum);
				if (cnt % 8 == 0)
				{
					pr_default("\n");
				}
			}
		}
		pending_csums -= csums_in_item;
		ret = 0;
		if (pending_csums > 0)
		{
			path->slots[0]++;
		}
		else
		{
			return 0;
		}
	}
fail:
	error("btrfs_lookup_csums search failed.\n");
	if (ret > 0)
	{
		ret = -ENOENT;
	}
	return ret;
}

static int btrfs_lookup_extent(struct btrfs_fs_info *info, struct btrfs_path *path, u64 ino, int cow)
{
	struct btrfs_key key;
	struct btrfs_key found_key;
	struct btrfs_file_extent_item *fi;
	struct extent_buffer *leaf;
	struct btrfs_root *fs_root;
	int ret = -1;
	int slot;
	int total_csums = 0;
	u64 bytenr;
	u64 itemnum = 0;
	struct btrfs_path *path1 = NULL;

	fs_root = info->fs_root;
	key.objectid = ino;
	key.type = BTRFS_EXTENT_DATA_KEY;
	key.offset = 0;
	ret = btrfs_search_slot(NULL, fs_root, &key, path, 0, 0);

	if (ret < 0)
	{
		goto error;
	}
	if (ret > 1)
	{
		error("Unable to find the entry");
		return ret;
	}
	struct btrfs_root *csum_root = btrfs_csum_root(info, 0);
	u16 csum_size = btrfs_super_csum_size(csum_root->fs_info->super_copy);
	while (1)
	{
		leaf = path->nodes[0];
		slot = path->slots[0];
		if (slot >= btrfs_header_nritems(leaf))
		{
			ret = btrfs_next_leaf(fs_root, path);
			if (ret == 0)
			{
				continue;
			}
			if (ret < 0)
			{
				goto error;
			}
		}
		btrfs_item_key_to_cpu(leaf, &found_key, slot);
		if (found_key.type != BTRFS_EXTENT_DATA_KEY)
		{
			btrfs_release_path(path);
			return -EINVAL;
		}

		fi = btrfs_item_ptr(leaf, slot, struct btrfs_file_extent_item);
		bytenr = btrfs_file_extent_disk_bytenr(leaf, fi);
		total_csums = (btrfs_file_extent_num_bytes(leaf, fi) / 1024) / csum_size;
		path->slots[0]++;
		itemnum++;
		path1 = btrfs_alloc_path();
		csum_root = btrfs_csum_root(info, 0);
		ret = btrfs_lookup_csums(NULL, csum_root, path1, bytenr, 0, total_csums);
		btrfs_release_path(path1);
		if (ret)
		{
			error("\n Error: btrfs_lookup_csum");
			return 1;
		}
	}

error:
	btrfs_release_path(path);
	return ret;
}

static int cmd_inspect_dump_csum(const struct cmd_struct *cmd, int argc, char **argv)
{
	struct btrfs_fs_info *info;
	int fd;
	int ret;
	struct btrfs_path path = {0};
	struct stat st;
	struct open_ctree_args oca = {0};
	struct btrfs_ioctl_fs_info_args *fi_args = calloc(1, sizeof(*fi_args));
	struct btrfs_ioctl_dev_info_args *di_args = calloc(1, sizeof(*di_args));
	oca.flags = OPEN_CTREE_PARTIAL;
	oca.filename = calloc(1, sizeof(di_args->path));
	char fsid_str[BTRFS_UUID_UNPARSED_SIZE];

	if (check_argc_exact(argc, 2))
	{
		usage_unknown_option(cmd, argv);
	}

	pr_default("path: %s\n", argv[1]);

	ret = stat(argv[1], &st);
	if (ret < 0)
	{
		error("unable to open file stat %s\n", argv[1]);
		exit(1);
	}

	if (!S_ISREG(st.st_mode))
	{
		error("%s is not a regular file.\n", argv[1]);
		exit(1);
	}

	fd = btrfs_open_path(argv[1], false, false);
	if (fd < 0)
	{
		error("btrfs_open_path failed returned error %d", fd);
		exit(1);
	}

	if (!fi_args || !di_args)
	{
		error("mem allocate failed\n");
		exit(1);
	}

	ret = ioctl(fd, BTRFS_IOC_FS_INFO, fi_args);
	if (ret < 0)
	{
		error("searching target filesystems returned error %d", ret);
		exit(1);
	}
	uuid_unparse(fi_args->fsid, fsid_str);
	pr_default("FSID: %s\n", fsid_str);

	for (u64 devid = 1; devid <= fi_args->max_id; devid++)
	{
		di_args->devid = devid;

		ret = ioctl(fd, BTRFS_IOC_DEV_INFO, di_args);
		if (ret < 0)
		{
			error("searching target device returned error %d", ret);
			exit(1);
		}
		else
		{
			memcpy((void *)oca.filename, di_args->path, sizeof(di_args->path));
		}
		char uuid_str[BTRFS_UUID_UNPARSED_SIZE];
		uuid_unparse(di_args->uuid, uuid_str);
		pr_default("UUID: %s\n", uuid_str);
		pr_default("PATH: %s\n", di_args->path);
		memset(di_args, 0, sizeof(*di_args));
	}

	if (strlen(oca.filename) == 0)
	{
		error("Open all btrfs device failed\n");
		exit(0);
	}

	info = open_ctree_fs_info(&oca);
	if (!info)
	{
		error("unable to open %s\n", argv[1]);
		exit(1);
	}

	if (st.st_size == 0)
	{
		error("file size is 0B, about.\n");
		exit(1);
	}

	ret = btrfs_lookup_extent(info, &path, st.st_ino, 0);
	ret = close_ctree(info->fs_root);
	btrfs_close_all_devices();
	pr_default("\n");

	return ret;
}
DEFINE_SIMPLE_COMMAND(inspect_dump_csum, "dump-csum");
