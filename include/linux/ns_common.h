/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NS_COMMON_H
#define _LINUX_NS_COMMON_H

struct proc_ns_operations;
struct nsctl_reg;

struct ns_common {
	atomic_long_t stashed;
	const struct proc_ns_operations *ops;
	struct nsctl_reg *reg;
	unsigned int inum;
};

#endif
