/*  Syslog internals
 *
 *  Copyright 2010 Canonical, Ltd.
 *  Author: Kees Cook <kees.cook@canonical.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _LINUX_SYSLOG_H
#define _LINUX_SYSLOG_H

#include <linux/slab.h>
#include <linux/kref.h>

/* Close the log.  Currently a NOP. */
#define SYSLOG_ACTION_CLOSE          0
/* Open the log. Currently a NOP. */
#define SYSLOG_ACTION_OPEN           1
/* Read from the log. */
#define SYSLOG_ACTION_READ           2
/* Read all messages remaining in the ring buffer. */
#define SYSLOG_ACTION_READ_ALL       3
/* Read and clear all messages remaining in the ring buffer */
#define SYSLOG_ACTION_READ_CLEAR     4
/* Clear ring buffer. */
#define SYSLOG_ACTION_CLEAR          5
/* Disable printk's to console */
#define SYSLOG_ACTION_CONSOLE_OFF    6
/* Enable printk's to console */
#define SYSLOG_ACTION_CONSOLE_ON     7
/* Set level of messages printed to console */
#define SYSLOG_ACTION_CONSOLE_LEVEL  8
/* Return number of unread characters in the log buffer */
#define SYSLOG_ACTION_SIZE_UNREAD    9
/* Return size of the log buffer */
#define SYSLOG_ACTION_SIZE_BUFFER   10
/* Create a new syslog ns */
#define SYSLOG_ACTION_NEW_NS        11

#define SYSLOG_FROM_READER	   0
#define SYSLOG_FROM_PROC	     1

enum log_flags {
	LOG_NOCONS      = 1,    /* already flushed, do not print to console */
	LOG_NEWLINE     = 2,    /* text ended with a newline */
	LOG_PREFIX      = 4,    /* text started with a prefix */
	LOG_CONT	= 8,    /* text is a fragment of a continuation line */
};

struct syslog_namespace {
	struct kref kref;	/* syslog_ns reference count & control */

	raw_spinlock_t logbuf_lock; /* access conflict locker */
	/* cpu currently holding logbuf_lock of ns */
	unsigned int logbuf_cpu;

	/* index and sequence number of the first record stored in the buffer */
	u64 log_first_seq;
	u32 log_first_idx;

	/* index and sequence number of the next record stored in the buffer */
	u64 log_next_seq;
	u32 log_next_idx;

	/* the next printk record to read after the last 'clear' command */
	u64 clear_seq;
	u32 clear_idx;

	char *log_buf;
	u32 log_buf_len;

	/* the next printk record to write to the console */
	u64 console_seq;
	u32 console_idx;

	/* the next printk record to read by syslog(READ) or /proc/kmsg */
	u64 syslog_seq;
	u32 syslog_idx;

	enum log_flags syslog_prev;
	size_t syslog_partial;

	/* per ns dumper */
	spinlock_t dump_list_lock;
	struct list_head dump_list;

	int dmesg_restrict;

	/*
	* user namespace which owns this syslog ns.
	*/
	struct user_namespace *owner;
};

static inline struct syslog_namespace *get_syslog_ns(
				struct syslog_namespace *ns)
{
	if (ns)
		kref_get(&ns->kref);
	return ns;
}

static inline void free_syslog_ns(struct kref *kref)
{
	struct syslog_namespace *ns;
	ns = container_of(kref, struct syslog_namespace, kref);

	kfree(ns->log_buf);
	kfree(ns);
}

static inline void put_syslog_ns(struct syslog_namespace *ns)
{
	if (ns)
		kref_put(&ns->kref, free_syslog_ns);
}

extern struct syslog_namespace init_syslog_ns;

int do_syslog(int type, char __user *buf, int len, int source,
			struct syslog_namespace *ns);

#endif /* _LINUX_SYSLOG_H */
