/*
 * fs/nsctlfs.c
 *
 *  Copyright (C) 2018
 *
 *  Author: Pavel Snajdr <snajpa@snajpa.net>
 *
 *  nsctlfs support
 *
 *  Still a heavy work in progress.
 *
 */

#include <linux/uaccess.h>

#include <linux/err.h>
#include <linux/kref.h>
#include <linux/cred.h>
#include <linux/time.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/magic.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/proc_ns.h>
#include <linux/kernfs.h>
#include <linux/sysfs.h>
#include <linux/seq_file.h>
#include <linux/idr.h>
#include <linux/user_namespace.h>

#include <linux/nsctlfs.h>

/* Index of all registered namespaces */
DEFINE_IDR(nsctl_def_idr);
EXPORT_SYMBOL_GPL(nsctl_def_idr);

/* Index of all namespace instance ids */
DEFINE_IDR(nsctl_global_reg_idr);
EXPORT_SYMBOL_GPL(nsctl_global_reg_idr);

static struct ucounts *inc_nsctl_namespaces(struct user_namespace *ns)
{
	return inc_ucount(ns, current_euid(), UCOUNT_NSCTL_NAMESPACES);
}

static void dec_nsctl_namespaces(struct ucounts *ucounts)
{
	dec_ucount(ucounts, UCOUNT_NSCTL_NAMESPACES);
}

void free_nsctl_ns(struct kref *kref)
{
	struct nsctl_namespace *ns;

	ns = container_of(kref, struct nsctl_namespace, kref);

	WARN_ON(ns == &init_nsctl_ns);

	dec_nsctl_namespaces(ns->ucounts);
	put_nsctl_ns(ns->parent);
	put_user_ns(ns->user_ns);
	ns_free_inum(&ns->ns);
	kfree(ns);
}


struct nsctl_namespace *clone_nsctl_ns(struct user_namespace *user_ns,
						struct nsctl_namespace *old_ns)
{
	struct nsctl_namespace *ns;
	struct nsctl_reg *reg;
	struct ucounts *ucounts;
	int err;

	/* TODO
	 * Some permission checking over here
	if (!ns_capable(user_ns, CAP_SYSLOG))
		return ERR_PTR(-EPERM);
	 */

	printk("nsctl: @ %s line %d", __func__, __LINE__);
	err = -ENOMEM;
	reg = alloc_nsctl_reg();
	if (!reg)
		goto fail;

	err = -ENOSPC;
	ucounts = inc_nsctl_namespaces(user_ns);
	if (!ucounts)
		goto fail;

	err = -ENOMEM;
	ns = kzalloc(sizeof(*ns), GFP_KERNEL);
	if (!ns)
		goto fail_dec;

	kref_init(&ns->kref);

	err = ns_alloc_inum(&ns->ns);
	if (err)
		goto fail_free;

	idr_init(&ns->reg_idr);

	ns->ucounts = ucounts;
	ns->ns.ops = &nsctlns_operations;
	ns->user_ns = get_user_ns(user_ns);
	ns->parent = get_nsctl_ns(old_ns);

	err = nsctl_register_namespace(reg, &namespace_def_nsctl, &ns->ns);
	if (err < 0)
		goto fail_idr;

	return ns;

fail_idr:
	idr_destroy(&ns->reg_idr);
fail_free:
	kfree(ns);
fail_dec:
	dec_nsctl_namespaces(ucounts);
fail:
	kfree(reg);
	return ERR_PTR(err);

}

struct nsctl_namespace *copy_nsctl_ns(bool new,
				  struct user_namespace *user_ns,
				  struct nsctl_namespace *old_ns)
{
	struct nsctl_namespace *new_ns;

	get_nsctl_ns(old_ns);
	if (!new)
		return old_ns;

	new_ns = clone_nsctl_ns(user_ns, old_ns);
	put_nsctl_ns(old_ns);

	return new_ns;
}

static struct ns_common *nsctl_ns_get(struct task_struct *task)
{
	struct nsctl_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy) {
		ns = nsproxy->nsctl_ns;
		get_nsctl_ns(ns);
	}
	task_unlock(task);

	return ns ? &ns->ns : NULL;
}

static void nsctl_ns_put(struct ns_common *ns)
{
	put_nsctl_ns(to_nsctl_ns(ns));
}

static int nsctl_ns_install(struct nsproxy *nsproxy, struct ns_common *new)
{
	struct nsctl_namespace *ns = to_nsctl_ns(new);

	if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(current_user_ns(), CAP_SYS_ADMIN))
		return -EPERM;

	put_nsctl_ns(nsproxy->nsctl_ns);
	nsproxy->nsctl_ns = get_nsctl_ns(ns);

	return 0;
}

static struct user_namespace *nsctl_ns_owner(struct ns_common *ns)
{
	return to_nsctl_ns(ns)->user_ns;
}

const struct proc_ns_operations nsctlns_operations = {
	.name	 = "nsctl",
	.get	 = nsctl_ns_get,
	.put	 = nsctl_ns_put,
	.install = nsctl_ns_install,
	.owner	 = nsctl_ns_owner,
};

struct nsctl_namespace init_nsctl_ns = {
	.user_ns = &init_user_ns,
	.ucounts = NULL,
	.kref	 = KREF_INIT(2),
	.parent	 = NULL,
	.ns.ops	 = &nsctlns_operations,
	.ns.inum = PROC_NSCTL_INIT_INO,
};
EXPORT_SYMBOL_GPL(init_nsctl_ns);

ssize_t nsctlfs_file_read(struct kernfs_open_file *of, char *buf,
			  size_t bytes, loff_t off)
{
	struct nsctl_ops *ops = of->kn->priv;
	struct nsctl_reg *reg = of->kn->parent->priv;
	printk("nsctl: @ %s line %d", __func__, __LINE__);
	return ops->read(reg->ns, buf, bytes, off);
}
ssize_t nsctlfs_file_write(struct kernfs_open_file *of, char *buf,
			  size_t bytes, loff_t off)
{
	struct nsctl_ops *ops = of->kn->priv;
	struct nsctl_reg *reg = of->kn->parent->priv;
	printk("nsctl: @ %s line %d", __func__, __LINE__);
	return ops->write(reg->ns, buf, bytes, off);
}
const struct kernfs_ops nsctlfs_file_ops = {
	.read	 = nsctlfs_file_read,
	.write	 = nsctlfs_file_write,
};
int nsctlfs_populate_reg_dir(struct kernfs_node *dst, struct nsctl_reg *reg)
{
	struct nsctl_def *def = reg->def;
	struct kernfs_node *kni;
	struct nsctl_ops *ops;
	int ret = 0;
	umode_t mode;
	
	printk("nsctl: @ %s line %d", __func__, __LINE__);

	spin_lock(&def->ops_list_lock);
	list_for_each_entry(ops, &def->ops_list, ops_list_node) {
		printk("nsctl: @ %s line %d", __func__, __LINE__);
		mode = S_IRUSR | S_IRGRP;
		if (ops->write)
			mode = S_IWUSR | S_IWGRP;
		get_nsctl_reg(reg);
		kni = kernfs_create_file(dst, ops->name,
					mode, 1024,
					&nsctlfs_file_ops, ops);
		if (IS_ERR(kni))
			goto revert;
		printk("nsctl: @ %s line %d", __func__, __LINE__);
		ret++;
	}
	spin_unlock(&def->ops_list_lock);

	return ret;
revert:
	/* TODO */
	printk("nsctl: @ %s line %d", __func__, __LINE__);
	BUG();
	return -1;
}
int nsctlfs_depopulate_reg_dir(struct nsctl_reg *reg)
{
	BUG();
	return 0;
}
int nsctlfs_mkregdir(struct nsctl_namespace *in_ns, struct nsctl_reg *reg)
{
	struct kernfs_node *kni, *dst;
	int id, ret;
	char name[33];
	umode_t mode = S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP;
	
	dst = (in_ns == &init_nsctl_ns) ? reg->kfs_node_init_ns
					: reg->kfs_node;

	id = (in_ns == &init_nsctl_ns) ? reg->global_id
				       : reg->id;

	printk("nsctl: @ %s line %d", __func__, __LINE__);

	get_nsctl_reg(reg);
	scnprintf(name, 32, "%s_%d", reg->def->name, id);
	kni = kernfs_create_dir(in_ns->kfs_node, name, mode, reg);
	if (IS_ERR(kni)) {
		ret = PTR_ERR(kni);
		goto fail_kni;
	}
	dst = kni;
	kernfs_get(kni);
	ret = nsctlfs_populate_reg_dir(dst, reg);
	if (ret < 0)
		goto fail;
	return 1;
fail:
	kernfs_remove(reg->kfs_node_init_ns);
	kernfs_put(kni);
fail_kni:
	put_nsctl_reg(reg);
	printk("nsctl: @ %s line %d", __func__, __LINE__);
	return ret;
}
int nsctlfs_rmregdir(struct nsctl_namespace *in_ns, struct nsctl_reg *reg)
{
	return 0;
}

int nsctlfs_populate_root_dir(struct nsctl_namespace *tgt_ns)
{
	struct idr *idr = &tgt_ns->reg_idr;
	struct nsctl_reg *reg;
	int id, revid, ret;
	
	printk("nsctl: @ %s line %d", __func__, __LINE__);

	if (tgt_ns == &init_nsctl_ns)
		idr = &nsctl_global_reg_idr;

	ret = 0;
	idr_lock(idr);
	idr_for_each_entry(idr, reg, id) {
		revid = id;
		ret = nsctlfs_mkregdir(tgt_ns, reg);
		if (ret < 0)
			goto revert;
		ret++;
	}
	idr_unlock(idr);
	return ret;

revert:
	idr_for_each_entry(idr, reg, revid) {
		if (revid > id)
			break;
		nsctlfs_rmregdir(tgt_ns, reg);
	}
	idr_unlock(idr);
	return -1;
}
int nsctlfs_depopulate_root_dir(struct nsctl_namespace *tgt_ns)
{
	BUG();
	return 0;
}
int nsctlfs_repopulate_root_dir(struct nsctl_namespace *tgt_ns)
{
	BUG();
	return 0;
}

int nsctlfs_show_path(struct seq_file *sf, struct kernfs_node *kf_node,
		     struct kernfs_root *kf_root)
{
	int len = 0;
	return len;
}

static struct kernfs_syscall_ops nsctlfs_syscall_ops = {
//	.show_path		= nsctlfs_show_path,
};

int nsctlfs_setup_root(struct nsctl_namespace *tgt_ns)
{
	int ret = 0;
	printk("nsctl: @ %s line %d", __func__, __LINE__);
	tgt_ns->kfs_root = kernfs_create_root(&nsctlfs_syscall_ops, 0, tgt_ns);
	if (IS_ERR(tgt_ns->kfs_root)) {
		ret = PTR_ERR(tgt_ns->kfs_root);
		return ret;
	}
	tgt_ns->kfs_node = tgt_ns->kfs_root->kn;
	kernfs_get(tgt_ns->kfs_root->kn);

	ret = nsctlfs_populate_root_dir(tgt_ns);
	return ret;
}

static struct dentry *nsctlfs_mount(struct file_system_type *fs_type,
				int flags, const char *unused_dev_name,
				void *data)
{
	struct dentry *dentry;
	struct nsctl_namespace *ns = current->nsproxy->nsctl_ns;
	bool new_sb;

	printk("nsctl: @ %s line %d", __func__, __LINE__);
	dentry = kernfs_mount(fs_type, flags, ns->kfs_root, NSCTLFS_MAGIC, &new_sb);
	/*
	 * In non-init nsctl namespace, instead of root cgroup's dentry,
	 * we return the dentry corresponding to the nsproxied nsctl_ns.
	 */
	if (!IS_ERR(dentry) && ns != &init_nsctl_ns) {
		struct dentry *nsdentry;

		nsdentry = kernfs_node_dentry(ns->kfs_node, dentry->d_sb);
		dput(dentry);
		dentry = nsdentry;
	}

//	if (IS_ERR(dentry) || !new_sb)
//		cgroup_put(&root->cgrp);

	return dentry;
}

static void nsctlfs_kill_sb(struct super_block *sb)
{
	//struct kernfs_root *kf_root = kernfs_root_from_sb(sb);
	//struct nsctl_namespace *ns = kf_root->kn->priv;

	/* Maybe do some cleanups here */

	printk("nsctl: @ %s line %d", __func__, __LINE__);
	kernfs_kill_sb(sb);
}
struct file_system_type nsctl_fs_type = {
	.name = "nsctl",
	.mount = nsctlfs_mount,
	.kill_sb = nsctlfs_kill_sb,
	.fs_flags = FS_USERNS_MOUNT,
};

int nsctl_define_ops(struct nsctl_def *def,
		     char *name,
		     ssize_t	(*read)	 (struct ns_common *ns, char *buf,
					  size_t bytes, loff_t off),
		     ssize_t	(*write) (struct ns_common *ns, char *buf,
					  size_t bytes, loff_t off))
{
	int buflen = strlen(name) + 6;
	struct nsctl_ops *ops = ERR_PTR(-EINVAL);

	printk("nsctl: @ %s line %d", __func__, __LINE__);
	ops = kzalloc(sizeof(struct nsctl_ops), GFP_KERNEL);
	if (!ops)
		return -ENOMEM;
	ops->name = kmalloc(buflen, GFP_KERNEL);
	if (!ops->name)
		goto fail;
	scnprintf(ops->name, buflen-1, "%s.%s",
					(write) ? "cmd" : "var",
					name);
	ops->read = read;
	ops->write = write;

	spin_lock(&def->ops_list_lock);
	list_add(&ops->ops_list_node, &def->ops_list);
	spin_unlock(&def->ops_list_lock);

	return 0;
fail:
	kfree(ops);
	return -ENOMEM;
}

ssize_t nsctlfs_common_clone_read(struct ns_common *ns, char *buf,
				  size_t bytes, loff_t off)
{
	struct nsctl_reg *reg = ns->reg;
	buf = kzalloc(7, GFP_KERNEL);
	buf = "wololo";
	printk("nsctlfs: clone_read ns %s id %d", reg->def->name,
						  reg->id);
	return 6;
}
ssize_t nsctlfs_common_clone_write(struct ns_common *ns, char *buf,
				   size_t bytes, loff_t off)
{
	struct nsctl_reg *reg = ns->reg;
	return 0;
}
ssize_t nsctlfs_common_apply_read(struct ns_common *ns, char *buf,
				  size_t bytes, loff_t off)
{
	struct nsctl_reg *reg = ns->reg;
	return 0;
}
ssize_t nsctlfs_common_apply_write(struct ns_common *ns, char *buf,
				   size_t bytes, loff_t off)
{
	struct nsctl_reg *reg = ns->reg;
	return 0;
}

int nsctl_define_common_ops(
			struct nsctl_def *def,
			int	(*clone) (struct ns_common *ns,
					  struct user_namespace *user_ns),
			int	(*apply) (struct ns_common *ns,
					  struct task_struct *tsk))
{
	int ret = 0;
	if (clone) {
		ret = nsctl_define_ops(def, "clone", nsctlfs_common_clone_read,
						   nsctlfs_common_clone_write);
		if (ret < 0)
			return ret;
		def->clone = clone;
	}
	if (apply) {
		ret = nsctl_define_ops(def, "apply", nsctlfs_common_apply_read,
						   nsctlfs_common_apply_write);
		if (ret < 0)
			return ret;
		def->apply = apply;
	}
	return ret;
}

void nsctl_define_namespace(struct nsctl_def *def)
{
	printk("nsctl: @ %s line %d", __func__, __LINE__);

	spin_lock_init(&def->ops_list_lock);
	INIT_LIST_HEAD(&def->ops_list);

	idr_lock(&nsctl_def_idr);
	def->id = idr_alloc_cyclic(&nsctl_def_idr, def, 1, 0, GFP_KERNEL);
	idr_unlock(&nsctl_def_idr);
}

struct nsctl_reg *alloc_nsctl_reg(void)
{
	return kzalloc(sizeof(struct nsctl_reg), GFP_KERNEL);
}

int nsctl_register_namespace(struct nsctl_reg *reg,
			     struct nsctl_def *def,
			     struct ns_common *nscommon)
{
	
	struct nsctl_namespace *ns;
	int err = -EINVAL;

	if (current && current->nsproxy && current->nsproxy->nsctl_ns)
		ns = current->nsproxy->nsctl_ns;
	else
		ns = &init_nsctl_ns;

	printk("nsctl: @ %s line %d", __func__, __LINE__);

	if (!nscommon || !nscommon->ops)
		goto fail;

	err = -ENOSPC;
	idr_lock(&nsctl_global_reg_idr);
	reg->global_id =
		idr_alloc_cyclic(&nsctl_global_reg_idr, reg, 1, 0, GFP_KERNEL);
	idr_unlock(&nsctl_global_reg_idr);
	if (reg->global_id < 0)
		goto fail;

	if (ns != &init_nsctl_ns) {
		idr_lock(&ns->reg_idr);
		reg->id =
			idr_alloc_cyclic(&ns->reg_idr, reg, 1, 0, GFP_KERNEL);
		idr_unlock(&ns->reg_idr);
		if (reg->id < 0)
			goto fail_idr;
	} else {
		reg->id = reg->global_id;
	}

	
	reg->ns = nscommon;
	reg->def = def;
	kref_init(&reg->kref);
	nscommon->reg = reg;

	if (!ns->kfs_root)
		return 0;

	/* Dir reg stuff creation perhaps here, linking this reg */
	err = nsctlfs_mkregdir(ns, reg);
	if (err < 0)
		goto fail_idr;

	if (ns != &init_nsctl_ns) {
		err = nsctlfs_mkregdir(&init_nsctl_ns, reg);
		if (err < 0)
			goto fail_mkregdir;
	}

	printk("nsctl: registered %s with dir creation", def->name);
	return 1;

fail_mkregdir:
	nsctlfs_rmregdir(ns, reg);
fail_idr:
	idr_lock(&ns->reg_idr);
	idr_remove(&ns->reg_idr, reg->id);
	idr_unlock(&ns->reg_idr);
fail:	return err;
}

int nsctl_deregister_ns(struct nsctl_reg *reg)
{
	BUG();
	return 0;
}

void free_nsctl_reg(struct kref *kref)
{
	BUG();
}

void __init nsctl_init_early(void)
{
	struct nsctl_namespace *ns = &init_nsctl_ns;
	idr_init(&ns->reg_idr);
	printk("nsctl: @ %s line %d", __func__, __LINE__);
}

void nsctl_define_namespaces_static(void)
{
}

struct nsctl_def namespace_def_nsctl = {
	.name = "nsctl",
	.init_ns = &init_nsctl_ns.ns,
};
EXPORT_SYMBOL_GPL(namespace_def_nsctl);

int nsctl_handler_clone(struct ns_common *ns, struct user_namespace *user_ns)
{
	printk("nsctl: @ %s line %d", __func__, __LINE__);
	return 0;
}
int nsctl_handler_apply(struct ns_common *ns, struct task_struct *tsk)
{
	printk("nsctl: @ %s line %d", __func__, __LINE__);
	return 0;
}

void __init nsctl_init(void)
{
	struct nsctl_namespace *ns = &init_nsctl_ns;
	struct nsctl_reg *reg;
	int ret;

	nsctl_define_namespaces_static();

	printk("nsctl: @ %s line %d", __func__, __LINE__);
	nsctl_define_namespace(&namespace_def_nsctl);

	printk("nsctl: @ %s line %d", __func__, __LINE__);
	nsctl_define_common_ops(&namespace_def_nsctl, nsctl_handler_clone,
						      nsctl_handler_apply);

	reg = alloc_nsctl_reg();
	ret = nsctl_register_namespace(reg, &namespace_def_nsctl,
					&init_nsctl_ns.ns);
	if (ret < 0)
		dump_stack();

	nsctlfs_setup_root(ns);

	printk("nsctl: @ %s line %d", __func__, __LINE__);
	WARN_ON(register_filesystem(&nsctl_fs_type));
	printk("nsctl: init");
}
