/*
 * nsctlfs.h
 *
 * Work in progress
 *
 */

#ifndef _LINUX_NSCTLFS_H
#define _LINUX_NSCTLFS_H

#include <linux/slab.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/err.h>
#include <linux/idr.h>
#include <linux/kref.h>
#include <linux/ns_common.h>

struct nsctl_ops;
struct nsctl_def;
struct nsctl_reg;
struct nsctl_namespace;

extern struct nsctl_namespace init_nsctl_ns;
extern const struct proc_ns_operations nsctlns_operations;

extern struct nsctl_def namespace_def_nsctl;

/*
 * Per-namespace-type defined namespace cmd/var operations
 *
 * Each namespace may provide custom operations to configure its instances.
 *
 * ops->name is generated from `name' parameter to nsctl_define_ops() 
 * and follows a convention using "cmd." or "var." prefix, depending
 * whether a write function parameter is provided to the operation.
 *
 * When defining operations of a new namespace, one may use
 * nsctl_define_common_ops to help with defining some commonly repeating ops
 * which all namespaces share.
 *
 */
struct nsctl_ops {
	struct list_head ops_list_node;
	char		 *name;
	ssize_t		(*read)	    (struct ns_common *ns, char *buf,
				     size_t bytes, loff_t off);
	ssize_t		(*write)    (struct ns_common *ns, char *buf,
				     size_t bytes, loff_t off);
};
#ifdef CONFIG_NSCTLFS
extern int nsctl_define_ops(
			struct nsctl_def *def,
			char *name,
			ssize_t	(*read)	 (struct ns_common *ns, char *buf,
					  size_t bytes, loff_t off),
			ssize_t	(*write) (struct ns_common *ns, char *buf,
					  size_t bytes, loff_t off));
extern int nsctl_define_common_ops(
			struct nsctl_def *def,
				/* touch cmd.clone # create new ns   *
				 * cat cmd.clone   # get new ns info */
			int	(*clone) (struct ns_common *ns,
					  struct user_namespace *user_ns),
				/* touch cmd.apply # apply to current task *
				 * cat cmd.apply   # empty                 */
			int	(*apply) (struct ns_common *ns,
					  struct task_struct *tsk));
#endif

/* 
 * Definition of namespace type, 
 *
 * there should be one for each namespace subsys.
 * 
 * For namespaces, that have dynamic init functions, use
 * nsctl_define_namespace() in their respective init()s to initialize a
 * description of new NS definition, then use nsctl_define_ops() to define
 * new commands/variables and handlers for the namespace.
 *
 * Statically initialized namespaces are described to nsctlfs in
 * nsctl_define_namespaces_static().
 * 
 * Namespace definitions are indexed in internal nsctl_def_list.
 *
 */
struct nsctl_def {
	int			id;
	char 			*name;
	spinlock_t		ops_list_lock;
	struct list_head	ops_list;
	struct ns_common	*init_ns;
	int			(*clone) (struct ns_common *ns,
					  struct user_namespace *user_ns);
	int			(*apply) (struct ns_common *ns,
					  struct task_struct *tsk);
};
#ifdef CONFIG_NSCTLFS
extern void nsctl_define_namespace(struct nsctl_def *def);
#endif

/*
 * Namespace instance registration token
 *
 * Each namespace instance should be registered on successful creation with
 * nsctlfs using nsctl_register_namespace().
 *
 * A directory in nsctlfs mountpoint is created, named using convention
 * "%s_%d", namespace_name, namespace_id in given nsctl namespace.
 *
 * Initial nsctl namespace contains directory representations of all namespaces
 * present in the running system.
 * 
 * IDs of namespace instances are unique to each nsctl namespace, to avoid
 * leaking ns usage information to other nsctl namespaces.
 *
 */
struct nsctl_reg {
	int			id;
	int			global_id;
	struct nsctl_def	*def;
	struct kref		kref;
	struct ns_common	*ns;
	struct kernfs_node	*kfs_node;	   // namespaced
	struct kernfs_node	*kfs_node_init_ns; // in init nsctl namespace
};
#ifdef CONFIG_NSCTLFS
extern int nsctl_register_namespace(struct nsctl_reg *reg,
				    struct nsctl_def *def,
				    struct ns_common *nscommon);
extern int nsctl_deregister_ns(struct nsctl_reg *reg);
extern struct nsctl_reg *alloc_nsctl_reg(void);
extern void free_nsctl_reg(struct kref *kref);
static inline struct nsctl_reg *get_nsctl_reg(struct nsctl_reg *e)
{
	if (e)
		kref_get(&e->kref);
	return e;
}
static inline void put_nsctl_reg(struct nsctl_reg *e)
{
	if (e)
		kref_put(&e->kref, free_nsctl_reg);
}
#endif

/*
 * nsctl namespace
 *
 * nsctl itself provides namespacing support, it can only be cloned via the new
 * interface nsctlfs provides with generic cmd.clone command.
 *
 */

struct nsctl_namespace {
	struct ns_common	ns;
	struct kref		kref;
	struct nsctl_namespace	*parent;
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	struct idr		reg_idr;
	struct kernfs_root	*kfs_root;
	struct kernfs_node	*kfs_node;
};
static inline struct nsctl_namespace *to_nsctl_ns(struct ns_common *ns)
{
	return container_of(ns, struct nsctl_namespace, ns);
}
#ifdef CONFIG_NSCTLFS
extern struct nsctl_namespace *clone_nsctl_ns(struct user_namespace *user_ns,
				struct nsctl_namespace *old_ns);
extern struct nsctl_namespace *copy_nsctl_ns(bool new,
				struct user_namespace *user_ns,
				struct nsctl_namespace *old_ns);
extern void free_nsctl_ns(struct kref *kref);
static inline struct nsctl_namespace *get_nsctl_ns(
				struct nsctl_namespace *ns)
{
	if (ns && (ns != &init_nsctl_ns))
		kref_get(&ns->kref);
	return ns;
}
static inline void put_nsctl_ns(struct nsctl_namespace *ns)
{
	if (ns && (ns != &init_nsctl_ns))
		kref_put(&ns->kref, free_nsctl_ns);
}

extern void nsctl_init_early(void);
extern void nsctl_init(void);

#else /* CONFIG_NSCTLFS not defined */
static inline int nsctl_define_ops(
			struct nsctl_def *def,
			char *name,
			ssize_t	(*read)	 (struct ns_common *ns, char *buf,
					  size_t bytes, loff_t off),
			ssize_t	(*write) (struct ns_common *ns, char *buf,
					  size_t bytes, loff_t off))
					{ return NULL; };
static inline int nsctl_define_common_ops(
			struct nsctl_def *def,
			int	(*clone) (struct ns_common *ns,
					  struct user_namespace *user_ns),
			int	(*apply) (struct ns_common *ns,
					  struct task_struct *tsk))
					{ return 0; };
static inline void nsctl_define_namespace(struct nsctl_def *def) { };
static inline int nsctl_register_namespace(struct nsctl_reg *reg,
					   struct nsctl_def *def,
					   struct ns_common *nscommon)
					{ return 0; };
static inline int nsctl_deregister_ns(struct nsctl_reg *reg)
					{ return 0; };
static inline struct nsctl_reg *alloc_nsctl_reg(void)
					{ return NULL; };
static inline void free_nsctl_reg(struct kref *kref) { };
static inline struct nsctl_reg *get_nsctl_reg(struct nsctl_reg *e)
				{ return e; };
static inline void put_nsctl_reg(struct nsctl_reg *e) { };

struct nsctl_namespace *clone_nsctl_ns(struct user_namespace *user_ns,
				struct nsctl_namespace *old_ns);
struct nsctl_namespace *copy_nsctl_ns(bool new,
				struct user_namespace *user_ns,
				struct nsctl_namespace *old_ns);
static inline int setup_nsctl_namespace(struct nsctl_namespace *ns)
					{ return 0; };
static inline void free_nsctl_ns(struct kref *kref) { };
static inline struct nsctl_namespace *get_nsctl_ns(
				struct nsctl_namespace *ns)
					{ return &init_nsctl_ns; };
static inline void put_nsctl_ns(struct nsctl_namespace *ns) { };
static inline void nsctl_init_early(void) { }
static inline void nsctl_init(void) { }
#endif /* CONFIG_NSCTLFS */
#endif /* _LINUX_NSCTLFS_H */
