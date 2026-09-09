// SPDX-License-Identifier: GPL-2.0
//go:build ignore

// Tier 2 process probe: independent ground truth for subprocess spawns.
//
// Three tracepoints feed a single ring buffer:
//   * syscalls/sys_enter_execve     -> KIND_EXEC, carries argv
//   * syscalls/sys_enter_exit_group -> caches the exit code, emits nothing
//   * sched/sched_process_exit      -> KIND_EXIT, replays the argv (and exit
//                                      code, if seen) cached at exec
//
// The argv captured at exec time is stashed in a hash map keyed by TGID so the
// exit event can report the same command string, giving the verifier a
// symmetric (exec, exit) pair without reading task_struct via CO-RE.
//
// Exit code: sched_process_exit's tracepoint args don't carry it (that needs
// task_struct via CO-RE). Instead we hook sys_enter_exit_group, which is what
// glibc's exit()/_exit() funnel through in a multi-threaded process, and cache
// the code onto the same execs record. A process killed by an uncaught signal
// never calls exit_group, so has_exit_code stays 0 for it -- that's a real
// "unknown", not a fabricated 0.
//
// argv is stored as MAX_ARGS fixed-width slots rather than packed end-to-end.
// Packing needs a running offset, and a helper write at a variable offset is
// exactly the pattern the BPF verifier struggles to bound through an unrolled
// loop. With slots, every offset is i * ARG_SLOT, a compile-time constant once
// the loop is unrolled, so the program verifies without bounds gymnastics. The
// cost is a fixed buffer and a per-argument length cap; userspace rejoins the
// slots into a command line.
//
// Legacy (non-CO-RE) style on purpose: it needs only <linux/bpf.h> and libbpf's
// bpf_helpers.h, so no vmlinux.h has to be generated or committed.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define ARG_SLOT 128                    // max bytes per argv entry, including NUL
#define MAX_ARGS 12                     // argv entries captured
#define ARGS_BUF (MAX_ARGS * ARG_SLOT)  // total argv bytes carried per event
#define FILENAME_LEN 256                // max bytes for the resolved execve path

#define KIND_EXEC 0
#define KIND_EXIT 1

// struct event carries both `filename` and `args`. `filename` is the path
// the kernel actually resolved and loaded (ctx->filename on sys_enter_execve),
// independent of whatever the caller chose to put in argv. `args` still
// carries argv, including argv[0], for display/forensics, but argv[0] must
// never be trusted as the process's identity: a caller can execve() a binary
// while passing an arbitrary, unrelated argv[0] (classic process
// masquerading), so userspace builds the reported command identity from
// `filename`, not from args[0]. See commandLine() in observer.go.
struct event {
	__u32 pid;
	__u32 kind;
	__u32 nargs;        // number of populated argv slots
	__s64 ts_ns;         // bpf_ktime_get_ns() at exec, or at exit for KIND_EXIT
	__s32 exit_code;     // valid only if has_exit_code is set
	__u8  has_exit_code;
	__u8  is_toplevel;
	char filename[FILENAME_LEN]; // resolved execve path; kernel-observed, not caller-supplied
	char args[ARGS_BUF];
};


struct proc_info {
	__u8 is_shell;
	__u8 is_toplevel;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct proc_info);
} tracked_pids SEC(".maps");

// User space sets this to 1 if we are tracking a specific process tree (PIDFilter > 0).
// If 0, we track everything system-wide and treat all as top-level.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} config_map SEC(".maps");

static __always_inline __u8 get_use_pid_filter() {
	__u32 zero = 0;
	__u8 *val = bpf_map_lookup_elem(&config_map, &zero);
	return val ? *val : 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); // 1 MiB
} events SEC(".maps");

// Per-CPU scratch space: struct event is far too large for the 512-byte BPF
// stack, so it is assembled here and then copied out.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event);
} heap SEC(".maps");

// argv captured at execve, keyed by TGID, replayed on process exit.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct event);
} execs SEC(".maps");

// tracepoint/syscalls/sys_enter_execve argument layout (stable ABI).
struct sys_enter_execve_ctx {
	__u64 pad;
	__s32 syscall_nr;
	__u32 pad2;
	const char *filename;
	const char *const *argv;
	const char *const *envp;
};

// tracepoint/sched/sched_process_exit argument layout (stable ABI).
struct sched_process_exit_ctx {
	__u64 pad;
	char comm[16];
	__s32 pid;
	__s32 prio;
};

// tracepoint/syscalls/sys_enter_exit_group argument layout (stable ABI).
// error_code is the raw syscall arg: reported by the kernel as size 8
// (syscall args are always captured as a padded long), so read it as u64
// and take the low 32 bits.
struct sys_enter_exit_group_ctx {
	__u64 pad;
	__s32 syscall_nr;
	__u32 pad2;
	__u64 error_code;
};


struct task_newtask_ctx {
	__u64 pad;
	__s32 pid;
	char comm[16];
	__u64 clone_flags;
	__s16 oom_score_adj;
};

SEC("tracepoint/task/task_newtask")
int handle_fork(struct task_newtask_ctx *ctx)
{
	if (!get_use_pid_filter())
		return 0;

	__u32 parent_pid = bpf_get_current_pid_tgid() >> 32;
	__u32 child_pid = ctx->pid;

	struct proc_info *p = bpf_map_lookup_elem(&tracked_pids, &parent_pid);
	if (!p)
		return 0;

	struct proc_info child = {0};
	// A direct child of the shell is a top-level command.
	if (p->is_shell) {
		child.is_toplevel = 1;
	} else {
		// Grandchildren are forensic-grade.
		child.is_toplevel = 0;
	}

	bpf_map_update_elem(&tracked_pids, &child_pid, &child, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct sys_enter_execve_ctx *ctx)
{
	__u32 zero = 0;
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	struct event *e = bpf_map_lookup_elem(&heap, &zero);
	if (!e)
		return 0;

	e->pid = pid;
	e->kind = KIND_EXEC;
	if (get_use_pid_filter()) {
		struct proc_info *p = bpf_map_lookup_elem(&tracked_pids, &pid);
		if (!p)
			return 0;
		e->is_toplevel = p->is_toplevel;
	} else {
		e->is_toplevel = 1;
	}

	e->ts_ns = bpf_ktime_get_ns();
	e->exit_code = 0;
	e->has_exit_code = 0;

	// Read the kernel-resolved path directly, not from argv. This is the
	// field the verifier trusts as the process's real identity.
	e->filename[0] = '\0';
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), ctx->filename);

	__u32 nargs = 0;
	int done = 0;

#pragma clang loop unroll(full)
	for (int i = 0; i < MAX_ARGS; i++) {
		// i * ARG_SLOT is constant per unrolled iteration, so both this
		// store and the helper read below are trivially in-bounds.
		e->args[i * ARG_SLOT] = '\0';
		if (done)
			continue;

		const char *argp = NULL;
		if (bpf_probe_read_user(&argp, sizeof(argp), &ctx->argv[i]) || !argp) {
			done = 1;
			continue;
		}

		long n = bpf_probe_read_user_str(&e->args[i * ARG_SLOT], ARG_SLOT, argp);
		if (n <= 0) {
			e->args[i * ARG_SLOT] = '\0';
			done = 1;
			continue;
		}
		nargs = i + 1;
	}
	e->nargs = nargs;

	bpf_map_update_elem(&execs, &pid, e, BPF_ANY);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}

// sys_enter_exit_group fires before the process is actually gone, so it just
// updates the cached execs record in place; sched_process_exit does the
// emitting. Fires only for processes that exit via exit()/_exit() rather than
// an uncaught signal.
SEC("tracepoint/syscalls/sys_enter_exit_group")
int handle_exit_group(struct sys_enter_exit_group_ctx *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	struct event *cached = bpf_map_lookup_elem(&execs, &tgid);
	if (!cached)
		return 0;

	// This is a pointer into the map's own storage (BPF_MAP_TYPE_HASH), so
	// the write lands directly in the cached record without a re-update.
	cached->exit_code = (__s32)ctx->error_code;
	cached->has_exit_code = 1;
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct sched_process_exit_ctx *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	__u32 tid = (__u32)id;

	// Only the thread-group leader's exit means the process is gone.
	if (tgid != tid)
		return 0;

	struct event *cached = bpf_map_lookup_elem(&execs, &tgid);
	if (!cached)
		return 0;

	__u32 zero = 0;
	struct event *e = bpf_map_lookup_elem(&heap, &zero);
	if (e) {
		// sizeof(struct event) is past clang's inline-memcpy threshold, so
		// copy the cached exec record out of the map with a helper. This
		// carries over exit_code/has_exit_code set by handle_exit_group, if
		// it fired.
		bpf_probe_read_kernel(e, sizeof(*e), cached);
		e->kind = KIND_EXIT;
		e->ts_ns = bpf_ktime_get_ns(); // actual exit time, not the exec time
		bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	}

	bpf_map_delete_elem(&execs, &tgid);
	if (get_use_pid_filter()) {
		bpf_map_delete_elem(&tracked_pids, &tgid);
	}
	return 0;

}
