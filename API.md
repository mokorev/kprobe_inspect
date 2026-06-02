# API Reference

This document describes the public functions and data structures provided by `kprobe_inspect`.

## Core API

### `kprobe_scan()`

```c
struct kprobe_nearby *kprobe_scan(struct kprobe *template, unsigned int max_insns);
```

Description
Scans forward from the probe address given in template (either by symbol_name or addr), decodes up to max_insns instructions, and creates a kprobe_nearby structure that holds the instruction information. Memory for the structure and its internal arrays is allocated automatically.

Parameters

- template – a partially filled struct kprobe that specifies the starting probe (must contain either symbol_name or addr). You may also set pre_handler / post_handler – they will be copied to the first instruction entry.
- max_insns – maximum number of instructions to scan (actual number may be smaller due to function boundary or decode failure).

Returns
A pointer to a kprobe_nearby structure on success, or NULL on failure (e.g., invalid address, out of memory).

Note
The actual number of scanned instructions is stored in kp_nearby->count. Always rely on kp_nearby->count instead of the requested max_insns – the scan may stop earlier because of function boundaries or decoding failures.

---
## Internal / Not recommended

### `kprobe_nearby_scan()`

This function is used internally by `kprobe_scan()` and **not intended for direct use**. Calling it directly may lead to incorrect behavior because it assumes the `kp` structure and its `info` array have already been allocated correctly. **Use `kprobe_scan()` instead.**

register_batch()

```c
int register_batch(struct kprobe_nearby *kp_nearby);
```

Description
Registers all kprobes stored in the kprobe_nearby structure (including the first instruction and every successfully scanned instruction). It automatically sets the pre_handler (and optionally post_handler) from the template probe used in kprobe_scan().

Parameters

- kp_nearby – structure returned by kprobe_scan().

Returns
Number of probes successfully registered (may be less than kp_nearby->count on error). Negative values indicate serious errors (e.g., kp_nearby is NULL).

Note
Calling register_batch twice on the same kp_nearby will fail (probes already registered). Use unregister_batch to clean up first.

---

unregister_batch()

```c
void unregister_batch(struct kprobe_nearby *kp_nearby);
```

Description
Unregisters all kprobes that were previously registered by register_batch() and frees the internal more_info entries. The kp_nearby structure itself is not freed; you must call kfree(kp_nearby) afterwards if you allocated it manually (but kprobe_scan() already allocates it, so you should free it when no longer needed).

Parameters

- kp_nearby – structure returned by kprobe_scan().

Returns
Nothing.

---

kprobe_release()

```c
void kprobe_release(struct kprobe_nearby *kp_nearby);
```

Description
Frees all internal more_info entries and the kp_nearby structure itself. It does not unregister any probes (use unregister_batch() first if probes were registered). This is intended for scenarios where you only want to inspect instruction information without activating probes.

Parameters

- kp_nearby – structure returned by kprobe_scan().

Returns
Nothing.

---

Utility Functions (Advanced)

get_symaddr_from_name()

```c
unsigned long get_symaddr_from_name(const char *name);
```

Description
Dynamically resolves a kernel symbol name to its address using a temporarily registered kprobe on kallsyms_lookup_name. Useful when you need a function address without manually reading /proc/kallsyms.

Parameters

- name – kernel symbol name (e.g., "printk").

Returns
The symbol address as unsigned long, or 0 if the symbol cannot be found.

Example

```c
unsigned long addr = get_symaddr_from_name("__x64_sys_getdents64");
```

kprobe_init()

```c
void kprobe_init(struct kprobe *kp);
```

Description
Helper function that ensures the addr field of kprobe is valid. If symbol_name is provided but addr is NULL, it temporarily registers and unregisters the probe to let the kernel fill in the address. This is normally not needed because kprobe_scan() performs this internally.

Parameters

- kp – pointer to a struct kprobe.

Returns
Nothing.

---

Data Structures

struct kprobe_nearby

```c
struct kprobe_nearby {
    struct kprobe current_kp;    // the starting probe (same as info[0].kp)
    unsigned int count;           // number of valid entries in info[]
    struct more_info *info[];     // flexible array of instruction information
};
```

struct more_info

```c
struct more_info {
    struct kprobe kp;      // kprobe structure for this instruction
    size_t length;          // instruction length in bytes
    long offset;            // byte offset from the starting probe address
    bool registered;        // whether this probe has been successfully registered
};
```

---

Error Handling

· Functions that return pointers (kprobe_scan) return NULL on failure.
· register_batch returns the number of successfully registered probes (0 on complete failure). Check dmesg for detailed error messages (e.g., insn_decode failures).
· Memory is automatically managed by kprobe_scan and kprobe_release; do not manually kfree internal fields unless you know what you are doing.

---

Thread Safety

The functions are not reentrant. Do not call them concurrently from multiple threads or interrupt contexts. A single kprobe_nearby structure should be used only by one execution context at a time.

---

Example: Full Workflow

```c
#include "kprobe_inspect.h"

static int my_handler(struct kprobe *p, struct pt_regs *regs) {
    printk(KERN_INFO "probe hit at %px\n", p->addr);
    return 0;
}

static int __init test_init(void) {
    struct kprobe kp = {
        .symbol_name = "__x64_sys_getdents64",
        .pre_handler = my_handler
    };
    struct kprobe_nearby *kn = kprobe_scan(&kp, 5);
    if (!kn) return -ENOMEM;

    register_batch(kn);
    // ... later ...
    unregister_batch(kn);
    return 0;
}
module_init(test_init);
```

---

See also

- README for quick start and known limitations.
- examples/ for complete working examples.
