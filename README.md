# kprobe_inspect
A lightweight Linux kernel tool that automatically scans instruction boundaries and batch-registers kprobes, enabling rapid debugging of probe-related issues like register corruption.

---

## Because of a register error, I decided to create a tool that can quickly scan a range of instructions and batch‑register probes.

---

## When can this tool dramatically improve your efficiency?

- **Pinpoint the exact instruction during a system crash**  
  When a crash occurs, you often only know which function failed, but not the exact instruction – especially when registers are unexpectedly corrupted. `kprobe_inspect` automatically handles instruction and function boundaries, supports up to 1024 instructions, and lets you cover any suspicious instruction range with one click.

- **Instruction‑level trace for vulnerability analysis and reproduction**  
  When you need to trace a vulnerable function instruction by instruction, `kprobe_inspect` acts as an automated precision microscope, freeing you from tedious “ground‑sweeping” work and allowing you to focus on the real problematic instructions.

- **When eBPF’s performance overhead is too high for a large number of probes**  
  If you need many probes and eBPF’s overhead becomes a bottleneck, give `kprobe_inspect` a try. It will not be slower than eBPF, and the author will continue to optimize its performance.

---

## What you should care about – the biggest advantage

**No external disassembler – pure kernel‑native.**  
`kprobe_inspect` relies solely on the Linux kernel's built‑in `insn` decoder. No third‑party libraries, no extra dependencies, perfect consistency with the kernel’s own instruction interpretation.
This lightweight, easy‑to‑use tool offers you just three core functions:  kprobe_scan, register_batch, and unregister_batch.

**Tiny footprint.**
 The core source file is only 8.44KB(less than 300 lines of code),making it easy to audit and integrate.

Here’s a quick example to help you understand how to use it:
```c
struct kprobe kp;
kp.pre_handler = my_handler;
kp.post_handler = my_post_handler;

struct kprobe_nearby* kp_nearby;
kp_nearby = kprobe_scan(&kp, number);  
// Give it a prepared probe and the number of instructions to scan forward.
// It returns a kprobe_nearby structure. If you only need batch insertion,
// you may not need to know the details of kprobe_nearby.

register_batch(kp_nearby); // This activates the probes.

/* If you want to unregister the probes that were batch‑activated via the kprobe_nearby structure, do this: */
unregister_batch(kp_nearby);

/* If you did NOT activate the probes, and only need to inspect instruction information around the starting probe, and finally want to free the memory, do this: */
kprobe_release(kp_nearby);

/* Below are the basic fields of the kprobe_nearby structure in the current version: */
struct kprobe_nearby {
    struct kprobe current_kp;          // your initial probe; info[0] always stores identical information.
                                       // To retrieve the kprobe_nearby structure directly from a kprobe,
                                       // use container_of(kp, struct kprobe_nearby, current_kp).
    unsigned int count;                // Number of successfully inserted probes.
                                       // Note that it may not equal the number you requested if the function boundary is reached.
                                       // For safety, always rely on this value.
    struct more_info* info[];          // The array of instruction information; see below for details.
};

struct more_info {
    struct kprobe kp;                  // If you need details of the probe at this instruction, look here.
    size_t length;                     // Length of this instruction.
    long offset;                       // Offset from the initial probe.
    bool registered;                   // Registration status: true means already registered.
};
```
---

## Known limitations

- *Architecture support*: Currently only x86 and x86‑64 (x64) are supported.  
- *Instruction decoder*: The kernel's `insn` engine may fail to decode certain rare or special instructions (e.g., `ud0`). In such cases, probe registration for that instruction will be skipped.

---

## Requirements

- **Architecture**: x86 / x86-64 only.
- **Kernel configuration**: Ensure the following options are enabled in your kernel config (`/boot/config-$(uname -r)`):

· Kernel headers: The build system needs the kernel headers matching your running kernel.

  ```text
  CONFIG_KPROBES=y
  CONFIG_MODULES=y
  CONFIG_MODULE_UNLOAD=y
  CONFIG_KALLSYMS=y
  CONFIG_X86_DECODER=y   # or CONFIG_INSN_DECODER
  ```
---
## Frequently Asked Questions

### 1. Compilation fails with `insn_decode` undefined.

**A:** `insn_decode` is an x86-specific kernel function that may not be exported on all kernels. `kprobe_inspect` dynamically resolves it via `kallsyms_lookup_name`. Make sure your kernel has `CONFIG_KALLSYMS=y` and `CONFIG_X86_DECODER=y` (or `CONFIG_INSN_DECODER`). Also ensure you are running an x86‑64 kernel.

### 2. `register_batch` returns success but my probe handler is never called.

**A:** Double‑check that:
- You have set `pre_handler` (and/or `post_handler`) for each probe before calling `register_batch`.
- The probed function is actually executed. For example, `__x64_sys_getdents64` is called when you run `ls` or `find`.
- Your `printk` messages are not filtered out by the console log level (run `dmesg` to see them).

### 3. How do I know if my kernel supports `kprobe_inspect`?

**A:** Run the following commands:
```bash
grep -E "CONFIG_KPROBES|CONFIG_MODULES|CONFIG_KALLSYMS|CONFIG_X86_DECODER" /boot/config-$(uname -r)
```
---
## License

This project is licensed under the GNU General Public License v2.0 (GPL-2.0). See the [LICENSE](LICENSE) file for details.
---
## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests on GitHub.

- **Reporting bugs**: Provide your kernel version, architecture, and a minimal test case.
- **Code contributions**: Follow the existing coding style and ensure `make` compiles without warnings.
- **Adding support for other architectures**: The instruction decoder (`insn`) is x86‑only for now; ARM64 or RISC‑V support would be a great addition.
---
##  ⚠️Important: Never call kprobe_inspect functions from within kprobe handlers

The functions provided by `kprobe_inspect` (e.g., `kprobe_scan`, `register_batch`, `unregister_batch`, `kprobe_release`) **must not** be called from your `pre_handler` or `post_handler`. These handlers run in atomic context (interrupts disabled, possibly holding locks). Calling functions that may sleep (`kmalloc`, `insn_decode`, etc.) or that modify kprobe state will lead to kernel crashes, deadlocks, or undefined behavior.

**Safe actions inside handlers:**  
- Simple `printk` or `pr_info`.  
- Reading registers.  
- Incrementing counters (using atomic operations).  
- Setting flags.

**Unsafe actions (forbidden):**  
- Any memory allocation (`kmalloc`).  
- Any function that might sleep.  
- Registering or unregistering kprobes.  
- Calling any `kprobe_inspect` API function.

