#ifndef KPROBE_SCAN_H
#define KPROBE_SCAN_H

#define MAX_INSN_NUM 1024
#define ZERONUMBER 1
#define NOADDR 2
#define UNKNOWNERR 3
#define EINIT 4
#define INVALIDADDR 5
#define FIRSTREGISTERED 6
#define NOKMALLOC 7
#define STR(sym) #sym

struct more_info{
	struct kprobe kp;
	size_t length;
	long offset;
	bool registered;
};

struct kprobe_nearby{
	struct kprobe current_kp;
	unsigned int count;
	struct more_info* info[];
};

void kprobe_init(struct kprobe* kp);
int kprobe_nearby_scan(struct kprobe_nearby* kp,int num);
struct kprobe_nearby* kprobe_scan(struct kprobe* p,int num);
unsigned long get_symaddr_from_name(const char* name);
int kprobe_scan_release(struct kprobe_nearby* kp);
int register_batch(struct kprobe_nearby* kp);
void unregister_batch(struct kprobe_nearby* kp);

#endif
