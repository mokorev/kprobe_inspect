#ifndef KPROBE_SCAN_H
#define KPROBE_SCAN_H

struct kprobe_nearby{
	struct kprobe kp;
	unsigned char* next;
	struct more_info info[];
}

int kprobe_scan_init(struct kprobe_nearby* kp,int num);
int register_batch(struct kprobe_nearby* kp);
void unregister_batch(struct kprobe_nearby* kp);

#endif
