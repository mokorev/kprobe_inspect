#include <linux/kprobes.h>
#include <asm/insn.h>

#include "test_kprobe_scan.h"

#define MAX_INSN_NUM 1024
#define SERONUMBER 1
#define NOADDR 2

struct more_info{
	size_t length;
	unsigned char* addr;
	int offset;
}

struct kprobe_nearby{
	struct kprobe kp;
	unsigned char* next;
	struct more_info info[];
}

static unsigned char* get_base(struct kprobe_nearby* kp,int i){
	if(!kp->kp.addr){
		return NULL;
	}
        kp->info[i].addr = (unsigned char*)kp->kp.addr;
        unsigned char* base = (unsigned char*)kp->kp.addr;
	return base;
}

static int kprobe_nearby_next(struct kprobe_nearby* kp,int i){
	struct insn insn;
	unsigned char* base = get_base(kp,i);
	if(base=NULL){
		return NULL;
	}
#ifdef __x86_64__
	bool x86_64 = true;
#else
	bool x86_64 = false;
#endif
	insn_init(&insn,(const void*)base,MAX_INSN_SIZE,x86_64);
	insn_get_length(&insn);
	kp->info[i].length = insn.length;
	kp->next = (unsigned char*)(base+kp->info[i].length)
	return 0;
}

int kprobe_scan_init(struct kprobe_nearby* kp,int num){
	memset(kp,0,sizeof(struct kprobe_nearby) + num * sizeof(struct more_info));
	if(num < 0){
		num = -num;
	}
	else if(num == 0) return -SERONUMBER;
	if(num > MAX_INSN_NUM){
		num = MAX_INSN_NUM;
	}
	int current_off=0;
	kp = kmalloc(sizeof(struct kprobe_nearby) + num * sizeof(struct more_info),GFP_KERNEL);
	if(!kp) return -ENOMEM;
	for(i=0;i<=num-1;i++){
		if(kprobe_nearby_next(kp,i)){
			return -NOADDR;
		}
		current_off += kp->info[i].length
		kp->info[i].offset = current_off;
		if(i=num-1){
			kp->next = NULL;
		}
	}
}

int register_batch(struct kprobe_nearby* kp){
	int index=0;
	if(register_handler(&(kp->kp) !=0){
		printk(KERN_ERR "kprobe_register_batch's kp->kp [%d] is error\n",index);
		return register_handler(&(kp->kp));
	}
	while(kp->next!=NULL){
		index++;
		kp->kp.addr = (kprobe_opcode_t*)kp->next
		if(register_handler(&(kp->kp) !=0)){
			printk(KERN_ERR "kprobe_register_batch's kp->kp [%d] is error\n",index);
			return register_handler(&(kp->kp));
		}
	}
	return 0;
}

void unregister_batch(struct kprobe_nearby* kp){
	int index=0;
	struct kprobe_nearby* p = kp;
	while(p->next! = NULL){
		unregister(&(p->kp));
		p = (struct kprobe_nearby*)p->next;
	}
	kfree(kp);
}

EXPORT_SYMBOL(kprobe_scan_init);
EXPORT_SYMBOL(register_batch);
EXPORT_SYMBOL(unregister_batch);









