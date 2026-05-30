#include <linux/kprobes.h>
#include <asm/insn.h>

#include "kprobe_inspect.h"

#define MAX_INSN_NUM 1024
#define SERONUMBER 1
#define NOADDR 2

typedef int (*insn_decode_t)(struct insn* insn,const void* ptr,int bufsz,enum insn_mode mode);

static unsigned char* get_base(struct kprobe_nearby* kp,int i){
	if(!kp->kp.addr){
		if(kp->kp.symbol_name){
			register_kprobe(&(kp->kp));
			unregister_kprobe(&(kp->kp));
		}else return NULL;
	}
	kp->info[i].addr = (unsigned char*)kp->kp.addr;
    unsigned char* base = (unsigned char*)kp->kp.addr;
	return base;
}

static bool kprobe_nearby_next(struct kprobe_nearby* kp,int i,insn_decode_t insn_decode){
	struct insn insn;
	unsigned char* base = get_base(kp,i);
	if(base == NULL){
		return false;
	}
	int ret;
	ret = insn_decode(&insn,(const void*)base,MAX_INSN_SIZE,INSN_MODE_KERN);
	if(ret<0){
		printk(KERN_ERR "insn_decode failed:%d\n",ret);
		return false;
	}
	kp->info[i].length = insn.length;
	kp->next = (unsigned char*)(base+kp->info[i].length);
	return true;
}

static unsigned long get_insn_decode(void){
	typedef unsigned long (*kallsyms_lookup_name_t)(const char* name);
	struct kprobe kp;
	unsigned long addr;
	kp.symbol_name = "kallsyms_lookup_name";
	if(register_kprobe(&kp)<0){
		return register_kprobe(&kp);
	}
	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	kallsyms_lookup_name_t my_kallsyms_lookup_name = (kallsyms_lookup_name_t)addr;
	unsigned long get_insn_decode = my_kallsyms_lookup_name("insn_decode");
	return get_insn_decode;
}


int kprobe_scan_init(struct kprobe_nearby* kp,int num){
	if(kp != NULL){
		memset(kp,0,sizeof(struct kprobe_nearby) + num * sizeof(struct more_info));
	}
	if(num < 0){
	num = -num;
	}
	else if(num == 0){
		return -SERONUMBER;
	}
	if(num > MAX_INSN_NUM){
		num = MAX_INSN_NUM;
	}
	int current_off = 0;
	kp = kmalloc(sizeof(struct kprobe_nearby) + num * sizeof(struct more_info),GFP_KERNEL);
	if(!kp) return -ENOMEM;
	unsigned long insn_addr = get_insn_decode();
	insn_decode_t insn_decode = (insn_decode_t)insn_addr;
	int i;
	for(i=0;i<=num-1;i++){
		if(!kprobe_nearby_next(kp,i,insn_decode)){
			return -NOADDR;
		}
		current_off += kp->info[i].length;
		kp->info[i].offset = current_off;
		if(i==(num-1)){
			kp->next = NULL;
		}
	}
	return 0;
}

int register_batch(struct kprobe_nearby* kp){
	int index = 0;
	if(register_kprobe(&(kp->kp)) !=0){
		printk(KERN_ERR "kprobe_register_batch's kp->kp [%d] is error\n",index);
		return register_kprobe(&(kp->kp));
	}
	while(kp->next!=NULL){
		index++;
		kp->kp.addr = (kprobe_opcode_t*)kp->next;
		if(register_kprobe(&(kp->kp)) !=0){
			printk(KERN_ERR "kprobe_register_batch's kp->kp [%d] is error\n",index);
			return register_kprobe(&(kp->kp));
		}
	}
	return 0;
}

void unregister_batch(struct kprobe_nearby* kp){
	struct kprobe_nearby* p = kp;
	while(p->next != NULL){
		unregister_kprobe(&(p->kp));
		p = (struct kprobe_nearby*)p->next;
	}
	kfree(kp);
}

EXPORT_SYMBOL(kprobe_scan_init);
EXPORT_SYMBOL(register_batch);
EXPORT_SYMBOL(unregister_batch);









