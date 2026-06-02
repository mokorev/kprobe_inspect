#include <linux/kprobes.h>
#include <asm/insn.h>

#include "kprobe_inspect.h"

typedef int (*insn_decode_t)(struct insn* insn,const void* ptr,int bufsz,enum insn_mode mode);
typedef int (*kallsyms_lookup_size_offset_t)(unsigned long addr,unsigned long* symbolsize,unsigned long* offset);

void kprobe_init(struct kprobe* kp){
	if(!kp->addr){
                if(kp->symbol_name){
                        register_kprobe(kp);
                        unregister_kprobe(kp);
                }else return;
        }
        if(!kp->symbol_name){
                if(kp->addr){
                    	register_kprobe(kp);
                    	unregister_kprobe(kp);
                }
        }
}

unsigned long get_symaddr_from_name(const char* name){
	typedef unsigned long (*kallsyms_lookup_name_t)(const char* name);
	struct kprobe kp;
	unsigned long addr;
	kp.symbol_name = "kallsyms_lookup_name";
	if(register_kprobe(&kp)<0){
		return 0;
	}
	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	kallsyms_lookup_name_t my_kallsyms_lookup_name = (kallsyms_lookup_name_t)addr;
	unsigned long get_addr_from_name = my_kallsyms_lookup_name(name);
	return get_addr_from_name;
}

int kprobe_nearby_scan(struct kprobe_nearby* kp,int num){
	if(!kp){
		printk(KERN_ERR "please kmalloc for your kprobe_nearby struct!");
		return -NOKMALLOC;
	}
	if(!kp->current_kp.addr){
		pr_err("no current_kp.addr!\n");
		return -NOADDR;
	}
	kprobe_init(&(kp->current_kp));
	if(num < 0){
		num = -num;
	}
	else if(num == 0){
		return -ZERONUMBER;
	}
	if(num > MAX_INSN_NUM){
		num = MAX_INSN_NUM;
	}
	unsigned long lookup_size_addr = get_symaddr_from_name("kallsyms_lookup_size_offset");
	if(!lookup_size_addr){
		printk(KERN_ERR "error from kprobe_nearby_scan's get_symaddr_from_name('kallsyms_lookup_size_offset')");
		return lookup_size_addr;
	}
	pr_info("get lookup_size_addr!\n");
	kallsyms_lookup_size_offset_t lookup_size = (kallsyms_lookup_size_offset_t)lookup_size_addr;
	unsigned long target_size;
	unsigned long target_offset;
	int result_lookup = lookup_size((unsigned long)kp->current_kp.addr,&target_size,&target_offset);
	if(!result_lookup){
		printk(KERN_ERR "error from kprobe_nearby_scan's lookup_size\n");
		return result_lookup;
	}
	target_size -= target_offset;
	pr_info("get the target's real size!it's: %d",target_size);
	unsigned long insn_addr = get_symaddr_from_name("insn_decode");
	if(insn_addr<0){
		printk(KERN_ERR "error from kprobe_nearby_scan's get_symaddr_from_name('insn_decode')\n");
		return insn_addr;
	}
	pr_info("get the insn_addr!\n");
	insn_decode_t insn_decode = (insn_decode_t)insn_addr;
	unsigned long current_off = 0;
	int i;
	struct insn* insn;
	insn = kmalloc(sizeof(struct insn),GFP_KERNEL);
	if(!insn) return -NOKMALLOC;
	memset(insn,0,sizeof(struct insn));
	int ret;
	ret = insn_decode(insn,(const void*)kp->current_kp.addr,MAX_INSN_SIZE,INSN_MODE_KERN);
	pr_info("get the insn_decode's real number,it's %d\n",insn->length);
	kp->info[0] = kmalloc(sizeof(struct more_info),GFP_KERNEL);
    memset(kp->info[0],0,sizeof(struct more_info));
	kp->info[0]->kp.addr = kp->current_kp.addr;
	kp->info[0]->length = insn->length;
	kp->info[0]->offset = 0;
	kp->info[0]->kp.pre_handler = kp->current_kp.pre_handler;
	kp->info[0]->kp.post_handler = kp->current_kp.post_handler;
	kp->count = 1;
	pr_info("current_kp.addr:%px, info[0]->kp.addr:%px,length:%d",kp->current_kp.addr,kp->info[0]->kp.addr,kp->info[0]->length);
	unsigned char* cursor = (unsigned char*)kp->current_kp.addr;
	for(i = 0;i+1 < num;i++){
		cursor = (unsigned char*)kp->info[i]->kp.addr + kp->info[i]->length;
		pr_info("temp_kp.add:%px\n",cursor);
        ret = insn_decode(insn,(const void*)cursor,MAX_INSN_SIZE,INSN_MODE_KERN);
        if(ret<0){
                printk(KERN_ERR "insn_decode failed:%d\n",ret);
                return false;
		}
		if((current_off+insn->length) > target_size){
                printk(KERN_ERR "target's size is to short,the scan was scan %d\n",i+1);
                return i+1;
        }
		kp->info[i+1] = kmalloc(sizeof(struct more_info),GFP_KERNEL);
		memset(kp->info[i+1],0,sizeof(struct more_info));
		pr_info("insn->length:%d\n",insn->length);
		kp->info[i+1]->kp.addr = (kprobe_opcode_t*)cursor;
		kp->info[i+1]->length = insn->length;
		kp->info[i+1]->offset = (long)(cursor-(unsigned char*)kp->current_kp.addr);
		kp->info[i+1]->kp.pre_handler = kp->current_kp.pre_handler;
		kp->info[i+1]->kp.post_handler = kp->current_kp.post_handler;
		kp->count++;
		pr_info("current_kp.addr:%px, info[%d]->kp.addr:%px,length:%d,offset:%d\n",kp->current_kp.addr,i+1,kp->info[i+1]->kp.addr,kp->info[i+1]->length,kp->info[i+1]->offset);
	}
	pr_info("count's num = %d\n",kp->count);
	return 0;
}

struct kprobe_nearby* kprobe_scan(struct kprobe* p,int num){
	struct kprobe_nearby* kp;
	unsigned long addr_p;
	const char* name_p;
	bool is_addr;
	if(p->addr){
		addr_p = (unsigned long)p->addr;
		is_addr = true;
	}
	if(p->symbol_name){
		name_p = p->symbol_name;
		is_addr = false;
	}
	if(!addr_p && !name_p){
		printk(KERN_ERR "your cant give a sero kprobe!");
		return NULL;
	}
	kp = kmalloc(sizeof(*kp) + num*sizeof(struct more_info*),GFP_KERNEL);
	if(!kp) return NULL;
	memset(kp,0,sizeof(*kp));
	kp->current_kp = *p;
	if(is_addr){
		kp->current_kp.addr = (kprobe_opcode_t*)addr_p;
	}else kp->current_kp.symbol_name = name_p;
	int result = kprobe_nearby_scan(kp,num);
	if(result>0){
		printk(KERN_ERR "it's to short,only kprobe %d\n",result);
        	return kp;
	}
	switch(result){
		case -ZERONUMBER:
			printk(KERN_ERR "ZERONUMBER in num\n");
			return NULL;
			break;
		case -NOADDR:
			printk(KERN_ERR "ADDR_ERRO in kprobe_inspect,or insn_decode is erroring!\n");
			return NULL;
			break;
		case -EINIT:
			printk(KERN_ERR "EINIT is in base_init is error!");
		case 0:
			return kp;
			break;
		default:
			printk(KERN_ERR "please help by yourself,the cause of error is usually found in dmesg!\n");
			return NULL;
			break;
	}
}

int register_batch(struct kprobe_nearby* kp){
	if(!kp){
		printk(KERN_ERR "invalid address!");
		return -INVALIDADDR;
	}
	int unmiss = 0;
	if(kp->info[0]->registered){
		printk(KERN_ERR "the first kprobe is registered!\n");
		return -FIRSTREGISTERED;
	}
	int result_register_first = register_kprobe(&(kp->info[0]->kp));
	if(result_register_first != 0){
		printk(KERN_ERR "kprobe_register_batch's kp->info->kp [0](current kp) is error\n");
		return result_register_first;
	}
	kp->info[0]->registered = true;
	unsigned int index;
	for(index = 1;index < kp->count;index++){
		if(!kp->info[index]){
			printk(KERN_ERR "register_batch's error is info[%d]!",index);
			unmiss++;
			printk(KERN_ERR "register_kprobe's unmiss is %d",unmiss);
			continue;
		}
		if(kp->info[index]->registered){
			printk(KERN_ERR "info[%d] is registered!unmiss+1!\n");
			unmiss++;
			printk(KERN_ERR "register_kprobe's unmiss is %d",unmiss);
			continue;
		}
		switch(register_kprobe(&kp->info[index]->kp)){
			case 0:
				kp->info[index]->registered = true;
				break;
			case 1:
				printk(KERN_ERR "the info[%d] is be register_kprobe away from error code: 1\n");
                        	unmiss++;
				printk(KERN_ERR "register_kprobe's unmiss is %d",unmiss);
                        	continue;
				break;
			default:
				printk(KERN_ERR "kprobe_register_batch's kp->kp [%d] is error,the error code is:%d\n",index,register_kprobe(&(kp->info[index]->kp)));
				unmiss++;
				printk(KERN_ERR "register_kprobe's unmiss is %d",unmiss);
				continue;
				break;
		}
	}
	return 0;
}

void unregister_batch(struct kprobe_nearby* kp){
	struct kprobe_nearby* p = kp;
	int list_num;
	int unmiss = 0;
	for(list_num = 0;list_num < kp->count;list_num++){
		if(p->info[list_num]->registered){
			unregister_kprobe(&(p->info[list_num]->kp));
			p->info[list_num]->registered = false;
		}else unmiss++;
		if(kp->info[list_num]){
			kfree(kp->info[list_num]);
		}
	}
	printk(KERN_INFO "unregister_batch's unmiss number:%d\n",unmiss);
	kfree(kp);
}

int kprobe_scan_release(struct kprobe_nearby* kp){
	int unregister_num = 0;
	struct kprobe_nearby* p = kp;
	int list_num;
	for(list_num = 0;list_num <= kp->count;list_num++){
		if(p->info[list_num]->registered){
			unregister_kprobe(&(p->info[list_num]->kp));
			unregister_num++;
		}
		kfree(kp->info[list_num]);
	}
	printk(KERN_INFO "release's list has %d\n",list_num);
	return unregister_num;
}


EXPORT_SYMBOL(kprobe_scan);
EXPORT_SYMBOL(kprobe_nearby_scan);
EXPORT_SYMBOL(register_batch);
EXPORT_SYMBOL(unregister_batch);
EXPORT_SYMBOL(kprobe_scan_release);
EXPORT_SYMBOL(kprobe_init);
EXPORT_SYMBOL(get_symaddr_from_name);














