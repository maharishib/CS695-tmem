#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/uuid.h>
#ifdef CONFIG_CLEANCACHE
#include <linux/cleancache.h>
#endif
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Maharishi Bhargava");
MODULE_VERSION("0.1");
#ifdef CONFIG_CLEANCACHE

#define INIT_ID 100
#define INIT_SHARED_ID 101
#define GET_PAGE_ID 102
#define PUT_PAGE_ID 103
#define INVALIDATE_PAGE_ID 104
#define INVALIDATE_INODE_ID 105
#define INVALIDATE_FS_ID 106

static int glayer_cc_init_fs(size_t pagesize){
	int ret = -1;
	asm volatile("vmcall":
			"=a"(ret):
			"a"(INIT_ID),"D"(pagesize):
			"cc");
	return ret;
}
static int glayer_cc_init_shared_fs(uuid_t *uuid, size_t pagesize){
	int ret = -1;
	asm volatile("vmcall":
			"=a"(ret):
			"a"(INIT_SHARED_ID),"D"(uuid),"S"(pagesize):
			"cc");
	return 0;
}
static int glayer_cc_get_page(int pool_id,struct cleancache_filekey key,pgoff_t index, struct page *page){
	int ret = -1;
	asm volatile("vmcall":
			"=a"(ret):
			"a"(GET_PAGE_ID),"D"(pool_id),"S"(&key),"d"(index),"c"(page):	//INCOMPLETE
			"cc");
	return 0;
}
static void glayer_cc_put_page(int pool_id,struct cleancache_filekey key,pgoff_t index,struct page *page){
	int ret = -1;
	asm volatile("vmcall":
			"=a"(ret):
			"a"(PUT_PAGE_ID),"D"(pool_id),"S"(&key),"d"(index),"c"(page):	//INCOMPLETE
			"cc");
	return ret;
}
static void glayer_cc_invalidate_page(int pool_id, struct cleancache_filekey key, pgoff_t index){
	int ret = -1;
	asm volatile("vmcall":
			"=a"(ret):
			"a"(INVALIDATE_PAGE_ID),"D"(pool_id),"S"(&key),"d"(index):
			"cc");
	return ret;
}
static void glayer_cc_invalidate_inode(int pool_id, struct cleancache_filekey key){

	int ret = -1;
	asm volatile("vmcall":
			"=a"(ret):
			"a"(INVALIDATE_INODE_ID),"D"(pool_id),"S"(&key):	//INCOMPLETE
			"cc");
	return ret;
}
static void glayer_cc_invalidate_fs(int pool_id){	
	int ret = -1;
	asm volatile("vmcall":
			"=a"(ret):
			"a"(INVALIDATE_FS_ID),"D"(pool_id):
			"cc");
	return ret;
}

static struct cleancache_ops glayer_cc_ops ={
	.init_fs = glayer_cc_init_fs,
	.init_shared_fs = glayer_cc_init_shared_fs,
	.get_page = glayer_cc_get_page,
	.put_page = glayer_cc_put_page,
	.invalidate_page = glayer_cc_invalidate_page,
	.invalidate_inode = glayer_cc_invalidate_inode,
	.invalidate_fs = glayer_cc_invalidate_fs
};

int glayer_cc_register_ops(void){
	printk(KERN_INFO "glayer: registering ops\n");
	return cleancache_register_ops(&glayer_cc_ops);
	
}
#endif
static int __init func_init(void){
	int ret;
	printk(KERN_INFO "glayer: msg from init\n");
	#ifdef CONFIG_CLEANCACHE
	printk(KERN_INFO "glayer: cleancache=true\n");
	ret = glayer_cc_register_ops();
	printk(KERN_INFO "glayer: return of register_ops %d\n",ret);
	#endif
	return 0;
}
static void __exit func_exit(void)
{
	printk(KERN_INFO "glayer: msg from exit\n");
}

module_init(func_init);
module_exit(func_exit);
