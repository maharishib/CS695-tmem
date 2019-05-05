#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/uuid.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/highmem.h>
#include <linux/list.h>
#include <linux/lzo.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/atomic.h>
#ifdef CONFIG_CLEANCACHE
#include <linux/cleancache.h>
#endif
#include "tmem.h"

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
#define MAX_POOLS_PER_CLIENT 10
#define MYCACHE_GFP_MASK (__GFP_FS | __GFP_NORETRY | __GFP_NOWARN | __GFP_NOMEMALLOC)

static unsigned long flobj_total;
static unsigned long flobj_found;
static unsigned long mycache_put_to_flush;
static unsigned long mycache_aborted_preload;
static unsigned long mycache_failed_alloc;
static unsigned long mycache_failed_get_free_pages;

static struct kmem_cache *mycache_objnode_cache;
static struct kmem_cache *mycache_obj_cache;
static atomic_t mycache_curr_obj_count = ATOMIC_INIT(0);
static unsigned long mycache_curr_obj_count_max;
static atomic_t mycache_curr_objnode_count = ATOMIC_INIT(0);
static unsigned long mycache_curr_objnode_count_max;
static atomic_t mycache_curr_eph_pampd_count = ATOMIC_INIT(0);
static unsigned long mycache_curr_eph_pampd_count_max;
static atomic_t mycache_curr_pers_pampd_count = ATOMIC_INIT(0);
static unsigned long mycache_curr_pers_pampd_count_max;

static atomic_t mycache_zbud_curr_raw_pages;
static atomic_t mycache_zbud_curr_zpages;
static unsigned long mycache_zbud_curr_zbytes;
static unsigned long mycache_zbud_cumul_zpages;
static unsigned long mycache_zbud_cumul_zbytes;

#define ZBH_SENTINEL  0x43214321
#define ZBPG_SENTINEL  0xdeadbeef
#define ZBUD_MAX_BUDS 2
struct zbud_hdr {
	uint32_t pool_id;
	struct tmem_oid oid;
	uint32_t index;
	uint16_t size; /* compressed size in bytes, zero means unused */
	DECL_SENTINEL
};





struct zbud_page {
	//struct list_head bud_list;
	struct list_head page_list;
	spinlock_t lock;
	struct zbud_hdr owner;	
	DECL_SENTINEL
	/* followed by NUM_CHUNK aligned CHUNK_SIZE-byte chunks */
};


#define CHUNK_SHIFT	6
#define CHUNK_SIZE	(1 << CHUNK_SHIFT)
#define CHUNK_MASK	(~(CHUNK_SIZE-1))
#define NCHUNKS		(((PAGE_SIZE - sizeof(struct zbud_page)) & \
				CHUNK_MASK) >> CHUNK_SHIFT)
#define MAX_CHUNK	(NCHUNKS-1)

static struct {
	struct list_head list;
	unsigned count;
} zbud_unbuddied[NCHUNKS];
/* list N contains pages with N chunks USED and NCHUNKS-N unused */
/* element 0 is never used but optimizing that isn't worth it */
static unsigned long zbud_cumul_chunk_counts[NCHUNKS];
/* protects the buddied list and all unbuddied lists */
static DEFINE_SPINLOCK(zbud_budlists_spinlock);

static LIST_HEAD(zbpg_unused_list);
static unsigned long mycache_zbpg_unused_list_count;

/* protects the unused page list */
static DEFINE_SPINLOCK(zbpg_unused_list_spinlock);



static struct {
	struct tmem_pool *tmem_pools[MAX_POOLS_PER_CLIENT];
	struct xv_pool *xvpool;
} cache_client;

struct mycache_preload {
	void *page;
	struct tmem_obj *obj;
	int nr;
	struct tmem_objnode *objnodes[OBJNODE_TREE_MAX_PATH];
};

static DEFINE_SPINLOCK(mycache_direct_reclaim_lock);
static DEFINE_PER_CPU(struct mycache_preload, mycache_preloads) = { 0, };

static int mycache_do_preload(struct tmem_pool *pool)
{
	struct mycache_preload *kp;
	struct tmem_objnode *objnode;
	struct tmem_obj *obj;	
	void *page;
	int ret = -ENOMEM;
	if (unlikely(mycache_objnode_cache == NULL))
		goto out;
	if (unlikely(mycache_obj_cache == NULL))
		goto out;
	if (!spin_trylock(&mycache_direct_reclaim_lock)) {
		mycache_aborted_preload++;
		goto out;
	}
	preempt_disable();
	kp = &get_cpu_var(mycache_preloads);
	while (kp->nr < ARRAY_SIZE(kp->objnodes)) {
		preempt_enable();
		objnode = kmem_cache_alloc(mycache_objnode_cache,
				MYCACHE_GFP_MASK);
		if (unlikely(objnode == NULL)) {
			mycache_failed_alloc++;
			goto unlock_out;
		}
		preempt_disable();
		kp = &get_cpu_var(mycache_preloads);
		if (kp->nr < ARRAY_SIZE(kp->objnodes))
			kp->objnodes[kp->nr++] = objnode;
		else
			kmem_cache_free(mycache_objnode_cache, objnode);
	}
	preempt_enable();
	obj = kmem_cache_alloc(mycache_obj_cache, MYCACHE_GFP_MASK);
	if (unlikely(obj == NULL)) {
		mycache_failed_alloc++;
		goto unlock_out;
	}
	page = (void *)__get_free_pages(MYCACHE_GFP_MASK,1);
	if (unlikely(page == NULL)) {
		mycache_failed_get_free_pages++;
		kmem_cache_free(mycache_obj_cache, obj);
		goto unlock_out;
	}
	preempt_disable();
	kp = &get_cpu_var(mycache_preloads);
	if (kp->obj == NULL)
		kp->obj = obj;
	else
		kmem_cache_free(mycache_obj_cache, obj);
	if (kp->page == NULL)
		kp->page = page;
	else
		free_page((unsigned long)page);
	ret = 0;
unlock_out:
	spin_unlock(&mycache_direct_reclaim_lock);
out:
	return ret;
}

static struct tmem_pool *mycache_get_pool_by_id(uint32_t poolid)
{
	struct tmem_pool *pool = NULL;

	if (poolid >= 0) {
		pool = cache_client.tmem_pools[poolid];
		if (pool != NULL)
			atomic_inc(&pool->refcount);
	}
	return pool;
}

static void mycache_put_pool(struct tmem_pool *pool)
{
	if (pool != NULL)
		atomic_dec(&pool->refcount);
}






static int create_new_pool(uint32_t flags){ //1 for persistent, 2 for shared
	printk(KERN_ALERT "glayer: new pool\n");
	int poolid=-1;
	struct tmem_pool *pool;
	//struct tmem_hashbucket *hb;
	int i;
	pool = kmalloc(sizeof(struct tmem_pool), GFP_KERNEL);
	if (pool == NULL) {
		printk(KERN_ALERT "pool creation failed: out of memory\n");
		return -1;
	}
	for (poolid = 0; poolid < MAX_POOLS_PER_CLIENT; poolid++)
		if (cache_client.tmem_pools[poolid] == NULL)
			break;
	if (poolid >= MAX_POOLS_PER_CLIENT) {
		kfree(pool);
		printk(KERN_ALERT "pool creation failed: no space left\n");
		return -1;
	}
	atomic_set(&pool->refcount, 0);
	pool->client = &cache_client;
	pool->pool_id = poolid;
	//my implementation
	tmem_new_pool(pool, flags);
	//implementation over
	cache_client.tmem_pools[poolid] = pool;
	printk(KERN_ALERT "pool created, poolid: %ld\n",poolid);
	return 0;
}
static int glayer_cc_init_fs(size_t pagesize){
	int ret = -1;
	////BUG_ON
	////BUG_ON(pagesize != PAGE_SIZE);
	ret = create_new_pool(0);
	return ret;
}


static int glayer_cc_init_shared_fs(uuid_t *uuid, size_t pagesize){
	int ret = -1;
	//printk(KERN_ALERT "glayer: shared fs\n");
	
	return 0;
}



static int glayer_cc_get_page(int pool_id,struct cleancache_filekey key,pgoff_t index, struct page *page){
	
	struct tmem_pool *pool;
	int ret = -1;
	unsigned long flags;
	size_t size = PAGE_SIZE;

	local_irq_save(flags);
	pool = mycache_get_pool_by_id(pool_id);
	struct tmem_oid *oidp = (struct tmem_oid *)&key;
	if (likely(pool != NULL)) {
		//printk(KERN_ALERT "glayer: before tmem get page\n");
		if (atomic_read(&pool->obj_count) > 0)
			ret = tmem_get(pool, oidp, index, (char *)(page),
					&size, 0, is_ephemeral(pool));
			printk(KERN_ALERT "glayer: get return: %d\n",ret);
		mycache_put_pool(pool);
	}
	local_irq_restore(flags);
	return ret;
}



static void glayer_cc_put_page(int pool_id,struct cleancache_filekey key,pgoff_t index,struct page *page){
	struct tmem_pool *pool;
	int ret = -1;
	struct tmem_oid *oidp = (struct tmem_oid *)&key;
	////BUG_ON(!irqs_disabled());
	pool = mycache_get_pool_by_id(pool_id);
	if(likely(pool!=NULL)){
		//mycache_freeze not used
		if(mycache_do_preload(pool) == 0){
			ret = tmem_put(pool, oidp, index, (char *)(page),PAGE_SIZE, 0, is_ephemeral(pool));
				
			mycache_put_pool(pool);
			preempt_enable();
		}
		//else
		//	printk(KERN_ALERT "glayer; preload not working\n");
		
	}
}



static void glayer_cc_invalidate_page(int pool_id, struct cleancache_filekey key, pgoff_t index){
	int ret = -1;
	//printk(KERN_ALERT "glayer: invalidate page\n");
	struct tmem_oid *oidp = (struct tmem_oid *)&key;
	struct tmem_pool *pool;
	unsigned long flags;

	local_irq_save(flags);
	//mycache_flush_total++;
	pool = mycache_get_pool_by_id(pool_id);
	if (likely(pool != NULL)) {
		if (atomic_read(&pool->obj_count) > 0){
			ret = tmem_flush_page(pool, oidp, index);
		mycache_put_pool(pool);
		//if(ret==0)
		//printk(KERN_ALERT "glayer: invalidate page,ret %ld\n",ret);
		}
	}
	//if (ret >= 0)
		//mycache_flush_found++;

	local_irq_restore(flags);
	return ret;
	
}
static void glayer_cc_invalidate_inode(int pool_id, struct cleancache_filekey key){
	struct tmem_oid *oidp = (struct tmem_oid *)&key;
	struct tmem_pool *pool = mycache_get_pool_by_id(pool_id);
	unsigned long flags;
	local_irq_save(flags);
	flobj_total++;
	if (likely(pool != NULL)) {
		if (atomic_read(&pool->obj_count) > 0){
			int ret=tmem_flush_object(pool, oidp);
			if (ret == 0){
				flobj_found++;
				//printk(KERN_ALERT "glayer: flfound =%ld,%ld\n",flobj_found,ret);
			}
			mycache_put_pool(pool);
		}
		
	}
	
		//printk(KERN_ALERT "glayer: pool is null\n");
	local_irq_restore(flags);
	
}
static void glayer_cc_invalidate_fs(int pool_id){	
	int ret = -1;
	printk(KERN_ALERT "glayer: invalidate pool\n");
	printk(KERN_ALERT "trying to destroy, poolid: %ld\n",pool_id);
	if(pool_id>0){
		struct tmem_pool *pool = cache_client.tmem_pools[pool_id];
		if (pool != NULL){
			cache_client.tmem_pools[pool_id] = NULL;
	/* wait for pool activity on other cpus to quiesce */
			while (atomic_read(&pool->refcount) != 0);
		//local_bh_disable();
		//ret = tmem_destroy_pool(pool);
		//local_bh_enable();
			kfree(pool);
			pr_info("destroyed pool id=%ld\n", pool_id);
		}
	}
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
	printk(KERN_ALERT "glayer: registering ops\n");
	return cleancache_register_ops(&glayer_cc_ops);
	
}
#endif





//hostops

static struct tmem_objnode *mycache_objnode_alloc(struct tmem_pool *pool)
{
	struct tmem_objnode *objnode = NULL;
	unsigned long count;
	struct mycache_preload *kp;

	kp = &get_cpu_var(mycache_preloads);
	
	if (kp->nr <= 0)
		goto out;
	objnode = kp->objnodes[kp->nr - 1];
	
	//BUG_ON(objnode == NULL);
	kp->objnodes[kp->nr - 1] = NULL;
	kp->nr--;
	count = atomic_inc_return(&mycache_curr_objnode_count);
	if (count > mycache_curr_objnode_count_max)
		mycache_curr_objnode_count_max = count;
out:
	return objnode;
}

static void mycache_objnode_free(struct tmem_objnode *objnode,
					struct tmem_pool *pool)
{
	atomic_dec(&mycache_curr_objnode_count);
	//BUG_ON(atomic_read(&mycache_curr_objnode_count) < 0);
	kmem_cache_free(mycache_objnode_cache, objnode);
}

static struct tmem_obj *mycache_obj_alloc(struct tmem_pool *pool)
{
	//printk(KERN_ALERT "glayer; in obj alloc:\n");
	struct tmem_obj *obj = NULL;
	unsigned long count;
	struct mycache_preload *kp;

	kp = &get_cpu_var(mycache_preloads);
	obj = kp->obj;
	////BUG_ON(obj == NULL);
	if(obj == NULL){
		//printk(KERN_ALERT "glayer;objnode==null in alloc:\n");
		return NULL;
	}
	kp->obj = NULL;
	count = atomic_inc_return(&mycache_curr_obj_count);
	if (count > mycache_curr_obj_count_max)
		mycache_curr_obj_count_max = count;
	return obj;
}

static void mycache_obj_free(struct tmem_obj *obj, struct tmem_pool *pool)
{
	atomic_dec(&mycache_curr_obj_count);
	//BUG_ON(atomic_read(&mycache_curr_obj_count) < 0);
	kmem_cache_free(mycache_obj_cache, obj);
}

static struct tmem_hostops mycache_hostops = {
	.obj_alloc = mycache_obj_alloc,
	.obj_free = mycache_obj_free,
	.objnode_alloc = mycache_objnode_alloc,
	.objnode_free = mycache_objnode_free,
};


//pamops
static void *mycache_get_free_page(void)
{
	struct mycache_preload *kp;
	void *page;

	kp = &get_cpu_var(mycache_preloads);
	page = kp->page;
	//BUG_ON(page == NULL);
	kp->page = NULL;
	return page;
}

static void mycache_free_page(void *p)
{
	free_page((unsigned long)p);
}
static struct zbud_page *zbud_alloc_raw_page(void)
{
	struct zbud_page *zbpg = NULL;
	struct zbud_hdr *owner;
	bool recycled = 0;

	spin_lock(&zbpg_unused_list_spinlock);
	if (!list_empty(&zbpg_unused_list)) {
		zbpg = list_first_entry(&zbpg_unused_list,
				struct zbud_page, page_list);
		//list_del_init(&zbpg->page_list);
		list_del(&zbpg->page_list);
		//printk(KERN_ALERT "glayer: in tmem_put reuse %p %\n",&zbpg->page_list);
		mycache_zbpg_unused_list_count--;
		recycled = 1;
	}
	spin_unlock(&zbpg_unused_list_spinlock);
	if (zbpg == NULL)
		/* none on zbpg list, try to get a kernel page */
		zbpg = mycache_get_free_page();
	if (likely(zbpg != NULL)) {
		INIT_LIST_HEAD(&zbpg->page_list);
		owner = &zbpg->owner;
		spin_lock_init(&zbpg->lock);
		if (recycled) {
			//ASSERT_INVERTED_SENTINEL(zbpg, ZBPG);
			SET_SENTINEL(zbpg, ZBPG);
			//BUG_ON(owner->size != 0 || tmem_oid_valid(&owner->oid));
		} else {
			atomic_inc(&mycache_zbud_curr_raw_pages);
			INIT_LIST_HEAD(&zbpg->page_list);
			SET_SENTINEL(zbpg, ZBPG);
			owner->size = 0;
			tmem_oid_set_invalid(&owner->oid);
		}
	}
	return zbpg;
}


static struct zbud_hdr *zbud_create(uint32_t pool_id, struct tmem_oid *oid,
					uint32_t index, struct page *page,
					void *cdata, unsigned size)
{
	struct zbud_hdr *owner = NULL;
	struct zbud_page *zbpg = NULL, *ztmp;
	char *to;
	int i;
	zbpg = zbud_alloc_raw_page();
	
	if (unlikely(zbpg == NULL))
		goto out;
	
	spin_lock(&zbpg->lock);
	spin_lock(&zbud_budlists_spinlock);
	owner = &zbpg->owner;
	SET_SENTINEL(owner, ZBH);
	owner->size = size+(sizeof(struct zbud_page));
	//printk(KERN_ALERT "glayer: in tmem_put zh->size %p %ld\n",owner,owner->size);
	owner->index = index;
	owner->oid = *oid;
	owner->pool_id = pool_id;
	/* can wait to copy the data until the list locks are dropped */
	spin_unlock(&zbud_budlists_spinlock);

	to = (char *)zbpg;
	to += (sizeof(struct zbud_page));
	//maharishi
	//memcpy(to, cdata, size-(sizeof(struct zbud_page)));
	memcpy(to, cdata, size);
	//printk(KERN_ALERT "glayer; put done: %p,%p\n",pool_id,&to[0],&to[1]);
	//printk(KERN_ALERT "glayer: in tmem_put memcpydone %p %p\n",to,to+size);
	spin_unlock(&zbpg->lock);
	atomic_inc(&mycache_zbud_curr_zpages);
	mycache_zbud_cumul_zpages++;
	mycache_zbud_curr_zbytes += size;
	mycache_zbud_cumul_zbytes += size;
out:
	return owner;
}
static void *mycache_pampd_create(char *data, size_t size, bool raw, int eph,
				struct tmem_pool *pool, struct tmem_oid *oid,
				 uint32_t index)
{
	void *pampd = NULL, *cdata,*temp;
	unsigned clen;
	int ret;
	unsigned long count;
	struct page *page = (struct page *)(data);
	//struct mycache_client *cli = pool->client;
	//uint16_t client_id = get_client_id_from_client(cli);
	unsigned long zv_mean_zsize;
	unsigned long curr_pers_pampd_count;
	u64 total_zsize;


	if(eph){
		cdata = kmap_atomic(page);
		// scribble on addr

		pampd = (void *)zbud_create(pool->pool_id, oid, index,page, cdata, size);
		kunmap_atomic(cdata);
		if (pampd != NULL) {
			count = atomic_inc_return(&mycache_curr_eph_pampd_count);
			if (count > mycache_curr_eph_pampd_count_max)
				mycache_curr_eph_pampd_count_max = count;
		}
	}
	else{
	//not used in our project
			
	}
	return pampd;
}
static void zbud_free_raw_page(struct zbud_page *zbpg)
{
	struct zbud_hdr *owner = &zbpg->owner;
	
	//ASSERT_SENTINEL(zbpg, ZBPG);
	//BUG_ON(!list_empty(&zbpg->bud_list));
	ASSERT_SPINLOCK(&zbpg->lock);
	//BUG_ON(owner->size != 0 || tmem_oid_valid(&owner->oid));
	INVERT_SENTINEL(zbpg, ZBPG);
	spin_unlock(&zbpg->lock);
	spin_lock(&zbpg_unused_list_spinlock);
	//printk(KERN_ALERT "glayer: in tmem_get reuse %p %\n",&zbpg->page_list);
	list_add_tail(&zbpg->page_list, &zbpg_unused_list);
	mycache_zbpg_unused_list_count++;
	spin_unlock(&zbpg_unused_list_spinlock);
}

static unsigned zbud_free(struct zbud_hdr *zh)
{
	unsigned size;

	//ASSERT_SENTINEL(zh, ZBH);
	//BUG_ON(!tmem_oid_valid(&zh->oid));
	size = zh->size;
	zh->size = 0;
	tmem_oid_set_invalid(&zh->oid);
	INVERT_SENTINEL(zh, ZBH);
	atomic_dec(&mycache_zbud_curr_zpages);
	return size;
}



static void zbud_free_and_delist(struct zbud_hdr *zh)
{
	unsigned chunks;
	struct zbud_hdr *zh_other;
	unsigned budnum = 0, size;
	struct zbud_page *zbpg =
		container_of(zh, struct zbud_page, owner);
	
	spin_lock(&zbud_budlists_spinlock);
	spin_lock(&zbpg->lock);
	/*if (list_empty(&zbpg->bud_list)) {
		 ignore zombie page... see zbud_evict_pages() 
		spin_unlock(&zbpg->lock);
		spin_unlock(&zbud_budlists_spinlock);
		return;
	}*/
	//printk(KERN_ALERT "glayer: in tmem_get before zbud_free\n");
	size = zbud_free(zh);
	//printk(KERN_ALERT "glayer: in tmem_get after zbud_free zh->size %ld\n",size);
	ASSERT_SPINLOCK(&zbpg->lock);
	spin_unlock(&zbud_budlists_spinlock);
	//printk(KERN_ALERT "glayer: in tmem_get before free_raw zh->size \n");
	spin_unlock(&zbud_budlists_spinlock);
	zbud_free_raw_page(zbpg);
	//printk(KERN_ALERT "glayer: in tmem_get after free_raw zh->size \n");
//	zh_other = &zbpg->buddy[(budnum == 0) ? 1 : 0];
	
	//if (zh_other->size == 0) 
		{ /* was unbuddied: unlist and free */
		//list_del_init(&zbpg->bud_list);
		//zbud_unbuddied[chunks].count--;
		
		//zbud_free_raw_page(zbpg);
	/*}else { was buddied: move remaining buddy to unbuddied list */
		//chunks = zbud_size_to_chunks(zh_other->size) ;
		//list_del_init(&zbpg->bud_list);
		//list_add_tail(&zbpg->bud_list, &zbud_unbuddied[chunks].list);
		//zbud_unbuddied[chunks].count++;
		//spin_unlock(&zbud_budlists_spinlock);
		//spin_unlock(&zbpg->lock);
	}
}

static void mycache_pampd_free(void *pampd, struct tmem_pool *pool,
				struct tmem_oid *oid, uint32_t index)
{
	//struct mycache_client *cli = pool->client;

	if (is_ephemeral(pool)) {
		zbud_free_and_delist((struct zbud_hdr *)pampd);
		atomic_dec(&mycache_curr_eph_pampd_count);
		//BUG_ON(atomic_read(&mycache_curr_eph_pampd_count) < 0);
	} else {
		//zv_free(cli->zspool, pampd);
		//atomic_dec(&mycache_curr_pers_pampd_count);
		////BUG_ON(atomic_read(&mycache_curr_pers_pampd_count) < 0);
	}
}
static void mycache_pampd_free_obj(struct tmem_pool *pool, struct tmem_obj *obj)
{
}

static void mycache_pampd_new_obj(struct tmem_obj *obj)
{
}

static int mycache_pampd_replace_in_obj(void *pampd, struct tmem_obj *obj)
{
	return -1;
}

static bool mycache_pampd_is_remote(void *pampd)
{
	return 0;
}

static char *zbud_data(struct zbud_hdr *zh, unsigned size)
{
	struct zbud_page *zbpg;
	char *p;
	unsigned budnum;

	ASSERT_SENTINEL(zh, ZBH);
	
	////BUG_ON(size == 0 || size > zbud_max_buddy_size());
	zbpg = container_of(zh, struct zbud_page, owner);
	//ASSERT_SPINLOCK(&zbpg->lock);
	p = (char *)zbpg;
	printk(KERN_ALERT "glayer: in tmem_get p %llu %llu %llu\n",p,p+1,p+(sizeof(struct zbud_page)));
	p += (sizeof(struct zbud_page));
	return p;
}


static int zbud_get_data(struct page *page, struct zbud_hdr *zh)
{
	struct zbud_page *zbpg;
	unsigned budnum = 0;
	unsigned int out_len = PAGE_SIZE;
	char *to_va, *from_va;
	unsigned size;
	int ret = 0;
	if(zh->oid.oid[0]==-1 || zh->oid.oid[1]==-1 || zh->oid.oid[2]==-1)
		return -1;
	if(!tmem_oid_valid(&zh->oid))
		return -1;
	//printk(KERN_ALERT "glayer; get done: %ld,%ld,%ld,%ld,%ld\n",zh->pool_id,zh->oid.oid[0],zh->oid.oid[1],zh->oid.oid[2],zh->index);

	zbpg = container_of(zh, struct zbud_page, owner);
	spin_lock(&zbpg->lock);
	/*if (list_empty(&zbpg->page_list)) {
		printk(KERN_ALERT "glayer: in tmem_get list-empty %ld\n",zh->size);
		// ignore zombie page... see zbud_evict_pages() 
		ret = -EINVAL;
		goto out;
	}*/
	//ASSERT_SENTINEL(zh, ZBH);
	////BUG_ON(zh->size == 0 || zh->size > zbud_max_buddy_size());
	size = zh->size-sizeof(struct zbud_page);
	//printk(KERN_ALERT "glayer: in tmem_get zh->size1 %p %ld\n",zh,zh->size);
	//char *p;
	//p = (char *)zbpg;
	//printk(KERN_ALERT "glayer: in tmem_get p %p %p %p\n",p,p+1,p+(sizeof(struct zbud_page)));
	to_va = kmap_atomic(page);
//	printk(KERN_ALERT "glayer: in tmem_get zh->size %ld\n",zh->size);
	char *p;
	p = (char *)zbpg;
	p+=(sizeof(struct zbud_page));
	memcpy(to_va,p,size);
	//to_va = zbud_data(zh, size);
	//BUG_ON(ret);
	////BUG_ON(out_len != PAGE_SIZE);
	kunmap_atomic(to_va);
	//printk(KERN_ALERT "glayer: in tmem_get zh->size2 %p %ld\n",zh,size);
out:
	spin_unlock(&zbpg->lock);
	return ret;
}

static int mycache_pampd_get_data_and_free(char *data, size_t *bufsize, bool raw,
					void *pampd, struct tmem_pool *pool,
					struct tmem_oid *oid, uint32_t index)
{
	int ret = -1;
	//printk(KERN_ALERT "glayer: in tmem_get get_data_and_free\n");
	//BUG_ON(!is_ephemeral(pool));
	//printk(KERN_ALERT "glayer; in tmem_get before decompress:\n");
	ret = zbud_get_data((struct page *)(data), pampd);
	//printk(KERN_ALERT "glayer; in tmem_get after decompress %d:\n",ret);
	zbud_free_and_delist((struct zbud_hdr *)pampd);
	//printk(KERN_ALERT "glayer; in tmem_get after free:\n");
	atomic_dec(&mycache_curr_eph_pampd_count);
	
	return ret;
}

static struct tmem_pamops mycache_pamops = {
	.create = mycache_pampd_create,
	//.get_data = mycache_pampd_get_data,
	.get_data_and_free = mycache_pampd_get_data_and_free,
	.free = mycache_pampd_free,
	.free_obj = mycache_pampd_free_obj,
	.new_obj = mycache_pampd_new_obj,
	.replace_in_obj = mycache_pampd_replace_in_obj,
	.is_remote = mycache_pampd_is_remote,
};

static int mycache_init(void){
	int ret = 0;
	unsigned int cpu;
	struct tmem_obj *obj = NULL;	
	struct mycache_preload *kp;
	tmem_register_hostops(&mycache_hostops);
	tmem_register_pamops(&mycache_pamops);
	ret = glayer_cc_register_ops();
	mycache_objnode_cache = kmem_cache_create("mycache_objnode",
				sizeof(struct tmem_objnode), 0, 0, NULL);
	mycache_obj_cache = kmem_cache_create("mycache_obj",
				sizeof(struct tmem_obj), 0, 0, NULL);
	//ret = mycache_new_client(LOCAL_CLIENT);
out:
	return ret;
	
}

static int __init func_init(void){
	int ret;
	printk(KERN_INFO "glayer: msg from init\n");
	#ifdef CONFIG_CLEANCACHE
	printk(KERN_INFO "glayer: cleancache=true\n");
	ret = mycache_init();
	printk(KERN_ALERT "glayer: return value %ld\n",ret);
	#endif
	return 0;
}
static void __exit func_exit(void)
{
	printk(KERN_ALERT "glayer: msg from exit\n");
}

module_init(func_init);
module_exit(func_exit);
