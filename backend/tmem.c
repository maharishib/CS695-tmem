#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>

#include "tmem.h"

#define POOL_SENTINEL 0x87658765
#define OBJ_SENTINEL 0x12345678
#define OBJNODE_SENTINEL 0xfedcba09


static struct tmem_hostops tmem_hostops;
static struct tmem_pamops tmem_pamops;

struct tmem_objnode_tree_path {
	struct tmem_objnode *objnode;
	int offset;
};

/* objnode height_to_maxindex translation */
static unsigned long tmem_objnode_tree_h2max[OBJNODE_TREE_MAX_PATH + 1];

void tmem_register_hostops(struct tmem_hostops *m)
{
	//tmem_objnode_tree_init();
	tmem_hostops = *m;
}

void tmem_register_pamops(struct tmem_pamops *m)
{
	tmem_pamops = *m;
}

static void tmem_pampd_destroy_all_in_obj(struct tmem_obj *);

/* free an object that has no more pampds in it */
static void tmem_obj_free(struct tmem_obj *obj, struct tmem_hashbucket *hb)
{
	struct tmem_pool *pool;

	BUG_ON(obj == NULL);
	ASSERT_SENTINEL(obj, OBJ);
	BUG_ON(obj->pampd_count > 0);
	pool = obj->pool;
	BUG_ON(pool == NULL);
	if (obj->objnode_tree_root != NULL) /* may be "stump" with no leaves */
		tmem_pampd_destroy_all_in_obj(obj);
	BUG_ON(obj->objnode_tree_root != NULL);
	BUG_ON((long)obj->objnode_count != 0);
	atomic_dec(&pool->obj_count);
	BUG_ON(atomic_read(&pool->obj_count) < 0);
	INVERT_SENTINEL(obj, OBJ);
	obj->pool = NULL;
	tmem_oid_set_invalid(&obj->oid);
	rb_erase(&obj->rb_tree_node, &hb->obj_rb_root);
}

/*
 * lookup index in object and return associated pampd (or NULL if not found)
 */
static void *tmem_pampd_lookup_in_obj(struct tmem_obj *obj, uint32_t index)
{
	unsigned int height, shift;
	struct tmem_objnode **slot = NULL;

	BUG_ON(obj == NULL);
	ASSERT_SENTINEL(obj, OBJ);
	BUG_ON(obj->pool == NULL);
	ASSERT_SENTINEL(obj->pool, POOL);

	height = obj->objnode_tree_height;
	if (index > tmem_objnode_tree_h2max[obj->objnode_tree_height])
		goto out;
	if (height == 0 && obj->objnode_tree_root) {
		slot = &obj->objnode_tree_root;
		goto out;
	}
	shift = (height-1) * OBJNODE_TREE_MAP_SHIFT;
	slot = &obj->objnode_tree_root;
	while (height > 0) {
		if (*slot == NULL)
			goto out;
		slot = (struct tmem_objnode **)
			((*slot)->slots +
			 ((index >> shift) & OBJNODE_TREE_MAP_MASK));
		shift -= OBJNODE_TREE_MAP_SHIFT;
		height--;
	}
out:
	return slot != NULL ? *slot : NULL;
}

static void tmem_obj_init(struct tmem_obj *obj, struct tmem_hashbucket *hb,
					struct tmem_pool *pool,
					struct tmem_oid *oidp)
{
	struct rb_root *root = &hb->obj_rb_root;
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct tmem_obj *this;

	BUG_ON(pool == NULL);
	atomic_inc(&pool->obj_count);
	obj->objnode_tree_height = 0;
	obj->objnode_tree_root = NULL;
	obj->pool = pool;
	obj->oid = *oidp;
	obj->objnode_count = 0;
	obj->pampd_count = 0;
	SET_SENTINEL(obj, OBJ);
	while (*new) {
		BUG_ON(RB_EMPTY_NODE(*new));
		this = rb_entry(*new, struct tmem_obj, rb_tree_node);
		parent = *new;
		switch (tmem_oid_compare(oidp, &this->oid)) {
		case 0:
			BUG(); /* already present; should never happen! */
			break;
		case -1:
			new = &(*new)->rb_left;
			break;
		case 1:
			new = &(*new)->rb_right;
			break;
		}
	}
	rb_link_node(&obj->rb_tree_node, parent, new);
	rb_insert_color(&obj->rb_tree_node, root);
}

static struct tmem_objnode *tmem_objnode_alloc(struct tmem_obj *obj)
{
	struct tmem_objnode *objnode;

	ASSERT_SENTINEL(obj, OBJ);
	BUG_ON(obj->pool == NULL);
	ASSERT_SENTINEL(obj->pool, POOL);
	objnode = (*tmem_hostops.objnode_alloc)(obj->pool);
	if (unlikely(objnode == NULL))
		goto out;
	objnode->obj = obj;
	SET_SENTINEL(objnode, OBJNODE);
	memset(&objnode->slots, 0, sizeof(objnode->slots));
	objnode->slots_in_use = 0;
	obj->objnode_count++;
out:
	return objnode;
}

static void tmem_objnode_free(struct tmem_objnode *objnode)
{
	struct tmem_pool *pool;
	int i;

	BUG_ON(objnode == NULL);
	for (i = 0; i < OBJNODE_TREE_MAP_SIZE; i++)
		BUG_ON(objnode->slots[i] != NULL);
	ASSERT_SENTINEL(objnode, OBJNODE);
	INVERT_SENTINEL(objnode, OBJNODE);
	BUG_ON(objnode->obj == NULL);
	ASSERT_SENTINEL(objnode->obj, OBJ);
	pool = objnode->obj->pool;
	BUG_ON(pool == NULL);
	ASSERT_SENTINEL(pool, POOL);
	objnode->obj->objnode_count--;
	objnode->obj = NULL;
	(*tmem_hostops.objnode_free)(objnode, pool);
}

static struct tmem_obj *tmem_obj_find(struct tmem_hashbucket *hb,
					struct tmem_oid *oidp)
{
	struct rb_node *rbnode;
	struct tmem_obj *obj;

	rbnode = hb->obj_rb_root.rb_node;
	while (rbnode) {
		BUG_ON(RB_EMPTY_NODE(rbnode));
		obj = rb_entry(rbnode, struct tmem_obj, rb_tree_node);
		switch (tmem_oid_compare(oidp, &obj->oid)) {
		case 0: /* equal */
			goto out;
		case -1:
			rbnode = rbnode->rb_left;
			break;
		case 1:
			rbnode = rbnode->rb_right;
			break;
		}
	}
	obj = NULL;
out:
	return obj;
}

static void tmem_objnode_node_destroy(struct tmem_obj *obj,
					struct tmem_objnode *objnode,
					unsigned int ht)
{
	int i;

	if (ht == 0)
		return;
	for (i = 0; i < OBJNODE_TREE_MAP_SIZE; i++) {
		if (objnode->slots[i]) {
			if (ht == 1) {
				obj->pampd_count--;
				(*tmem_pamops.free)(objnode->slots[i],
								obj->pool);
				objnode->slots[i] = NULL;
				continue;
			}
			tmem_objnode_node_destroy(obj, objnode->slots[i], ht-1);
			tmem_objnode_free(objnode->slots[i]);
			objnode->slots[i] = NULL;
		}
	}
}
static void tmem_pampd_destroy_all_in_obj(struct tmem_obj *obj)
{
	if (obj->objnode_tree_root == NULL)
		return;
	if (obj->objnode_tree_height == 0) {
		obj->pampd_count--;
		(*tmem_pamops.free)(obj->objnode_tree_root, obj->pool);
	} else {
		tmem_objnode_node_destroy(obj, obj->objnode_tree_root,
					obj->objnode_tree_height);
		tmem_objnode_free(obj->objnode_tree_root);
		obj->objnode_tree_height = 0;
	}
	obj->objnode_tree_root = NULL;
}

static int tmem_pampd_add_to_obj(struct tmem_obj *obj, uint32_t index,
					void *pampd)
{
	int ret = 0;
	struct tmem_objnode *objnode = NULL, *newnode, *slot;
	unsigned int height, shift;
	int offset = 0;

	/* if necessary, extend the tree to be higher  */
	if (index > tmem_objnode_tree_h2max[obj->objnode_tree_height]) {
		height = obj->objnode_tree_height + 1;
		if (index > tmem_objnode_tree_h2max[height])
			while (index > tmem_objnode_tree_h2max[height])
				height++;
		if (obj->objnode_tree_root == NULL) {
			obj->objnode_tree_height = height;
			goto insert;
		}
		do {
			newnode = tmem_objnode_alloc(obj);
			if (!newnode) {
				ret = -ENOMEM;
				goto out;
			}
			newnode->slots[0] = obj->objnode_tree_root;
			newnode->slots_in_use = 1;
			obj->objnode_tree_root = newnode;
			obj->objnode_tree_height++;
		} while (height > obj->objnode_tree_height);
	}
insert:
	slot = obj->objnode_tree_root;
	height = obj->objnode_tree_height;
	shift = (height-1) * OBJNODE_TREE_MAP_SHIFT;
	while (height > 0) {
		if (slot == NULL) {
			/* add a child objnode.  */
			slot = tmem_objnode_alloc(obj);
			if (!slot) {
				ret = -ENOMEM;
				goto out;
			}
			if (objnode) {

				objnode->slots[offset] = slot;
				objnode->slots_in_use++;
			} else
				obj->objnode_tree_root = slot;
		}
		/* go down a level */
		offset = (index >> shift) & OBJNODE_TREE_MAP_MASK;
		objnode = slot;
		slot = objnode->slots[offset];
		shift -= OBJNODE_TREE_MAP_SHIFT;
		height--;
	}
	BUG_ON(slot != NULL);
	if (objnode) {
		objnode->slots_in_use++;
		objnode->slots[offset] = pampd;
	} else
		obj->objnode_tree_root = pampd;
	obj->pampd_count++;
out:
	return ret;
}

static void *tmem_pampd_delete_from_obj(struct tmem_obj *obj, uint32_t index)
{
	struct tmem_objnode_tree_path path[OBJNODE_TREE_MAX_PATH + 1];
	struct tmem_objnode_tree_path *pathp = path;
	struct tmem_objnode *slot = NULL;
	unsigned int height, shift;
	int offset;

	BUG_ON(obj == NULL);
	ASSERT_SENTINEL(obj, OBJ);
	BUG_ON(obj->pool == NULL);
	ASSERT_SENTINEL(obj->pool, POOL);
	height = obj->objnode_tree_height;
	if (index > tmem_objnode_tree_h2max[height])
		goto out;
	slot = obj->objnode_tree_root;
	if (height == 0 && obj->objnode_tree_root) {
		obj->objnode_tree_root = NULL;
		goto out;
	}
	shift = (height - 1) * OBJNODE_TREE_MAP_SHIFT;
	pathp->objnode = NULL;
	do {
		if (slot == NULL)
			goto out;
		pathp++;
		offset = (index >> shift) & OBJNODE_TREE_MAP_MASK;
		pathp->offset = offset;
		pathp->objnode = slot;
		slot = slot->slots[offset];
		shift -= OBJNODE_TREE_MAP_SHIFT;
		height--;
	} while (height > 0);
	if (slot == NULL)
		goto out;
	while (pathp->objnode) {
		pathp->objnode->slots[pathp->offset] = NULL;
		pathp->objnode->slots_in_use--;
		if (pathp->objnode->slots_in_use) {
			if (pathp->objnode == obj->objnode_tree_root) {
				while (obj->objnode_tree_height > 0 &&
				  obj->objnode_tree_root->slots_in_use == 1 &&
				  obj->objnode_tree_root->slots[0]) {
					struct tmem_objnode *to_free =
						obj->objnode_tree_root;

					obj->objnode_tree_root =
							to_free->slots[0];
					obj->objnode_tree_height--;
					to_free->slots[0] = NULL;
					to_free->slots_in_use = 0;
					tmem_objnode_free(to_free);
				}
			}
			goto out;
		}
		tmem_objnode_free(pathp->objnode); /* 0 slots used, free it */
		pathp--;
	}
	obj->objnode_tree_height = 0;
	obj->objnode_tree_root = NULL;

out:
	if (slot != NULL)
		obj->pampd_count--;
	BUG_ON(obj->pampd_count < 0);
	return slot;
}

int tmem_put(struct tmem_pool *pool, struct tmem_oid *oidp, uint32_t index,
		struct page *page)
{
	int ret = -1;
	struct tmem_obj *obj = NULL, *objfound = NULL, *objnew = NULL;
	void *pampd = NULL, *pampd_del = NULL;
	ret = -ENOMEM;
	bool ephemeral;
	struct tmem_hashbucket *hb;
	ephemeral = is_ephemeral(pool);
	hb = &pool->hashbucket[tmem_oid_hash(oidp)];
	spin_lock(&hb->lock);
	obj = objfound = tmem_obj_find(hb, oidp);
	//put tested if find fails
	if (obj != NULL) {
		pampd = tmem_pampd_lookup_in_obj(objfound, index);
		if (pampd != NULL) {
			/* if found, is a dup put, flush the old one */
			pampd_del = tmem_pampd_delete_from_obj(obj, index);
			BUG_ON(pampd_del != pampd);
			(*tmem_pamops.free)(pampd, pool);
			if (obj->pampd_count == 0) {
				objnew = obj;
				objfound = NULL;
			}
			pampd = NULL;
		}
	} else 
	{
		obj = objnew = (*tmem_hostops.obj_alloc)(pool);
		if (unlikely(obj == NULL)) {
			ret = -ENOMEM;
			goto out;
		}
		tmem_obj_init(obj, hb, pool, oidp);
	}
	BUG_ON(obj == NULL);
	BUG_ON(((objnew != obj) && (objfound != obj)) || (objnew == objfound));
	pampd = (*tmem_pamops.create)(obj->pool, &obj->oid, index, page);
	if (unlikely(pampd == NULL)){
		printk(KERN_ALERT "glayer; pamd is null\n");
		goto free;
	}
	printk(KERN_ALERT "glayer; pamd created:\n");
	ret = tmem_pampd_add_to_obj(obj, index, pampd);
	if (unlikely(ret == -ENOMEM))
		/* may have partially built objnode tree ("stump") */
		goto delete_and_free;
	printk(KERN_ALERT "glayer; added to object:\n");
	goto out;

delete_and_free:
	printk(KERN_ALERT "glayer; delete and free:\n");
	(void)tmem_pampd_delete_from_obj(obj, index);
free:
	printk(KERN_ALERT "glayer; free:\n");
	if (pampd)
		(*tmem_pamops.free)(pampd, pool);
	if (objnew) {
		tmem_obj_free(objnew, hb);
		(*tmem_hostops.obj_free)(objnew, pool);
	}
out:
	spin_unlock(&hb->lock);
	return ret;
}
int tmem_flush_object(struct tmem_pool *pool, struct tmem_oid *oidp)
{
	printk(KERN_ALERT "flushing: %d\n",pool->obj_count);
}
void tmem_new_pool(struct tmem_pool *pool, uint32_t flags)
{
	int persistent = flags & TMEM_POOL_PERSIST;
	int shared = flags & TMEM_POOL_SHARED;
	
	struct tmem_hashbucket *hb = &pool->hashbucket[0];
	int i;

	for (i = 0; i < TMEM_HASH_BUCKETS; i++, hb++) {
		hb->obj_rb_root = RB_ROOT;
		spin_lock_init(&hb->lock);
	}

	atomic_set(&pool->obj_count, 0);
	printk(KERN_ALERT "pool obj count: %d\n",pool->obj_count);
	//need to understand this SET_SENTINEL(pool, POOL);
	pool->persistent = persistent;
	pool->shared = shared;
}
