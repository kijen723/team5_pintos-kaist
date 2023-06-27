/* vm.c: Generic interface for virtual memory objects. */

#include <string.h>
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "vm/vm.h"
#include "vm/anon.h"
#include "vm/file.h"
#include "vm/inspect.h"
#include "vm/uninit.h"

struct list frame_table;
struct list_elem *clock_ptr;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init (&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page *new_page = (struct page *) malloc (sizeof (struct page));

		switch (VM_TYPE (type)) {
			case VM_ANON:
				uninit_new (new_page, upage, init, type, aux, anon_initializer);
				break;
			case VM_FILE:
				uninit_new (new_page, upage, init, type, aux, file_backed_initializer);
				break;
		}

		new_page->writable = writable;
		new_page->pml4 = thread_current ()->pml4;

		/* TODO: Insert the page into the spt. */
		return spt_insert_page (spt, new_page);
	}

	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page temp_page;
	/* TODO: Fill this function. */
	temp_page.va = pg_round_down (va);

	struct hash_elem *temp_hash_elem = hash_find (&spt->table, &temp_page.hash_elem);

	if (temp_hash_elem == NULL)
		return NULL;

	return hash_entry (temp_hash_elem, struct page, hash_elem);
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	struct hash_elem *temp_elem = hash_insert (&spt->table, &page->hash_elem);

	if (temp_elem == NULL)
		succ = true;
		return succ;

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	struct frame *frame = page->frame;

	if (frame) {
		if (frame->cow_cnt == 0) {
			if (clock_ptr == &frame->elem)
				list_clock_next (&frame_table);
			list_remove (&frame->elem);
			palloc_free_page (frame->kva);
			free(frame);
		} else {
			list_remove (&page->cow_elem);
			vm_down_cow_cnt (frame);

			if (frame->page == page)
				frame->page = list_begin (&frame->child_pages);
		}
	}

	if (hash_delete (&spt->table, &page->hash_elem))
		vm_dealloc_page (page);

	return;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	struct thread *curr = thread_current();
	 /* TODO: The policy for eviction is up to you. */

	while (1) {
		list_clock_next (&frame_table);
		victim = list_entry (clock_ptr, struct frame, elem);

		if (pml4_is_accessed (victim->pml4, victim->page->va)) {
			pml4_set_accessed (victim->pml4, victim->page->va, false);
			continue;
		}

		break;
	}

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	swap_out (victim->page);

	struct page *page = victim->page;
	struct list_elem *temp_elem = list_begin (&victim->child_pages);

	for (; temp_elem != list_tail (&victim->child_pages); temp_elem = temp_elem->next) {
		struct page *temp_page = list_entry (temp_elem, struct page, cow_elem);

		temp_page->frame = NULL;
		pml4_clear_page (temp_page->pml4, temp_page->va);
	}

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = (struct frame *) malloc (sizeof(struct frame));
	/* TODO: Fill this function. */
	if (frame == NULL)
		return NULL;

	frame->kva = palloc_get_page (PAL_USER);

	if (frame->kva)
		list_push_back (&frame_table, &frame->elem);
	else
		frame = vm_evict_frame ();

	clock_ptr = &frame->elem;
	frame->page = NULL;
	frame->pml4 = NULL;
	frame->cow_cnt = 0;
	list_init (&frame->child_pages);

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	if (spt_find_page (&thread_current ()->spt, addr))
		return;

	uintptr_t stack_bottom = pg_round_down (addr);
	vm_alloc_page (VM_ANON, stack_bottom, true);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
	struct thread *curr = thread_current ();
	struct frame *old_frame = page->frame;

	page->frame = NULL;
	list_remove (&page->cow_elem);
	if (old_frame->page == page)
		old_frame->page = list_begin (&old_frame->child_pages);
	pml4_clear_page (curr->pml4, page->va);

	struct frame *new_frame = vm_get_frame ();
	new_frame->page = page;
	page->frame = new_frame;

	if (!pml4_set_page (curr->pml4, page->va, new_frame->kva, page->writable))
		return false;

	new_frame->pml4 = curr->pml4;
	list_push_back (&new_frame->child_pages, &page->cow_elem);
	memcpy (new_frame->kva, old_frame->kva, PGSIZE);
	vm_down_cow_cnt (old_frame);

	return true;
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	bool succ = false;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if (is_kernel_vaddr (addr) || addr == NULL)
		return false;

	uintptr_t stack_limit = USER_STACK - (1 << 20);
	uintptr_t rsp = user ? f->rsp : thread_current ()->user_rsp;

	if (addr >= rsp - 8 && addr <= USER_STACK && addr >= stack_limit)
		vm_stack_growth(addr);

	struct page *page = spt_find_page (spt, addr);

	if (page == NULL)
		return false;

	if (!page->writable && write)
		return false;

	if (write && !not_present && page->frame->cow_cnt > 0)
		if (vm_handle_wp (page))
			return true;

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = spt_find_page (&thread_current ()->spt, va);
	/* TODO: Fill this function */
	if (page == NULL)
		return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	struct thread *curr = thread_current ();

	/* Set links */
	frame->page = page;
	frame->pml4 = curr->pml4;
	list_push_back (&frame->child_pages, &page->cow_elem);
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if (!pml4_set_page(curr->pml4, page->va, frame->kva, page->writable))
		return false;

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init (&spt->table, spt_hash, spt_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	struct thread *curr = thread_current ();
	struct hash_iterator i;
	struct hash *parent_hash = &src->table;

	hash_first (&i, parent_hash);
	while (hash_next (&i)) {
		struct page *parent_page = hash_entry (hash_cur (&i), struct page, hash_elem);

		if (parent_page->operations->type == VM_UNINIT) {
			vm_initializer *init = parent_page->uninit.init;
			void *aux = parent_page->uninit.aux;

			vm_alloc_page_with_initializer (parent_page->uninit.type, parent_page->va, parent_page->writable, init, aux);
		} else {
			struct page *child_page = (struct page *) malloc (sizeof (struct page));
			memcpy (child_page, parent_page, sizeof (struct page));

			if (!spt_insert_page (dst, child_page))
				return false;

			if (!pml4_set_page (curr->pml4, child_page->va, child_page->frame->kva, false))
				return false;

			if (!pml4_set_page (parent_page->pml4, parent_page->va, parent_page->frame->kva, false))
				return false;

			list_push_back (&child_page->frame->child_pages, &child_page->cow_elem);
			child_page->frame->cow_cnt++;
			child_page->pml4 = curr->pml4;
		}
	}

	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	struct thread *curr = thread_current ();
	struct list_elem *temp_elem = list_begin (&curr->mmap_list);

	for (; temp_elem != list_tail (&curr->mmap_list);) {
		struct mmap_file *temp_mmap = list_entry (temp_elem, struct mmap_file, elem);
		temp_elem = temp_elem->next;
		munmap (temp_mmap->addr);
	}

	hash_destroy (&spt->table, hash_destructor);
}

unsigned
spt_hash (const struct hash_elem *elem, void *aux UNUSED) {
	const struct page *temp_page = hash_entry (elem, struct page, hash_elem);

	return hash_bytes (&temp_page->va, sizeof(temp_page->va));
}

static unsigned
spt_less (const struct hash_elem *a, const struct hash_elem *b) {
	const struct page *page_a = hash_entry (a, struct page, hash_elem);
	const struct page *page_b = hash_entry (b, struct page, hash_elem);

	return page_a->va < page_b->va;
}

void
hash_destructor (struct hash_elem *hash_elem, void *aux) {
	struct page *page = hash_entry (hash_elem, struct page, hash_elem);
	struct frame *frame = page->frame;

	if (frame) {
		if (frame->cow_cnt == 0) {
			if (clock_ptr == &frame->elem)
				list_clock_next (&frame_table);
			list_remove (&frame->elem);

			palloc_free_page (frame->kva);
			free (frame);
		} else {
			list_remove (&page->cow_elem);
			vm_down_cow_cnt (frame);

			if (frame->page == page)
				frame->page = list_begin (&frame->child_pages);
		}
	}

	vm_dealloc_page (page);
}

void
list_clock_next (struct list *l) {
	clock_ptr = clock_ptr->next;

	if (list_tail (l) == clock_ptr)
		clock_ptr = list_begin (l);
}

void
vm_down_cow_cnt (struct frame *frame) {
	frame->cow_cnt--;

	if (frame->cow_cnt == 0) {
		struct list_elem *temp_elem = list_begin (&frame->child_pages);
		struct page *temp_page = list_entry (temp_elem, struct page, cow_elem);

		pml4_set_page (temp_page->pml4, temp_page->va, frame->kva, temp_page->writable);
	}
}
