/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/* NOTE: The beginning where custom code is added */
#include "threads/vaddr.h"
#include "lib/kernel/hash.h"
#include "vm/uninit.h"
/* NOTE: The end where custom code is added */

/* NOTE: The beginning where custom code is added */
#define MAX_STACK_SIZE (1 << 23) // 8 MB
/* NOTE: The beginning where custom code is added */

/* NOTE: The beginning where custom code is added */
static struct list frame_table;
static struct lock frame_table_lock;
/* NOTE: The end where custom code is added */

/* NOTE: The beginning where custom code is added */
static unsigned
page_hash (const struct hash_elem *e, void *aux UNUSED) {
    const struct page *p = hash_entry(e, struct page, hash_elem);
    return hash_bytes(&p->va, sizeof p->va);
}
static bool
page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    const struct page *p1 = hash_entry(a, struct page, hash_elem);
    const struct page *p2 = hash_entry(b, struct page, hash_elem);
    return p1->va < p2->va;
}
static void
page_destroy (struct hash_elem *e, void *aux UNUSED) {
    struct page *p = hash_entry(e, struct page, hash_elem);
    vm_dealloc_page(p);
}
static bool
is_stack_access(void *fault_addr, void *rsp) {
    /* Check if the fault address is a valid user address */
    if (fault_addr == NULL || !is_user_vaddr(fault_addr)) {
        return false;
    }

    /* Get the current stack pointer */
    void *stack_ptr = rsp;

    /* If the fault address is within the stack growth limit */
    if (fault_addr >= (stack_ptr - 8) && fault_addr >= (USER_STACK - MAX_STACK_SIZE)) {
        return true;
    }

    return false;
}
/* NOTE: The end where custom code is added */

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

	/* NOTE: The beginning where custom code is added */
	list_init(&frame_table);
    lock_init(&frame_table_lock);
	/* NOTE: The end where custom code is added */
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
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */

		struct page *new_page = (struct page *) malloc(sizeof(struct page));
		if (new_page == NULL)
            return false;

		bool (*page_initializer)(struct page *, enum vm_type, void *) = NULL;

        switch (VM_TYPE(type)) {
            case VM_ANON:
                page_initializer = anon_initializer;
                break;
            case VM_FILE:
                page_initializer = file_backed_initializer;
                break;
            default:
                /* Handle other types if necessary */
                free(new_page);
                return false;
        }

		/* Initialize the uninit page with uninit_new */
        uninit_new(new_page, upage, init, type, aux, page_initializer);

        /* Set the writable flag */
        new_page->writable = writable;

		/* Insert the page into the spt */
        if (!spt_insert_page(spt, new_page)) {
            free(new_page);
            return false;
        }

		return true;
	}

	return false;

	/* NOTE: The end where custom code is added */

// err:
// 	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	/* TODO: Fill this function. */

	/* NOTE: The beginning where custom code is added */
	struct page page;
	struct hash_elem *e;

	page.va = pg_round_down(va);
    e = hash_find(&spt->pages, &page.hash_elem);
    return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
	/* NOTE: The end where custom code is added */
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
	/* TODO: Fill this function. */

	/* NOTE: The beginning where custom code is added */
	if (hash_insert(&spt->pages, &page->hash_elem) != NULL) {
        free(page);
        return false;
    }
    return true;
	/* NOTE: The end where custom code is added */
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	/* NOTE: The beginning where custom code is added */
	swap_out(victim->page);
    victim->page = NULL;
    return victim;
	/* NOTE: The end where custom code is added */
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	/* TODO: Fill this function. */

	/* NOTE: The beginning where custom code is added */
	// void *kva = palloc_get_page(PAL_USER);
    // if (kva == NULL) {
    //     return vm_evict_frame();
    // }

	// struct frame *frame = malloc(sizeof(struct frame));
    // if (frame == NULL) {
    //     palloc_free_page(kva);
    //     return NULL;
    // }

	struct frame *frame = malloc(sizeof(struct frame));
    if (frame == NULL)
        return NULL;

    frame->kva = palloc_get_page(PAL_USER);
    if (frame->kva == NULL) {
        free(frame);
        return NULL;
    }

    frame->page = NULL;

	// frame->kva = kva;
    // frame->page = NULL;
	lock_acquire(&frame_table_lock);
    list_push_back(&frame_table, &frame->frame_elem);
	lock_release(&frame_table_lock);
	/* NOTE: The end where custom code is added */

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static bool
vm_stack_growth (void *addr) {
	/* NOTE: The beginning where custom code is added */
	// void *stack_page = pg_round_down(addr);
	void *stack_bottom = pg_round_down(addr);
    // vm_alloc_page(VM_ANON | VM_MARKER_0, stack_page, true);
	if (!vm_alloc_page(VM_ANON | VM_MARKER_0, stack_bottom, true)) {
        return false;
    }

	/* Claim the page */
    if (!vm_claim_page(stack_bottom)) {
        return false;
    }

	return true;
	/* NOTE: The end where custom code is added */
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED, bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;

	/* NOTE: The beginning where custom code is added */
	void *fault_addr = pg_round_down(addr);
	/* NOTE: The end where custom code is added */

	// struct page *page = NULL;
	/* NOTE: The beginning where custom code is added */
	struct page *page = spt_find_page(spt, fault_addr);
	/* NOTE: The end where custom code is added */

	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	if (page == NULL) {
        if (is_stack_access(fault_addr, f->rsp)) {
            if (!vm_stack_growth(fault_addr)) {
                return false;
            }
            page = spt_find_page(spt, fault_addr);
			if (page == NULL) {
				return false;
			}
        } else {
            return false;
        }
    }

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
vm_claim_page(void *va) {
	/* TODO: Fill this function */

    /* 1. Round down the virtual address to the nearest page boundary */
    void *page_va = pg_round_down(va);

    /* 2. Retrieve the current thread's supplemental page table */
    struct supplemental_page_table *spt = &thread_current()->spt;

    /* 3. Check if the page is already present in the supplemental page table */
    struct page *page = spt_find_page(spt, page_va);
    if (page == NULL) {
        /* 4. Allocate and initialize a new page structure */
        page = malloc(sizeof(struct page));
        if (page == NULL) {
            return false; /* 메모리 할당 실패 */
        }

        page->va = page_va;
        page->writable = true; /* 필요에 따라 설정 */
        page->frame = NULL; /* 초기에는 프레임이 없음 */
        page->is_loaded = false; /* 페이지가 아직 로드되지 않음 */

        /* 5. 페이지를 보조 페이지 테이블에 삽입 */
        if (!spt_insert_page(spt, page)) {
            free(page);
            return false; /* 삽입 실패 */
        }
    }

    /* 6. 페이지가 이미 로드되어 있는지 확인 */
    if (page->is_loaded) {
        /* 페이지가 이미 로드되어 있으므로 추가 작업 없이 성공 */
        return true;
    }

    /* 7. 페이지를 실제로 할당하고 매핑 */
    if (!vm_do_claim_page(page)) {
        return false; /* 페이지 할당 실패 */
    }

    /* 8. 페이지가 성공적으로 로드됨을 표시 */
    page->is_loaded = true;

    return true;
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	/* NOTE: The beginning where custom code is added */
	if (frame == NULL) {
        return false;
    }
	/* NOTE: The end where custom code is added */

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */

	/* NOTE: The beginning where custom code is added */
	if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable)) {
        return false;
    }
	/* NOTE: The end where custom code is added */

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	/* NOTE: The beginning where custom code is added */
	hash_init(&spt->pages, page_hash, page_less, NULL);
	/* NOTE: The end where custom code is added */
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst, struct supplemental_page_table *src) {
	struct hash_iterator i;
    hash_first(&i, &src->pages);
    while (hash_next(&i)) {
        struct page *parent_page = hash_entry(hash_cur(&i), struct page, hash_elem);
        // 페이지 복사 또는 공유 로직 구현
    }
    return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_destroy(&spt->pages, page_destroy);
}
