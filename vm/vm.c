/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/* NOTE: The beginning where custom code is added */
#include "threads/vaddr.h"
#include "lib/kernel/hash.h"
#include "vm/uninit.h"
#include "include/threads/mmu.h"
/* NOTE: The end where custom code is added */

/* NOTE: The beginning where custom code is added */
static struct list frame_list;  // List of all frames
// static struct lock frame_list_lock;
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
// static bool
// is_stack_access(void *fault_addr, void *rsp) {
//     /* Check if the fault address is a valid user address */
//     if (fault_addr == NULL || !is_user_vaddr(fault_addr)) {
//         return false;
//     }
//     /* Get the current stack pointer */
//     void *stack_ptr = rsp;
//     /* If the fault address is within the stack growth limit */
//     if (fault_addr >= (stack_ptr - 8) && fault_addr >= (USER_STACK - MAX_STACK_SIZE)) {
//         return true;
//     }
//     return false;
// }
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
    list_init(&frame_list);
    // lock_init(&frame_list_lock);
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
bool vm_do_claim_page (struct page *page);
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

		/* TODO: Insert the page into the spt. */

        /* Create the uninit page. */
        struct page *new_page = malloc(sizeof(struct page));
        if (new_page == NULL) {
            return false;  // Memory allocation failed.
        }

        /* Fetch the initializer based on the VM type and create "uninit" page struct. */
        bool (*initializer)(struct page *, void *aux) = NULL;

        switch (VM_TYPE(type)) {
            case VM_ANON:
                initializer = anon_initializer;  // Assume anon_initializer exists
                break;
            case VM_FILE:
                initializer = file_backed_initializer;  // Assume file_backed_initializer exists
                break;
            // Add other cases as needed.
            default:
                /* Handle other types if necessary */
                free(new_page);
                return false;
        }

        /* Call uninit_new to create an uninitialized page. */
        uninit_new(new_page, upage, init, type, aux, initializer);

        /* Modify the writable field after creating the page. */
        new_page->writable = writable;

        /* Insert the page into the supplemental page table (SPT). */
        if (!spt_insert_page(spt, new_page)) {
            goto err;  // If insertion fails, clean up and return false.
        }

        return true;  // Success!
    err:
        free(new_page);  // Clean up the allocated memory on failure.
        return false;
    }
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	// struct page *page = NULL;
	/* TODO: Fill this function. */

	// return page;

    /* NOTE: The beginning where custom code is added */
    /* Align the virtual address to the page boundary */
    va = pg_round_down (va);  

    /* Create a dummy page to search for the desired page */
    struct page p;
    p.va = va;

    /* Find the page in the hash table */
    struct hash_elem *e = hash_find (&spt->page_table, &p.hash_elem);
    
    if (e == NULL) {
        return NULL;  // Page not found
    }
    
    /* Return the found page */
    return hash_entry (e, struct page, hash_elem);
    /* NOTE: The end where custom code is added */
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
	// int succ = false;
	/* TODO: Fill this function. */

	// return succ;

    /* NOTE: The beginning where custom code is added */
    /* Ensure that spt and page are valid. */
    if (spt == NULL || page == NULL) {
        return false;
    }

    /* Try to insert the page into the supplemental page table (SPT). */
    struct hash_elem *prev = hash_insert(&spt->page_table, &page->hash_elem);

    /* If prev is NULL, the insertion was successful. */
    return (prev == NULL);
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

    // static struct list_elem *clock_hand = NULL;

    // /* If the clock hand is uninitialized, start from the beginning of the frame list. */
    // if (clock_hand == NULL || clock_hand == list_end(&frame_list)) {
    //     clock_hand = list_begin(&frame_list);
    // }

    // while (true) {
    //     struct frame *frame = list_entry(clock_hand, struct frame, elem);
        
    //     /* Check the accessed bit for the page associated with this frame. */
    //     if (!pml4_is_accessed(thread_current()->pml4, frame->page->va)) {
    //         // If the accessed bit is not set, this is our victim.
    //         return frame;
    //     }

    //     // Otherwise, clear the accessed bit and move the clock hand forward.
    //     pml4_set_accessed(thread_current()->pml4, frame->page->va, false);
    //     clock_hand = list_next(clock_hand);

    //     // If we reach the end of the list, wrap around to the beginning.
    //     if (clock_hand == list_end(&frame_list)) {
    //         clock_hand = list_begin(&frame_list);
    //     }
    // }

    // /* In case no frame is selected (shouldn't happen), return NULL. */
    // return NULL;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	// struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

    /* NOTE: The beginning where custom code is added */
    struct frame *victim = vm_get_victim ();

    if (victim == NULL) {
        return NULL;  // No victim available, return NULL.
    }

    /* Swap out the page associated with the victim frame. */
    if (victim->page != NULL) {
        if (!swap_out(victim->page)) {
            return NULL;  // Swap out failed, return NULL.
        }

        /* After swapping out, disconnect the page from the frame. */
        victim->page->frame = NULL;
        victim->page = NULL;
    }

    /* Return the evicted frame, which is now available for reuse. */
    return victim;
    /* NOTE: The end where custom code is added */

	// return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
    /* 프레임 구조체 동적 할당 */
    struct frame *frame = malloc(sizeof(struct frame));  // 프레임 구조체를 명시적으로 할당
    if (frame == NULL) {
        return NULL;  // 메모리 할당 실패 시 NULL 반환
    }

    /* palloc을 통해 커널 가상 주소 할당 */
    frame->kva = palloc_get_page(PAL_USER);  // 사용자 풀에서 페이지 할당
    if (frame->kva == NULL) {
        return NULL;
        /* 페이지 할당 실패 시 페이지 교체 수행 */
        // frame = vm_evict_frame();  // 페이지 교체를 통해 새 프레임 확보
        // if (frame == NULL) {
        //     return NULL;
        // }
    }

    /* 프레임 초기화 */
    frame->page = NULL;  // 현재는 페이지가 연결되지 않음

    /* 프레임 리스트에 추가 */
    // lock_acquire(&frame_list_lock);
    list_push_back(&frame_list, &frame->elem);  // 프레임을 전역 프레임 리스트에 추가
    // lock_release(&frame_list_lock);

    ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
    return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault(struct intr_frame *f, void *addr, bool user, bool write, bool not_present) {
    /* TODO: Validate the fault */
	/* TODO: Your code goes here */

    /* NOTE: The beginning where custom code is added */
    struct supplemental_page_table *spt = &thread_current()->spt;

    /* 페이지 폴트가 발생한 주소의 페이지를 찾습니다. */
    struct page *page = spt_find_page(spt, addr);
    
    /* 페이지가 존재하지 않거나, 해당 주소가 유효하지 않다면 실패로 처리합니다. */
    if (page == NULL || !not_present) {
        return false;
    }

    /* 만약 쓰기 접근이고 페이지가 쓰기 불가능하면 실패로 처리합니다. */
    if (write && !page->writable) {
        return false;
    }

    /* 페이지를 물리 메모리에 할당하여 처리합니다. */
    if (!vm_do_claim_page(page)) {
        return false;  // 페이지 할당 실패 시 false 반환
    }

    return true;
    /* NOTE: The end where custom code is added */
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
vm_claim_page (void *va) {
	// struct page *page = NULL;
	/* TODO: Fill this function */

	// return vm_do_claim_page (page);

    /* NOTE: The end where custom code is added */
    struct supplemental_page_table *spt = &thread_current()->spt;

    /* Find the page associated with the virtual address va. */
    struct page *page = spt_find_page(spt, va);
    if (page == NULL) {
        return false;  // The page does not exist, return false.
    }

    /* Call vm_do_claim_page to actually allocate the frame and map it. */
    return vm_do_claim_page(page);
    /* NOTE: The end where custom code is added */
}

/* Claim the PAGE and set up the mmu. */
bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

    /* NOTE: The beginning where custom code is added */
    if (frame == NULL) {
        return false;  // No available frame, return false.
    }
    /* NOTE: The end where custom code is added */

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */

    /* NOTE: The beginning where custom code is added */
    /* Insert the page table entry to map the page's virtual address (va) 
       to the frame's physical address (frame->kva). */
    // if (!pagedir_set_page(thread_current()->pagedir, page->va, frame->kva, page->writable)) {
    //     /* If we can't map the page in the page table, free the frame and return false. */
    //     vm_free_frame(frame);
    //     return false;
    // }
    if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable)) {
        // palloc_free_page(frame);
        // free(frame);
        return false;
    }
    /* NOTE: The end where custom code is added */

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
    /* Ensure spt is not NULL */
    // ASSERT(spt != NULL);

    /* Initialize the hash table in the supplemental page table */
    hash_init(&spt->page_table, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy(struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {

    /* NOTE: The beginning where custom code is added */
	struct hash_iterator i;
	hash_first(&i, &src->page_table);
	while (hash_next(&i)) {
		struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
		enum vm_type type = src_page->operations->type;
		void *upage = src_page->va;
		bool writable = src_page->writable;
		if (type == VM_UNINIT) {
			vm_initializer *init = src_page->uninit.init;
			void *aux = src_page->uninit.aux;
			vm_alloc_page_with_initializer(VM_ANON, upage, writable, init, aux);
			continue;
		}

		if (!vm_alloc_page(type, upage, writable)) {
			return false;
		}

		if (!vm_claim_page(upage)) {
			return false;
		}

		struct page *dst_page = spt_find_page(dst, upage);
		memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
	}
	return true;
    /* NOTE: The end where custom code is added */
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */

    /* NOTE: The beginning where custom code is added */
    hash_clear(&spt->page_table, page_destroy);
    /* NOTE: The end where custom code is added */
}
