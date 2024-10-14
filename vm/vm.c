/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/* NOTE: The beginning where custom code is added */
static uint64_t
spt_hash_func(const struct hash_elem *e, void *aux) {
	const struct page *page = hash_entry(e, struct page, hash_elem);
	return hash_int(page->va); 
}

static bool
spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux) {
	const struct page *page_a = hash_entry(a, struct page, hash_elem);
	const struct page *page_b = hash_entry(b, struct page, hash_elem);
	return page_a->va < page_b->va;
}

void page_destructor(struct hash_elem *e, void *aux UNUSED) {
	struct page *page = hash_entry(e, struct page, hash_elem);
	vm_dealloc_page(page);
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
	lock_init(&spt_kill_lock);
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

		/* NOTE: The beginning where custom code is added */
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
	// struct page *page = NULL;
	/* TODO: Fill this function. */

	/* NOTE: The beginning where custom code is added */
	struct page page;
	struct hash_elem *found_elem;

	page.va = pg_round_down(va);
	found_elem = hash_find(&spt->pages, &page.hash_elem);

	return found_elem != NULL ? hash_entry(found_elem, struct page, hash_elem) : NULL;
	/* NOTE: The end where custom code is added */
	// return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
	// int succ = false;
	/* TODO: Fill this function. */
	/* NOTE: The beginning where custom code is added */
	if (hash_insert(&spt->pages, &page->hash_elem) != NULL) {
        free(page);
        return false;
    }
    return true;
	/* NOTE: The end where custom code is added */
	// return succ;
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
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	// struct frame *frame = NULL;
	/* TODO: Fill this function. */
	/* NOTE: The beginning where custom code is added */
	struct frame *frame = malloc(sizeof(struct frame));
	frame->kva = palloc_get_page(PAL_USER);
	frame->page = NULL;

	if (frame->kva == NULL)
		PANIC("todo");

	lock_acquire(&frame_table_lock);
    list_push_back(&frame_table, &frame->frame_elem);
	lock_release(&frame_table_lock);
	/* NOTE: The end where custom code is added */
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
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	// struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	/* NOTE: The beginning where custom code is added */
	void *fault_addr = pg_round_down(addr);
	if (fault_addr == NULL || !is_user_vaddr(fault_addr)) {
        return false;
    }
	struct page *page = spt_find_page(spt, fault_addr);

	if (page == NULL)
        return false;
    
	/* NOTE: The end where custom code is added */
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
	/* NOTE: The beginning where custom code is added */
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
	/* NOTE: The end where custom code is added */
    return true;
}




/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	/* NOTE: The beginning where custom code is added */
	if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable)) {
		/* TODO: may be need dealloc page and frame */
        return false;
    }
	/* NOTE: The end where custom code is added */
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	/* NOTE: The beginning where custom code is added */
	ASSERT(spt != NULL);
	hash_init(&spt->pages, spt_hash_func, spt_less_func, NULL);
	/* NOTE: The end where custom code is added */
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {

	/* Iterate through all entries in the source supplemental page table */
	struct hash_iterator i;
	hash_first(&i, &src->pages); // src의 해시 테이블을 순회하기 위한 초기화

	while (hash_next(&i)) {	
		struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem); // 현재 페이지 가져오기
		enum vm_type type = VM_TYPE(src_page->operations->type); // 페이지 타입 확인 (anon, file 등)

		/* 새로운 페이지를 할당하여 자식 프로세스에 추가합니다 */
		struct page *new_page = malloc(sizeof(struct page)); // 새 페이지를 위한 메모리 할당
		if (new_page == NULL) {
			return false;
		}

		/* 페이지 속성 복사 */
		new_page->va = src_page->va;
		new_page->writable = src_page->writable;
		new_page->is_loaded = src_page->is_loaded;
		new_page->operations = src_page->operations;

		/* 페이지 타입에 따라 적절히 초기화 및 클레임 */
		switch (type) {
			case VM_ANON:
				// anon 페이지 복사
				if (!anon_initializer(new_page, src_page->operations->type, NULL)) {
					free(new_page);
					return false;
				}
				break;
			case VM_FILE:
				// file-backed 페이지 복사
				if (!file_backed_initializer(new_page, src_page->operations->type, NULL)) {
					free(new_page);
					return false;
				}
				break;
			default:
				// 알 수 없는 타입의 경우 에러 처리
				free(new_page);
				return false;
		}

		/* 새로운 페이지를 destination의 supplemental page table에 추가 */
		if (!spt_insert_page(dst, new_page)) {
			free(new_page);
			return false;
		}

		/* 물리 메모리 할당 (frame 할당) */
		if (src_page->is_loaded) {
			if (!vm_do_claim_page(new_page)) {
				free(new_page);
				return false;
			}
			/* Frame의 내용 복사 (메모리 복사) */
			memcpy(new_page->frame->kva, src_page->frame->kva, PGSIZE);
		}
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	/* NOTE: The beginning where custom code is added */
	// lock_acquire(&spt_kill_lock);
	// hash_destroy(&spt->pages, page_destructor);
	// lock_release(&spt_kill_lock);
	/* NOTE: The end where custom code is added */
}