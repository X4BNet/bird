/*
 *	BIRD Internet Routing Daemon -- Raw allocation
 *
 *	(c) 2020  Maria Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "lib/resource.h"

#include <stdlib.h>
#include <unistd.h>

#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif

#ifdef HAVE_MMAP
static u64 page_size = 0;
#ifdef HAVE_ALIGNED_ALLOC
static _Bool use_fake = 0;
#endif
#else
static const u64 page_size = 4096; /* Fake page size */
#endif

u64 get_page_size(void)
{
  if (page_size)
    return page_size;

#ifdef HAVE_MMAP
  if (page_size = sysconf(_SC_PAGESIZE))
  {
    if ((u64_popcount(page_size) > 1) || (page_size > 16384))
    {
#ifdef HAVE_ALIGNED_ALLOC
      /* Too big or strange page, use the aligned allocator instead */
      page_size = 4096;
      use_fake = 1;
#else
      bug("Strange page size: %lu", page_size);
#endif
    }
    return page_size;
  }

  bug("Page size must be non-zero");
#endif
}

void *
alloc_page(void)
{
#ifdef HAVE_MMAP
#ifdef HAVE_ALIGNED_ALLOC
  if (!use_fake)
  {
#endif
    void *ret = mmap(NULL, get_page_size(), PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ret == MAP_FAILED)
      bug("mmap(%lu) failed: %m", page_size);
    return ret;
#ifdef HAVE_ALIGNED_ALLOC
  }
  else
#endif
#endif
#ifdef HAVE_ALIGNED_ALLOC
  {
    void *ret = aligned_alloc(page_size, page_size);
    if (!ret)
      bug("aligned_alloc(%lu) failed", page_size);
    return ret;
  }
#endif
}

void
free_page(void *ptr)
{
#ifdef HAVE_MMAP
#ifdef HAVE_ALIGNED_ALLOC
  if (!use_fake)
  {
#endif
    if (munmap(ptr, get_page_size()) < 0)
      bug("munmap(%p) failed: %m", ptr);
#ifdef HAVE_ALIGNED_ALLOC
  }
  else
#endif
#endif
#ifdef HAVE_ALIGNED_ALLOC
    free(ptr);
#endif
}