/* reproduces clang-21 merging arena stores without the required cast */
#define __arena __attribute__((address_space(1)))

struct links {
  unsigned long marker;
  struct links __arena *next;
  struct links __arena *prev;
  struct links __arena *fifo;
};

unsigned long zero_links(struct links __arena **slot)
{
  struct links __arena *p = *slot;
  unsigned long marker;

  if (!p)
    return 0;
  marker = p->marker;
  p->next = 0;
  p->prev = 0;
  p->fifo = 0;
  return marker;
}
