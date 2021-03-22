# BIRD Journey to Threads. Chapter 2: Asynchronous route export

BIRD is a fast, robust and memory-efficient routing daemon designed and
implemented at the end of 20th century. We're doing a significant amount of
BIRD's internal structure changes to make it possible to run in multiple
threads in parallel. One of the major changes is route export rework.

## How routes are propagated through BIRD

In the previous chapter, you could learn how the route import works. We should
now extend that process by the route export.

1. (In protocol code.) Create the route itself and propagate it through the
   right channel by calling `rte_update`.
2. The channel runs its import filter.
3. New best route is selected.
4. For each channel:
    1. The channel runs its preexport hook and export filter.
    2. (Optionally.) The channel merges the nexthops to create an ECMP route.
    3. The channel calls the protocol's `rt_notify` hook.
5. After all exports are finished, the `rte_update` call finally returns and
   the source protocol may do anything else.

Let's imagine that all the protocols are running in parallel. There are two
protocols with a route prepared to import. One of those wins the table lock,
does the import and then the export touches the other protocol which must
either:
* store the route export until it finishes its own imports, or
* have independent import and export parts.

Both of these conditions are infeasible for common use. Implementing them would
make protocols much more complicated with lots of new code to test and release
at once and also quite a lot of corner cases. Risk of deadlocks is also worth
mentioning.

## Asynchronous route export

We decided to make it easier for protocols and decouple the import and export
this way:

1. The import is done.
2. Best route is selected.
3. Resulting changes are stored.

Then, after the importing protocol returns, the exports are processed for each
exporting channel. In future, this will be possible in parallel: Some protocols
may process the export directly after it is stored, other protocols will wait
until they finish another job.

This eliminates the risk of deadlocks and all protocols' `rt_notify` hooks can
rely on their independence. There is only one question. How to store the changes?

## Route export modes

To find a good data structure for route export storage, we shall first know the
readers. The exporters may request different modes of route export.

### Export everything

This is the most simple route export mode. The exporter wants to know about all
the routes as they're changing. We therefore simply store the old route until
the change is fully exported and then we free the old stored route.

To manage this, we can simply queue the changes one after another and postpone 
old route cleanup after all channels have exported the change. The queue member
would look like this:

```
struct {
  struct rte_storage *new;
  struct rte_storage *old;
};
```

### Export best

This is another simple route export mode. We check whether the best route has
changed; if not, no export happens. Otherwise, the export is propagated as the
old best route changing to the new best route. 

To manage this, we could use the queue from the previous point by adding new
best and old best pointers. It is guaranteed that both the old best and new
best pointers are always valid in time of export as all the changes in them
must be stored in future changes which have not been exported yet by this
channel and therefore not freed yet.

```
struct {
  struct rte_storage *new;
  struct rte_storage *new_best;
  struct rte_storage *old;
  struct rte_storage *old_best;
};
```

Anyway, we're getting to the complicated export modes where this simple
structure is simply not enough.

### Export merged

Here we're getting to some kind of problems. The exporting channel requests not
only the best route but also all routes that are good enough to be considered
ECMP-eligible (we call these routes *mergable*). The export is then just one
route with just the nexthops merged.  Export filters are executed before
merging and if the best route is rejected, nothing is exported at all.

To achieve this, we have to re-evaluate export filters any time the best route
or any mergable route changes. Until now, the export could lock solely the
export queue as all the pointed routes are read-only. The merged export needs
to look at the other routes as well.

We decided to solve this problem by enforcing an `export table` when `merge paths`
is enabled in config. Moreover, the only merging protocol is `kernel` for now
and this protocol also needs to periodically refeed the routes to check whether
the kernel fib is synced with BIRD table properly. To avoid periodic main table
locking and filter re-evaluation, the kernel protocol will use the export table
to store all routes after export filter evaluation. If merging, kernel will
*export everything* and merging will be done in the export table only,
otherwise it will *export best*.

So we can still go with the simple structure. Or not?

### Export first accepted

In this mode, the channel runs export filters on a sorted list of routes, best first.
If the best route gets rejected, it asks for the next one until it finds an
acceptable route or exhausts the list. This export mode requires a sorted table.
BIRD users will know this export mode as `secondary` in BGP.

For now, BIRD stores two bits per route for each channel. The *export bit* is set
if the route has been really exported to that channel. The *reject bit* is set
if the route was rejected by the export filter.

When processing a route change for accepted, the algorithm first checks the
export bit for the old route. If this bit is set, the old route is that one
exported so we have to find the right one to export. Therefore the sorted route
list is walked best to worst to find a new route to export, using the reject
bit to evaluate only routes which weren't rejected in previous runs of this
algorithm.

If the old route bit is not set, the algorithm walks the sorted route list best
to worst, checking the position of new route with respect to the exported route.
If the new route is worse, nothing happens, otherwise the new route is sent to
filters and finally exported if passes.

This mode can be also solved by enforcing `export table`, anyway let's try
whether we find anything better. Contrary to route merging, the *first
accepted* mode may be set in quite a lot of protocols, therefore causing a
large memory overhead.  But before that, there are other things to consider.

## Feature request: Pass route order information to export filters

There is a legimate request to allow the export filters to know whether the
current route is the best or other. Even more, the filter may know the order
of the route; whether it is first, third or whatever.

There is also a request to extend the *first accepted* policy to *first N
accepted* as well as *use only first N routes for filtering*. Let's try to make
this possible as well.

To summarize the feature, the channel would 

1. apply an optional limit on number of routes for the same destination,
2. run the filters,
3. and apply another optional limit on number of routes that pass the filters.

This may be configured like this:

* First accepted as `export net limit all 1;`
* Best as `export net limit 1;`
* Any as `export net limit all;`

## Implementation of exports with a double per-destination limit

First of all, let's assume that on every export, we may simply query the table
for a complete list of valid routes. Otherwise we have to store (in worst case)
the complete list in the table journal. This is obviously a problem if the route list
may change (or the whole destination may disappear) while being read unless we
go for RCU which is an overkill for now. For the very beginning, we'll just lock
the complete table by a mutex. This is going to be a bottleneck in future so
some of future chapters of this series will return to this topic.

### Pending export data structure

For unsorted tables, the double export limit is not possible to implement as
the non-best routes are considered equivalent. Therefore we have to consider
only sorted tables for the double export limit.

For sorted tables, in *export best* and *export everything* modes, there is no
need to lock the table at all. When *export first accepted* or similar modes
are active, we have to store also the old and new route order to reconstruct
the exact change. Anyway, to reconstruct it properly, we have to lock the table,
get all routes for the destination and process all the exports for single
destination at once. Therefore we also store the *next export for the same
destination* pointer.

Last problem is to skip exports which have been already processed by using the
*next export for the same destination* pointer. This is solved by adding a
table-local sequential ID to every export and a bitmap to every channel,
marking already processed exports by setting the appropriate bit.

```
struct rt_pending_export {
  struct rt_pending_export * _Atomic next;	/* Next export for the same destination */
  struct rte_storage *new;			/* New route */
  struct rte_storage *new_best;			/* New best route in unsorted table */
  struct rte_storage *old;			/* Old route */
  struct rte_storage *old_best;			/* Old best route in unsorted table */
  u32 new_order;				/* Order of the new route in sorted table */
  u32 old_order;				/* Order of the old route in sorted table */
  _Atomic u64 seq;				/* Sequential ID (table-local) of the pending export */
};
```

We should also add several items into `struct channel`.

```
  struct rt_pending_export *current_export;	/* If exporting, this is set, otherwise NULL */
  struct bmap export_seen_map;			/* One if that export has been already seen */
  u64 export_seq_indexer;			/* Sequential ID reducer for bitmap usage */
  u64 export_seq_last_cleanup;			/* Last sequential ID when cleanup was triggered */
  semaphore pending_exports_sem;		/* Post if export pushed */
  struct coroutine *export_coro;		/* The export coroutine */
```

Finally, some additional information has to be stored in `struct rtable`.

```
  list pending_exports;				/* List of packed struct rt_pending_export */
  struct fib export_fib;			/* Fib storing newest exports for each net */
  _Atomic u64 next_export_seq;			/* The next export will have this ID */
  coro *maint_coro;				/* Maintenance coroutine */
```

The `struct rt_pending_export` seems to be best allocated by requesting a whole
memory page, containing a common list node, a simple header and packed all the
structures in the rest of the page. Let's compare typical sizes on 32-bit and
64-bit architectures:

|                        | 64-bit  | 32-bit |
| ---------------------- | ------: | -----: |
| One list node size     |   16 B  |   8 B  |
| Size of one export	 |   56 B  |  36 B  |
| Exports in one page    |   72    |   112  |

In case of congestion, there will be lots of exports and every spare kilobyte
counts. If BIRD is almost idle, the optimization does nothing on the overall performance.

### Export algorithm

As we have explained at the beginning, the current export algorithm is
table-driven. The table walks the channel list and propagates the update.
The now export algorighm is channel-driven. The table just indicates that it
has something new in export queue and the channel decides what to do with that and when.

#### Pushing an export

When a table has something to export, it obtains, fills and enqueues an
instance of `struct rt_pending_export`. Then it pings its maintenance coroutine
(`rt_event`) to notify the exporting channels about a new route. If there is
already a ping pending, nothing is done.

The maintenance coroutine, when it manages to acquire the lock, walks the list
of channels and wakes or starts their export coroutines unless they are already
processing an older export.

These two levels of asynchronicity are here for two reasons.

1. There may be lots of channels (hundreds of them).
2. The notification is going to wait until the route author finishes, hopefully
   importing more routes and therefore allowing more exports to be processed at once.

The table also finds the route destination in an auxiliary table (`export_fib`).
This table stores the last exports for every destination. If there is no
record, it simply creates a record pointing to the new export. If there is
some, it sets that export's `next` pointer to this newer export and changes
also the record to point to this export. This subqueue makes it possible for
the double per-destination limit to work.

#### Processing an export

After those two levels of asynchronicity, the channel finally gets its turn.
The channel knows what export to begin with: it is either that one in the
notification (if notified), or simply the next one after the last processed.

1. The channel checks its `export_seen_map` whether this export has been
   already processed. If so, it skips to the next export. No action is needed.
2. The channel composes the final export for the current destination by walking
   the single-linked list in `next` pointers. The channel also marks all of
   these exports as processed in its `export_seen_map`.
3. If the double per-destination limit is set:
    1. The channel (in first version) simply always asks the table for the current state.
    2. Then the channel applies the recorded changes in reverse order.
    3. Finally, the channel processes all the changes.
4. In the best-only export mode, the `new_best` in the newest export is compared
   to the `old_best` in the oldest export and propagated if different.
5. In the export everything mode, the exports are (in first version) just propagated
   from beginning to end.
6. After the export is finished (or skipped):
    1. If there is no other export, the `export_seen_map` is reset and
       `export_seq_indexer` set to the table's `next_export_seq`.
       Then the channel export coroutine sets a timer for several seconds before
       shutting down.
    2. If there are still exports pending but the difference between
       `export_seq_indexer` and current export's `seq` is high enough,
       the channel also moves its `export_seq_indexer` and shifts all the bits
       in the `export_seen_map` down to reduce memory usage.
    3. In any case, if there are exports pending, the channel export coroutine
       releases and acquires the lock, allowing other routines to run as well,
       and goes on to process the next export.

#### Cleaning up

The last question is cleaning up the exports that have been processed by all
channels (and finally also freeing the routes). This is also done on demand by
the table's maintenance coroutine.

The channel export coroutine pings the table's maintenance coroutine in three cases.

1. The coroutine is shutting down after being idle.
2. Difference between the channel's `export_seq_last_cleanup` and
   `export_seq_indexer` values is higher than a threshold.
3. The channel's `export_seen_map` is being shifted.

The first case covers cleanup when BIRD is almost idle. The third case covers
cleanup in congestion times. The second case is the most tricky one; it covers
a situation when the table gets several updates per second in a steady rate,
enough to never shut down the export coroutines and also enough to reset the
`export_seen_map` after almost every export.

The table's maintenance coroutine walks all the channels and tries to find
whether it can free at least one whole page of pending exports (see above).
It may be not used completely but there must be no active export any more.
If impossible, it just waits for another ping. Otherwise …

1. The whole page is removed from the `pending_exports` list.
2. For each of the exports, the auxiliary table record is checked and cleared if needed.
3. All the `old` routes in the exports are freed.
4. Finally, the page itself is returned to OS.
5. If there is another page to clean up, the maintenance coroutine repeats this procedure.

## Next steps

After these changes, we have to move forward from threads to real parallel execution
to have some actual performance improvement.

*It's still a long road to the version 2.1. This series of texts should document
what is needed to be changed, why we do it and how. The previous chapter showed 
the necessary changes in route storage. In the next chapter, we're going to describe
how the coroutines are implemented and what kind of locking system are we
employing to prevent deadlocks. Stay tuned!*
