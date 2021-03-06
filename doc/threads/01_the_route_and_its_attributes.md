# BIRD Journey to Threads. Chapter 1: The Route and its Attributes

BIRD is a fast, robust and memory-efficient routing daemon designed and
implemented at the end of 20th century. Its concept of multiple routing
tables with pipes between them will be the topic of this and the following
chapter of BIRD Journey to Threads series.

## How routes are stored

BIRD routing table is just a hierarchical noSQL database. On top level, the
routes are keyed by their destination, called *net*. Due to historic reasons,
the *net* is not only *IPv4 prefix*, *IPv6 prefix*, *IPv4 VPN prefix* etc.,
but also *MPLS label*, *ROA information* or *BGP Flowspec record*. As there may
be several routes for each *net*, an obligatory part of the key is *src* aka.
*route source*. The route source is a tuple of the originating protocol
instance and a 32-bit unsigned integer. If a protocol wants to withdraw a route,
it is enough to have the *net* and *src* to identify what route is to be withdrawn.

The route itself consists of (basically) a list of key-value records, with
value types ranging from a 16-bit unsigned integer for preference to a BGP path
structure. The keys are pre-defined by protocols (e.g. BGP path or OSPF
metrics), or by BIRD core itself (preference, route gateway), or finally, the
user can declare their own attribute keys using the keyword `attribute` in config.

## Attribute list implementation

Currently, there are three layers of route attributes. We call them *route*
(*rte*), *attributes* (*rta*) and *extended attributes* (*ea*, *eattr*).

The first layer, *rte*, contains the *net* pointer, several fixed-size route
attributes (mostly preference and protocol-specific metrics), flags, lastmod
time and a pointer to *rta*.

The second layer, *rta*, contains the *src* (a pointer to a singleton instance),
a route gateway, several other fixed-size route attributes and a pointer to
*ea* list.

The third layer, *ea* list, is a variable-length list of key-value attributes,
containing all the remaining route attributes.

Distribution of the route attributes between the attribute layers is somehow
arbitrary. Mostly, in the first and second layer, there are attributes that
were thought to be accessed frequently (e.g. in best route selection) and
filled in in most routes, while in the third layer, there are infrequently used
and/or infrequently accessed route attributes.



When BGP or OSPF originates routes, there are commonly more routes with the same attribute list. 

