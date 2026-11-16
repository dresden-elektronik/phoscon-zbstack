#ifndef ZB_LIMITS_H
#define ZB_LIMITS_H

/* The sizes of the library's fixed pools and its optional parts, each a default a build may override with `-D`,
   as CMake's options do. Every translation unit must see the same values, since they shape structs that cross
   targets. docs/configuration.md gives each one's cost and what it couples with, and §7 the sizes the suites pass at. */

#ifndef ZB_APS_FRAGMENTATION
#define ZB_APS_FRAGMENTATION 1          /* 1: APS fragmentation is built; 0: a fragmented frame is DEFRAG_UNSUPPORTED */
#endif

#if ZB_APS_FRAGMENTATION != 0 && ZB_APS_FRAGMENTATION != 1
#error "ZB_APS_FRAGMENTATION is 0 or 1"
#endif

#ifndef ZB_ZDO_CLIENT
#define ZB_ZDO_CLIENT 0                 /* 1: the device object's client half and Zb_StackZdoRequest are built */
#endif

#if ZB_ZDO_CLIENT != 0 && ZB_ZDO_CLIENT != 1
#error "ZB_ZDO_CLIENT is 0 or 1"
#endif

#ifndef ZB_LIMIT_APS_TX
#define ZB_LIMIT_APS_TX 8               /* APS data requests in flight at once */
#endif

#ifndef ZB_LIMIT_NWK_TX
#define ZB_LIMIT_NWK_TX 8               /* NWK frames issued and not yet confirmed */
#endif

#ifndef ZB_LIMIT_MAC_TX_TRACK
#define ZB_LIMIT_MAC_TX_TRACK 8         /* MAC transmits issued, and the confirms their answers produced */
#endif

#ifndef ZB_LIMIT_MAC_TRANSACTION
#define ZB_LIMIT_MAC_TRANSACTION 32     /* frames held for a sleepy child's poll */
#endif

#ifndef ZB_LIMIT_MAC_INDICATION
#define ZB_LIMIT_MAC_INDICATION 8       /* received frames the MAC holds for the layer above: one radio poll's worth */
#endif

#ifndef ZB_LIMIT_NWK_INDICATION
#define ZB_LIMIT_NWK_INDICATION 8       /* received frames waiting in APS for the layer above */
#endif

#ifndef ZB_LIMIT_CORE_INDICATION
#define ZB_LIMIT_CORE_INDICATION ZB_LIMIT_NWK_INDICATION   /* frames for the application: one turn's worth */
#endif

#ifndef ZB_LIMIT_NWK_NEIGHBOR
#define ZB_LIMIT_NWK_NEIGHBOR 64        /* the neighbour table: parent, children and routers in range */
#endif

#ifndef ZB_LIMIT_NWK_ROUTE
#define ZB_LIMIT_NWK_ROUTE 128          /* the routing table */
#endif

#ifndef ZB_LIMIT_NWK_DISCOVERY
#define ZB_LIMIT_NWK_DISCOVERY 8        /* route discoveries under way */
#endif

#ifndef ZB_LIMIT_NWK_SOURCE_ROUTE
#define ZB_LIMIT_NWK_SOURCE_ROUTE 200   /* the source route table */
#endif

#ifndef ZB_LIMIT_NWK_BTT
#define ZB_LIMIT_NWK_BTT 32             /* broadcasts remembered, against their repeats */
#endif

#ifndef ZB_LIMIT_AF_ENDPOINT
#define ZB_LIMIT_AF_ENDPOINT 8          /* application endpoints */
#endif

#ifndef ZB_LIMIT_AF_CLUSTER
#define ZB_LIMIT_AF_CLUSTER 16          /* clusters in one endpoint's input list, and in its output list */
#endif

#ifndef ZB_LIMIT_APS_BIND
#define ZB_LIMIT_APS_BIND 8             /* the binding table */
#endif

#ifndef ZB_LIMIT_APS_GROUP
#define ZB_LIMIT_APS_GROUP 16           /* the group table's memberships */
#endif

#ifndef ZB_LIMIT_APS_DUP
#define ZB_LIMIT_APS_DUP 64             /* frames remembered against duplicates: 1.6 s x 3 retries at 13 a second */
#endif

#ifndef ZB_LIMIT_SECURITY_KEYPAIR
#define ZB_LIMIT_SECURITY_KEYPAIR 200   /* link keys held, one per device the trust centre gave one */
#endif

#ifndef ZB_LIMIT_CORE_JOINER
#define ZB_LIMIT_CORE_JOINER 200        /* joiners whose parent a trust centre remembers */
#endif

#ifndef ZB_LIMIT_NWK_ADDR_MAP
#define ZB_LIMIT_NWK_ADDR_MAP 200       /* Table 3-68's address map: devices whose two addresses this one knows */
#endif

#ifndef ZB_LIMIT_SECURITY_INCOMING
#define ZB_LIMIT_SECURITY_INCOMING 128  /* NWK frame-counter windows, one per previous hop and key */
#endif

#if ZB_LIMIT_APS_TX < 1 || ZB_LIMIT_NWK_TX < 1 || ZB_LIMIT_MAC_TX_TRACK < 1 || ZB_LIMIT_MAC_TRANSACTION < 1 ||  \
    ZB_LIMIT_MAC_INDICATION < 1 || ZB_LIMIT_NWK_INDICATION < 1 || ZB_LIMIT_CORE_INDICATION < 1 ||              \
    ZB_LIMIT_NWK_NEIGHBOR < 1 || ZB_LIMIT_NWK_ROUTE < 1 || ZB_LIMIT_NWK_DISCOVERY < 1 ||                      \
    ZB_LIMIT_NWK_SOURCE_ROUTE < 1 || ZB_LIMIT_NWK_BTT < 1 || ZB_LIMIT_AF_ENDPOINT < 1 ||                      \
    ZB_LIMIT_AF_CLUSTER < 1 || ZB_LIMIT_APS_BIND < 1 || ZB_LIMIT_APS_GROUP < 1 || ZB_LIMIT_APS_DUP < 1 ||     \
    ZB_LIMIT_SECURITY_KEYPAIR < 1 || ZB_LIMIT_CORE_JOINER < 1 || ZB_LIMIT_NWK_ADDR_MAP < 1 ||                \
    ZB_LIMIT_SECURITY_INCOMING < 1
#error "every ZB_LIMIT_* is at least 1"
#endif

/* An acknowledgement and a route request are matched on an 8-bit counter, unique among those in flight. */
/* One radio batch (RADIO_FRAME_BATCH_MAX, 8): a shallower ring takes fewer frames a turn, and the suites prove 8 up */
#if ZB_LIMIT_MAC_INDICATION < 8
#error "ZB_LIMIT_MAC_INDICATION is at least 8, one radio batch"
#endif

#if ZB_LIMIT_APS_TX > 256 || ZB_LIMIT_NWK_DISCOVERY > 256
#error "ZB_LIMIT_APS_TX and ZB_LIMIT_NWK_DISCOVERY are at most 256"
#endif

/* A NWK frame's handle is one octet, shared with the relays held behind the pool. */
#if ZB_LIMIT_NWK_TX > 250
#error "ZB_LIMIT_NWK_TX is at most 250"
#endif

/* The management reports count their entries in one octet, and duplicates are told apart by an 8-bit counter. */
#if ZB_LIMIT_NWK_NEIGHBOR > 255 || ZB_LIMIT_NWK_ROUTE > 255 || ZB_LIMIT_APS_BIND > 255 || ZB_LIMIT_APS_DUP > 255
#error "ZB_LIMIT_NWK_NEIGHBOR, ZB_LIMIT_NWK_ROUTE, ZB_LIMIT_APS_BIND and ZB_LIMIT_APS_DUP are at most 255"
#endif

/* An Active_EP_rsp lists every endpoint in one ZDP frame, and a cluster count is one octet. */
#if ZB_LIMIT_AF_ENDPOINT > 77 || ZB_LIMIT_AF_CLUSTER > 255
#error "ZB_LIMIT_AF_ENDPOINT is at most 77 and ZB_LIMIT_AF_CLUSTER at most 255"
#endif

#endif
