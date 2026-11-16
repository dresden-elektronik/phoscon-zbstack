# Conformance

An index from this stack's source files to the pages of the standards they implement.
Each row names one logical source file and the page ranges to read it against; the clauses' text is the standards' and is not copied here (D-150).
The per-rule detail lives in the code's own comments, one clause per rule, and in the suites that assert them.
A rule here that this stack chose rather than read is a decision in `docs/internals/decisions.md`.
The wire these rules act on is `docs/internals/protocol.md`; what a module owns is its header comment.

A row and its marks come from a two-direction audit of the file against the standard, the maintainers' procedure.

## 1. The MAC band: the clauses each source file implements

![A sequence diagram with four columns: the network layer and the MAC of this stack acting as parent, the Phoscon RCP, and a child end device whose receiver is off. The network layer hands a frame for the child to the MAC as Mac_IndirectRequest. The MAC queues it with MacIndirect_Queue, holding it for at most its persistence time, and writes the pendingTable to the RCP: the child's short and extended address, set as PROP_MAC_SRC_MATCH_ENABLED and the two address lists. When the child wakes it sends a Data Request. The RCP acknowledges it at once with Frame Pending 1, taken from the table without asking the host; this bit is amber. Only then does the RCP hand the Data Request up, marked acknowledged with Frame Pending. MacIndirect_DoPollAnswer picks the oldest frame held for the child and drops the child from the table, and the frame goes out through the RCP, its own Frame Pending bit saying whether more is held, never retried. The child acknowledges it, the RCP reports the completion, MacIndirect_ReleaseAttempt takes the frame off the queue, and the MAC confirms success to the network layer. A framed alternative shows the child never polling: MacIndirect_AgeTransactions discards the frame past its persistence time, the pendingTable is restated without the child, and the network layer is confirmed ZB_ERR_TRANSACTION_EXPIRED.](../images/indirect.png)

*Figure 1: a frame for a sleeping child.*
The parent writes the child's address into the RCP's source-match table ahead of time, so the RCP's Ack to the child's poll already carries Frame Pending, in amber, and the held frame follows.
Source: `tools/diagrams/indirect.py`.

One row per logical source file.
The clause numbers sit in the code's own comments, one per rule, and the pages are here so a reader can find what a file answers to.
M2024 is IEEE Std 802.15.4-2024, R23.1 is Zigbee Core R23.1 (05-3474-23); `docs/internals/refs.md` §1.2 says where each is obtained.

| Source file | Where its clauses are printed |
| --- | --- |
| `mac_frame.c` the frame codec | M2024 pages 62 (6.2), 79 (7.2.2), 82-83 (7.2.3, 7.2.4), 83 (7.2.8), 84 (7.2.11), 86-90 (7.3.1.2, 7.3.1.4, 7.3.1.5, 7.3.1.6), 91 (7.3.3), 93 (7.3.5), 182 (10.2.2.1) |
| `mac/mac_rx.c` the receive path and the filter | M2024 pages 62 (6.2), 70 (6.6.2), 84 (7.2.11), 88 (7.3.1.4), 108 (7.5.2), 116 (8.2.4.3), 361-363 (10.21.4, 10.21.5.1, 10.21.5.2), 377 (10.22.4.1), 379 (10.23.1); R23.1 pages 562-563 (Annex D.10.2) |
| `mac/mac_tx.c` the transmit path and its asks | M2024 pages 62 (6.2), 69-70 (6.6.1, 6.6.2), 72-73 (6.6.3.1, 6.6.3.4), 80 (7.2.2.4, 7.2.2.6), 82-84 (7.2.3, 7.2.4, 7.2.11), 86 (7.3.1), 93 (7.3.4.2, 7.3.4.3), 108 (7.5.2), 362-363 (10.21.5.1, 10.21.5.2), 374 (10.22.2), 377 (10.22.4.1), None (7.3.7); R23.1 pages 239 (3.2.1.1.3) |
| `mac/mac_scan.c` the ED, active and orphan scans and MLME-ORPHAN | M2024 pages 64-65 (6.4.1, 6.4.1.2), 69-70 (6.6.2), 108 (7.5.2, 7.5.4), 127-129 (8.2.8.2, 8.2.8.3), 350 (10.18), 351 (10.19), 352-355 (10.20.1, 10.20.2.1, 10.20.3.1, 10.20.4, 10.20.4.2, 10.20.4.3) |
| `mac/mac_beacon.c` the beacon, answered and received | M2024 pages 86-90 (7.3.1, 7.3.1.2, 7.3.1.4, 7.3.1.5, 7.3.1.6, 7.3.1.7), 108 (7.5.2), 116 (8.2.4.3), 351 (10.19), 375 (10.22.3), 377 (10.22.4.1) |
| `mac/mac_indirect.c` the transaction queue | M2024 pages 69 (6.6.1), 73 (6.6.3.4), 75 (6.6.6), 80 (7.2.2.4), 143 (8.3.4), 363 (10.21.5.2), 374-375 (10.22.2, 10.22.3), 378 (10.22.5.2, 10.22.5.3) |
| `mac/mac_assoc.c` the association, both halves | M2024 pages 62 (6.2), 70 (6.6.2), 88 (7.3.1.4), 112 (8.2.2), 356 (10.21.2), 361-363 (10.21.4, 10.21.5.1, 10.21.5.2), 369 (10.21.6.1.5), 374-375 (10.22.2, 10.22.3), 377 (10.22.4.1), None (7.1.17); R23.1 pages 342 (3.6.1.6.1) |
| `mac/mac.c` the façade, the PIB and the confirmations | M2024 pages 62 (6.2), 69-70 (6.6.1, 6.6.2), 73 (6.6.3.4), 82 (7.2.3), 86-87 (7.3.1, 7.3.1.2), 89 (7.3.1.6), 108 (7.5.2, 7.5.4), 112 (8.2.2), 116 (8.2.4.3), 127-129 (8.2.8.2, 8.2.8.3), 136 (8.3.2), 143 (8.3.4), 146 (8.3.5), 148 (8.3.6), 351 (10.19), 352-355 (10.20), 356 (10.21.2), 362-363 (10.21.5, 10.21.5.1, 10.21.5.2), 369 (10.21.6.1.5), 374-375 (10.22.2, 10.22.3), 377-379 (10.22.4.1, 10.22.5.2, 10.22.5.3, 10.23.1), None (7.2.1.4) |

## 2. The NWK band: the clauses each source file implements

![A sequence diagram with three routers as columns: originator S, this stack; relay R; and destination D, out of S's range. S has a frame for D and no route: it holds the frame in its transmit slot, NWK_TX_AWAITING_ROUTE, and marks a routing entry for D as NWK_ROUTE_DISCOVERY_UNDERWAY with a discovery entry. S broadcasts a Route Request to every router with path cost zero. R records a discovery entry and an active reverse route to S, and rebroadcasts the request after a jitter with the S to R link cost added. D finds the request is for itself, records a reverse route to S through R, and unicasts a Route Reply to R. R sets its route to D active with next hop D and readdresses the reply to S. The Route Reply reaching S is amber: S's route to D turns active through R and the requests stop. S sends the held frame to R, which acknowledges it at the MAC; R relays it over its route to D, which acknowledges it at the MAC; and D returns an APS acknowledgement end to end when one was asked for. Two framed alternatives follow. If no reply comes, the discovery entry expires and the frame is confirmed NWK_STATUS_ROUTE_ERROR without being sent. If a link breaks later, R's relayed frame goes unacknowledged, Nwk_RouteInvalidate turns every route through D inactive, R sends a Network Status naming D to S, and S removes its route, so its next frame for D starts a new discovery.](../images/routing.png)

*Figure 2: finding a route.*
S holds the frame and broadcasts a Route Request; the Route Reply that comes back along the reverse routes, in amber, makes S's route active and releases the frame.
Source: `tools/diagrams/routing.py`.

One row per logical source file, and the clause list is what that file answers to: the pages are where each clause's own heading is printed, resolved from the clause and not from a cross-reference.

| Source file | Where its clauses are printed |
| --- | --- |
| `nwk/nwk_frame.c` the NPDU codec | R23.1 pages 50 (1.4.2), 288-293 (3.3, 3.3.1.1, 3.3.1.1.2, 3.3.1.1.5, 3.3.1.2, 3.3.1.3, 3.3.1.4, 3.3.1.5, 3.3.1.6, 3.3.1.7, 3.3.1.8, 3.3.1.8.1, 3.3.2.2.2, 3.4), 295 (3.4.1.1), 379 (3.6.4.3), 383 (3.6.4.5), 392 (3.6.6), 396 (3.6.7), 421 (4.3.2)  |
| `nwk/nwk_rx.c` the receive path and the radius | R23.1 pages 291 (3.3.1.1.8, 3.3.1.7), 305 (3.4.7.2), 350 (3.6.1.6.1, 3.6.1.6.1.3), 355 (3.6.1.7), 320 (3.4.14), 372 (3.6.2.2), 374 (3.6.2.3), 380 (3.6.4.3.2), 379 (3.6.4.3), 382 (3.6.4.4.3, 3.6.4.4.4), 384 (3.6.4.5.1.2), 392 (3.6.6), 420 (4.3.1.2), 478 (4.5.1.3) |
| `nwk/nwk_tx.c` the transmit path and its retries | M2024 pages 82-84 (7.2.4), 374 (10.22.2); R23.1 pages 239-240 (3.2.1.1.1, 3.2.1.1.3, 3.2.1.2.1), 291 (3.3.1.5, 3.3.1.6, 3.3.1.7, 3.3.1.8), 293 (3.3.2.2.2), 295 (3.4.1.1), 379 (3.6.4.3), 393-394 (3.6.6), 383 (3.6.4.5.1), 411 (3.6.13), 417 (4.2.2), 419-421 (4.3.1.1, 4.3.1.2, 4.3.2) |
| `nwk/nwk_addr.c` the addressing, the broadcast classes and the address map | R23.1 pages 239 (3.2.1.1.3), 291 (3.3.1.2, 3.3.1.3), 334 (Table 3-68), 360-361 (3.6.1.10.1, 3.6.1.10.2), 372 (3.6.2.2), 392 (3.6.6) |
| `nwk/nwk_btt.c` the broadcast transaction table | R23.1 pages 392 (3.6.6) |
| `nwk/nwk_command.c` the command layer | R23.1 pages 293 (3.3.2.2.2), 299-300 (3.4.3.2, 3.4.3.3.1), 302 (3.4.3.3.2), 363 (3.6.1.10.5), 372 (3.6.2.2), 383 (3.6.4.5.1), 387 (3.6.4.5.2), 390 (3.6.4.8.1), 411 (3.6.13), 417 (4.2.2) |
| `nwk/nwk_cost.c` the link cost | R23.1 pages 375 (3.6.4.1), 383 (3.6.4.5.1), 388 (3.6.4.5.3) |
| `nwk/nwk_discovery.c` the discovery helpers | R23.1 pages 122 (2.4), 376 (3.6.4.2), 379 (3.6.4.3), 383 (3.6.4.5.1), 386 (3.6.4.5.1.7) |
| `nwk/nwk_parents.c` the discovery table and its ranking, and the ED scan | R23.1 pages 246-247 (3.2.2.2.3, 3.2.2.3, 3.2.2.4), 254-256 (3.2.2.11, 3.2.2.12), 339-340 (3.6.1.5, 3.6.1.5.1, 3.6.1.5.2), 354 (3.6.1.6.1.4) |
| `nwk/nwk_neighbor.c` the neighbour table | R23.1 pages 344 (3.6.1.6.1.1), 350 (3.6.1.6.1.3), 360 (3.6.1.9), 372 (3.6.2.2), 374 (3.6.2.3), 375 (3.6.3), 379 (3.6.4.3), 381-383 (3.6.4.4.1, 3.6.4.4.3, 3.6.4.4.4, 3.6.4.5.1), 390 (3.6.4.8), 392 (3.6.6) |
| `nwk/nwk_linkstatus.c` the link status command and the two metrics the ranking is made of | R23.1 pages 307-308 (3.4.8, 3.4.8.3.1, 3.4.8.3.2), 341 (3.6.1.6), 380 (3.6.4.4.1), 381 (3.6.4.4.2), 382 (3.6.4.4.3, 3.6.4.4.3.1, 3.6.4.4.4) |
| `nwk/nwk_sourceroute.c` the route record and Table 3-67's source route table | R23.1 pages 291 (3.3.1.8.3), 304 (3.4.5), 391 (3.6.4.5.5) |
| `nwk/nwk_poll.c` a resting end device's polls and NLME-SYNC | R23.1 pages 223-224 (2.5.4.5.5.1, 2.5.4.5.5.2), 268 (3.2.2.24, 3.2.2.25), 371 (3.6.1.15), 372 (3.6.2.2) |
| `nwk/nwk_timeout.c` the end device timeout command pair | R23.1 pages 313-316 (3.4.11, 3.4.12, Table 3-58), 400 (3.6.10) |
| `nwk/nwk_indirect.c` indirect delivery to a sleepy child | R23.1 pages 239 (3.2.1.1.3), 392 (3.6.6) |
| `nwk/nwk_join.c` the join and the rejoin | R23.1 pages 313-316 (3.4.11, 3.4.12), 320-323 (3.4.14, 3.4.15, 3.4.15.2), 122 (2.4), 256 (3.2.2.13), 258-259 (3.2.2.14, 3.2.2.15), 291 (3.3.1.2), 293 (3.4), 295 (3.4.1.1), 305-307 (3.4.6, 3.4.6.1, 3.4.6.2, 3.4.6.3.1, 3.4.7, 3.4.7.1, 3.4.7.2, 3.4.7.3.1), 342 (3.6.1.6.1), 344 (3.6.1.6.1.1), 347 (3.6.1.6.1.2), 350 (3.6.1.6.1.3), 361-362 (3.6.1.10.3, 3.6.1.10.5, 3.6.1.10.6), 360 (3.6.1.8), 390 (3.6.4.8.1), 399 (3.6.9), 400-401 (3.6.10.2, 3.6.10.3), 403 (3.6.10.8), 411 (3.6.13), 420 (4.3.1.2) |
| `nwk/nwk_get.c` the NIB read of the two tables | R23.1 pages 270-271 (3.2.2.27, 3.2.2.28) |
| `nwk/nwk_leave.c` the leave command and the four leave procedures | R23.1 pages 263-265 (3.2.2.18, 3.2.2.18.3, 3.2.2.19, Table 3-26, Table 3-27, Table 3-28), 303 (3.4.4.2, 3.4.4.3.1), 363-368 (3.6.1.11.1, 3.6.1.11.2, 3.6.1.11.3, 3.6.1.11.4), 402 (3.6.10.4.1), 496 (4.6.3.6.3) |
| `nwk/nwk_permit.c` the association permit and its countdown | R23.1 pages 251-252 (3.2.2.7, 3.2.2.7.3, 3.2.2.8.1, Table 3-15, Table 3-16) |
| `nwk/nwk_relay.c` the relay | R23.1 pages 122 (2.4), 372 (3.6.2.2), 379 (3.6.4.3), 390 (3.6.4.8.1), 392 (3.6.6) |
| `nwk/nwk_route.c` the routing table | R23.1 pages 376 (3.6.4.2), 379 (3.6.4.3), 383 (3.6.4.5.1), 387-388 (3.6.4.5.2, 3.6.4.5.3), 390 (3.6.4.8, 3.6.4.8.1) |
| `nwk/nwk_rreq.c` the route request | R23.1 pages 50 (1.4.2), 291 (3.3.1.5), 295-296 (3.4.1.3, 3.4.1.3.1, 3.4.1.3.1.2, 3.4.1.3.2, 3.4.1.3.4, 3.4.1.3.5), 383 (3.6.4.5.1), 396 (3.6.7)  |
| `nwk/nwk_rreqrelay.c` the request relayed | R23.1 pages 122 (2.4), 383 (3.6.4.5.1) |
| `nwk/nwk_rreqrx.c` the request received | R23.1 pages 291 (3.3.1.4), 295-296 (3.4.1.2, 3.4.1.3.2, 3.4.1.3.3), 383 (3.6.4.5.1), 388 (3.6.4.5.3) |
| `nwk/nwk_rreqtx.c` the request sent | R23.1 pages 122 (2.4), 295 (3.4.1.1, 3.4.1.2), 383 (3.6.4.5.1) |
| `nwk/nwk_rrep.c` the route reply composed | R23.1 pages 50 (1.4.2), 297-298 (3.4.2.2, 3.4.2.3, 3.4.2.3.1, 3.4.2.3.4, 3.4.2.3.5, 3.4.2.3.6, 3.4.2.3.7), 387 (3.6.4.5.2), 396 (3.6.7)  |
| `nwk/nwk_rreprx.c` the route reply received | R23.1 pages 387-388 (3.6.4.5.2, 3.6.4.5.3) |
| `nwk/nwk_status.c` the network status command | R23.1 pages 300 (3.4.3.3, 3.4.3.3.1), 302 (3.4.3.3.2), 390 (3.6.4.8.1), 411 (3.6.13) |
| `nwk/nwk_tlv.c` the TLVs | R23.1 pages 288 (3.3) |
| `nwk/nwk_beacon.c` the beacon payload | R23.1 pages 399 (3.6.8.1, 3.6.8.2) |
| `nwk/nwk.c` the NWK façade and its dispatches | R23.1 pages 239 (3.2.1.1.1, 3.2.1.1.3), 246-247 (3.2.2.3, 3.2.2.4), 340 (3.6.1.5.1), 288-291 (3.3.1, 3.3.1.1.8), 293 (3.3.2.2.2, 3.4), 307 (3.4.8.1, 3.4.8.2), 42 (2.2.4.1.1, 2.2.4.1.3), 334 (Table 3-68), 342 (3.6.1.6.1), 344 (3.6.1.6.1.1), 360-363 (3.6.1.10.1, 3.6.1.10.2, 3.6.1.10.5), 360 (3.6.1.8), 371-374 (3.6.2), 379 (3.6.4.3), 390 (3.6.4.3.2), 380 (3.6.4.4.1), 381 (3.6.4.4.2), 400 (3.6.10, 3.6.10.1), 382 (3.6.4.4.3, 3.6.4.4.3.1, 3.6.4.4.4), 382-388 (3.6.4.5), 390 (3.6.4.5.5, 3.6.4.8), 392 (3.6.6), 393-394 (3.6.6), 396 (3.6.7), 411 (3.6.13), 417 (4.2.2), 419-421 (4.3.1, 4.3.2), 478 (4.5.1.3) |

## 3. The APS band and the security crossing: the clauses each source file implements

| Source file | Where its clauses are printed |
| --- | --- |
| `aps/aps_frame.c` the APDU codec | R23.1 pages 85-86 (2.2.5, 2.2.5.1.1), 88 (2.2.5.1.2, 2.2.5.1.3, 2.2.5.1.4, 2.2.5.1.5, 2.2.5.1.6, 2.2.5.1.7, 2.2.5.1.8), 90-91 (2.2.5.2, 2.2.5.2.2, 2.2.5.2.3), 101-102 (2.2.8.4.1, 2.2.8.4.3), 461 (4.4.10, 4.4.11), 477 (4.5.1) |
| `aps/aps.c` the service, its rings and its deferrals | R23.1 pages 60-61 (2.2.4, 2.2.4.1.1), 72 (2.2.4.3), 66 (2.2.4.1.2), 68 (2.2.4.1.3), 81-82 (2.2.4.5, 2.2.4.5.1, 2.2.4.5.3), 84-86 (2.2.4.5.5, 2.2.5, 2.2.5.1.1), 88 (2.2.5.1.6, 2.2.5.1.7), 91-92 (2.2.5.2.3, 2.2.7), 98 (2.2.8), 100-101 (2.2.8.3.1, 2.2.8.4.1, 2.2.8.4.2), 103 (2.2.8.4.4, 2.2.8.4.5), 425-426 (4.4.1, 4.4.1.1, 4.4.1.2), 64 (2.2.4.1.1.3), 63 (Table 2-2), 428 (4.4.1.3), 435 (4.4.2.2), 436-437 (4.4.2.3), 441 (4.4.5), 443 (4.4.5.2), 446 (4.4.7.1), 448 (4.4.7.2.3), 449 (4.4.8.1), 451 (4.4.8.2.3), 461 (4.4.11), 471 (4.4.12), 478 (4.5.1.3), 491 (4.6.3.4.2), 497 (4.6.3.7), 506 (4.6.3.8), 519 (4.7.3.8, 4.7.3.8.1), 437-439 (4.4.3), 530 (4.9.2), 483-484 (4.6.3.2.1), 439-440 (4.4.4, 4.4.4.1.3, 4.4.4.2) |
| `aps/aps_transportkey.c` the Transport-Key body | R23.1 pages 45 (1.2.3), 84 (2.2.5), 432 (4.4.2.1.3), 461-463 (4.4.11.1.2, 4.4.11.1.3, 4.4.11.1.3.1, 4.4.11.1.3.2, 4.4.11.1.3.3, 4.4.11.1.4) |
| `aps/aps_tclink.c` the trust centre link key commands | R23.1 pages 45 (1.2.3), 443 (4.4.5.2), 448 (4.4.7.2.3), 449 (4.4.8.1), 466 (4.4.11.4, 4.4.11.4.2, 4.4.11.4.3), 468 (4.4.11.7, 4.4.11.7.3, 4.4.11.7.4, 4.4.11.8), 519 (4.7.3.8, 4.7.3.8.1) |
| `aps/aps_admit.c` the Update Device, Remove Device and Tunnel bodies | R23.1 pages 45 (1.2.3), 438-439 (4.4.3.1.1, 4.4.3.2.3), 441 (4.4.4.2.3), 465 (4.4.11.2, 4.4.11.2.2, 4.4.11.2.3, 4.4.11.2.4, 4.4.11.2.5, 4.4.11.3, 4.4.11.3.2), 467 (4.4.11.6, 4.4.11.6.2, 4.4.11.6.3, 4.4.11.6.4), 477 (4.5.1), 483 (4.6.3.2.1), 495 (4.6.3.6.2), 497 (4.6.3.7.1, 4.6.3.7.2) |
| `aps/aps_keydoor.c` the two Transport-Key doors | R23.1 pages 428 (4.4.1.3, 4.4.1.5), 433 (4.4.2.1.3), 436-437 (4.4.2.3), 461 (4.4.11, 4.4.11.1), 530 (4.9.2) |
| `aps/aps_tx.c` the APS transmit | R23.1 pages 61 (2.2.4.1.1), 86 (2.2.5.1.1), 88 (2.2.5.1.2, 2.2.5.1.7), 101 (2.2.8.4.1), 103 (2.2.8.4.4), 425-426 (4.4.1.1, 4.4.1.2), 461 (4.4.10), 484 (4.6.3.2.1), 103-104 (2.2.8.4.5, 2.2.8.4.5.3) |
| `aps/aps_rx.c` the APS receive | R23.1 pages 86 (2.2.5.1.1), 426 (4.4.1.2), 461 (4.4.10) |
| `aps/aps_ack.c` the acknowledgements | R23.1 pages 61 (2.2.4.1.1), 86 (2.2.5.1.1), 91 (2.2.5.2.3), 101-103 (2.2.8.4.1, 2.2.8.4.2, 2.2.8.4.3, 2.2.8.4.4), 105 (2.2.8.4.5.4), 417 (4.2.2), 425 (4.4.1) |
| `aps/aps_dup.c` duplicate rejection | R23.1 pages 88 (2.2.5.1.7, 2.2.5.1.8), 101 (2.2.8.4.2), 103 (2.2.8.4.5) |
| `aps/aps_group.c` the group table | R23.1 pages 81-82 (2.2.4.5, 2.2.4.5.1, 2.2.4.5.3), 84 (2.2.4.5.5), 100-101 (2.2.8.3, 2.2.8.3.1, 2.2.8.4.2) |
| `security.c` the security crossing, over `src/crypto/` | R23.1 pages 414 (4.2), 419-420 (4.3, 4.3.1.1, 4.3.1.2), 421 (4.3.2), 423 (4.3.4, 4.3.4.1), 424 (4.4, 4.4.1.1), 426-427 (4.4.1.2), 455 (4.6.3.2.3, 4.6.3.2.4), 483 (4.6.3.2.1), 478 (4.5.1.3, 4.5.1.1.4), 479 (4.5.3), 489 (4.6.3.1), 491 (4.6.3.4.2), 506-508 (4.6.3.8, 4.6.3.8.1, Table 4-41), 448 (4.4.7.2.3), 449 (4.4.8.1), 468 (4.4.11.7.4), 513-514 (4.7.3.1), 519 (4.7.3.8.1) |
| `zb_state.c` the device's own state | R23.1 pages 399 (3.6.9), 419-420 (4.3, 4.3.1.2), 423 (4.3.4), 425 (4.4.1.1), 476 (4.4.12.1), 506 (4.6.3.8) |

### 3.1 What the NWK and APS bands have not built

Every deferral above is a mark on the file that owes it, and this list is the same set read as a work list: each clause with the reason its mark gives.
It is not a list of defects, and the audit's `0 defect marks` line is the one that says so.

- **3.6.1.8** in `nwk_join.c`: the NIST testing regimen the clause names for the address generator, a claim about a random source and not a code path; the rest of the clause, 3.2.2.13's four forms and 3.4.14's commissioning joins, is built
- **3.6.11** and **3.6.12** are MAYs no row claims: power negotiation and multiple MAC interfaces are features a device may choose, and this one has a single interface and no link power table
- **3.6.1.5** has no row: network and parent discovery is the application's, which fills Table 3-74's pool through `Nwk_JoinParentAdd`, and the pool's order stands in for 3.6.1.5.2's ranking, whose LQA bands and beacon flags the entries do not carry (D-223)
- **2.4.4.2** in `zdo/zdo.c`: a heard Device_annce moves the row of its IEEE address and counts a contradiction; the entry that held the announced address is not marked as having no known valid one, because the map has no such state
- **3.6.9** is `zb_state.c`'s: the SHOULD list, a parent's child list and an end device's parent are captured and restored, and a restored joiner is joined again with no join
- **2.2.4.1.1.3** over a restore: the map is not in the state, so `zb_state.c` maps the pairs the state names, a centralized network's trust centre at 0x0000 (4.6.2.2), an end device's parent and each child, and a bound 64-bit destination among them is sent rather than confirmed NO_SHORT_ADDRESS
- **2.4.3.1.12.1** has no row: a router or coordinator that rebooted SHALL broadcast a Parent_annce once joined, and nothing sends or answers one yet, so a restored parent learns that a child moved only through child aging
- **2.4.3.3.7.2** in `zdo/zdo.c`: the Beacon Appendix Encapsulation Global TLV of I.4.10 and the NIB value it sets, which is a TLV store this stack does not keep; the duration, the 0xff reading, the TC_Significance rule and the broadcast that owes no answer are built
- **3.2.2.18.3's MLME-RESET leg** in `nwk/nwk_leave.c`: 3.2.2.18.3 asks for an MLME-RESET when the rejoin arm is FALSE, and this stack's departure clears the NIB through 3.6.1.11.4 and the PIB identity instead; a MAC reset would also drop the DSN numbering and the beacon configuration band A applied, which the join and rejoin paths read back out of them

Nothing else in chapter 3 is deferred: routing's discovery, relay, repair, source routes and many-to-one reporting, the neighbour table's ranking, the join's four forms and its commissioning pair, the timeout exchange and the child aging, and the address map's conflicts are all built.

## 4. The security crossing: the module's contract

Not a clause index: this section states what this stack's own operations answer, and the clauses they implement are located in 9.5.

`security` is the CCM* crossing for both layers (4.3.1.1 with 4.3.1.2 over a network key, 4.4.1.1 with 4.4.1.2 over a link key) configured at birth, persisting nothing: 4.3.4's duties are the application's over what `Security_Snapshot` exports, and both halves share the `src/crypto` seam, the caller's `Security`, and one level.

| The operation | What it answers |
| --- | --- |
| `Security_Init`, `Security_Restore` | `ZB_OK`, or `ZB_ERR_BAD_ARGUMENT` for the first configuration rule failed: Init after zeroing the struct, Restore after validating only, so either refusal leaves what the caller had |
| `Security_Reset` | nothing; zeroes keys, link keys, both counter stores, the scratch buffers and the log pointer |
| `Security_IsEnabled`, `Security_IsAuthenticated`, `Security_Level` | the NWK question (a non-zero level and a live descriptor under the active sequence number), the joined flag, `nwkSecurityLevel` |
| `Security_Protect`, `Security_Unprotect` | `ZB_OK` with the secured NPDU, or the payload with the hop identity and whether a newer key was adopted; the refusals are the second bullet |
| `Security_ProtectAps`, `Security_UnprotectAps` | the same at the link-key crossing, plus the entry index Table 2-4's KeyIndex names, the resolved partner and the received RVFC bit |
| `Security_KeyPairCount`, `Security_FindKeyPairByIeee`, `Security_FindKeyPairByShort`, `Security_KeyPairAt` | the pool size; an entry's index by DeviceAddress or known short alias, -1 for none; one entry by index, 0 for none |
| `Security_Snapshot` | the observability view in parallel arrays: the active sequence number, the live descriptors, the key-pair bank |

- **The configuration.**
  `Security_Config`: the level (0, or Table 4-38's 1, 2, 3, 5, 6, 7, 4 refused, M = 0), this device's own extended address, the key set with a per-key outgoing counter, `nwkAllFresh`, the key pairs with a counter pair each, and the caller's log pool, 0 for reporting nowhere.
  It arrives here and nowhere else.
- **The NWK pair's refusals.**
  `ZB_ERR_BAD_ARGUMENT` a shape or bound; `ZB_ERR_UNSUPPORTED` level 0x00, or a control octet this stack never selects ('01' with extended nonce 1 is the only form read); `ZB_ERR_AUTH` no descriptor under the received sequence number, or a MIC that does not verify; `ZB_ERR_BAD_FRAME_COUNTER` a received 0xFFFFFFFF, a replay below the stored window, or an outgoing counter at 2^32-1; `ZB_ERR_NO_SPACE` the pool full with `nwkAllFresh` TRUE, or a frame over the band's ceiling; `ZB_ERR_INTERNAL` the CCM* seam refusing.
- **The APS pair's, and its one difference.**
  The same six words, from a partner resolved per 4.4.1.2 step 2 rather than from a sequence number: extended nonce set, the auxiliary header's source field decides the entry, and an authorized device refuses one naming another device than the hint (D-240); unset, the caller's EUI64 hint decides.
  `ZB_ERR_AUTH` therefore also covers a source no pair names, and step 8's `UNVERIFIED_FRAME_COUNTER` (peer synchronisation bit set, `VerifiedFrameCounter` clear), a word Table 2-2 does not print.
  The 5-or-13-octet auxiliary follows the nonce bit, not a caller's argument; the RVFC bit is reported.
- **Two policies a reader would otherwise guess at.**
  `nwkAllFresh` TRUE refuses a frame whose window would not fit the pool (`ZB_ERR_NO_SPACE`); FALSE accepts it and records nothing, that sender keeping no window: the house's reading, no clause printing an eviction policy.
  The window is committed only after the MIC verifies.
- **An acknowledgement's two crossings.**
  The NWK frame carrying an APS acknowledgement is secured whenever the device's security level is not NONE (that crossing is the device's state and not a `TxOptions` request) and the APSDU of that acknowledgement is not: 4.4.1 protects a data frame's Payload, and Figure 2-9 has none.
  4.4.1.1 secures a frame that "needs security protection" (a data request or a command that requires it) and prints no such need for an acknowledgement; Table 4-41 only lists the ACK types a peer may send APS-secured, which receipt already takes.
  So this stack's own acknowledgements stay APS-unsecured, a reading and not a printed rule.
- **Snapshot and restore.**
  The snapshot is the observability view in parallel arrays and nothing else of the state leaves it; the restore is validate-then-fill, installing counters exactly as given: the bank is `zb_state`'s.
- **The key-pair pool's door rules.**
  `KeyAttributes` PROVISIONAL, UNVERIFIED or VERIFIED, since 4.4.12.1 backs up every entry and an UNVERIFIED one is awaiting its Verify-Key, and encrypts nothing (4.4.1.1 step 1a-ii, 1b-i): the global pair secures a frame asked under it; a global link key held, 4.4.1.2 step 4's freshness rule printed for unique keys only; `Features & Capabilities` limited to 0x00/0x01, and a key-pair list beside level 0x00 refused: 4.4.1.1 step 3 takes the APS level from the NIB.

- **Two chapter-4 defects this module works around, recorded rather than followed.**
  4.3.1.1 step 3c names the auxiliary's fields in the nonce in the order "frame counter … source address … security control", crossing its own steps 2b and 2c, while 4.5.2.2 and Figure 4-26 print source address, frame counter, control: the fields decide, and `securityDoWriteNonce` writes that order.
  And 4.4.1.2 step 2 says the nonce's source is "the source address in the APS frame", a field an APS header does not carry at all; the reading taken is the NWK layer's source, from the auxiliary header when the extended nonce bit is set and from the matched key pair otherwise.

## 5. The recorded framing read by a party that has never seen this source

Not a clause index: a measured check of our own capture against a third-party dissector.

Fifteen frames this stack composed and an RCP put on the air, an NSDU sent unsecured and secured, were written to a libpcap file and dissected by `tshark` (Wireshark 4.6.9): an implementation with its own header tables, its own FCS implementation and its own CCM* code, given nothing from this repository but the octets.
What it reads is the confirmation D-119(a) asks for; what it declines is the boundary of what a witness of the framing can witness at all.

| What the outside dissection confirms | Where the claim stands | Mark |
| --- | --- | --- |
| The MHR of all 15 recorded frames: type data; Frame Version 0 with Security Enabled 0, the pairing 7.3.2.2 makes a version-0 frame carry, and Annex D.6 the reason this stack keeps it; Acknowledge Request 1, Frame Pending 0, PAN ID Compression 1 with both addressing modes 16-bit and **no source PAN field in the frame**; destination PAN `0xbeef`; `0x1234` and `0xdead` in that transmitted order; the sequence octet; and the last two octets as the footer, computing to what the octets ahead of them give, `wpan.fcs` Correct on 15/15 | 802.15.4-2024 7.2.2 with Figure 7-2, 7.2.4…7.2.7, Figure 7-14, 7.2.1 (MFR inside the MAC frame); Zigbee R23.1 Annex D.6; §9.1, §9.3 | **measured** (third-party corroboration) |
| The NPDU beneath it: `0x0008` and `0x0208`, protocol version 2, destination and source short addresses equal to the MAC's, radius 30, sequence 17 held across a transaction whose MAC sequence advances 33 34 35 36 | R23.1 3.3.2 with Figure 3-4, 3.6.2.1, 3.6.2.2; §2 | **measured** |
| The APDU's header, read out of the ciphertext of a secured frame and identical to the same transaction sent unsecured: Data, unicast, APS security clear, acknowledgement requested, no extended header, destination endpoint 2, source endpoint 1, cluster `0x0006`, profile `0x0104`, APS counter 0 | R23.1 2.2.5.1.1 with Figure 2-7, Table 2-21; §3 | **measured** |
| The secured NPDU's auxiliary, as a condition of a MIC that verifies rather than as a layout guessed at: 14 octets, control `0x28` with the **level sub-field zero** and the key-identifier sub-field `01`, extended nonce set, RVFC clear; the frame counter, whose low octet is the one that advances across the four attempts; the source EUI-64 in transmitted order; key sequence 0; and a 4-octet MIC closing the NPDU. Corrupting the counter, one ciphertext octet or the MIC (with the footer recomputed each time, so the FCS gate cannot be what stopped it) makes the dissector refuse everything above the NWK header, as does naming a different key and as does asking it for a 64-bit tag (`zbee_nwk.seclevel:ENC-MIC64` moves the tag window to `5469f846ea276c07` and fails) | R23.1 4.5.1.3, 4.5.1.4, 4.3.1.1 step 8 with Table 4-38, 4.3.1.2 step 1; §2, §4 (`0x28` on the air, `0x2D` re-injected for the authentication string, M from this device's own level) | **measured** |
| Where it reaches past what this stack claims: given the profile and cluster, Wireshark hands the six ASDU octets to its ZCL dissector and reports frame control `0x66` (frame type `0x02`, manufacturer specific), manufacturer code `0x6172`, transaction sequence 109, command `0x65`, one octet of payload left. Those six octets are the application's, and chapter 2 prescribes nothing about their shape: an inert `66 72 61 6d 65 64` is a legal ASDU and no clause makes it a ZCL frame. **Wireshark reading a different thing, not our framing wrong against a named clause**: the octets are confirmed, their meaning above the APS header is not, and band A builds no ZCL to argue the point with (`af`, `zdo`, `zcl` deferred) | R23.1 2.2.5.1.9 with Figure 2-7 and Table 2-2 (the frame payload field "contains information specific to individual frame types"; the ASDU is what an APSDE-DATA.request puts in it) | **measured, open** (what the fixture claims ends at the APS header) |
| What it refuses without a key, and the name of the thing that made it refuse: `zbee_sec.encrypted_payload`, an expert item of the ZigBee NWK security subtree (PI_UNDECODED, Warning), with the hierarchy stopping at `wpan:zbee_nwk:data`; the reason is that no key reached its keyring, nothing in the capture transports one, and the only route left is the ZigBee dissector's **Pre-configured Keys** table (`zbee_…key_table`, UAT `zigbee_pc_keys`), which the run filled on the `tshark` command line. Wireshark 4.6.9 has no develop-mode preference (`zbee_sec.enable_develop_mode_keys`, `zbee_sec.network_key`: unknown; `wpan.802154_key`: obsolete), and the level the decryption runs at is `zbee_nwk.seclevel`, never the air's zeroed sub-field | the dissector's own registration (`epan/dissectors/packet-zbee-security.c`), read off `tshark -G` output and the refusals | **measured, upstream** |

The witness's reach, stated exactly: a party with no knowledge of this repository confirms the MAC header of every recorded frame, the footer rule, the NWK header and the secured NPDU's whole security envelope including the level-0-on-the-air correction, and the APS header out of ciphertext whose key it was given; it does not confirm what the six payload octets mean, and it cannot be made to confirm the RSSI, the channel or the PHY convergence layer, none of which travel in a recorded PSDU.

## 6. The size bounds of the implementation

The bounds of what crosses the seam, each with the table or clause that prints it.

| Bound | Value | Source |
| --- | --- | --- |
| MPDU / PSDU | 127 octets | Figure 13-4 (PHR Frame Length is bits 0-6) plus 13.1.3.2 ("the total number of octets contained in the PSDU"); R23.1 D.12.1.1.2 restates `aMaxPHYPacketSize` as 127 for Zigbee |
| NSDU handed to our MAC | ≤ 108 = 127 − (`nwkcMACFrameOverhead` 11 + `nwkcMinHeaderOverhead` 8) | R23.1 Table 3-2, Table 3-65 |
| MAC overhead to budget for | 11 octets assumed, 9 minimum | R23.1 Table 3-65; 802.15.4-2006 Table 85 (`aMinMPDUOverhead`) |
| unsecured payload our MAC must carry | ≥ 119 = 127 − `nwkcMinHeaderOverhead` | R23.1 D.5, which quotes IEEE's own 118 (`aMaxMACPayloadSize`) and 102 (`aMaxMACSafePayloadSize`): **both constants were dropped from 802.15.4-2024** (8.4.2 Table 8-35 keeps only `aMaxLostBeacons` and `aMaxSifsFrameSize` = 18), so 802.15.4-2006 Table 85 is their only source |
| Spinel/HDLC frame | 256 octets including its FCS | §2 |
| MAC interfaces behind the MCPS/MLME pair | 1 now, ≤ 32 | R23.1 Table 3-69 (`nwkMacInterfaceTable` index 0-31) |
| Ack composition window | 12 symbol periods = 0.192 ms at the 2.4 GHz band's 62.5 ksymbol/s | 11.2.3, Table 12-1 (`aTurnaroundTime`), Table 11-1 (symbol rate) |

## 7. The application framework: the clauses each source file implements

One row per source file, as 9.4's and 9.5's tables are: the pages are where each clause's own heading is printed.

| Source file | Where its clauses are printed |
| --- | --- |
| `af/af.c` the endpoint table and the ASDU path | R23.1 pages 110-111 (2.3.1.3, 2.3.2.5), 111 (2.3.2.5.1), 61 (2.2.4.1.1), 63 (Table 2-2) |
| `zdo/zdo.c` the device object's server half | R23.1 pages 122 (2.4), 124-125 (2.4.2.8, 2.4.2.8.1, 2.4.2.8.4), 126 (2.4.4.1), 133-134 (2.4.3.1.7, 2.4.3.1.11), 171 (2.4.4.2), 181-182 (2.4.4.2.7), 223 (2.5.4.5.4.3), 138-139 (2.4.3.2.2, 2.4.3.2.3), 143-145 (2.4.3.3.2, 2.4.3.3.3, 2.4.3.3.4), 145-146 (2.4.3.3.5), 147-148 (2.4.3.3.7, 2.4.3.3.7.2), 196-197 (2.4.4.3.5, 2.4.4.3.7), 171-180 (2.4.4.2.1, 2.4.4.2.2, 2.4.4.2.3, 2.4.4.2.4, 2.4.4.2.5, 2.4.4.2.6), 189-196 (2.4.4.3.2, 2.4.4.3.3, 2.4.4.3.4), 113 (2.3.1.3, 2.3.2.3, 2.3.2.4, 2.3.2.5), 114 (2.3.2.3.4), 116 (2.3.2.3.10), 87 (2.2.5.1.1), 212-213 (Table 2-129) |
| `zdo/zdo_client.c` the device object's client half, built with `ZB_ZDO_CLIENT` | R23.1 pages 127-132 (2.4.3.1.1, 2.4.3.1.2, 2.4.3.1.3, 2.4.3.1.3.1, 2.4.3.1.4, 2.4.3.1.5, 2.4.3.1.6, 2.4.3.1.7), 172-173 (2.4.4.2.1, 2.4.4.2.2), 181 (2.4.4.2.7), 633-634 (I.4.8) |
| `zcl/zcl.c` the Cluster Library's foundation and the Basic cluster | ZCL R8 pages 2-8 to 2-9 (2.4.1, 2.4.1.1, 2.4.1.2, 2.4.1.3, 2.4.1.4), 2-11 to 2-13 (2.5.1, 2.5.2, 2.5.2.1), 2-28 (2.5.12), 2-55 (Table 2-15), 2-46 (Table 2-18), 3-6 to 3-7 (3.2.1.3, 3.2.2.2, Table 3-7) |
| `zb_core.c` the surface an application stands on | R23.1 pages 231 (Table 2-135), 246 (3.2.2.3), 342 (3.6.1.6.1), 110-111 (2.3.2.5), 61 (2.2.4.1.1), 87 (2.2.5.1.1, 2.2.5.1.1.2), 100-101 (2.2.8.4.2), 134 (2.4.3.1.11, 2.4.3.1.11.1), 223-225 (2.5.4.5.5), 251-252 (3.2.2.7), 363-368 (3.6.1.11), 483 (4.6.3.2.1), 439 (4.4.3.2.3), 440 (4.4.4.1.2), 495 (4.6.3.6.1, 4.6.3.6.2), 516 (4.7.3.2), 519 (4.7.3.8), 562 (D.9) |
| `aps/aps_bind.c` the binding table | R23.1 pages 64 (2.2.4.1.1.3), 73 (Table 2-6), 98-99 (2.2.8.2), 93 (Table 2-24) |
