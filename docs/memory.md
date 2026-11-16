# Memory

Where the stack's RAM goes on a host at the defaults, a network of 200 devices, and how long each part of it is used.
Every byte sits in an object the caller owns, and nothing is allocated (`docs/internals/coding-rules.md` §7); `docs/configuration.md` §3 names the limit that sets each table's length.
Every number is what `tools/mem_size.py` prints in its host column, a 64-bit build with the host's `cc`; `-D NAME=VALUE` prints any other sizes.
A 32-bit host differs only where an entry holds a pointer.

## 1. Where the bytes are

![One memory map read downwards, every block as tall as its bytes: Zb_Core's layers, MAC, NWK, APS, security, AF, ZDO and the core's own, each split into its largest tables, then what Zb_Stack adds around it, the RCP's driver, the lifecycle and the configuration. The tables that grow with the network are amber: the source routes, the neighbours, the routes, the broadcast table and the address map in NWK, the link keys and the frame counters in security, the sleepy children's frames in the MAC, the joiners in the core.](images/memmap.png)

*Every table is a fixed array inside one object; amber is what the number of devices sizes.*

`Zb_Stack` is 97 608 bytes, and `Zb_Core`, the stack without its radio driver, 84 064 of them.
The tables §1.1 lists grow with the network and take 58 304 bytes, 60% of `Zb_Stack`; everything else is the same for 20 devices or 200.
A table is listed when it holds 96 bytes or more, or a received frame passes through it.

### 1.1. What 200 devices size

| Limit | Member | Holds | Entries x bytes | Bytes |
| --- | --- | --- | --- | --- |
| `SECURITY_KEYPAIR` | `keyPairs` | a link key per device that asked for one | 200 x 56 | 11 200 |
| `NWK_SOURCE_ROUTE` | `sourceRoutes` | a source route per device the coordinator answers | 200 x 40 | 8 000 |
| `NWK_NEIGHBOR` | `neighbors` | the devices in direct range | 64 x 104 | 6 656 |
| `CORE_JOINER` | `joiners` | a parent per joiner | 200 x 32 | 6 400 |
| `MAC_TRANSACTION` | `transactions` | frames waiting for a sleepy child | 32 x 192 | 6 144 |
| `NWK_ROUTE` | `routes` | a next hop per destination | 128 x 44 | 5 632 |
| `NWK_BTT` | `btt` | the broadcasts seen, for duplicates and their repetitions | 32 x 160 | 5 120 |
| `NWK_ADDR_MAP` | `addressMap` | an address pair per device | 200 x 24 | 4 800 |
| `SECURITY_INCOMING` | `incoming` | a frame-counter window per neighbour and key | 128 x 24 | 3 072 |
| `APS_DUP` | `dups` | the APS frames seen, for duplicates | 64 x 12 | 768 |
| `MAC_TRANSACTION` | `pairs` | the sleepy children's address pairs | 32 x 16 | 512 |

The four tables at 200 cost 152 bytes a device: a link key 56, a source route 40, a joiner 32 and an address-map row 24.
The others follow the network's shape rather than its count: the neighbours in range, the routes in use, the sleepy children, the broadcasts in flight (`docs/configuration.md` §3, "Many devices").

### 1.2. MAC: 12 976 bytes

| Member | Entries x bytes | Bytes |
| --- | --- | --- |
| `indirect.transactions` | 32 x 192 | 6 144 |
| `rx.indications` | 8 x 248 | 1 984 |
| `rx.batch` | 8 x 160 | 1 280 |
| `indirect.pairs` | 32 x 16 | 512 |
| `rx.stepPolls` | 8 x 32 | 256 |
| `indirect.confirms` | 4 x 32 | 128 |
| `indirect.commStatus` | 4 x 32 | 128 |
| the rest | | 2 544 |

### 1.3. NWK: 38 192 bytes

| Member | Entries x bytes | Bytes |
| --- | --- | --- |
| `sourceRoutes` | 200 x 40 | 8 000 |
| `neighbors` | 64 x 104 | 6 656 |
| `routes` | 128 x 44 | 5 632 |
| `btt` | 32 x 160 | 5 120 |
| `addressMap` | 200 x 24 | 4 800 |
| `tx` | 8 x 184 | 1 472 |
| `rreqTx` | 8 x 152 | 1 216 |
| `rreqRelay` | 8 x 152 | 1 216 |
| `joinParents` | 6 x 80 | 480 |
| `joinIndications` | 8 x 48 | 384 |
| `joinPending` | 8 x 48 | 384 |
| `macConfirms` | 8 x 32 | 256 |
| `macPolls` | 8 x 32 | 256 |
| `macIndication` | 1 x 248 | 248 |
| `discoveries` | 8 x 20 | 160 |
| `confirms` | 8 x 20 | 160 |
| `macCommStatus` | 4 x 32 | 128 |
| `leaveIndications` | 4 x 24 | 96 |
| `indication` | 1 x 48 | 48 |
| the rest | | 1 480 |

### 1.4. APS: 7 240 bytes

| Member | Entries x bytes | Bytes |
| --- | --- | --- |
| `tx` | 8 x 368 | 2 944 |
| `indications` | 8 x 168 | 1 344 |
| `dups` | 64 x 12 | 768 |
| `frag` | 4 x 192 | 768 |
| `confirms` | 8 x 40 | 320 |
| `keyIndications` | 4 x 48 | 192 |
| `groups` | 16 x 8 | 128 |
| `updateDevices` | 4 x 32 | 128 |
| the rest | | 648 |

With fragmentation off (`ZB_APS_FRAGMENTATION=0`) `frag` goes and each `tx` entry is 224 bytes, 5 320 for the layer.

### 1.5. Security: 14 656 bytes

| Member | Entries x bytes | Bytes |
| --- | --- | --- |
| `keyPairs` | 200 x 56 | 11 200 |
| `incoming` | 128 x 24 | 3 072 |
| the rest | | 384 |

### 1.6. AF: 1 696 bytes

| Member | Entries x bytes | Bytes |
| --- | --- | --- |
| `indications` | 8 x 112 | 896 |
| `endpoints` | 8 x 96 | 768 |
| the rest | | 32 |

### 1.7. ZDO: 552 bytes

| Member | Entries x bytes | Bytes |
| --- | --- | --- |
| `responses` | 4 x 96 | 384 |
| the rest | | 168 |

### 1.8. The core's own: 8 752 bytes

| Member | Entries x bytes | Bytes |
| --- | --- | --- |
| `joiners` | 200 x 32 | 6 400 |
| `indications` | 8 x 168 | 1 344 |
| `bindings` | 8 x 48 | 384 |
| `keysOwed` | 4 x 40 | 160 |
| the rest | | 464 |

### 1.9. What Zb_Stack adds: 13 544 bytes

| Part | Entries x bytes | Bytes |
| --- | --- | --- |
| `rcp`, the port's `path` | | 4 096 |
| `rcp`, its `rxQueue` | 16 x 160 | 2 560 |
| `rcp`, the rest | | 4 960 |
| `lifecycle` | 4 x 272 | 1 088 |
| `config` | | 736 |
| the rest | | 104 |

`rcp` is the RCP driver `Zb_Stack` embeds, 11 616 bytes, used when the configuration names no radio of its own.

## 2. How long each part is used

![Four lanes over three steps of the application's loop, each lane as tall as the bytes it holds. The device's life: used all along, the tallest by far. Across steps: sends, relays, the broadcast table and the frames for sleepy children, which come and go over several steps. Within a step: the receive rings and the rings between layers, used only while a step runs, in amber. Within a call: buffers held for one call, used for an instant. Under them the call frames, hatched, on the caller's stack and not to scale. Each lane's whole width is reserved, used or not.](images/memlife.png)

*Every lane is reserved for the device's whole life; only the first is used for all of it.*
The lanes divide `Zb_Core`; their heights are the table's, and when each lane is in use is an illustration, not a trace.

| Lifetime | What | Bytes |
| --- | --- | --- |
| the device's life | `neighbors`, `routes`, `addressMap`, `sourceRoutes`, `joiners`, the sleepy children's `pairs`, `groups`, `bindings`, `endpoints`, the keys and frame counters, the beacon payload, the PIB | 48 476 |
| across steps | each layer's `tx`, `indirect`'s frames, `btt`, `rreqTx`, `rreqRelay`, `dups`, association and joining, ZDO's `responses`, the application's ring | 27 039 |
| within a step | the MAC's receive ring and batch, the confirm and indication rings between layers, NWK's held frame, `af`'s `indications` | 7 496 |
| within a call | `plainScratch`, `secureScratch`, `relayNpdu`, `ackApdu`, the security crossing's `adata` and `frame`, `mpdu` | 1 053 |
| within a call, on the caller's stack | the call frames | |

## 3. One frame received

A full frame: a 127-byte PSDU carrying an 82-byte ASDU, unicast and NWK-secured, from the RCP to the application's ring.

![One row per buffer the frame is copied into inside the library, in the order it climbs: the MAC's batch, the MAC's ring, NWK's copy of it, the security crossing's two buffers, NWK's plaintext the decrypt writes into and APS reads in place, APS's ring, Zb_CoreStep's local and the application's ring. Each outline is as wide as the buffer and its amber fill as wide as the frame's octets in it; stack buffers are hatched. Under them the 82-byte payload is set against all the buffers it passed through, end to end.](images/memrxframe.png)

*Inside the library the frame is copied nine times; the 82 bytes the application gets pass through about 1.5 KB.*

### 3.1. Before the MAC, in the port and the RCP driver

| Layer | Buffer | Bytes | Held until | In |
| --- | --- | --- | --- | --- |
| `port` | `posixPump`'s `chunk` | 256 | the call returns | stack |
| `port` | `rxRing` | 512 | the backend reads it | object |
| `rcp` | `chunk` | 64 | the next read | object |
| `rcp` | `decoder.payload` | 254 | the closing flag | object |
| `rcp` | `frame` | 254 | the next HDLC frame | object |
| `rcp` | `radioReadStreamRaw`'s `frame` | 160 | the call returns | stack |
| `rcp` | `rxQueue`, one entry | 160 | the MAC polls it, in the same turn | object |

The first five hold the frame HDLC-escaped or Spinel-wrapped, so about 30 bytes longer than the PSDU.

### 3.2. In the library, from the MAC to the application

| Layer | Buffer | Bytes | Frame octets | Held until | In |
| --- | --- | --- | --- | --- | --- |
| `mac` | `rx.batch`, one entry | 160 | 127 | the MAC's step ends | object |
| `mac` | `rx.indications`, one entry | 248 | 127 | NWK drains it, in the same step | object |
| `nwk` | `macIndication` | 248 | 127 | the next frame | object |
| `security` | `adata` | 127 | 22 | the call returns | object |
| `security` | `frame` | 127 | 90 | the call returns | object |
| `nwk` | `plainScratch` | 116 | 90 | APS is done with it, in the same step | object |
| `aps` | `indications`, one entry | 168 | 82 | the core drains it, in the same step | object |
| `zb_core` | `Zb_CoreStep`'s `indication` | 168 | 82 | the loop's next frame | stack |
| `zb_core` | `indications`, one entry | 168 | 82 | the application takes it | object |

The object's buffers come to 1 362 bytes and the stack's to 168, for 82 bytes delivered; each decrypt also holds a 192-byte key schedule on the stack.
The decrypt writes straight into `plainScratch` and zeroes it when the tag fails (D-284), and APS reads the NSDU there (D-285).
An APS-secured frame adds APS's `plainScratch`, 108 bytes, and a second pass through `adata` and `frame`.
A group frame takes one APS ring entry and one application ring entry per member endpoint.

## 4. One frame sent

The same frame going out: an 82-byte ASDU with an APS acknowledgement requested, NWK-secured, from `Zb_StackApsRequest` to the RCP.
The caller's ASDU is referenced, not copied, until the APS layer builds its frame.

![One row per buffer the frame is copied into inside the library, in the order it goes down: APS's send slot, NWK's send slot, the security crossing's two buffers, NWK's secured frame and the MAC's MPDU. Each outline is as wide as the buffer and its amber fill as wide as the frame's octets in it. The two send slots are held until the acknowledgement or the confirm, the rest only within the call. Under them the 82-byte payload is set against all the buffers it passed through.](images/memtxframe.png)

*Fewer copies than the receive path, but the first two are held across steps, until the frame is acknowledged.*

### 4.1. In the library, from the application to the MAC

| Layer | Buffer | Bytes | Frame octets | Held until | In |
| --- | --- | --- | --- | --- | --- |
| `aps` | `tx`, one entry | 368 | 90 | the APS acknowledgement, or the last retry | object |
| `nwk` | `tx`, one entry | 184 | 98 | the MAC's confirm | object |
| `security` | `adata` | 127 | 22 | the call returns | object |
| `security` | `frame` | 127 | 116 | the call returns | object |
| `nwk` | `secureScratch` | 116 | 116 | the next protect | object |
| `mac` | `mpdu` | 127 | 127 | the call returns | object |

The object's buffers come to 1 049 bytes for 82 bytes sent, 552 of them held until the acknowledgement; an APS `tx` entry carries a 128-byte fragment buffer whether the frame is fragmented or not.
An APS-secured frame adds APS's `secureScratch`, 108 bytes; a frame for a sleeping child adds a 127-byte MAC transaction, held until the child polls.
A broadcast this device originates adds a 116-byte copy in its broadcast-table record, held for the broadcast's delivery time.

### 4.2. After the MAC, in the RCP driver and the port

| Layer | Buffer | Bytes | Held until | In |
| --- | --- | --- | --- | --- |
| `rcp` | `txFrame`, one slot | 127 | the radio's confirm | object |
| `rcp` | `request` | 254 | the call returns | object |
| `rcp` | `wire` | 1 024 | the call returns | object |
| `port` | `txRing` | 1 024 | the device takes it | object |
