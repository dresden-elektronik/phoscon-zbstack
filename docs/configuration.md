# Configuring the build

What a build of the Phoscon Zigbee Stack can be told: the build type, the AES implementation, whether APS fragmentation is built, and the size of every table the library keeps.
**After reading** you can size the stack for a gateway with many devices or for a small target, and you know which values the suites prove.

## 1. Setting an option

Every option is a CMake cache variable, set with `-D` when the build directory is configured:

```sh
cmake -S . -B build/gateway -DCMAKE_BUILD_TYPE=Release -DZB_LIMIT_APS_TX=16 -DZB_LIMIT_NWK_TX=16
cmake --build build/gateway
```

A build directory remembers its options.
To change one later, configure the same directory again with only that option, `cmake -B build/gateway -DZB_LIMIT_APS_TX=32`, and build; everything that depends on it is rebuilt.
An empty value puts a size back to its default: `-DZB_LIMIT_APS_TX=`.

`cmake -LH build/gateway` lists every option with its help line, and `ccmake` or `cmake-gui` edit them interactively.
When an option differs from its default, configuring prints a line naming each one that does.

An application that builds the stack as part of its own CMake project sets the options as cache entries before it adds the stack's directory, and gets the libraries alone: **`ZB_BUILD_TREE`**, `ON` only when the stack is the top-level project, also builds the tools, the examples and the suites.

```cmake
set(ZB_LIMIT_APS_TX 16 CACHE STRING "")
add_subdirectory(phoscon_zbstack)
target_link_libraries(my_app PRIVATE zb_stack)
```

## 2. Build options

**`CMAKE_BUILD_TYPE`**, no default.
`Debug` adds AddressSanitizer and UndefinedBehaviorSanitizer with Clang or GCC, which is how the suites are meant to run.
**`ZB_SANITIZE`**, `ON` only when the stack is the top-level project, is what adds them, so an application that adds the stack's directory chooses its own sanitizers.
`Release` is for an application.

**`ZB_AES_IMPLEMENTATION`**, default `scalar`.
`scalar` computes each AES round as FIPS-197 states it; `table` looks every multiply up in tables, which is faster and costs more read-only data.

**`ZB_APS_FRAGMENTATION`**, default `ON`.
Fragmentation carries an ASDU too large for one frame as several blocks, up to 128 octets in all.
`OFF` leaves it out and saves 144 bytes per `ZB_LIMIT_APS_TX` entry and the reassembly pool, 1.9 KB at the defaults, for a small target whose application never sends or receives a payload that large.
Such a build answers a fragmented frame with an indication whose status is `DEFRAG_UNSUPPORTED` and which carries no payload, and does not acknowledge it, as the Zigbee specification asks of a device without fragmentation.
A send that does not fit one frame is refused with `ZB_ERR_NO_SPACE` whether or not it asks for fragmentation, and the node descriptor states no fragmentation support and 82 octets as the largest transfer.

**`ZB_ZDO_CLIENT`**, default `OFF`.
`ON` builds the device object's client half: `zdo_client.h` writes the device and service discovery requests and reads the responses the stack has no reader for, and `Zb_StackZdoRequest` sends a request numbered with the device object's own counter.
An application that writes its own ZDP requests leaves it out and sends them with `Zb_StackApsRequest` from endpoint 0, numbering them itself.
It adds code and no state, so the table sizes and the size pins are the same either way.

**`ZB_U_STREAMS_LIBRARY`** and **`ZB_U_STREAMS_INCLUDE_DIR`**, empty by default.
An application that links its own `u_bstream` and `u_sstream` names that library and the directory of its `u_bstream.h` and `u_sstream.h`, and the tree compiles nothing of `vendor/` (D-290).
Both headers must be the revisions `vendor/MANIFEST` pins, byte for byte, or the configure stops; the sources are the application's to keep at the same tags.
Only copies of those two headers reach the tree's include path, and the library is linked without its own include directories, so another header there, such as deconz-lib's `aps.h`, is never read in place of the tree's.

**`ZB_LIMIT_*`**, empty by default: the table sizes of §3.
Empty keeps the default written in `src/zb/zb_limits.h`.

## 3. Table sizes

The library allocates nothing: every table it keeps is a fixed array inside the stack object.
A full table refuses what would need one more entry and counts the refusal, unless its row says otherwise.

| Option | Default | Holds |
| --- | --- | --- |
| `ZB_LIMIT_APS_TX` | 8 | APS requests in flight |
| `ZB_LIMIT_NWK_TX` | 8 | NWK frames not yet confirmed |
| `ZB_LIMIT_MAC_TX_TRACK` | 8 | MAC transmits and their confirms |
| `ZB_LIMIT_MAC_TRANSACTION` | 32 | frames waiting for a sleepy child |
| `ZB_LIMIT_MAC_INDICATION` | 8 | received frames the MAC holds for NWK; a turn takes no more than it has room for |
| `ZB_LIMIT_NWK_INDICATION` | 8 | received frames waiting in APS; NWK holds one, for APS to read |
| `ZB_LIMIT_CORE_INDICATION` | as `NWK_INDICATION` | frames waiting for the application |
| `ZB_LIMIT_NWK_NEIGHBOR` | 64 | parent, children, routers in range |
| `ZB_LIMIT_NWK_ROUTE` | 128 | routes; full, the oldest is replaced |
| `ZB_LIMIT_NWK_DISCOVERY` | 8 | route discoveries under way |
| `ZB_LIMIT_NWK_SOURCE_ROUTE` | 200 | source routes |
| `ZB_LIMIT_NWK_BTT` | 32 | broadcasts remembered against repeats |
| `ZB_LIMIT_AF_ENDPOINT` | 8 | the application's endpoints |
| `ZB_LIMIT_AF_CLUSTER` | 16 | clusters per list of one endpoint |
| `ZB_LIMIT_APS_BIND` | 8 | bindings |
| `ZB_LIMIT_APS_GROUP` | 16 | group memberships |
| `ZB_LIMIT_APS_DUP` | 64 | frames remembered against duplicates, enough for every retry of thirteen frames a second |
| `ZB_LIMIT_SECURITY_KEYPAIR` | 200 | link keys, one per device given one |
| `ZB_LIMIT_CORE_JOINER` | 200 | joiners whose parent is remembered |
| `ZB_LIMIT_NWK_ADDR_MAP` | 200 | devices whose two addresses are known; a trust centre needs one per device it may remove |
| `ZB_LIMIT_SECURITY_INCOMING` | 128 | NWK frame counters, one per neighbour sending and network key |

**Range.**
Every size is at least 1, and a value outside its range stops the build with a message naming it.
The one other lower bound is the receive path's, and the upper bounds are the protocol's:

- `MAC_INDICATION` at least 8, one radio poll's frames: the suites prove it from there.
- `APS_TX` and `NWK_DISCOVERY` at most 256: each request in flight is matched on an 8-bit counter.
- `NWK_TX` at most 250: a frame's handle is one octet, shared with frames held for relaying.
- `NWK_NEIGHBOR`, `NWK_ROUTE`, `APS_BIND` and `APS_DUP` at most 255: a management report counts its entries in one octet, and duplicates are told apart by an 8-bit counter.
- `AF_ENDPOINT` at most 77: an Active_EP_rsp lists every endpoint in one frame.
- `AF_CLUSTER` at most 255: a cluster count is one octet.

The other sizes are bounded only by memory.

**Memory.**
At the defaults a `Zb_Stack` is 97 608 bytes on a 64-bit host, and 95 688 with fragmentation off (`tools/mem_size.py`).
4 KB of that is the device path its port keeps, as long as Linux's `PATH_MAX`, so a `/dev/serial/by-id/` name opens.
Measured on a 64-bit host, each entry adds, in bytes: `APS_TX` 408 (264 with fragmentation off), `NWK_DISCOVERY` 324, `NWK_INDICATION` 168, `AF_ENDPOINT` 282, `MAC_INDICATION` 248, `MAC_TRANSACTION` 208, `NWK_TX` 192, `CORE_INDICATION` 168, `NWK_BTT` 160, `NWK_NEIGHBOR` 104, `MAC_TX_TRACK` 84, `AF_CLUSTER` 64 at 8 endpoints, `SECURITY_KEYPAIR` 56, `APS_BIND` 48, `NWK_ROUTE` 44, `NWK_SOURCE_ROUTE` 40, `CORE_JOINER` 32, `NWK_ADDR_MAP` 24, `SECURITY_INCOMING` 24, `APS_DUP` 12, `APS_GROUP` 8.
A 32-bit target needs less, and a saved state adds 24 bytes per neighbour, 64 per link key and 16 per frame counter.

## 4. What a size depends on

**Sending in parallel.**
Each APS request in flight needs a NWK frame of its own when it is sent, and a request that finds the NWK table full is refused; raise `NWK_TX` with `APS_TX`.
An acknowledged request's APS acknowledgement uses a NWK frame too.
The RCP tracks at most 4 transmits at a time; a fifth is refused for room and the NWK tries it again as it would a failed attempt, so `MAC_TX_TRACK` above 4 only holds confirms waiting to be read.
A send to a binding issues one APS request per matching entry, so more matches than free `APS_TX` entries deliver to some destinations and not all.

**Receiving.**
The RCP hands over up to 8 frames at a time, so `NWK_INDICATION` below 8 drops some of a full batch.
A frame for a group becomes one indication per member endpoint.
One turn hands the application at most as many frames as the APS holds, which is why `CORE_INDICATION` follows `NWK_INDICATION`; set smaller, the rest of a full turn is dropped and counted.

**Many devices.**
A trust centre keeps a link key per device that asked for its own (`SECURITY_KEYPAIR`), a parent per joiner (`CORE_JOINER`) and an address-map row per device it may remove (`NWK_ADDR_MAP`), so each of the three follows the number of devices; a coordinator that answers many devices through many-to-one routing wants a source route per device too (`NWK_SOURCE_ROUTE`).
The neighbour table holds only the devices in direct range, and `SECURITY_INCOMING` needs one window per neighbour that sends, twice over during a network key change.
The defaults hold a network of 200 devices, about a third of them end devices: these four at 200, the neighbour table at 64, routes and frame counters at 128.
A device with 32 KB of RAM holds far fewer; `docs/memory.md` §1.1 gives what each of these tables takes at the defaults.

**Children.**
A frame for a sleepy child waits in `MAC_TRANSACTION` until the child polls, and a broadcast holds one copy per sleepy child, so a coordinator with many sleepy children raises both `NWK_NEIGHBOR` and `MAC_TRANSACTION`.
The MAC learns each child's address pair when it associates, in a table as large as `MAC_TRANSACTION`, and does not forget one yet: past that many associations since the stack started, a new child's pending frames are announced less precisely.

**Endpoints.**
One Simple_Desc_rsp describes at most 34 clusters across an endpoint's two lists, so `AF_CLUSTER` above 17 helps only an endpoint with a short second list.

## 5. Saved state

`Zb_StateCapture` writes the children and the link keys into a `Zb_State`, whose arrays are `NWK_NEIGHBOR` and `SECURITY_KEYPAIR` long.
A saved state is read back only by a build with the same two sizes; the state's version does not change with them.

## 6. A build without CMake

Every file that includes a stack header must be compiled with the same `-DZB_LIMIT_*` definitions, because the sizes shape structs that the library, the stack and the application share.
A file compiled with other values sees another layout, and nothing reports it.
CMake attaches the definitions to the library target, so everything that links it is compiled with them.

## 7. What the suites prove

The suites, and the size pins among them, run at the defaults, and pass with `ZB_APS_FRAGMENTATION` `OFF` and with `ZB_ZDO_CLIENT` `ON` as well, which adds the `zdo_client` suite and a stack case.
They also pass at a small profile: `NWK_ADDR_MAP`, `NWK_NEIGHBOR`, `NWK_ROUTE` and `NWK_BTT` at 16, `SECURITY_KEYPAIR`, `CORE_JOINER`, `NWK_SOURCE_ROUTE` and `MAC_TRANSACTION` at 8, `SECURITY_INCOMING` 32, `APS_DUP` 24.
In a build with sizes of its own the size pins are left out and the suite prints the sizes instead; a case that fills a table fills it at the size the build gives it.
A size is checked against its range when the stack is compiled, so `ctest` in a build with any other sizes is the check that they work.
