# `docs/internals/decisions.md`: the decision register

The reasoning behind the choices this stack makes where the specification leaves one open, reads an ambiguous clause, or departs from one; `docs/internals/architecture.md` holds the shape and points here.
The specifications are the source of truth, so an entry records a choice and its reason, never what a clause already says.
An id is the address code cites: permanent, never renumbered and never reused, so the gaps in the numbering are entries that were retired.
**After reading** you can resolve any `D-`id a comment cites to the reasoning behind it, and see what is still open.

Tags: **spec** (a clause), **measured** (a Phoscon RCP measurement), **upstream** (a donor), **open** (an option not yet chosen), **mandate** (a rule of this repository), **decision** (the entry itself), **api** and **seam**.

House rules are in `docs/internals/coding-rules.md`: no dates, no `file:line`, no narrative of how a conclusion was reached, ids cited from code comments rather than restated there.

## Index

Every id, its title and where it stands.
`Decided` is the archive; `Open` and `Parked` are the agenda.

### Agenda: what is not settled (5)

| id | title | status |
| --- | --- | --- |
| D-18 | MCU target and its budget | Parked |
| D-20 | Software MAC timing | Parked |
| D-22 | One port contract or two | Parked |
| D-26 | Enforcing one session per port | Open |
| D-111 | 3.6.1.10.5's 0x0e verification is not built | Open |

### Settled: the archive the code cites (217)

| id | title | status |
| --- | --- | --- |
| D-301 | `Zb_Stack` offers a sleepy end device, which polls at 250 ms while it attaches and 7.5 s after | Decided |
| D-300 | A device whose receiver rests hears only its poll's window, even on a radio that never sleeps | Decided |
| D-299 | A joiner updates its trust centre link key unless told to keep the one it joined with | Decided |
| D-298 | An energy scan reports the radio's dBm, the peak of its dwells, and no level where nothing was measured | Decided |
| D-297 | An address answer's associated devices are the end devices the neighbour table holds as children | Decided |
| D-296 | The address map tells the application what it learns, changes and refuses | Decided |
| D-295 | The higher layer may seed a source route, and is told what records and 0x0b do to the table | Decided |
| D-294 | The saved state keeps the channel and nwkUpdateId, and a restore still takes the first schema | Decided |
| D-293 | A group frame no member took may go to each endpoint of its profile | Decided |
| D-292 | A request to the device's own address is delivered to it, not sent | Decided |
| D-290 | An application that links its own u_bstream and u_sstream at the pinned revisions replaces vendor/ | Decided |
| D-289 | The device object answers Match_Desc_req, and a request it does not support is answered or handed over | Decided |
| D-286 | The default sizes hold a network of 200 devices | Decided |
| D-285 | NWK holds one received frame for APS, read in place, and receives nothing more until APS is done | Decided |
| D-284 | CCM* decrypts into the caller's output and zeroes it when the tag fails | Decided |
| D-283 | The MAC's indication ring is a limit of one radio poll, and a poll asks for no more than it has room for | Decided |
| D-282 | A stick may be named by its USB serial number, which the platform resolves at every open | Decided |
| D-281 | An RCP whose port goes away is opened again at its path, and a loop with no port sleeps | Decided |
| D-280 | The ZDP client is an option, and it numbers with the device object's counter | Decided |
| D-279 | The device object's own sends carry a tag of their own, and their outcomes stay the library's | Decided |
| D-278 | An application's files are the platform's, on an opaque handle | Decided |
| D-277 | The clock is the platform's: `Port_NowMs()` returns it, and a deadline is a subtraction | Decided |
| D-276 | An example may use the substrate and the port's contract | Decided |
| D-273 | The examples take no transmit gate | Decided |
| D-272 | An active scan takes no more frames than its beacon ring has room for | Decided |
| D-271 | RejoinNetwork 0x01 is the MAC's orphan scan, and a parent realigns its own child | Decided |
| D-270 | A rejoin asks a parent whose beacon carries the R23 appendix by commissioning | Decided |
| D-269 | A rejoin is answered whatever the permit, and a trust centre rejoin needs the device's own key | Decided |
| D-268 | A device told to leave and rejoin discovers its network and rejoins | Decided |
| D-266 | An end device sends every unicast to its parent | Decided |
| D-265 | A relay discovers only for its end device child, and holds that frame for the route | Decided |
| D-264 | An RCP that does not answer within a second is lost | Decided |
| D-263 | A frame waits in line for the RCP's one request | Decided |
| D-262 | A relayed frame that failed for any reason is reported to its source | Decided |
| D-261 | A unicast a router carries for the network gets the retries any unicast gets | Decided |
| D-260 | A test mesh cuts a link at the radio seam, not in the library | Decided |
| D-259 | A router scans as often as Table 2-135 says before it chooses a network | Decided |
| D-258 | A backbone sibling keeps its place until a rank passes it by a quarter and one frame | Decided |
| D-257 | The final LQA is 3.6.3's median, over the MAC's LQI as the raw sample | Decided |
| D-256 | The neighbour's link state moves only as the standard prints | Decided |
| D-254 | APS fragmentation is a build option, and a build without it says so on the air | Decided |
| D-253 | Every pool size is a default a build may override, within the protocol's bounds | Decided |
| D-252 | An APS data request carries the caller's tag, given back in its confirm | Decided |
| D-251 | `Zb_Stack` reports events, and an application is a state machine over them | Decided |
| D-249 | A relay that forwards a Route Reply takes its route to ACTIVE | Decided |
| D-243 | A broadcast the door refused for room is held and sent on the next turn | Decided |
| D-242 | The configured extended address is the device's identity, whatever the RCP reports | Decided |
| D-241 | The core's join door runs discovery, the join and the key wait, on channels the caller names | Decided |
| D-240 | An unauthorized device takes a relayed frame whose auxiliary source is not the NWK sender | Decided |
| D-239 | Network discovery empties the table, scans actively and owns the beacon ring while it runs | Decided |
| D-238 | The discovery table is ranked as 3.6.1.5.2 prints, and a parent may be known by its short address alone | Decided |
| D-237 | An active scan runs under the broadcast PAN and leaves a refused channel unscanned | Decided |
| D-236 | An Initial Join takes the attach mechanism the parent's beacon chooses | Decided |
| D-235 | A beacon reply the transmit door has no room for is asked again for 100 ms | Decided |
| D-234 | An Association Request whose PIB write has no room is held like its transmit | Decided |
| D-233 | A confirm that names no issue pairs by destination and NWK sequence number | Decided |
| D-232 | A direct frame carries macMaxFrameRetries, an indirect one none | Decided |
| D-231 | A transmit waits behind the PIB writes taken before it | Decided |
| D-230 | A frame of the join layer's own the transmit door has no room for is held, not lost | Decided |
| D-229 | A join command to a child whose receiver rests is held for its poll | Decided |
| D-228 | An Initial Join states key negotiation with no method and no secret | Decided |
| D-227 | A commissioning join takes the next-parent loop, and an address conflict is asked once more | Decided |
| D-226 | An unjoined device takes an unsecured commissioning response, as a rejoin response | Decided |
| D-225 | A commissioning child borrows the PIB for its exchange and gives it back on failure | Decided |
| D-224 | A failed rejoin moves to the next parent of the network it named | Decided |
| D-223 | A failed association moves to the next parent, never back to the same one | Decided |
| D-222 | An Association Request the transmit door has no room for is held, not abandoned | Decided |
| D-221 | A joined parent takes an unsecured commissioning request | Decided |
| D-220 | A device joins through a router: Update Device, Tunnel and Remove Device on both sides | Decided |
| D-219 | A device that associates anew is heard from whatever counter it sends | Decided |
| D-218 | A trust centre answers a trust centre link key request with a derived key | Decided |
| D-217 | A broadcast may address the ZDO endpoint | Decided |
| D-216 | The core owns the network, the radio's mode and the trust centre's key | Decided |
| D-215 | An AIB entry naming an endpoint with no descriptor is still delivered | Decided |
| D-214 | ZCL is a codec the application calls, not a layer the stack carries | Decided |
| D-213 | 2.2.8.4.2's group table is consulted only where the application asks | Decided |
| D-212 | One send door, and only what composes layers is wrapped | Decided |
| D-210 | The application's surface is the APS primitive, and the library owns endpoint 0 | Decided |
| D-208 | A permit refusal the layer cannot attribute to the MAC is INV_REQUESTTYPE | Decided |
| D-207 | A leaving device's former parent, and a MAC reset this stack cannot issue | Decided |
| D-206 | The leave answer goes out before the departure, with codes the table admits | Decided |
| D-204 | The entry a leave announcement names is read before it is rewritten | Decided |
| D-201 | Which leave request is validated, and which is a parent removing a child | Decided |
| D-200 | A permit that cannot be re-stated is refused as a state, not as a parameter | Decided |
| D-199 | What a ZDP response may answer | Decided |
| D-198 | A binding link belongs to a source device, and no cluster is a wildcard | Decided |
| D-197 | What a neighbour report states when the NIB holds nothing | Decided |
| D-196 | The binding entry's printed vocabulary | Decided |
| D-195 | The join's SecurityTimer is armed only where the network can authenticate | Decided |
| D-193 | The neighbour ranking's three windows are this stack's numbers | Decided |
| D-192 | A relayed source route is bounded by the octets' room, not by nwkMaxSourceRoute | Decided |
| D-191 | Fragmentation is built at window size 1, and a repeated block re-acknowledges | Decided |
| D-187 | A local conflict is announced once, after the jitter, to the receivers that rest on | Decided |
| D-186 | The address map is a table of rows, and a conflict is counted before it is resolved | Decided |
| D-185 | An acknowledgement measured between two RCPs names when each side transmits | Decided |
| D-184 | A neighbour's relay of this device's broadcast is read before the frame is dropped | Decided |
| D-183 | A document budget is derived or chosen, and the difference decides whether to cut | Decided |
| D-182 | An unverified frame counter has its own status, and a transport key verifies its pair | Decided |
| D-181 | A broadcast this device sent is repeated by its own record | Decided |
| D-180 | A command frame is acknowledged though its transaction owes no confirm | Decided |
| D-178 | A level with no key is the joining device | Decided |
| D-177 | The join's key wait is a second confirmation, not a delayed first | Decided |
| D-176 | 4.4.1.3 decides the addressee, and a distributed network skips it | Decided |
| D-175 | A transport-key transaction owes no confirmation | Decided |
| D-174 | A secured APS command is unprotected before it is identified | Decided |
| D-172 | A send to the low-power routers' class goes out as the MAC broadcast | Decided |
| D-171 | 4.6.3.4.2's "Otherwise" answers the operating state, and Table 4-41 decides the verified-counter bit | Decided |
| D-170 | A link key is held whether it is unique or global, and step 4's replay check follows the type | Decided |
| D-169 | How this stack reads R23.1's printed contradictions about transported keys | Decided |
| D-168 | The APS layer protects with three key identifiers and not with the fourth | Decided |
| D-167 | A transmit the seam refuses is a status the network layer re-asks | Decided |
| D-165 | A frame that started a route discovery is sent when the route appears | Decided |
| D-164 | The APS duplicate table records and never expires, because 2.2.8.4.2 prints no interval | Decided |
| D-163 | The APS layer's NWK-security ask follows the network, not the TxOptions | Decided |
| D-160 | The transmit PSDU carries its footer, and a firmware that counts it itself is a defect to fix there | Decided |
| D-159 | An MLME-instigated transaction's outcome is MLME-COMM-STATUS | Decided |
| D-158 | A child's two address forms are joined where the association is answered | Decided |
| D-157 | The Ack's Frame Pending bit is the radio's, stated from a table band A writes | Decided |
| D-156 | Table 3-51's rows bind the frame this layer generates, not the one it receives | Decided |
| D-155 | An Association Request keeps two PAN fields even when they would be equal | Decided |
| D-154 | The association permit's effect is the indication, and the answer's status is the profile's | Decided |
| D-152 | A transaction is confirmed on completion, and an attempt's failure is reported so the layer above can act | Decided |
| D-151 | A poll arriving while an extraction is on the air is answered with nothing | Decided |
| D-150 | A document states this stack's behaviour and locates the rule, and never restates it | Decided |
| D-149 | The reaction to a pending address runs as macAutoRequest TRUE | Decided |
| D-148 | The poll a beacon owes is addressed to that beacon's own source | Decided |
| D-147 | The indication carries the fields this stack has, and names the ones it does not | Decided |
| D-146 | A device that is not a coordinator answers a Data Request with 10.22.3's empty frame | Decided |
| D-145 | Promiscuous mode is a listener's mode, and 10.23.1's receiver request is deferred | Decided |
| D-143 | The first-level filter is the MAC's own, and a received beacon is its own event | Decided |
| D-142 | The association extraction starts where macResponseWaitTime ends, and a second window bounds the answer | Decided |
| D-139 | An entry is a decision and its consequences, in a fixed shape at a cap | Decided |
| D-135 | A deferral is stated where it is returned, and a gate reads it | Decided |
| D-134 | The counters are one snapshot, and it says when it was read | Decided |
| D-132 | A count a tool prints is not a claim a document makes | Decided |
| D-128 | Stochastic address assignment is a seeded draw over 1..0xfff7 | Decided |
| D-125 | A frame that names this device as its source is not an arrival | Decided |
| D-124 | An energy-scan dwell is a dialogue over time, so the seam issues it and collects it | Decided |
| D-123 | A dialect is what it answers, not what it is called | Decided |
| D-122 | A report is band A's input and never its output | Decided |
| D-121 | A seam call is one unit, so the backend's write queue must hold a whole one | Decided |
| D-119 | The send half is checked against on-air captures | Decided |
| D-118 | The route reply's path cost is added once per hop, at receipt | Decided |
| D-117 | `nwkStatus`'s 0xff is a house sentinel, and Table 3-84 prints no such value | Decided |
| D-116 | What a received Network Status removes, and where "my child" comes from | Decided |
| D-115 | Annex I.2.3's command-scoped local tags, and four readings | Decided |
| D-114 | The send side: an untrackable broadcast, the schedule pools, and whose duty a sleepy copy is | Decided |
| D-112 | A reserved field is zeroed on transmission and judged on receipt by nothing (1.4.2) | Decided |
| D-110 | Table 3-78's two unused statuses get their writers | Decided |
| D-109 | Passive acknowledgement is a mark on the record, and only a relayed broadcast has one | Decided |
| D-108 | α is one, and it is a value and not a field | Decided |
| D-106 | Ageing in Table 3-75's unit, and what a retired outgoing cost means for a route | Decided |
| D-105 | `LoopFree`'s operands, and the two places its answer decides | Decided |
| D-104 | One discovery per destination, and the timer confirms by Table 3-79's request id | Decided |
| D-103 | A received relay count is bounded by its own frame, and Table 3-51's broadcast row refuses `Discover Route 0x01` at the codec | Decided |
| D-102 | 3.6.2.3's lost-child mark is re-evaluated on the window the clause prints | Decided |
| D-101 | 3.6.13's "unsupported" is every Table 3-54 identifier this layer does not process, and the reply is Figure 3-61's three octets | Decided |
| D-99 | A relayed Route Request keeps its originator's fields and repeats at the request's own interval | Decided |
| D-98 | One MAC interface: `nwkMacInterfaceTable` is not modelled | Decided |
| D-97 | `SecurityEnable` at level 0 is refused, not ignored | Decided |
| D-94 | Who initiates a route discovery, when it gives up, and what the request is told | Decided |
| D-92 | Route discovery's reception, the worse direction, and the Route Reply's octets | Decided |
| D-91 | Route discovery's table, its sizes, and the Route Request's octets | Decided |
| D-90 | One security object, two crossings | Decided |
| D-89 | The acknowledgement's NWK frame takes the device's own crossing | Decided |
| D-87 | A door refusal is not a confirmation | Decided |
| D-86 | A non-unicast acknowledgement and a group-mode command are refused | Decided |
| D-85 | Table 2-2's `nwkBroadcastAddress` band is deliberately wider | Decided |
| D-84 | The re-protect-per-issue rule travels to APS | Decided |
| D-83 | The owed acknowledgement precedes the queued delivery | Decided |
| D-82 | An acknowledgement of a secured data frame stays unsecured at APS | Decided |
| D-81 | Acknowledgement matching compares only what the acknowledgement repeats | Decided |
| D-80 | A frame the security crossing refused is not deduplicated | Decided |
| D-79 | A duplicate hit answers before the pool is written | Decided |
| D-78 | Any convenient group-table order; only the fan-out is fixed | Decided |
| D-77 | The indication ring is sized to `NsduLength`'s ceiling | Decided |
| D-76 | A frame with a version or multicast bit is refused even in relay | Decided |
| D-75 | An address outside Table 3-75's range is none at all | Decided |
| D-74 | Xorshift32 must not be seeded at 0 | Decided |
| D-73 | 3.6.13 step 5 prints no SecurityEnable | Decided |
| D-72 | The last-confirm-status bound is not a printed code | Decided |
| D-71 | A device does not hand a frame to itself | Decided |
| D-70 | A broadcast this device originated is not one it processes | Decided |
| D-69 | Table 3-84 has no code for an over-ceiling secured frame | Decided |
| D-68 | 3.4.3.2's source-IEEE rule is deliberately not honoured | Decided |
| D-67 | 3.6.2.3 steps 4 and 5: which entry a broadcast marks | Decided |
| D-66 | 3.6.2.2's unsecured carve-out applies only to a frame for this device | Decided |
| D-65 | An operating Zigbee router is named, not modelled | Decided |
| D-64 | `TxTime` is absent | Decided |
| D-63 | The NLDE handle is the transmit the request became | Decided |
| D-56 | Randomness arrives as seeds | Decided |
| D-53 | The unstated points of the NWK security procedure | Decided |
| D-52 | Where keys and counters live | Decided |
| D-49 | The broadcast delivery time is a stand-in | Decided |
| D-47 | The RCP composes the poll's acknowledgement | Decided |
| D-43 | The block implementation is a link-time seam | Decided |
| D-42 | The crypto band | Decided |
| D-41 | A broken invariant calls the executable's handler | Decided |
| D-38 | What band A does when a completion never arrives | Decided |
| D-37 | Who owns the acknowledgement wait | Decided |
| D-35 | Each backend has its own pump | Decided |
| D-34 | What a radio with no acknowledgement metadata may report | Decided |
| D-33 | Band A computes the frame's footer | Decided |
| D-32 | Band B stops pulling before it loses a frame | Decided |
| D-31 | A host's transmit buffer is sized for the escaped frame | Decided |
| D-30 | What a device's `LAST_STATUS` becomes at the seam | Decided |
| D-29 | Channel support on a dialect that does not report it | Decided |
| D-23 | Persistence is a plain state object | Decided |
| D-19 | Repository licence | Decided |
| D-16 | The receive stamp is the device's clock | Decided |
| D-15 | Delivery across the seam is pulled and copied | Decided |
| D-13 | The MAC is inside the library and the seam is the radio service | Decided |
| D-11 | 802.15.4 revision coverage | Decided |
| D-10 | Roles | Decided |
| D-7 | One source tree split by band | Decided |
| D-5 | A typed field codec above the byte stream | Decided |
| D-1 | Build and test scaffolding | Decided |

## Entries

## D-301 · `Zb_Stack` offers a sleepy end device, which polls at 250 ms while it attaches and 7.5 s after

**Status:** Decided · **tags:** spec, decision

**Decided: `sleepy` makes an end device's macRxOnWhenIdle FALSE; it polls at 250 ms while it waits for the network key, its link key or a fragmented message, at `pollIntervalMs` otherwise, 7.5 s by default, and again at once when its parent says more is held.**
3.6.1.15 prints the attach rate; the application profile sets the normal one (2.5.4.5.5.1), so 7.5 s is this stack's choice, under macTransactionPersistenceTime.
A poll the parent never acknowledges is a parent link failure, which the rejoin counts (2.5.4.5.5.1).
NLME-SYNC's 3 retries are this stack's: no clause prints them.
The node descriptor's capability is the association's.

**Consequences.**
A restore comes back sleepy from the config, not the state.

## D-300 · A device whose receiver rests hears only its poll's window, even on a radio that never sleeps

**Status:** Decided · **tags:** spec, decision, seam, measured

**Decided: with macRxOnWhenIdle FALSE the MAC discards every frame heard outside a poll's window, a scan or an association unless `Mac_Config.hearsWhileAsleep` is set; the window opens when the Data Request leaves and closes on the parent's frame or `MAC_POLL_WAIT_MS` after the Ack.**
A ConBee or RaspBee keeps its receiver on (Phoscon RCP ignores `MAC_RX_ON_WHEN_IDLE`), so the discard imitates a sleeping radio; the flag is for debugging.
An Ack with Frame Pending zero ends the poll at once (10.22.3); a completion reporting no bit is read as one.
The wait is macMaxFrameTotalWaitTime plus room for two hosts behind serial links: 100 ms, open.

**Consequences.**
MLME-POLL.confirm carries SUCCESS, NO_DATA or the transmit's failure, and the frame's Frame Pending bit; a discard is counted.

## D-299 · A joiner updates its trust centre link key unless told to keep the one it joined with

**Status:** Decided · **tags:** spec, decision

**Decided: a joiner sends Request-Key once it holds the network key, holds the key sent unverified and sends Verify-Key, which a SUCCESS Confirm-Key verifies; `keepJoinedLinkKey` keeps the joined key, as an older device does.**
4.7.3.8 requires the update where no key negotiation ran, and prints no timing: one Request-Key waits 5 s, three are sent, then the global key is kept.
A restored device keeps its saved key.
4.4.8.2.3 step 3 ends on SUCCESS before step 7 verifies; here SUCCESS verifies and any other status forgets the entry.
An unverified key encrypts nothing (4.4.1.1).

**Consequences.**
A reset joiner meets its old key, which the application forgets (`Zb_CoreForgetLinkKey`): 4.7.3.1 step 2b adds the global entry only where none is found.

## D-298 · An energy scan reports the radio's dBm, the peak of its dwells, and no level where nothing was measured

**Status:** Decided · **tags:** spec, decision, seam, measured

**Decided: an ED scan's level is the seam's dBm, the peak of the dwells that cover ScanDuration, and a channel no dwell measured is unscanned, never given a level.**
8.2.8.3 and Table 3-10 print an octet whose mapping to power is the radio's own, unmeasured on any RCP here; the seam reports dBm (D-124).
10.18 keeps the maximum over ScanDuration, whose milliseconds are asked as the radio's dwell units, at most 1000 a dwell.
A unit is the radio's millisecond, measured at about 2.2 of the host's on a ConBee II, so a dwell lasts at least what was asked.
`RADIO_SCAN_NO_LEVEL` means nothing was measured, not a floor.

**Consequences.**
NLME-ED-SCAN.confirm carries dBm and a measured flag.

## D-297 · An address answer's associated devices are the end devices the neighbour table holds as children

**Status:** Decided · **tags:** spec, decision

**Decided: NWK_addr_rsp and IEEE_addr_rsp list, and answer for, the neighbour table's end devices whose relationship is child or unauthenticated child.**
2.4.3.1.1.2 and 2.4.3.1.2.2 select by Device Type 0x02 alone, but Tables 2-87 and 2-88 name the list "each associated device", and 2.4.2.1 "associated child devices".
A previous child (0x04) has left, and a lost child (0x07) is being heard through another parent (3.6.2.3), so neither is associated.
StartIndex is left out only when no device is associated, so a StartIndex past the list still carries it, with NumAssocDev 0.
An extended answer names the device itself, as both procedures print it.

**Consequences.**
A device that left is not answered for by its old parent.

## D-296 · The address map tells the application what it learns, changes and refuses

**Status:** Decided · **tags:** spec, decision

**Decided: every pair Table 3-68's map adds or changes, and every network address a second extended address claims, is a notice on an 8-deep ring, which `Zb_Stack` reports as `ZB_EVENT_ADDRESS`.**
2.5.4.5.4.3 has the ZDO keep the mappings known to applications updated, and leaves the mechanism to the stack.
A conflict leaves the map's first holder in place, so the notice names the claimant.

**Consequences.**
The map is not in the saved state, so after a restart every device is told again; a full ring counts what it lost.
2.4.3.1.11.2 reads a Device_annce's conflict otherwise, its other holder's row marked without a valid address: that reading is open.

## D-295 · The higher layer may seed a source route, and is told what records and 0x0b do to the table

**Status:** Decided · **tags:** spec, decision

**Decided: `Nwk_SetSourceRoute` writes a row of Table 3-66's nwkRouteRecordTable (0x9c), held with no lifetime until a record or a 0x0b replaces it; every change a record or a 0x0b makes is a notice on a 16-deep ring.**
A NIB attribute is the higher layer's to set, and a coordinator such as deCONZ seeds its saved routes back at start.
3.6.4.5.5's last sentence is built too: a record also replaces each row held for a relay on it, the neighbour's row going.
Relays are in 3.3.1.8.3's order, the record's own.

**Consequences.**
R23.1 prints no removal on leave or address conflict: the application lets a seed go with no relays.
Expiry and seeds are not notices.

## D-294 · The saved state keeps the channel and nwkUpdateId, and a restore still takes the first schema

**Status:** Decided · **tags:** spec, decision

**Decided: `Zb_State` version 2 adds `channel`, captured from the MAC, and fills `nwkUpdateId` from the beacon the device sends; a restore puts the update id back into that beacon and comes back on the state's channel unless the config names one, which must then agree.**
3.6.9's SHOULD list names nwkUpdateId and the MAC Interface Table, whose channel a restore otherwise had to be told.
Version 1 is still restored, its channel left to the config, so a network saved before stays restorable.

**Consequences.**
A joiner's update id is still 0 until it is restored from a state that names one.

## D-293 · A group frame no member took may go to each endpoint of its profile

**Status:** Decided · **tags:** decision

**Decided: `APS_GROUP_DELIVERY_ENDPOINTS` delivers a group frame with no member in the group table once to each registered endpoint whose profile is the frame's, 0xffff on either side matching any; a frame that matches none is counted in `groupFramesUnmatched` and dropped.**
It is a third arm beside D-213's, a departure from 2.2.8.4.2 like `APS_GROUP_DELIVERY_UNFILTERED`: an application that keeps no group table then reads a group frame at a real endpoint rather than at 0xff.
APS still hands the frame over once; the core, which holds the endpoints, makes the copies.

**Consequences.**
Each copy takes a slot in the core's ring of eight, and one that finds it full is counted in `indicationsDropped`.

## D-292 · A request to the device's own address is delivered to it, not sent

**Status:** Decided · **tags:** spec, decision

**Decided: an APSDE-DATA.request whose destination is the device's own network address or extended address is indicated to the device as a received frame would be and confirmed SUCCESS; nothing goes on the air, and a full confirm or indication ring refuses it with `ZB_ERR_NO_SPACE`.**
2.2.4.1.1 and 3.2.1.1.3 do not forbid that destination, and 4.6.3.7.11 names a coordinator's NLDE-DATA.request to 0x0000 "a loopback message".
An application may ask its own device object for descriptors and Mgmt_Lqi this way.
A request APS security was asked for is delivered unsecured: it never leaves the device.

**Consequences.**
The device object's answer loops back too, to the application.
`Aps_Loopbacks` counts them.

## D-290 · An application that links its own u_bstream and u_sstream at the pinned revisions replaces vendor/

**Status:** Decided · **tags:** decision

**Decided: `ZB_U_STREAMS_LIBRARY` names the application's library holding both streams and `ZB_U_STREAMS_INCLUDE_DIR` its headers; the tree then compiles nothing of `vendor/`, and a configure whose `u_bstream.h` or `u_sstream.h` does not hash as `vendor/MANIFEST` says stops.**
An application such as deCONZ links its own copies at the same tags, and two copies of one library in one executable is one too many.
Empty, the default, builds `vendor/` as before, so the standalone, firmware and audit builds do not change.

**Consequences.**
The headers are checked, the sources cannot be: the application vouches for its `.c` at the tag.
Only copies of the two headers reach the tree's path, since the application's directory may also hold an `aps.h` or a `zcl.h`.
`parent_streams` builds a parent project both ways.

## D-289 · The device object answers Match_Desc_req, and a request it does not support is answered or handed over

**Status:** Decided · **tags:** spec, decision, measured

**Decided: Match_Desc_req is answered by 2.4.4.2.7's procedure over the registered endpoints; a unicast request the device object does not support is answered NOT_SUPPORTED and a broadcast one dropped (2.4.4.1), unless `zdpUnsupportedToApplication` hands it to the application.**
Every answer carries NWKAddrOfInterest: steps 2b, 4b and 6 say "Status and MatchLength fields only", but Figure 2-62, Table 2-93 and 2.4.4.2.7.3 omit only MatchList, and readers expect four octets.
A broadcast address of interest is answered with this device's own: an EmberZNet OTA client took `0xFFFD` for its server's address.
A parent holds no child's descriptors, so a child end device of interest is NO_DESCRIPTOR.

**Consequences.**
IKEA's OTA lookup finds a coordinator endpoint listing input cluster 0x0019, at 0x0000.

## D-286 · The default sizes hold a network of 200 devices

**Status:** Decided · **tags:** decision

**Decided: the tables that follow the device count default to 200 (`NWK_ADDR_MAP`, `SECURITY_KEYPAIR`, `CORE_JOINER`, `NWK_SOURCE_ROUTE`), the neighbour table to 64, routes and frame counters to 128, the broadcast table and a sleepy child's frames to 32, duplicates to 64.**
The default is sized for 200 devices, mostly routers and about a third end devices, which is more than most networks hold.
A coordinator built at the defaults then needs no sizes of its own; a 32 KB device names its own.

**Consequences.**
The footprint at these sizes is `docs/memory.md`'s.
A saved state is read back only by a build with the same neighbour and link-key sizes (D-253).

## D-285 · NWK holds one received frame for APS, read in place, and receives nothing more until APS is done

**Status:** Decided · **tags:** decision

**Decided: NWK's indication ring becomes one held frame whose NSDU points into the receive's buffers; `Nwk_IndicationDone` resumes the receive, and the step's tasks after the receive wait until it has drained.**
The decrypt already writes into scratch, so a frame needs no copy if it climbs before the next is decrypted (`docs/memory.md`).
APS takes every frame in its step, so the step keeps its order, and APS drains confirms again after the frames.
A frame still held when the next step begins is dropped and counted in `droppedIndications`, so a caller that takes nothing still relays.

**Consequences.**
Suites take frames through `Test_NwkStep`.
`plainScratch` is the receive's alone: a rejoin request is protected in the send buffers.

## D-284 · CCM* decrypts into the caller's output and zeroes it when the tag fails

**Status:** Decided · **tags:** spec, decision

**Decided: `Aes_CcmDecrypt` writes the plaintext into `out`, computes the tag over it there, and zeroes `out` when the tag fails; an `out` that is the ciphertext is refused.**
A staging buffer on the stack sat on the deepest call chain of an MCU's step (`docs/memory.md`).
R23.1 A.4 and 802.15.4-2024 B.3.4 ask that nothing is released when the tag fails and that the purported plaintext is destroyed, which a zeroed `out` meets at the return.

**Consequences.**
D-218's second key reads the same ciphertext, which a decrypt in place would have destroyed.

## D-283 · The MAC's indication ring is a limit of one radio poll, and a poll asks for no more than it has room for

**Status:** Decided · **tags:** decision

**Decided: `ZB_LIMIT_MAC_INDICATION` sizes the MAC's indication ring, 8 and at least 8, one radio batch; a receive pass asks the radio for no more frames than the ring has free, and NWK takes the ring one frame at a time.**
The ring and NWK's copy of it were a large share of `Zb_Core` on an MCU, and the stack empties both every step (`docs/memory.md`).
A poll sized to the free slots still receives at any depth, so a caller draining less often needs no deeper ring.

**Consequences.**
NWK keeps one MAC indication.
A full ring still skips the poll as `pollsSkipped`.

## D-282 · A stick may be named by its USB serial number, which the platform resolves at every open

**Status:** Decided · **tags:** decision

**Decided: a path `usb-serial:<serial>` names the USB device with exactly that serial number; the POSIX open resolves it each time, through IOKit on macOS and sysfs on Linux, refusing a shared serial.**
A Linux name such as `/dev/ttyUSB0` belongs to whatever enumerated first, and `/dev/serial/by-id` needs udev, which containers often lack.
sysfs is mounted in a container, and a rescan at every reopen needs no hotplug events, which a container does not receive.
A plain path still opens: a header UART has no USB device, and some adapters have no usable serial.

**Consequences.**
`Port_Device` names the node opened; `tools/port_find` shows what a selector would open.
macOS's `cu.usbmodem` name appends a digit to a ConBee II's serial, so the serial is read, not the name.

## D-281 · An RCP whose port goes away is opened again at its path, and a loop with no port sleeps

**Status:** Decided · **tags:** decision

**Decided: when the stack's port faults while the network is up, `Zb_Stack` closes it at once and opens the same path again every second until one opens; `ZB_EVENT_RCP_LOST` carries `ZB_ERR_NO_DEVICE` for this and `ZB_ERR_DEVICE_LOST` for a reset or a quiet RCP.**
An unplugged ConBee III otherwise left the radio in FAULT, which nothing leaves, and `Zb_StackNextEvent` returning at once.
`RcpRadio_Reopen` keeps the loss owed, so the MAC re-applies its PIB, mode and pending table as after a reset (D-38, D-122).
A radio fault with no port fault is left alone.

**Consequences.**
The platform has `Port_SleepMs` beside `Port_NowMs`, and `Zb_StackNextEvent` sleeps on it when `Port_Wait` cannot wait.
A hung-up line (`POLLHUP`) is a port that went away, as macOS reports one.

## D-280 · The ZDP client is an option, and it numbers with the device object's counter

**Status:** Decided · **tags:** spec, decision

**Decided: `ZB_ZDO_CLIENT`, off by default, builds `zdo_client`'s request writers and response readers and `Zb_StackZdoRequest`, which numbers a request with the device object's own counter and moves it only when the request is taken.**
2.4.2.8.1 has "the application object itself" keep one counter for the commands it sends, and endpoint 0's object is the device object, so an application numbering its own ZDP requests would run a second counter.
An application that writes its own requests carries none of the code.
The client holds no state: a response is matched by the application (D-210).

**Consequences.**
A Node_Desc_req carries the Fragmentation Parameters Global TLV 2.4.3.1.3.1 asks for, from the device's own node descriptor.

## D-279 · The device object's own sends carry a tag of their own, and their outcomes stay the library's

**Status:** Decided · **tags:** decision, api

**Decided: every send the device object makes (an answer, an announcement, its own request) carries `ZDO_TAG_OWN`, and `Zb_Stack` keeps a confirm from endpoint 0 under that tag from the application; an application may send from endpoint 0 under any other tag, and `Zb_StackApsRequest` refuses that one.**
D-252's tag is the only name a confirm carries back, so without its own tag an answer the device object made could take the place of the application's request in flight.
A ZDP response stays the application's (D-210), so an application asks from endpoint 0 and matches the answer by its transaction sequence number.

**Consequences.**
`Af_DataRequestParameters` carries the tag down to `Aps_ApsdeReq`; `ZB_STACK_TAG_DEVICE_OBJECT` names it at the façade.

## D-278 · An application's files are the platform's, on an opaque handle

**Status:** Decided · **tags:** decision, seam

**Decided: `port_file.h` declares `Port_FileOpen`, `Read`, `Write`, `Seek`, `Size`, `Sync`, `Close`, `Delete`, `Rename` and `Exists` on a `PortFile` that keeps the platform's handle as a `uintptr_t`; the backend the build links defines them, as it defines `Port_NowMs`.**
Each answers 1 or 0 and returns a count through its argument: a caller acts on whether it worked, not on why.
No band calls them, so a target without files defines none and only a program that calls them fails to link.

**Consequences.**
`port_file_posix.c` keeps the descriptor, opens close-on-exec and retries on `EINTR`; a failure leaves `errno` in `platformErrno`.
A file saved under another name, synced and renamed over the old one survives a crash or a power cut.
An example may include `port_file.h` (D-276).

## D-277 · The clock is the platform's: `Port_NowMs()` returns it, and a deadline is a subtraction

**Status:** Decided · **tags:** decision, seam

**Decided: `uint32_t Port_NowMs(void)` returns the target's monotonic millisecond counter, defined by the backend the build links as `Port_DefaultOps` is; the port's ops carry no clock.**
A clock is the platform's, not a serial link's, so a caller holds no port to read it.
A target without a monotonic clock defines no `Port_NowMs` and fails to link rather than answering wall-clock time.
Nothing above band C may assume more of the clock than this: free-running, an arbitrary epoch, one wrap every 49.7 days, every deadline compared with `Zb_timeReached` or `Zb_timeWithin`.

**Consequences.**
`port_posix` reads `clock_gettime(CLOCK_MONOTONIC)`.
`port_null` and `port_win32` define none, and a suite still drives bands A and B with a `nowMs` it chose.

## D-276 · An example may use the substrate and the port's contract

**Status:** Decided · **tags:** decision, mandate

**Decided: an example may include `src/utils/` and `port.h` beside the façade and the codecs, and reaches the platform only through `Port_DefaultOps()` and the port's free calls.**
An example shows what an application built on this stack has to hand, and that is more than the façade: the clock, deadlines, bounded byte work.
A platform header would tie the example to one target, so the build's own backend names the platform for it.

**Consequences.**
The examples measure `--seconds` with `Port_NowMs()` and `Zb_timeWithin`, not `time()`.
A layer header is still refused, as D-216 has it.
What several examples share lives in `examples/common/`, a band a suite may test, and may include `u_sstream.h`.

## D-273 · The examples take no transmit gate

**Status:** Decided · **tags:** decision

**Decided: `example_coordinator` and `example_router` transmit when run, with no `--tx` or `--allow-tx`; the gate stays on the bench tools.**
An example is an application to be read and copied, and an application has no such gate.
The bench tools keep it, since a stray run of one can arm an RCP on a live channel (`docs/internals/hardware.md` §8).

**Consequences.**
`example_router --channels` still has no default, because its discovery transmits on every channel it names.

## D-272 · An active scan takes no more frames than its beacon ring has room for

**Status:** Decided · **tags:** decision, measured

**Decided: while an active scan runs, the MAC's receive pass takes from the radio no more frames than its beacon notification ring has room for, and the rest wait in the radio's queue until the layer above drains the ring.**
A ConBee III on Linux hands over a scan's beacons in one read, and a ring of two dropped the one permitting parent on every try.
Growing the ring, 200 bytes a notification, is not taken.

**Consequences.**
A scan's receive slows to two frames a turn, and nothing else waits on it.
`caseActiveScanKeepsEveryBeacon` in the `mac` suite has four beacons from one turn all notified.

## D-271 · RejoinNetwork 0x01 is the MAC's orphan scan, and a parent realigns its own child

**Status:** Decided · **tags:** spec, decision

**Decided: RejoinNetwork 0x01 runs an orphan scan of the channels named, the radio's own when none, and a realignment joins the device under its sender; a parent realigns an orphan it holds as a child to the address it has.**
6168 names the MAC's orphaning procedure, and 6163-6165 put the scan's status on the join's confirm.
5199-5205 and 5283 have parents support orphan scan.
802.15.4-2024 10.20 prints both halves, 7.5.4 the realignment, which 10.20.1 writes into the PIB.
An orphan the parent does not hold is sent nothing; a router child is a sibling once joined (7935-7936), so only an end device is realigned.
The realignment's MLME-COMM-STATUS is not reported.

**Consequences.**
The `mac` and `nwk` suites' orphan cases hold both halves; no orphan has run on air.

## D-270 · A rejoin asks a parent whose beacon carries the R23 appendix by commissioning

**Status:** Decided · **tags:** spec, decision

**Decided: a rejoin sends a Network Commissioning Request of type 0x01 to a parent whose discovery entry carries the R23 appendix, and 0x06 to any other; `attachMechanism` overrides as for a join.**
7971-7984 print the choice, and 7641 makes commissioning the preferred mechanism.
The request carries the Joiner Encapsulation without key negotiation methods (7689-7694), secured when SecurityEnable is set (7976-7977).
Its answer is judged as any rejoin's (8056-8061), a refusal moves to the next parent by that parent's own mechanism, and 0xF0 asks again once from the address it names (7737-7738).
A parent no discovery entry describes is asked by 0x06, and one whose beacon named no IEEE address is matched by its short address (8059-8060).

**Consequences.**
The `nwk` suite's `caseTheBeaconChoosesTheRejoinMechanism` and `caseCommissioningRejoinIsAnswered` hold it.

## D-269 · A rejoin is answered whatever the permit, and a trust centre rejoin needs the device's own key

**Status:** Decided · **tags:** spec, decision

**Decided: a parent answers a NWK Rejoin Request while joining is not permitted, and a trust centre sends the network key after a trust centre rejoin only to a device it holds a unique link key for.**
8077-8082 name what the permit refuses: an association and a commissioning Initial Join.
A rejoin is received at any time (8090, 12470), and the permit flag is only for new devices (14045-14048).
12483-12487 rejects a trust centre rejoin without a unique link key.
Read together, the clauses agree.

**Consequences.**
The `stack` suite's forgotten child rejoins with the permit closed.

## D-268 · A device told to leave and rejoin discovers its network and rejoins

**Status:** Decided · **tags:** spec, decision

**Decided: a device whose own leave carries Rejoin 1 discovers the parents on its channel and rejoins its network, secured (RejoinNetwork 0x02, D-270), then announces itself; a parent drops a marked frame from a child it does not hold and sends it a Leave with Rejoin 1.**
8670-8680 prints the parent's half, sent at once.
7175-7176 and 5299-5301 have the device object rejoin through NLME-JOIN.
7950-7952 put the discovery first, and it ignores the permit flag (14045-14048).
A rejoin that fails waits for the next Leave.

**Consequences.**
The `stack` suite has a coordinator forget its child, its permit closed (D-269); `interop`'s phase A sends 8 Leaves for 8 refused marks.

## D-266 · An end device sends every unicast to its parent

**Status:** Decided · **tags:** spec, decision, measured

**Decided: an end device's unicast goes to its parent at the MAC, with the final destination in the NWK header, and with no parent entry it is confirmed ROUTE_ERROR.**
R23.1 prints no next hop for it.
Read literally, 8866-8868 has a device without routing capacity, which 8800-8803 makes every end device, discard its own frames.
The rest of the text has the frame travel through the parent: 9457-9458 for a broadcast, 8773 and 9037-9041 for the discovery the parent makes for it, 9416-9419 for an APS transaction with a device other than the parent.
A product end device was observed to do the same.

**Consequences.**
`nwk_routeflow` sends one through a parent that has to discover; the `core` pair's asker holds its server as its parent.

## D-265 · A relay discovers only for its end device child, and holds that frame for the route

**Status:** Decided · **tags:** spec, decision

**Decided: a relay without an ACTIVE route discovers only for a data frame that asks for it from its own end device child, and holds that frame in a NWK transmit slot meanwhile.**
R23.1 contradicts itself: 9029-9042 forbids every case but three, while 8779 and 8861-8863 let a relay discover.
This stack builds 9042's SHALL NOT, so any other such frame is discarded, with no status since 0x00 is retired.
9060 lets the frame wait; with no slot free the frame is discarded.
A held frame that fails once routed is reported as any relayed frame is (D-262).

**Consequences.**
`nwk_routeflow` pins both sides on the mesh air.
How a product router treats a frame it has no route for settles the reading.

## D-264 · An RCP that does not answer within a second is lost

**Status:** Decided · **tags:** decision, measured

**Decided: `Zb_Stack` gives the RCP 1000 ms to answer a request, then resets it as it would after a reset the RCP announced, and reports `ZB_EVENT_RCP_LOST`.**
The slowest answer measured on a five-hop line was 406 ms, on a ConBee I in a burst of route requests.
A start asks again until its 3000 ms deadline, so one lost RESET does not end it.
A frame in a NWK transmit slot that ends with the RCP charges no neighbour.
Band A stops waiting after 1000 ms and never asks again, so band B frees a result 2000 ms after the frame was asked for; four such results would otherwise refuse every frame.

## D-263 · A frame waits in line for the RCP's one request

**Status:** Decided · **tags:** decision, measured

**Decided: band B takes a frame into its transmit track and sends it when the RCP's one Spinel request is free; only a full track refuses.**
The RCP answers a transmit when it has ended, so its request is held for the frame's time on air.
Refusing for that said "no room" while the track held 0 or 1 of 4.
Frames and PIB writes leave in the order the seam took them, which keeps D-231's rule.
Each slot holds its PSDU, about 600 bytes more in all.
A frame the wire has not taken after 500 ms ends as NO_SPACE, inside band A's 1000 ms wait; a reset ends the whole line.
Measured on six RCPs at five unicasts a second: no send refused, against 10 before.

## D-262 · A relayed frame that failed for any reason is reported to its source

**Status:** Decided · **tags:** spec, decision

**Decided: a relayed data frame whose attempts all failed sends a network status to its source, whatever the reason, and only a link seen failing invalidates routes.**
8874 says "for any reason" and 8882 says the relaying device SHALL send the status.
Table 3-56 prints no code but 0x02 for a frame that did not cross, so a refused or channel-busy frame carries that.
9357 ties a broken route to a failed link, so without NO_ACK or a device refusal the relay keeps its route.
A relay with no transmit slot has nothing to send the status with, and is only counted.

## D-261 · A unicast a router carries for the network gets the retries any unicast gets

**Status:** Decided · **tags:** spec, decision

**Decided: a relayed unicast, a Route Reply, a Network Status and a route record take a slot of the NWK transmit pool and run its retries, with no NLDE-DATA.confirm, superseding D-69's "a self-initiated relay owes none".**
8874-8877: a router that "fails to deliver a unicast frame for any reason" SHALL retry up to nwkcUnicastRetries, each attempt delayed and re-encrypted; 8882-8884 report a relayed frame's final failure to its source.
The pool already re-secures each attempt and runs the delay.

**Consequences.**
These frames share eight slots with the application's sends; with none left, a forward is dropped and counted.
A frame refused on every attempt is reported to its source (D-262).

## D-260 · A test mesh cuts a link at the radio seam, not in the library

**Status:** Decided · **tags:** decision, seam

**Decided: `hearing` is a `Radio_Ops` shim that makes a device deaf to named devices, and `tools/zb_mesh` is the node that stands on it; the library has no notion of ignoring a neighbour.**
An ignore list in NWK would be a custom mechanism; a shim leaves every clause running.
It judges the hop, never the originator, so relayed traffic still arrives.
The RCP acknowledges in firmware before the host can drop a frame, so a unicast to an ignored device stays off the air and ends as NO_ACK.

**Consequences.**
A cut is named at both ends, and because a beacon names no extended address, a line opens each parent's permit in turn.
The air stays shared, so a cut is no RF gap.

## D-259 · A router scans as often as Table 2-135 says before it chooses a network

**Status:** Decided · **tags:** spec, decision, measured

**Decided: `Zb_CoreJoin` runs the discovery `:Config_NWK_Scan_Attempts` times, default 5, spaced by `:Config_NWK_Time_btwn_Scans`, default 100 ms, and only then chooses; `Zb_StackConfig` can set both.**
5228-5231 repeat the discovery for "a more accurate neighbor list", so it runs every attempt even if the first hears a parent, and it is not a retry.
A repeat therefore keeps the table D-239 empties at the start, and a parent heard again is updated in place.
A scan that hears nothing on every attempt ends the join.

**Consequences.**
One lost beacon no longer ends a join, as it did in 1 of 40 joins on six RCPs.
A router takes about 1.2 s on one channel, 11 s on all sixteen.

## D-258 · A backbone sibling keeps its place until a rank passes it by a quarter and one frame

**Status:** Decided · **tags:** spec, decision

**Decided: a sibling takes a backbone place from its holder only when its rank exceeds the holder's by more than a quarter of that rank plus 8.**
9007-9008 revise the classification when the metrics "change considerably" and print no number, so this stack states one.
One frame moves a rank by 8, so the 8 stops a single frame swapping two idle entries, and the quarter scales with rank, which traffic can raise into the thousands.
An empty place is filled at once.

**Consequences.**
Without a margin, six devices with traffic changed places 66 to 730 times in 15 minutes; nothing on the wire depends on it.
A sustained shift in traffic still moves the backbone.

## D-257 · The final LQA is 3.6.3's median, over the MAC's LQI as the raw sample

**Status:** Decided · **tags:** spec, decision

**Decided: `lqi` is the median of the three most recent raw samples, and of two the lower; a raw sample is the MAC's LQI.**
8760 sets the average aside and two samples have no middle, so the lower claims no better a link than was heard.
8752 points at a raw formula folding in RSSI, printed in the sub-GHz annex with bounds to be measured on production hardware; none are measured here, so it is not built.

**Consequences.**
A single bad frame moves no cost, and a real change takes two frames.
Two stored samples and the count fit the octets `lqi` already held, so the table does not grow.

## D-256 · The neighbour's link state moves only as the standard prints

**Status:** Decided · **tags:** spec, decision

**Decided: the outgoing cost and the age move only on a link status, RouterAge is held, and any departure waits until a product test shows a real issue.**
8168-8172 and Table 3-75 give cost and age that one source, so a route request may wait a period for one (9120-9122).
Diversity is 8947-8953's A\B, so a receiver a sender names counts itself.
A link status sender is a sibling, since RouterAge is valid on no other row.
A link status covering every address that omits this device clears the sender's outgoing cost (8955-8961).
7935-7936 settle a joined router over 8404: it has no parent, so a former parent's departure leaves it joined, and 11973 owes no report of it leaving.

## D-254 · APS fragmentation is a build option, and a build without it says so on the air

**Status:** Decided · **tags:** spec, decision

**Decided: `ZB_APS_FRAGMENTATION` builds 2.2.8.4.5's fragmentation by default; without it, a fragmented frame is indicated DEFRAG_UNSUPPORTED with no ASDU and no acknowledgement (2.2.4.1.3.3), and a send that does not fit one frame is refused.**
Fragmentation costs every transaction a 128-octet ASDU and the device a reassembly pool, about 1.9 KB that a small target whose payloads fit one frame never uses.
The node descriptor states the choice: 2.3.2.3.4's Fragmentation Supported bit, and 2.3.2.3.10's transfer sizes, 128 octets with fragmentation and one message's 82 without.

**Consequences.**
Both builds pass every suite; the size pins and the reassembly case hold one expectation per build.

## D-253 · Every pool size is a default a build may override, within the protocol's bounds

**Status:** Decided · **tags:** decision

**Decided: the library's pool sizes are `ZB_LIMIT_*` defaults in `src/zb/zb_limits.h`, each overridable with `-D` or the CMake option of that name; the header stops a build outside a size's bounds.**
An application sending many requests at once, or a coordinator with many children, must be able to size the stack without editing headers.
The bounds are only what breaks without a refusal: an 8-bit counter or handle, a one-octet count, Active_EP_rsp's one frame.
Couplings that end in a counted refusal are documented in `docs/configuration.md`, not enforced.

**Consequences.**
CMake sets the definitions on `zb_mac` publicly, so every target sharing the structs sees one layout.
A saved `Zb_State` carries only to a build of the same sizes.

## D-252 · An APS data request carries the caller's tag, given back in its confirm

**Status:** Decided · **tags:** decision, api

**Decided: `Aps_ApsdeReq` carries a `uint16_t tag` the caller chooses, and the `Aps_Confirm` of that request carries it back unchanged; it never reaches the air.**
Table 2-3 prints a confirm's destination, endpoints and status, and two requests to one destination and cluster cannot be told apart by them, so an application sending several in parallel could not match its confirms.
The APS counter names the frame, not the request, and is the stack's to choose.
The tag is the caller's, so the stack never checks it for uniqueness.

**Consequences.**
`ZB_EVENT_SENT` carries it in `sent.tag`, which is how an application matches several sends in flight.

## D-251 · `Zb_Stack` reports events, and an application is a state machine over them

**Status:** Decided · **tags:** mandate, api

**Decided: an application meets one type, `Zb_Stack`, starts it with one config and takes events from `Zb_StackNextEvent`, which turns the stack and waits until one happens or a timeout passes; the stack's own states never reach it.**
`Zb_Stack` is `Zb_Core`, the portable library object, composed with the Spinel backend and the port; `Zb_Layers`, the layer composition, is private to `Zb_Core`.
Otherwise an application tracks the stack's states beside its own.
The events: network up or failed, a device joined, data, a send's outcome, the RCP lost and back (`ZB_EVENT_RCP_LOST`, `ZB_EVENT_RCP_BACK`), stopped.
A send before the network is up comes back as a failed send.

**Consequences.**
`Zb_Stack` owns the backend, the port, the clock, entropy, bring-up and teardown; `Zb_Core` keeps its polls for an MCU integration.

## D-249 · A relay that forwards a Route Reply takes its route to ACTIVE

**Status:** Decided · **tags:** spec, decision

**Decided: the forwarder half of 3.6.4.5.2 sets the routing entry's status to ACTIVE beside the next hop and the residual cost it prints, as the originator half does.**
R23.1 9258-9263 prints only the next hop and the cost for a relay, whose entry 9195 left DISCOVERY_UNDERWAY.
Read literally, 8852-8856 then has that relay start a discovery of its own for the data the route was found for, and 3.6.4.5.1.7 deletes the entry when the discovery expires, so a route through two relays would drop its data as NO_ROUTE.
No reading of the chapter wants a found route unusable at its own hops.

**Consequences.**
The `nwk_routeflow` case pins it at one relay and `nwk_rreqflow`'s chain at the end of three devices.

## D-243 · A broadcast the door refused for room is held and sent on the next turn

**Status:** Decided · **tags:** decision, measured

**Decided: a broadcast refused NO_SPACE or BUSY at the transmit door is not confirmed but asked again every turn for `NWK_BROADCAST_HOLD_MS`, and its confirm is the outcome of the request that reached the air.**
Each router's Device_annce, sent behind the join's PIB writes (D-231), was otherwise confirmed "no room" and sent only 500 ms later by 3.6.6's table.
Once sent, its table record counts the passive-acknowledgment wait from that send, and the resting children's copies follow.
The hold is no longer than nwkPassiveAckTimeout and retries run first, so the record never resends a held frame.
Past the hold the refusal is confirmed and the record goes.
A transmission outcome is still confirmed at once (D-167).

## D-242 · The configured extended address is the device's identity, whatever the RCP reports

**Status:** Decided · **tags:** decision

**Decided: `Zb_LayersInit` takes the configuration's extended address as the operational address and the security module's ownIeee, and does not refuse one that disagrees with the device's factory address.**
A replacement unit takes over an existing network's configuration, and its factory EUI-64 is not the one the network knows.
Early ConBee IIIs report an address that is not theirs.
The binding that matters stays: the address on the air and the one in the CCM* nonce are one, and a config naming two different ones is refused.
The factory field is read and never written; it is what an application uses when it names no address.

## D-241 · The core's join door runs discovery, the join and the key wait, on channels the caller names

**Status:** Decided · **tags:** spec, decision, api

**Decided: `Zb_CoreJoin` discovers permitting networks on the caller's channels, chooses the network asked for or the best-ranked parent's, issues NLME-JOIN and ends once the key is installed or NO_KEY comes; `Zb_CorePollJoinResult` reads its result.**
3.6.1.6.1.1 puts discovery before the join, and the core sequences layers an application must not (D-216).
A secured join's SUCCESS confirm precedes the key, so the door waits for the device to be joined in D-216's sense.
The channel mask has no default: an active scan transmits on every channel it visits.
The capability follows the device type, a router an FFD on mains.
A router configured onto no network answers no Beacon Request until it joins, then beacons for the network joined.

## D-240 · An unauthorized device takes a relayed frame whose auxiliary source is not the NWK sender

**Status:** Decided · **tags:** spec, decision

**Decided: `Security_UnprotectAps` refuses an extended-nonce frame naming another device than the NWK source maps to only once this device is authorized.**
4.4.1.2 step 2 has a joined, unauthorized device use the pair of its pre-installed link key, and 4.6.3.7.2's parent relays the trust centre's Transport Key: the auxiliary header names the trust centre, the NWK source is the parent.
The binding is this stack's guard against a neighbour claiming another sender, and before authorization it refused that key whenever the child knew its parent's IEEE address, as a commissioning join teaches it.
An authorized device keeps the guard.

## D-239 · Network discovery empties the table, scans actively and owns the beacon ring while it runs

**Status:** Decided · **tags:** spec, decision

**Decided: `Nwk_NetworkDiscoveryRequest` empties the discovery table, starts the MAC's active scan and, each step until the scan confirms, takes every beacon notification through 3.6.1.5.1 into the table.**
A mask naming no channel of 11 to 26 is INVALID_PARAMETER, returned as BAD_ARGUMENT.
Rules 4 to 6 compare the NIB's nwkExtendedPanId as read from the beacon this device states, 0 when it names none.
`Nwk_DiscoveryEntries` is the NLME-GET of nwkDiscoveryTable, best-ranked first.
Only while a discovery runs does the NWK read the beacon ring, so instruments read it otherwise.
A join waits until the discovery confirms.

## D-238 · The discovery table is ranked as 3.6.1.5.2 prints, and a parent may be known by its short address alone

**Status:** Decided · **tags:** spec, decision, measured

**Decided: a join tries the best-ranked untried Table 3-74 entry.**
The order: a good LQA (nwkGoodParentLQA, default 75) before a marginal one, then Table I-6's hub connectivity, preferred parent and long uptime, then the newer Update ID with wrap.
Rules 5 and 6 are not built.
A parent heard again updates its row; a full table gives its lowest row only to a better newcomer.
A beacon names its sender by short address, so an entry may lack the IEEE: the commissioning request then omits the destination IEEE and the answer from that short address teaches it.
The RCP reports LQI 255 at almost any signal, so the LQA split ranks little.

## D-237 · An active scan runs under the broadcast PAN and leaves a refused channel unscanned

**Status:** Decided · **tags:** spec, decision

**Decided: `Mac_ScanRequest` scans the named channels lowest first under macPanId 0xffff, restoring the channel and PAN after; a channel whose Beacon Request CCA refused is reported unscanned.**
6.6.2 accepts a foreign PAN's beacon only under the broadcast PAN; the 2006 active scan sets and restores it, a sentence 2024 dropped.
A refusal for want of room is held MAC_SCAN_HOLD_MS, then the channel is unscanned too.
While scanning, non-beacon frames are discarded and no beacon's Address List owes a poll (6.4.1.2).
Beacons go up one by one with their channel, macAutoRequest FALSE.
The confirm is SUCCESS with a beacon heard, NO_BEACON with a request sent, else CHANNEL_ACCESS_FAILURE.

## D-236 · An Initial Join takes the attach mechanism the parent's beacon chooses

**Status:** Decided · **tags:** spec, decision

**Decided: with no mechanism forced, an Initial Join asks a parent whose beacon carried the R23 appendix by Network Commissioning and any other by MAC association.**
3.6.1.6.1.1's rules 1 and 3 make the beacon's appendix the choice.
The discovery entry carries `r23Appendix`, read by `Nwk_BeaconHasAppendix`: whole TLVs behind the info field, the Router Information TLV among them (3.6.8.1).
`attachMechanism` can force either mechanism, for a test of one.
A rejoin takes the choice the same way (D-270).

## D-235 · A beacon reply the transmit door has no room for is asked again for 100 ms

**Status:** Decided · **tags:** decision

**Decided: a beacon reply refused BUSY or NO_SPACE, or with no free track slot, stays owed and is asked again each step for MAC_BEACON_HOLD_MS, then counted refused.**
A PIB write queued on the parent refuses it too (D-231), and the scanner would then see no beacon on that try.
The hold is short because a scanner listens on the channel only for a dwell this device cannot know; 100 ms is band A's own number, open.
Later replies wait behind the held one, in request order.
Any other refusal is still counted at once.

## D-234 · An Association Request whose PIB write has no room is held like its transmit

**Status:** Decided · **tags:** decision, measured

**Decided: when 10.21.2's PIB write is refused BUSY or NO_SPACE, the request is held with the write owed, both re-asked each step under D-222's one macResponseWaitTime.**
A refused write otherwise goes straight back to NLME-JOIN as a failure before the exchange: measured on a RaspBee II on channel 25, 3 of 3 associations failed that way.
The write is asked again before the frame, so the request still leaves behind its PAN.
Past the hold the exchange fails with TRANSACTION_OVERFLOW, nothing sent.

## D-233 · A confirm that names no issue pairs by destination and NWK sequence number

**Status:** Decided · **tags:** decision

**Decided: an NLDE confirm whose handle matches no waiting APS issue is paired by destination and the NWK sequence number the request was composed with.**
D-63 makes the handle the pairing, but a frame held for a sleeping child, a re-issued attempt and a discard that ran no transmit carry none the issue recorded.
By destination alone, two frames for one child could each take the other's confirm.
The sequence number is supplied once per frame (3.6.2.1) and 3.2.1.1.3's retries re-send that frame, so it names the one.
`Nwk_LastRequestSeq` hands it to the issue beside `Nwk_LastRequestHandle`.
A confirm matching neither is counted ignored.

## D-232 · A direct frame carries macMaxFrameRetries, an indirect one none

**Status:** Decided · **tags:** spec, decision, measured

**Decided: `tx` takes each frame's retry count: macMaxFrameRetries for a direct frame asking an acknowledgment, 0 otherwise.**
802.15.4-2024 6.6.3.4 retransmits a direct frame up to macMaxFrameRetries times and never an indirect one.
The RCP's PIB read reports a count of 0, so a frame relying on it goes out once: measured on a ConBee II to an absent address, one copy per DSN before, four after.
Table 8-36's default of 3 holds until the field is set; more than 7 is refused.
Band B neither stores nor reports the field.
maxCsmaBackoffs stays 0, each firmware's default.

## D-231 · A transmit waits behind the PIB writes taken before it

**Status:** Decided · **tags:** decision, measured

**Decided: a transmit reaches the RCP behind every PIB write taken before it; D-263 holds it in line to do so.**
A frame sent right after a PIB set could otherwise overtake its own write.
Measured on a RaspBee II at 38 400 baud: the commissioning request left before its short address, which landed about 6.5 ms later; the parent answered after about 6 ms, so about half the sessions lost the answer.
The same overtaking would send a Beacon Request before its channel write, a rejoin on the old channel and an association request before its PAN.
The source-match statement is not waited for: it decides frame pending, not what the radio accepts.

## D-230 · A frame of the join layer's own the transmit door has no room for is held, not lost

**Status:** Decided · **tags:** decision, measured

**Decided: a join-layer frame the MAC refuses with BUSY or NO_SPACE is copied and offered again each step for MAC_ASSOC_SEND_WAIT_MS, then dropped and counted; a request's countdown starts when it goes out.**
D-222 holds the MAC's association request the same way; these frames bypass it through `Nwk_TxIssueRaw`.
Measured: without the hold, every commissioning join on a ConBee II lost the parent's End Device Timeout Response to the busy door, by timing alone.
It covers the commissioning and rejoin requests and answers, the timeout pair and the unsolicited rejoin response.
One frame is held at a time; a second refusal meanwhile is lost.

## D-229 · A join command to a child whose receiver rests is held for its poll

**Status:** Decided · **tags:** spec, decision

**Decided: the commissioning response and the End Device Timeout Response go on the transaction queue when the child's receiver rests, as the rejoin response does.**
3.4.15.1 asks for indirect transmission when the request's Receiver on when idle bit is 0, for a refusal as for a grant.
3.4.12.1 names no transmission option, but a resting end device hears its parent only through its poll (10.22.2), so the timeout response follows the data path's rule for a resting child.
The child's half polls inside its countdown (D-225).

## D-228 · An Initial Join states key negotiation with no method and no secret

**Status:** Decided · **tags:** spec, decision

**Decided: every commissioning request but a rejoin carries Figure I-2's Supported Key Negotiation Methods TLV (tag 65) inside the Joiner Encapsulation, with both bitmasks zero and the device's EUI-64.**
3.4.14.3.3 (lines 7689-7691) requires it when not rejoining, and line 7693 forbids it on a rejoin.
Zero is what is built: no Request Key, no SPEKE and no install code (Tables I-4, I-5), so the trust centre sends the network key under the current link key, Table 3-70's other path.
`capsJoinerTLVsUnfragmentedMaxSize` is named but not printed; the request's TLVs come to 21 octets.

## D-227 · A commissioning join takes the next-parent loop, and an address conflict is asked once more

**Status:** Decided · **tags:** spec, decision

**Decided: a commissioning attempt that times out or is refused moves to the next parent as D-223's association does; a 0xF0 answer is asked once more of the same parent from the address it gave, and a second 0xF0 fails that parent.**
3.6.1.10.3 (lines 8271-8277) expects the device to retry with the new address; one re-send is that retry and not a new parent, so it uses none of nwkMaxInitialJoinParentAttempts.
Every attempt keeps the address the join claimed and moves the PIB to the next parent's channel and PAN.

## D-226 · An unjoined device takes an unsecured commissioning response, as a rejoin response

**Status:** Decided · **tags:** spec, decision

**Decided: 3.6.2.2's unjoined branch lets through an unsecured Network Commissioning Response addressed to this device, beside the rejoin response.**
3.6.1.10.6 (lines 8319-8330) accepts either response unencrypted when the device sent the corresponding unencrypted request, and drops an unsolicited one.
The gate lets it through, and the join layer drops it unless a commissioning join is waiting for it.
An Initial Join is always sent unsecured, and 3.4.15.2 answers at the request's level, so without this a secured-level joiner could never read its answer.

## D-225 · A commissioning child borrows the PIB for its exchange and gives it back on failure

**Status:** Decided · **tags:** spec, decision

**Decided: before 3.4.14's request the child writes the parent's channel and PAN and the address it claims into the PIB, and puts the PAN and address back to 0xffff when the join fails.**
3.4.14.1 makes that address the request's source, and the radio filters the answer by it.
The answer counts only from the parent asked and to this device (3.6.1.6.1.2, lines 8056-8061), within macResponseWaitTime, with polls where the receiver rests; else NO_DATA.
On success the answered address is kept and the parent recorded, arming the NO_KEY wait and 3.6.10.2's timeout request.
While the exchange runs the device is no member: `Nwk_IsPartOfNetwork` and the send door say not yet, and a second join is BUSY.

## D-224 · A failed rejoin moves to the next parent of the network it named

**Status:** Decided · **tags:** spec, decision

**Decided: a rejoin that times out or is refused tries the next discovery entry of the network it named, until nwkMaxRejoinParentAttempts attempts are made or none is left.**
3.6.1.6.1.1 (lines 8010-8016) gives the rejoin its own bound, Table 3-50's 0xC3, default 3; a config naming 0 takes it.
A candidate has a known short address and a channel this layer joins, and need not permit joining.
Each request goes out on its parent's channel; a rejoin naming no network goes to the parent it holds, on the radio's channel.
Every attempt keeps the first one's source address and security, and an answer from a parent already left is dropped (lines 8056-8061).
A request the next parent cannot be sent ends the rejoin.

## D-223 · A failed association moves to the next parent, never back to the same one

**Status:** Decided · **tags:** spec, decision

**Decided: an unsuccessful association tries the next potential parent until nwkMaxInitialJoinParentAttempts attempts are made or none is left, then confirms with the last attempt's status.**
3.6.1.6.1.1 (lines 8010-8016) names the next parent, so one parent is one attempt whatever the bound.
The default is 1 (Table 3-50, 0xC2), so a default join tries one parent; a config naming 0 takes it.
A potential parent permits joining, belongs to the network asked for and sits on a channel ScanChannels allows; with none left the request is NOT_PERMITTED.
The parents are tried in D-238's ranking; lines 7928-7930 let the application reorder.
A next parent the MAC refuses ends it.
Commissioning takes this loop (D-227), the rejoin D-224's.

## D-222 · An Association Request the transmit door has no room for is held, not abandoned

**Status:** Decided · **tags:** spec, decision, measured

**Decided: when the transmit door answers BUSY or NO_SPACE after 10.21.2's PIB write, the request is held and re-asked each step for one macResponseWaitTime; only then does the exchange fail with TRANSACTION_OVERFLOW.**
D-167 reads IEEE 7.2.4's MAC as one that never refuses a request, so no room is a wait and not an answer.
The PIB is written once and put back once, on the failure only.
Abandoning at once would write the PIB back on every refusal, and behind a USB-serial bridge (ConBee III) those writes filled band B's queue, so every later join was refused NO_SPACE.
Any other refusal still fails the exchange at the door.

## D-221 · A joined parent takes an unsecured commissioning request

**Status:** Decided · **tags:** spec, decision

**Decided: a joined parent takes an unsecured Network Commissioning request, the one unsecured command besides 0x06.**
Read alone, 3.6.2.2 drops every other unsecured command.
3.6.1.6.1.3 drops a network-encrypted Initial Join, so it expects one unsecured, and 3.6.1.10.3 calls the request "secured or unsecured"; the reading that leaves the command usable wins.
The request is judged by 3.6.1.6.1.3's own rules: an Initial Join is refused while joining is not permitted, a known device is matched by its IEEE address, and an unsecured rejoin never rewrites a known neighbour (8106-8110).
A known device's unsecured Initial Join, which a factory-reset product makes, is a join again at its entry's address.
A rejoin-type request continues while joining is not permitted.

## D-220 · A device joins through a router: Update Device, Tunnel and Remove Device on both sides

**Status:** Decided · **tags:** spec, decision

**Decided: a router reports a join and a child's departure with Update Device (4.6.3.2.1, 4.6.3.6.2), the trust centre tunnels the key back (4.6.3.7), and Remove Device goes through the parent (4.6.3.6.1).**
A join at the trust centre enters the same `APSME-UPDATE-DEVICE.indication` ring as a received command, its Table 4-14 status from the join method; 0x01 and 0x03 are owed the key, 0x00 and 0x02 nothing (4.4.3.2.3).
The trust centre notes each joiner's parent in 8 rows; a full table evicts the oldest, since the newest joiner is the likeliest removed.
Under a global key the router sends both copies 4.6.3.2.1 prints.
Relay Message is not built: 4.6.3.7.7 keeps the key in a Tunnel, and the relay serves key negotiation, which is not built.

## D-219 · A device that associates anew is heard from whatever counter it sends

**Status:** Decided · **tags:** spec, decision, measured

**Decided: when a parent's association answer is delivered, the NWK incoming frame-counter windows held for that device's address are dropped, under every key.**
R23.1 4.3.4 has a device keep its outgoing NWK frame counter across factory resets, and predicts that the network rejects frames otherwise.
A TRÅDFRI bulb does not: its counter went from 20484 to 0 across a reset, and every frame after its new association was refused as a replay.
3.6.1.6.1.3's new neighbour entry therefore starts fresh.
A device that does not associate keeps its replay protection; the cost is that a forged association can reset one device's window.

## D-218 · A trust centre answers a trust centre link key request with a derived key

**Status:** Decided · **tags:** spec, decision

**Decided: the trust centre link key a Zigbee 3.0 joiner requests (4.7.3.8) is B.1.4's keyed hash of the device's address under an application's seed.**
4.7.3.8.1 lets the key be made "programmatically using an algorithm", and D-56 keeps the platform's entropy out of the library.
A device that asks twice gets the same key, so keys never fall out of step (4.7.3.8).
The request may come under the global key, whose entry names no device, so step 2's address test applies to a unique pair only.
The key goes out under the key the device holds now, and until its Verify-Key confirms the new entry a frame that fails under it is tried under the global key.
No seed, no answer; an application key request is not built.

## D-217 · A broadcast may address the ZDO endpoint

**Status:** Decided · **tags:** spec, decision, measured

**Decided: the codec and the send door take a broadcast to endpoint 0x00, and the device object announces there.**
2.2.5.1.2 delivers a broadcast "to the destination endpoint specified within the range 0x01-0xfe or to all active endpoints if specified as 0xff", and its next paragraph names 0x00 the ZDO.
Read as a range rule, that makes 2.4.3.1.11.1 impossible: Device_annce is a ZDP command to endpoint 0, and its addressing is broadcast.
0xff excludes endpoint 0x00, so it cannot stand in.
A codec that refuses that address drops a TRÅDFRI bulb's announcements as damaged.
A test network on channel 15 carries broadcast APS frames to endpoint 0x00 (`test/fixtures/conbee2_ch15_nwksec_hex.txt`).
A ZDP request broadcast to 0xff stays the device object's.

## D-216 · The core owns the network, the radio's mode and the trust centre's key

**Status:** Decided · **tags:** decision, mandate

**Decided: `Zb_Core` states the beacon, the radio's filtered mode and the trust centre's key delivery, so an application never sequences a layer for them.**
A beacon is the device's identity, not an operator's choice, so `Zb_CoreInit` states Table 3-83's info field and 3.2.2.7's permit door has something to open.
The radio's filtered mode is a fact about the RCP, which acknowledges nothing in receive-all mode, so the device's first turn states it.
A joining device is owed the network key, which 4.6.3.2.1 makes the trust centre's duty, so the core sends it under the configured global link key.
A join is learnt from the device's own 2.4.3.1.11 announcement, which the device object republishes.

**Consequences.**
`examples/` includes no layer header, and the band audit holds it.

## D-215 · An AIB entry naming an endpoint with no descriptor is still delivered

**Status:** Decided · **tags:** decision

**Decided: a group frame whose member endpoint holds no simple descriptor is delivered like any other member's.**
The group table is the application's statement about its memberships, and the endpoint registry the device's statement about what it advertises.
Policing the first with the second would invent a rule neither 2.2.8.3 nor 2.3.2.5 asks for, and drop traffic the application asked to receive.

## D-214 · ZCL is a codec the application calls, not a layer the stack carries

**Status:** Decided · **tags:** decision, api

**Decided: no cluster is registered with the stack; a cluster server is an application that registers a simple descriptor and answers its own ASDUs, and the `zcl` module's codecs are calls it may use.**
A cluster is a `uint16` in a simple descriptor's input and output lists, so a separate registration would let the registry and the descriptor disagree.
ZCL's size, its vendor extensions and its per-profile interpretations make it a library an application chooses, not a layer the stack steps.

## D-213 · 2.2.8.4.2's group table is consulted only where the application asks

**Status:** Decided · **tags:** spec, decision

**Decided: `APS_GROUP_DELIVERY_MEMBERS` follows 2.2.8.4.2 and is the default; `APS_GROUP_DELIVERY_UNFILTERED` delivers a group frame with no member once, with `dstAddrMode` 0x01, the group as `dstAddress` and `dstEndpoint` 0xff, instead of dropping it.**
2.2.8.4.2 delivers a group frame only to the endpoints the table associates with the group, so delivering a stranger is a departure.
Unfiltered, the application sees every group frame exactly once and never twice, so its filter needs no case for a group it is also a member of.
Sending to a group consults no membership (2.2.8.4.1).

## D-212 · One send door, and only what composes layers is wrapped

**Status:** Decided · **tags:** decision, api

**Decided: `Zb_CoreSendRequest` takes Table 2-2's request, adds a running guard and a source-endpoint check, and only a duty that sequences more than one layer is wrapped beside it.**
The application already includes `aps.h` to name what it polls, and a second request type would be a second truth.
Endpoint 0 is the library's, and any other must be a registered descriptor, since a device cannot send from an endpoint it does not advertise; that check is this stack's, not a clause.
A wrapped call sequences what the application should not have to, such as a leave's answer before the departure or the permit's beacon beside its countdown.

## D-210 · The application's surface is the APS primitive, and the library owns endpoint 0

**Status:** Decided · **tags:** spec, mandate

**Decided: an application speaks the APS primitive and nothing below it, through `Zb_Stack` (D-251) or directly on `Zb_Core`: one send door, one polled ring, never a layer; endpoint 0 and the ZDP requests are the library's.**
`Zb_Layers` is the transport, MAC through APS and security; `Zb_Core` adds the endpoint registry with 2.3.2.5.1's checks, the device object and the binding table.
A ZDP request to endpoint 0, or broadcast to 0x00 or 0xff, is the device object's (D-217), unless D-289 hands an unsupported one over.
A ZDP response is the application's, matched by the transaction sequence number it wrote.
`Device_annce` is the one request the object consumes and also republishes (2.4.3.1.11.1).
An APS indication ring has one reader, so no framework layer sits above APS.

## D-208 · A permit refusal the layer cannot attribute to the MAC is INV_REQUESTTYPE

**Status:** Decided · **tags:** spec, decision

**Decided: a permit refusal from this stack's beacon door, which answers with a `ZbStatus` rather than a MAC status, is reported as INV_REQUESTTYPE.**
Table 3-16 admits only that code and the MLME-SET.confirm status, so a code of its own would put an unadmitted octet on the management response.

## D-207 · A leaving device's former parent, and a MAC reset this stack cannot issue

**Status:** Decided · **tags:** spec, decision

**Decided: a departing device clears what the NWK layer holds and states its own address as none, and issues no MLME-RESET.**
3.6.1.11.4 asks for the former parent's relationship to be set to 0x03 and for MLME-RESET to the MAC, then clears the whole neighbour table a sentence later.
This stack's MAC offers no reset door.

## D-206 · The leave answer goes out before the departure, with codes the table admits

**Status:** Decided · **tags:** spec, decision

**Decided: the leave answer is sent before the device departs; a frame the layer could not put on the air is NOT_SUPPORTED, a device not in the neighbour table is the layer below's UNKNOWN_DEVICE, and a refused validation is NOT_AUTHORIZED.**
2.4.3.3.5.2 fixes the order, and a device whose own address and PAN were just reset has nothing to answer with.
D-201 maps UNKNOWN_DEVICE to DEVICE_NOT_FOUND on the wire.

## D-204 · The entry a leave announcement names is read before it is rewritten

**Status:** Decided · **tags:** spec, decision

**Decided: a router reads the neighbour entry a leave announcement names before 3.6.1.11.3 modifies it, so its repeat of its parent's announcement is reachable.**
3.6.1.11.3 modifies the entry "regardless of the value of the rejoin flag" and then asks whether the sender was the parent; read in that order the repeat could never run.
The repeat goes out before the extended PAN id is cleared and before the orphaning is reported, the paragraph's own order.

## D-201 · Which leave request is validated, and which is a parent removing a child

**Status:** Decided · **tags:** spec, decision

**Decided: 3.6.1.11.3.1 validates a Mgmt_Leave_req that names the receiving device; one naming another device is the parent-side removal 3.2.2.18.3 prints.**
Read whole, step 1 would make a coordinator drop every leave request, which 3.2.2.18.2 contradicts: a coordinator or router "MAY also generate this primitive to remove a device from the network".
2.4.3.3.5.2 singles out the case where "the DeviceAddress in the request is equal to the local device's EUI64", and for that case fixes RemoveChildren and Rejoin to FALSE whatever the frame printed.
UNKNOWN_DEVICE is no ZDP code, so the answer a peer gets is Table 2-129's DEVICE_NOT_FOUND.

**Consequences.**
A coordinator can remove its own child and cannot be asked to remove itself.

## D-200 · A permit that cannot be re-stated is refused as a state, not as a parameter

**Status:** Decided · **tags:** spec, decision

**Decided: 3.2.2.7's request answers NOT_PERMITTED when the device holds no beacon info to re-state, and INV_REQUESTTYPE when it is an end device.**
3.2.2.7.3 sets macAssociationPermit by writing the beacon, so a device never given beacon info cannot carry it out, which is Table 2-129's "not in the proper state".
Table 3-16's other arm is an IEEE status, and Table 2-129 reserves 0x93-0xff, so none is copied into a ZDP octet.

**Consequences.**
The permit leg keeps the beacon info the application last set, so a countdown can clear the Association Permit bit alone.

## D-199 · What a ZDP response may answer

**Status:** Decided · **tags:** spec, decision

**Decided: a Bind_rsp, an Unbind_rsp or a table report answers only with a status its own table prints.**
Table 2-97 prints SUCCESS, NOT_SUPPORTED, INVALID_EP, TABLE_FULL and NOT_AUTHORIZED, and Table 2-98 swaps TABLE_FULL for NO_ENTRY.
Tables 2-101, 2-103 and 2-105 print NOT_SUPPORTED or whatever their GET confirm returned.
INV_REQUESTTYPE is in Table 2-129 and in none of the five, so a malformed request answers NOT_SUPPORTED and an endpoint outside the printed range answers INVALID_EP.
A secured send with no key pair answers SECURITY_FAIL, 2.2.4.1.1.3's words for security processing that fails.
NO_SHORT_ADDRESS stays Table 2-29's definition: a miss in the address map.

**Consequences.**
An application reading a status learns which check refused the request.
The framework carries the destination an indication arrived with, so a unicast-only command can drop a broadcast.

## D-198 · A binding link belongs to a source device, and no cluster is a wildcard

**Status:** Decided · **tags:** spec, decision

**Decided: the fan-out searches the entries whose source address is this device, and a ClusterId of 0xffff is an ordinary cluster.**
2.2.4.1.1.3 says the search uses "the endpoint and cluster identifiers", and 2.2.8.2.1's mapping makes every entry a link of one source device, `(as, es, cs)`.
Reading the search as address-blind lets a coordinator, which 2.4.4.2.24.1 allows to hold other devices' entries, re-address its own frames from them.
The only wildcards R23.1 prints are Match_Desc_req's profile id and Clear_All_Bindings' EUI64 list.

**Consequences.**
An entry sourced by another device is reported by Mgmt_Bind_req and never used for a send, and one entry per cluster is what a bind buys.

## D-197 · What a neighbour report states when the NIB holds nothing

**Status:** Decided · **tags:** spec, decision

**Decided: 2.4.4.3.2's neighbour report states what the NIB does not hold in the field's own words.**
Tree depth is deprecated by 3.6.8 to 0x00 and no Table 3-75 row holds one, so entries are reported at 0x00.
Table 3-75 holds no extended PAN id, and a neighbour is a device whose frames this stack took on this PAN, so the report states this network's.
Permit joining is never observed, and Table 2-102 prints an unknown value, which 2.4.4.3.2.1 says to use where a value is unavailable.
The same rule covers a device type, a receiver duty and an IEEE address an entry never heard.

**Consequences.**
A report claims no number this stack does not hold, and Table 2-101's cap of two records is why a neighbour table is read by paging.

## D-196 · The binding entry's printed vocabulary

**Status:** Decided · **tags:** spec, decision

**Decided: a binding entry holds only Table 2-6's two destination modes, 0x01 for a group with no destination endpoint and 0x03 for an extended address with one.**
0x00 and 0x02 are reserved there, although 0x02 is legal in a data request, so a bound unicast is stored as an extended address and mapped through `nwkAddressMap` when it is sent.
Table 2-6 prints the destination endpoint as 0x01-0xff and Table 2-55 as 0x01-0xfe, and the stack takes the narrower.
No room answers TABLE_FULL, which Table 2-97 prints for that failure, and not 2.4.3.2.2.2's INSUFFICIENT_SPACE.
An entry already held is not duplicated and is answered SUCCESS, which no clause states.

**Consequences.**
A bind of a 16-bit destination is refused rather than stored wrong.

## D-195 · The join's SecurityTimer is armed only where the network can authenticate

**Status:** Decided · **tags:** spec, decision, measured

**Decided: 3.6.1.6.1.1's SecurityTimer is armed for a new child only when the security level is not `NONE`.**
The countdown revokes a join that never shows a frame the network key protects, and a network at level 0x00 protects nothing.
Armed there, it deleted every child after `apsSecurityTimeOutPeriod`'s 10 s, leaving the neighbour table empty.
The relationship stays 0x05 (unauthenticated child) until a secured frame promotes it, as 3.6.2.1's table says.

**Consequences.**
A level-0x00 parent keeps its children; a secured network's countdown is unchanged.

## D-193 · The neighbour ranking's three windows are this stack's numbers

**Status:** Decided · **tags:** spec, decision

**Decided: `nwkcMinRouterObservationTime`, `nwkcBackboneMeshFormationTime` and `nwkcBackboneMeshRouterNeighbors` are 2, 8 and 2, chosen here because Table 3-66 names them without printing a value.**
3.6.4.4.3.1's algorithm is printed in full and only its three windows are the manufacturer's.
The two times count RouterAge ticks, one per link status received from a known sender, about `nwkLinkStatusPeriod`'s 15 s apart, so an entry may be dropped after 30 s and promoted after 2 min.
The rank is the printed formula, its two metrics 3.6.4.4.2's sums over the sender's link status list.

**Consequences.**
A full neighbour table no longer refuses a new link status: the lowest-ranked sibling past the window gives way to the sender, and with none the frame is dropped.

## D-192 · A relayed source route is bounded by the octets' room, not by nwkMaxSourceRoute

**Status:** Decided · **tags:** spec, decision

**Decided: `nwkMaxSourceRoute` caps the routes this device builds; a frame it relays is bounded only by the octets' room, and the relay clears the discovery sub-field.**
NIB attribute 0x93 is what a device writes into the routes it constructs, and 3.6.4.3.2's relay is not construction: the list arrives written.
3.6.4.3.2 relays by a direct MCPS-DATA.request to a named hop, so the discovery sub-field is suppressed on the way out even when it arrived set, as a live network's relays do.

**Consequences.**
The codec has two composers, `NwkFrame_Compose` and `NwkFrame_ComposeRelay`.

## D-191 · Fragmentation is built at window size 1, and a repeated block re-acknowledges

**Status:** Decided · **tags:** spec, decision, api

**Decided: 2.2.8.4.5's fragmentation is built at Table 2-28's `apscWindowSize` 1 and no higher, and a block the window has already passed is acknowledged again rather than dropped.**
2.2.8.4.5: "the use of a window size of 1 is the only window size guaranteed to interoperate", every larger window being a manufacturer's own.
The acknowledgement names the lowest block of the window with one bit per block and the rest at 1, so a window of one leaves seven bits set.
A repeated block means the sender missed that acknowledgement, which the clause's persistence paragraph answers.

**Consequences.**
`aps_frag` holds the pool and the arithmetic; `aps_tx.c` splits and the receive path reassembles.
`ZB_APS_FRAGMENTATION` 0 builds without it, a fragmented frame then answering DEFRAG_UNSUPPORTED.

## D-187 · A local conflict is announced once, after the jitter, to the receivers that rest on

**Status:** Decided · **tags:** spec, decision

**Decided: 3.6.1.10.5's 0x0d Network Status is armed by a local conflict, sent once after `nwkcMaxBroadcastJitter` to 0xfffd, and a second conflict found before it goes out replaces the address it names.**
The clause delays the broadcast so a device hearing another's announcement of the same conflict can drop its own, and one pending announcement is what this stack keeps.
The address field is the offending one, and an end device announces nothing: resolution is its parent's.

**Consequences.**
A 0x0d naming the same address, heard before the delay runs out, withdraws the announcement.
The conflict broadcast runs after the turn's indications are drained.

## D-186 · The address map is a table of rows, and a conflict is counted before it is resolved

**Status:** Decided · **tags:** spec, decision

**Decided: Table 3-66's nwkAddressMap is a pool of Table 3-68's pairs sized by `ZB_LIMIT_NWK_ADDR_MAP`, learning a pair returns a verdict rather than a boolean, and the two conflicts are counted apart.**
R23.1 prints no size; the default of 200 is one row per device a trust centre may remove.
3.6.1.10.2 prints one conflict on this device's own address and another on a third device's.
A null 64-bit address is filled rather than conflicted, and a row is added only with no conflict, no row at either address, and room.
The local case compares a pair against this device's own addresses, so it needs no row of its own.

**Consequences.**
The lookups give 2.2.4.1.1.3's mode 0x03 a short address and 2.2.4.1.3.2's indication a 64-bit source.

## D-185 · An acknowledgement measured between two RCPs names when each side transmits

**Status:** Decided · **tags:** mandate, measured

**Decided: a two-RCP measurement of an acknowledgement states when each side transmits, using `tools/rcp_send`'s `--listen-on` and `--send-at`.**
An RCP that transmits before its peer is listening is not answered, which once read as a direction that loses frames.
With the listener armed for seconds and the request held back 1500 ms, every frame is acknowledged in both directions with no retry.
`--listen-on` holds the receive window open and `--send-at` holds the transmit back; a measurement with neither is a race.

## D-184 · A neighbour's relay of this device's broadcast is read before the frame is dropped

**Status:** Decided · **tags:** spec, decision

**Decided: a broadcast carrying this device's own source address marks its Table 3-81 record before the receive pipeline drops it.**
3.6.6 has a router keep track of which neighbours relayed the broadcast, and that relay is the only passive acknowledgement there is.
The frame is the one the source test drops, so the mark is made before the drop.
The clause's power-up guard is about processing such a frame, and nothing is processed: it is not delivered, relayed or counted.

**Consequences.**
D-181's repetition can be withdrawn once every neighbour has relayed.

## D-183 · A document budget is derived or chosen, and the difference decides whether to cut

**Status:** Decided · **tags:** mandate

**Decided: a document with one entry per thing in the tree has its word budget derived from that count, and a narrative document has one chosen by editorial judgement.**
A derived budget below the count fails a document that obeys its own rules.
A chosen budget is a limit, and passing it prompts the question whether the content belongs in another document.
Neither kind is trimmed to reach a number.

**Consequences.**
Every budget in `test/docs_audit.py` says which kind it is and how its number was reached.

## D-182 · An unverified frame counter has its own status, and a transport key verifies its pair

**Status:** Decided · **tags:** spec, decision

**Decided: 4.4.1.2 step 8 answers `ZB_ERR_UNVERIFIED_FRAME_COUNTER` and stores no counter, and the transport key a joiner accepts verifies the pair it came from.**
Step 8 a) names that result, and 4.6.3.8 forbids storing a counter for a pair whose `VerifiedFrameCounter` is FALSE.
`ZB_ERR_AUTH` would say the tag did not verify, about a frame whose tag just did.
4.6.3.8's last paragraph is the other half: the pair a transport key arrived from is verified with that command's counter, since nothing earlier can be replayed to a device that has just joined.

**Consequences.**
4.6.3.8.1's challenge is deferred.

## D-181 · A broadcast this device sent is repeated by its own record

**Status:** Decided · **tags:** spec, decision

**Decided: the Table 3-81 record of a broadcast this device originates keeps the octets it would repeat, and 3.6.6's count runs for it as for a relay.**
3.6.6 has a router "retransmit a previously broadcast frame at most nwkMaxBroadcastRetries times", and the device's own frame is one.
A repetition is counted apart from a relay, the two being different duties on the same table.

## D-180 · A command frame is acknowledged though its transaction owes no confirm

**Status:** Decided · **tags:** spec, decision, measured

**Decided: a transport-key command this device receives is answered with an APS acknowledgement, although its transaction owes no confirmation (D-175).**
4.4.11 prints "ACK request 1" for every unicast command, whatever 4.4.2 prints about primitives.
A dropped key is answered too, with `SECURITY_FAIL`, the status the check's verdict amounts to.
Without the acknowledgement the key installed and the trust centre re-sent it and counted the transaction failed.

## D-178 · A level with no key is the joining device

**Status:** Decided · **tags:** spec, decision

**Decided: `Security_Init` accepts `nwkSecurityLevel` above 0x00 with no key in the set, and `Security_IsEnabled` reports that state as not enabled.**
A joining device states the level it can do and has not been given the network key yet, which is 4.6.3.2.4's device waiting for a Transport Key.
Refusing the configuration made the join unbuildable.
The active-key test is what 3.6.1.6.1.1's `NO_KEY` hangs on, so it stays inside `Security_IsEnabled`.
A transmit that asks for security in that state fails `NO_KEY` at the key lookup.

## D-177 · The join's key wait is a second confirmation, not a delayed first

**Status:** Decided · **tags:** spec, decision

**Decided: a successful join is confirmed at once, and 3.6.1.6.1.1's `NO_KEY` arrives as a second `NLME-JOIN.confirm` when `apsSecurityTimeOutPeriod` passes with no network key.**
3.6.1.6.1.1 prints the wait before the success confirmation, which would hold SUCCESS back until the key came.
4.6.3.2.4 counts the same timer from "receiving the NLME-JOIN.confirm primitive", so success comes first there, and this stack reads that order.
The period follows D-169: Table 3-75's countdown in seconds, armed from Table 4-35's ten.
The reset 4.6.3.2.4 owes a device that got no key is the application's.

**Consequences.**
The parent's side, 3.6.1.6.1.3, is the same countdown on the child's entry, stopped by the first network-secured frame from it.

## D-176 · 4.4.1.3 decides the addressee, and a distributed network skips it

**Status:** Decided · **tags:** spec, decision

**Decided: a received transport-key command is judged by 4.4.1.3 and then 4.4.2.3, in that order.**
4.4.1.3 asks whether the sender is the trust centre: an unsecured frame by its IEEE source against `apsTrustCenterAddress`, one without that field by a NWK source of `0x0000`, a secured frame by the pair its protection used.
A centralized network discards a command from anybody else, a partner's type 0x03 among them.
Then 4.4.2.3: the policy, the all-F source, the link-key requirement, the destination.
A distributed network, the address all-F, skips both: its unsecured all-F-sourced key is that network's normal key.
The policy is `requireLinkKeyEncryptionForApsTransportKey` or a preconfigured link key, 4.4.1.5's two statements of one rule.

**Consequences.**
D-169's reading of `apsTrustCenterAddress`'s three printed initial values, 4.6.3.1's all-F, is what the first test compares against.

## D-175 · A transport-key transaction owes no confirmation

**Status:** Decided · **tags:** spec, decision

**Decided: an APS command transaction writes no confirmation, and its outcome is counted instead.**
4.4.2 prints an `APSME-TRANSPORT-KEY.request` and an `.indication` and no confirm primitive, and Table 4-8 names no Status parameter.
The slot is freed with `Aps_CommandAnswers` or `Aps_CommandFailures` moved, and `Aps_ConfirmQueue` never holds an answer to a command.

## D-174 · A secured APS command is unprotected before it is identified

**Status:** Decided · **tags:** spec, decision

**Decided: the APS command dispatch runs below the security crossing, because the command identifier of a secured frame is inside its protected region.**
4.4.2.3's first act on a transport-key command is security processing, and only then the key type.
A command identifier sits after the APS counter, inside the octets 4.4.1.2 protects.
The cost is that a secured command this stack does not process still advances its key pair's incoming counter, which is 4.4.1.2 step 8's duty for a frame whose MIC verified.

## D-172 · A send to the low-power routers' class goes out as the MAC broadcast

**Status:** Decided · **tags:** spec, decision

**Decided: a NWK destination of `0xfffb` is transmitted as a MAC broadcast, and the class is refused on reception.**
Table 3-80 prints `0xfffb` as "Low power routers only", and 3.6.6 discards a frame whose destination does not match the receiver's type.
3.2.1.1.3 step 6 lists only `0xFFFF`, `0xFFFD` and `0xFFFC` among the destinations sent as a MAC broadcast, and no clause says how `0xfffb` is sent.
The alternative was to refuse a destination the table prints; no device here is a low-power router, so reception refuses it.

## D-171 · 4.6.3.4.2's "Otherwise" answers the operating state, and Table 4-41 decides the verified-counter bit

**Status:** Decided · **tags:** spec, decision

**Decided: three readings, each where the literal text cannot stand.**
4.6.3.4.2's "Otherwise" clause, which puts a key in the active slot, answers "When in the normal operating state", since read as "not accepted" it would install the key its own "only if" has just refused.
So a normal-state key from anyone but the trust center is refused, a trust-center key replaces the alternate, and the join's key replaces the active one.
A trust-center key re-sent under the active number with the same octets changes nothing, since 4.3.4 lets only APSME-SWITCH-KEY reset that counter.
Table 4-41, which "Sending devices SHALL use", sets the Require Verified Frame Counter bit for an ACK to a datagram, where 4.4.1.1 step 4 a iii names only the datagram.

## D-170 · A link key is held whether it is unique or global, and step 4's replay check follows the type

**Status:** Decided · **tags:** spec, decision

**Decided: a key pair may hold a global link key, and 4.4.1.2 step 4's replay check runs only for a unique one.**
Step 4 (10300-10303) is conditional: "If the apsLinkKeyType of the associated link key is 0x00 (unique) and there is an incoming frame count".
A global key is shared by every device the trust center gave it to, so no per-device window exists.
4.4.1.5 and Table 4-6's Global column need a device holding a preconfigured global key to accept the transport key encrypted with it.
4.5.3's two derived keys come from that key and share its counters.

## D-169 · How this stack reads R23.1's printed contradictions about transported keys

**Status:** Decided · **tags:** spec, decision

**Decided: five self-contradictions in the transport-key text are read as follows.**
Tables 4-6 and 4-7 are consulted by their captions, 4-6 on reception and 4-7 on sending, the cross-references at lines 10352 and 10359 being printing errors.
`apsTrustCenterAddress` starts as the all-F string of 4.6.3.1 and Table 4-35; 4.9.2's all-zero sentence describes the pre-join cache.
`NO_KEY` on NLME-JOIN.confirm follows 3.6.1.6.1.1, the only clause mandating it, carried as Table 3-84's `0xcd` although Table 3-23 does not print it.
`apsSecurityTimeOutPeriod` is held in milliseconds at its ten-second printed default and decremented in whole seconds.
StandardKeyType `0x02` is refused, Table 4-9 reserving it whatever 4.4.11.1.3.3 says.

## D-168 · The APS layer protects with three key identifiers and not with the fourth

**Status:** Decided · **tags:** spec, decision

**Decided: an APSDU is protected with key identifier `00`, `02` or `03`, and `01` is refused with its reason named.**
4.4.1.1 step 1 b) ii sets `00` for every command but the transport key, `02` "when transporting a network key" and `03` when transporting a link key, and 4.4.1.2 obtains material for those three only.
Table 4-39 defines `01` as a network key and 4.2.3 allows APS security on it, yet no APS processing clause reaches it, and 4.5.1.4's key sequence number field exists only for it.
Table 2-2's TxOptions `0x02` is therefore read as a request this stack cannot honour at the APS layer (D-163).

## D-167 · A transmit the seam refuses is a status the network layer re-asks

**Status:** Decided · **tags:** spec, decision, seam

**Decided: a refusal at the seam's transmit call stands for IEEE 7.2.4's `TRANSACTION_OVERFLOW`, and 3.2.1.1.3's unicast retry law runs on it.**
IEEE 7.2.4 confirms a transaction with that status when "there is no capacity to store another transaction", and its MAC never refuses a request.
3.2.1.1.3 retries it like NO_ACK and CHANNEL_ACCESS_FAILURE: up to nwkcUnicastRetries, each attempt delayed by nwkcUnicastRetryDelay.
One law answers refusal and failed completion alike, and an attempt counts as the request issued.
A broadcast's outcome is confirmed at once, 3.6.6 resending it; one refused for room is held (D-243).
Band B names its own lack of room `ZB_ERR_NO_SPACE`, keeping `ZB_ERR_BUSY` for the device's answer.

## D-165 · A frame that started a route discovery is sent when the route appears

**Status:** Decided · **tags:** spec, decision

**Decided: 3.6.4.5.1's "MAY choose to buffer the received frame pending route discovery" is taken as buffering.**
A request with DiscoverRoute 0x01 and no routing entry keeps its composed NPDU in its slot, and the turn a reply leaves that entry ACTIVE issues it over the next hop 3.6.4.3 found.
Table 3-77's RecentActivity and TotalUsageCount move with that use.
A discovery that times out answers Table 3-84's ROUTE_ERROR with the frame unsent.

**Consequences.**
The confirmation is the MAC's answer to an attempt, handle included.

## D-164 · The APS duplicate table records and never expires, because 2.2.8.4.2 prints no interval

**Status:** Decided · **tags:** spec, decision

**Decided: the duplicate table's timing chooses the eviction and nothing else.**
2.2.8.4.2 asks for "at least source address, APS counter, and timing information" and prints no interval after which a duplicate stops being one, so the pair is the key and the time only chooses which record a full pool drops.
The pool is `ZB_LIMIT_APS_DUP`, Table 2-23 printing a floor of one and no ceiling; the key is the NWK source, an APS header carrying no device address.

**Consequences.**
A pair still recorded is a duplicate however long ago it was seen, and the 8-bit counter's wrap can make that a false one; the pool's size bounds the window.
A hit refreshes nothing, so eviction sees first sight and not last.

## D-163 · The APS layer's NWK-security ask follows the network, not the TxOptions

**Status:** Decided · **tags:** spec, decision

**Decided: the carrier's protection is the network's, and Table 2-2's 0x02 is an ask the network answers from its own state.**
4.2.2 gives the NWK the decision and reads the NLDE SecurityEnable parameter as a prohibition only.
`Aps_TxIssue` asks for security whenever `Nwk_Security(nwk)` is enabled, so a link-key APSDU on a network at level 0x05 travels NWK-secured.
A device holding no key material composes the frame unprotected rather than refusing the request.

**Consequences.**
The ask is FALSE only where a hop must be unsecured, the transport key to a joiner (R23.1 4.6.3.2.1).

## D-160 · The transmit PSDU carries its footer, and a firmware that counts it itself is a defect to fix there

**Status:** Decided · **tags:** spec, decision, measured

**Decided: this stack composes the FCS and sends it in the PSDU, and the RCP takes that length as the PHR.**
Upstream Spinel's host sends the PSDU with its FCS, and the Phoscon RCP firmware takes the caller's length as the PHR.
One firmware revision counted the FCS itself, putting two extra octets on the air; it was fixed in the firmware.
Stripping the footer here was not taken, because it makes the host depend on a revision fact the version string does not state.

## D-159 · An MLME-instigated transaction's outcome is MLME-COMM-STATUS

**Status:** Decided · **tags:** spec, decision

**Decided: 10.22.2's two primitives are kept apart.**
A transaction an MLME response started (10.21.5.2's answer) reports SUCCESS, a failure or TRANSACTION_EXPIRED through MLME-COMM-STATUS.indication with the destination the frame named, and owes no MCPS-DATA.confirm.
A transaction a request started keeps the confirm its MsduHandle is matched against.

**Consequences.**
`Mac_Transaction.isMlmeInstigated`, a ring of four and `Mac_PollCommStatus`; `nwk` drains the ring and counts it (`Nwk_CommStatusSeen`).
`test/mac/cases_association.c` asserts both primitives.

## D-158 · A child's two address forms are joined where the association is answered

**Status:** Decided · **tags:** spec, decision

**Decided: the extended and short address pair is learned where 10.21.5.2 names both forms, and nowhere else.**
That answer carries the extended address the request came from and the short address allocated to it, so the transaction queue keeps the pairing.
A poll in either form then finds the transaction, and the pending table can name both.
No frame a device sends carries both forms, so a device that never associated here stays unnamed and its statement is D-157's fallback.

**Consequences.**
`MacIndirect_PairFor` over a pool of `MAC_ADDRESS_PAIR_MAX` (the transaction pool's size); a full pool refuses and counts rather than dropping another device's pair.
`test/mac/cases_association.c` asserts a short-form poll extracting the answer queued under the extended one.

## D-157 · The Ack's Frame Pending bit is the radio's, stated from a table band A writes

**Status:** Decided · **tags:** spec, decision, measured, seam

**Decided: 10.22.3's Frame Pending bit is composed by the RCP from a table band A states, and the statement says whether it is complete.**
The RCP composes the Ack, so the host cannot set the bit.
The table names every device a frame waits for, in both forms this MAC knows (D-158).
A statement it cannot complete, a held device's other form unknown or a list full, clears the enable bit: every Ack then claims pending, 10.22.3's answer for a coordinator that cannot know.
An empty complete table means nothing is pending.

**Consequences.**
The seam carries `Radio_Ops.pendingTable` and `Radio_Pending.isComplete`; band B writes the three properties as one statement at adoption, on every queue move and after a reset (`docs/internals/protocol.md` §7.4.5).

## D-156 · Table 3-51's rows bind the frame this layer generates, not the one it receives

**Status:** Decided · **tags:** spec, decision, measured

**Decided: a source-routed NPDU this layer generates carries Discover Route 00, and one that arrives carrying 01 is read.**
Table 3-51's Source routed row prints 00, and the frame control field is the transmitter's to set.
Real networks send 01 on source-routed frames, and refusing that on reception lost them.
The Broadcast row is treated the same: a sleepy end device's Device_annce arrives as a broadcast carrying 01.

**Consequences.**
`nwkFrameTransmit` refuses the configuration and `nwkFrameClaim` does not, so a received frame is not lost to a field its sender chose.
A reserved destination follows the same shape, refused only on what this layer sends.

## D-155 · An Association Request keeps two PAN fields even when they would be equal

**Status:** Decided · **tags:** spec, decision

**Decided: 10.21.5.1 outranks 7.2.2.6's compression bullet.**
7.2.2.6 says that with both addresses present and the two PAN identifiers equal, the compression field "shall be set to one"; 10.21.5.1 says the source PAN ID "shall contain the broadcast PAN ID".
The two collide when the destination is the broadcast PAN, and a receiver reading a compressed source PAN takes the PAN it is joining rather than the joiner's.

**Consequences.**
`macPanCompressed` keeps the source PAN for an Association Request, so the frame carries `ffff` twice where the two coincide, which every receiver accepts.

## D-154 · The association permit's effect is the indication, and the answer's status is the profile's

**Status:** Decided · **tags:** spec, decision

**Decided: a coordinator whose macAssociationPermit is FALSE still indicates an Association Request upward, and the answer carries PAN_ACCESS_DENIED.**
802.15.4 10.21.2 says such a coordinator "shall ignore" the command; R23.1 3.6.1.6.1.3 says it "SHALL issue MLME-ASSOCIATE.response with a status of 0x02, PAN_ACCESS_DENIED".
This stack runs the profile, so the permit decides the answer's status, not whether the MAC hands the request up.

**Consequences.**
`mac_rx` hands the request up whatever the permit says, and the counters count only the association handler's own refusals.

## D-152 · A transaction is confirmed on completion, and an attempt's failure is reported so the layer above can act

**Status:** Decided · **tags:** spec, decision, open

**Decided: a failed extraction is confirmed with the seam's refusal and the transaction survives it; the completion, SUCCESS or TRANSACTION_EXPIRED, is confirmed under the same MsduHandle.**
10.22.2 names one indication per completion and says nothing of the attempts before it.
The layer above keys its retry law on the handle, and a silent failure would leave it waiting for an expiry.
Open: a single outcome that still tells the layer above to retry.

**Consequences.**
One handle can carry more than one confirmation, and `test/mac/cases_indirect.c` asserts both.

## D-151 · A poll arriving while an extraction is on the air is answered with nothing

**Status:** Decided · **tags:** spec, decision

**Decided: while a transaction's extraction is unacknowledged, a Data Request from that device is counted unanswered and no second frame is issued.**
6.6.3.4 forbids the coordinator to retransmit an indirect frame, and 10.22.3 asks it to send the pending frame; silence is the composition of the two, bounded by the seam's completion.

**Consequences.**
`pollsUnanswered` counts it, so a device polling faster than the radio answers is visible.
A backend that never reports a completion extends the window to `MAC_COMPLETION_TIMEOUT_MS` on every attempt.

## D-150 · A document states this stack's behaviour and locates the rule, and never restates it

**Status:** Decided · **tags:** mandate

**Decided: no document paraphrases or quotes a clause of a standard.**
A document states what this stack does and locates the rule by clause and page; the clause's content is the standard's.
Where a rule had only ever been restated, the restatement was often wrong, and code was written from it.
A quotation survives only in a decision that shows the sentences it composes.

**Consequences.**
Each `docs/internals/conformance.md` row carries a page locator, and `docs_audit` counts the rows still without one.
The rule for comments is in `docs/internals/coding-rules.md` §6, which cites this entry.

## D-149 · The reaction to a pending address runs as macAutoRequest TRUE

**Status:** Decided · **tags:** spec, decision, open

**Decided: a beacon whose Address List names this device makes the MAC send a Data Request unconditionally, Table 8-36's `macAutoRequest` default.**
10.22.3 conditions the reaction on "macAutoRequest is TRUE", and Table 8-36 prints TRUE as the default.
The attribute is not exposed, so the default is what runs; open: a surface that would set it.

**Consequences.**
The poll is a frame the MAC sends on its own account, counted where its answer was missed, and it owes the layer above no confirmation (8.3.5).

## D-148 · The poll a beacon owes is addressed to that beacon's own source

**Status:** Decided · **tags:** spec, decision

**Decided: the Data Request 10.22.3 owes is addressed to the coordinator the beacon came from, with that beacon's addressing mode, PAN and address.**
10.22.4.1 sets the destination "according to the coordinator to which the Data Request command is directed", and the mode "according to the value of macCoordShortAddress".
This stack holds no `macCoordShortAddress`, and a beacon's own source is the coordinator it came from.
R23.1 Annex D.4's request table prints the addressed row first, and only an addressed frame can be acknowledged by a hardware address filter.

## D-147 · The indication carries the fields this stack has, and names the ones it does not

**Status:** Decided · **tags:** spec, decision

**Decided: Table 8-32's parameters are delivered where this stack holds them, and the absent ones are named in `docs/internals/conformance.md`.**
Delivered: both addressing modes with addresses and PANs, the Msdu, MpduLinkQuality, the timestamp, FramePending and the frame version.
Absent: HeaderIeList and PayloadIeList, AckSent (the radio's, reported by no seam operation), DataRate and EmptyPayload (PHR facts the seam does not carry), RangingReportDescriptor and the security parameters.

**Consequences.**
`Rssi` is `rssiDbm`, the signed dBm the seam reports, not the table's 0x00-0xff scale.

## D-146 · A device that is not a coordinator answers a Data Request with 10.22.3's empty frame

**Status:** Decided · **tags:** spec, decision, open

**Decided: any device that receives a Data Request answers it, with a queued transaction or 10.22.3's empty frame, whether or not it is a coordinator.**
10.22.3 gives the duty to a coordinator, and no clause says what a non-coordinator does with a Data Request it receives.
The answer states a true thing either way, and dropping it would leave the asker waiting out `macResponseWaitTime`.
Open: a non-coordinator's duty.

**Consequences.**
`pollsUnanswered` counts a poll whose answer could not be composed, never one from a device with an empty queue.

## D-145 · Promiscuous mode is a listener's mode, and 10.23.1's receiver request is deferred

**Status:** Decided · **tags:** spec, decision, open

**Decided: `macPromiscuousMode` is Table 10-114's attribute, default FALSE; when TRUE the interest tests are bypassed and the duties and refusals still apply.**
10.23.1 has the MAC "process received frames according to 6.6.2 and pass all frames correctly received": the FCS and reserved-value rules still decide what is correct, c) to e) stop being interest tests, and the duties still run.
The MLME asking the PHY to enable and restore its receiver is deferred, no seam operation carrying it; a promiscuous MAC is a listener, not a deployment.

**Consequences.**
An indication in this mode has the Msdu, link quality, timestamp and RSSI as its valid parameters.

## D-143 · The first-level filter is the MAC's own, and a received beacon is its own event

**Status:** Decided · **tags:** spec, decision, measured

**Decided: every received frame passes 6.6.2's first-level filter in the MAC whatever the radio hands up, and a beacon is reported as its own event with the body parsed.**
`macPromiscuousMode` defaults to FALSE (Table 10-114), so 6.6.2's filter is the MAC's duty.
The AT86RF233 build is armed promiscuous and its treatment of a foreign destination PAN is unmeasured, so the filter is not delegated to the RCP.
8.2.4.3 owes a received beacon `MLME-BEACON-NOTIFY.indication`, and the indication ring is this stack's primitive surface.

**Consequences.**
A foreign PAN's traffic is dropped with a count, each refusal counted under the reason that refused it.
The mode is D-145's.

## D-142 · The association extraction starts where macResponseWaitTime ends, and a second window bounds the answer

**Status:** Decided · **tags:** spec, decision, open

**Decided: the extraction starts one `macResponseWaitTime` after the acknowledgment, repeats while nothing has arrived, and concludes `NO_DATA` at the end of a second window.**
10.21.2 requires a wait of "at most macResponseWaitTime" for the coordinator's decision and an extraction "after macResponseWaitTime", then `NO_DATA` where no response arrives "within macResponseWaitTime".
An extraction permitted only after the deadline cannot meet a deadline already past, so one wait bounds the decision and a second the extraction.
Open: whether the second window should be one further `macResponseWaitTime`.

**Consequences.**
A join needing the whole decision time takes two windows.

## D-139 · An entry is a decision and its consequences, in a fixed shape at a cap

**Status:** Decided · **tags:** mandate

**Decided: a register entry carries a status, what was decided and what follows from it, in at most 150 words.**
The shape is the same every time, so a reader finds the decision without reading the entry.
The option weighed and dropped and the run that forced a change are not decisions; the commit carries them.

**Consequences.**
An entry over the cap fails `docs_audit`.

## D-135 · A deferral is stated where it is returned, and a gate reads it

**Status:** Decided · **tags:** mandate

**Decided: a band-A function answering `ZB_ERR_UNSUPPORTED` says why in one line, naming the document that owns the deferral, and `comment_audit` fails a refusal that says nothing.**
A per-clause table in a doc-comment would break `docs/internals/coding-rules.md` §6's comment rules, and one line naming the owning document fits them.

## D-134 · The counters are one snapshot, and it says when it was read

**Status:** Decided · **tags:** api

**Decided: the MAC's counters and queue depths are one `Mac_Counters` record returned by value, not one getter each.**
Read one at a time, those numbers can straddle a step, and the suites read several of them at one moment.
One record is one moment, and the snapshot states which.

## D-132 · A count a tool prints is not a claim a document makes

**Status:** Decided · **tags:** mandate

**Decided: a document states what a suite proves, never how many cases or assertions it took, and `docs_audit` fails a count a gate already prints.**
`test/suite_ledger.py` prints the case list and the assertion count, `ctest -N` the registered names, and the audits their own counts.
A document retyping one of those is a second copy of machine output kept current by hand.

## D-128 · Stochastic address assignment is a seeded draw over 1..0xfff7

**Status:** Decided · **tags:** spec, decision

**Decided: 3.6.1.8's assignment is a seeded xorshift32 draw over 0x0001..0xfff7, rejected against the NIB's addresses, the address map and this device's own, with the coordinator's 0x0000 never allocated and no address after 64 draws.**
3.6.1.8 makes the address random and non-conflicting ("its parent SHALL choose a random address that does not already appear in any entry in the parent's NIB").
No address after `NWK_JOIN_ADDRESS_TRIES` is the capacity answer 3.6.1.6.1.3 gives.

## D-125 · A frame that names this device as its source is not an arrival

**Status:** Decided · **tags:** decision

**Decided: a delivered frame whose MAC source address is this device's own is consumed before any classification, counted as `selfEchoes`, and handed to no layer above.**
6.6.1 makes the source address the transmitter's, so such a frame cannot have come from anybody else, and a radio does not receive what it transmits.
No indication, no poll detection and no answer follow.

## D-124 · An energy-scan dwell is a dialogue over time, so the seam issues it and collects it

**Status:** Decided · **tags:** seam, measured

**Decided: the seam carries a dwell as a pair, `scanStart` issuing one dwell in the device's own units and `scanCollect` reporting the level or NOT_READY.**
No RCP dialect can be asked for a band in one synchronous call: `SET MAC_SCAN_STATE = 2` starts one dwell on one channel, refuses a second, and reports the level and the end as two notifications.
A period of 200 occupies 343-505 host ms and 1000 occupies 2128 ms, so a synchronous call would pump the link for seconds inside the stack's turn, where band A's deadlines are judged against the caller's `nowMs`.
`scanStart` refuses a period outside the printed bound rather than leaning on the RCP's clamp.

## D-123 · A dialect is what it answers, not what it is called

**Status:** Decided · **tags:** decision, measured

**Decided: an RCP dialect is a fingerprint of what the device answers, and a capability is discovered rather than assumed.**
One build answers `DSPINEL/1.0; AT86RF233` at every revision measured, and its property table moved under that unchanged name: `RADIO_CAPS` went from `0x10d` to `0x10f`, and the scan group from `PROP_NOT_FOUND` to answered (`docs/internals/hardware.md` §3).
No vendor build has been measured, so the table cannot be tied to the name.

## D-122 · A report is band A's input and never its output

**Status:** Decided · **tags:** seam, measured

**Decided: the PIB mask band A adopted from `Radio_GetPib` and the mask it may write with `Radio_SetPib` are separate.**
`Radio_GetPib` says what the device holds and `Radio_SetPib` asks it to hold what a mask names.
Adopting the report whole, `RADIO_PIB_HW_ADDRESS` included, and handing it back as a request on recovery made every re-application fail against band B, which refuses that field.
The MAC then composed from a device holding the defaults its own re-arm had left, and `pibReapplications` never moved.

## D-121 · A seam call is one unit, so the backend's write queue must hold a whole one

**Status:** Decided · **tags:** seam, measured

**Decided: band B's property write queue is sized from the seam's PIB fields that a dialect maps to a write, so the largest `Radio_SetPib` call fits whole.**
`Radio_SetPib` is one call over a mask of any size the seam allows, and band B expands it into one property write per mapped field: four on the OpenThread table and six on the DSPINEL one.
A queue bound derived from nothing refused the largest call `ZB_ERR_NO_SPACE` whole, before a byte reached the link.

**Consequences.**
`RCP_RADIO_WRITE_QUEUE_MAX` is 6, and grows with the largest dialect's mapped fields.

## D-119 · The send half is checked against on-air captures

**Status:** Decided · **tags:** mandate, measured

**Decided: the known answer for a composed NSDU is an on-air capture, the `loopback_ch26_tx_*` fixtures, never the codec's own output.**
A codec that composes and dissects with one source cannot disagree with itself.
The RCP regenerates the footer, so the two footer octets are the device's own, and the peer's received copy is the authority where the host amended them.

## D-118 · The route reply's path cost is added once per hop, at receipt

**Status:** Decided · **tags:** spec, decision

**Decided: a forwarder adds the cost of the link the reply arrived over, once, before judging it against Table 3-79's residual cost.**
3.6.4.5.2 (9225-9228) adds the cost of the hop just crossed; 3.6.4.5.2.1 (9265-9269) adds the cost of the hop about to be crossed.
Executing both would count each link twice, against 3.6.4.1's `C(P) = min(Σ αᵢ·C(Dᵢ,Dᵢ₊₁), 0xff)`, which has one term per hop.
The responder starts the field at the cost of the link to the device it answers (9210), and the forwarded reply carries the sum with its cost octet alone rewritten (D-99(iii)).
3.6.4.5.2.1's sentence is the same addition seen from the sender and is not performed again.
The clamp at 0xff follows D-92(b).

## D-117 · `nwkStatus`'s 0xff is a house sentinel, and Table 3-84 prints no such value

**Status:** Decided · **tags:** spec, decision

**Decided: `NWK_STATUS_LAST_MAC_STATUS` 0xff in `Nwk_DataConfirmParameters.nwkStatus` means no printed code names the outcome, and `status` carries the MAC's status underneath.**
Table 3-84 prints no row at all from 0xd8 on, so a confirm whose outcome no code names has no printed value to carry.
`Nwk_TxConfirmStatus` answers 0xcc, 0xcd or 0xce where the security crossing named one and the sentinel where it did not (D-72).
The value is a word between two layers of this build and never reaches the air: a Network Status frame carries Table 3-56's code.

## D-116 · What a received Network Status removes, and where "my child" comes from

**Status:** Decided · **tags:** spec, decision

**Decided: a removal 3.6.4.8.1 orders is a deletion of the routing-table entry, and "my child" is Table 3-75's relationship field.**
3.6.4.8.1 prints receipt rules for a router that is the destination of a 0x01 or 0x02 (9392-9395), a router relaying one to its end-device child (9361-9365, 9397-9400), and an end device, which informs the next higher layer through NLME-NWK-STATUS.indication (9401-9402).
"Remove" is the clause's own word, so the entry is deleted rather than marked.
No frame states the parent relationship, so the neighbour table's relationship field is the only source.

## D-115 · Annex I.2.3's command-scoped local tags, and four readings

**Status:** Decided · **tags:** spec, decision

**Decided: the Annex I TLV walk is told the command whose payload it reads and interprets a local tag id only where that command's clause defines it.**
I.1.2 and I.2.3 make a local tag id specific to one message: K.2.1's three for a request, tag 0 alone for the reply and the network status.
Any other tag is an Unknown Tag and is skipped, and a length that runs past the payload is malformed whatever the id.
**(a)** A reserved value of a field in use is refused on receipt, 1.4.2 being about reserved fields.
**(b)** The NSDU ceiling is Table 3-2's 108.
**(c)** A relay index starts uninitialised.
**(d)** The LQA octet belongs to the frame that carried it.

## D-114 · The send side: an untrackable broadcast, the schedule pools, and whose duty a sleepy copy is

**Status:** Decided · **tags:** spec, decision

**Decided: a broadcast this device originates is refused with Table 3-84's `BT_TABLE_FULL` 0xd2 when Table 3-81 has no room, and the route request retry schedule is a pool keyed by Table 3-79's (destination, request id) pair.**
3.6.6's passive acknowledgement needs a record to be judged against, so the record is claimed before the frame is issued, for `nwkNetworkBroadcastDeliveryTime`.
`FRAME_NOT_BUFFERED` 0xd3 answers a request the pools cannot hold (Table 3-3).
3.6.4.5.1 (9072-9075) gives the retry count to the initiation, and 3.6.4.3 makes a second destination a discovery of its own.
3.2.1.1.3's three retried statuses are the law, and a sleepy neighbour's copy is the parent's duty, not the originator's.

## D-112 · A reserved field is zeroed on transmission and judged on receipt by nothing (1.4.2)

**Status:** Decided · **tags:** spec, decision

**Decided: chapter 3's reserved fields are never set on transmission and never checked on receipt.**
1.4.2 has products zero reserved fields and "make no further assumptions about these fields nor perform processing based on their content", so refusing a frame on them is such processing.
This covers Figure 3-5's frame-control bits 14-15, Figure 3-10's option bits 0-2 and 7, and Figure 3-12's option bits 0-3 and 7.
Chapter 2 prints the opposite for its own frames (2.2.5), so the two layers differ, each on its own sentence.
Protocol version checks stay, since 1.4.2 prints that discard.
A reserved value of a field in use, such as Table 3-53's `0x02, 0x03` or Table 3-55's many-to-one `3`, is not a reserved field and stays a refusal on receipt.

## D-111 · 3.6.1.10.5's 0x0e verification is not built

**Status:** Open · **tags:** spec, open

**Decided: the 0x0e address verification of 3.6.1.10.5 is the one arc of this group not built.**
Many-to-one routing, route repair, the mesh backbone, joining, the transport key and address conflict resolution are built (`docs/status.md`).

## D-110 · Table 3-78's two unused statuses get their writers

**Status:** Decided · **tags:** spec, decision

**Decided: `INACTIVE` is written by 3.6.4.8.1's invalidation, and `DISCOVERY_FAILED` where a discovery's timer ends while 3.6.4.5.1.7's deletion does not apply.**
`INACTIVE` (0x3) marks every entry whose next hop is a broken link, whether it failed under a forwarded frame or under a retired outgoing cost (D-106); the entry keeps its fields, the clause saying invalidate, not delete.
3.6.4.3 takes an ACTIVE entry only, so an inactive one is not chosen.
`DISCOVERY_FAILED` (0x2) applies when another Table 3-79 entry for the same destination is still live, so the routing entry survives and records the attempt that ended.
The last expiry deletes the entry, `DISCOVERY_FAILED` included, by 3.6.4.5.6's "any Status field value other than ACTIVE".

## D-109 · Passive acknowledgement is a mark on the record, and only a relayed broadcast has one

**Status:** Decided · **tags:** spec, decision

**Decided: the Table 3-81 record carries a mark for each neighbour that has relayed the broadcast, and 3.6.6's passive-acknowledgement branch runs on it.**
3.6.6 prints two branches: without passive acknowledgement a device retransmits "exactly nwkMaxBroadcastRetries times", and with it only while a neighbour "has not relayed the broadcast frame within nwkPassiveAckTimeout".

## D-108 · α is one, and it is a value and not a field

**Status:** Decided · **tags:** spec, decision, open

**Decided: Table 3-69's `InterfaceLinkCostScalar` is its printed default 1, so `Nwk_CostAccumulate` adds the link cost unscaled.**
3.6.4.1's C(P) is `min(Σ αᵢ·C(Dᵢ,Dᵢ₊₁), 0xff)`, with an α per interface, and this stack models one interface (D-98).
A configuration field nothing sets, or a multiplication by a constant 1, would document nothing.
Open: a second interface, where each link's contribution is scaled in `Nwk_CostAccumulate`'s caller, together with `nwkMacInterfaceTable` and `INVALID_INTERFACE` (D-98).

## D-106 · Ageing in Table 3-75's unit, and what a retired outgoing cost means for a route

**Status:** Decided · **tags:** spec, decision

**Decided: a neighbour entry's age is a count of 15 s `nwkLinkStatusPeriod` intervals since it was last refreshed, and past `nwkRouterAgeLimit` its outgoing cost goes to 0 and the routes through it become `INACTIVE`.**
Table 3-75 prints `Age` in nwkLinkStatusPeriod intervals, so the entry carries a tick count and not a stamp.
Any frame from the device refreshes the entry (3.6.1.7), so the count returns to 0 and the link is measured again, the reuse 3.6.4.4.4 permits.
An entry no frame has ever stamped is not aged, so a neighbour table seeded by configuration does not decay from the epoch.
A link with no measurement left is a failed link, so 3.6.4.8.1's invalidation follows; otherwise a route could still point at a stale link.

## D-105 · `LoopFree`'s operands, and the two places its answer decides

**Status:** Decided · **tags:** spec, decision

**Decided: in 3.6.4.5.3's `LoopFree(R1, R2)`, R1 is the advertised route and R2 the local route, and `path-cost(R2)` is read from Table 3-79's residual cost.**
Step (i) fixes the arguments as `LoopFree(advertised route, local route)`; FALSE means the advertisement is ignored (9300-9301), and 9139, 9168, 9248 and 9256 repeat the test inside the two receive procedures.
`path-cost(R2)` has no printed source: Table 3-77 carries no path cost, so a local route's cost lives only where the path was recorded.

## D-104 · One discovery per destination, and the timer confirms by Table 3-79's request id

**Status:** Decided · **tags:** spec, decision

**Decided: a second frame for a destination whose discovery is running waits on that discovery, and a waiting frame is answered by the timer of the request id it waits on.**
3.6.4.3 has a frame treated "as though route discovery has been initiated for this frame" when this device already initiated it, so no second request id, Table 3-79 slot or broadcast schedule is made.
3.6.4.5.1.7 says what the timer deletes and not which waiting frame it answers.
Answering every waiting request for the destination would fail one discovery's requests with another's timer, so the timer, 3.6.4.5.2's release and the schedule are keyed by Table 3-79's pair.
Two frames that joined one discovery are answered together, once.

## D-103 · A received relay count is bounded by its own frame, and Table 3-51's broadcast row refuses `Discover Route 0x01` at the codec

**Status:** Decided · **tags:** spec, decision

**Decided: a received relay count is bounded by the frame, 58 relays, and `nwkMaxSourceRoute` bounds only the routes this device writes.**
3.3.1.8.1 prints no ceiling on the received value, so the ceiling is what the NPDU's 116 octets leave after the eight always-present header octets and the two route-control octets.
`nwkMaxSourceRoute` (NIB 0x93, default 0x0c) is the most this device writes into a route of its own.
Table 3-51's broadcast row refuses `Discover Route 0x01` on what this device sends (D-156).

## D-102 · 3.6.2.3's lost-child mark is re-evaluated on the window the clause prints

**Status:** Decided · **tags:** spec, decision, open

**Decided: a neighbour marked 0x07 by 3.6.2.3 is deleted if still marked one second later, the clause's own example.**
3.6.2.3 has the NLME evaluate the entry after the APS layer has processed the message and delete it if the field is still 0x07.
This layer has no "APS has processed it" signal, so the evaluation is a timer (`NWK_LOST_CHILD_EVALUATION_MS`) rather than a callback.
A mark nothing clears inside the window is deleted, the outcome the clause prints for a stack that found no address conflict.
Open: the other outcome, a conflict resolved into 0x08, has no writer.

## D-101 · 3.6.13's "unsupported" is every Table 3-54 identifier this layer does not process, and the reply is Figure 3-61's three octets

**Status:** Decided · **tags:** spec, decision

**Decided: a unicast NWK command for this device whose identifier this layer does not process is answered with a Network Status of 0x13, Unknown Command, in Figure 3-61's three octets carrying the offending identifier.**
3.6.13 orders the answer "whenever an unknown or unsupported unicast NWK command is received", and recognition and support are two different answers.
An identifier Table 3-54 prints but this layer does not process is therefore unsupported.

## D-99 · A relayed Route Request keeps its originator's fields and repeats at the request's own interval

**Status:** Decided · **tags:** spec, decision

**Decided: a relayed Route Request changes only its radius and path cost, repeats at `nwkcRREQRetryInterval`, is judged against Table 3-79 before Table 3-81, and carries both commands' Annex K tails octet for octet.**
3.6.4.5.1.4 prints a relay count and no interval, so the relay repeats at `nwkcRREQRetryInterval` (Table 3-65: 254 ms), the interval of the schedule it belongs to.
A relayed copy keeps its initiator's source, source IEEE and sequence number, so the broadcast table would discard every further copy of one request before 3.6.4.5.1.2's own dedup could take the cheaper path.

## D-98 · One MAC interface: `nwkMacInterfaceTable` is not modelled

**Status:** Decided · **tags:** spec, decision, open

**Decided: the stack models one MAC interface and no `nwkMacInterfaceTable`, so `INVALID_INTERFACE` is a status no path composes.**
3.2.1.1.3's next-hop path selects an interface out of Table 3-69 and answers `INVALID_INTERFACE` where it is not enabled; with one MCPS/MLME pair there is nothing to select.
3.6.6's Trusted Link rule has no interface type to test either.
The one interface is index 0 at α = 1, so 3.6.4.1's `min(Σ αᵢ·C, 0xff)` runs as its special case and no advertised path cost is scaled.
Open: whether a second interface arrives, and what a caller would hand one.

## D-97 · `SecurityEnable` at level 0 is refused, not ignored

**Status:** Decided · **tags:** spec, decision

**Decided: a request asking for security at a device whose `nwkSecurityLevel` is 0 is refused with `ZB_ERR_UNSUPPORTED`, counted, not sent, and owed no confirmation (D-87).**
Table 3-2 says the parameter "will be ignored" at level 0, while 4.2.2 conditions the frame-protection mechanism on it.
4.2.2 is the more specific, because it names the mechanism the parameter chooses between.
Honouring the table would put on the air a frame the caller asked to have protected.
The cost: a caller that follows the table finds out through the refusal rather than through a peer that receives plaintext.

## D-94 · Who initiates a route discovery, when it gives up, and what the request is told

**Status:** Decided · **tags:** spec, decision

**Decided: discovery starts from an NLDE-DATA.request with `DiscoverRoute` 0x01 and no routing entry; the NLME-ROUTE-DISCOVERY primitive (3.6.4.5.1 case 1) is not built.**
A device with no routing duty answers 3.6.4.3's ROUTE_ERROR, the one status Table 3-84 offers a frame with no path.
9047-9054's three-way choice is applied: an ACTIVE entry keeps its status, any other is reused as DISCOVERY_UNDERWAY, otherwise `Nwk_RouteClaim` evicts by 3.6.4.8.
`routeRequestId` and `nwkRoutingSequenceNumber` increment per composition, and the TLV carries the value after the increment.
A refused payload moves neither, and `Zb_State` restores the routing sequence number forward only.

## D-92 · Route discovery's reception, the worse direction, and the Route Reply's octets

**Status:** Decided · **tags:** spec, decision

**Decided: only the destination, or its proxy for an end-device child, answers a Route Request.**
9142-9147's instruction that a forwarder also reply is irreconcilable with 3.6.4.5.1.1 and would flood a mesh with one reply per relay; `NWK_RREQ_RX_FORWARDER_REPLY` names that answer and is never produced.
The path cost grows by the maximum of the link's incoming and outgoing costs (9122-9124), clamped at 0xff by 3.6.4.1's `C(P) = min(Σ αᵢ·C, 0xff)`.
The dedup drops only a path cost greater than Table 3-79's forward cost, so an equal cost updates the entry.
The transmitting device's address arrives beside the frame, not from the header.

## D-91 · Route discovery's table, its sizes, and the Route Request's octets

**Status:** Decided · **tags:** spec, decision

**Decided: Table 3-79 is a pool of `NWK_DISCOVERY_MAX` = 8 entries keyed on (source address, route request ID), and a full pool refuses and counts.**
Table 3-79 has no NIB attribute and no printed size.
Its reuse rule is the one 3.6.4.2 prints for this table alone, so a claim recycles the entry that expires first and never evicts a live one.
Expiry is stored as a deadline, `nwkcRouteDiscoveryTime` being 10 s (Table 3-65).
The Extended Route Information TLV is mandatory on compose and optional on parse (K.2.1.1), since earlier revisions do not carry it.

## D-90 · One security object, two crossings

**Status:** Decided · **tags:** api, decision

**Decided: the façade takes one `Security_Config` and attaches it to NWK and APS: one key material set, 4.3.1 protecting the NWK frame and 4.4.1 the APSDU.**
The combination this cannot express is APS security on with the NWK crossing off.
No case needs it, and a device on a real network cannot want it, since 3.6.2.2 discards every unsecured frame at a joined and authenticated peer.
Expressing it would take a per-layer attach, which is not built.

## D-89 · The acknowledgement's NWK frame takes the device's own crossing

**Status:** Decided · **tags:** spec, decision

**Decided: an owed APS acknowledgement is carried in an NWK frame secured as any frame the device sends, while its APSDU stays the plain acknowledgement.**
An acknowledgement sent with `securityEnable` 0 is discarded by a peer at level 0x05 at 3.6.2.2's unsecured gate, and acknowledged transfer between two secured devices would then run into NO_ACK.
The acknowledgement is both things at once, one per layer.

## D-87 · A door refusal is not a confirmation

**Status:** Decided · **tags:** decision

**Decided: a request refused at the door, including one the codec refuses, owes no confirmation.**
A retransmission the layer below refused for a full pool keeps its wait and its attempt count.

## D-86 · A non-unicast acknowledgement and a group-mode command are refused

**Status:** Decided · **tags:** spec

**Decided: a non-unicast acknowledgement and a command frame in group mode are refused as forms.**
Figures 2-8 and 2-9 with 2.2.8.4.3 and 4.4.11 rule 2 leave no form for either.

## D-85 · Table 2-2's `nwkBroadcastAddress` band is deliberately wider

**Status:** Decided · **tags:** spec, decision

**Decided: the APS door accepts Table 2-2's `nwkBroadcastAddress` band, wider than Table 3-80's classes, and refuses its Reserved half.**
The two tables disagree, and the disagreement is kept one layer apart by design.

## D-84 · The re-protect-per-issue rule travels to APS

**Status:** Decided · **tags:** spec, decision

**Decided: an APS retransmission is re-protected at each issue, as D-53(i) does for NWK.**
4.4.1.2 step 4 would refuse a repeated frame counter, so the rule extends beyond the NWK text where it is printed.

## D-83 · The owed acknowledgement precedes the queued delivery

**Status:** Decided · **tags:** spec, decision

**Decided: the owed APS acknowledgement goes out before the delivery is queued.**
This is the stack's reading of "commence".

## D-82 · An acknowledgement of a secured data frame stays unsecured at APS

**Status:** Decided · **tags:** spec, decision

**Decided: the APSDU of an acknowledgement to a secured data frame is not APS-secured.**
The specification prints no secured acknowledgement form.
Its NWK frame is secured as D-89 states.

## D-81 · Acknowledgement matching compares only what the acknowledgement repeats

**Status:** Decided · **tags:** spec, decision

**Decided: an acknowledgement is matched on exactly the fields 2.2.5.2.3.1 prints it repeating.**
The profile identifier and the acknowledgement's own destination endpoint are deliberately not compared.

## D-80 · A frame the security crossing refused is not deduplicated

**Status:** Decided · **tags:** spec, decision

**Decided: a frame the security crossing refused neither consults the duplicate table nor enters it, and a deferred frame is not recorded either.**
The table's subject is a frame passed up previously.
Replays of a refused frame therefore land in the security counters again.

## D-79 · A duplicate hit answers before the pool is written

**Status:** Decided · **tags:** spec, decision

**Decided: a duplicate hit answers before the duplicate pool is written and refreshes nothing, not even the record it hit (2.2.8.4.2).**

## D-78 · Any convenient group-table order; only the fan-out is fixed

**Status:** Decided · **tags:** spec, decision

**Decided: group delivery walks the group table in pool order, one indication per member.**
2.2.8.3.1 licenses any convenient order, so only the fan-out is fixed.

## D-77 · The indication ring is sized to `NsduLength`'s ceiling

**Status:** Decided · **tags:** spec, decision

**Decided: the NWK indication ring holds 108 payload octets and refuses beyond them.**
Table 3-4 bounds `NsduLength` at aMaxPHYPacketSize − (nwkcMACFrameOverhead + nwkcMinHeaderOverhead) = 127 − (0x0b + 0x08) = 108, the same ceiling as 3.2.1.1.1's request.
Chapter 3 prints no rule refusing a received frame beyond it; the MAC's 127-octet PSDU is what makes one impossible to receive.

## D-76 · A frame with a version or multicast bit is refused even in relay

**Status:** Decided · **tags:** spec, decision

**Decided: a frame carrying a protocol version or a multicast bit this codec never writes is refused, even when the device would merely relay it.**
The version half is the codec's: `NwkFrame_Parse` answers `ZB_ERR_UNSUPPORTED`, counted as `droppedUnsupported`.
The multicast half is the receive path's, because a codec answers one status, not two: `nwk` refuses bit 8 before any gate reads the destination, a group id there (3.3.1.2), and counts `Nwk_DroppedMulticast`.
The codec still parses such a frame to its payload boundary and reports the sub-field.

## D-75 · An address outside Table 3-75's range is none at all

**Status:** Decided · **tags:** spec, decision

**Decided: an address outside Table 3-75's range is treated as no device address at all.**
10.22.4.1 reads such a value as extended.

## D-74 · Xorshift32 must not be seeded at 0

**Status:** Decided · **tags:** decision

**Decided: the seeding of the xorshift32 generator never lands on 0.**
0 is the generator's only fixed point, so a state at 0 stays there.

## D-73 · 3.6.13 step 5 prints no SecurityEnable

**Status:** Decided · **tags:** spec, decision

**Decided: the Network Status reply this device originates under 3.6.13 carries the device's own security (4.2.2).**
Step 5 prints no SecurityEnable.

## D-72 · The last-confirm-status bound is not a printed code

**Status:** Decided · **tags:** spec, decision

**Decided: the last-confirm-status bound is not a printed code.**
It is 3.2.1.1.3 handing the last word on a confirm's status to the MAC at the seam.

## D-71 · A device does not hand a frame to itself

**Status:** Decided · **tags:** spec, decision

**Decided: the door refuses a request whose destination is the device itself, as band A's own rule.**
R23.1 prints no case of a device handing a frame to itself.

## D-70 · A broadcast this device originated is not one it processes

**Status:** Decided · **tags:** spec, decision

**Decided: a device does not process a broadcast it originated.**
3.6.6's warm-up gate needs a clock band A does not keep for it.

## D-69 · Table 3-84 has no code for an over-ceiling secured frame

**Status:** Decided · **tags:** spec, decision

**Decided: a secured frame over the band's ceiling is not answered 0xd3.**
Table 3-84 prints no code for it, and 0xd3 is a pool's answer, not a length's.

## D-68 · 3.4.3.2's source-IEEE rule is deliberately not honoured

**Status:** Decided · **tags:** spec, decision

**Decided: 3.4.3.2's source-IEEE rule is deliberately not honoured, while its destination-IEEE half is honoured from a neighbour entry.**
No radius rule is printed for a Network Status frame, so the reply carries the network default.

## D-67 · 3.6.2.3 steps 4 and 5: which entry a broadcast marks

**Status:** Decided · **tags:** spec, decision

**Decided: step 4 leaves a fresh broadcast examinable, and step 5 marks the entry keyed on the NWK source, not the MAC carrier.**

## D-66 · 3.6.2.2's unsecured carve-out applies only to a frame for this device

**Status:** Decided · **tags:** spec, decision

**Decided: the unsecured rejoin carve-out admits a frame only when its destination is this device's own address.**
3.6.2.2's "otherwise the frame SHALL be dropped" closes the command sentence, and "destined to itself" excludes a broadcast the device would merely relay.
An unsecured rejoin request on any Table 3-80 class is discarded, claims no broadcast record, is indicated to nobody and relayed nowhere.
The `nwk` suite's `caseUnsecuredRejoinOnABroadcastIsDropped` proves it, beside the same frame addressed to the device, which is admitted.

## D-65 · An operating Zigbee router is named, not modelled

**Status:** Decided · **tags:** spec, decision

**Decided: a router of this stack is a router from init; "operating Zigbee router" is not a separate state.**

## D-64 · `TxTime` is absent

**Status:** Decided · **tags:** spec, decision

**Decided: the confirms carry no `TxTime`.**
Band A has no wall clock behind `nwkTimeStamp`.

## D-63 · The NLDE handle is the transmit the request became

**Status:** Decided · **tags:** spec, api

**Decided: `Nwk_DataConfirmParameters.handle` pairs a confirm with its request as the transmit the request became (`Nwk_LastRequestHandle`), not as an octet the layer above supplies.**
Tables 3-2 and 3-3 print `NsduHandle` at both ends, over 0x00 to 0xff, as the document's identity for one NLDE transmission.
Neither table prints an AckRequest: the acknowledgement is asked one layer down through 3.2.1.1.3's TxOptions, so that ask is band A's own decision.

## D-56 · Randomness arrives as seeds

**Status:** Decided · **tags:** spec, api

**Decided: every random value the layers need is a seed the application supplies and a generator the library runs; no layer above band C draws entropy from the platform.**
The touchpoints are three: the NWK sequence number "initialized with a random value" (3.6.2.1, Table 3-66), the broadcast jitter bounded by `nwkcMaxBroadcastJitter` (3.6.6, Table 3-65), and the joining child's address selection.
A run is then reproducible from its seeds.

**Consequences.**
`Zb_LayersConfig` carries `seqStart`, `jitterSeed` and `joinSeed`; the façade may fill them from `Port_Entropy`.

## D-53 · The unstated points of the NWK security procedure

**Status:** Decided · **tags:** spec, decision

**Decided: hop-by-hop protection, unprotect first, and the nonce from the transmitted octets.**
(i) A relaying device unprotects a frame and re-protects it with its own extended address and counter; no clause states it, but it is the only reading of 4.5.1.3, 4.3.1.2's counter steps and 3.6.4.3's per-retry re-encryption, so the transmit slot and the broadcast record hold the unsecured octets and re-protect at each issue.
(ii) A secured frame is unprotected before anything else consumes it, the radius decrement included, since the radius is inside the authenticated string; a source-routed secured frame therefore authenticates its route.
(iii) The nonce takes the transmitted auxiliary octets verbatim, then the control octet before its step-8 zeroing, so the level travels in the nonce only.

## D-52 · Where keys and counters live

**Status:** Decided · **tags:** api, decision

**Decided: network key material, its sequence numbers, the security level, the device's extended address and the frame counters arrive at `Security_Init` in a configuration object the application owns.**
The module copies key octets into its own fixed pool, wiped on replacement and zeroed on `Security_Reset`, and holds the live counters as caller-owned state.
`Security_Snapshot` returns the active sequence number and the outgoing counters whenever the application wants to persist them.
The library reads and writes no storage, so 4.3.4's persistence rules (counters kept across factory resets, shadow key material per joinable network) are the application's duty over the data the snapshot exposes.

## D-49 · The broadcast delivery time is a stand-in

**Status:** Decided · **tags:** spec, decision, open

**Decided: broadcast records expire at `NWK_NETWORK_BROADCAST_DELIVERY_TIME_MS` = 9000 ms.**
The NIB attribute it stands for (0x88) prints no number for this profile.
Open as a number.

## D-47 · The RCP composes the poll's acknowledgement

**Status:** Decided · **tags:** measured, spec, seam

**Decided: band A answers a poll by transmitting the queued frame, and states Frame Pending through the seam's pending table and in the frames it composes, never in the acknowledgement.**
The RCP composes the acknowledgement within the 12-symbol turnaround, and no measured build lets the host compose or amend it.
R23.1 D.10.2.3's "SHALL affect the pending bit in the ACK frame" assumes a host-owned acknowledgement; the pending table is how the host satisfies it.
802.15.4-2024 has no poll-reception primitive, so the coordinator's half is a band A queue plus a band A event.
Each delivered transaction carries Frame Pending per 10.22.2, and an empty poll gets 10.22.3's zero-length answer.

**Consequences.**
A sleepy child pays one extra poll round trip, and a bare-transceiver backend could later state pending in its own acknowledgement.

## D-43 · The block implementation is a link-time seam

**Status:** Decided · **tags:** seam, measured

**Decided: `src/crypto/aes.h` is one contract header with candidate `.c` files, and exactly one is linked per build.**
The CMake option `ZB_AES_IMPLEMENTATION` names the candidate (`aes_scalar.c` the reference, `aes_table.c` the table candidate); the `crypto_aes` suite gates both.
The linker enforces the choice: a value naming no file is a CMake error, and two candidates in one build collide as duplicate symbols, so no `#ifdef` is needed.
The `bands` audit's one-module-per-pair rule cannot hold here by construction, so it carries the named exemption list `SEAM_IMPLS` and nothing else is relaxed.

## D-42 · The crypto band

**Status:** Decided · **tags:** spec, decision

**Decided: our own AES-128 from FIPS-197, with CTR, CMAC and CCM*, built from forward block encryptions only.**
CCM* decryption is CTR plus a recomputed tag, the plaintext zeroed when the tag fails (D-284), so the band offers no block-decrypt operation.
The crypto core is the part this stack must own, so it is not vendored.
`Aes_Key` is the caller's struct, scheduled and wiped by calls on it; no key material is held in the band.
The band is pure and one-shot: no streaming state, nothing buffered between calls.
Nonce and frame-counter management belongs to band A's `security` module.

## D-41 · A broken invariant calls the executable's handler

**Status:** Decided · **tags:** decision, upstream

**Decided: `ZB_ASSERT` always compiles its check and hands a failure to the one `Zb_AssertHandler` the executable links.**
The upstream `u_assert` elides the check in release builds and traps through compiler intrinsics.
Here a compiled-out check is what an assert exists to catch, and the handler can carry the failure into the record stream (`LOG_REASON_ASSERT`) and a sink.
This keeps platform guards out of the portable set; the rule itself is `docs/internals/coding-rules.md` §5.

## D-38 · What band A does when a completion never arrives

**Status:** Decided · **tags:** measured, decision, open

**Decided: `Mac_Step` ages an outstanding transmit by `MAC_COMPLETION_TIMEOUT_MS` = 1000 ms, confirms it `ZB_ERR_TIMEOUT` and sets `needsRearm`, and does not re-arm the backend itself.**
The reset belongs to whoever owns the backend, because band A may not know which backend it has (D-35).
Measured completions arrive 14 to 21 ms after the request, so one that outlives a second has not been delayed.
The number is open.

## D-37 · Who owns the acknowledgement wait

**Status:** Decided · **tags:** seam, measured

**Decided: the radio owns it when `Radio_Caps.handlesAckTimeout` says so, and band A otherwise claims no acknowledgement.**
A backend without the flag cannot report one, so `Mac_DataConfirmParameters.acked` stays 0 whatever it said.
Band A has no wait of its own: no property of either dialect carries an acknowledgement wait, so a host-side timeout would be a number nothing can set.
The flag is in `Radio_Caps` rather than read from the dialect's `RADIO_CAPS` bitmap, which is one dialect's vocabulary.

## D-35 · Each backend has its own pump

**Status:** Decided · **tags:** seam, decision

**Decided: `Radio_Ops` carries no pump; every backend has its own step call, and band A never sees it.**
Moving a link is a property of a backend: `RcpRadio_Pump` pulls bytes and finishes Spinel transactions, `LoopbackRadio_Pump` ages scripted answers.
Whoever owns the backend owns its pump, so a target with no link at all runs band A unchanged.

## D-34 · What a radio with no acknowledgement metadata may report

**Status:** Decided · **tags:** measured, seam

**Decided: `Radio_TxResult.isAcked` is 1 only when band A asked for an acknowledgement and the device says the exchange succeeded.**
Neither ConBee II build reports what a transmit's acknowledgement contained.
Measured on a radio running ACK_TIMEOUT: `0 OK` for an acknowledged frame to a peer filtered to that address, `17 NO_ACK` for the same frame to a peer merely listening.
A frame that asked for nothing is never reported answered, and no acknowledgement contents are claimed.

## D-33 · Band A computes the frame's footer

**Status:** Decided · **tags:** spec, measured, seam

**Decided: `mac_frame` computes the FCS, and band B only forwards it to a radio whose `Radio_Caps` reports a footer, or strips it for one that does not.**
The footer is inside the MAC frame (7.2.1, 5.6.3), and band A is the MAC.
Measured: the build that wants a footer transmits its own recomputation, so band A's footer guarantees the length the dialect requires, and correctness for a radio that does not recompute.
The `mac_frame` suite therefore asserts it against captured air frames.

## D-32 · Band B stops pulling before it loses a frame

**Status:** Decided · **tags:** seam, decision

**Decided: when band B's delivery queue has no room for what one more chunk could hold, it leaves the bytes in band C's ring and stops reading.**
A drop counted in band B for a full queue would report as a device fault one band A caused.

## D-31 · A host's transmit buffer is sized for the escaped frame

**Status:** Decided · **tags:** decision

**Decided: the transmit ring holds twice the 256-octet HDLC maximum plus flags (`PORT_TX_RING_MAX` = 1024).**
Escaping is applied on the way out, so the octets written can be up to twice the frame.
A ring sized for 256 would refuse a legal frame whose octets happened to escape.

## D-30 · What a device's `LAST_STATUS` becomes at the seam

**Status:** Decided · **tags:** seam, decision

**Decided: one named status per code the RCP reports, and a stated folding for the rest.**
`OK` is `ZB_OK`, `INVALID_ARGUMENT` `ZB_ERR_BAD_ARGUMENT`, `INVALID_STATE` `ZB_ERR_NOT_READY`, `PARSE_ERROR` `ZB_ERR_BAD_FRAME`, `BUSY` `ZB_ERR_BUSY`, `PROP_NOT_FOUND` and `UNIMPLEMENTED` `ZB_ERR_UNSUPPORTED`, a reset announcement `ZB_ERR_DEVICE_LOST`, anything else `ZB_ERR_DEVICE`.
`zb_status.h` is append-only, and the device's own code travels with the reply, so folding loses nothing.

## D-29 · Channel support on a dialect that does not report it

**Status:** Decided · **tags:** measured, spec

**Decided: band B reports `PHY_CHAN_SUPPORTED` where the dialect has it and the PHY's own set where it does not, never a mixture.**
The DSPINEL build answers `PROP_NOT_FOUND` for `0x22 PHY_CHAN_SUPPORTED`.
For the 2450 MHz O-QPSK PHY the set is the standard's: channels 11 to 26, `fc = 2405 + 5(k − 11)` MHz (802.15.4-2024 11.1.3.3).
A channel outside the reported set is refused before anything is written.

## D-26 · Enforcing one session per port

**Status:** Open · **tags:** measured, open

**Open: how the port ensures one session per device.**
The port requests exclusive use with `TIOCEXCL`, but macOS still accepts a second opener on a ConBee II, which then takes the traffic the first reader expected.
Armed RCP state survives a close, so the next opener inherits the previous configuration unless the session ended with a reset.
Options: an advisory lock on the device node, a lock file named after the path, or disarming on close.
None is portable, so the choice shapes the port.

## D-23 · Persistence is a plain state object

**Status:** Decided · **tags:** api, decision

**Decided: the stack takes and returns a plain C state object, and serialising it is the application's job.**
`Zb_StateCapture` fills a `Zb_State` and `Zb_StateRestore` reads one back; it holds only scalars and fixed arrays of structs, each with its own count, so no storage call reaches band C.
Entries are identified by content, never by index.
A restore validates the whole set before touching module state, and a count above the bound is refused rather than truncated.
Key material is opt-in per entry through `keyPresent`, so an object kept in plain flash can carry counters alone.
`Zb_StackCapture` and `Zb_StackConfig.state` carry it through the façade for every role.

## D-22 · One port contract or two

**Status:** Parked · **tags:** open

**Parked: `port.h` stays a single byte-stream contract until a bare transceiver target exists.**
A bare transceiver would need register transactions plus IRQ and reset lines; this is deferred with D-18.

## D-20 · Software MAC timing

**Status:** Parked · **tags:** open

**Parked with the MCU profiles: it only matters when a backend accelerates nothing.**
On a host the RCP link can never meet a 12-symbol turnaround, so the MAC delegates acknowledgement and CSMA to the RCP and says so in the capability record.

## D-19 · Repository licence

**Status:** Decided · **tags:** mandate

**Decided: BSD-3-Clause, with the notice in `LICENSE`.**
A permissive licence lets an MCU vendor or a product take the stack without a copyleft review.
It conflicts with no reference corpus because nothing here is derived from one: the standards are read only, the GPL-3.0 zigbee-on-host project contributes no code, and the deCONZ ConBee II firmware may never be a donor (`docs/internals/refs.md` §5).
The vendored files keep their own notices.

## D-18 · MCU target and its budget

**Status:** Parked · **tags:** open

**Parked: nothing about a chip, its memory budget, pool shrinkage or an MCU port is decided until a target exists.**
The host profiles and the freestanding gate are what prepare for it.

## D-16 · The receive stamp is the device's clock

**Status:** Decided · **tags:** seam, decision

**Decided: the seam carries `deviceStampTicks`, the device's own clock in the device's own unit, and no host-side timestamp.**
Spinel names the unit microseconds, while the AT86RF233 build ticks at about 2.37 µs (`docs/internals/protocol.md` §8.1).
A stamp band C cannot produce accurately would be a field that lies.

## D-15 · Delivery across the seam is pulled and copied

**Status:** Decided · **tags:** seam, decision, open

**Decided: `rxPoll` pulls received frames in batches of at most `RADIO_FRAME_BATCH_MAX`, and each frame is copied out.**
Band B then holds nothing band A received, and there is no callback from band B into band A.
The rest of `Radio_Ops` (`caps`, `pibSet`/`pibGet`, `filter`, `tx` with its `completion`, `isLost`, and the issued-and-collected `scanStart`/`scanCollect`) is in `src/seam/radio.h`, exercised by the `seam` suite.
Open: filtered unicast delivery, since only promiscuous receive is measured.

## D-13 · The MAC is inside the library and the seam is the radio service

**Status:** Decided · **tags:** spec, seam

**Decided: band A owns the 802.15.4 MAC, and a backend exchanges PSDUs and reports what it accelerated.**
Band A owns MHR assembly and dissection, sequence numbering, AR and version policy, polls, the indirect queue and the PIB mirror; the MCPS/MLME pair is the library-internal NWK to MAC interface.
Neither RCP dialect exposes a MAC data service, Figure 8-1 puts MCPS/MLME above the MAC, and `RADIO_CAPS` exists to enumerate delegated primitives.
The capabilities are a runtime struct read from `CAPS`, `RADIO_CAPS` and `RCP_API_VERSION`, because two measured dialects differ in mandatory fields and no compile-time device profile can cover both.

## D-11 · 802.15.4 revision coverage

**Status:** Decided · **tags:** spec

**Decided: IEEE 802.15.4-2024 is the citation of record, with 802.15.4-2006 for the numeric MAC status codes 2024 no longer lists.**
802.15.4-2024 is the active compilation of the 2020 edition R23.1 assumes, and its clause 7 carries the frame layout and the Information Elements R23.1 Annex D.11 relies on.

## D-10 · Roles

**Status:** Decided · **tags:** decision

**Decided: the coordinator and the router are the roles this stack is built for, and the end device is built too, as the instrument that proves the other two.**
A parent queueing for a sleepy child, a child polling, a parent ageing its children and a rejoin after a missed timeout are what give the other two meaning.

## D-7 · One source tree split by band

**Status:** Decided · **tags:** mandate

**Decided: one `src/` tree split by band, not by host.**
`src/zb/` is band A, `src/seam/`, `src/rcp/` and `src/loopback/` band B, `src/port/` band C, with the substrate in `src/crypto/`, `src/utils/` and `src/log/`, and the façade in `src/stack/`.
The bands audit derives membership from the directory a file lives in, so the layout is the enforcement; a second axis such as `host/` would give one file two answers.
The map is `docs/internals/README.md`, "The source tree".

## D-5 · A typed field codec above the byte stream

**Status:** Decided · **tags:** api, decision

**Decided: `src/rcp/spinel.{c,h}` is a typed field codec, and a module never touches the byte stream directly for a protocol field.**
There is no format-string or variadic packing API: interpreting a `SPINEL_DATATYPE_*` grammar at runtime moves the bounds checks away from the code that needs them, and fault injection cannot reach inside a format expansion.
A property's shape is written as explicit calls in `props.c`, which is also where a dialect's deviations live.
`Spinel_PackedUintBytes` and `Spinel_PrefixedBytes` let a caller prove a buffer fits before composing, so no partial frame is a property of the composition.
The library's zigzag LEB128 is not Spinel's packed uint and stays unused.

## D-1 · Build and test scaffolding

**Status:** Decided · **tags:** mandate

**Decided: CMake and plain `ctest`, with no external test framework and no package lookup.**
Every suite is a plain C99 program with its own `main`, using this repository's own assertion family (`test/support/test_harness`).
The suites count their own failures, print `FAIL: <what>`, and are pinned per suite by `test/suite_ledger.py`, so a framework would add nothing.
