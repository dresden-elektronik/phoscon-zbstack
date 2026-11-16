# Architecture

How the stack is shaped: the bands and the seam between them, where the MAC splits, and how a frame travels.

## At a glance

- **One library**: the 802.15.4 MAC and every Zigbee layer above it are band A, the same code on every target; it never touches a platform.
- **A seam below the MAC**: the library's bottom edge is a PSDU pipe and a capability report, so the MAC is the library's own on every radio.
- **No thread, no clock, no allocation**: the caller turns the library, passes the time and lends every buffer; every wait is a deadline checked on a turn.

## 1. Bands and the seam

The stack is one library, and beneath it a swappable radio service (Figure 1).

![The stack read downwards. At the top, the application: examples/ with a coordinator and a router, and your application. Under it the doors: zb_stack.h, one object reporting events, and zb_core.h, the library under it for a loop of its own. Band A, in amber, is the library in four layers: the application layer (af, zdo, zcl, zb_state), APS (aps, aps_ack, aps_frag, aps_bind, aps_tclink), NWK in two rows (nwk, security, nwk_join, nwk_command, nwk_btt; nwk_route, nwk_rreq, nwk_relay, nwk_neighbor, nwk_indirect) and the MAC (mac, mac_tx, mac_rx, mac_assoc, mac_scan, mac_indirect). Under it the seam, seam/radio.h, a PSDU pipe and a report of what the radio can do. Band B, the radio backends: rcp_radio, spinel_session, spinel, props, hdlc and loopback_radio. Under it port/port.h: bytes in and out, a millisecond clock, entropy. Band C, the port: port_posix for Linux, macOS and BSD, port_win32 dashed as a stub, port_null and port_log. At the bottom the RCPs, outside the tree: ConBee II and RaspBee II, and ConBee III, each running Phoscon RCP. Beside every band stands the substrate: utils, log, crypto and vendor/. Arrows say calls go down, and results are polled, nothing calls up.](../images/bands.png)

*Figure 1: the bands and the seam.*
Calls go down and results are polled; nothing calls up.

| Band | Holds | Talks to |
| --- | --- | --- |
| **A: the library** | the MAC, NWK, APS, the security crossing, the application layer (`af`, `zdo`, `zcl`), `zb_core` and `zb_layers` over them, and `zb_state` | the seam, nothing else |
| **the stack** | `src/stack/`: `Zb_Stack`, the library composed with the Spinel backend and the port, reporting events | the application above; bands A, B and C below |
| **the seam** | `src/seam/radio.h`: a table of function pointers and the status code each answers with | bands A and B |
| **B: radio backends** | `rcp_radio` (an RCP behind `hdlc`, `spinel`, `spinel_session`, `props`) and `loopback_radio` (no hardware) | the seam, band C |
| **C: the port** | the byte stream, a monotonic clock, entropy | the operating system, or nothing |
| *substrate* | `src/utils/`, `src/log/`, `src/crypto/` and `vendor/`: bounded memory and text, the log pool, AES-128 with its modes | nothing above it |

The library never includes the backend or the port, and the backend never includes the library: the seam header is the only file both sides share.

## 2. Why the seam is below the MAC

The standard puts the MAC's data and management services above the MAC, no co-processor protocol offers a MAC data service, an RCP reports what its silicon accelerates rather than a service, and a seam above the MAC would grow a MAC inside every backend.

## 3. The MAC splits, and the split line is timing

What must happen within the radio's turnaround is the RCP's; everything that can wait milliseconds is the library's (Figure 2).

![Two columns, HOST MAC (band A, src/zb/mac/) and RCP (Phoscon RCP, behind the seam), against a logarithmic time axis from 100 microseconds to 100 seconds, each duty placed at the deadline its next step must meet. The RCP holds the microsecond duties: CCA at 128 µs, the Ack with its address match and Frame Pending bit within the 192 µs turnaround, a CSMA-CA backoff unit of 320 µs, and retransmission when the 864 µs Ack wait ends. An amber band crosses both columns at about 14 to 21 milliseconds, where a transmit's completion is measured coming back over the link. Below the band the host holds the millisecond windows: an active scan's dwell of at least 30.72 ms a channel, MAC_BEACON_HOLD_MS at 100 ms, MAC_ASSOC_POLL_DELAY_MS at 123 ms, MAC_RESPONSE_WAIT_MS at 492 ms, MAC_COMPLETION_TIMEOUT_MS at 1 s and MAC_TRANSACTION_PERSISTENCE_MS at 30 s. Under the axis, a group with no air deadline lists the host duties done whenever Mac_Step runs: MacFrame_Compose for the MHR, the sequence numbers, the ackRequest policy, macTxFrameRetries, the MacRx_QueueFrame software filter, and the indirect queue. An arrow labelled pendingTable runs from the indirect queue up to the RCP's Ack: written as the queue moves, read inside the turnaround.](../images/macsplit.png)

*Figure 2: the MAC split line.*
A duty whose deadline falls before a transmit's completion can come back over the serial link is the RCP's, and everything after it is the host's.

| The library's MAC | The RCP's radio, reported as a capability |
| --- | --- |
| the MAC header built and read: frame control, addressing, sequence numbers, the FCS | CSMA-CA and CCA, backoff windows, the CCA threshold |
| polls as a policy: when to poll, what a poll received means, the indirect queue and its expiry | the Ack, composed inside a turnaround no host behind USB answers |
| the PIB as the MAC's own state: PAN identifier, both addresses, channel, receiver-on-when-idle, retry counts | applying a PIB value to the silicon, and saying when one is not supported |
| MAC commands: Data Request, Beacon Request, association, orphan notification | retries awaiting an Ack: a MAC that retried as well would send one frame twice |
| | address filtering, the Frame Pending bit from the source-match table, energy scan |

What the RCP does on the library's behalf is read from its capability report at bring-up, never compiled in.
An RCP that resets itself loses the configuration the MAC gave it, so the backend reports the loss and the MAC applies it again; a serial port that goes away is the same loss.

## 4. The seam, call by call

`tx` hands back a handle at once and the MAC collects the outcome on a later step; every other write is queued for the backend (Figure 3).

![A sequence diagram with lifelines for band A's MAC, the rcp_radio backend behind seam/radio.h, and the Phoscon RCP reached over Spinel and HDLC. In bring-up, the caller's loop pumps rcp_radio, which resets the RCP, reads its version, capabilities and address, and arms it; the MAC asks caps and gets Radio_Caps as read at discovery; pibSet and filter answer ZB_OK at once and are only queued, and later pumps write them one at a time, each echoed. In transmit, tx writes SET STREAM_RAW inside the call and returns a handle at once, in amber; the RCP runs CSMA-CA, CCA, the Ack wait and the retries on its own; the MAC asks completion for the handle and gets ZB_ERR_NOT_READY until the RCP's LAST_STATUS arrives with the request's TID, and the next completion returns the Radio_TxResult, in amber. A table maps the RCP's status to the seam's: OK to ZB_OK, with isAcked only when an Ack was asked for; NO_ACK to ZB_ERR_NO_ACK; CCA_FAILURE to ZB_ERR_CHANNEL_ACCESS_FAILURE; a reset to ZB_ERR_DEVICE_LOST; no answer to ZB_ERR_TIMEOUT; any other code through SpinelSession_StatusToZb. In receive, an unsolicited STREAM_RAW is copied into rxQueue, and rxPoll hands the MAC a batch of Radio_Frame. In a reset, the RCP's RESET notification makes rcp_radio arm again and owe the loss: an open handle completes with ZB_ERR_DEVICE_LOST, and isLost answers 1 until the RCP runs again and once after, so the MAC holds and then re-applies its PIB, mode and pending table. When the indirect queue moves, pendingTable is written to the RCP's source-match table. A dashed frame shows the energy scan, which the MAC's ED scan and a bench tool call.](../images/seam.png)

*Figure 3: the seam, call by call.*
The handle and its result, in amber, make the seam a pipe and not a MAC data service: nothing waits while a handle is out.

| Call | Contract |
| --- | --- |
| `caps` | which MAC primitives the silicon performs, and the dialect's flags |
| `pibSet`, `pibGet` | channel and page, PAN identifier, addresses, receiver-on-when-idle, retry counts, ack timeout, CCA threshold; a refused value is reported back |
| `filter` | filtered or promiscuous, and the address filter's contents |
| `tx` | a complete MPDU in, a handle out at once |
| `completion` | the outcome for a handle, including whether the Ack arrived |
| `rxPoll` | every received PSDU, with LQI, RSSI, timestamp and error code |
| `isLost` | the configuration the library gave the RCP is gone |
| `pendingTable` | the addresses the RCP acknowledges with Frame Pending set |
| `scanStart`, `scanCollect` | one energy dwell on one channel, started now and collected on a later turn |

How `rcp_radio` carries each call over Spinel is `docs/internals/protocol.md`.

## 5. Inside band A

### 5.1 The primitives between NWK and MAC

`nwk` and `mac` speak the primitives the standards define (MCPS-DATA, MLME-*, Zigbee's MLME-POLL.indication), because Zigbee's own text is written in them.

### 5.2 The application's surface

An application speaks the APS data service and nothing below it: one send call and one polled ring of indications.
The library owns endpoint 0, so a ZDP request is the device object's and never reaches the application; a ZDP response is the application's, since it asked.
The application registers its simple descriptors, and the device object answers discovery requests from them.
A cluster is a number in a descriptor's lists, so a cluster server is an application that registers a descriptor and answers its frames.

## 6. The data path

A frame going out runs down the layers inside the caller's turn, and what became of it comes back as polled results (Figure 4).

![The transmit path in two columns. On the left the request goes down in solid arrows: the application calls Zb_StackApsRequest, which goes all the way down in this call unless a layer holds it; zb_core checks that a source endpoint other than 0 is registered and calls Aps_DataRequest; aps takes a slot, builds the frame and its counter and applies APS security if asked, then calls Nwk_DataRequest; nwk finds or discovers a route, keeps the broadcast table, writes the header and applies NWK security, then calls Mac_DataRequest; mac writes the MHR, sequence number and FCS with a retry count for the radio and hands one whole MPDU to the seam's tx for a handle; rcp_radio sends SET STREAM_RAW, answering no room while a reply or a write is owed; Hdlc_Encode and Port_Write carry it to the RCP, where Phoscon RCP runs CSMA, the retries and the Ack. On the right, in amber, the slots where a frame waits: APS_TX_AWAITING_ACK, sent again until the APS ack comes, then NO_ACK, ended by Aps_AckSlotForAck from the receive path; NWK_TX_AWAITING_ROUTE, held while discovery runs; NWK_TX_AWAITING_RETRY, a unicast retried and a broadcast held for room; MAC_TX_OUTSTANDING, waiting for the radio's completion or timing out; and Mac_IndirectRequest, a resting child's frame kept until it polls. The confirm comes up in dashed arrows: the RCP's PROP_LAST_STATUS read through Hdlc_Feed by RcpRadio_Pump, the seam's completion, Mac_PollConfirms, Nwk_PollConfirms, and ZB_EVENT_SENT, the event the application takes.](../images/txpath.png)

*Figure 4: a frame going out.*
Amber marks the slots where a frame waits or is sent again; the host MAC never retries, it hands the radio a retry count.

A frame coming in is pulled through the seam by the MAC and handed up layer by layer, to be relayed, answered by the device object, or left for the application (Figure 5).

![The receive path, read bottom to top in one column. From the RCP, where Phoscon RCP has filtered the address and already sent the Ack, Port_Read and Hdlc_Feed, run by the application's RcpRadio_Pump, bring the bytes to rcp_radio, which turns a STREAM_RAW notification into a queued Radio_Frame. The MAC pulls a batch through the seam's rxPoll each step and checks the FCS, the header, its own echo and the filter, and runs the beacon, association and poll duties. Mac_PollIndications hands the frame to Security_Unprotect, in amber: a NWK-secured frame is checked for its MIC and frame counter, and a failure is dropped. nwk handles the radius, commands and the broadcast table and decides between this device and a relay. Nwk_PollIndications hands it to Aps_RxSecureReceive, in amber: an APS-secured frame that fails goes up as a status with an empty ASDU. aps ends a waiting send on an ack, rejects duplicates, reassembles fragments and delivers to groups. Aps_PollIndications, inside Zb_CoreStep, hands it to zb_core: a ZDP request is the device object's, and the rest reach the application as ZB_EVENT_DATA from Zb_StackNextEvent. To the right, dashed boxes show what a layer sends back down through the transmit path: MacIndirect_DoPollAnswer, the frame held for a polling child; Nwk_RelayUnicast and Nwk_RelayBroadcast, re-secured and sent on; Aps_AckRespond, the APS ack the frame asked for; and Zdo_HandleIndication, the device object's answer.](../images/rxpath.png)

*Figure 5: a frame coming in.*
Amber marks the two security crossings: the network layer drops a frame that fails, and the APS layer passes it up as a status.

Both paths run inside one call, `Zb_LayersStep(nowMs)`; the byte pump feeds the backend only, and nothing in band A waits, sleeps or blocks.

## 7. Portability

- **Only the port and the backend are target-shaped**: another target replaces `port` and `rcp_radio`, not their callers, and band A compiles from one source list everywhere.
- **No allocation**: every pool is sized at build time, so a small target shrinks pools and changes no code.
- **One execution context**: the backend's byte pump may run in an interrupt, a poll loop or a callback, but band A runs only inside `Zb_LayersStep(nowMs)`.
- **Band A is given its world**: time, entropy, the radio and the pool sizes arrive from the caller.

| Profile | Links | For |
| --- | --- | --- |
| `test-loopback` | A + `loopback_radio` + `port_null` | every band-A suite, with no radio at all |
| `host-rcp` | A + `rcp_radio` + `port_posix` or `port_win32` | an RCP on macOS, Linux or Windows |
| `mcu-rcp` | A + `rcp_radio` + a UART or SPI port | not planned (§8): a microcontroller beside an RCP |
| `wasm` | A + `loopback_radio` or a JavaScript backend + a JavaScript port | not planned (§8) |

How a target plugs in is `docs/porting.md`.

## 8. Scope

Not part of the design for now: Thread, certification harnesses, and microcontroller or WASM targets, though band A stays free of platform knowledge so that either remains possible.
Planned and not yet built: Green Power, and Touchlink over Inter-PAN frames (`docs/status.md`).
