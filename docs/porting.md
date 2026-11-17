# Porting

How the stack is brought to a platform: the port is the one module that knows a device, a clock or an operating system, and this is its contract.
**After reading** you can add a target without touching the library, because every platform call a target owes is named here.
The gates this contract is held to are `docs/internals/testing.md` §2, and which target they run on is `docs/internals/testing.md` §6.1.

A host application uses `Zb_Stack`, this port and the Spinel backend composed (`docs/guide.md`); a target of its own drives `Zb_Stack` over its own radio with `Zb_StackTurn`, or uses `Zb_Core` directly.
Four things are needed from the world: the byte stream and entropy as port services (`Port_Entropy`, D-56), a monotonic clock from the platform (`Port_NowMs()`, D-277, read here and passed up as parameters), and a log pool the application owns and drains.
Storage is deliberately absent (§5).
The hosts are macOS, Linux and Windows; a microcontroller target is not planned (`docs/internals/architecture.md` §8), though bands A and B build with no host assumption in them.
GCFFlasher (`github.com/dresden-elektronik/gcfflasher`) is the pattern this follows: a shared core plus one `.c` per platform family selected by the build, and device enumeration kept in tools rather than in the core.

| Service | Shape | Needed by | Rule |
| --- | --- | --- | --- |
| Byte stream to the radio | `Port_Open` / `Port_Close` / `Port_Read` / `Port_Write`, non-blocking, bounded, overflow-counted | `rcp_radio` (`hdlc`, `spinel`) | the only **mandatory** port service |
| Monotonic time | `Port_NowMs()`, the platform's (D-277): a free-running millisecond counter, monotonic, one wrap every 2^32 ms, an epoch nothing may read a date out of | the target's main loop and the tools: never bands A or B | `nowMs` stays a parameter everywhere above band C and every deadline is compared with `Zb_timeReached`/`Zb_timeWithin` (`docs/internals/coding-rules.md` §4.1); a target with no monotonic clock defines no `Port_NowMs` and fails to link rather than answer wall-clock time |
| Entropy | `Port_Entropy` on the port contract (decision 56): one call fills the whole request or writes nothing, `len` above `PORT_ENTROPY_MAX` 256 is refused at the door | the application and tools; band A takes its seeds through its own config: `Nwk_Config.seqStart` and `jitterSeed`, `Mac_Config.dsnStart` a port that does not answer the op answers `ZB_ERR_UNSUPPORTED`; `port_null` hands out its script in call order and `ZB_ERR_NO_SPACE` at the end of it |
| Waiting on the device | `Port_Wait` (D-251): returns when the device has something to read or a limit has passed, draining the transmit ring first | the host's loop, so it sleeps on the device rather than on a clock | optional: a target with no way to block answers `ZB_ERR_UNSUPPORTED`; `port_posix` uses `poll()`, where a hung-up line marks the device gone (D-281), and `port_win32` one ReadFile under a timeout (D-302) |
| Sleeping with no device | `Port_SleepMs(ms)`, the platform's beside `Port_NowMs` (D-281) | `Zb_StackNextEvent`, while its port is gone or cannot wait | `port_posix` uses `nanosleep`, resumed after a signal, and `port_win32` `Sleep`; a target that defines `Port_NowMs` defines it too |
| Files | `Port_File*` in `port_file.h` (D-278): open, read, write, seek, size, close, delete, rename, exists on a `PortFile` whose handle is opaque, each answering 1 or 0 | applications only: no band calls them | optional: a target without files defines none, and a program calling them fails to link there; `port_file_posix.c` uses `open`/`read`/`write`/`rename`, `port_file_win32.c` `CreateFile` and `MoveFileEx` |
| Diagnostics | a log pool the caller owns and drains (`Zb_LayersConfig.log`) | every band | fixed-size binary records, per `docs/internals/coding-rules.md` §5 |

Absent by design: threads, descriptors, a filesystem, signals, sockets, sleeping, `sleep()` in any form, and any `#if defined(ZB_TARGET_…)` outside `src/port/`.

## 1. The byte stream, exactly

As built in `src/port/`.
The portable half (rings, counters, states) is `port.c`; a target supplies a `PortDeviceOps` table (`open`, `close`, `pump`, `drain`, `lastFault`, and the optional `entropy` and `nowMs`), so one binary can hold two targets at once, which is what the suites need and what keeps band B free of any knowledge of which one it is talking to.
Counts are `uint32_t` (`docs/internals/coding-rules.md` §1), never `size_t`.

```
ZbStatus Port_Init (Port *port, const PortDeviceOps *ops);
ZbStatus Port_Open (Port *port, const char *path, const PortConfig *config);
void     Port_Close(Port *port);
ZbStatus Port_Write(Port *port, const uint8_t *bytes, uint32_t len, uint32_t *written);
ZbStatus Port_Read (Port *port, uint8_t *buf, uint32_t cap, uint32_t *got);
uint32_t Port_Drops(const Port *port);      /* inbound bytes lost to a full ring */
uint32_t Port_Refusals(const Port *port);   /* outbound writes refused for want of space */
PortFault Port_Fault(const Port *port);     /* open / read / write / device gone */
uint32_t Port_PlatformErrno(const Port *port);
PortState Port_State(const Port *port);     /* closed / ready / fault */
```

The state is caller-owned (`Port` is a struct the application or a suite allocates), and the ring sizes are configuration: `PortConfig` may shrink a ring to any power of two up to the fixed pool, never beyond it, a build-time assertion ties the pool to its named constant, and an illegal size answers `ZB_ERR_BAD_ARGUMENT` before a device is touched.
With no `PortConfig` at all the documented defaults apply, and a suite asserts that they are the defaults the device implementation actually receives: 115200 (`docs/internals/hardware.md` §2), rings of 512 bytes in and 1024 out, and a request for exclusive use.

| Rule | Reason |
| --- | --- |
| `Port_Write` and `Port_Read` never block, never allocate, and report how many bytes actually moved | a blocked call is unbounded latency in a stack with no threads |
| a write is **atomic**: either entirely accepted or refused with `ZB_ERR_BUSY` and `*written == 0`, and the refusal is counted | a half-written HDLC frame is worse than a refused one; the ring is left untouched |
| `*got == 0` with `ZB_OK` is a normal answer when nothing is pending | the caller's state machine must be able to say "nothing happened this step" |
| inbound overflow drops the **newest** bytes and increments `Port_Drops`; the oldest survive | `docs/internals/coding-rules.md` §4.3; an invisible drop would be blamed on the radio |
| bytes already in the ring are delivered **after** the device faults; the loss is reported once the ring has nothing left | a stack must not discard frames it already holds because the link died afterwards |
| a fault is a state (`PORT_STATE_FAULT`), a reason (`PortFault`) and the platform's own error number | "absent" and "gone mid-run" are different events, and only the port module knows which |
| the fault reaches band B as a status from `Port_Read`/`Port_Write`, which the backend raises as the seam `lost` event (`docs/internals/architecture.md` §4) | band A must re-apply its PIB mirror, and only band B knows the device died |
| No flow control is required of a target | a WASM glue cannot provide it; a target that has it may use it privately |
| No default device path, ever: a null or empty path is `ZB_ERR_BAD_ARGUMENT` and nothing is invented | devices of one kind share a port-name prefix, and the wrong one would be armed (`docs/internals/hardware.md` §8) |
| The port *requests* exclusive use but does not rely on it | measured: macOS accepts a second opener regardless (D-26) |

## 2. Rings, bursts, and who feeds them

![The port. A device node, the RCP over USB or a UART, on the left. In the receive row, posixPump runs inside Port_Read and reads only what fits, pushing bytes with Port_PushRx into rxRing, in amber, 512 bytes, whose newest bytes are dropped and counted by Port_Drops when it is full; band B's RcpRadio_Pump takes them out with Port_Read. A dashed, owed interrupt pushes into the same ring, the recommended option. In the transmit row, RcpRadio_Pump hands a whole frame to Port_Write into txRing, in amber, 1024 bytes, refused whole with ZB_ERR_BUSY and counted by Port_Refusals when it is full; posixDrain runs inside Port_Write and writes it to the device with Port_TxHead and Port_ConsumeTx. Either ring is a power of two PortConfig may shrink. Below, clock_gettime reading CLOCK_MONOTONIC feeds Port_NowMs, a millisecond counter that wraps every 2^32 ms, and posixEntropy reading getentropy feeds Port_Entropy, which fills the whole request or nothing; only the application reads either, passing nowMs to RcpRadio_Pump and Zb_CoreStep and a seed into Zb_CoreConfig. A strip headed deadlines, not timers shows the 32-bit counter: a window opened at startMs runs off the end and continues from 0 to deadlineMs, and nowMs is the larger number yet the deadline is still ahead, because Zb_timeReached reads nowMs minus deadlineMs as signed and Zb_timeWithin reads nowMs minus startMs as unsigned, so a span under 2^31 ms reads right across the wrap.](images/port.png)

*Figure 1: the port, its rings and its deadlines.*
Two fixed rings, in amber, sit between the device and band B, filled and emptied by the target's pump and drain inside `Port_Read` and `Port_Write`; the clock and the entropy are read by the application alone, so every wait above it is a deadline compared against the `nowMs` it hands down.
Source: `tools/diagrams/port.py`.

The inbound ring is the one mechanism every target shares, and its size is arithmetic, not taste: 115200 8N1 is ≈ 11.5 kB/s ≈ 87 µs per byte, and one maximum Spinel frame (256 bytes, `docs/internals/protocol.md` §2) is ≈ 22 ms of air on that link.

| Ring | Budget | Note |
| --- | --- | --- |
| inbound | ≥ 2 maximum frames = 512 B | holds a ≈ 44 ms burst; on a host the pump reads only what fits and the rest waits in the operating system's buffer, so `Port_Drops` moves only where something pushes, an interrupt or a suite |
| outbound | 2 maximum frames + both flags = 1024 B | one frame at its worst escaping; one transmit is outstanding at a time by the `spinel` pending-slot rule |

An interrupt-driven target chooses one of the two shapes `docs/internals/coding-rules.md` §4.7 permits: the interrupt appends **bytes** to the port's ring and everything above decodes inside `Zb_LayersStep` (recommended: one ISR-safe mechanism, no reentrancy anywhere else), or the interrupt hands a **decoded frame** to band B's own ring (less work in the step function, two ISR-safe code paths to test).
Under-sizing a ring is a test, not an accident: `port_conformance` replays a transcript against a deliberately one-frame ring and asserts the drop counter and a clean HDLC resync.

## 3. Targets

One contract, one implementation per platform family, selected by the build.

| File | Covers | Selected by |
| --- | --- | --- |
| `src/port/port.h` + `port.c` | the §1 contract, the rings, counters and the state machine: portable C99 with no platform knowledge | always |
| `src/port/port_posix.h` + `port_posix.c` | macOS and Linux: `open`/`read`/`write` + `termios` raw 8N1 + `TIOCEXCL`, `clock_gettime(CLOCK_MONOTONIC)` for `Port_NowMs`, and the pseudo-terminal helpers the suites run the contract against | `PortPosixOps()` |
| `src/port/port_file.h` + `port_file_posix.c` | an application's files on macOS and Linux: a descriptor in `PortFile`'s handle, opened close-on-exec, every call retried on `EINTR` | UNIX |
| `src/port/port_log_posix.h` + `port_log_posix.c`, `log_names.c` | the log sink on macOS and Linux: one line per record on standard error, built from the host-side name table | UNIX |
| `src/port/port_log_win32.h` + `port_log_win32.c` | the log sink on Windows: the same line, on the standard error handle | Windows |
| `src/port/port_file.h` + `port_file_win32.c` | an application's files on Windows: a handle in `PortFile`'s handle, shared as a POSIX descriptor is, and a rename that replaces in one step | Windows |
| `src/port/port_locate.h` + `port_locate.c` | a stick named `usb-serial:<serial>` (D-282): the selector and its exact match, portable, over the platform's list | always |
| `port_locate_sysfs.c` | Linux's sysfs walk with POSIX calls: the Linux list, and the suite's fixture tree on any POSIX host | UNIX |
| `port_locate_linux.c`, `port_locate_darwin.c`, `port_locate_win32.c` | the platform's list: the sysfs walk at the system's root, IOKit's serial services and the USB serial number above each, or SetupAPI's COM ports and the USB device above each | Linux, Apple, Windows |
| `src/port/port_null.h` + `port_null.c` | the scripted port: chosen chunk sizes, injected pump and drain failures, captured writes, and a record of the configuration it was handed; no clock, because a suite injects `nowMs` into the band it drives | `PortNullOps()` |
| `src/port/port_win32.h` + `port_win32.c` | Windows: `CreateFile` on `\\.\COM<n>`, a `DCB` for 8N1 binary, `COMMTIMEOUTS` for a read that returns at once and a wait that returns on the first octet (D-302), `BCryptGenRandom` for entropy and `QueryPerformanceCounter` for `Port_NowMs` | `PortWin32Ops()` |
| `src/port/port_wasm.c` | a WASM host's port | deferred |
| `src/port/port_mcu_*.c` | not planned (`docs/internals/architecture.md` §8) | decision 18 |

The backend the build links also defines `Port_DefaultOps()`, which hands a host program its ops without a platform header: `port_posix.c` or `port_win32.c`.
A new target may start as a stub, a real file whose every call answers `ZB_ERR_UNSUPPORTED`, not an empty implementation: it keeps the matrix honest, and no conformance gate may pass on account of it (`docs/internals/coding-rules.md` §1).

Note how much of the matrix needs no hardware at all: `port_null` plus `hdlc`, `spinel`, `mac_frame`, `mac` and the whole protocol band never touch a device, so a host without an RCP still proves that the band builds and passes there.
What genuinely needs an RCP is `port_contract`'s device half, the seam's `tx` row and the rig gates of `docs/internals/testing.md` §3.

The target is chosen twice over, and both choices are build-time: the build links `port_posix.c` only where a POSIX system exists, and the caller hands one ops table to `Port_Open`.
That is what keeps platform knowledge out of `port.h`, lets a suite hold two targets in one process, and leaves band B unable to tell which target it is talking to.
Only the platform files of `src/port/` (`port_posix.c`, `port_file_posix.c`, `port_log_posix.c`, `port_locate_sysfs.c`, `port_locate_darwin.c`, and the four `*_win32.c`) include a platform header, and the `bands` suite fails the build if anything else does.

What differs across the three host systems, and what has been measured:

| Concern | macOS | Linux | Windows |
| --- | --- | --- | --- |
| Device path | `/dev/cu.usbmodem*` for the CDC sticks, `/dev/cu.usbserial-*` for the FTDI one | on a Pi 5, `/dev/ttyACM*` measured for a ConBee II, `/dev/ttyUSB*` for a ConBee III, `/dev/ttyAMA0` for a RaspBee | `COM<n>`, needing the `\\.\COM10` form from two digits up |
| Raw mode | termios raw with `CREAD\|CLOCAL` and `CSTOPB`/`PARENB` cleared | same API | no raw-mode notion at all: a `DCB` with 8 data bits, one stop bit, no parity, binary |
| Read with nothing pending | `O_NONBLOCK`, and `select` in the harness today | same | `COMMTIMEOUTS` so a read returns immediately having transferred zero bytes |
| Monotonic clock | `clock_gettime(CLOCK_MONOTONIC)`, implemented and asserted | same call expected | `QueryPerformanceCounter`, implemented and asserted |
| ConBee II (native CDC) driver | Apple's CDC serial client | `cdc-acm` expected | Windows' own `usbser`, measured |
| ConBee III (FTDI bridge) driver | the kernel FTDI serial driver | `ftdi_sio`, measured on a Pi 5 | a COM port through the VCP driver; FTD2XX is the alternative a flasher uses to drive the reset line, which carrying Spinel frames does not need |
| Enumeration by USB serial number | IOKit: each `IOSerialBSDClient`'s callout node and the `USB Serial Number` above it, measured for the CDC and the FTDI sticks (D-282) | sysfs: `/sys/class/tty/<name>/device` up to the first directory with `idVendor`, measured on a Pi 5 (Debian 13) and on Arch, no udev needed | SetupAPI: each present port of the Ports class, its `PortName`, and the first `USB\VID_…\<serial>` instance above it, measured for the CDC stick, whose COM port is the USB device itself, and for the FTDI one, whose serial the FTDI bus suffixes and the USB device does not |
| Permissions | no `sudo` needed | device-node group membership | typically none |

A stick named `usb-serial:<serial>` is found through that row at every open (D-282); `port_find` prints what it would open.
In a container, `/sys` is mounted and the lookup works, but a node must exist there to be opened: `--device /dev/ttyUSB0` maps one name only, so a stick that comes back as `ttyUSB1` is not there; `-v /dev:/dev` with `--device-cgroup-rule 'c 188:* rmw'` (ttyUSB) or `'c 166:* rmw'` (ttyACM) is a setup in which it is.

The macOS and Linux columns are **measured**.
On Windows 11 with MSVC 17.7 (Visual Studio 2022) the build and every suite pass, `port_win32` among them, and a ConBee III on COM10 through the FTDI driver and a ConBee II on COM11 through the USB-CDC one are each found by `usb-serial:`, come up in 242 and 222 ms, receive on channel 11 and run the example coordinator, and the ConBee II pulled mid-run is reported lost, reopened at the same `usb-serial:` name when it is back, and holds the network again **measured**.
On Linux the build and every suite, `port_contract` and `port_posix` among them, pass on a Raspberry Pi 5 (Debian, gcc 14.2, aarch64), where a RaspBee II on its UART joins a network, and in Ubuntu 24.04 (gcc 13.3) and Debian 13 (gcc 14.2) on x86_64, where a closed terminal ends in a read error, not in macOS's `POLLHUP` **measured**.
glibc fixes its feature set at the first system header and hides POSIX under `-std=c99`, so `port_posix.c` defines its level before any include and each tool that sleeps names `_POSIX_C_SOURCE`.
The contract does not move with them: no `speed_t`, `ssize_t`, `socklen_t`, `struct timespec` or any other platform type appears in `port.h`, and baud stays a `uint32_t` that each implementation maps to whatever its platform calls 115200.

## 4. Deadlines, not timers

The clock is the platform's and exists nowhere else; the backend the build links defines it:

```c
uint32_t Port_NowMs(void);
```

| Rule | Reason |
| --- | --- |
| monotonic and free-running, an arbitrary epoch, milliseconds | a deadline is a subtraction only if the counter never steps backwards and every caller reads the same one |
| one wrap every 2^32 ms: 49.7 days | the counter is a `uint32_t` like every count in this stack, so the wrap is arithmetic to be measured rather than avoided |
| a target whose clock is not monotonic defines no `Port_NowMs`, so the build fails to link | wall-clock time read as a deadline never expires, and a device that goes quiet is the worst way to fail; an unimplemented clock is absent rather than approximated (`docs/internals/coding-rules.md` §1) |
| no port is asked for | the counter is the platform's, and runs whether or not a link does |
| `nowMs` stays a parameter above band C | `docs/internals/coding-rules.md` §4.1: the layers above never read a clock, so a suite drives them with a number it chose and the tools read the one the platform reports |

Bands A and B own deadlines and never own timers: a wait is a deadline compared on a turn, so the caller turns the library every few milliseconds, as the examples do.
A query for the earliest pending deadline, `Zb_NextDeadline`, is planned and not built (`docs/internals/testing.md` §2); with it a host would `poll()` with that timeout, a microcontroller wait for an interrupt or that instant, and WASM set one timer.
A deadline is then compared as a distance and never as two numbers: `Zb_timeReached(nowMs, deadlineMs)` and `Zb_timeWithin(nowMs, startMs, windowMs)` (`src/utils/zb_time.h`, D-277) are the two comparisons, and a span shorter than 2^31 ms (24.8 days) is measured correctly across the wrap in either direction, a suite drives both directions, and the `nwk` suite drives a real retry across it.
Sub-millisecond sleeping and any symbol-level timing are not portable, must not appear in band A or B, and are decision 20's problem, where the only legitimate owner is the radio.

## 5. Persistence as a snapshot, not a service

Band C provides **no** storage (decision 23): bands A and B own the snapshot and the application decides where its bytes live.
The proposal, its gains, its costs and the keyed-blob alternative it rejects are the body of `docs/internals/decisions.md` D-23.

## 6. The portability gate

"Portable" is a claim about the build, not about the prose: the gates are `docs/internals/testing.md` §2's (`bands`, `freestanding`, `vendor`, `port_conformance`) run over the targets `docs/internals/testing.md` §6.1 lists, and what they demand of a port is that `port_posix.c` is the only file including a platform header and that every behavioural difference reaches bands A and B as a capability flag from `caps` (`docs/internals/architecture.md` §4, decision 13).

Which target is implemented, stubbed or parked is `docs/internals/testing.md` §6.1.
