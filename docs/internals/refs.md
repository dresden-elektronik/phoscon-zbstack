# References

The corpora this project reads, what each is for, and what it may never be used for.
**After reading** you can tell whether a piece of code may be read, copied or vendored here, and which source outranks which.
Nothing read here is modified, built into, or vendored into the tree, except what `vendor/` pins (§6).

## 1. Corpus and license posture

| Source | What it is | License | Role here |
| --- | --- | --- | --- |
| Zigbee Core Specification R23.1, document 05-3474-23, Connectivity Standards Alliance | the PHY, MAC, NWK, APS, AF, ZDO and security layers, annexes included | CSA copyright, served by CSA at no charge | **normative** for everything above the radio; CSA now lists R23.2 as the current revision (§1.2) |
| Zigbee Cluster Library Specification, document 07-5123, revision R8 | chapter 2's foundation (frame formats, general commands, data types, statuses) and chapter 3's clusters, Basic among them | Zigbee Alliance copyright, served by CSA at no charge | **normative** for `src/zb/zcl/` |
| IEEE Std 802.15.4-2024, "IEEE Standard for Low-Rate Wireless Networks" | the active compilation of 802.15.4-2020 with 802.15.4z-2020, 802.15.4aa-2022 and 802.15.4-2020/Cor 1-2022 | IEEE copyright, free through the IEEE GET 802 program | **normative** for the MAC |
| IEEE Std 802.15.4-2006 | wireless MAC and PHY for low-rate WPANs | IEEE copyright | the only source of the numeric MAC status-code enumeration (`docs/internals/protocol.md` §9.2) and of the clause numbers Zigbee's own references were written against |
| FIPS PUB 197, "Advanced Encryption Standard" (NIST, 2001) | the AES block cipher | U.S. Government work, public domain | **normative** for the `src/crypto/` block cipher; the suite's block KAT is appendix C.1, the S-box spot values appendix A.1 |
| NIST SP 800-38A | block cipher modes, CTR | U.S. Government work, public domain | **normative** for `Aes_CtrCipher`; vectors appendix F.5.1 |
| NIST SP 800-38B | the CMAC mode | U.S. Government work, public domain | **normative** for `Aes_Cmac`; vectors appendix D.1, the same set as RFC 4493 |
| NIST SP 800-38C | the CCM mode | U.S. Government work, public domain | CCM reference and vectors (appendix C); the stack's CCM* follows IEEE 802.15.4-2024 Annex B, which agrees with it for M ≤ 8 |
| OpenThread, <https://github.com/openthread/openthread> | the reference Spinel/HDLC implementation, host and RCP sides | BSD-3-Clause / Apache-2.0 | **primary protocol source** for Spinel and HDLC semantics: the host-side RCP client (`radio_spinel.cpp`), the property and capability tables, the unit tests |
| zigbee-on-host, <https://github.com/Nerivec/zigbee-on-host> | a host-side Zigbee stack over an OpenThread RCP, TypeScript | **GPL-3.0** | layer map, protocol tables, feature decomposition. **No code import**: copyleft, and this tree is BSD-3-Clause (D-19) |
| Phoscon RCP 0.2.0, <https://github.com/dresden-elektronik/phoscon-rcp> | the Spinel radio co-processor firmware every supported device runs | BSD-3-Clause | **spec source** for the DSPINEL dialect (`docs/internals/protocol.md` §8, `docs/internals/hardware.md` §1). Not a code donor; see §4 |
| deconz-lib, <https://github.com/dresden-elektronik/deconz-lib> | the deCONZ host-side shared library (C), with its `u_assert.h` invariant macro | BSD style (per its file headers) | shape reference only for `src/utils/zb_assert.h`: not a code donor, no line transcribed; the divergences are D-41 |
| gcfflasher, <https://github.com/dresden-elektronik/gcfflasher> | cross-platform ConBee/RaspBee flasher (C) | BSD style, its own `LICENSE.txt` | the tool that flashes Phoscon RCP; and the coarse pattern reference for band C: a shared core plus one `.c` per platform family selected by CMake, `termios` on POSIX against `DCB`/`COMMTIMEOUTS` on Windows |
| `vendor/u_bstream/` | upstream `~cryo/u_bstream`, pinned `e4ed3be5c203…` | 3-clause BSD | **vendored**: built and used as written (§6), the bounded byte-stream reader/writer under every codec |
| `vendor/u_sstream/` | upstream `~cryo/u_sstream`, pinned `03f45b897141…`, with its own tests | 3-clause BSD | **vendored**: libc-free text building and parsing for diagnostics and tool output (§6) |

### 1.1 The specs are the authority; implementations are evidence

The specifications outrank every implementation in this table.
An implementation (however good, however close to the shipping firmware, however widely used) records what some authors believed the protocol to be, at some date, with their own bugs, their own subset, and their own obsolete normative references.
It answers "how do people get this behaviour working"; it never answers "what is the protocol".

Precedence for a protocol question:

1. the relevant clause of a specification in §1: claim marker **spec**;
2. a measurement on one of our RCPs: **measured**; authoritative about our devices, never about the protocol;
3. a reference implementation: **upstream**;
4. inference from captured frames, stated as an inference.

A measurement that contradicts a specification is recorded as a device deviation plus an open question (`docs/internals/protocol.md` §10), never as a licence to follow the device.
An implementation that contradicts a specification is a defect: the stack follows the specification, and where interoperation forces us to meet the deviation, that deviation is named in the doc that owns it.

Revision matters as much as authority.
Zigbee R23.1 assumes the MAC and PHY of IEEE Std 802.15.4-2020 (Annex D.1.2) and defines joining frames in terms of 802.15.4-2020 Information Elements (Annex D.11); this stack follows the active compilation of that revision, **802.15.4-2024**, and reads 802.15.4-2006 beside it.
Reading the two against each other is part of the job: 802.15.4-2024 renumbers Clause 7 wholesale (the frame control field is 7.2.2 / Figure 7-2, the acknowledgment is 7.3.3 / Figure 7-15, the command list is Table 7-11), renumbers the frame types after the four it inherited (Table 7-1 prints 4 Reserved, 5 Multipurpose, 6 Fragment, 7 Extended), and *drops* the numeric MAC status enumeration that 802.15.4-2006 Table 78 supplies and that Zigbee Annex D.2 still cites, so a citation must name the edition it came from, and R23.1's pointer to clause 7.4.4.6 of 802.15.4-2020 has to be read as 7.4.4.2 of the held 802.15.4-2024.

This rule is not hypothetical: a frame-control layout inherited from two earlier implementations was the 802.15.4-2003 one, wrong in the flags and impossible for acknowledgment frames, and both carried the same mistake because both placed the same fields in the same octets; `docs/internals/protocol.md` §9.1 records the correction.

The spec PDFs are copyright of CSA and IEEE: read them, cite clause numbers, quote short passages with attribution.
They are reference material, not donors, and no copy of one is part of this tree.

### 1.2 How the standards are obtained, and which revision is current

| Document | Status at the publisher | How an individual gets it |
| --- | --- | --- |
| **IEEE 802.15.4-2024** (DOI 10.1109/IEEESTD.2024.10794632) | **Active Standard**, superseding 802.15.4-2020 | free through the IEEE GET 802 program |
| IEEE 802.15.4-2020 and older editions | superseded | purchase only |
| **Zigbee Core R23.2**, document 06-3474-23 | CSA's current Zigbee Core specification | free from `csa-iot.org/developer-resource/specifications-download-request/`, after accepting CSA's copyright agreement |
| Zigbee Core R23.1 (05-3474-23), R22.1, ZCL R8 and R7, Base Device Behavior, Green Power, Zigbee Direct, Smart Energy | listed and served by CSA | the same page, the same agreement |

Annexes are inside the base PDF: R23.1 carries Annex A (CCM*), B (security building blocks), C (test vectors), **D (MAC and PHY sub-layer clarifications)**, G (inter-PAN) and J (ECDHE processing).
CSA's agreement states the document is provided at no charge, that CSA remains the copyright holder, and that the document is not in the public domain.
The IE framework, the Enhanced Beacon Request (7.5.3) and the Enhanced Beacon Filter IE (7.4.4.2) are fully specified in 802.15.4-2024; only Zigbee's own payload IEs are Zigbee-only, defined by R23.1's own tables (Vendor Specific Nested IEs under OUI 0x4A191B).

## 2. What to read in OpenThread

Priority order:

| File | Why |
| --- | --- |
| `src/lib/hdlc/hdlc.cpp` | the framing our §2 of `docs/internals/protocol.md` implements |
| `src/lib/spinel/spinel.c` | `spinel_packed_uint_encode/decode`, `spinel_datatype_pack` format strings |
| `src/lib/spinel/spinel_encoder.cpp`, `spinel_decoder.cpp` | exact typed-value rules, struct length prefixes, truncation behaviour |
| `src/ncp/ncp_base.cpp`, `ncp_base_radio.cpp`, `ncp_base_dispatcher.cpp` | the **NCP side**: what a command does, which handlers are compiled in a radio build, how responses are queued (the TID rule), `PackRadioFrame`, `DecodeStreamRawTxRequest` |
| `src/lib/spinel/radio_spinel.cpp` (upstream only) | a complete host-side RCP client: handshake, capability negotiation, raw TX/RX, sleep, energy scan |
| `src/lib/spinel/spinel_driver.cpp` (upstream only) | TID policy: upstream uses TID 1 for everything and relies on in-order replies |
| `tests/unit/test_hdlc.cpp`, `test_spinel_encoder.cpp`, `test_spinel_decoder.cpp` | vectors to compare against (`docs/internals/testing.md` §2.1) |

### 2.1 Test infrastructure worth copying in shape

| Path | What it is | What we take |
| --- | --- | --- |
| `tests/unit/test_hdlc.cpp` | framing cases including sync handling, plus a 50 000-iteration random-frame section inside the unit test | the model for our `hdlc` fault-injection suite |
| `tests/unit/test_spinel_encoder.cpp`, `test_spinel_decoder.cpp`, `test_spinel_buffer.cpp` | type-by-type vectors, truncation and buffer cases | vectors and case lists for `spinel_codec` |
| `tests/fuzz/ncp_hdlc_received.cpp`, `radio_receive_done.cpp` | random HDLC fed into the NCP receive path; the RCP receive-command path | our fixed-seed random-stream test covers the same interface |
| `tests/toranj/ncp/` | 43 black-box NCP protocol tests driven over a real link | the shape of the rig layer in `docs/internals/testing.md` §3 |
| `tests/scripts/expect/posix-rcp.exp` | a scripted session against an RCP-backed NCP | the shape of a repeatable hardware smoke run |

When a device behaves oddly, read the source at the firmware's own revision, not at the newest one.

## 3. Flashing and board facts

Phoscon RCP's own documents map the family (MCU, radio, host link, bootloader layout) and give the packaging and flash pipeline with its mandatory pre-flash check.
Two facts that bind us: the flash path ends in a **bootloader trap** triggered by a specific 16-byte host frame, so a stray write can drop an RCP into the bootloader; this stack never writes that frame and never flashes an RCP.

## 4. The oracle rule

Phoscon RCP treats this repository as an **independent implementation that has never seen its firmware**, and uses it as a cross-check on its own.
That value exists only if the independence is real:

- our Spinel/HDLC codec is derived from OpenThread and from measurements on the wire;
- Phoscon RCP's documents are consulted to *interpret* behaviour and to record its published property set, never to copy an algorithm or a table verbatim into our source;
- where its documentation and our measurement disagree, the measurement is recorded as a measurement and the disagreement is listed in `docs/internals/protocol.md` §10.

## 5. What may be a code donor

**Nothing outside `vendor/`.**
`docs/internals/coding-rules.md` §1 requires `src/` to be written from scratch.
Reference corpora may be read, quoted in documentation with attribution, and used as test-vector sources; they may not be copied, restyled, or linked.
§6 governs the one exception: code that is used as written, under its own licence, at a pinned revision.
The GPL-3.0 and proprietary entries are additionally off-limits as *semantic* donors for anything we ship, to keep provenance clean.
The specifications are normative authority, not donors either: a table we transcribe from a spec is our own encoding of a clause we cite.

## 6. Vendored code

`vendor/` holds third-party code that this stack **builds and uses as written**.
It exists because the alternative is writing plumbing that already exists, is licensed permissively, carries its own tests, and because a libc-free stack needs a libc-free place to put bytes and text.

| Library | Upstream | Pinned revision | Newest tag | Licence | What it is for here |
| --- | --- | --- | --- | --- | --- |
| `u_bstream` | `https://git.sr.ht/~cryo/u_bstream` (`~cryo/utils`) | `e4ed3be5c20331f40c388218f308a589ff9f47eb` | `v1.3.0` | 3-clause BSD, `vendor/u_bstream/LICENSE.txt` | the bounded byte-stream reader/writer every codec is built on: `u8/u16/u32/u64` little- and big-endian, signed variants, byte runs, the unsigned 32-bit varint and zigzag LEB128 |
| `u_sstream` | `https://git.sr.ht/~cryo/u_sstream` (`~cryo/utils`) | `03f45b897141d1a29a22157a9e0d07089f2d41ed` | `v1.5.2` | 3-clause BSD, `vendor/u_sstream/LICENSE.txt` | bounded text: `put_hex`, `put_long`, `put_str`, `find`, `compare`, and the libc-free `U_strtol`/`U_strtod`, the host-side rendering that `docs/internals/coding-rules.md` §5 requires without `printf`, and later diagnostics and tool output |

| Rule | Reason |
| --- | --- |
| Vendored files are **verbatim**: no renaming, no restyling, no local patch, no reformatting | a vendored copy that drifts is a fork with someone else's copyright on it, and it silently becomes *our* bug to carry |
| An application that links its own copy at the same tags names it, and `vendor/` is then not compiled; its headers are hashed against `vendor/MANIFEST` at configure (D-290) | one copy of a library per executable, and the pin still holds for what the tree compiles against |
| `vendor/MANIFEST` pins the upstream URL, the commit, the licence file and the sha256 of every vendored file; the `vendor` suite re-hashes the tree and fails the build on any drift, including a file that is present but not pinned | "we did not modify it" has to be a measured claim (verified by test: appending a comment to a vendored header fails the suite) |
| The libraries are **used as they are**: no local edit, and no expectation that upstream changes for us. Where a capability is missing, the adapting layer is ours, above the vendored code: for `U_BStream` it is `src/utils/zb_bstream.h`, the `Zb_bstream_` calls | `u_bstream` read big-endian but did not write it before `v1.3.0`, so our property layer wrote those octets with `put_u8` (`docs/internals/coding-rules.md` §1) until the writers came from upstream (`docs/internals/coding-rules.md` §1). GCFFlasher added `U_bstream_put_u32_be` to its own copy of the library: the drift this rule forbids. Our own primitives in `src/utils/` (`Zb_memcpy`, `Zb_memset`, `Zb_memcmp`, `Zb_strlen`) are ours, written to our rules with our widths, and carry our prefix, since `U_` is the u_* libraries' (`docs/internals/coding-rules.md` §2) |
| The vendored library's own tests are vendored with it and run as suites | `u_sstream`'s own tests are its conformance. `u_bstream` ships **none**, so this repository writes its own gate (`test/test_u_bstream.c`): the pin exists because of a `u_bstream` behaviour, and that behaviour must be asserted, not assumed |
| Vendored code is exempt from the naming, `uint32_t`-count and no-literal-suffix rules of `docs/internals/coding-rules.md` §1 and §6: it is not our style; it is still held to the include graph, the no-allocation rule, and the ban on libc and platform headers in library code | the point of vendoring is that the code is *theirs*; the point of the gate is that what reaches our bands is still allocation-free and libc-free (verified: each `.c` includes only its own header) |
| Its types are crossed, not harmonised: `u_bstream` speaks `unsigned long`, `u_sstream` plain `unsigned`, our bands speak `uint32_t`, and the conversion is an explicit cast at the call, in our code, or inside `src/utils/zb_bstream`, whose calls take `uint32_t` | the alternative is editing the vendored signatures, which this section forbids; the narrowing is bounded because every buffer length in this stack is a named constant at most `PORT_FRAME_MAX` (`docs/internals/conformance.md` §6), and the `u_bstream` suite pins the pattern |
| Nothing copyleft or proprietary is ever vendored | the GPL-3.0 corpus and the proprietary vendor firmware stay out (§5), whatever their technical merit |
| The pin is a commit, not a tag, where a tag is wrong for this build | `u_bstream` `v1.2.0` gates its 64-bit accessors on `__STDC_VERSION__ >= 201112L`, i.e. C11; under this tree's `-std=c99` they would silently vanish. The fix to `>= 199901L` was pinned as a commit until `v1.3.0` carried it, and `u_bstream` is pinned at that tag |

Upstream also carries, per the sourcehut project `~cryo/utils`, a third small module (`u_library`, dynamic loading) that is **not** vendored: it is irrelevant here and would drag `dlopen`/`LoadLibrary` into the tree.
