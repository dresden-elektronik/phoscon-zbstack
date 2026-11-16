#!/usr/bin/env python3
"""Runs tools/zb_mesh on every RCP of a bench and reads what the nodes printed.

    zb_mesh_bench.py sync
    zb_mesh_bench.py line <out> --nodes a b c d e f --tx --allow-tx
    zb_mesh_bench.py line <out> --nodes a b c d e f --lockstep --uni-ms 20 --tx --allow-tx
    zb_mesh_bench.py line <out> --nodes a b c d e --child f --lockstep --uni-ms 20 --tx --allow-tx
    zb_mesh_bench.py mesh <out> --coordinator a --tx --allow-tx
    zb_mesh_bench.py mesh <out> --coordinator a --uni-ms 1000 --leave c:120 --tx --allow-tx
    zb_mesh_bench.py report <out> [--against <earlier out>]

`line` makes each node hear only its two sides, so a frame end to end has to
route; the first name is the coordinator. With `--lockstep` only the
coordinator sends, one unicast at a time, and nobody broadcasts. `--child`
adds an end device that hears only the coordinator, its parent, and with
`--lockstep` it is the one that sends. `mesh` lets all of them hear each other. The defaults stay fixed, so
a new build can be held against an earlier one. Without `--tx --allow-tx` either
command prints what it would start, and opens nothing
(docs/internals/hardware.md §8).

The bench is a file of its own, because a port or a serial is no business of
the tree. `--bench` names it, tmp/mesh_bench.json by default:

    {"hosts": {"pi": {"ssh": "pi.local", "dir": "~/tree", "binary": "build/mesh/zb_mesh"}},
     "nodes": [{"name": "a", "path": "/dev/<port>", "baud": 115200, "ieee": "<eui64>"},
               {"name": "c", "host": "pi", "path": "/dev/<port>", "baud": 57600, "ieee": "<eui64>"}]}

A node with no `host` runs here. `sync` copies the tree to each host and builds
zb_mesh there and here, which a run does not do by itself.
"""

import argparse
import glob
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCAL_BINARY = os.path.join(ROOT, "build", "host", "zb_mesh")
EPID = "00000000beef0012"
SSH_FAILED = 255

# How a line is opened, one parent at a time (docs/internals/testing.md §7).
LINE_SECOND_NODE_S = 2
LINE_CHILD_S = 2                # the end device joins the coordinator first, so it hears every router announce itself
LINE_CHILD_SECOND_NODE_S = 4
LINE_THIRD_NODE_S = 15
LINE_NODE_GAP_S = 45
LINE_SETTLE_S = 45
MESH_NODE_GAP_S = 2
MESH_PERMIT_MAX_S = 250

SUMMARY_COUNTERS = (
    "refusedRequests", "forwardsRefused", "forwardsGivenUp", "linkFailuresReported", "routesInvalidated",
    "statusRoutesRemoved", "routeRequestsSent", "relaysSent", "droppedNoRoute", "bttFullDrops",
    "backbonePromotions", "rxFrameCounterRejects", "txWaitsExpired",
    "txResultsUncollected", "replyTimeouts", "resetsSeen",
)
NODE_COLUMNS = (
    "linkStatusSent", "linkStatusApplied", "droppedDuplicate", "relaysSent", "routeRequestsSent",
    "routeRepliesSent", "droppedNoRoute", "linkFailuresReported", "forwardsGivenUp", "backbonePromotions", "unheard",
)
TIMING_LIMITS = ("lt10", "lt20", "lt50", "lt100", "lt200", "lt500", "lt1000", "ge1000")
PROBLEM = re.compile(r"runtime error|AddressSanitizer|failed t=|stick lost|did not start|ERROR")


def load_bench(path):
    with open(path) as handle:
        bench = json.load(handle)

    bench["byName"] = {node["name"]: node for node in bench["nodes"]}

    return bench


def line_plan(names, traffic_s, uni_ms, bc_s, ghost_s, lockstep, child=None, forget_at=None, coordinator_permit=10):
    """Each node's start and arguments: permits close before the next parent opens, and each is deaf past its sides."""
    second = LINE_CHILD_SECOND_NODE_S if child else LINE_SECOND_NODE_S
    starts = [0 if i == 0 else second if i == 1 else LINE_THIRD_NODE_S + LINE_NODE_GAP_S * (i - 2)
              for i in range(len(names))]
    traffic_at = starts[-1] + LINE_SETTLE_S
    total = traffic_at + traffic_s
    plan = []

    for i, name in enumerate(names):
        permit = 0 if i == len(names) - 1 else coordinator_permit if i == 0 else 30 if i == 1 else 50
        sends = not lockstep or (i == 0 and not child)
        args = ["--role", "c" if i == 0 else "r", "--epid", EPID, "--permit", permit,
                "--seconds", total - starts[i], "--traffic-at", traffic_at - starts[i] - 2, "--to", "all",
                "--uni-ms", uni_ms if sends else 0,
                "--bc-s", 0 if lockstep else bc_s, "--ghost-s", 0 if lockstep else ghost_s]

        if lockstep and sends:
            args.append("--lockstep")

        if forget_at and i == 0:
            args += ["--forget-children-at", traffic_at + forget_at]

        if child and i != 0:
            args += ["--ignore", {"name": child}]

        for j, other in enumerate(names):
            if abs(i - j) > 1:
                args += ["--ignore", {"name": other}]

                if j == 0:
                    args += ["--ignore-short", 0]

        plan.append((starts[i], name, args))

    if child:
        args = ["--role", "e", "--epid", EPID, "--seconds", total - LINE_CHILD_S,
                "--traffic-at", traffic_at - LINE_CHILD_S - 2, "--to", "all",
                "--uni-ms", uni_ms, "--bc-s", 0 if lockstep else bc_s, "--ghost-s", 0 if lockstep else ghost_s]

        if lockstep:
            args.append("--lockstep")

        for other in names[1:]:
            args += ["--ignore", {"name": other}]

        plan.insert(1, (LINE_CHILD_S, child, args))

    return plan


def mesh_plan(names, coordinator, seconds, uni_ms, bc_s, ghost_s, leave):
    order = [coordinator] + [name for name in names if name != coordinator]
    plan = []

    for i, name in enumerate(order):
        args = ["--role", "c" if name == coordinator else "r", "--epid", EPID,
                "--permit", min(seconds, MESH_PERMIT_MAX_S) if name == coordinator else 0,
                "--seconds", seconds - i * MESH_NODE_GAP_S, "--uni-ms", uni_ms, "--bc-s", bc_s, "--ghost-s", ghost_s]

        if leave and leave.split(":")[0] == name:
            args += ["--leave-at", leave.split(":")[1]]

        plan.append((i * MESH_NODE_GAP_S, name, args))

    return plan


def node_command(bench, name, args, trace):
    """The argv that starts one node, here or over ssh."""
    node = bench["byName"][name]
    words = ["--tx", "--allow-tx", "--path", node["path"], "--baud", str(node["baud"])]

    for arg in args:
        words.append(bench["byName"][arg["name"]]["ieee"] if isinstance(arg, dict) else str(arg))

    if trace:
        words.append("--trace")

    if "host" not in node:
        return [LOCAL_BINARY] + words

    host = bench["hosts"][node["host"]]
    remote = "cd %s && exec %s %s" % (host["dir"], host["binary"], " ".join(shlex.quote(word) for word in words))

    return ["ssh", "-o", "BatchMode=yes", host["ssh"], remote]


def port_users(bench, name):
    """What holds a node's port now: one session per port, and the platform enforces none (docs/internals/hardware.md §8)."""
    node = bench["byName"][name]

    if "host" in node:
        host = bench["hosts"][node["host"]]
        command = ["ssh", "-o", "BatchMode=yes", host["ssh"], "fuser %s 2>/dev/null" % shlex.quote(node["path"])]
    elif shutil.which("lsof"):
        command = ["lsof", "-t", "--", node["path"]]
    else:
        return ""

    asked = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    return "could not ask" if asked.returncode == SSH_FAILED else asked.stdout.strip()


def run_plan(bench, plan, out, trace, allowed):
    if not allowed:
        for start, name, args in plan:
            print("+%4ds %s: %s" % (start, name, shlex.join(node_command(bench, name, args, trace))))

        print("nothing started: a run takes --tx and --allow-tx (docs/internals/hardware.md §8)")
        return 0

    busy = [(name, users) for _, name, _ in plan for users in [port_users(bench, name)] if users]

    if busy:
        print("not started, a port is in use or could not be checked: %s" % busy)
        return 1

    os.makedirs(out)
    began = time.monotonic()
    running = []

    try:
        for start, name, args in plan:
            time.sleep(max(0, start - (time.monotonic() - began)))

            with open(os.path.join(out, name + ".txt"), "w") as log:
                running.append(subprocess.Popen(node_command(bench, name, args, trace), stdout=log,
                                                stderr=subprocess.STDOUT))

        failed = sum(1 for process in running if process.wait() != 0)
    finally:
        for process in running:
            if process.poll() is None:
                process.terminate()

    for label in sorted({bench["byName"][name].get("host") for _, name, _ in plan} - {None}):
        after = subprocess.run(["ssh", "-o", "BatchMode=yes", bench["hosts"][label]["ssh"],
                                "pgrep -a zb_mesh; vcgencmd get_throttled"],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        with open(os.path.join(out, label + "_after.txt"), "w") as log:
            log.write(after.stdout)

    print("done: %s, %d node(s) exited with a failure" % (out, failed))

    return 0


def sync(bench):
    status = subprocess.run(["cmake", "--build", os.path.dirname(LOCAL_BINARY), "--target", "zb_mesh"]).returncode

    for host in bench.get("hosts", {}).values():
        copied = subprocess.run(["rsync", "-a", "--exclude", "build", "--exclude", ".git", "--exclude", "tmp",
                                 "--exclude", "refs", ROOT + "/", "%s:%s/" % (host["ssh"], host["dir"].replace("~/", ""))])
        built = subprocess.run(["ssh", "-o", "BatchMode=yes", host["ssh"], "cd %s && cmake --build %s --target zb_mesh"
                                % (host["dir"], os.path.dirname(host["binary"]))])
        status = status or copied.returncode or built.returncode

    return status


def read_run(path):
    """Every node's printed summaries, keyed by the bench's name for it."""
    run = {"names": [], "self": {}, "up": {}, "counters": {}, "tx": {}, "rx": {}, "neighbors": {}, "routes": {},
           "ghost": {}, "broadcast": {}, "timing": {}, "slow": {}, "problems": [], "hosts": {}}

    for file in sorted(glob.glob(os.path.join(path, "*.txt"))):
        name = os.path.basename(file)[:-4]

        if name.endswith("_after"):
            with open(file, errors="replace") as handle:
                run["hosts"][name[:-len("_after")]] = handle.read().strip()
            continue

        run["names"].append(name)

        with open(file, errors="replace") as handle:
            for line in handle:
                fields = dict(re.findall(r"(\w+)=(\S+)", line))

                if line.startswith("up "):
                    run["up"][name] = fields
                    run["self"][fields["self"]] = name
                elif line.startswith("nwkstat"):
                    run["counters"][name] = fields
                elif line.startswith("txsum"):
                    run["tx"][(name, fields["dst"])] = fields
                elif line.startswith("rxsum"):
                    run["rx"][(name, fields["src"])] = fields
                elif line.startswith("neighbor"):
                    run["neighbors"].setdefault(name, []).append(fields)
                elif line.startswith("route "):
                    run["routes"].setdefault(name, []).append(fields)
                elif line.startswith("timing"):
                    run["timing"][(name, fields["kind"])] = fields
                elif line.startswith("slowreply"):
                    run["slow"].setdefault(name, []).append(fields)
                elif line.startswith("ghostsum"):
                    run["ghost"][name] = fields
                elif line.startswith("bcsum"):
                    run["broadcast"][name] = fields
                elif PROBLEM.search(line):
                    run["problems"].append((name, line.strip()[:150]))

    return run


def run_totals(run):
    totals = {"taken": 0, "ok": 0, "noAck": 0, "noRoute": 0, "other": 0, "refused": 0, "delivered": 0, "twice": 0}

    for (name, dst), sent in run["tx"].items():
        for key in ("taken", "ok", "noAck", "noRoute", "other", "refused"):
            totals[key] += int(sent[key])

        received = run["rx"].get((run["self"].get(dst, dst), run["up"][name]["self"]), {})
        totals["delivered"] += int(received.get("uni", 0))
        totals["twice"] += int(received.get("uniDup", 0))

    for key in SUMMARY_COUNTERS:
        totals[key] = sum(int(counters.get(key, 0)) for counters in run["counters"].values())

    return totals


def print_run(run):
    print("node    up   self  " + " ".join(column[:9].rjust(9) for column in NODE_COLUMNS))

    for name in run["names"]:
        counters = run["counters"].get(name)

        if counters is None:
            print("%-6s no counters" % name)
            continue

        print("%-6s %3s %s  " % (name, run["up"].get(name, {}).get("t", "-"), counters["self"])
              + " ".join(counters.get(column, "-").rjust(9) for column in NODE_COLUMNS))

    print("\nunicast  from->to  taken    ok noAck noRoute other refused attempts delivered(twice)")

    for (name, dst), sent in sorted(run["tx"].items()):
        to = run["self"].get(dst, dst)
        received = run["rx"].get((to, run["up"][name]["self"]), {})
        print("  %6s->%-6s %5s %5s %5s %7s %5s %7s %8s %s(%s)"
              % (name, to, sent["taken"], sent["ok"], sent["noAck"], sent["noRoute"], sent["other"], sent["refused"],
                 sent["attempts"], received.get("uni", "-"), received.get("uniDup", "-")))

    print("\nbroadcast: sender taken ok, then what each other node received(twice)")

    for name in run["names"]:
        if name in run["broadcast"] and name in run["up"]:
            sent = run["broadcast"][name]
            source = run["up"][name]["self"]
            heard = " ".join("%s:%s(%s)" % (other, run["rx"].get((other, source), {}).get("bc", "-"),
                                            run["rx"].get((other, source), {}).get("bcDup", "-"))
                             for other in run["names"] if other != name)
            print("  %6s %4s %4s  %s" % (name, sent["taken"], sent["ok"], heard))

    print("\nneighbours: peer/relationship/cost/lqa/routerAge/txFail")

    for name in run["names"]:
        print("  %-6s" % name, " ".join(
            "%s/%s/c%s/q%s/a%s/f%s" % (run["self"].get(entry["addr"], entry["addr"]), entry["rel"], entry["cost"],
                                       entry["lqa"], entry["routerAge"], entry["txFail"])
            for entry in run["neighbors"].get(name, [])))

    print("\nroutes: destination>next hop/status")

    for name in run["names"]:
        print("  %-6s" % name, " ".join(
            "%s>%s/%s" % (run["self"].get(entry["dst"], entry["dst"]), run["self"].get(entry["next"], entry["next"]),
                          entry["status"])
            for entry in run["routes"].get(name, [])))

    if run["timing"]:
        print("\nrequest timing, ms: how many answered within each limit")
        print("  node   kind         n  max " + " ".join(limit.rjust(6) for limit in TIMING_LIMITS))

        for (name, kind), timing in sorted(run["timing"].items()):
            if timing["n"] != "0":
                print("  %-6s %-7s %6s %4s " % (name, kind, timing["n"], timing["max"])
                      + " ".join(timing[limit].rjust(6) for limit in TIMING_LIMITS))

    for name, slow in sorted(run["slow"].items()):
        print("  slow on %s: %s" % (name, " ".join("%s:%s" % (entry["at"], entry["ms"]) for entry in slow)))

    for label, text in sorted(run["hosts"].items()):
        print("\nafter the run on %s: %s" % (label, text))

    print("\nproblems:", run["problems"][:30] if run["problems"] else "none")


def print_totals(run, earlier):
    totals = run_totals(run)
    base = run_totals(earlier) if earlier else None

    print("\ntotals" + ("                          earlier" if base else ""))

    for key, value in totals.items():
        print("  %-24s %7d" % (key, value) + ("  %7d" % base[key] if base else ""))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bench", default=os.path.join(ROOT, "tmp", "mesh_bench.json"))
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("sync")

    report = commands.add_parser("report")
    report.add_argument("out")
    report.add_argument("--against")

    line = commands.add_parser("line")
    line.add_argument("--nodes", nargs="+", required=True)
    line.add_argument("--traffic", type=int, default=240)
    line.add_argument("--lockstep", action="store_true")
    line.add_argument("--child", help="an end device whose parent is the coordinator")
    line.add_argument("--forget-at", type=int, help="seconds into the traffic: the coordinator forgets its children")
    line.add_argument("--coordinator-permit", type=int, default=10, help="seconds the coordinator permits joining")

    mesh = commands.add_parser("mesh")
    mesh.add_argument("--coordinator", required=True)
    mesh.add_argument("--seconds", type=int, default=190)
    mesh.add_argument("--leave", help="name:seconds, a router that leaves")

    for command, uni_ms in ((line, 1000), (mesh, 200)):
        command.add_argument("out")
        command.add_argument("--uni-ms", type=int, default=uni_ms)
        command.add_argument("--bc-s", type=int, default=10)
        command.add_argument("--ghost-s", type=int, default=30)
        command.add_argument("--trace", action="store_true")
        command.add_argument("--channel", type=int, choices=range(11, 27), default=12)
        command.add_argument("--protect-channel", type=int, action="append", default=[],
                             help="a channel no node may arm on; repeatable, passed to every zb_mesh")
        command.add_argument("--protect-pan", action="append", default=[],
                             help="a PAN in hex no node may use; repeatable, passed to every zb_mesh")
        command.add_argument("--tx", action="store_true")
        command.add_argument("--allow-tx", action="store_true")

    options = parser.parse_args()

    if options.command == "report":
        run = read_run(options.out)
        print_run(run)
        print_totals(run, read_run(options.against) if options.against else None)
        return 0

    bench = load_bench(options.bench)

    if options.command == "sync":
        return sync(bench)

    named = options.nodes + ([options.child] if options.child else []) if options.command == "line" \
        else [options.coordinator]

    if options.command == "mesh" and options.leave:
        named = named + [options.leave.split(":")[0]]

    unknown = [name for name in named if name not in bench["byName"]]

    if unknown:
        print("not on this bench: %s" % unknown)
        return 2

    if os.path.exists(options.out):
        print("%s exists, and a run does not write over an earlier one" % options.out)
        return 2

    if options.command == "line":
        plan = line_plan(options.nodes, options.traffic, options.uni_ms, options.bc_s, options.ghost_s, options.lockstep,
                         options.child, options.forget_at, options.coordinator_permit)
    else:
        plan = mesh_plan([node["name"] for node in bench["nodes"]], options.coordinator, options.seconds,
                         options.uni_ms, options.bc_s, options.ghost_s, options.leave)

    if options.channel != 12:
        plan = [(start, name, args + ["--channel", options.channel]) for start, name, args in plan]

    protect = [arg for channel in options.protect_channel for arg in ("--protect-channel", channel)]
    protect += [arg for pan in options.protect_pan for arg in ("--protect-pan", pan)]

    if protect:
        plan = [(start, name, args + protect) for start, name, args in plan]

    return run_plan(bench, plan, options.out, options.trace, options.tx and options.allow_tx)


if __name__ == "__main__":
    sys.exit(main())
