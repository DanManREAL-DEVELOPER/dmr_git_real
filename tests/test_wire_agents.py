"""Tests for `gitreal --wire-agents` (the agent-hook installer).

Verifies: creates AGENTS.md when no rule file exists; idempotent (never duplicates the
managed block); updates existing rule files in place without clobbering their content;
replaces a stale block; points at .git-real/git-real.json; carries no em-dashes.

Run:  python tests/test_wire_agents.py   (exit 0 = all pass)
"""
import os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import gitreal

B, E = gitreal.WIRE_BEGIN, gitreal.WIRE_END


def _read(p):
    with open(p, "r", encoding="utf-8") as fh:
        return fh.read()


def main():
    passed = failed = 0

    def check(label, cond):
        nonlocal passed, failed
        ok = bool(cond)
        passed += ok
        failed += (not ok)
        print(("PASS" if ok else "FAIL"), label)

    # block sanity: points at the verdict file, matched delimiters, no em-dash
    block = gitreal.wire_block()
    check("block points at .git-real/git-real.json", ".git-real/git-real.json" in block)
    check("block has matched delimiters", B in block and E in block)
    check("block contains no em-dash", chr(0x2014) not in block)

    # 1) no rule file exists -> creates AGENTS.md only
    d = tempfile.mkdtemp()
    res = gitreal.wire_agents(d)
    check("creates AGENTS.md when none exist", res.get("AGENTS.md") == "created")
    check("does not create CLAUDE.md", not os.path.exists(os.path.join(d, "CLAUDE.md")))
    check("AGENTS.md carries the hook", ".git-real/git-real.json" in _read(os.path.join(d, "AGENTS.md")))

    # 2) idempotent: a second run never duplicates the block
    gitreal.wire_agents(d)
    content = _read(os.path.join(d, "AGENTS.md"))
    check("exactly one BEGIN delimiter after re-run", content.count(B) == 1)
    check("exactly one END delimiter after re-run", content.count(E) == 1)

    # 3) existing rule file updated in place, original content preserved
    d2 = tempfile.mkdtemp()
    claude = os.path.join(d2, "CLAUDE.md")
    with open(claude, "w", encoding="utf-8") as fh:
        fh.write("# My project rules\n\nKeep it simple.\n")
    res2 = gitreal.wire_agents(d2)
    c2 = _read(claude)
    check("existing CLAUDE.md wired (inserted)", res2.get("CLAUDE.md") == "inserted")
    check("original content preserved", "Keep it simple." in c2)
    check("hook appended to CLAUDE.md", B in c2 and ".git-real/git-real.json" in c2)
    check("AGENTS.md not created when a target exists", "AGENTS.md" not in res2)

    # 4) a stale/edited block is replaced, not duplicated, surroundings intact
    with open(claude, "w", encoding="utf-8") as fh:
        fh.write("# rules\n\n" + B + "\nstale hook text\n" + E + "\n\ntail line\n")
    gitreal.wire_agents(d2)
    c3 = _read(claude)
    check("stale block replaced", "stale hook text" not in c3)
    check("still exactly one block after replace", c3.count(B) == 1 and c3.count(E) == 1)
    check("surrounding content preserved on replace", "# rules" in c3 and "tail line" in c3)
    check("replaced block points at verdict file", ".git-real/git-real.json" in c3)

    # 5) all three targets wired when all exist
    d3 = tempfile.mkdtemp()
    for n in ("CLAUDE.md", "AGENTS.md", ".cursorrules"):
        open(os.path.join(d3, n), "w").close()
    res3 = gitreal.wire_agents(d3)
    check("wires all three existing targets", set(res3) == {"CLAUDE.md", "AGENTS.md", ".cursorrules"})

    total = passed + failed
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
