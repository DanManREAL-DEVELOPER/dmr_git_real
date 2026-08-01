# The GIT_REAL Background Story

*Why a solo dev built a git tool for the age of AI agents, and the blind spot his own agent caught along the way.*

## Two years of fighting my own repos

I have been building with AI coding agents for about two years. Somewhere along the way my setup turned into eight to twelve terminals running at once, agents working in parallel across a pile of git worktrees, features expanding faster than I could track them, and work getting abandoned mid-stream the second a better idea showed up.

Git got wild. Dirty trees everywhere. Untracked files I did not recognize. Side branches an agent spun up and forgot about. And the moment that broke me every single time: an agent stops, looks at a working tree, and asks, "there is a dirty tree here, what do you want to do with it?" And I have no idea. Is it junk? Is it an hour of unsaved work I am one wrong keystroke away from nuking? I could not tell, and neither could the agent.

I tried everything to stay on top of it. Governance files. Notes. Discipline. It has been my number one pain point since the day I started.

## I went looking for this. It did not exist.

Before writing a single line, I did the honest thing and went hunting. Opened tabs on every tool I could find. Watched YouTube walkthroughs to see if any of them solved it. There are good git dashboards and good status tools out there, and I respect them. But I could not find one that did the specific thing I needed: drop into any folder, track the whole repo in real time, and then hand a clear verdict to the agents themselves so they stop guessing.

That gap is the entire reason GIT_REAL exists.

## So I built it

GIT_REAL is one file you drop into a repo. It tracks everything end to end and turns the question "what do I do with this tree?" into two numbers, recomputed live, each with its reasons spelled out:

- **Safe to Commit:** how clean a commit would be right now.
- **Safe to Discard:** how safe it is to nuke the dirty tree, or whether you are about to lose real work.

It classifies every file the moment it appears, flags secrets with a blinking alert and masks them so nothing leaks, tracks your branches and push state, and for the eight-to-twelve-worktree crowd it has a FLEET mode: one wall, every repo, scored and ranked, with anything dangerous flashing red.

But the part that actually matters, the thing I could not find anywhere else: GIT_REAL writes a machine-readable verdict to `.git-real/git-real.json`, and your agents read it before they commit or discard. There is even an MCP server so they can call it mid-task. Every other git tool renders your repo for a human to read. GIT_REAL writes a decision an agent acts on. That is the whole trick.

## The part I am proudest of, and it is a confession

I have a brand built on showing the machinery, so here is the machinery.

While I was prepping the launch, one of my own AI agents was helping me rename some folders, and it caught a blind spot in my secret scanner. My regex was missing a whole class of secrets: snake_case keys like `db_password`, and `aws_secret_access_key = "..."` value lines. The exact kind of thing that leaks into a repo and turns into a 2 a.m. incident. My own stress test had missed it. My agent did not.

We fixed it with two surgical regex changes and a nine-case regression test. And then I did the only honest thing I could think of: I put that exact secret into the demo, so the launch clip literally shows GIT_REAL catching the thing my own testing missed. That is not a polished marketing moment. It is the real one, and it is the one I wanted to show you.

That whole experience pushed the next feature too: secret-in-history detection, which tells you whether a secret was caught in time, or is already committed and needs to be rotated and scrubbed.

## It was built the way it is meant to be used

Here is the part I love most. GIT_REAL, the tool whose entire job is keeping AI agents honest, was itself built shoulder to shoulder with AI agents. More than one, running in parallel, reconciled through a shared report so nothing drifted between them. Which is exactly the kind of chaos GIT_REAL exists to make sane. The tool and its own origin turned out to be the same story.

## Why it is called GIT_REAL

My daughter named it. I was talking through options out loud, and she said, "how about GIT_REAL," like *get real*. It stuck instantly. It is on brand, it made me smile, and now her idea is on a public repo. That one is for her.

## It is yours

GIT_REAL is open source, MIT licensed. Drop it into a repo, point your agents at it, and never debug another agent's dirty tree again.

Get real about your repo.

*- DanManREAL*
