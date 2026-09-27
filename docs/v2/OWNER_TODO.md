# Owner to-do (needs your accounts or admin rights)

Things a Claude Code cloud session cannot do for you: its GitHub access refuses tag pushes and
repository-settings changes, and it has no PyPI account. Work top to bottom; delete items as you
finish them, and this file once it is empty.

_Last updated: 2026-09-27 (after M1)._

## 1. GitHub: land v2 on `main` (about 10 minutes)

Order matters: tag v1 **before** merging, while `main` still points at the last v1 commit.

1. **Tag the last v1 commit.** The README already links to this tag.

   ```bash
   git fetch origin
   git rev-parse origin/main            # must print 534c9b1b8164a1ea5a0cf33c1d7403b8a5c1281c
   git tag -a v1-final 534c9b1 -m "v1-final: last commit of QRP2P v1"
   git push origin v1-final
   ```

   (Or in the web UI: Releases → Draft a new release → tag `v1-final`, target `main`.)

2. **Require CI on `main`.** Settings → Rules → Rulesets → New ruleset → *Import a ruleset* →
   choose `.github/rulesets/main.json` → Create. It allows changes only through pull requests,
   requires the CI checks, blocks force-push and deletion, and has no bypass (it applies to you
   too).
   - Import the file from the **M1 branch** (`claude/v2-m1-protocol-core`, 9 checks: M0's seven
     plus "Formal model (ProVerif)" and "Mutation testing (core)"). The M0 branch's copy has only
     seven. If you imported the M0 copy already, add the two checks by hand (Rulesets → the
     ruleset → Require status checks → Add checks).
   - If you later rename a CI job in `.github/workflows/ci.yml`, update the ruleset in the same
     change, or every merge into `main` will wait for a check that never reports.

3. **Merge [PR #3](https://github.com/DivinityQQ/quantum-resistant-p2p/pull/3) (M0)** with
   **"Create a merge commit"**, not squash or rebase. The commits record decisions (for example the
   MSVC liboqs finding), and the M1 branch is stacked on M0: it keeps working without a rebase
   only if M0's commits reach `main` unchanged.
4. **Then the M1 PR** (base `claude/v2-m0-crypto-foundations`). After step 3, change its base to
   `main` (Edit next to the PR title), or let GitHub do it by deleting the M0 branch with
   *Automatically delete head branches* on. Wait for CI on `main` (all 9 checks), then merge it
   with a merge commit too.

5. **Housekeeping (optional, your call).**
   - Settings → General → enable *Automatically delete head branches*. With it, a stacked PR whose
     base branch is deleted after merging is retargeted to `main` automatically.
   - Delete branches that are now superseded: `claude/codebase-review-security-arch-cjdcr5` (an
     older copy of the design commit) and `dev` (old v1 work; still reachable through history).
   - GitHub Pages: `gh-pages` still serves the **v1** documentation site. Turn Pages off
     (Settings → Pages) or leave it until v2 has docs.

## 2. PyPI: reserve the name `qrp2p`

The name was still free on 2026-09-27. Only an actual upload claims it.

1. Create a PyPI account and enable two-factor authentication (required for uploads).
2. Choose one path:
   - **Quick, one-off.** Create an *account-wide* API token (a project-scoped one cannot exist
     before the project), then from a clean checkout of `main`:

     ```bash
     uv build
     uv publish --token pypi-...        # uploads qrp2p 2.0.0.dev0
     ```

     Afterwards delete that token and, if you keep one, create a project-scoped token.
   - **Trusted publishing (no secrets).** Ask a Claude session for a release workflow first; then
     on PyPI add a *pending publisher* (owner `DivinityQQ`, repository `quantum-resistant-p2p`,
     the workflow file name and environment name it tells you) and run the workflow once. This is
     needed for M6 anyway.
3. Notes: a version number can never be reused once uploaded, even after deletion. `2.0.0.dev0`
   is a pre-release, so plain `pip install qrp2p` will not pick it up. PyPI's name-squatting policy
   (PEP 541) is not a concern because the package contains real code.

## 3. Report the liboqs SLH-DSA bug (optional, about 30 minutes)

Facts are in `docs/v2/research/VERIFIED_FACTS.md` (liboqs section). Summary:

- `plat_local.h` lines 110 and 123 test `__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__`. MSVC defines
  neither macro, so the test is `0 == 0` and SHA-256/512 take the big-endian path on x64. SLH-DSA
  SHA-2 variants then produce non-standard signatures that do not even verify against themselves;
  SHAKE variants and all KEMs are fine.
- Present in liboqs 0.16.0 and liboqs `main` (commit `b196b57`, 2026-09-24), and in the upstream
  source `pq-code-package/slhdsa-c` (`main`, `174c02e`). liboqs's CI never catches it because it
  builds with `-DOQS_ENABLE_SIG_SLH_DSA=OFF` in nearly every job, including every Windows job.
- Evidence you can cite: our failing Windows CI run (run 36333980431, job "liboqs windows-latest"),
  the Linux reproduction (`-U__BYTE_ORDER__ -U__ORDER_BIG_ENDIAN__`), and our workaround in
  `.github/workflows/ci.yml`.
- Suggested fix: `#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__` (MSVC only
  targets little-endian CPUs).

Steps: search both issue trackers for "MSVC", "BYTE_ORDER" and "SLH-DSA Windows" first. If nothing
exists, open an issue (ideally with the one-line PR) on `pq-code-package/slhdsa-c`, then an issue on
`open-quantum-safe/liboqs` that links to it and mentions the disabled Windows CI coverage. It is a
correctness bug that makes verification fail (fail-closed), not a forgery, so a public issue is
appropriate. A Claude session can draft both texts on request.

## 4. Your workstation (when you want to run things locally)

```bash
# uv: https://docs.astral.sh/uv/  (then)
uv python install 3.14
uv sync --all-extras --dev
uv run pytest && uv run ruff check . && uv run pyright && uv run lint-imports
```

- Lab algorithms locally (optional): build liboqs 0.16.0 with the flags in `ci.yml` (on Windows
  with MSVC, include the `CFLAGS` byte-order workaround), then
  `OQS_INSTALL_PATH=<prefix> QRP2P_REQUIRE_LIBOQS=1 uv run pytest -m liboqs`.
- Formal model (optional locally): `opam install proverif` (2.05), then `python formal/verify.py`.
  CI runs it on every push; locally it takes about 12 minutes, most of it `handshake_fs.pv`.
- Mutation testing (optional locally): `uv run mutmut run && uv run python -m tests.mutation_gate`
  (5-20 minutes). CI runs it too.

## 5. Claude Code cloud environment (optional)

The cloud container blocks `opam.ocaml.org`, `gitlab.inria.fr` and `bblanche.gitlabpages.inria.fr`,
so a session there cannot run ProVerif itself and relies on CI for it. To let sessions run the
model directly, add those hosts to the environment's allowed domains (cloud environment menu in a
session's title bar → Edit → Network access). Tag pushes and repository settings stay refused
there by design; those remain items for you.
