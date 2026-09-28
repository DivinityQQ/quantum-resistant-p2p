# Owner to-do (needs your accounts or admin rights)

Things a Claude Code cloud session cannot do for you: its GitHub access refuses tag pushes and
repository-settings changes, and it has no PyPI account. Work top to bottom; delete items as you
finish them, and this file once it is empty.

_Last updated: 2026-09-28 (v2 on `main`)._

## 1. GitHub: turn off the v1 Pages site

v1 is tagged (`v1-final`), the `main` ruleset is active, v2 is merged and the stale branches are
gone. One item is left, because the API refuses it: `gh-pages` still serves the **v1**
documentation site. Settings → Pages → *Unpublish site* (then delete the `gh-pages` branch if you
like; `v1-final` does not need it).

## 2. PyPI: reserve the name `qrp2p` (trusted publishing)

The name was still free on 2026-09-27. Only an actual upload claims it. Releases go through
`.github/workflows/release.yml` with trusted publishing: PyPI accepts an upload only from that
workflow in this repository, so no API token exists to leak.

1. **PyPI account**: enable two-factor authentication (Account settings; uploads require it).
2. **Pending publisher** (pypi.org → Your account → Publishing → *Add a new pending publisher*,
   GitHub tab):
   - PyPI Project Name: `qrp2p`
   - Owner: `DivinityQQ`
   - Repository name: `quantum-resistant-p2p`
   - Workflow name: `release.yml`
   - Environment name: `pypi`

   A pending publisher does not reserve the name; the first upload does, and turns it into a
   normal publisher.
3. **Tag the release** on `main` (after the release workflow is merged):

   ```bash
   git switch main && git pull
   git tag -a v2.0.0.dev0 -m "qrp2p 2.0.0.dev0: name placeholder (M0+M1)"
   git push origin v2.0.0.dev0
   ```

4. **Approve** the run: Actions → Release → *Review deployments* → `pypi` → Approve. The page
   https://pypi.org/project/qrp2p/ appears a minute later.

Notes: a version number can never be reused once uploaded, even after deletion. `2.0.0.dev0` is a
pre-release, so plain `pip install qrp2p` ignores it (`pip install --pre qrp2p` finds it).
PyPI's name-squatting policy (PEP 541) is not a concern because the package contains real code.

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

## 4. Claude Code cloud environment (optional)

The cloud container blocks `opam.ocaml.org`, `gitlab.inria.fr` and `bblanche.gitlabpages.inria.fr`,
so a session there cannot run ProVerif itself and relies on CI for it. To let sessions run the
model directly, add those hosts to the environment's allowed domains (cloud environment menu in a
session's title bar → Edit → Network access). Tag pushes and repository settings stay refused
there by design; those remain items for you.
