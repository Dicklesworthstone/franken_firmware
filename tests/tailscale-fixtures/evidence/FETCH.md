# How the pinned inputs of T01 were fetched

Read-only, public sources, fetched on 2026-11-06. Nothing here logs in, enrolls or contacts a tailnet. The pinned trees are **not committed** (they are third-party source); the ledger holds
short verbatim excerpts and the digests needed to tell a wrong tree from the right one, and `scripts/e2e/t01 --tier full --sources DIR` re-checks them.

| input | how | pin |
|---|---|---|
| tailscale-rs source | `gh api repos/tailscale/tailscale-rs/tarball/d34658bbb2eb4593ae6df959aa93e9ee1e0457c6 > tailscale-rs.tar.gz`, then `tar -xzf tailscale-rs.tar.gz -C DIR/tailscale-rs --strip-components=1` | commit `d34658bbb2eb4593ae6df959aa93e9ee1e0457c6` (v0.6.1); the tree digest is in `docs/tailscale/profiles.json` `derived_facts`, because a GitHub tarball is not byte-stable but its contents are |
| aws-lc-sys 0.45.0 | `curl -sSL -o aws-lc-sys-0.45.0.crate https://static.crates.io/crates/aws-lc-sys/aws-lc-sys-0.45.0.crate`, then `tar -xzf ... -C DIR/aws-lc-sys --strip-components=1` | crate sha256 `9bff6c3b54fad79a2e60b8102caf565819711497c1f5f092f49508e2f5c31b27` (the version locked by tailscale-rs v0.6.1) |
| mio 1.2.1 | `curl -sSL -o mio-1.2.1.crate https://static.crates.io/crates/mio/mio-1.2.1.crate`, then `tar -xzf ... -C DIR/mio --strip-components=1` | crate sha256 `02bd0af71c67b473010cbbc60715ee815645a4dc942899111f494b4b737d6fda` |
| Go port table | `https://raw.githubusercontent.com/golang/go/2aae1000ea1d4b28923b96db28acf4e3b99d6aff/src/internal/platform/zosarch.go` | tag go1.27.3 |
| tailscale release facts | `gh api repos/tailscale/tailscale/releases/latest`; `https://raw.githubusercontent.com/tailscale/tailscale/73a48057aaf5f60e4f770b398e9b7af576b01dbe/go.mod` and `.../release/dist/unixpkgs/targets.go`; `https://pkgs.tailscale.com/stable/?mode=json`; `https://pkgs.tailscale.com/stable/tailscale_1.104.5_mips.tgz.sha256` | v1.104.5, commit `73a48057aaf5f60e4f770b398e9b7af576b01dbe` |
| documentation pages (mutable) | `https://go.dev/wiki/MinimumRequirements`, `https://go.dev/doc/go1.27`, `https://tailscale.com/docs/concepts/userspace-networking`, `.../how-to/set-up-small-tailscale`, `.../features/access-control/key-expiry`, `.../concepts/control-data-planes`, `.../reference/derp-servers`, `https://man7.org/linux/man-pages/man2/epoll_create.2.html`, `.../eventfd.2.html` | the digest of what was retrieved, at the time in each ledger entry; a page may change later, and then the excerpt, not the page, is the record |

The excerpts were cut from the fetched bytes by a script, never typed (file excerpts by an anchor line and a line count, page excerpts by a start and an end phrase of the
whitespace-normalized text). `T01-P05-ledger-vs-sources` re-cuts every excerpt that came from a supplied file.
