# Publishing `why` to the AUR

The files in this directory are the Arch User Repository package for `why`.
`PKGBUILD` builds the tool from a tagged source release; `.SRCINFO` is the
machine-readable metadata the AUR website reads.

The package name is `why`. If that name is already taken on the AUR, pick
something else (for example `why-linux`) and update `pkgname` in both files.

## 0. Prerequisites

The release has to exist before the package can point at it:

```console
$ git tag -a v0.1.0 -m "why 0.1.0"
$ git push origin v0.1.0
```

`PKGBUILD` downloads
`https://github.com/bjl32/why/archive/refs/tags/v0.1.0.tar.gz`, so the tag name
must match `v$pkgver`.

## 1. One-time AUR setup

1. Register at <https://aur.archlinux.org> and add an SSH public key under
   *My Account → SSH Public Key*. The usual key is `~/.ssh/id_ed25519.pub`.
2. Check that the package name is free:
   <https://aur.archlinux.org/packages?K=why>

## 2. Fill in the checksum

The committed `PKGBUILD` has `sha256sums=('SKIP')` because the release tarball
does not exist yet. Once the tag is pushed, let `makepkg` compute it:

```console
$ cd packaging/aur
$ updpkgsums
```

`updpkgsums` downloads the tarball, writes the real `sha256sums`, and does not
touch anything else. If you would rather compute it by hand:

```console
$ curl -L https://github.com/bjl32/why/archive/refs/tags/v0.1.0.tar.gz | sha256sum
```

## 3. Test the package locally

```console
$ cd packaging/aur
$ makepkg -f          # build into a .pkg.tar.zst
$ makepkg -si         # build and install (needs sudo)
$ why --version
```

`makepkg` refuses to run as root; use a normal user.

## 4. Push to the AUR

```console
$ git clone ssh://aur@aur.archlinux.org/why.git
$ cd why
$ cp /path/to/repo/packaging/aur/PKGBUILD .
$ updpkgsums
$ makepkg --printsrcinfo > .SRCINFO
$ git add PKGBUILD .SRCINFO
$ git commit -m "Initial import: why 0.1.0"
$ git push
```

The AUR accepts only `PKGBUILD` and `.SRCINFO`; everything else is ignored.

If port 22 is blocked, add this to `~/.ssh/config` and use `ssh://aur@aur.archlinux.org:443/why.git`:

```sshconfig
Host aur.archlinux.org
  HostName aur.archlinux.org
  Port 443
  User aur
```

## 5. Updating

For each new release: bump `pkgver`, reset `pkgrel=1`, run `updpkgsums`, refresh
`.SRCINFO`, and push. Reviewers expect the `pkgrel` to increase for packaging
changes and reset for version changes.

## Alternatives

* **`why-git`** — a VCS package that clones `master` and sets
  `sha256sums=('SKIP')`; it tracks development instead of a release.
* **`why-bin`** — repackages a prebuilt binary from a GitHub release. This
  requires publishing release artifacts, and is worth doing only once the
  project ships binaries for each architecture.
