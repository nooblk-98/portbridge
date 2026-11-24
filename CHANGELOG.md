# Changelog

All notable changes to PortBridge are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Each release on GitHub carries the
notes for its version.

## [1.6.1] - 2026-11-24

### Changed

- **Versioned files are cached for a year.** Static files requested with the
  running release's number (`?v=1.6.1`) are sent with `immutable` and a one-year
  lifetime, so pages load without checking the server for every script and style.
  Anything else, and every development build, is still revalidated each time.
- **A development build says so.** A build that is not a release reports
  `0.0.0-dev` instead of the made-up `0.1.0`, in the footer and `--version`.
- **Faster first load.** The logo (also the favicon) was a 657 KB SVG that only
  wrapped a PNG; it is now an 18 KB PNG.
- **Tidier source.** The dashboard script is split into one file per area, the
  Python-era leftovers and unused code are gone, and the README screenshots show
  the current look. `npm run screenshots` in `frontend/` regenerates them from the
  demo data.

### Fixed

- **Upgrades no longer show an old stylesheet behind a caching proxy.** A reverse
  proxy that caches assets for hours (Nginx Proxy Manager's "Cache Assets") kept
  serving the previous release's CSS and scripts, so new features looked missing
  after an upgrade. Static files are now requested with the release number
  (`/static/css/tailwind.css?v=1.6.1`), so each release is a new file to every
  browser and cache.

## [1.6.0] - 2026-11-24

### Added

- **A falling-stars background.** Twinkling stars and the occasional shooting star
  drift behind the dashboard and the sign-in screen, in both themes: a deep indigo
  night sky in dark mode and a soft lavender sky in light mode. It is pure CSS
  (keyframes in the Tailwind config), with no scripts and no graphics libraries,
  so it costs almost nothing. With "reduce motion" on, the stars hold still.

### Fixed

- The large faint icons behind the Total Clients, Active Ports and Network cards
  were almost invisible, especially in dark mode. They are now clearly visible in
  both themes.
- The logo in the desktop sidebar showed inside a white square. It is now a plain
  circle, like the logo on the phone header and the sign-in screen.

## [1.5.0] - 2026-11-24

### Added

- **An "update available" notice.** When a newer release exists, the dashboard
  shows a banner with **What's new**, **Remind me later** and **Ignore this
  version**. What's new opens a popup with the release's changelog and the
  upgrade command to copy (the `install.sh --upgrade` line for Debian and Ubuntu,
  or the Compose pull and recreate for Docker). Remind me later hides it for a
  day; Ignore hides that version until a newer one appears. Nothing upgrades by
  itself, so you stay in control.

  Your browser asks GitHub's public releases API at most every six hours and
  sends nothing about your installation, and the page's security policy allows
  that one address only when the check is on. Release notes are shown as plain
  text, never as HTML. Set `UPDATE_CHECK=0` to turn it off; it is on by default
  in release builds only.

## [1.4.3] - 2026-11-24

### Changed

- **The whole UI is styled with Tailwind.** The 1,700-line hand-written
  `style.css` is gone: every style is a utility class in the templates, shared
  styles live in one `ui.html` partial, and the theme is defined in the Tailwind
  config. The look is unchanged, except that the dashboard rings now turn amber
  or red as their tone intends (an old stylesheet ordering bug kept them green).
- **Browser end-to-end tests.** About 55 Playwright tests drive the real
  dashboard at desktop and phone sizes against fixture data and a fake
  WireGuard runner, and run in CI. Icon-only buttons gained accessible names.

## [1.4.2] - 2026-11-24

### Added

- **A single footer.** It sits under the page content on every screen, pinned
  while the page scrolls, and no longer repeats in the sidebar or menu drawer. It
  links to the repository and release, and says "Made with ❤️ by nooblk for the
  community", linked to the author's GitHub profile. The sign-in screen shows it
  too.

### Changed

- **One front-end toolchain.** The stylesheet is built from a committed Tailwind
  configuration in `frontend/` (`npm run build:css`), instead of a pre-built file
  with no source. The new footer and the mobile Forwarding cards use Tailwind
  classes rather than custom CSS. CI rebuilds the stylesheet and fails if the
  committed one is out of date. Running PortBridge still needs no Node.
- Vendored third-party scripts moved to `app/static/vendor/`.

## [1.4.1] - 2026-11-24

### Fixed

- **Mobile controls.** The menu button sits on the left, the header stays outside
  the scrolling content, and the circular logo shows without its square tile on
  the dashboard and the sign-in screen.
- **Forwarding rules on mobile.** Each rule is a stacked card, so the target
  client and the delete button are no longer hidden off-screen.
- **Invalid forwarding storage no longer wipes your rules.** If the forwarding
  file cannot be read, listing, adding, removing and applying rules now report
  the error and leave the file untouched. Peers and routes stay available.
- **Blank internal port.** Adding a forwarding rule with an empty internal port
  uses the public port instead of failing.

### Changed

- Loading, empty and error states appear at the right times on every page.
- The dashboard no longer makes a duplicate summary request, pauses background
  polling in hidden tabs, and reuses recent traffic history when you switch
  ranges.
- Static assets are revalidated, and authenticated pages, API responses and
  downloads are never cached by the browser.

## [1.4.0] - 2026-11-24

### Added

- **A notice when peers must import an updated profile.** After a route is
  advertised or its access changes, the dashboard shows a banner listing the
  split-tunnel peers whose profile changed, with the new routes, a link to
  download the profile and an **Imported** button. The notice stays until you
  confirm the import, even if you downloaded the profile first, because a
  download does not prove it was installed on the device.

## [1.3.4] - 2026-11-24

### Fixed

- The Server access explanations said it controlled every program on the
  PortBridge server, including `curl` and `ssh` run from a shell. It controls
  Docker containers and other traffic forwarded through the server, such as Nginx
  Proxy Manager. Programs run directly on the server are not restricted. The
  card hover, dialog, toasts and docs now say so.

## [1.3.3] - 2026-11-24

### Changed

- The Server access explanations now say what turning it off does not affect:
  peers can still reach each other over the tunnel, route access still governs
  advertised networks, and forwarded public ports keep working. Only connections
  that the PortBridge server itself starts are controlled.

## [1.3.2] - 2026-11-24

### Changed

- The Server access explanations, toasts and docs now say what it does: the
  PortBridge server, and programs running on it such as a Docker reverse proxy or
  `curl`, can connect to the services running on a peer.

## [1.3.1] - 2026-11-24

### Changed

- **Server access is off by default.** Programs on the PortBridge hosted server,
  such as a Docker reverse proxy, can reach a peer only after you switch Server
  access on for it. `ALLOW_LOCAL_TO_PEERS` is now `off` unless set to `1`, and it
  is the default for peers that have no setting of their own. Peers that relied
  on the previous default need the switch turned on to keep working.
- The Server access explanations, toasts and docs now say "the PortBridge hosted
  server" instead of "this server".

## [1.3.0] - 2026-11-24

### Added

- **A Server access switch for each peer**, on its card and in its settings,
  with the same round switch and hover explanation as Split tunnel. It controls
  whether programs on the server, such as a Docker reverse proxy or `curl`, can
  open connections to that peer and the networks it advertises.

### Changed

- `ALLOW_LOCAL_TO_PEERS` is now the default for peers that have no setting of
  their own, and the firewall rules are written per peer instead of for the
  whole tunnel. Existing peers keep following the default, which is on.

## [1.2.5] - 2026-11-24

### Fixed

- Programs on the server that forward traffic, such as a Docker container
  running a reverse proxy, could not open connections to peers or to subnets they
  advertise, because PortBridge's firewall dropped everything entering the
  tunnel. Servers that proxied peer services before moving to PortBridge saw
  their proxy hosts return 502 errors.

### Changed

- New setting `ALLOW_LOCAL_TO_PEERS`, on by default. Programs on the server
  other than the tunnel and the public interface may open connections to peers,
  and peers may only answer them. Peers still cannot start connections to the
  server's other services, and the internet still reaches peers only through a
  forwarding rule. Set `ALLOW_LOCAL_TO_PEERS=0` for the previous behaviour.

## [1.2.4] - 2026-11-24

### Fixed

- The two icon tiles on the Dashboard quick action cards (Add New Client and
  Open Port) are now the same fixed square size on every screen. They were
  taller than wide, and could differ depending on how the icon font loaded.

## [1.2.3] - 2026-11-24

### Added

- The README now says plainly that PortBridge is a self-hosted alternative to
  Tailscale and Headscale (and lists similar VPN, mesh and tunnel tools), when to
  choose it, and how to use the server as a bastion (jump) host.

### Fixed

- `install.sh` no longer hangs when a download stalls. Downloads now time out
  and retry, for both `curl` and `wget`.

## [1.2.2] - 2026-11-24

### Changed

- **A tidier Peer settings dialog.** Sections now have even spacing and
  dividers, split tunnel is a labelled switch row that matches the switch on
  peer cards, and DNS, MTU and keepalive share one row with short labels and a
  single help line.
- The Peers online card lists up to five peers and links to the rest, so it no
  longer needs an inner scrollbar. Cards that sit beside a taller one centre
  their content.
- The README screenshots show the current interface, including the Peer
  settings dialog, with sample peers.

### Fixed

- The dashboard styles reused names that older styles already used. That shifted
  some text and background colours on the Routes page and in dialogs, and drew a
  stray green dot in the corner of the Routes page. They now use their own names.
- The disk gauge reports the real filesystem instead of a bind mount created by
  the service sandbox.

## [1.2.0] - 2026-11-24

### Added

- **A live dashboard.** The Dashboard page now shows, in the same light and
  dark theme as the rest of the app:
  - **Peers online**: a ring with each peer's avatar and connection state.
  - **Total traffic**: all-time and last-24-hour download and upload, with the
    split between them.
  - **Top talkers**: the busiest peers for the selected period.
  - **Connection health**: checks for the WireGuard interface and port, peers,
    firewall rules, IP forwarding and internet access, with an overall status.
  - **Traffic over time**: a chart you can switch between the last hour, the
    last 24 hours and the last 7 days.
  - **Server**: CPU, memory and disk gauges, load average and uptime.
- Two new API endpoints behind the dashboard: `GET /api/stats` and
  `GET /api/stats/history?range=1h|24h|7d`.
- Traffic history. The server samples WireGuard's counters once a minute and
  keeps minute samples for 24 hours and ten-minute buckets for 7 days in
  `metrics.json` under `DATA_DIR`. Counter resets, such as an interface restart,
  are handled, and lifetime totals survive restarts.

### Changed

- The dashboard layout follows the width of the page, so it fits a phone, a
  narrow window or a wide screen, with or without the sidebar.

### Fixed

- The upload and download arrows on peer cards were reversed. Upload now means
  data a peer sent to the server and download means data sent to the peer.

## [1.1.0] - 2026-11-24

This release also includes everything from the automatically numbered 1.0.1
to 1.0.10 builds, which shipped within hours of each other.

### Added

- **Split tunnel switch on every peer card.** A round switch turns split tunnel
  on or off in one click, with a hover and keyboard tooltip that explains the
  difference between split tunnel and full tunnel.
- **Advertised routes on peer cards**, shown as chips, so you can see what each
  device shares without opening its settings.
- **Cartoon avatars for peers**, generated in the browser from each peer's
  public key (DiceBear Avataaars, bundled locally). Nothing is requested from an
  outside service, and an avatar stays the same if the peer is renamed.
- **Pages with their own URLs.** `/clients`, `/routes` and `/forwarding` open
  directly, work with the back and forward buttons, update the tab title, and
  return you to the page you wanted after signing in.
- **Footer with the repository link and running version** on the dashboard and
  the sign-in page.
- **Install, upgrade and uninstall from one script.** `install.sh` downloads the
  latest release and verifies its SHA-256 checksum. Use `--upgrade` to update in
  place, `--uninstall` (with `--purge` to also delete peers and keys) to remove
  it, `PORTBRIDGE_VERSION` to pin a version and `PORTBRIDGE_ADMIN_PASSWORD` for
  unattended installs.
- **Prebuilt static Linux binaries** for x86_64 and arm64 on every release, with
  checksums.
- `portbridge --version` and `portbridge hash-password`, and an
  `ADMIN_PASSWORD_HASH` setting that takes a salted hash instead of a password.
- Unit tests for iptables rule rendering, route validation, sign-in sessions and
  password hashing. CI now runs them.
- The dashboard follows the system colour scheme, remembers a manual choice and
  keeps it in sync across browser tabs.

### Changed

- **New peers use split tunnel by default.** Devices keep their own internet
  connection and public IP unless you switch the peer to full tunnel. Peers
  whose settings were saved with split tunnel off keep that choice.
- **Peer internet access through the server is allowed by default**, so a peer
  set to full tunnel works without extra setup. Set `ALLOW_INTERNET_EGRESS=0` to
  block it.
- **The dashboard listens on all interfaces by default** (`APP_HOST=0.0.0.0`),
  and the Compose files publish port 3000. It is served over plain HTTP, so put
  it behind an HTTPS reverse proxy, restrict the port in your firewall, or set
  `APP_HOST=127.0.0.1` and use an SSH tunnel.
- Every code change merged to `main` is now verified, tagged, built and
  published as the latest release. Documentation-only changes do not release.
- Docker images are built from the release tag and pushed one at a time.
- The sign-in form, scrollbars and colour handling follow current web platform
  guidance (autofill attributes, standard scrollbar properties).
- The README has a banner, screenshots, a configuration table and updated
  install instructions.

### Security

- The installer stores a salted PBKDF2-SHA256 hash of the dashboard password
  instead of the password itself.
- The systemd unit adds `PrivateTmp`, `ProtectControlGroups`,
  `RestrictSUIDSGID`, `RestrictRealtime` and `LockPersonality`.
- GitHub Actions are pinned to commit SHAs.

### Upgrading

Run the installer with `--upgrade`:

```sh
curl -fsSL https://raw.githubusercontent.com/nooblk-98/portbridge/main/install.sh | sudo bash -s -- --upgrade
```

Peers that switch to split tunnel need their profile re-imported on the device.
The Routes tab shows which profiles need a fresh export.

## [1.0.0] - 2026-11-24

First release of the Rust version of PortBridge: a WireGuard server with a web
dashboard, per-peer routes with access rules, and public TCP and UDP port
forwarding.

[1.4.0]: https://github.com/nooblk-98/portbridge/compare/v1.3.4...v1.4.0
[1.3.4]: https://github.com/nooblk-98/portbridge/compare/v1.3.3...v1.3.4
[1.3.3]: https://github.com/nooblk-98/portbridge/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/nooblk-98/portbridge/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/nooblk-98/portbridge/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/nooblk-98/portbridge/compare/v1.2.5...v1.3.0
[1.2.5]: https://github.com/nooblk-98/portbridge/compare/v1.2.4...v1.2.5
[1.2.4]: https://github.com/nooblk-98/portbridge/compare/v1.2.3...v1.2.4
[1.2.3]: https://github.com/nooblk-98/portbridge/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/nooblk-98/portbridge/compare/v1.2.0...v1.2.2
[1.2.0]: https://github.com/nooblk-98/portbridge/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/nooblk-98/portbridge/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/nooblk-98/portbridge/releases/tag/v1.0.0
