# Security policy

## Supported versions

Security fixes go into the latest release. Please upgrade before reporting a problem, using the commands in the [README](README.md#update).

## Reporting a vulnerability

PortBridge controls a VPN and a firewall, so please **do not describe a vulnerability in a public issue or pull request**.

1. If this repository has the **Report a vulnerability** button under its **Security** tab, use it. It sends the report privately to the maintainer.
2. Otherwise, open a public issue titled **"Security: private contact request"** with no technical details, and the maintainer will reply with a private way to share them.

Include what you found, how to reproduce it, the version you tested (shown in the dashboard footer) and, if you can, how you think it should be fixed. You will get an answer, and credit in the release notes if you want it, once the fix is out.

## Running PortBridge safely

- The dashboard is served over plain HTTP. Put it behind an HTTPS reverse proxy, restrict port 3000 to trusted addresses, or bind it to localhost and use an SSH tunnel.
- Use a long, unique dashboard password, and keep the `.env` file or `/etc/portbridge/portbridge.env` private.
- Treat a backup of the data folder like a password: it contains your peers' private keys.
- Only share a route or publish a port when you need to, and use **Route access** to limit who can reach it.
