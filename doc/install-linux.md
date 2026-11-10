# Installing a Blazecoin V2 node on Linux (Ubuntu / Debian)

A step-by-step guide to running `blazecoind` from the release tarball as a system service: download,
verify, install, configure, run under systemd, open the P2P port, upgrade. Every command is meant to be
copied as written. Tested on Ubuntu 22.04 and 24.04; Debian 12 works the same way.

What you need: an x86_64 machine or VPS with Ubuntu 22.04+ or Debian 12+ (glibc 2.35 or later), about
**4 GB of free disk** for the chain and **1 GB of RAM** or more, and a user with `sudo`.

The binaries are self-contained: they only need the standard C/C++ runtime that every Ubuntu/Debian
install already has. No extra packages are required.

## 1. Download and verify

Pick the latest `-linux` release on the [Releases page](https://github.com/AMA-CSharp-Code/blazecoin-core/releases)
and set its version below (2.1.3 at the time of writing).

```bash
VER=2.1.3
cd /tmp
wget https://github.com/AMA-CSharp-Code/blazecoin-core/releases/download/v${VER}-linux/Blazecoin-Core-V${VER}-linux-x86_64.tar.gz
wget https://github.com/AMA-CSharp-Code/blazecoin-core/releases/download/v${VER}-linux/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

The last command must print `Blazecoin-Core-V2.1.3-linux-x86_64.tar.gz: OK`. If it says anything else,
stop and download again.

## 2. Install the binaries

```bash
tar -xzf Blazecoin-Core-V${VER}-linux-x86_64.tar.gz
sudo install -m 0755 blazecoin-${VER}/blazecoind blazecoin-${VER}/blazecoin-cli /usr/local/bin/
blazecoind --version | head -1
```

The last line should print `Blazecoin Core version v2.1.3` (or the version you downloaded).

## 3. Create a service user and the data directory

The node runs as its own unprivileged user, with its data in `/var/lib/blazecoin`.

```bash
sudo useradd --system --home-dir /var/lib/blazecoin --shell /usr/sbin/nologin blazecoin
sudo mkdir -p /var/lib/blazecoin
sudo chown blazecoin:blazecoin /var/lib/blazecoin
sudo chmod 0710 /var/lib/blazecoin
```

(Running it by hand under your own account instead? The default data directory on Linux is
`~/.blazecoinv2.0/` - note the `.0`.)

## 4. Write the configuration

This is the configuration the public relay nodes use. Paste the whole block:

```bash
sudo tee /var/lib/blazecoin/blazecoin.conf > /dev/null <<'EOF'
# Blazecoin V2 node
server=1
listen=1
# RPC stays on this machine only. Never open port 55413 to the internet.
rpcallowip=127.0.0.1
# The chain can go hours or days without a block; this stops the node
# treating a quiet tip as "still syncing".
maxtipage=99999999
dbcache=256
# Peers to start from (the two public relays are also built into the binary)
addnode=51.210.47.141:55414
addnode=54.39.23.245:55414
addnode=blazecoin.co.uk:55414
EOF
sudo chown blazecoin:blazecoin /var/lib/blazecoin/blazecoin.conf
sudo chmod 0640 /var/lib/blazecoin/blazecoin.conf
```

No RPC user or password is needed: the node writes a fresh random `.cookie` file into the data
directory on every start, and `blazecoin-cli` reads it. See section 8 if another program (a pool,
an explorer) needs to call the RPC.

The `blazecoin.conf` inside the tarball is the fuller desktop-wallet template. If you use it on a
server, delete or comment out its `wallet=Primary` line, because that wallet will not exist there.

## 5. Install the systemd service

```bash
sudo tee /etc/systemd/system/blazecoind.service > /dev/null <<'EOF'
[Unit]
Description=Blazecoin V2 daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=blazecoin
Group=blazecoin
ExecStart=/usr/local/bin/blazecoind -datadir=/var/lib/blazecoin
Restart=on-failure
RestartSec=30
# The database needs a clean flush on stop. Never shorten this or use kill -9.
TimeoutStopSec=600
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateDevices=true
ReadWritePaths=/var/lib/blazecoin

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now blazecoind
sudo systemctl status blazecoind --no-pager
```

`status` should show `active (running)`. The same file is in this repository as
[`contrib/init/blazecoind.service`](../contrib/init/blazecoind.service).

Do **not** add `-daemon` to `ExecStart`: systemd runs the node in the foreground and handles
restarts itself.

## 6. Open the P2P port

Other nodes connect to you on **55414/tcp**. With `ufw`:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 55414/tcp comment 'Blazecoin P2P'
sudo ufw enable
```

On a cloud VPS, also allow 55414/tcp in the provider's firewall or security group. Never open
55413 (RPC).

## 7. Check it is syncing

Every `blazecoin-cli` call runs as the service user and names the data directory. A shell alias
saves typing:

```bash
echo "alias blz='sudo -u blazecoin blazecoin-cli -datadir=/var/lib/blazecoin'" >> ~/.bashrc
source ~/.bashrc

blz getblockchaininfo        # "blocks" climbs towards "headers"
blz getconnectioncount       # should be 2 or more within a minute
blz getpeerinfo | grep '"addr"'
journalctl -u blazecoind -f  # live log (Ctrl+C to leave)
```

A first sync from nothing takes a few hours. It is finished when `blocks` equals `headers` and
`initialblockdownload` is `false`. Compare the height with https://blazecoin.co.uk.

## 8. RPC for a pool or other software (optional)

On the same machine, the simplest way is the cookie file: `/var/lib/blazecoin/.cookie` holds
`__cookie__:<password>` and changes on every restart. Add your pool's user to the `blazecoin` group
(`sudo usermod -aG blazecoin <user>`) so it can read it.

If the software needs a fixed user and password, generate an `rpcauth` line instead of writing a
plain password into the config. Pick a long random password and run:

```bash
python3 - <<'EOF'
import hmac, os, getpass
user = input("rpc user: ")
pw = getpass.getpass("rpc password: ")
salt = os.urandom(16).hex()
print(f"rpcauth={user}:{salt}${hmac.new(salt.encode(), pw.encode(), 'sha256').hexdigest()}")
EOF
```

Add the printed `rpcauth=...` line to `blazecoin.conf` and run `sudo systemctl restart blazecoind`. The
software then uses that user and password against `127.0.0.1:55413`. Keep RPC on loopback. If the
pool runs on another machine, use a VPN or an SSH tunnel, and never port-forward 55413.

Mining pools must pay out to **legacy `B...` addresses**. SegWit is disabled on this chain, so coins
sent to a `blz1...` or wrapped-SegWit address can never be spent. Release 2.1.3 refuses to create them.

## 9. Wallet on the node (optional)

A pure relay or pool backend does not need a wallet. If you want one:

```bash
blz createwallet "main"
blz -rpcwallet=main getnewaddress      # a legacy B... address
```

To load it at every start, add `wallet=main` to `blazecoin.conf`. **Back up**
`/var/lib/blazecoin/wallets/main/` to another machine; it is the only copy of your keys.

## 10. Day-to-day commands

| What | Command |
|---|---|
| Stop | `sudo systemctl stop blazecoind` (waits for the clean flush; can take a minute) |
| Start | `sudo systemctl start blazecoind` |
| Restart | `sudo systemctl restart blazecoind` |
| Log | `journalctl -u blazecoind -f`, or `/var/lib/blazecoin/debug.log` |
| Version | `blz getnetworkinfo \| grep subversion` |

**Never** `kill -9` the daemon or pull the power during a write. An unclean stop can corrupt the block
database and force a full re-sync.

## 11. Upgrading to a new release

```bash
VER=<new version>
cd /tmp
# download + verify as in step 1, then:
tar -xzf Blazecoin-Core-V${VER}-linux-x86_64.tar.gz
sudo systemctl stop blazecoind
sudo install -m 0755 blazecoin-${VER}/blazecoind blazecoin-${VER}/blazecoin-cli /usr/local/bin/
sudo systemctl start blazecoind
blz getnetworkinfo | grep subversion
```

The data, wallet and configuration carry over. The release notes say if a re-index is ever needed.

## 12. Running a pool against your node

Most pool problems are one of four things: **the node, RPC, the pool software, the network**. Check them
in that order and the fault usually shows itself. (The `blz` alias is from step 7.)

### 12.1 Is the node running and in sync?

```bash
sudo systemctl status blazecoind
blz getblockchaininfo
```

`blocks` must equal `headers` and `initialblockdownload` must be `false`. While the node is still
syncing, `getblocktemplate` refuses with "is in initial sync", and a node that is behind hands miners
stale work. Compare the height with https://blazecoin.co.uk.

### 12.2 Does it have peers?

```bash
blz getconnectioncount
blz getpeerinfo | grep '"addr"'
```

You want 2 or more. With 0 peers, `getblocktemplate` refuses with "is not connected". Check that
55414/tcp is open in `ufw` and in the VPS provider's firewall, then try
`blz addnode 51.210.47.141:55414 onetry`.

### 12.3 Can the pool reach RPC?

From the machine the pool runs on, with the user and password the pool is configured with (the
`rpcauth` line from step 8):

```bash
curl --user USER --data-binary '{"jsonrpc":"1.0","id":"t","method":"getblocktemplate","params":[{"rules":["segwit"]}]}' \
     -H 'content-type: text/plain;' http://127.0.0.1:55413/
```

| Result | Meaning |
|---|---|
| a JSON block template (`"height"`, `"coinbasevalue"`, …) | RPC works. If the pool still fails, the fault is in the pool software or its config |
| `401 Unauthorized` / empty reply | wrong user or password, or the `rpcauth` line was added without restarting the node |
| `Connection refused` | node not running, or the pool is on another machine (RPC answers on 127.0.0.1 only; see step 8) |
| `must be called with the segwit rule set` | the pool calls `getblocktemplate` without `"rules":["segwit"]`. This node needs the rule even though SegWit is not active on Blazecoin. Most pool software sends it already |
| `is in initial sync` / `is not connected` | back to 12.1 / 12.2 |

### 12.4 Read the logs, newest first

```bash
journalctl -u blazecoind -n 100 --no-pager
tail -f /var/lib/blazecoin/debug.log
```

Then the pool's own log. Look for the **first** error: the ones after it usually follow from it.
A submitted block shows up in `debug.log` as `UpdateTip: new best=…` (accepted) or with a
reject reason (`high-hash`, `bad-txnmrklroot`, `bad-cb-amount`, …), which points at the pool's block
building.

### 12.5 Blocks found but no payouts

- `blz -rpcwallet=<wallet> getbalances`: freshly mined coins show as `immature`. **A coinbase can be
  spent after 30 confirmations** on Blazecoin (about 15 minutes at the 30-second target, longer when
  the network is quiet). Pools that assume Bitcoin's 100 just pay later than they could.
- The pool's payout and reward addresses must be **legacy `B…`**. A `blz1…` or wrapped-SegWit
  (P2SH-segwit) address can never be spent here, and 2.1.3 refuses to make them.
- Check that the wallet the pool pays from is loaded at start (`wallet=<name>` in `blazecoin.conf`).

### 12.6 Miners connect and then drop

This is nearly always the share difficulty. Set the stratum start difficulty for the hardware:
higher for ASICs, lower for small or USB miners. Use vardiff if the pool supports it. Also check
that the algorithm is set to **scrypt** in both the pool and the miner.

### 12.7 Things that are normal on this chain

- **Quiet periods.** Hashrate is low, so the gap between blocks varies a lot. A pause is not by itself
  a fault: check 12.1 and 12.2, and if they pass, the node is fine.
- **Difficulty moves every block** (the Phoenix-413 retarget since block 4,194,000). Big swings after
  a large miner joins or leaves are expected.

### 12.8 Keep a runbook

Write down every fault you hit, what you saw and what fixed it. After a few weeks that list covers
most of what goes wrong on your setup.

## Troubleshooting

- **`status` shows `failed` straight away:** run `journalctl -u blazecoind -n 50`. The usual causes are
  a typo in `blazecoin.conf`, or data directory files owned by root because the node was once started
  with `sudo blazecoind`. To fix the owner: `sudo chown -R blazecoin:blazecoin /var/lib/blazecoin`.
- **`Could not locate RPC credentials`:** you ran `blazecoin-cli` as yourself. Use the `blz` alias
  from step 7 (it runs as `blazecoin` with the right `-datadir`).
- **No peers:** check that outbound 55414 is allowed, then try
  `blz addnode 51.210.47.141:55414 onetry`.
- **`GLIBC_2.35 not found`:** the OS is too old (for example Ubuntu 20.04). Use 22.04 or newer, or
  build from source (`doc/build-unix.md`).
- **"No wallet is loaded" (error -18):** expected on a node without a wallet. See step 9.
