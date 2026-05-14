# chat0 -- P2P End-to-End Encrypted Chat

> Serverless | End-to-end encrypted | Onion-routed | Sybil-resistant </br>
> Author: Yassine Salihi </br>
> Author: Wissal Mokdad </br>
> Author: Hafsa Azarg </br>
> Author: Rania Elhezzam </br>

A fully decentralised instant messaging desktop app built with **Wails v2**
(Go 1.23 backend + TypeScript/Vite frontend). No central server, no accounts,
no metadata leakage.

---

## Table of Contents

1. [How it works](#how-it-works)
2. [Prerequisites](#prerequisites)
3. [Arch Linux (primary)](#arch-linux-primary)
4. [Ubuntu / Debian](#ubuntu--debian)
5. [macOS](#macos)
6. [Windows](#windows)
7. [Build and Run](#build-and-run)
8. [Connecting nodes](#connecting-nodes)
9. [Simulation harness](#simulation-harness)
10. [Project layout](#project-layout)
11. [Troubleshooting](#troubleshooting)

---

## How it works

```
Alice               Relay hop              Bob
  |                     |                   |
  |-- AES layer 3 ----->|                   |
  |   AES layer 2        |-- AES layer 2 -->|
  |   AES layer 1        |   AES layer 1    |--> plaintext
  |
  X25519 per hop | Ed25519 signatures | SHA-256 PoW Sybil barrier
```

| Property          | Mechanism                                          |
|-------------------|----------------------------------------------------|
| Confidentiality   | AES-256-GCM, X25519 ECDH session key (HKDF-SHA256) |
| Integrity         | Ed25519 signature on every packet                  |
| Forward secrecy   | Ephemeral X25519 per TCP connection                |
| Anonymity         | 3-hop onion routing, fixed 4096-byte padding       |
| Sybil resistance  | SHA-256 PoW difficulty 20 (~1M hashes per identity)|
| Censorship bypass | Gossip mesh + user-supplied bootstrap nodes        |
| Replay protection | Random message IDs + 10-minute dedup window        |

---

## Prerequisites

| Tool      | Min version | Notes                          |
|-----------|-------------|--------------------------------|
| Go        | 1.23        | `go version` to check          |
| Node.js   | 18          | `node --version`               |
| npm       | 9           | bundled with Node              |
| Wails CLI | 2.12        | installed via `go install`     |
| C compiler| gcc / clang | required for CGO/WebKit        |

---

## Arch Linux (primary)

This is the main development platform.

### 1. System packages

```bash
sudo pacman -Syu
sudo pacman -S go nodejs npm gcc webkit2gtk base-devel
```

Wayland users: also install `xdg-utils`. If the window is black on Wayland:

```bash
GDK_BACKEND=x11 ./build/bin/chat0
```

### 2. Wails CLI

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@latest
```

Add Go bin to PATH -- add this line to `~/.bashrc` or `~/.zshrc`:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
source ~/.bashrc
```

Verify everything is ready:

```bash
go version      # go1.23.x
node --version  # v18.x or v20.x
wails version   # Wails CLI v2.12.x
```

### 3. Unzip and fetch dependencies

```bash
unzip V-chat-O-main.zip
cd V-chat-O-main
go mod tidy
cd frontend && npm install && cd ..
```

### 4. Run in dev mode (hot-reload)

```bash
wails dev
```

The desktop window opens. The terminal prints:

```
[app] node id=3f8a1b2c...  addr=:9000  pow=00000a7f...
```

### 5. Build a production binary

```bash
wails build
./build/bin/chat0
```

---

## Ubuntu / Debian

### 1. System packages

```bash
sudo apt update
sudo apt install golang nodejs npm gcc \
    libgtk-3-dev libwebkit2gtk-4.0-dev \
    build-essential pkg-config
```

On Ubuntu 22.04+ replace `libwebkit2gtk-4.0-dev` with `libwebkit2gtk-4.1-dev`
if the 4.0 package is not found.

### 2. Go 1.23 (if apt version is outdated)

```bash
sudo apt remove golang
wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### 3. Project setup

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@latest
export PATH=$PATH:$(go env GOPATH)/bin

unzip V-chat-O-main.zip && cd V-chat-O-main
go mod tidy
cd frontend && npm install && cd ..
wails dev
```

---

## macOS

### 1. Homebrew and dependencies

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install go node
xcode-select --install    # provides clang and WebKit (already on macOS)
```

### 2. Project setup

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@latest
export PATH=$PATH:$(go env GOPATH)/bin

unzip V-chat-O-main.zip && cd V-chat-O-main
go mod tidy
cd frontend && npm install && cd ..
wails dev
```

For a universal binary on Apple Silicon (M1/M2/M3):

```bash
wails build --platform darwin/universal
```

---

## Windows

### 1. Install tools

- **Go 1.23+**: <https://go.dev/dl/> (use the .msi installer)
- **Node.js 18+**: <https://nodejs.org/> (LTS version)
- **WebView2**: pre-installed on Windows 10 21H2+ and Windows 11.
  Otherwise download from <https://developer.microsoft.com/en-us/microsoft-edge/webview2/>

### 2. PowerShell setup

```powershell
go install github.com/wailsapp/wails/v2/cmd/wails@latest
# The Go installer puts %USERPROFILE%\go\bin in PATH automatically

Expand-Archive V-chat-O-main.zip
cd V-chat-O-main
go mod tidy
cd frontend; npm install; cd ..
wails dev
```

When the app first runs, Windows Firewall will prompt for network access.
Click **Allow** so peers can connect on port 9000.

---

## Build and Run

### Dev mode (all platforms)

```bash
wails dev
```

- Hot-reloads TypeScript and CSS on file save
- Browser devtools available at <http://localhost:34115>
- Go backend logs printed to the terminal

### Production build

```bash
wails build
```

| Platform | Output path              |
|----------|--------------------------|
| Linux    | `./build/bin/chat0`      |
| macOS    | `./build/bin/chat0.app`  |
| Windows  | `./build/bin/chat0.exe`  |

---

## Connecting nodes

### Same machine (two terminals)

```bash
# Terminal 1 -- listens on :9000
wails dev

# Terminal 2 -- second instance auto-picks :9001
./build/bin/chat0
```

In the second window, type `127.0.0.1:9000` in the **Connect** box and click
the button. The peer appears in the sidebar within a second.

### Local network

Find your IP address:

```bash
ip a # TODO : SEARCH A BETTER ONE    # Linux
ipconfig getifaddr en0            # macOS
ipconfig                          # Windows (look for IPv4 Address)
```

Share `YOUR_IP:9000` with everyone on the same network. They type it in their
Connect box.

### Over the internet (no server required)

```bash
# Option A -- ngrok tunnel (easiest)
ngrok tcp 9000
# Copy the printed address e.g. tcp://0.tcp.ngrok.io:12345 and share it

# Option B -- VPS bootstrap node
# Run chat0 on any VPS at VPS_IP:9000
# All clients add VPS_IP:9000 in the Bootstrap box
# Gossip automatically propagates peer addresses between clients
```

### Onion routing

Toggle **Onion routing** in the sidebar before sending. The message is
wrapped in 3 AES layers and routed through available relay peers. Messages
delivered via onion show the onion badge in the chat.

---

## Simulation harness

Tests delivery rate and censorship robustness without the UI:

```bash
go run ./simulation/
```

Spins up 5 in-process nodes, forms a ring mesh, sends 20 messages with 25%
simulated packet drops, and prints:

```
=== Simulation Results ===
Duration:         318ms
Messages sent:    15 / 20 (75% after censorship)
Messages dropped: 5
Messages received (all nodes): 43
Delivery rate:    57.3%

Per-node snapshots:
  node-0  peers=2  sent=4   recv=9   dropped=1
  node-1  peers=2  sent=3   recv=8   dropped=2
  ...
```

---

## Project layout

```
V-chat-O-main/
|-- main.go               Wails entry point (1024x768 window)
|-- app.go                App struct, startup, all Wails-bound methods
|-- go.mod                module chat0, Go 1.23, Wails v2.12
|-- wails.json            App name, build commands, author info
|
|-- crypto/
|   `-- crypto.go         X25519, AES-256-GCM, Ed25519, HKDF-SHA256
|
|-- onion/
|   `-- onion.go          Layered encryption: WrapMessage / PeelLayer
|
|-- p2p/
|   `-- node.go           TCP listener, handshake, gossip, dedup window
|
|-- discovery/
|   `-- discovery.go      SHA-256 PoW, reputation table, bootstrap manager
|
|-- metrics/
|   `-- metrics.go        Latency (avg+P99), delivery rate, censorship sim
|
|-- simulation/
|   `-- main.go           Headless 5-node evaluation harness
|
`-- frontend/
    |-- index.html
    |-- src/
    |   |-- main.ts       Rooms, peer list, metrics panel, onion toggle
    |   |-- app.css       Dark theme, 3-panel grid layout
    |   `-- style.css
    `-- wailsjs/          Auto-generated Go <-> TypeScript bindings
```

---

## Troubleshooting

| Problem                      | Likely cause            | Fix                                                  |
|------------------------------|-------------------------|------------------------------------------------------|
| `wails: command not found`   | GOPATH/bin not in PATH  | `export PATH=$PATH:$(go env GOPATH)/bin`             |
| `webkit2gtk not found`       | Missing system lib      | Arch: `sudo pacman -S webkit2gtk` / Ubuntu: see above|
| Port 9000 already in use     | Another process         | App falls back to `:0` -- check **Listen** in sidebar|
| Peer refuses connection      | Firewall blocking TCP   | `sudo ufw allow 9000/tcp`                            |
| `go mod tidy` fails          | Go version < 1.23       | Upgrade Go (see platform section)                    |
| Black window on Wayland      | WebKit/Wayland bug      | `GDK_BACKEND=x11 ./build/bin/chat0`                 |
| Startup slow (5-10 s)        | PoW solving             | Normal -- difficulty 20 takes 1-5 s, happens once   |
| Messages not appearing       | Wrong room selected     | Both nodes must be on the same room tab              |
| `tsc` error on `wails dev`   | Unused TS variable      | Remove unused variables from `frontend/src/main.ts`  |
