# GoCatcher
<p align="justify">
GoCatcher is a small but powerfull tool designed to capture and analyze HTTP requests in real-time, allowing users to inspect and modify response parameters. It also enables storing custom payloads—such as HTML forms, JavaScript snippets, and XSS vectors—for targeted web penetration testing or CTFs. From a security perspective, GoCatcher is especially useful for identifying vulnerabilities like SSRF, XSS, etc. by testing how web applications handle injected inputs and manipulated requests, helping security professionals streamline testing and documentation of potential attack vectors.
</p>

> GoCatcher is the Go rewrite of the original Python `pyCatcher`. It ships as a single static binary with no runtime dependencies.

## Install
Requires Go 1.26+ to build.
```
git clone https://github.com/sp34rh34d/GoCatcher.git
cd GoCatcher
go build -o gocatcher .
./gocatcher
```

## Build for every OS
Cross-compiled binaries (Linux, macOS, Windows, FreeBSD / amd64·arm64·arm) are written to `dist/`:
```
make cross      # or: ./build.sh
```
Build only for the current platform:
```
make build      # produces ./gocatcher
```

## Test payloads (XSS · CSRF · SSTI · XXE · SSRF)
GoCatcher ships with built-in test payloads (source: `internal/payloads/assets/`).
They are **embedded in the binary and preloaded on startup**, so they are
available immediately — no seeding or `load` required. Just launch and serve:
```
./gocatcher
  list               # the payloads are already registered
  run --port 8080    # start serving them
```

They are designed to **call back** to the catcher (Burp-Collaborator style), so
a hit shows up in the request log. **Authorized testing / CTF / bug bounty only.**

| Route        | Content-Type          | Payload                                             |
|--------------|-----------------------|-----------------------------------------------------|
| `/xss`       | application/javascript| cookie/DOM/storage exfil hook + injection vectors   |
| `/csrf`      | text/html             | auto-submitting CSRF PoC (POST/GET/fetch variants)  |
| `/ssti`      | text/plain            | detection polyglot + per-engine RCE (Jinja2/Twig/…) |
| `/xxe`       | application/xml        | classic read, SSRF-via-XXE, blind OOB, PHP filter   |
| `/evil.dtd`  | application/xml-dtd    | OOB DTD used by the blind-XXE payload               |
| `/ssrf`      | text/plain            | callback, loopback/IP bypasses, cloud metadata      |
| `/lfi`       | text/plain            | path traversal, PHP wrappers, RFI                   |
| `/redirect`  | text/plain            | open-redirect bypasses                              |
| `/deser`     | text/plain            | insecure deserialization (Java/PHP/.NET/pickle)     |
| `/log4shell` | text/plain            | Log4Shell / JNDI strings                            |
| `/sqli`      | text/plain            | SQLi detection, UNION, time-based, OOB exfil        |
| `/pp`        | text/plain            | prototype pollution                                 |

Replace the `127.0.0.1:8080` callback host inside each payload with your
`--serveo` / EC2 URL when testing remote targets. Callbacks land on paths like
`/collect`, `/ssti-oob`, `/xxe-oob`, `/ssrf-hit` — all captured by the catch-all.
To edit or add your own, use the `add` command, or drop files in
`internal/payloads/assets/` and rebuild.

## Args
```
            --== options ==--
    exit                  ->  close this app
    list                  ->  show all custom routes
    add                   ->  add new route
       ├──  --path        ->  specify a name for the new route
       └──  --header      ->  set a custom header for every http response, you can add multiple headers
                              (--header ContentType:text/html --header test2:test2)
                              if you need add (space) on header value just add ++ 
                              (--header X-Custom-Header:This++is++a++test)
    load                  ->  load all registered custom routes from custom_routes.ini file
    save                  ->  save custom routes on custom_routes.ini file
    del --id <path id>    ->  delete specific path
    editor                ->  choose the editor for new routes (nano/neovim/vim)
    history [key=val …]   ->  show captured requests (filter by path/method/alert/remote)
    export <fmt> <file>   ->  export captures as json | csv | har
    replay <seq> <url>    ->  resend a captured request to a new target
    set <key> <value>     ->  save callback-url / slack / discord / telegram / webhook / dashboard-token
    config                ->  show saved configuration
    run                   ->  start http server
       ├──  --port        ->  specify http port (default 8080)
       ├──  --interface   ->  specify listen interface (default 0.0.0.0)
       ├──  --tunnel <p>  ->  expose local app via serveo | localhost.run | pinggy | ngrok | nip.io
       ├──  --ssl         ->  enable ssl context
       ├──  --key         ->  set private key (.key/.pem)
       ├──  --pub         ->  set public key (.crt/.pem)
       ├──  --dashboard   ->  serve the live web dashboard at /_dashboard
       ├──  --dns         ->  start the DNS callback listener (OOB exfil)
       ├──  --dns-port    ->  DNS listener port (default 5353)
       ├──  --quiet       ->  suppress console request log (still captured)
       └──  --log <file>  ->  append the request log to a file
    help                  ->  show this menu
```

## What's new in GoCatcher
Beyond catching requests, GoCatcher closes the full "serve payload → it fires →
capture, decode and get notified" loop:

- **Capture & history** — every request is stored (in-memory ring + appended to
  `gocatcher_requests.jsonl`). Browse with `history`, filter (`history path=/ssrf
  alert=XSS`), and `export json|csv|har` for your report.
- **Callback decoder & alerts** — hits on payload callback paths (`/collect`,
  `/ssti-oob`, `/xxe-oob`, `/ssrf-hit`, `/c/<token>`…) are classified
  (XSS/SSTI/XXE/SSRF/CSRF/…), the XSS beacon's base64 JSON is **decoded**, and a
  high-visibility `FIRED` banner is printed with the stolen cookies/DOM.
- **Notifications** — `set slack|discord|telegram-token+telegram-chat|webhook`
  to get pinged the moment a callback fires (great for bug bounty).
- **Live dashboard** — `run --dashboard` → open `/_dashboard` for a real-time
  feed (SSE), with filtering and alert highlighting; protect it with
  `set dashboard-token <secret>`.
- **Payload templating** — payloads may use `{{callback_url}}`, `{{token}}`,
  `{{victim_ip}}`, `{{host}}`, substituted on serve. Set your public URL once
  with `set callback-url https://you.serveo.net`.
- **SSRF redirector** — `/ssrf-redir?to=<url>` returns a 302 (defaults to cloud
  metadata) for redirect-based SSRF bypasses.
- **DNS callback** — `run --dns` starts a UDP DNS server that logs blind OOB
  exfiltration that only leaves the target over DNS.
- **More payloads** — in addition to XSS/CSRF/SSTI/XXE/SSRF: LFI/RFI, open
  redirect, insecure deserialization, Log4Shell/JNDI, SQLi (incl. OOB),
  prototype pollution. All preloaded (`list`).
- **Replay** — `replay <seq> <target>` resends any captured request elsewhere.

## Fetch GoCatcher on local network
Starting GoCatcher on port `1337`, allow internal network only (using a local web instance for testing)

<img width="920" height="697" alt="Captura de pantalla 2026-10-08 a la(s) 6 00 59 p  m" src="https://github.com/user-attachments/assets/b0a10f7a-9424-4b67-a62a-1b18b3fa7f09" />
<br>

## Fetch GoCatcher via internet
Sometimes you need to fetch your request catcher over internet (bugBounty/CTFs/pentesting), to expose your GoCatcher over internet, you can use a free [AWS EC2](https://aws.amazon.com/es/ec2/?trk=02bd2428-3348-4251-8b76-83ffa306f0f1&sc_channel=ps&ef_id=CjwKCAjw89jGBhB0EiwA2o1On8sv-Lp0963ncIsL-IVsaw-DsyBYpD8YT7UWJoWMhlqK8RxYmlvSEhoCVNkQAvD_BwE:G:s&s_kwcid=AL!4422!3!647999789403!e!!g!!aws%20ec2!19685287168!143348659342&gad_campaignid=19685287168&gbraid=0AAAAADjHtp8RYoaYTiZTBI93z1pldSMDl&gclid=CjwKCAjw89jGBhB0EiwA2o1On8sv-Lp0963ncIsL-IVsaw-DsyBYpD8YT7UWJoWMhlqK8RxYmlvSEhoCVNkQAvD_BwE) or using a port forward service like [lhr](https://localhost.run) / [serveo](https://serveo.net).\
GoCatcher can open the tunnel for you with `--tunnel <provider>` (or the legacy
`--serveo`). Pick whichever is up — serveo has been flaky:

| Provider | Command | Needs |
|---|---|---|
| serveo | `run --tunnel serveo` | ssh, serveo.net reachable |
| localhost.run | `run --tunnel localhost.run` | ssh |
| pinggy | `run --tunnel pinggy` | ssh (uses port 443) |
| ngrok | `run --tunnel ngrok` | `ngrok` binary + `ngrok config add-authtoken <token>` |
| nip.io | `run --tunnel nip.io` | nothing — but it is **DNS only** (no tunnel): it just gives a hostname that resolves to your IP, so the target must already be able to reach that IP (public/EC2 or same LAN) |

The assigned public URL is printed as `<provider> » https://…`. Set it as your
callback so payloads use it automatically: `set callback-url https://…`.
<br>
<img width="959" height="756" alt="Captura de pantalla 2026-10-08 a la(s) 6 03 58 p  m" src="https://github.com/user-attachments/assets/a2563ada-1acc-499d-9f8d-df01005d9c3c" />


## Adding a custom route and save your XSS payload
You can store your XSS payloads using the following command\
`add --path hello --header Referer:https://fakereferer.com/ --header X-Flag:just++testing`\
This opens your editor so you can paste/write the payload. The first time you
add a route, GoCatcher detects which editors are installed (**nano / neovim /
vim**) and shows an arrow-key menu to pick one (↑/↓ to move, ⏎ to select). The
choice is saved to `~/.gocatcher.conf` and reused for every new route — change
it anytime with the `editor` command.
<br>

<img width="1090" height="149" alt="Screenshot 2025-09-26 at 8 41 33 AM" src="https://github.com/user-attachments/assets/a79a8f33-b9d6-4dda-8ea2-94131a13ded0" />
<br>

<img width="1643" height="392" alt="Screenshot 2025-09-26 at 8 43 33 AM" src="https://github.com/user-attachments/assets/b54e0bbc-4255-492f-9ff9-0023cbd51807" />





