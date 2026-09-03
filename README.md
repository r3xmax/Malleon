# Malleon

Malleon automates HTTP/HTTPS configuration for Cobalt Strike Malleable C2 profiles using real traffic captured from legitimate applications.

```yaml
PS C:\Malleon> py malleon.py --help
usage: malleon [-h] {capture,build,run,inspect,setup,cleanup} ...

positional arguments:
  {capture,build,run,inspect,setup,cleanup}
    capture             Run a binary and capture its HTTP/HTTPS traffic
    build               Populate a Malleable C2 profile from captured flows
    run                 Capture traffic and populate a profile in one step (no intermediate file)
    inspect             Display a summary table of captured flows
    setup               One-time admin setup: generate CA cert, install in ROOT store, configure WinHTTP proxy
    cleanup             Undo 'malleon setup': remove mitmproxy CA cert from ROOT store and reset WinHTTP proxy

options:
  -h, --help            show this help message and exit
```

# Table of Contents

- [What it does](#what-it-does)
- [Quick Start](#quick-start)
- [Base Malleable Profile](#base-malleable-profile)
- [Installation](#installation)
- [Workflow](#workflow)
  - [Setup](#setup)
  - [Capture](#capture)
  - [Inspect](#inspect)
  - [Build](#build)
    - [Body Camouflage](#body-camouflage)
  - [Run](#run)
  - [Cleanup](#cleanup)
- [SEE THIS BEFORE PRODUCTION](#see-this-before-production)
- [Disclaimer](#disclaimer)

# What it does

Setting up the environment and configuring HTTP/HTTPS blocks for Malleable C2 profiles is slow. Set up a proxy manually, install the Burp Suite certificate, hunt for convincing requests by hand, copy and paste headers one by one... it all takes time, and the result isn't always convincing enough.

Malleon automates the whole process of environment configuration, traffic capture, and Malleable C2 profile population.

**The best part? You can use your own custom Malleable profile templates.** Malleon only populates the necessary `http-*` blocks, leaving the rest of your profile exactly as you defined it.

# Quick Start

```powershell
# One-time setup (run as administrator)
py malleon.py setup

# Capture traffic and populate your profile in one command
py malleon.py run --profile .\custom.profile --output .\onenote.profile -- 'C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE'

# Inspect what was captured before building (recommended)
py malleon.py capture -o .\flows.json -- 'C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE'
py malleon.py inspect flows.json
py malleon.py build flows.json --profile .\custom.profile --output .\output.profile --target-domain d.docs.live.net

# Clean up when done (run as administrator)
py malleon.py cleanup
```

# Base Malleable Profile

Malleon requires a base profile to work from. It is designed to let you use your own custom Malleable profiles and build different variants in seconds from a single `.json` capture file.

You can find a collection of Malleable C2 profiles in [this repository](https://github.com/xx0hcd/malleable-c2-profiles).

The blocks Malleon populates are:

- `http-get`, `http-post`, `http-stager`
- `http-config`
- `set useragent`

Everything else remains untouched. The `http-*` blocks do not need to be fully defined in your base profile. 

If a block is absent, Malleon will create it. If it already exists, Malleon will update only the fields it owns and leave everything else (including any `metadata`, `id`, and `output` blocks you have defined) exactly as they are.



# Installation

Malleon is designed for Windows and requires Python 3.10 or newer.

```powershell
git clone https://github.com/r3xmax/malleon.git
cd malleon
python3 -m pip install -e . # install Malleon as a module & dependencies (mitmproxy 10.0)
```

# Workflow

Malleon's capabilities are best explained by following the same workflow you would use when working with the tool in practice. Let's walk through it step by step.

## Setup

First, the proxy needs to be configured so Malleon can capture HTTP requests.

From an Administrator terminal, run the `setup` command.

```powershell
PS C:\Malleon> py malleon.py setup
mitmproxy CA certificate installed in Windows ROOT store.
WinINet: saved existing proxy settings.
WinINet: set ProxyEnable = 1.
WinINet: set ProxyServer = 127.0.0.1:8080.
WinINet: set ProxyOverride = "".
Setup complete.
```

This will install the mitmproxy CA certificate in the Windows ROOT store (that's why it requires elevated privileges) and configure both the `WinHTTP` and `WinINet` proxy stacks to route traffic through Malleon's MITM proxy.

## Capture

```powershell
PS C:\Malleon> py malleon.py capture --help
usage: malleon capture [-h] -o OUTPUT [-p PORT] [--timeout SECONDS] ...

positional arguments:
  binary_cmd            Binary and its arguments (use -- to separate from malleon flags)

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output JSON file
  -p PORT, --port PORT  Local proxy port (default: 8080)
  --timeout SECONDS     Kill the binary after this many seconds
```

It's recommended to capture traffic from a terminal without elevated privileges, as some applications do not allow themselves to be run as Administrator (e.g. OneDrive).

When running Malleon in `capture` mode, the specified application will be launched and Malleon will start capturing all incoming and outgoing requests.

```powershell
PS C:\Malleon> py malleon.py capture --output flows.json -- 'C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE'
```

Try to interact with the application as much as possible to capture different types of requests. This will give you more flexibility when building a good profile.

To finish the capture, simply close the application. Malleon will display a message with the captured flows.

```powershell
131 flows -> flows.json
```

A flow is basically the intermediate format Malleon uses to store each captured HTTP request together with its corresponding response as a pair.

## Inspect

The next step is to inspect the captured traffic.

```powershell
PS C:\Malleon> py malleon.py inspect --help                
usage: malleon inspect [-h] [--show-id INDICES] [-m METHOD] [-d DOMAIN] FLOWS_JSON

Prints a numbered flow table and a domain frequency summary.

positional arguments:
  FLOWS_JSON            Captured flows JSON to inspect

options:
  -h, --help            show this help message and exit
  --show-id INDICES     Comma-separated 1-based flow indices to display as raw HTTP dumps
  -m METHOD, --method METHOD
                        Filter table to flows with this HTTP method (case-insensitive)
  -d DOMAIN, --domain DOMAIN
                        Filter table to flows from this host (case-insensitive)
```

When running the inspect command without specifying any options, you can get a detailed view of the traffic captured previously.

```powershell
PS C:\Malleon> py malleon.py inspect flows.json
#    Method   Host                                            URI                                       Content-Type        
1    GET      support.content.office.net                      /whatsnew/a91c4f72-bd36-4e08-92fa-c7d...  -                   
2    GET      ecs.office.com                                  /config/v1/OneAuth-MSAL/10.2.1?OS=Win...  application/json    
3    PUT      recent.svc.cloud.microsoft                      /ocs/docs/recent?rs=es-ES                 -                   
4    GET      relcomms-prod-dagnegedescbeefs.b02.azurefd.net  /whatsnew/a91c4f72-bd36-4e08-92fa-c7d...  text/html           
5    POST     login.live.com                                  /RST2.srf                                 application/soap+xml
<SNIP>

Domains:
  d.docs.live.net                                 33 flow(s)
  my.microsoftpersonalcontent.com                 31 flow(s)
  mobile.events.data.microsoft.com                10 flow(s)
<SNIP>
```

Malleon allows you to display text dumps of flows (request & response pairs) using the `--show-id` parameter. This is especially useful when you need to verify which headers and body content will be used to populate the HTTP blocks of your profile, and choose the ones that best fit your use case.

```powershell
PS C:\Malleon> py malleon.py inspect flows.json --show-id 2,38
-----------------------------------------------------------------------------------------------------------------------------------
ID 2 | GET https://ecs.office.com/config/v1/OneAuth-MSAL/10.2.1?OS=Windows&ApplicationID=com.microsoft.Office&OneAuthVersion=10.2.1 (-)
-----------------------------------------------------------------------------------------------------------------------------------
GET /config/v1/OneAuth-MSAL/10.2.1?OS=Windows&ApplicationID=com.microsoft.Office&OneAuthVersion=10.2.1 HTTP/1.1
X-ECS-Client-Last-Telemetry-Events: ecs_client_library_name=OneAuth-MSAL,ecs_client_app_name=OneAuth-MSAL,ecs_client_version=10.2.1
If-None-Match: "<SNIP>"
User-Agent: OneAuth/10.2.1 (Windows)
Host: ecs.office.com

HTTP/1.1 304 Not Modified
Cache-Control: no-cache,max-age=3600
Content-Type: application/json
ETag: "<SNIP>"
Server: Microsoft-HTTPAPI/2.0
<SNIP>

-----------------------------------------------------------------------------------------------------------------------------------
ID 38 | POST https://d.docs.live.net/<RESOURCE_ID>/Documents/Example.one/_vti_bin/cellstorage.svc/CellStorageService (multipart/related)
-----------------------------------------------------------------------------------------------------------------------------------
POST /<RESOURCE_ID>/Documents/Example.one/_vti_bin/cellstorage.svc/CellStorageService HTTP/1.1
Connection: Keep-Alive
Content-Type: multipart/related; type="application/xop+xml"; boundary="urn:uuid:<BOUNDARY>"
<SNIP>
```

Flows can also be filtered by method (`--method`) and/or domain (`--domain`).

```powershell
# Shows only flows related to d.docs.live.net
PS C:\Malleon> py malleon.py inspect flows.json --domain d.docs.live.net

# Shows only GET method flows
PS C:\Malleon> py malleon.py inspect flows.json --method get

# Apply both filters at the same time
PS C:\Malleon> py malleon.py inspect flows.json --method post --domain d.docs.live.net
```

## Build

The captured `.json` flows file can now be used by the build module to populate your Cobalt Strike Malleable C2 profile.

```powershell
PS C:\Malleon> py malleon.py build --help
usage: malleon build [-h] --profile BASE_PROFILE -o OUTPUT_PROFILE [--target-domain DOMAIN] [-i INDICES] [--body-camouflage] [--body-split N] [--force-body-camouflage] FLOWS_JSON

Reads traffic fields (URIs, headers, user-agent) from a captured flows JSON produced by 'malleon capture' and writes them into the base profile, leaving all operator settings (sleep, jitter, staging, process injection) untouched.

positional arguments:
  FLOWS_JSON            Captured flows JSON (output of 'malleon capture')

options:
  -h, --help            show this help message and exit
  --profile BASE_PROFILE
                        Base Malleable C2 profile to populate
  -o OUTPUT_PROFILE, --output OUTPUT_PROFILE
                        Path for the populated output profile
  --target-domain DOMAIN
                        Only use flows from this host for profile population
  -i INDICES, --id INDICES
                        Comma-separated 1-based flow indices to use (e.g. 1,3,12). Mutually exclusive with --target-domain.
  --body-camouflage     Use the captured response body to hide C2 data inside http-get.server and http-post.server output blocks (prepend + append around beacon data).
  --body-split N        Bytes of the response body to use as prepend (first N) and append (last N). Default: 128.
  --force-body-camouflage
                        Like --body-camouflage but also replaces any existing 'output' block the operator has already defined in the base profile.
```

After inspecting the captured traffic, `substrate.office.com` stands out as the most interesting domain. Although it does not have the highest number of requests, it contains both GET and POST requests. This allows us to build a more complete profile without having to use GET headers to populate POST blocks, or vice versa.

The most basic way to build a profile is simply to specify the domain of interest using `--target-domain`.

```powershell
PS C:\Malleon> py malleon.py build flows.json --profile custom.profile --output onenote.profile --target-domain substrate.office.com                        
warning: http-get.client size is ~1584 bytes.
         May exceed the limit allowed by Cobalt Strike (typically ~500 bytes max).
         Remove headers manually from the output profile before production.
warning: http-post.client size is ~1968 bytes.
         May exceed the limit allowed by Cobalt Strike (typically ~500 bytes max).
         Remove headers manually from the output profile before production.
Profile written to onenote.profile
```

The warnings indicate that some specific sections exceed the byte limits allowed by Cobalt Strike. This is intentional; Malleon is designed to populate the profile with **all** available request and response content.

The operator should ultimately decide which content is most relevant for each use case. This approach keeps the captured information intact while allowing unnecessary content to be removed manually when needed.

Using `inspect` before `build` also allows you to select the exact requests with `--id`, giving you more control over the profile creation process instead of letting Malleon choose the flows automatically.

```powershell
PS C:\Malleon> py malleon.py inspect flows.json --domain substrate.office.com
#   Method  Host                  URI                            Content-Type    
22  GET     substrate.office.com  /imageB2/v1.0/me/image/$value  application/json
<SNIP>
43  POST    substrate.office.com  /api/v2.0/me/Signals           -               

PS C:\Malleon> py malleon.py build flows.json --profile custom.profile --output onenote.profile --force-body-camouflage --id 26,43
Profile written to onenote.profile
```

### Body Camouflage

Malleon features `--body-camouflage`, which automatically extracts real response body content from captured traffic and uses it to wrap the server output, embedding the encrypted beacon data between legitimate content in every C2 response.

It works by populating the `prepend` and `append` directives in `http-*.server.output`.

Example `http-*.server.output` without body camouflage:

```yaml
output {
  netbios;
  print;
}
```

Example `http-*.server.output` with body camouflage:

```yaml
output {
    base64;
    prepend "{\"error\":{\"code\":\"ImageNotFound\",\"message\":\"Exception of type 'Microsoft.People.Image.Common.Exceptions.ImageNotFoundException' ";
    append "e\":\"ImageNotFound\",\"message\":\"Exception of type 'Microsoft.People.Image.Common.Exceptions.ImageNotFoundException' was thrown.\"}}";
    print;
}
```

To enable it, use `--body-camouflage` or `--force-body-camouflage` depending on whether your base profile already has an `output` block defined in the `http-*` blocks.

```powershell
PS C:\Malleon> py malleon.py build flows.json --profile custom.profile --output onenote.profile --target-domain substrate.office.com --force-body-camouflage
warning: response body (142 chars) is shorter than 2x --body-split (256): --body-camouflage split may be ineffective.
<SNIP>
Profile written to onenote.profile
```

One useful aspect of this option is that it also allows you to specify the exact number of bytes to use to wrap the output with the `--body-split` option.

A few considerations to keep in mind:
- If not specified, the default value is `128`. This means that 128 bytes will be used for both the `prepend` and `append`.
- If the specified number of bytes is not available in the response body, Malleon will automatically split the available content in half. This means there is no need to worry about specifying a value that is too large.

## Run

The module `run` combines `capture` and `build` into a single command, skipping the intermediate flows file. It is useful when you already know which domain you want to target and do not need to inspect the traffic before building.

```powershell
PS C:\Malleon> py malleon.py run --profile custom.profile --output onenote.profile --target-domain substrate.office.com --force-body-camouflage -- 'C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE'
<SNIP>
93 flow(s) captured
Fields populated: useragent, http-get, http-post, http-config
Profile written to onenote.profile
```

Please note that the `run` command does not support `--id/-i`. Since traffic is captured and built in a single step, there is no opportunity to inspect the flows in between. If you need to handpick specific flows, use `capture` and `build` separately.

## Cleanup

Once you are done capturing traffic, the proxy configuration needs to be reverted.

From an Administrator terminal, run the `cleanup` command.

```powershell
PS C:\Malleon> py malleon.py cleanup
WinHTTP proxy reset to direct.
WinINet: no saved state found; using safe defaults.
WinINet: restored ProxyEnable = 0.
WinINet: deleted ProxyServer.
WinINet: deleted ProxyOverride.
mitmproxy CA certificate removed from Windows ROOT store.
Cleanup complete.
```

This will remove the mitmproxy CA certificate from the Windows ROOT store and restore both the `WinHTTP` and `WinINet` proxy stacks to their original state before `setup` was run.

# SEE THIS BEFORE PRODUCTION

Before putting a profile into production, there are two important limitations to keep in mind:
- Real applications like Chrome or Office generate traffic that far exceeds Cobalt Strike's compiled size limits. As mentioned earlier, Malleon puts all captured content into the HTTP configuration, leaving it up to the operator to remove whatever is not needed.
- **Hardcoded dynamic headers:** It is HIGHLY recommended to review and remove dynamic headers (such as `Date`, `X-Request-ID`, `MS-CV`, `X-ClientRequestId`, etc.) before production. These headers change on every real request and will be sent as static values by Cobalt Strike. Make sure to review these before deploying.

Being automated does not mean you should run it blindly; situational awareness matters in every operation. Good luck!

# Disclaimer

This tool was developed for **professional purposes** and is intended exclusively for security professionals and red team operators working in **authorized environments**.

The use of Malleon outside of this context is illegal and strictly prohibited. The author takes no responsibility for any misuse or damage caused by this tool.