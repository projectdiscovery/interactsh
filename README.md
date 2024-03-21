<h1 align="center">
  <br>
<img src="https://user-images.githubusercontent.com/8293321/150756129-df9990c2-cdc0-4c6e-b3ae-3d17079968c5.png" width="200px" alt="Interactsh"></a>
</h1>
<h4 align="center">An OOB interaction gathering server and client library</h4>

<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://github.com/projectdiscovery/interactsh/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://goreportcard.com/badge/github.com/projectdiscovery/interactsh"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/interactsh"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#usage">Usage</a> •
  <a href="#interactsh-client">Interactsh Client</a> •
  <a href="#interactsh-server">Interactsh Server</a> •
  <a href="#interactsh-integration">Interactsh Integration</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>

---

**Interactsh** is an open-source tool for detecting out-of-band interactions. It is a tool designed to detect vulnerabilities that cause external interactions.

# Features

- DNS/HTTP(S)/SMTP(S)/LDAP Interaction
- CLI / Web / Burp / ZAP / Docker client
- AES encryption with zero logging
- Automatic ACME based Wildcard TLS w/ Auto Renewal
- DNS Entries for Cloud Metadata service
- Dynamic HTTP Response control
- Self-Hosted Interactsh Server
- Multiple domain support **(self-hosted)**
- NTLM/SMB/FTP/RESPONDER Listener **(self-hosted)**
- Wildcard / Protected Interactions **(self-hosted)**
- Customizable Index / File hosting **(self-hosted)**
- Customizable Payload Length **(self-hosted)**
- Custom SSL Certificate **(self-hosted)**

# Interactsh Client

## Usage

```sh
interactsh-client -h
```

This will display help for the tool. Here are all the switches it supports.

```yaml
Usage:
  ./interactsh-client [flags]

Flags:
INPUT:
   -s, -server string  interactsh server(s) to use (default "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me")

CONFIG:
   -config string                           flag configuration file (default "$HOME/.config/interactsh-client/config.yaml")
   -n, -number int                          number of interactsh payload to generate (default 1)
   -t, -token string                        authentication token to connect protected interactsh server
   -pi, -poll-interval int                  poll interval in seconds to pull interaction data (default 5)
   -nf, -no-http-fallback                   disable http fallback registration
   -cidl, -correlation-id-length int        length of the correlation id preamble (default 20)
   -cidn, -correlation-id-nonce-length int  length of the correlation id nonce (default 13)
   -sf, -session-file string                store/read from session file

FILTER:
   -m, -match string[]   match interaction based on the specified pattern
   -f, -filter string[]  filter interaction based on the specified pattern
   -dns-only             display only dns interaction in CLI output
   -http-only            display only http interaction in CLI output
   -smtp-only            display only smtp interactions in CLI output

UPDATE:
   -up, -update                 update interactsh-client to latest version
   -duc, -disable-update-check  disable automatic interactsh-client update check
   
OUTPUT:
   -o string                         output file to write interaction data
   -json                             write output in JSONL(ines) format
   -ps, -payload-store               enable storing generated interactsh payload to file
   -psf, -payload-store-file string  store generated interactsh payloads to given file (default "interactsh_payload.txt")
   -v                                display verbose interaction

DEBUG:
   -version            show version of the project
   -health-check, -hc  run diagnostic check up
```

## Running interactsh
See https://docs.projectdiscovery.io/tools/interactsh/running for more details on running interactsh-server and interactsh-client.

## Client & Server
The Interactsh tool comprises two main components: [`interachsh-cleint`](https://docs.projectdiscovery.io/tools/interactsh/running) and [`interachsh-server`](https://docs.projectdiscovery.io/tools/interactsh/server). Each plays a critical role in the process of detecting out-of-band vulnerabilities, but they operate in distinct manners and serve different purposes.

### Interactsh Server
* Function: Captures and records callbacks from interaction URLs.
* Deployment: Hosted publicly to receive requests from tested systems.
* Use Case: Ideal for those hosting their instance for privacy or control.

ProjectDiscovery maintains a number of [publically accessable interactsh servers](https://docs.projectdiscovery.io/tools/interactsh/running#projectdiscovery-interachsh-servers) that you can use in order to only run the client for your specific use case. Alternatively, you can [self host your own interactsh server](https://docs.projectdiscovery.io/tools/interactsh/running#self-hosted-interactsh-server) if you want it to run on your custom domain or you need more control over the server side interactions.

### Interactsh Client
* Function: Generates URLs for testing, retrieves interaction logs from the server.
* Deployment: Runs locally for managing URLs and analyzing captured data.
* Use Case: Used by testers to create and analyze tests for out-of-band vulnerabilities.

### Acknowledgement

Interactsh is inspired from [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator).

### License

Interactsh is distributed under [MIT License](https://github.com/projectdiscovery/interactsh/blob/master/LICENSE.md) and made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team.

