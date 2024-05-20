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
- NTLM/SMB/FTP(S)/RESPONDER Listener **(self-hosted)**
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

## Interactsh CLI Client

Interactsh Cli client requires **go1.20+** to install successfully. Run the following command to get the repo - 

```sh
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
```

### Default Run

This will generate a unique payload that can be used for OOB testing with minimal interaction information in the output.

```console
interactsh-client

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v0.0.5

        projectdiscovery.io

[INF] Listing 1 payload for OOB Testing
[INF] c23b2la0kl1krjcrdj10cndmnioyyyyyn.oast.pro

[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (A) from 172.253.226.100 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (AAAA) from 32.3.34.129 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received HTTP interaction from 43.22.22.50 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (MX) from 43.3.192.3 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (TXT) from 74.32.183.135 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received SMTP interaction from 32.85.166.50 at 2021-26-26 12:26
```

### Session File

`interactsh-client` with `-sf, -session-file` flag can be used store/read the current session information from user defined file which is useful to resume the same session to poll the interactions even after the client gets stopped or closed. 

```console
interactsh-client -sf interact.session

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ 1.0.3

        projectdiscovery.io

[INF] Listing 1 payload for OOB Testing
[INF] c23b2la0kl1krjcrdj10cndmnioyyyyyn.oast.pro

[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (A) from 172.253.226.100 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (AAAA) from 32.3.34.129 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received HTTP interaction from 43.22.22.50 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (MX) from 43.3.192.3 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (TXT) from 74.32.183.135 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received SMTP interaction from 32.85.166.50 at 2021-26-26 12:26
```

### Verbose Mode


Running the `interactsh-client` in **verbose mode** (v) to see the whole request and response, along with an output file to analyze afterwards.

```console
interactsh-client -v -o interactsh-logs.txt

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ 1.0.3

    projectdiscovery.io

[INF] Listing 1 payload for OOB Testing
[INF] c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro

[c58bduhe008dovpvhvugcfemp9yyyyyyn] Received HTTP interaction from 103.22.142.211 at 2021-09-26 18:08:07
------------
HTTP Request
------------

GET /favicon.ico HTTP/2.0
Host: c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro
Referer: https://c58bduhe008dovpvhvugcfemp9yyyyyyn.oast.pro
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36


-------------
HTTP Response
-------------

HTTP/1.1 200 OK
Connection: close
Content-Type: text/html; charset=utf-8
Server: oast.pro

<html><head></head><body>nyyyyyy9pmefcguvhvpvod800ehudb85c</body></html>
```

### Using Self-Hosted server

Using the `server` flag, `interactsh-client` can be configured to connect with a self-hosted Interactsh server, this flag accepts single or multiple server separated by comma.

```sh
interactsh-client -server hackwithautomation.com
```

We maintain a list of default Interactsh servers to use with `interactsh-client`:

- oast.pro
- oast.live
- oast.site
- oast.online
- oast.fun
- oast.me

Default servers are subject to change/rotate/down at any time, thus we recommend using a self-hosted interactsh server if you are experiencing issues with the default server.

### Using Protected Self-Hosted server

Using the `token` flag, `interactsh-client` can connect to a self-hosted Interactsh server that is protected with authentication.

```sh
interactsh-client -server hackwithautomation.com -token XXX
```

### Using with Notify

If you are away from your terminal, you may use [notify](https://github.com/projectdiscovery/notify) to send a real-time interaction notification to any supported platform.

```sh
interactsh-client | notify
```

![image](https://user-images.githubusercontent.com/8293321/116283535-9bcac180-a7a9-11eb-94d5-0313d4812fef.png)


## Interactsh Web Client

[Interactsh-web](https://github.com/projectdiscovery/interactsh-web) is a free and open-source web client that displays Interactsh interactions in a well-managed dashboard in your browser. It uses the browser's local storage to store and display all incoming interactions. By default, the web client is configured to use **interact.sh** as default interactsh server, and supports other self-hosted public/authencaited interactsh servers as well.

A hosted instance of **interactsh-web** client is available at https://app.interactsh.com

<img width="2032" alt="interactsh-web" src="https://user-images.githubusercontent.com/8293321/136621531-d72c9ece-0076-4db1-98c9-21dcba4ba09c.png">

## Interactsh Docker Client

A [Docker image](https://hub.docker.com/r/projectdiscovery/interactsh-client) is also provided with interactsh client that is ready to run and can be used in the following way:

```sh
docker run projectdiscovery/interactsh-client:latest
```

```console
docker run projectdiscovery/interactsh-client:latest

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v1.0.0

        projectdiscovery.io

[INF] Listing 1 payload for OOB Testing
[INF] c59e3crp82ke7bcnedq0cfjqdpeyyyyyn.oast.pro
```

## Burp Suite Extension

[interactsh-collaborator](https://github.com/wdahlenburg/interactsh-collaborator) is Burp Suite extension developed and maintained by [@wdahlenb](https://twitter.com/wdahlenb)

- Download latest JAR file from [releases](https://github.com/wdahlenburg/interactsh-collaborator/releases) page.
- Open Burp Suite &rarr; Extender &rarr; Add &rarr; Java &rarr; Select JAR file &rarr; Next
- New tab named **Interactsh** will be appeared upon successful installation.
- See the [interactsh-collaborator](https://github.com/wdahlenburg/interactsh-collaborator) project for more info.

<img width="2032" alt="burp" src="https://user-images.githubusercontent.com/8293321/135176099-0e3fa01c-bdce-4f04-a94f-de0a34c7abf6.png">

## OWASP ZAP Add-On

Interactsh can be used with OWASP ZAP via the [OAST add-on for ZAP](https://www.zaproxy.org/docs/desktop/addons/oast-support/). With ZAP's scripting capabilities, you can create powerful out-of-band scan rules that leverage Interactsh's features. A standalone script template has been provided as an example (it is added automatically when you install the add-on).

- Install the OAST add-on from the [ZAP Marketplace](https://www.zaproxy.org/addons/).
- Go to Tools &rarr; Options &rarr; OAST and select **Interactsh**.
- Configure [the options](https://www.zaproxy.org/docs/desktop/addons/oast-support/services/interactsh/options/) for the client and click on "New Payload" to generate a new payload.
- OOB interactions will appear in the [OAST Tab](https://www.zaproxy.org/docs/desktop/addons/oast-support/tab/) and you can click on any of them to view the full request and response.
- You can set Interactsh as the default for ActiveScan in the `Options` > `OAST` > `General` menu.
- When checking the `Use Permanent Database` option, you can review interactions that occurred after ZAP was terminated.
- See the [OAST add-on documentation](https://www.zaproxy.org/docs/desktop/addons/oast-support/) for more info.

![zap](https://user-images.githubusercontent.com/16446369/135211920-ed24ba5a-5547-4cd4-b6d8-656af9592c20.png)
*Interactsh in ZAP*

![Options > OAST > General](https://github.com/hahwul/interactsh/assets/13212227/005bb527-3f60-4822-8b76-f9a3fd06df83)
*`Options` > `OAST` > `General`*


-------


# Interactsh Server

Interactsh server runs multiple services and captures all the incoming requests. To host an instance of **interactsh-server**, you are required to setup:

1. Domain name with custom **host names** and **nameservers**.
2. Basic droplet running 24/7 in the background.

# Usage

```sh
interactsh-server -h
```

This will display help for the tool. Here are all the switches it supports.

```yaml
Usage:
  ./interactsh-server [flags]

Flags:
INPUT:
   -d, -domain string[]                     single/multiple configured domain to use for server
   -ip string                               public ip address to use for interactsh server
   -lip, -listen-ip string                  public ip address to listen on (default "0.0.0.0")
   -e, -eviction int                        number of days to persist interaction data in memory (default 30)
   -ne, -no-eviction                        disable periodic data eviction from memory
   -a, -auth                                enable authentication to server using random generated token
   -t, -token string                        enable authentication to server using given token
   -acao-url string                         origin url to send in acao header to use web-client) (default "*")
   -sa, -skip-acme                          skip acme registration (certificate checks/handshake + TLS protocols will be disabled)
   -se, -scan-everywhere                    scan canary token everywhere
   -cidl, -correlation-id-length int        length of the correlation id preamble (default 20)
   -cidn, -correlation-id-nonce-length int  length of the correlation id nonce (default 13)
   -cert string                             custom certificate path
   -privkey string                          custom private key path
   -oih, -origin-ip-header string           HTTP header containing origin ip (interactsh behind a reverse proxy)

CONFIG:
   -config string               flag configuration file (default "$HOME/.config/interactsh-server/config.yaml")
   -dr, -dynamic-resp           enable setting up arbitrary response data
   -cr, -custom-records string  custom dns records YAML file for DNS server
   -hi, -http-index string      custom index file for http server
   -hd, -http-directory string  directory with files to serve with http server
   -ds, -disk                   disk based storage
   -dsp, -disk-path string      disk storage path
   -csh, -server-header string  custom value of Server header in response
   -dv, -disable-version        disable publishing interactsh version in response header

UPDATE:
   -up, -update                 update interactsh-server to latest version
   -duc, -disable-update-check  disable automatic interactsh-server update check
   
SERVICES:
   -dns-port int           port to use for dns service (default 53)
   -http-port int          port to use for http service (default 80)
   -https-port int         port to use for https service (default 443)
   -smtp-port int          port to use for smtp service (default 25)
   -smtps-port int         port to use for smtps service (default 587)
   -smtp-autotls-port int  port to use for smtps autotls service (default 465)
   -ldap-port int          port to use for ldap service (default 389)
   -ldap                   enable ldap server with full logging (authenticated)
   -wc, -wildcard          enable wildcard interaction for interactsh domain (authenticated)
   -smb                    start smb agent - impacket and python 3 must be installed (authenticated)
   -responder              start responder agent - docker must be installed (authenticated)
   -ftp                    start ftp agent (authenticated)
   -smb-port int           port to use for smb service (default 445)
   -ftp-port int           port to use for ftp service (default 21)
   -ftps-port int          port to use for ftps service (default 990)
   -ftp-dir string         ftp directory - temporary if not specified

DEBUG:
   -version            show version of the project
   -debug              start interactsh server in debug mode
   -ep, -enable-pprof  enable pprof debugging server
   -health-check, -hc  run diagnostic check up
   -metrics            enable metrics endpoint
   -v, -verbose        display verbose interaction
```

We are using GoDaddy for domain name and DigitalOcean droplet for the server, a basic $5 droplet should be sufficient to run self-hosted Interactsh server. If you are not using GoDaddy, follow your registrar's process for creating / updating DNS entries.

<table>
<td>

## Configuring Interactsh domain

- Navigate to `https://dcc.godaddy.com/control/portfolio/{{domain}}/settings?subtab=hostnames`
- Add &rarr; Submit `ns1`, `ns2` with your `SERVER_IP` as value

<img width="1288" alt="gdd-hostname" src="https://user-images.githubusercontent.com/8293321/135175512-135259fb-0490-4038-845a-0b62b1b8f549.png">

- Navigate to `https://dcc.godaddy.com/control/dnsmanagement?domainName={{domain}}&subtab=nameservers`
- Change Nameservers &rarr; I'll use my own nameservers &rarr; Submit `ns1.INTERACTSH_DOMAIN`, `ns2.INTERACTSH_DOMAIN`

<img width="1288" alt="gdd-ns" src="https://user-images.githubusercontent.com/8293321/135175627-ea9639fd-353d-441b-a9a4-dae7f540d0ae.png">

</td>
</table>

<table>
<td>

## Configuring Interactsh server

Install `interactsh-server` on your **VPS**

```bash
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest
```

Considering domain name setup is **completed**, run the below command to run `interactsh-server`

```bash
interactsh-server -domain INTERACTSH_DOMAIN
```

Following is an example of a successful installation and operation of a self-hosted server:

![interactsh-server](https://user-images.githubusercontent.com/8293321/150676089-b5638c19-33a3-426a-987c-3ac6fa227012.png)

A number of needed flags are configured automatically to run `interactsh-server` with default settings. For example, `ip` and `listen-ip` flags set with the Public IP address of the system when possible.

</td>
</table>

## Running Interactsh Server

```console
interactsh-server -domain interact.sh

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v1.0.0

                projectdiscovery.io

[INF] Listening with the following services:
[HTTPS] Listening on TCP 46.101.25.250:443
[HTTP] Listening on TCP 46.101.25.250:80
[SMTPS] Listening on TCP 46.101.25.250:587
[LDAP] Listening on TCP 46.101.25.250:389
[SMTP] Listening on TCP 46.101.25.250:25
[DNS] Listening on TCP 46.101.25.250:53
[DNS] Listening on UDP 46.101.25.250:53
```

## Interactsh Server with Multiple Domain

Multiple domain names can be given in the same way as above to run the same interactsh server across multiple **configured domains**.

```console
interactsh-server -d oast.pro,oast.me

    _       __                       __       __
   (_)___  / /____  _________ ______/ /______/ /_
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ 1.0.5

                projectdiscovery.io

[INF] Loading existing SSL Certificate for:  [*.oast.pro, oast.pro]
[INF] Loading existing SSL Certificate for:  [*.oast.me, oast.me]
[INF] Listening with the following services:
[HTTPS] Listening on TCP 46.101.25.250:443
[HTTP] Listening on TCP 46.101.25.250:80
[SMTPS] Listening on TCP 46.101.25.250:587
[LDAP] Listening on TCP 46.101.25.250:389
[SMTP] Listening on TCP 46.101.25.250:25
[DNS] Listening on TCP 46.101.25.250:53
[DNS] Listening on UDP 46.101.25.250:53
```

<table>
<td>

**Note:**

While running interactsh server on **Cloud VM**'s like Amazon EC2, Google Cloud Platform (GCP), it is required to update the security rules to allow **"all traffic"** for inbound connections.

</td>
</table>

There are more useful capabilities supported by `interactsh-server` that are not enabled by default and are intended to be used only by **self-hosted** servers.

## Interactsh Server behind a reverse proxy

`interactsh-server` might require custom ports for services if the default ones are already busy. If this is the case but still default ports are required as part of the payload, it's possible to configure `interactsh-server` behind a reverse proxy, by port-forwarding HTTP/TCP/UDP based services via `http/stream` proxy directive (`proxy_pass`).

## Nginx

Assuming that `interactsh-server` essential services run on the following ports:

- HTTP: 8080/TCP
- HTTPS: 8440/TCP
- SMTP: 8025/TCP
- DNS: 8053/UDP
- DNS: 8053/TCP

The nginx configuration file to forward the traffic would look like the following one:

```conf
# http/https
http {
   server {
      listen 443 ssl;
      server_name mysite.com;
      ssl_certificate /etc/nginx/interactsh.pem;
      ssl_certificate_key /etc/nginx/interactsh.key;

      location / {
         proxy_pass https://interachsh.mysite.com:80/;
         proxy_set_header Host $host;
         proxy_set_header X-Real-IP $remote_addr;
         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
         proxy_set_header X-Forwarded-Proto $scheme;
      }        
   }
}

stream {
   # smtp
   server {
      listen 25;
      proxy_pass interachsh.mysite.com:8025;
   }

   # dns
   server {
      listen 53;
      proxy_pass interachsh.mysite.com:8053;
   }
   server {
      listen 53 udp;
      proxy_pass interachsh.mysite.com:8053;
   }
}
```

**Configured Domains**

```console
interactsh-server -d oast.pro,oast.me

    _       __                       __       __
   (_)___  / /____  _________ ______/ /______/ /_
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ 1.0.5

                projectdiscovery.io

[INF] Loading existing SSL Certificate for:  [*.oast.pro, oast.pro]
[INF] Loading existing SSL Certificate for:  [*.oast.me, oast.me]
[INF] Listening with the following services:
[HTTPS] Listening on TCP 46.101.25.250:443
[HTTP] Listening on TCP 46.101.25.250:80
[SMTPS] Listening on TCP 46.101.25.250:587
[LDAP] Listening on TCP 46.101.25.250:389
[SMTP] Listening on TCP 46.101.25.250:25
[DNS] Listening on TCP 46.101.25.250:53
[DNS] Listening on UDP 46.101.25.250:53
```

## Custom Server Index

Index page for http server can be customized while running custom interactsh server using `-http-index` flag.

```console
interactsh-server -d hackwithautomation.com -http-index banner.html
```

`{DOMAIN}` placeholder is also supported in index file to replace with server domain name.

![image](https://user-images.githubusercontent.com/8293321/179397016-f6ee12e0-5b0b-42b6-83e7-f0972a804655.png)


## Static File Hosting

Interactsh http server optionally enables file hosting to help in security testing. This capability can be used with a self-hosted server to serve files for common payloads for **XSS, XXE, RCE** and other attacks.

To use this feature, `-http-directory` flag can be used which accepts diretory as input and files are served under `/s/` directory.

```console
interactsh-server -d hackwithautomation.com -http-directory ./paylods
```

![image](https://user-images.githubusercontent.com/8293321/179396480-d5ff8399-8b91-48aa-b21f-c67e40e80945.png)

## Dynamic HTTP Response

Interactsh http server optionally enables responding with dynamic HTTP response by using query parameters. This feature can be enabled by using `-dr` or `-dynamic-resp` flag.

The following query parameter names are supported - `body`, `header`, `status` and `delay`. Multiple `header` parameters can be specified to set multiple headers. 

- **body** (response body)
- **header** (response header)
- **status** (response status code)
- **delay** (response time)

```console
curl -i 'https://hackwithautomation.com/x?status=307&body=this+is+example+body&delay=1&header=header1:value1&header=header1:value12'

HTTP/2 307 
header1: value1
header1: value12
server: hackwithautomation.com
x-interactsh-version: 1.0.7
content-type: text/plain; charset=utf-8
content-length: 20
date: Tue, 13 Sep 2022 12:31:05 GMT

this is example body
```

> **Note**:

- Dynamic HTTP Response feature is disabled as default.
- By design, this feature lets anyone run client-side code / redirects using your interactsh domain / server
- Using this option with an isolated domain is recommended to **avoid security impact** on associated root/subdomains.

## Wildcard Interaction

To enable `wildcard` interaction for configured Interactsh domain `wildcard` flag can be used with implicit authentication protection via the `auth` flag if the `token` flag is omitted.

```console
interactsh-server -domain hackwithautomation.com -wildcard

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v1.0.0

        projectdiscovery.io

[INF] Client Token: 699c55544ce1604c63edb769e51190acaad1f239589a35671ccabd664385cfc7
[INF] Listening with the following services:
[HTTPS] Listening on TCP 157.230.223.165:443
[HTTP] Listening on TCP 157.230.223.165:80
[SMTPS] Listening on TCP 157.230.223.165:587
[LDAP] Listening on TCP 157.230.223.165:389
[SMTP] Listening on TCP 157.230.223.165:25
[DNS] Listening on TCP 157.230.223.165:53
[DNS] Listening on UDP 157.230.223.165:53
```

## LDAP Interaction

As default, Interactsh server support LDAP interaction for the payload included in [search query](https://ldapwiki.com/wiki/LDAP%20Query%20Examples), additionally `ldap` flag can be used for complete logging.

```console
interactsh-server -domain hackwithautomation.com -sa -ldap

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v1.0.0

        projectdiscovery.io

[INF] Client Token: deb58fc151e6f0e53d448be3eb14cd7a11590d8950d142b9cd1abac3c2e3e7bc
[INF] Listening with the following services:
[DNS] Listening on UDP 157.230.223.165:53
[LDAP] Listening on TCP 157.230.223.165:389
[HTTP] Listening on TCP 157.230.223.165:80
[SMTP] Listening on TCP 157.230.223.165:25
[DNS] Listening on TCP 157.230.223.165:53
```

## Custom Payload Length

The length of the interactsh payload is **33** by default, consisting of **20** (unique correlation-id) + **13** (nonce token), which can be customized using the `cidl` and `cidn` flags to make shorter when required with self-hosted interacsh server.


```console
interactsh-server -d hackwithautomation.com -cidl 4 -cidn 6

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v1.0.2

        projectdiscovery.io

[INF] Loading existing SSL Certificate for:  [*.hackwithautomation.com, hackwithautomation.com]
[INF] Listening with the following services:
[HTTPS] Listening on TCP 157.230.223.165:443
[SMTPS] Listening on TCP 157.230.223.165:587
[DNS] Listening on UDP 157.230.223.165:53
[HTTP] Listening on TCP 157.230.223.165:80
[LDAP] Listening on TCP 157.230.223.165:389
[SMTP] Listening on TCP 157.230.223.165:25
[DNS] Listening on TCP 157.230.223.165:53
```

**Note:** It is important and required to use same length on both side (**client** and **server**), otherwise co-relation will not work.

```console
interactsh-client -s hackwithautomation.com -cidl 4 -cidn 6

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v1.0.2

        projectdiscovery.io

[INF] Listing 1 payload for OOB Testing
[INF] c8rf4e8xm4.hackwithautomation.com
```

## Custom SSL Certificate

The [certmagic](https://github.com/caddyserver/certmagic) library is used by default by interactsh server to produce wildcard certificates for requested domain in an automatic way. To use your own SSL certificate with self-hosted interactsh server, `cert` and `privkey` flag can be used to provider required certificate files.

**Note:** To utilize all of the functionality of the SSL protocol, a wildcard certificate is mandatory.


```console
interactsh-server -d hackwithautomation.com -cert hackwithautomation.com.crt -privkey hackwithautomation.com.key

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v1.0.2

        projectdiscovery.io

[INF] Listening with the following services:
[HTTPS] Listening on TCP 157.230.223.165:443
[SMTP] Listening on TCP 157.230.223.165:25
[HTTP] Listening on TCP 157.230.223.165:80
[LDAP] Listening on TCP 157.230.223.165:389
[DNS] Listening on TCP 157.230.223.165:53
[SMTPS] Listening on TCP 157.230.223.165:587
[DNS] Listening on UDP 157.230.223.165:53
```

## Supported Protocols

### FTP

FTP support can be enabled with the `-ftp` flag and is recommended for self-hosted instances only. The FTP agent simulates a fully-functional FTP server agent with authentication that captures authentications with every file operation. By default, the agent listens for clear text FTP on port 21 (this can be changed with the `-ftp-port` flag) and tls FTP on port 990 (this can be changed with the `-ftps-port` flag) and lists in read-only mode the content of the OS default temporary directory (customizable with the `-ftp-dir` option). The ftp engine uses the custom certificate and private key if provided or it will extract the certificate and private key from the first acme domain if provided.
Example of starting the FTP daemon and capturing a login interaction:

```console
$ sudo go run . -ftp -skip-acme -debug -domain localhost
...
[INF] Outbound IP: 192.168.1.16
[INF] Client Token: 6dc07e4a76c3d5e58e4bea13ce073dc403499b128c62397aff7b934a6e4822e3
[INF] Listening with the following services:
[DNS] Listening on TCP 192.168.1.16:53
[SMTP] Listening on TCP 192.168.1.16:25
[HTTP] Listening on TCP 192.168.1.16:80
[FTP] Listening on TCP 192.168.1.16:21
[DNS] Listening on UDP 192.168.1.16:53
[LDAP] Listening on TCP 192.168.1.16:389
[DBG] FTP Interaction: 
{"protocol":"ftp","unique-id":"","full-id":"","raw-request":"USER test\ntest logging in","remote-address":"127.0.0.1:51564","timestamp":"2022-09-29T00:49:42.212323+02:00"}
```

## External Supported Protocols

### SMB

The `-smb` flag enables the Samba protocol (only for self-hosted instances). The samba protocol uses [impacket](https://github.com/SecureAuthCorp/impacket) `smbserver` class to simulate a samba daemon share listening on port `445` unless changed by the `-smb-port` flag. When enabled, interactsh executes under the hoods the script `smb_server.py`. Hence Python3 and impacket dependencies are required.
Example of enabling the samba server:

```console
$ sudo interactsh-server -smb -skip-acme -debug -domain localhost
```

### Responder
[Responder](https://github.com/lgandx/Responder) is wrapped in a docker container exposing various service ports via docker port forwarding. The interactions are retrieved by monitoring the shared log file `Responder-Session.log` in the temp folder. To use it on a self-hosted instance, it's necessary first to build the docker container and tag it as `interactsh`(docker daemon must be configured correctly and with port forwarding capabilities):

```console
docker build . -t interactsh
```

Then run the service with:

```console
$ sudo interactsh-server -responder -d localhost
```

On default settings, the daemon listens on the following ports:

- UDP: 137, 138, 1434
+ TCP: 21 (might collide with FTP daemon if used), 110, 135, 139, 389, 445, 1433, 3141, 3128

## Interactsh Integration

### Use as library

The [examples](examples/) uses interactsh client library to get external interactions for a generated URL by making a http request to the URL.

### Nuclei - OAST

[Nuclei](https://github.com/projectdiscovery/nuclei) vulnerability scanner utilize **Interactsh** for automated payload generation and detection of out of band based security vulnerabilities.

See [Nuclei + Interactsh](https://blog.projectdiscovery.io/nuclei-interactsh-integration/) Integration blog and [guide document](https://nuclei.projectdiscovery.io/templating-guide/interactsh/) for more information.

# Cloud Metadata

Interactsh server supports DNS records for cloud metadata services, which is useful for testing SSRF-related vulnerabilities.

Currently supported metadata services:

- [AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- [Alibaba](https://www.alibabacloud.com/blog/alibaba-cloud-ecs-metadata-user-data-and-dynamic-data_594351)

Example:

* **aws.interact.sh** points to 169.254.169.254
* **alibaba.interact.sh** points to 100.100.100.200

-----

### Acknowledgement

Interactsh is inspired from [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator).

### License

Interactsh is distributed under [MIT License](https://github.com/projectdiscovery/interactsh/blob/master/LICENSE.md) and made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team.

