<h1 align="center">Interactsh</h1>
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

**Interactsh** is an Open-Source Solution for Out of band Data Extraction, A tool designed to detect bugs that cause external interactions, For example - Blind SQLi, Blind CMDi, SSRF, etc.


# Features

- DNS/HTTP/HTTPS/SMTP Interaction support
- NTLM/SMB Listener support (self-hosted)
- Wildcard Interaction support (self-hosted)
- CLI / Web / Burp / ZAP Client support
- AES encryption with zero logging
- SELF Hosted Interactsh server support
- Automatic ACME based Wildcard TLS w/ Auto Renewal

# Interactsh Client

## Interactsh CLI Client

Interactsh Cli client requires **go1.17+** to install successfully. Run the following command to get the repo - 

```sh
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
```

### Running Interactsh CLI Client

This will generate a unique payload that can be used for OOB testing with minimal interaction information in the ouput.

```console
interactsh-client

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v0.0.5

        projectdiscovery.io

[INF] Listing 1 payload for OOB Testing
[INF] c23b2la0kl1krjcrdj10cndmnioyyyyyn.interactsh.com

[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (A) from 172.253.226.100 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (AAAA) from 32.3.34.129 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received HTTP interaction from 43.22.22.50 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (MX) from 43.3.192.3 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (TXT) from 74.32.183.135 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received SMTP interaction from 32.85.166.50 at 2021-26-26 12:26
```

Running the Interactsh client in **verbose mode** (v) to see the whole request and response, along with an output file to analyze afterwards.

```console
interactsh-client -v -o interactsh-logs.txt

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v0.0.5

    projectdiscovery.io

[INF] Listing 1 payload for OOB Testing
[INF] c58bduhe008dovpvhvugcfemp9yyyyyyn.interactsh.com

[c58bduhe008dovpvhvugcfemp9yyyyyyn] Received HTTP interaction from 103.22.142.211 at 2021-09-26 18:08:07
------------
HTTP Request
------------

GET /favicon.ico HTTP/2.0
Host: c58bduhe008dovpvhvugcfemp9yyyyyyn.interactsh.com
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Accept-Encoding: gzip, deflate, br
Accept-Language: en-IN,en;q=0.9
Cookie: _ga=GA1.2.440163205.1619796009; _iub_cs-77854424=%7B%22timestamp%22%3A%222021-04-30T15%3A23%3A23.192Z%22%2C%22version%22%3A%221.30.2%22%2C%22consent%22%3Atrue%2C%22id%22%3A77854424%7D
Referer: https://c58bduhe008dovpvhvugcfemp9yyyyyyn.interactsh.com/
Sec-Ch-Ua: "Google Chrome";v="93", " Not;A Brand";v="99", "Chromium";v="93"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Sec-Fetch-Dest: image
Sec-Fetch-Mode: no-cors
Sec-Fetch-Site: same-origin
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36



-------------
HTTP Response
-------------

HTTP/1.1 200 OK
Connection: close
Content-Type: text/html; charset=utf-8
Server: interactsh.com

<html><head></head><body>nyyyyyy9pmefcguvhvpvod800ehudb85c</body></html>
```

Using the `server` flag, Interactsh client can be configured to connect with a self-hosted interactsh server.

```sh
interactsh-client -server hackwithautomation.com
```

Using the `token` flag, Interactsh client can connect to a self-hosted interactsh server that is protected with authentication.

```sh
interactsh-client -server hackwithautomation.com -token XXX
```

If you are away from your terminal, you may use [notify](https://github.com/projectdiscovery/notify) to send a real-time interaction notification to any supported platform.

```sh
interactsh-client | notify
```

![image](https://user-images.githubusercontent.com/8293321/116283535-9bcac180-a7a9-11eb-94d5-0313d4812fef.png)


# Usage

```sh
interactsh-client -h
```

This will display help for the tool. Here are all the switches it supports.

| Flag          | Description                                         | Example                               |
| ------------- | --------------------------------------------------- | ------------------------------------- |
| n             | Interactsh payload count to generate (default 1)    | interactsh-client -n 2                |
| poll-interval | Interaction poll interval in seconds (default 5)    | interactsh-client -poll-interval 1    |
| server        | Interactsh server to use (default "interactsh.com") | interactsh-client -server domain.com |
| dns-only      | Display only DNS interaction in CLI output          | interactsh-client -dns-only           |
| http-only     | Display only HTTP interaction in CLI output         | interactsh-client -http-only          |
| smtp-only     | Display only SMTP interaction in CLI output         | interactsh-client -smtp-only          |
| json          | Write output in JSONL(ines) format                  | interactsh-client -json               |
| token         | Authentication token to connect interactsh server   | interactsh-client -token XXX          |
| persist       | Enables persistent interactsh sessions              | interactsh-client -persist            |
| o             | Output file to write interaction                    | interactsh-client -o logs.txt         |
| v             | Show verbose interaction                            | interactsh-client -v                  |


## Interactsh Web Client

[Interactsh-web](https://github.com/projectdiscovery/interactsh-web) is a free and open-source web client that displays Interactsh interactions in a well-managed dashboard in your browser. It uses the browser's local storage to store and display all incoming interactions. By default, the web client is configured to use - **interachsh.com**, a cloud-hosted interactsh server, and supports other self-hosted public/authencaited interactsh servers as well.

A hosted instance of **interactsh-web** client is available at https://app.interactsh.com

<img width="2032" alt="interactsh-web" src="https://user-images.githubusercontent.com/8293321/134819734-136b0109-972a-42f9-b4f4-9498d944d15d.png">


## Interactsh Docker Client

Interactsh client includes a [Docker image](https://hub.docker.com/r/projectdiscovery/interactsh-client) that is ready to run and can be used in the following way:

```sh
docker run projectdiscovery/interactsh-client:latest
```

```console
docker run projectdiscovery/interactsh-client:latest

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v0.0.5

        projectdiscovery.io

[INF] Listing 1 payload for OOB Testing
[INF] c59e3crp82ke7bcnedq0cfjqdpeyyyyyn.interactsh.com
```

## Burp Suite Extension

[interactsh-collaborator](https://github.com/wdahlenburg/interactsh-collaborator) is Burp Suite extension developed and maintained by [@wdahlenb](https://twitter.com/wdahlenb)

- Download latest JAR file from [releases](https://github.com/wdahlenburg/interactsh-collaborator/releases) page.
- Open Burp Suite &rarr; Extender &rarr; Add &rarr; Java &rarr; Select JAR file &rarr; Next
- New tab named **Interactsh** will be appeared upon successful installation.
- See the [interactsh-collaborator](https://github.com/wdahlenburg/interactsh-collaborator) project for more info.

<img width="2032" alt="burp" src="https://user-images.githubusercontent.com/8293321/134889745-b542d0b9-1232-4d85-9447-826d48c0e3ee.png">

### OWASP ZAP Add-On

Interactsh can be used with OWASP ZAP via the [OAST add-on for ZAP](https://www.zaproxy.org/docs/desktop/addons/oast-support/). With ZAP's scripting capabilities, you can create powerful out-of-band scan rules that leverage Interactsh's features. A standalone script template has been provided as an example (it is added automatically when you install the add-on).

- Install the OAST add-on from the [ZAP Marketplace](https://www.zaproxy.org/addons/).
- Go to Tools &rarr; Options &rarr; OAST and select **Interactsh**.
- Configure [the options](https://www.zaproxy.org/docs/desktop/addons/oast-support/services/interactsh/options/) for the client and click on "New Payload" to generate a new payload.
- OOB interactions will appear in the [OAST Tab](https://www.zaproxy.org/docs/desktop/addons/oast-support/tab/) and you can click on any of them to view the full request and response.
- See the [OAST add-on documentation](https://www.zaproxy.org/docs/desktop/addons/oast-support/) for more info.


# Interactsh Server

Interactsh server runs multiple web services and capture all the incoming requests, to host interactsh-server, you are required to have followings:

1. Domain name with custom **host names** and **nameservers**.
2. Basic VPS running 24/7 in the background.

We are using GoDaddy for domain name and DigitalOcean droplet for the server, a basic $5 droplet should be sufficient to run self-hosted Interactsh server. If you are not using GoDaddy, follow your registrar's process for creating / updating DNS entries.

<table>
<td>

## Configuring Interactsh domain

- Navigate to `https://dcc.godaddy.com/manage/{{domain}}/dns`
- Advanced Features &rarr; Host names &rarr; Add &rarr; Submit `ns1`, `ns2` with `VPS IP` as value

<img width="1288" alt="gdd-hostname" src="https://user-images.githubusercontent.com/8293321/134817477-1f83e9c4-8a2a-4f7e-bc66-106a1eb41ff1.png">

- Navigate to `https://dns.godaddy.com/{{domain}}/nameservers`
- I'll use my own nameservers &rarr; Submit `ns1.{{domain}}`, `ns2.{{domain}}`

<img width="1500" height="500" alt="gdd-ns" src="https://user-images.githubusercontent.com/8293321/134817482-15e3dc4f-6429-4e2d-9ff4-b25289cfd172.png">

</td>
</table>

<table>
<td>

## Configuring Interactsh server


Install interactsh-server on your **remote VPS**

```bash
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest
```

Considering **domain name setup is completed**, run the below command to run interactsh server

```bash
interactsh-server -domain domain.com
```

**Alternatively**, you can utilize ready to run [docker image](https://hub.docker.com/r/projectdiscovery/interactsh-server) of interactsh-server on your **remote machine** with

```sh
docker run projectdiscovery/interactsh-server:latest -domain domain.com
```

Following is an example of a successful installation and operation of a self-hosted server:

![interactsh-server](https://user-images.githubusercontent.com/8293321/134819391-51137c77-61d5-4ae8-9504-947dd444d863.png)


A number of needed flags are configured automatically to run interactsh server with default settings. For example, the `hostmaster` flag with a valid email address such as `admin@domain.com` and the `ip` and `listen-ip` flags with the public IP address of the VPS.

A hosted instance of **interactsh-server** used as default with interactsh-client is available at https://interactsh.com

</td>
</table>

# Usage

```sh
interactsh-server -h
```

This will display help for the tool. Here are all the switches it supports.

| Flag       | Description                                                  | Example                                           |
| ---------- | ------------------------------------------------------------ | ------------------------------------------------- |
| auth       | Enable authentication to server using random generated token | interactsh-server -auth                           |
| token      | Enable authentication to server using given token            | interactsh-server -token MY_TOKEN                 |
| domain     | Domain to use for interactsh server                          | interactsh-server -server domain.com             |
| eviction   | Number of days to persist interactions for (default 30)      | interactsh-server -domain domain.com             |
| hostmaster | Hostmaster email to use for interactsh server                | interactsh-server -hostmaster admin@domain.com   |
| ip         | Public IP Address to use for interactsh server               | interactsh-server -ip XX.XX.XX.XX                 |
| listen-ip  | Public IP Address to listen on                               | interactsh-server -listen-ip XX.XX.XX.XX          |
| root-tld   | Enable wildcard/global interaction for *.domain.com          | interactsh-server -root-tld                       |
| origin-url | Origin URL to send in ACAO Header                            | interactsh-server -origin-url https://domain.com |
| responder  | Start a responder agent - docker must be installed           | interactsh-server -responder                      |
| smb        | Start a smb agent - impacket and python 3 must be installed  | interactsh-server -smb                            |
| debug      | Run interactsh in debug mode                                 | interactsh-server -debug                          |


There are more useful capabilities supported by Interactsh server that are not enabled by default and are intended to be used only by self-hosted servers. These feature are **not** available with hosted server at https://interactsh.com

`root-tld` flag enables wildcard (`*.domain.com`) interaction support with your self-hosted server and includes implicit authentication protection via the `auth` flag if the `token` flag is omitted.

```bash
interactsh-server -domain domain.com -root-tld

2021/09/28 12:18:24 Client Token: 4c17895a460123ea439abbad64e0e02c2c7be660464d75299f76e1a972ac4e56
2021/09/28 12:18:24 TLS certificates are not expiring, continue!
2021/09/28 12:18:24 Listening on DNS, SMTP and HTTP ports
```

# Interactsh Integration

### Nuclei - OOB Scan

[Nuclei](https://github.com/projectdiscovery/nuclei) is fast and customizable vulnerability scanner utilize **Interactsh** for automated payload generation and detection of out of band based security vulnerabilities.

See [Nuclei + Interactsh](https://blog.projectdiscovery.io/nuclei-interactsh-integration/) Integration blog and [guide document](https://nuclei.projectdiscovery.io/templating-guide/interactsh/) for more info.

-----

### Acknowledgement

Interactsh is inspired from [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator).

### License

Interactsh is distributed under [MIT License](https://github.com/projectdiscovery/interactsh/blob/master/LICENSE.md) and made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team.