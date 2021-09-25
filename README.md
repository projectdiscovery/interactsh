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
  <a href="#installing-interactsh-client">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#running-interactsh-client">Interactsh Client</a> •
  <a href="#setting-up-self-hosted-instance">Interactsh Server</a> •
  <a href="#burp-suite-extension">Burp Suite Extension</a> •
  <a href="#owasp-zap-addon">OWASP ZAP Add-on</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>

---

**Interactsh** is an Open-Source Solution for Out of band Data Extraction, A tool designed to detect bugs that cause external interactions, For example - Blind SQLi, Blind CMDi, SSRF, etc.


# Features

- DNS/HTTP/SMTP Interaction support
- CLI / Web / Burp / ZAP Client support
- AES encryption with zero logging
- SELF Hosted server support
- Automatic ACME based Wildcard TLS w/ Auto Renewal

A hosted instance of the service with WEB UI is available at https://interact.projectdiscovery.io.


<table>
<td>
<b>Note:</b> No data is retained on the server, restarting it for maintenance / accidental crash will wipe out prior interactions.
</td>
</table>


# Installing Interactsh Client

Interactsh Client requires **go1.15+** to install successfully. Run the following command to get the repo - 

```sh
GO111MODULE=on go get -v github.com/projectdiscovery/interactsh/cmd/interactsh-client
```

# Usage

```sh
interactsh-client -h
```

This will display help for the tool. Here are all the switches it supports.

| Flag          | Description                                                  | Example                                    |
| ------------- | ------------------------------------------------------------ | ------------------------------------------ |
| n             | Number of interactable URLs to generate (default 1)          | interactsh-client -n 2                     |
| poll-interval | Number of seconds between each poll request (default 5)      | interactsh-client -poll-interval 1         |
| url           | URL of the interactsh server (default "hxxps://interact.sh") | interactsh-client -url hxxps://example.com |
| dns-only      | Filter DNS  interactions                                     | interactsh-client -dns-only                |
| http-only     | Filter HTTP interactions                                     | interactsh-client -http-only               |
| smtp-only     | Filter SMTP interactions                                     | interactsh-client -smtp-only               |
| json          | Show JSON output                                             | interactsh-client -json                    |
| o             | Store interaction logs to file                               | interactsh-client -o logs.txt              |
| v             | Show verbose interaction                                     | interactsh-client -v                       |


### Running Interactsh Client

This will generate single URL that can be used for interaction.

```console
interactsh-client

    _       __                       __       __  
   (_)___  / /____  _________ ______/ /______/ /_ 
  / / __ \/ __/ _ \/ ___/ __ '/ ___/ __/ ___/ __ \
 / / / / / /_/  __/ /  / /_/ / /__/ /_(__  ) / / /
/_/_/ /_/\__/\___/_/   \__,_/\___/\__/____/_/ /_/ v0.0.4

    projectdiscovery.io

[INF] Listing 1 URL for OOB Testing
[INF] c23b2la0kl1krjcrdj10cndmnioyyyyyn.interact.sh

[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (A) from 172.253.226.100 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (AAAA) from 32.3.34.129 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received HTTP interaction from 43.22.22.50 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (MX) from 43.3.192.3 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received DNS interaction (TXT) from 74.32.183.135 at 2021-26-26 12:26
[c23b2la0kl1krjcrdj10cndmnioyyyyyn] Received SMTP interaction from 32.85.166.50 at 2021-26-26 12:26
```

### Sending Interaction to Discord,Slack,Telegram with Notify

```sh
interactsh-client | notify
```

![image](https://user-images.githubusercontent.com/8293321/116283535-9bcac180-a7a9-11eb-94d5-0313d4812fef.png)


### Burp Suite Extension

Interactsh client can be used within burp suite using [interactsh-collaborator](https://github.com/wdahlenburg/interactsh-collaborator) extension devloped by [@wdahlenb](https://twitter.com/wdahlenb)

- Download latest JAR file from https://github.com/wdahlenburg/interactsh-collaborator/releases
- Open Burp suite, Navigate to **Extender** tab, Click on **Add** and select the downloaded JAR file
- New tab named **Interactsh** will be appeared upon successful installation.


### OWASP ZAP Add-On

Interactsh can be used with OWASP ZAP via the [OAST add-on for ZAP](https://www.zaproxy.org/docs/desktop/addons/oast-support/). With ZAP's scripting capabilities, you can create powerful out-of-band scan rules that leverage Interactsh's features. A standalone script template has been provided as an example (it is added automatically when you install the add-on).

- Install the OAST add-on from the [ZAP Marketplace](https://www.zaproxy.org/addons/).
- Go to Tools &rarr; Options &rarr; OAST and select **Interactsh**.
- Configure [the options](https://www.zaproxy.org/docs/desktop/addons/oast-support/services/interactsh/options/) for the client and click on "New Payload" to generate a new payload.
- OOB interactions will appear in the [OAST Tab](https://www.zaproxy.org/docs/desktop/addons/oast-support/tab/) and you can click on any of them to view the full request and response.
- See the [OAST add-on documentation](https://www.zaproxy.org/docs/desktop/addons/oast-support/) for more info.


### Setting up self-hosted instance 

<details>
<summary>Click here for details</summary>
<br>


1. Navigate to `https://dcc.godaddy.com/manage/{{domain}}/dns/hosts` > Advanced Features > Host names, add `ns1` and `ns2` as hostnames with the **IP** of your server.
 
2. Navigate to `https://dns.godaddy.com/{{domain}}/nameservers` > Enter my own nameservers (advanced) > Add `ns1.{{domain}}` and `ns2.{{domain}}` as name servers.

3. Installing **interactsh-server** on your server.

```bash
GO111MODULE=on go get -v github.com/projectdiscovery/interactsh/cmd/interactsh-server
```

4. Starting **interactsh-server**, to ensure server is always running in the background, make sure to start the server in the screen session.

```bash
interactsh-server -domain {{Domain}} -hostmaster admin@{{Domain}} -ip {{Server_IP}} -listen-ip {{Server_IP}}
```

```bash
interactsh-server -domain example.com -hostmaster admin@example.com -ip XX.XX.XX.XX -listen-ip XX.XX.XX.XX
```

Server setup should be completed with this, now client can be used to generate your own payloads.

5. Installing **interactsh-client** for using interactsh service.

```
GO111MODULE=on go get -v github.com/projectdiscovery/interactsh/cmd/interactsh-client
```

6. Running **interactsh-clien**t with **self-hosted** domain.

```
interactsh-client -url https://example.com
```

</details>

### Acknowledgement

Interactsh is inspired from [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator).

### License

Interactsh is distributed under [MIT License](https://github.com/projectdiscovery/interactsh/blob/master/LICENSE.md) and made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team.