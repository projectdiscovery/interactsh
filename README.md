# Interactsh

Interact.sh is an Open-Source OOB Data Extraction tool designed to detect bugs that cause external interactions, For example - Blind SQLi, Blind CMDi, SSRF, etc.

A hosted instance of the service is available at https://interact.sh.

### Installation instruction for self-hosting interactsh client / server

1. We will be using [lego](https://github.com/go-acme/lego), Let's Encrypt client and ACME library for setting up **wildcard certificate** and [GoDaddy](https://godaddy.com) domain provider.

```bash
apt install lego
```

To automate certificate creation and verifcation we will using pair of **GoDaddy API** key/secret that can be generated from https://developer.godaddy.com/keys

2. Execute the following command by replacing appropriate values of `{{ }}`.

```bash
GODADDY_API_KEY={{GODADDY_API_KEY}} \
GODADDY_API_SECRET={{GODADDY_API_SECRET}} \
lego --dns godaddy --domains "*.{{domain}}" --domains "{{domain}}" --email {{godaddy_email}} run
```

3. Navigate to `https://dcc.godaddy.com/manage/{{domain}}/dns` , update **A** record with **IP** of your server.

4. Navigate to `https://dns.godaddy.com/{{domain}}/nameservers` > Enter my own nameservers (advanced)

```bash
ns1.{{domain}}
ns2.{{domain}}
```

5. Installing **interactsh-server** on your server.

```bash
GO111MODULE=on go get -v github.com/projectdiscovery/interactsh/cmd/interactsh-server
```

6. Navigate to `https://dns.godaddy.com/{{domain}}/nameservers` > Enter my own nameservers (advanced)

7. Starting **interactsh-server**, to ensure server is always running in the background, make sure to start the server in the screen session.

```bash
interactsh-server -cacert /root/.lego/certificates/_.{domain}.crt -cakey /root/.lego/certificates/_.{{DOMAIN}}.key -domain {{DOMAIN}} -hostmaster admin@interact.sh -ip {{SERVER_IP}}
```

8. Installing **interactsh-client** for using interactsh service.

```
GO111MODULE=on go get -v github.com/projectdiscovery/interactsh/cmd/interactsh-client
```

9. Running **interactsh-clien**t with **self-hosted** domain.
```
interactsh-client -url https://{{your_domain}}
```

