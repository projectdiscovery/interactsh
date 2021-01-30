# interactsh

Interact.sh is an Open-Source OOB Data Extraction tool designed for use with [Nuclei](https://github.com/projectdiscovery/nuclei) to detect Bugs that cause external interactions, For example - Blind SQLi, Blind CMDi, SSRF, etc.

A hosted instance of the service is available at https://interact.sh.

Installation Instructions - 

```bash
wget https://golang.org/dl/go1.15.7.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.15.7.linux-amd64.tar.gz
echo "export PATH=$PATH:/usr/local/go/bin" >> .bashrc
source .bashrc
apt-get -y install make git
git clone https://github.com/go-acme/lego.git
cd lego
make build
CF_DNS_API_TOKEN=mgKBy4zBGGNkrlQNSvXq4DBqQR1HpHnxtLdDtq4b CF_ZONE_API_TOKEN=-O6sEg59n9mkKu3KeAbtCJNc1B_Jw7gqOjrm54yE ./dist/lego -domains "*.interact.sh" -domains "interact.sh" --email "nizamul@projectdiscovery.io" --dns cloudflare run
./interactsh -domain interact.sh -hostmaster admin@interact.sh -ip 134.209.31.79 -cacert /etc/letsencrypt/live/interact.sh/fullchain.pem -cakey /etc/letsencrypt/live/interact.sh/privkey.pem -debug
```