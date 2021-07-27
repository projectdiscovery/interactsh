module github.com/projectdiscovery/interactsh

go 1.15

replace (
	github.com/projectdiscovery/fastdialer => /Users/marcornvh/go/src/github.com/projectdiscovery/fastdialer
	github.com/projectdiscovery/hmap => /Users/marcornvh/go/src/github.com/projectdiscovery/hmap
)

require (
	git.mills.io/prologic/smtpd v0.0.0-20210710122116-a525b76c287a
	github.com/eggsampler/acme/v3 v3.2.1
	github.com/google/uuid v1.2.0
	github.com/jasonlvhit/gocron v0.0.1
	github.com/json-iterator/go v1.1.11
	github.com/karlseguin/ccache/v2 v2.0.8
	github.com/miekg/dns v1.1.43
	github.com/pkg/errors v0.9.1
	github.com/projectdiscovery/fastdialer v0.0.13-0.20210727180624-4b8261cc6d2a
	github.com/projectdiscovery/fileutil v0.0.0-20210601061022-8ef4fc6fbfb6
	github.com/projectdiscovery/gologger v1.1.4
	github.com/projectdiscovery/retryablehttp-go v1.0.1
	github.com/rs/xid v1.3.0
	github.com/stretchr/testify v1.7.0
	gopkg.in/corvus-ch/zbase32.v1 v1.0.0
)
