# Hidden Bridge
## Introduction
Hidden bridge is a virtual server service, supported by DNS resolver with custom configuration.

Currently it supports HTTP and HTTPS protocols, and a virtual service plugin can be written to be have in any way required

### Examples
* Reverse proxying
* URL path (re)mapping
* Custom APIs
* custom request and response processing
* Tunelling other TCP protocols that can be massaged to connect as HTTPS clients (i.e using ssh proxy command, gnutls client etc)

## Launching
```
hiddenbridge -config config.yml
```

## Building
```
python3 -m pip install ./python/requirements.txt
go generate
go build
```

## Root CA
```
mkdir -p keys
openssl genrsa -out keys/hiddenbridgeCA.key 2048
openssl req -x509 -new -nodes -key keys/hiddenbridgeCA.key -sha256 -days 1825 -out keys/hiddenbridgeCA.pem
```

```
sudo cp keys/hiddenbridgeCA.pem /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
```

## Sign Certificate
A took, "signcert" is available to assist creating certificates to be used by hiddenbridge and its plugins
```
make signcert
mkdir -p keys

./signcert -v debug -in keys/hiddenbridgeCA.pem -in-key keys/hiddenbridgeCA.key -out keys/newsite.key -out-key keys/newsite.key -n new.site.com -n www.new.site.com
```

## Dump certificate on server
```
openssl s_client -showcerts -connect <server>:<port> | openssl x509 -text
```

## Ansible
### Inventory
```
ansible/environment/hosts/hosts.yml
```
Requires valid information to be entered:
* IP address
* User name
* Path to python intrepreter

## Tinyproxy
* By default is listening on 8888

## Test Webserver
A certificate is needed
```
openssl req -x509 -newkey rsa:2048 -keyout python/testwebserver/key.pem -out python/testwebserver/cert.pem -days 365 -nodes
```

