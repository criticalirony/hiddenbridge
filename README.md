# Hidden Bridge
## Introduction
Transparent proxy, supported by DNS resolver with custom configuration.

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
```
mkdir -p keys
openssl genrsa -out keys/hiddenbridge.org.key 2048
openssl req -new -sha256 \
    -key keys/hiddenbridge.org.key \
    -subj "/C=US/ST=CA/O=HiddenBridge, Inc./CN=hiddenbridge.org" \
    -reqexts SAN \
    -config <(cat /etc/ssl/openssl.cnf \
        <(printf "\n[SAN]\nsubjectAltName=DNS:hiddenbridge.org,DNS:www.hiddenbridge.org")) \
    -out keys/hiddenbridge.org.csr

openssl req -in keys/hiddenbridge.org.csr -noout -text

openssl x509 -req -in keys/hiddenbridge.org.csr -CA keys/hiddenbridgeCA.pem -CAkey keys/hiddenbridgeCA.key -CAcreateserial -out keys/hiddenbridge.org.pem -days 500 -sha256

openssl x509 -in keys/hiddenbridge.org.pem -text -noout
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

