# Hidden Bridge
## Introduction
Transparent proxy, supported by DNS resolver with custom configuration.

## Launching
```
hiddenbridge -config config.yml
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

