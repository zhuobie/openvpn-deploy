# Introduction

Currently this script has only been tested on Debian 12, and it is recommended to install it on a freshly installed, clean Debian 12 system. 

Perhaps I will add more systems support in the future.

# Usage

## Install

```
./openvpn_deploy.sh install
```

## Add user

```
./openvpn_deploy.sh authorize client1
```

This will generate a file named client1.ovpn in the directory /root/, and you can use it to connect to the server.

```
./openvpn_deploy.sh authorize client2 "10.8.0.111"
```

This will generate a file named client2.ovpn in the directory /root/, and assign the client a static IP address of 10.8.0.111.

## Remove user

```
./openvpn_deploy.sh revoke client1
```

This will remove the authorization of the client1.ovpn file, and client1 can not connect to the vpn server anymore.

## Uninstall

```
./openvpn_deploy.sh uninstall
```

This will remove all the certificates, keys, and configuration files for OpenVPN, and delete firewall rules.

## Help

```
./openvpn_deploy.sh help
```

Display a short help message.
