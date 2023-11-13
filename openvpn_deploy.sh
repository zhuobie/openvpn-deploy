#!/bin/bash
set -euo pipefail

command=""
sub_command=""
sub_sub_command=""

if [ $# -eq 0 ]; then
    command="help"
fi

if [ $# -eq 1 ]; then
    command=$1
fi

if [ $# -eq 2 ]; then
    command=$1
    sub_command=$2
fi

if [ $# -eq 3 ]; then
    command=$1
    sub_command=$2
    sub_sub_command=$3
fi

if [ $# -gt 3 ]; then
    echo "Too many arguments"
    exit 1
fi

#### Modify these parameters as needed. ####
option_server_ip="192.168.52.130" 
option_server_vpn_port="18135" 
option_server_vpn_proto="udp" # "udp" or "tcp"
option_subnet_ip="10.8.0.0" 
option_subnet_mask="255.255.255.0"
option_nic_redirect="true"
option_easyrsa_algo="ec" # "ec" or "dh" 
option_req_country="CN"
option_req_province="Beijing"
option_req_city="Beijing"
option_req_org="Company Name"
option_req_email="admin@company.com"
option_req_ou="Development Department"
#### Modify these parameters as needed. ####

interface_local=$(ip -o link show | awk -F': ' '{print $2}' | grep -vE '^(lo|docker|tun|vpn)' | head -n 1)
cidr=0
IFS="." read -ra octets <<< "$option_subnet_mask"
for octet in "${octets[@]}"; do
  while [ "$octet" -gt 0 ]; do
    cidr=$((cidr + octet % 2))
    octet=$((octet / 2))
  done
done

install_ufw() {
    apt install -y ufw
    ufw disable
    ufw allow ${option_server_vpn_port}/${option_server_vpn_proto}
    if [[ "$option_nic_redirect" == "true" ]]; then
        echo "#" >> /etc/ufw/before.rules
        echo "*nat" >> /etc/ufw/before.rules
        echo ":POSTROUTING ACCEPT [0:0]" >> /etc/ufw/before.rules
        echo "-A POSTROUTING -s ${option_subnet_ip}/${cidr} -o ${interface_local} -j MASQUERADE" >> /etc/ufw/before.rules
        echo "COMMIT" >> /etc/ufw/before.rules
        echo 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> /etc/ufw/ufw.conf
    fi
    expect -c "
      spawn ufw enable
      expect {
        \"Command may disrupt \" {send \"y\r\"}
      }
    expect eof"
    ufw reload
}

uninstall_ufw() {
    if command -v ufw > /dev/null 2>&1; then
        ufw disable
        ufw delete allow ${option_server_vpn_port}/${option_server_vpn_proto}
        sed -i '/^DEFAULT_FORWARD_POLICY=\"ACCEPT\"/d' /etc/ufw/ufw.conf
        set +e
        line_number=$(grep -n -- "-A POSTROUTING -s ${option_subnet_ip}/${cidr} -o ${interface_local} -j MASQUERADE" /etc/ufw/before.rules | cut -d: -f1)
        set -e
        if [[ -n "$line_number" ]]; then
            sed -i "$((line_number-3)),$((line_number+1))d" /etc/ufw/before.rules
        fi
        expect -c "
          spawn ufw enable
          expect {
            \"Command may disrupt \" {send \"y\r\"}
          }
        expect eof"
        ufw reload        
    fi
}

uninstall() {
    cd /root
    rm -rf openvpn-ca
    if [[ -d "/etc/openvpn" ]]; then 
        cd /etc/openvpn
        rm -rf ca.crt client.conf dh.pem server.conf server.crt server.key ta.key crl.pem
        rm -rf server/*
        rm -rf client/*
        rm -rf ccd
    fi
    if [[ -e "/lib/systemd/system/openvpn.service" ]]; then
        systemctl stop openvpn@server
        systemctl disable openvpn@server
    fi
}

install_server() {
    server_ip=$(awk -F. '{print $1"."$2"."$3"."$4+1}' <<< "$option_subnet_ip")
    echo "server ip: $server_ip"
    apt install -y openvpn easy-rsa expect
    cd /root
    make-cadir openvpn-ca && cd openvpn-ca
    line_number=$(grep -n '#set_var EASYRSA_REQ_OU		"My Organizational Unit"' vars | cut -d: -f1)
    sed -i "$((line_number+1))a\set_var EASYRSA_REQ_COUNTRY    \"${option_req_country}\"" vars
    sed -i "$((line_number+2))a\set_var EASYRSA_REQ_PROVINCE   \"${option_req_province}\"" vars
    sed -i "$((line_number+3))a\set_var EASYRSA_REQ_CITY       \"${option_req_city}\"" vars
    sed -i "$((line_number+4))a\set_var EASYRSA_REQ_ORG        \"${option_req_org}\"" vars
    sed -i "$((line_number+5))a\set_var EASYRSA_REQ_EMAIL      \"${option_req_email}\"" vars
    sed -i "$((line_number+6))a\set_var EASYRSA_REQ_OU         \"${option_req_ou}\"" vars
    sed -i "$((line_number+7))a\\#" vars

    if [[ "$option_easyrsa_algo" == "ec" ]]; then
        sed -i 's/#set_var EASYRSA_ALGO		rsa/set_var EASYRSA_ALGO		"ec"/g' vars
        sed -i 's/#set_var EASYRSA_DIGEST		"sha256"/set_var EASYRSA_DIGEST		"sha512"/g' vars
    fi

    ./easyrsa init-pki

    expect -c "
      spawn ./easyrsa build-ca nopass
      expect {
        \"\]\:\" {send \"\r\"}
      }
    expect eof"
    
    mv vars pki/

    expect -c "
      spawn ./easyrsa gen-req server nopass
      expect {
        \"\]\:\" {send \"\r\"}
      }
    expect eof"

    expect -c "
      spawn ./easyrsa sign-req server server
      expect {
        \"Confirm request details: \" {send \"yes\r\"}
      }
    expect eof"

    if [[ "$option_easyrsa_algo" != "ec" ]]; then
        ./easyrsa gen-dh
    fi
    EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

    openvpn --genkey secret pki/ta.key
    cp /root/openvpn-ca/pki/{ca.crt,ta.key,crl.pem} /etc/openvpn/
    if [[ "$option_easyrsa_algo" != "ec" ]]; then
        cp /root/openvpn-ca/pki/dh.pem /etc/openvpn/
    fi
    cp /root/openvpn-ca/pki/issued/server.crt /etc/openvpn
    cp /root/openvpn-ca/pki/private/server.key /etc/openvpn
    cp /usr/share/doc/openvpn/examples/sample-config-files/server.conf /etc/openvpn/server.conf
    if [[ "$option_server_vpn_proto" == "tcp" ]]; then
        sed -i 's/;proto tcp/proto tcp/g' /etc/openvpn/server.conf
        sed -i 's/proto udp/;proto udp/g' /etc/openvpn/server.conf
    fi
    sed -i "s/port 1194/port ${option_server_vpn_port}/g" /etc/openvpn/server.conf
    sed -i "s/server 10.8.0.0 255.255.255.0/server ${option_subnet_ip} ${option_subnet_mask}/g" /etc/openvpn/server.conf
    if [[ "$option_easyrsa_algo" == "ec" ]]; then 
        sed -i 's/dh dh2048.pem/dh none/g' /etc/openvpn/server.conf
    else
        sed -i 's/dh dh2048.pem/dh dh.pem/g' /etc/openvpn/server.conf
    fi
    sed -i 's/tls-auth ta.key 0/;tls-auth ta.key 0/g' /etc/openvpn/server.conf
    line_number=$(grep -n ';tls-auth ta.key 0' /etc/openvpn/server.conf | cut -d: -f1)
    sed -i "${line_number}a\tls-crypt ta.key" /etc/openvpn/server.conf
    sed -i "$((line_number+1))a\crl-verify crl.pem" /etc/openvpn/server.conf
    mkdir -p /etc/openvpn/ccd
    sed -i 's/;client-config-dir ccd/client-config-dir ccd/g' /etc/openvpn/server.conf
    sed -i 's/;topology subnet/topology subnet/g' /etc/openvpn/server.conf
    if [[ "$option_nic_redirect" == "true" ]]; then
        sed -i '/^\;push\s\"redirect\-gateway/s/^;//' /etc/openvpn/server.conf
        sed -i '/^\;push\s\"dhcp\-option\sDNS/s/^;//g' /etc/openvpn/server.conf
    fi
    sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
    sysctl -p
    systemctl start openvpn@server
    systemctl enable openvpn@server
}

install_client() {
    cd /root/openvpn-ca
    cp pki/{ca.crt,ta.key} /etc/openvpn/client/
    cp /usr/share/doc/openvpn/examples/sample-config-files/client.conf /etc/openvpn/
    if [[ "$option_server_vpn_proto" == "tcp" ]]; then
        sed -i 's/;proto tcp/proto tcp/g' /etc/openvpn/client.conf
        sed -i 's/proto udp/;proto udp/g' /etc/openvpn/client.conf
    fi
    sed -i "s/remote my-server-1 1194/remote ${option_server_ip} ${option_server_vpn_port}/g" /etc/openvpn/client.conf
    sed -i "s/;user openvpn/user nobody/g" /etc/openvpn/client.conf
    sed -i "s/;group openvpn/group nogroup/g" /etc/openvpn/client.conf
    sed -i "s/ca ca.crt/;ca ca.crt/g" /etc/openvpn/client.conf
    sed -i "s/cert client.crt/;cert client.crt/g" /etc/openvpn/client.conf
    sed -i "s/key client.key/;key client.key/g" /etc/openvpn/client.conf
    sed -i "s/tls-auth ta.key 1/;tls-auth ta.key 1/g" /etc/openvpn/client.conf
    line_number=$(grep -n ';key client.key' /etc/openvpn/client.conf | cut -d: -f1)
    sed -i "$((line_number+1))a\key-direction 1" /etc/openvpn/client.conf
    sed -i "$((line_number+2))a\\#" /etc/openvpn/client.conf
}

client_authorize() {
    client_name=$1
    client_ip=$2
    KEY_DIR=/etc/openvpn/client
    OUTPUT_DIR=/root
    BASE_CONFIG=/etc/openvpn/client.conf
    cd /root/openvpn-ca

    expect -c "
      spawn ./easyrsa gen-req ${client_name} nopass
      expect {
        \"\]\:\" {send \"\r\"}
      }
    expect eof"

    expect -c "
      spawn ./easyrsa sign-req client ${client_name}
      expect {
        \"Confirm request details: \" {send \"yes\r\"}
      }
    expect eof"

    cp pki/private/${client_name}.key /etc/openvpn/client/
    cp pki/issued/${client_name}.crt /etc/openvpn/client/

    if [[ "$client_ip" != "auto" ]]; then
        echo "ifconfig-push $client_ip $option_subnet_mask" > /etc/openvpn/ccd/${client_name}
    fi

    cat ${BASE_CONFIG} \
      <(echo -e '<ca>') \
      ${KEY_DIR}/ca.crt \
      <(echo -e '</ca>\n<cert>') \
      ${KEY_DIR}/${client_name}.crt \
      <(echo -e '</cert>\n<key>') \
      ${KEY_DIR}/${client_name}.key \
      <(echo -e '</key>\n<tls-crypt>') \
      ${KEY_DIR}/ta.key \
      <(echo -e '</tls-crypt>') \
      > ${OUTPUT_DIR}/${client_name}.ovpn
}

client_revoke() {
    cd /root/openvpn-ca
    client_name=$1
    expect -c "
      spawn ./easyrsa revoke ${client_name}
      expect {
        \"Continue with revocation: \" {send \"yes\r\"}
      }
    expect eof"
    ./easyrsa gen-crl
    cp pki/crl.pem /etc/openvpn/
    rm -rf /etc/openvpn/ccd/${client_name}
    rm -rf /etc/openvpn/client/${client_name}.crt
    rm -rf /etc/openvpn/client/${client_name}.key
}

help() {
    echo "Usage: $0 [OPTION]"
    echo "  install                          Install OpenVPN Server."
    echo "  uninstall                        Uninstall OpenVPN Server"
    echo "  authorize client1 <ip addr>      add client with static ip address"
    echo "  revoke client1                   Revoke client authorization"
}

if [[ "$command" == "help" ]]; then
    help
    exit 0
fi

if [[ "$command" == "install" ]]; then
    install_server
    install_client
    install_ufw
    exit 0
fi

if [[ "$command" == "uninstall" ]]; then
    uninstall
    uninstall_ufw
    exit 0
fi

if [[ "$command" == "authorize" ]]; then
    if [[ "$sub_sub_command" == "" ]] || [[ "$sub_sub_command" == "auto" ]]; then
        client_authorize "$sub_command" "auto"
        exit 0
    else 
        client_authorize "$sub_command" "$sub_sub_command"
        exit 0
    fi
fi

if [[ "$command" == "revoke" ]]; then
    client_revoke "$sub_command"
    exit 0
fi

# Examples:
## ./openvpn_deploy.sh help
## ./openvpn_deploy.sh uninstall
## ./openvpn_deploy.sh install
## ./openvpn_deploy.sh authorize client1
## ./openvpn_deploy.sh authorize client1 auto
## ./openvpn_deploy.sh authorize client2 "10.8.0.110"
## ./openvpn_deploy.sh revoke client1
