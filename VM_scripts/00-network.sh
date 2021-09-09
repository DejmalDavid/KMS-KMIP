#!/bin/bash

#DAVID DEJMAL MASTER THESIS 2021 VUT FIT

# network settings

# device
NETWORK_DEVICE=$(ip --oneline addr show | awk '$3 == "inet" && $2 != "lo" { print $2}' | head -n 1)
echo ${NETWORK_DEVICE}

# DHCP / Static
echo 'If you want use DHCP set true; if not set false. After inserting, press Ctrl+d'
NETWORK_DHCP=$(</dev/stdin)
echo 
echo Insert:"${NETWORK_DHCP}"

# konfiguration file
if test "${NETWORK_DHCP}" = 'true'
then
cat > /etc/netplan/00-installer-config.yaml <<EOF
network:
    version: 2
    renderer: networkd
    ethernets:
        ${NETWORK_DEVICE}:
            dhcp4: true
EOF
else
echo 'Insert IP address  (in format xxx.xxx.xxx.xxx/YY). After inserting, press Ctrl+d'
NETWORK_IP_ADDRESSES=$(</dev/stdin)
echo ""
echo Insered IP address:"${NETWORK_IP_ADDRESSES}"
echo 'Set IP of gateway (in format xxx.xxx.xxx.xxx). After inserting, press Ctrl+d'
NETWORK_GATEWAY4=$(</dev/stdin)
echo ""
echo Insered IP address:"${NETWORK_GATEWAY4}"
echo 'Insert IP address of DNS servers separated by commas (in format xxx.xxx.xxx.xxx, yyy.yyy.yyy.yyy). After inserting, press Ctrl+d'
NETWORK_DNS_ADDRESSES=$(</dev/stdin)
echo ""
echo Insered IP address:"${NETWORK_DNS_ADDRESSES}"

cat > /etc/netplan/00-installer-config.yaml <<EOF
network:
    version: 2
    renderer: networkd
    ethernets:
        ${NETWORK_DEVICE}:
            addresses:
                - ${NETWORK_IP_ADDRESSES}
            gateway4: ${NETWORK_GATEWAY4}
            nameservers:
                addresses: [${NETWORK_DNS_ADDRESSES}]
EOF
fi

# apply
netplan apply
