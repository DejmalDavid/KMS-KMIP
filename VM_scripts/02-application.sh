#!/bin/bash

#DAVID DEJMAL MASTER THESIS 2021 VUT FIT

# etcd
# install
apt-get update
apt-get -y upgrade
# stop and kill, if its already running
systemctl stop unattended-upgrades && sleep 20
kill -9 $(pidof unattended-upgrades) 2>/dev/null

apt-get -y install etcd
# dir with data - MAIN DIRECTORY
mkdir -p /etc/etcd/ /var/lib/etcd/kms_data
# it is symlink, dont wanna edit in dest, but make copy in etc
systemctl stop etcd && sleep 20
# not should running its alias
systemctl stop etcd2 && sleep 5
systemctl mask etcd
# if its still running, kill it
kill -9 $(pidof etcd) 2>/dev/null
rm -f /etc/systemd/system/etcd2.service
# make new service
cp /lib/systemd/system/etcd.service /etc/systemd/system/etcd2.service
sed -i -e 's%Environment=ETCD_DATA_DIR=/var/lib/etcd/default%Environment=ETCD_DATA_DIR=/var/lib/etcd/kms_data%'  -e 's%^ExecStart.*%ExecStart=/usr/bin/etcd --config-file /etc/etcd/etcd.conf%' -e '/Alias=etcd2.service/d' /etc/systemd/system/etcd2.service
cat > /etc/etcd/etcd.conf <<EOF
# This is the configuration file for the etcd server.

# Human-readable name for this member.
name: 'KMS'

# Path to the data directory.
data-dir: /var/lib/etcd/kms_data

# Path to the dedicated wal directory.
wal-dir:

# Number of committed transactions to trigger a snapshot to disk.
snapshot-count: 1000

# Time (in milliseconds) of a heartbeat interval.
heartbeat-interval: 100

# Time (in milliseconds) for an election to timeout.
election-timeout: 1000

# Raise alarms when backend size exceeds the given quota. 0 means use the
# default quota.
quota-backend-bytes: 0

# List of comma separated URLs to listen on for peer traffic.
listen-peer-urls: http://localhost:2380

# List of comma separated URLs to listen on for client traffic.
listen-client-urls: http://localhost:2379

# Maximum number of snapshot files to retain (0 is unlimited).
max-snapshots: 0

# Maximum number of wal files to retain (0 is unlimited).
max-wals: 0

# Comma-separated white list of origins for CORS (cross-origin resource sharing).
cors:

# List of this member's peer URLs to advertise to the rest of the cluster.
# The URLs needed to be a comma-separated list.
initial-advertise-peer-urls: http://localhost:2380

# List of this member's client URLs to advertise to the public.
# The URLs needed to be a comma-separated list.
advertise-client-urls: http://localhost:2379

# Discovery URL used to bootstrap the cluster.
discovery:

# Valid values include 'exit', 'proxy'
discovery-fallback: 'exit'

# HTTP proxy to use for traffic to discovery service.
discovery-proxy:

# DNS domain used to bootstrap initial cluster.
discovery-srv:

# Initial cluster configuration for bootstrapping.
initial-cluster:

# Initial cluster token for the etcd cluster during bootstrap.
initial-cluster-token: 'etcd-cluster'

# Initial cluster state ('new' or 'existing').
initial-cluster-state: 'new'

# Reject reconfiguration requests that would cause quorum loss.
strict-reconfig-check: false

# Accept etcd V2 client requests
enable-v2: false

# Enable runtime profiling data via HTTP server
enable-pprof: true

# Valid values include 'on', 'readonly', 'off'
proxy: 'off'

# Time (in milliseconds) an endpoint will be held in a failed state.
proxy-failure-wait: 5000

# Time (in milliseconds) of the endpoints refresh interval.
proxy-refresh-interval: 30000

# Time (in milliseconds) for a dial to timeout.
proxy-dial-timeout: 1000

# Time (in milliseconds) for a write to timeout.
proxy-write-timeout: 5000

# Time (in milliseconds) for a read to timeout.
proxy-read-timeout: 0

client-transport-security:
  # Path to the client server TLS cert file.
  cert-file:

  # Path to the client server TLS key file.
  key-file:

  # Enable client cert authentication.
  client-cert-auth: false

  # Path to the client server TLS trusted CA cert file.
  trusted-ca-file:

  # Client TLS using generated certificates
  auto-tls: false

peer-transport-security:
  # Path to the peer server TLS cert file.
  cert-file:

  # Path to the peer server TLS key file.
  key-file:

  # Enable peer client cert authentication.
  client-cert-auth: false

  # Path to the peer server TLS trusted CA cert file.
  trusted-ca-file:

  # Peer TLS using generated certificates.
  auto-tls: false

# Enable debug-level logging for etcd.
debug: false

logger: zap

# Specify 'stdout' or 'stderr' to skip journald logging even when running under systemd.
log-outputs: [stderr]

# Force to create a new one member cluster.
force-new-cluster: false

auto-compaction-mode: periodic
auto-compaction-retention: 0
EOF
chown -R etcd: /var/lib/etcd/
systemctl daemon-reload
systemctl enable etcd2 --now

# konfiguration
export ETCDCTL_API=3
# users
# par --interactive=false not working for me :(
# root
ETCDCTL_ROOT_USERNAME=root
echo ${ETCDCTL_ROOT_USERNAME} > /root/etcd_root_username.txt
ETCDCTL_ROOT_PASSWD=$(openssl rand -base64 32)
echo ${ETCDCTL_ROOT_PASSWD} > /root/etcd_root_password.txt
etcdctl user add ${ETCDCTL_ROOT_USERNAME}:${ETCDCTL_ROOT_PASSWD}
# user
ETCDCTL_USER_USERNAME=etcd_user
echo ${ETCDCTL_USER_USERNAME} > /home/pykmip-server-user/.secrets/etcd_user_username.txt
ETCDCTL_USER_PASSWD=$(openssl rand -base64 32)
echo ${ETCDCTL_USER_PASSWD} > /home/pykmip-server-user/.secrets/etcd_user_password.txt
etcdctl user add ${ETCDCTL_USER_USERNAME}:${ETCDCTL_USER_PASSWD}
chown pykmip-server-user: /home/pykmip-server-user/.secrets/etcd_user_username.txt /home/pykmip-server-user/.secrets/etcd_user_password.txt
chmod 600 /home/pykmip-server-user/.secrets/etcd_user_username.txt /home/pykmip-server-user/.secrets/etcd_user_password.txt
# role
ETCDCTL_USER_ROLE=etcd_user_role
etcdctl role add ${ETCDCTL_USER_ROLE}
# permission for role
etcdctl role grant-permission ${ETCDCTL_USER_ROLE} --prefix=true readwrite /managed_objects/
etcdctl role grant-permission ${ETCDCTL_USER_ROLE} --prefix=true readwrite /general/
# role for user
etcdctl user grant-role ${ETCDCTL_USER_USERNAME} ${ETCDCTL_USER_ROLE}
# enable auth - if wanna login check  /home/pykmip-server-user/.secrets
etcdctl auth enable
# set counter to 0
etcdctl --user ${ETCDCTL_USER_USERNAME}:${ETCDCTL_USER_PASSWD} put /general/object_counter 0
# for test read counter - except value 0
etcdctl --user ${ETCDCTL_USER_USERNAME}:${ETCDCTL_USER_PASSWD} get /general/object_counter

# python3.9
apt-get update
apt-get -y install python3.9 python3-pip
# set verzion python3.9 as preferred 
update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 10
update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 20
update-alternatives --auto python3
# download modules
mkdir pip_packages
python3 -m pip download -d pip_packages pykmip cffi etcd3
# install modules 
python3 -m pip install pykmip cffi etcd3

#fix unattended-upgrades, automatic updates
ln -s /usr/lib/python3/dist-packages/apt_inst.cpython-38-x86_64-linux-gnu.so /usr/lib/python3/dist-packages/apt_inst.so
ln -s /usr/lib/python3/dist-packages/apt_pkg.cpython-38-x86_64-linux-gnu.so /usr/lib/python3/dist-packages/apt_pkg.so

# konfiguration pykmip
mkdir -p /etc/pykmip/policy/ /etc/pykmip/ssl/ /var/log/pykmip/
# create certs 
./create_certificates.py
chown -R pykmip-server-user: /var/log/pykmip/
chmod 700 /var/log/pykmip/
# permission for dir and files - private, not to read for everybody
# must be for read to export in vCenter
# chmod 640 /etc/pykmip/ssl/*
NETWORK_IP_ADDRESSES=$(ip --oneline addr show | awk '$3 == "inet" && $2 != "lo" { print $4}' | sed 's%/.*%%' | head -n 1)


# server
cat > /etc/pykmip/server.conf <<EOF
[server]
hostname=${NETWORK_IP_ADDRESSES}
port=5696
certificate_path=/etc/pykmip/ssl/server_cert.pem
key_path=/etc/pykmip/ssl/server_key.pem
ca_path=/etc/pykmip/ssl/root_cert.pem
auth_suite=TLS1.2
policy_path=/etc/pykmip/policy
enable_tls_client_auth=False
tls_cipher_suites=
    TLS_RSA_WITH_AES_128_CBC_SHA256
    TLS_RSA_WITH_AES_256_CBC_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
logging_level=INFO
database_path=etcd3
EOF

# client
cat > /etc/pykmip/pykmip.conf <<EOF
[client]
host=${NETWORK_IP_ADDRESSES}
port=5696
certfile=/etc/pykmip/ssl/client_cert_test_user.pem
keyfile=/etc/pykmip/ssl/client_key_test_user.pem
ca_certs=/etc/pykmip/ssl/root_cert.pem
cert_reqs=CERT_REQUIRED
ssl_version=PROTOCOL_TLS
do_handshake_on_connect=True
suppress_ragged_eofs=True
username=Test User
password=Test User
EOF

# policy
cat > /etc/pykmip/policy/policy.json <<EOF
{
    "example": {
        "preset": {
            "CERTIFICATE": {
                "LOCATE": "ALLOW_ALL",
                "CHECK": "ALLOW_ALL",
                "GET": "ALLOW_ALL",
                "GET_ATTRIBUTES": "ALLOW_ALL",
                "GET_ATTRIBUTE_LIST": "ALLOW_ALL",
                "ADD_ATTRIBUTE": "ALLOW_OWNER",
                "MODIFY_ATTRIBUTE": "ALLOW_OWNER",
                "DELETE_ATTRIBUTE": "ALLOW_OWNER",
                "OBTAIN_LEASE": "ALLOW_ALL",
                "ACTIVATE": "ALLOW_OWNER",
                "REVOKE": "ALLOW_OWNER",
                "DESTROY": "ALLOW_OWNER",
                "ARCHIVE": "ALLOW_OWNER",
                "RECOVER": "ALLOW_OWNER"
            },
            "SYMMETRIC_KEY": {
                "REKEY": "ALLOW_OWNER",
                "REKEY_KEY_PAIR": "ALLOW_OWNER",
                "DERIVE_KEY": "ALLOW_OWNER",
                "LOCATE": "ALLOW_OWNER",
                "CHECK": "ALLOW_OWNER",
                "GET": "ALLOW_OWNER",
                "GET_ATTRIBUTES": "ALLOW_OWNER",
                "GET_ATTRIBUTE_LIST": "ALLOW_OWNER",
                "ADD_ATTRIBUTE": "ALLOW_OWNER",
                "MODIFY_ATTRIBUTE": "ALLOW_OWNER",
                "DELETE_ATTRIBUTE": "ALLOW_OWNER",
                "OBTAIN_LEASE": "ALLOW_OWNER",
                "GET_USAGE_ALLOCATION": "ALLOW_OWNER",
                "ACTIVATE": "ALLOW_OWNER",
                "REVOKE": "ALLOW_OWNER",
                "DESTROY": "ALLOW_OWNER",
                "ARCHIVE": "ALLOW_OWNER",
                "RECOVER": "ALLOW_OWNER"
            },
            "PUBLIC_KEY": {
                "LOCATE": "ALLOW_ALL",
                "CHECK": "ALLOW_ALL",
                "GET": "ALLOW_ALL",
                "GET_ATTRIBUTES": "ALLOW_ALL",
                "GET_ATTRIBUTE_LIST": "ALLOW_ALL",
                "ADD_ATTRIBUTE": "ALLOW_OWNER",
                "MODIFY_ATTRIBUTE": "ALLOW_OWNER",
                "DELETE_ATTRIBUTE": "ALLOW_OWNER",
                "OBTAIN_LEASE": "ALLOW_ALL",
                "ACTIVATE": "ALLOW_OWNER",
                "REVOKE": "ALLOW_OWNER",
                "DESTROY": "ALLOW_OWNER",
                "ARCHIVE": "ALLOW_OWNER",
                "RECOVER": "ALLOW_OWNER"
            },
            "PRIVATE_KEY": {
                "REKEY": "ALLOW_OWNER",
                "REKEY_KEY_PAIR": "ALLOW_OWNER",
                "DERIVE_KEY": "ALLOW_OWNER",
                "LOCATE": "ALLOW_OWNER",
                "CHECK": "ALLOW_OWNER",
                "GET": "ALLOW_OWNER",
                "GET_ATTRIBUTES": "ALLOW_OWNER",
                "GET_ATTRIBUTE_LIST": "ALLOW_OWNER",
                "ADD_ATTRIBUTE": "ALLOW_OWNER",
                "MODIFY_ATTRIBUTE": "ALLOW_OWNER",
                "DELETE_ATTRIBUTE": "ALLOW_OWNER",
                "OBTAIN_LEASE": "ALLOW_OWNER",
                "GET_USAGE_ALLOCATION": "ALLOW_OWNER",
                "ACTIVATE": "ALLOW_OWNER",
                "REVOKE": "ALLOW_OWNER",
                "DESTROY": "ALLOW_OWNER",
                "ARCHIVE": "ALLOW_OWNER",
                "RECOVER": "ALLOW_OWNER"
            },
            "SPLIT_KEY": {
                "REKEY": "ALLOW_OWNER",
                "REKEY_KEY_PAIR": "ALLOW_OWNER",
                "DERIVE_KEY": "ALLOW_OWNER",
                "LOCATE": "ALLOW_OWNER",
                "CHECK": "ALLOW_OWNER",
                "GET": "ALLOW_OWNER",
                "GET_ATTRIBUTES": "ALLOW_OWNER",
                "GET_ATTRIBUTE_LIST": "ALLOW_OWNER",
                "ADD_ATTRIBUTE": "ALLOW_OWNER",
                "MODIFY_ATTRIBUTE": "ALLOW_OWNER",
                "DELETE_ATTRIBUTE": "ALLOW_OWNER",
                "OBTAIN_LEASE": "ALLOW_OWNER",
                "GET_USAGE_ALLOCATION": "ALLOW_OWNER",
                "ACTIVATE": "ALLOW_OWNER",
                "REVOKE": "ALLOW_OWNER",
                "DESTROY": "ALLOW_OWNER",
                "ARCHIVE": "ALLOW_OWNER",
                "RECOVER": "ALLOW_OWNER"
            },
            "TEMPLATE": {
                "LOCATE": "ALLOW_OWNER",
                "GET": "ALLOW_OWNER",
                "GET_ATTRIBUTES": "ALLOW_OWNER",
                "GET_ATTRIBUTE_LIST": "ALLOW_OWNER",
                "ADD_ATTRIBUTE": "ALLOW_OWNER",
                "MODIFY_ATTRIBUTE": "ALLOW_OWNER",
                "DELETE_ATTRIBUTE": "ALLOW_OWNER",
                "DESTROY": "ALLOW_OWNER"
            },
            "SECRET_DATA": {
                "REKEY": "ALLOW_OWNER",
                "REKEY_KEY_PAIR": "ALLOW_OWNER",
                "DERIVE_KEY": "ALLOW_OWNER",
                "LOCATE": "ALLOW_OWNER",
                "CHECK": "ALLOW_OWNER",
                "GET": "ALLOW_OWNER",
                "GET_ATTRIBUTES": "ALLOW_OWNER",
                "GET_ATTRIBUTE_LIST": "ALLOW_OWNER",
                "ADD_ATTRIBUTE": "ALLOW_OWNER",
                "MODIFY_ATTRIBUTE": "ALLOW_OWNER",
                "DELETE_ATTRIBUTE": "ALLOW_OWNER",
                "OBTAIN_LEASE": "ALLOW_OWNER",
                "GET_USAGE_ALLOCATION": "ALLOW_OWNER",
                "ACTIVATE": "ALLOW_OWNER",
                "REVOKE": "ALLOW_OWNER",
                "DESTROY": "ALLOW_OWNER",
                "ARCHIVE": "ALLOW_OWNER",
                "RECOVER": "ALLOW_OWNER"
            },
            "OPAQUE_DATA": {
                "REKEY": "ALLOW_OWNER",
                "REKEY_KEY_PAIR": "ALLOW_OWNER",
                "DERIVE_KEY": "ALLOW_OWNER",
                "LOCATE": "ALLOW_OWNER",
                "CHECK": "ALLOW_OWNER",
                "GET": "ALLOW_OWNER",
                "GET_ATTRIBUTES": "ALLOW_OWNER",
                "GET_ATTRIBUTE_LIST": "ALLOW_OWNER",
                "ADD_ATTRIBUTE": "ALLOW_OWNER",
                "MODIFY_ATTRIBUTE": "ALLOW_OWNER",
                "DELETE_ATTRIBUTE": "ALLOW_OWNER",
                "OBTAIN_LEASE": "ALLOW_OWNER",
                "GET_USAGE_ALLOCATION": "ALLOW_OWNER",
                "ACTIVATE": "ALLOW_OWNER",
                "REVOKE": "ALLOW_OWNER",
                "DESTROY": "ALLOW_OWNER",
                "ARCHIVE": "ALLOW_OWNER",
                "RECOVER": "ALLOW_OWNER"
            },
            "PGP_KEY": {
                "REKEY": "ALLOW_OWNER",
                "REKEY_KEY_PAIR": "ALLOW_OWNER",
                "DERIVE_KEY": "ALLOW_OWNER",
                "LOCATE": "ALLOW_OWNER",
                "CHECK": "ALLOW_OWNER",
                "GET": "ALLOW_OWNER",
                "GET_ATTRIBUTES": "ALLOW_OWNER",
                "GET_ATTRIBUTE_LIST": "ALLOW_OWNER",
                "ADD_ATTRIBUTE": "ALLOW_OWNER",
                "MODIFY_ATTRIBUTE": "ALLOW_OWNER",
                "DELETE_ATTRIBUTE": "ALLOW_OWNER",
                "OBTAIN_LEASE": "ALLOW_OWNER",
                "GET_USAGE_ALLOCATION": "ALLOW_OWNER",
                "ACTIVATE": "ALLOW_OWNER",
                "REVOKE": "ALLOW_OWNER",
                "DESTROY": "ALLOW_OWNER",
                "ARCHIVE": "ALLOW_OWNER",
                "RECOVER": "ALLOW_OWNER"
            }
        }
    }
}
EOF

cat > /etc/systemd/system/pykmip-server.service <<EOF
# /etc/systemd/system/pykmip-server.service

[Unit]
Description=pykmip server
After=network.target

[Service]
User=pykmip-server-user
PAMName=login
# WorkingDirectory=/cesta/k/adresari
ExecStart=/usr/local/bin/pykmip-server
Type=simple
RestartSec=20
Restart=always
TimeoutSec=60
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

# application
mkdir backup
cp /usr/local/lib/python3.9/dist-packages/kmip/services/server/engine.py ./backup/
cp ../APP_scripts/engine.py /usr/local/lib/python3.9/dist-packages/kmip/services/server/

mkdir /usr/local/lib/python3.9/dist-packages/kmip/etcd3
cp ../APP_scripts/ETCDwrapper.py ../APP_scripts/__init__.py /usr/local/lib/python3.9/dist-packages/kmip/etcd3

# service
systemctl daemon-reload
systemctl enable pykmip-server.service --now
etcdctl --user ${ETCDCTL_USER_USERNAME}:${ETCDCTL_USER_PASSWD} get /general/object_counter
