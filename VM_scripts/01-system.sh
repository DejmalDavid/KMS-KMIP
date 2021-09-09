#!/bin/bash

#DAVID DEJMAL MASTER THESIS 2021 VUT FIT

#WARNING excepts user name "kms"
# general
mkdir -p /root/bin/


# update system
apt-get update
# for dev you can add packages: grc mc htop colordiff byobu
apt-get -y install tmux netfilter-persistent iptables-persistent update-notifier-common software-properties-common open-vm-tools
apt-get -y purge popularity-contest ubuntu-advantage-tools apport
apt-get -y upgrade
apt-get -y autoremove
apt-get autoclean


# grub - ban IPv6
sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=""/' /etc/default/grub
sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="ipv6.disable=1 sysrq_always_enabled=1"/' /etc/default/grub
update-grub

# bug https://ubuntuforums.org/showthread.php?t=2441797
tee -a /etc/multipath.conf > /dev/null  <<EOF
blacklist {
    devnode "^(ram|raw|loop|fd|md|dm-|sr|scd|st|sda)[0-9]*"
}
EOF
systemctl restart multipathd

# SSH
# Remove small Diffie-Hellman moduli
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
mv /etc/ssh/moduli.safe /etc/ssh/moduli

# Users keys
echo Insert SSH keys for user kms, after inserting all of them, press Ctrl+d
SSH_KEYS=$(</dev/stdin)
echo ""
echo Keys added...

mkdir -p /etc/ssh/ssh_authorized_keys
echo "${SSH_KEYS}" > /etc/ssh/ssh_authorized_keys/kms
chown kms: /etc/ssh/ssh_authorized_keys/kms
chmod 0600 /etc/ssh/ssh_authorized_keys/kms

#WARRNING param "AllowUsers kms" 
cat > /etc/ssh/sshd_config <<EOF
#
Port 22
Protocol 2
AddressFamily inet
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
RekeyLimit 64M 180s
ClientAliveInterval 300
ClientAliveCountMax 0
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 60
MaxStartups 10:30:60
StrictModes yes
MaxAuthTries 1
MaxSessions 4
PubkeyAuthentication yes
AuthorizedKeysFile /etc/ssh/ssh_authorized_keys/%u
IgnoreRhosts yes
PasswordAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
ChallengeResponseAuthentication no
UsePAM yes
DisableForwarding yes
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server
UseDNS no
Ciphers aes256-gcm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com
AllowUsers kms
EOF

chown root: /etc/ssh/sshd_config
chmod 0600 /etc/ssh/sshd_config
systemctl restart sshd


# Firewall
systemctl stop ufw
systemctl mask ufw
cat > /root/bin/firewall.sh <<EOF
#!/bin/sh

iptables -F

iptables -A INPUT -s 127.0.0.0/8 ! -i lo -j DROP -m comment --comment "loopback without 127.0.0.0"
iptables -A INPUT -i lo -j ACCEPT -m comment --comment "loopback"
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP -m comment --comment "invalid"
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment "established"

# SSH
iptables -A INPUT -p tcp -m tcp --dport 22 --syn -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT -m comment --comment "ssh"

# Ping
iptables -A INPUT -p icmp --icmp-type 8 -j ACCEPT -m comment --comment "ping 8"
iptables -A INPUT -p icmp --icmp-type 3 -j ACCEPT -m comment --comment "ping 3"
iptables -A INPUT -p icmp --icmp-type 11 -j ACCEPT -m comment --comment "ping 11"

# Policy
iptables -P INPUT DROP -m comment --comment "policy"
iptables -P FORWARD DROP -m comment --comment "policy"

# Save
netfilter-persistent save
EOF

sh -x /root/bin/firewall.sh

# IP address of vCenter, from whitch will be allowed port 5696
echo 'Insert IP address of vCenter server (in format xxx.xxx.xxx.xxx), after inserting, press Ctrl+d'
VCENTER_IP_ADDRESS=$(</dev/stdin)
echo ""
echo Insered IP address of vCenter:"${VCENTER_IP_ADDRESS}"
iptables -A INPUT -p tcp -m tcp --dport 5696 --source ${VCENTER_IP_ADDRESS}/32 --syn -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT -m comment --comment "KMS - vCenter"
netfilter-persistent save


# automatic updates - user define what and when
# or you can bad universe as source for apt
sed -i 's/\/\/[[:blank:]]*"${distro_id}:${distro_codename}-updates";/"${distro_id}:${distro_codename}-updates";/' /etc/apt/apt.conf.d/50unattended-upgrades
echo 'Insert time of possible automatic reboot in format HH:MM, after inserting, press Ctrl+d'
REBOOT_TIME=$(</dev/stdin)
echo ""
echo Insered time:"${REBOOT_TIME}"

sed -i "s/\/\/Unattended-Upgrade::Automatic-Reboot-Time \"02:00\";/Unattended-Upgrade::Automatic-Reboot-Time \""${REBOOT_TIME}"\";/" /etc/apt/apt.conf.d/50unattended-upgrades
echo 'Enable automatic reboot? Insert true or false, after inserting, press Ctrl+d'
REBOOT_AUTO=$(</dev/stdin)
echo ""
echo Insered value:"${REBOOT_AUTO}".

sed -i "s/\/\/Unattended-Upgrade::Automatic-Reboot \"false\";/Unattended-Upgrade::Automatic-Reboot \""${REBOOT_AUTO}"\";/" /etc/apt/apt.conf.d/50unattended-upgrades
sed -i 's/\/\/Unattended-Upgrade::Remove-Unused-Dependencies "false";/Unattended-Upgrade::Remove-Unused-Dependencies "true";/' /etc/apt/apt.conf.d/50unattended-upgrades
sed -i 's/\/\/Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";/Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";/' /etc/apt/apt.conf.d/50unattended-upgrades

mkdir -p /etc/systemd/system/apt-daily.timer.d
# User define when + dispersion (+)
echo Nest set time when will be check updates and possible dispersion.
echo Insered time +- dispersion will be not be in conflict whith time of reboot.
echo 'Insert the time of the checks and run of automatic updates in format HH:MM:SS, after inserting, press Ctrl+d'
UPDATE_TIME=$(</dev/stdin)
echo ""
echo Time of updates:"${UPDATE_TIME}".

# prevents possible overloading of update servers 
echo 'Enter the number of minutes of possible dispersion from the update time, after inserting, press Ctrl+d'
UPDATE_RANDOM_DELAY=$(</dev/stdin)
echo ""
echo Dispersion in minutes:"${UPDATE_RANDOM_DELAY}".
cat > /etc/systemd/system/apt-daily.timer.d/override.conf <<EOF
[Timer]
OnCalendar=
OnCalendar=*-*-* ${UPDATE_TIME}
RandomizedDelaySec=${UPDATE_RANDOM_DELAY}m
EOF

systemctl daemon-reload
systemctl restart unattended-upgrades
systemctl restart apt-daily.timer

# creation of user, for running kms service and dir for secrets
adduser --system --shell /bin/bash --group --disabled-login --home /home/pykmip-server-user pykmip-server-user
mkdir /home/pykmip-server-user/.secrets/
chown -R pykmip-server-user: /home/pykmip-server-user/
chmod 700 /home/pykmip-server-user/.secrets/

# openssl
OPENSSL_CONF=/etc/ssl/openssl.cnf
sed -i '1 i\openssl_conf = default_conf' ${OPENSSL_CONF}
cat >> ${OPENSSL_CONF} <<EOF
[default_conf]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT:@SECLEVEL=0
EOF

echo After pressing Enter, the machine will reboot 
read
reboot
