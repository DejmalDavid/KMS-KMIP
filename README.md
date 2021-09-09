# KMS-KMIP
**Key Managment Server based on Ubuntu, PyKMIP and ETCD**

This is a master thesis of David Dejmala from BUT FIT 2021 (text available here but only in Czech). https://www.vut.cz/en/students/final-thesis/detail/136784
The goal of the project was to create a Key Management Server for the vSphere platform using only free available tools. 

**Main technologies:**
* Ubuntu 20.04 LTS
* Python 3.9.0+ 
* PyKMIP 0.10 
* ETCD 3.2.26 

Tested in vSphere 7.0 environment in the form of Standard Key Manager. The server communicates using the KMIP protocol. PyKMIP has been extended with the option to save data in ETCD, see APP_cripts. If you change param "database_path = etcd3" to the file path in the /etc/pykmip/server.conf, the original SQLite will be used as the storage. ETCD is configured for localhost communication only. 

The installation is fully automated via shell scripts modified for Ubuntu 20.04 LTS. They also include a manual fix for some system errors that are likely to be fixed via regular updates in the future. Warning if scripts end with errors! Commands are not transactional. Scripts must be run as root (most commands require elevated privileges). 

**Script description:**
* 00-network.sh - generates the file /etc/netplan/00-installer-config.yaml according to the specified options and set network.
* 01-system.sh - Set all system modifications. You will be prompted to enter SSH keys, firewall settings, vCenter IP addresses and system update settings. At the end, the machine restarts for all adjustments and updates to take effect.
_CAUTION dont lose SSH access to the machine! It is assumed that there is a user "kms" who is in the sudo group and connect only via cert._
* 02-application.sh - No data is entered here. The script installs and initializes PyKMIP and ETCD and all modifications. During initialization, TLS certificates and passwords are generated for KMIP comunication. Test connection to the ETCD is also included. After completing the script, KMS is already fully functional and ready to handle KMIP requests on the default port 5696 from specific IP (from 01-system.sh (firewall)).

All files in directory Configuration are only for information as configuration looks. They are already content of skripts. Configuration doesn't have to be copied.

**Instalation:**
1. Copy both directories (APP_scripts and VM_scripts) to the same directory (they refer to each other like ../APP_cripts/). 
   1. You can use clear install Ubuntu server. Server MUST include user "kms"
1. sudo ./00-network.sh
1. sudo ./01-system.sh
1. sudo ./02-application.sh

Yeah its easy ;)

**Basic debug commands:**
* `cat /etc/netplan/00-installer-config.yaml `
* `ip a `
* `iptables -L `
* `systemctl status etcd `
* `systemctl status pykmip-server `
* `ps -fu pykmip-server-user `

PyKMIP contains server and client part. The client can be used for testing purposes. The `/usr/local/lib/python3.9/dist-packages/kmip/demos/pie` directory contains test scripts. For example:
* `create.py -a AES -l 256 # creates a symmetric key`
* `create_key_pair.py -a RSA -l 2048 # create key pair `

To connect to vCenter as Standart Key Provider you will need to upload a certificate from `/etc/pykmip/ssl/server_cert.pem` and `/etc/pykmip/ssl/server_key.pem`. Whole procedure in vCenter is described here (https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.security.doc/GUID-78DD547A-6FFC-49F1-A5F2-ECD7507EE835.html) and in text of master thesis.

Logs from server are in dir `/var/log/pykmip`

**TODO:**
1. Make KMS cluster (configuration ETCD + set firewall, should be easy)
1. Create and test backup stragedy
1. Refactor ETCDwrapper.py to save object in JSON to ETCD
1. Test with other application
1. Create web administration (with ETCD shoud be easy)
1. and much much more... 

This project is for testing purposes only, do not use in production! It is not safe! If you lost keys for VM they are lost!

If you have any questions, write me an e-mail ;) I would be very happy if someone use it.
