#!/bin/bash
PASSW=$1
echo "[+] Checking for root permissions"
if [ "$EUID" -ne 0 ];then
    echo "Please run this script as root"
    exit 1
fi

echo "[+] Seeting needrestart to automatic to prevent restart pop ups"
sudo sed -i 's/#$nrconf{restart} = '"'"'i'"'"';/$nrconf{restart} = '"'"'a'"'"';/g' /etc/needrestart/needrestart.conf

echo "[+] Checking for updates"
apt-get update
apt-get upgrade -y

echo "[+] setting max files for opensearch"
sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' >> /etc/sysctl.conf

echo "[+] Installing depenbdancies and MongoDB"
apt install dirmngr gnupg apt-transport-https ca-certificates software-properties-common -y
#apt-get install apt-transport-https openjdk-17-jre-headless uuid-runtime pwgen net-tools -y
apt-get install apt-transport-https uuid-runtime pwgen net-tools -y
wget -qO - https://www.mongodb.org/static/pgp/server-5.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/5.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-5.0.list
wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb
dpkg -i ./libssl1.1_1.1.1f-1ubuntu2_amd64.deb
apt-get update
apt-get install -y mongodb-org
systemctl daemon-reload
systemctl enable mongod
systemctl start mongod

echo "[+] Disabling huge pages support"
cat > /etc/systemd/system/disable-transparent-huge-pages.service <<EOF
Description=Disable Transparent Huge Pages (THP)
DefaultDependencies=no
After=sysinit.target local-fs.target
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo never | tee /sys/kernel/mm/transparent_hugepage/enabled > /dev/null'
[Install]
WantedBy=basic.target
EOF

systemctl daemon-reload
systemctl enable disable-transparent-huge-pages.service
systemctl start disable-transparent-huge-pages.service

echo "[+] Opensearch User"
adduser --system --disabled-password --disabled-login --home /var/empty --no-create-home --quiet --force-badname --group opensearch

echo "[+] Installing Opensearch"
wget https://artifacts.opensearch.org/releases/bundle/opensearch/2.0.1/opensearch-2.0.1-linux-x64.tar.gz


#Create Directories
mkdir -p /graylog/opensearch/data
mkdir /var/log/opensearch

#Extract Contents from tar
tar -zxf opensearch-2.0.1-linux-x64.tar.gz
mv opensearch-2.0.1/* /graylog/opensearch/

#Create empty log file
sudo -u opensearch touch /var/log/opensearch/graylog.log

#Set Permissions
chown -R opensearch:opensearch /graylog/opensearch/
chown -R opensearch:opensearch /var/log/opensearch
chmod -R 2750 /graylog/opensearch/
chmod -R 2750 /var/log/opensearch

#Create System Service

cat > /etc/systemd/system/opensearch.service <<EOF
[Unit]
Description=Opensearch
Documentation=https://opensearch.org/docs/latest
Requires=network.target remote-fs.target
After=network.target remote-fs.target
ConditionPathExists=/graylog/opensearch
ConditionPathExists=/graylog/opensearch/data
[Service]
Environment=OPENSEARCH_HOME=/graylog/opensearch
Environment=OPENSEARCH_PATH_CONF=/graylog/opensearch/config
ReadWritePaths=/var/log/opensearch
User=opensearch
Group=opensearch
WorkingDirectory=/graylog/opensearch
ExecStart=/graylog/opensearch/bin/opensearch
# Specifies the maximum file descriptor number that can be opened by this process
LimitNOFILE=65535
# Specifies the maximum number of processes
LimitNPROC=4096
# Specifies the maximum size of virtual memory
LimitAS=infinity
# Specifies the maximum file size
LimitFSIZE=infinity
# Disable timeout logic and wait until process is stopped
TimeoutStopSec=0
# SIGTERM signal is used to stop the Java process
KillSignal=SIGTERM
# Send the signal only to the JVM rather than its control group
KillMode=process
# Java process is never killed
SendSIGKILL=no
# When a JVM receives a SIGTERM signal it exits with code 143
SuccessExitStatus=143
# Allow a slow startup before the systemd notifier module kicks in to extend the timeout
TimeoutStartSec=180
[Install]
WantedBy=multi-user.target
EOF

echo "[+] Backing up opensearch and creating new one for Graylog"
cp /graylog/opensearch/config/opensearch.yml /graylog/opensearch/config/opensearch-bup.yml
rm /graylog/opensearch/config/opensearch.yml
touch /graylog/opensearch/config/opensearch.yml
chown opensearch:opensearch /graylog/opensearch/config/opensearch.yml
chmod 2750 /graylog/opensearch/config/opensearch.yml

cat > /graylog/opensearch/config/opensearch.yml <<EOF
cluster.name: graylog
node.name: node1
path.data: /graylog/opensearch/data
path.logs: /var/log/opensearch
network.host: 127.0.0.1
discovery.seed_hosts: ["127.0.0.1"]
cluster.initial_master_nodes: ["127.0.0.1"]
action.auto_create_index: false
plugins.security.disabled: true
EOF

echo "[+] Reloading Opensearch Service"
systemctl daemon-reload
systemctl enable opensearch.service
systemctl start opensearch.service

echo "[+] Installing graylog"
wget https://packages.graylog2.org/repo/packages/graylog-5.0-repository_latest.deb
dpkg -i graylog-5.0-repository_latest.deb
apt-get update && sudo apt-get install graylog-server -y

SECRET=`pwgen -N 1 -s 96`
if [[ -z $passw ]]; then
    echo -n "Enter Admin wenb interface Password: "
    read passw
    ADMIN=`echo $passw| tr -d '\n' | sha256sum | cut -d" " -f1`
    echo "Generated password salt is " $secret
    echo "Genberated admin hash is " $admin
else
    ADMIN=`echo $passw| tr -d '\n' | sha256sum | cut -d" " -f1`
    echo "Generated password salt is " $secret
    echo "Genberated admin hash is " $admin
fi
echo "[+] Adjusting Graylog Server configuration file"
CONFIGSECRET=`echo "password_secret = "$SECRET`
CONFIGADMIN=`echo "root_password_sha2 = "$ADMIN`
echo "[+] replacing in configuration files"
sed -r "s/password_secret =/${CONFIGSECRET}/g" -i /etc/graylog/server/server.conf
sed -r "s/root_password_sha2 =/${CONFIGADMIN}/g" -i /etc/graylog/server/server.conf
sed -i 's/#http_bind_address = 127.0.0.1:9000/http_bind_address = 0.0.0.0:9000/g' /etc/graylog/server/server.conf

echo "[+] Disabling Gralog version checks"
echo "versionchecks = false" >> /etc/graylog/server/server.conf

echo "[+] Starting Graylog"
systemctl daemon-reload
systemctl enable graylog-server.service
systemctl start graylog-server.service

echo "###################################################################"
echo "## Set your JVM memory options for your server in below          ##"
echo "## /etc/default/graylog-server                                   ##"
echo "## /graylog/opensearch/config/jvm.options.d                      ##"
echo "## After setting, restart opensearch and graylog                 ##" 
echo "###################################################################"
