
cat <<start_content
########################################################################
#                                                                      #
#               AzuraCast Installation and Hardening Script            #
#                                                                      #
#                  Created by Honeytree Technologies, LLC              #
#                            www.honeytreetech.com                     #
#                                                                      #
#                      AzuraCast: honeytree.social                     #
#                      Email : info@honeytreetech.com                  #
#                                                                      #
########################################################################
start_content

sleep 3

cat <<startup_warning
########################################################################
#####  THIS IS IMPORTANT, PLEASE READ CAREFULLY BEFORE SELECTING   #####
#####                                                              #####
#####   This will install AzuraCast on fresh server                #####
#####                                                              #####
#####  Installing on an operating AzuraCast server will wipe data  #####
#####                                                              #####
########################################################################
startup_warning


# Function to generate a random character
function random_char() {
	local chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	echo -n "${chars:RANDOM%${#chars}:1}"
}

# Function to generate a random string of a given length
function random_string() {
	local length=$1
	local result=""
	for ((i = 0; i < length; i++)); do
		result="${result}$(random_char)"
	done
	echo -n "$result"
}

# Function to validate if the port number is within the specified range
validate_port() {
		local port=$1
		local excluded_ports=("80" "443" "3000")

		if [[ $port =~ ^[0-9]+$ && $port -ge 0 && $port -le 65536 ]]; then
				for excluded_port in "${excluded_ports[@]}"; do
						if [ "$port" -eq "$excluded_port" ]; then
								return 2  # Excluded port
						fi
				done
				return 0  # Valid port number
		else
				return 1  # Invalid port number
		fi
}

while true; do
	read -p "Enter valid domain name: " domain_name
	if [ -n "${domain_name}" ]; then
		break
	else
		echo "Domain cannot be empty. Please enter domain."
	fi
done

read -p "Enter the DB USER NAME (Default: azuracast): " db_username
if [ -z ${db_username} ] ; then
	db_username=azuracast
fi

temp_password="pass_$(random_string 16)"
read -p "Enter the DB PASSWORD (Default: ${temp_password}): " db_password
if [ -z ${db_password} ] ; then
	db_password=${temp_password}
fi
echo "Your db password is ${db_password}"


temp_db="azura_$(random_string 8)"
read -p "Enter the DB NAME (Default: ${temp_db}): " db_name
if [ -z ${db_name} ] ; then
	db_name=${temp_db}
fi
echo "Your db name is ${db_name}"

while true; do
	read -p "Enter a ssh_port number (1-65535, excluding 80, 443, and 3000): " port
	# Validate the input
	validate_port "$port"
	case $? in
		0)
			echo "SSH  port will be: $port"
			ssh_port=$port
			break  # Exit the loop as a valid port has been entered
			;;
		1)
			echo "Invalid port number. Please enter a valid port number between 1 and 65535."
			;;
		2)
			echo "Invalid port number. Port $port is excluded. Please choose a different port."
			;;
	esac
done


# Remove old docker container if docker already present 
if docker -v &>/dev/null; then
	sudo docker rm -f $(docker ps -a -q)
	sudo docker volume rm $(docker volume ls)
fi

# install new version of docker
sudo apt-get update -y
sudo apt-get install -y ca-certificates curl gnupg lsb-release
if test -f /usr/share/keyrings/docker-archive-keyring.gpg; then
 sudo rm /usr/share/keyrings/docker-archive-keyring.gpg
fi
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update -y
sudo apt-get install -y  docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose


# assign work directory
work_dir=~/azuracast
# Remove old work directory if present
sudo rm -rf ${work_dir}
# Make new work directory
mkdir ${work_dir}

touch ${work_dir}/.env
touch ${work_dir}/azuracast.env
touch ${work_dir}/docker-compose.yml


# add content in the docker-compose file
cat <<docker_content >${work_dir}/docker-compose.yml
version: '2.2'

services:
	web:
		container_name: azuracast
		image: "ghcr.io/azuracast/azuracast:${AZURACAST_VERSION:-latest}"
		labels:
			- "com.centurylinklabs.watchtower.scope=azuracast"
		# Want to customize the HTTP/S ports? Follow the instructions here:
		# https://www.azuracast.com/docs/administration/docker/#using-non-standard-ports
		ports:
			- '3000:80'
			- '8443:443'
			- '2222:2022'
		env_file:
			- azuracast.env
			- .env
		volumes:
			- station_data:/var/azuracast/stations
			- backups:/var/azuracast/backups
			- db_data:/var/lib/mysql
			- www_uploads:/var/azuracast/storage/uploads
			- shoutcast2_install:/var/azuracast/storage/shoutcast2
			- stereo_tool_install:/var/azuracast/storage/stereo_tool
			- geolite_install:/var/azuracast/storage/geoip
			- sftpgo_data:/var/azuracast/storage/sftpgo
			- acme:/var/azuracast/storage/acme
		restart: unless-stopped
		ulimits:
			nofile:
				soft: 65536
				hard: 65536
		logging:
			options:
				max-size: "1m"
				max-file: "5"

	updater:
		container_name: azuracast_updater
		image: ghcr.io/azuracast/updater:latest
		volumes:
			- /var/run/docker.sock:/var/run/docker.sock
		logging:
			options:
				max-size: "1m"
				max-file: "5"

volumes:
	db_data: { }
	acme: { }
	shoutcast2_install: { }
	stereo_tool_install: { }
	geolite_install: { }
	sftpgo_data: { }
	station_data: { }
	www_uploads: { }
	backups: { }

docker_content

cat <<env >> ${work_dir}/.env
COMPOSE_PROJECT_NAME=azuracast

AZURACAST_HTTP_PORT=80
AZURACAST_HTTPS_PORT=443

AZURACAST_SFTP_PORT=2022

AZURACAST_PUID=1000
AZURACAST_PGID=1000

NGINX_TIMEOUT=1800
AZURACAST_VERSION=stable

env

cat <<azuracast_env >> ${work_dir}/azuracast.env

# AzuraCast Customization
# The application environment.
# Valid options: production, development, testing
APPLICATION_ENV=production

# Manually modify the logging level.
# This allows you to log debug-level errors temporarily (for problem-solving) or reduce
# the volume of logs that are produced by your installation, without needing to modify
# whether your installation is a production or development instance.
# Valid options: debug, info, notice, warning, error, critical, alert, emergency
# LOG_LEVEL=notice

# Enable the composer "merge" functionality to combine the main application's
# composer.json file with any plugins' composer files.
# This can have performance implications, so you should only use it if
# you use one or more plugins with their own Composer dependencies.
# Valid options: true, false
COMPOSER_PLUGIN_MODE=false

# The minimum port number to use when automatically assigning ports to a station.
# By default, this matches the first forwarded port on the "stations" container.
# You can modify this variable if your station port range is different.
# Be sure to also forward the necessary ports via `docker-compose.yml`
# (and nginx, if you want to use the built-in port-80/443 proxy)!
AUTO_ASSIGN_PORT_MIN=8000

# The maximum port number to use when automatically assigning ports to a station.
# See AUTO_ASSIGN_PORT_MIN.
AUTO_ASSIGN_PORT_MAX=8499

# This allows you to debug Slim Application Errors you may encounter
# By default, this is disabled to prevent users from seeing privileged information
# Please report any Slim Application Error logs to the development team on GitHub
# Valid options: true, false
SHOW_DETAILED_ERRORS=false


#
# Database Configuration
# --
# Once the database has been installed, DO NOT CHANGE these values!
#

# The host to connect to. Leave this as the default value unless you're connecting
#   to an external database server.
# Default: localhost
# MYSQL_HOST=localhost

# The port to connect to. Leave this as the default value unless you're connecting
#   to an external database server.
# Default: 3306
# MYSQL_PORT=3306

# The username AzuraCast will use to connect to the database.
# Default: azuracast
MYSQL_USER=${db_username}

# The password AzuraCast will use to connect to the database.
# By default, the database is not exposed to the Internet at all and this is only
#   an internal password used by the service itself.
# Default: azur4c457
MYSQL_PASSWORD=${db_password}

# The name of the AzuraCast database.
# Default: azuracast
MYSQL_DATABASE=${db_name}

# Automatically generate a random root password upon the first database spin-up.
#   This password will be visible in the mariadb container's logs.
# Default: yes
MYSQL_RANDOM_ROOT_PASSWORD=yes

# Log slower queries for the purpose of diagnosing issues. Only turn this on when
#   you need to, by uncommenting this and switching it to 1.
# To read the slow query log once enabled, run:
#   docker-compose exec mariadb slow_queries
# Default: 0
# MYSQL_SLOW_QUERY_LOG=0

# Set the amount of allowed connections to the database. This value should be increased
# if you are seeing the `Too many connections` error in the logs.
# Default: 100
# MYSQL_MAX_CONNECTIONS=100

# The InnoDB buffer pool size controls how much data & indexes are kept in memory.
# Making sure that this value is as large as possible reduces the amount of disk IO.
# Default: 128M
# MYSQL_INNODB_BUFFER_POOL_SIZE=128M

# The InnoDB log file is used to achieve data durability in case of crashes or unexpected shutoffs
# and to allow the DB to better optimize IO for write operations.
# Default: 16M
# MYSQL_INNODB_LOG_FILE_SIZE=16M

#
# Redis Configuration
#
# Uncomment these fields if you are using a third-party Redis host instead of the one provided with AzuraCast.
# Do not modify these fields if you are using the standard AzuraCast Redis host.
#

# Whether to use the Redis cache; if set to false, will disable Redis and use flatfile cache instead.
# Default: true
# ENABLE_REDIS=true

# Name of the Redis host.
# Default: localhost
# REDIS_HOST=localhost

# Port to connect to on the Redis host.
# Default: 6379
# REDIS_PORT=6379

# Database index to use on the Redis host.
# Default: 1
# REDIS_DB=1

#
# Advanced Configuration
#

# PHP's maximum POST body size and max upload filesize.
# PHP_MAX_FILE_SIZE=25M

# PHP's maximum memory limit.
# PHP_MEMORY_LIMIT=128M

# PHP's maximum script execution time (in seconds).
# PHP_MAX_EXECUTION_TIME=30

# The maximum execution time (and lock timeout) for the 15-second, 1-minute and 5-minute synchronization tasks.
# SYNC_SHORT_EXECUTION_TIME=600

# The maximum execution time (and lock timeout) for the 1-hour synchronization task.
# SYNC_LONG_EXECUTION_TIME=1800

# The delay between Now Playing checks for every station.
# Decrease for more frequent checks at the expense of performance;
# increase for less frequent checks but better performance (for large installations).
# Default: 0
# NOW_PLAYING_DELAY_TIME=0

# The maximum number of concurrent processes for now playing updates.
# Increasing this can help reduce the latency between updates now playing updates on large installations.
# Default: 5
# NOW_PLAYING_MAX_CONCURRENT_PROCESSES=5

# Maximum number of PHP-FPM worker processes to spawn.
# PHP_FPM_MAX_CHILDREN=5

#
# PHP-SPX profiling extension Configuration
#
# These environment variables allow you to enable and configure the PHP-SPX profiling extension
# which can be helpful when debugging resource issues in AzuraCast.
#
# The profiling dashboard can be accessed by visting https://yourdomain.com/?SPX_KEY=dev&SPX_UI_URI=/
# If you change the PROFILING_EXTENSION_HTTP_KEY variable change the value for SPX_KEY accordingly.
#

# Enable the profiling extension.
# Profiling data can be viewed by visiting http://your-azuracast-site/?SPX_KEY=dev&SPX_UI_URI=/
# Default: 0
# PROFILING_EXTENSION_ENABLED=0

# Profile ALL requests made to this account.
# This will have significant performance impact on your installation and should only be used in test circumstances.
# Default: 0
# PROFILING_EXTENSION_ALWAYS_ON=0

# Configure the value for the SPX_KEY parameter needed to access the profiling dashboard
# Default: dev
# PROFILING_EXTENSION_HTTP_KEY=dev

# Configure the IP whitelist for the profiling dashboard
# By default only localhost is allowed to access this page.
# Uncomment this line to enable access for you.
# Default: 127.0.0.1
# PROFILING_EXTENSION_HTTP_IP_WHITELIST=*
azuracast_env


docker-compose -f ${work_dir}/docker-compose.yml up -d



# Setting up the nginx 

if nginx -v &>/dev/null; then
	echo "Nginx is already install installed"
	rm /etc/nginx/sites-available/azuracast
	rm /etc/nginx/sites-enabled/azuracast
else
	sudo apt-get update
	sudo apt-get install -y nginx
fi

# make the nginx file for the application 
touch /etc/nginx/sites-available/azuracast
cat <<nginx_content >>/etc/nginx/sites-available/azuracast
server {

		server_name ${domain_name};

		proxy_set_header Host \$host;

		proxy_set_header X-Real-IP \$remote_addr;

		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

		proxy_set_header X-Forwarded-Proto \$scheme;

		proxy_set_header Proxy "";

		proxy_http_version 1.1;

		proxy_set_header Upgrade \$http_upgrade;

		proxy_set_header Connection "upgrade";



				location / {

						proxy_pass http://localhost:3000;

						proxy_pass_header Server;



						proxy_buffering on;

						proxy_redirect off;

				}

}
nginx_content

#  Link to sites-enabled to enable the virtual host.
sudo ln -s /etc/nginx/sites-available/azuracast /etc/nginx/sites-enabled/

#  Reload the nginx service.
sudo systemctl restart nginx

# Config ufw firewall to allow Nginx ports. Skip if your server doesn't have ufw.
sudo ufw allow 'Nginx Full'

# Secure AzuraCast with Let's Encrypt SSL
sudo apt-get install -y certbot python3-certbot-nginx

# Generate the ssl certificate for domain
sudo certbot --nginx -d ${domain_name}

systemctl restart nginx

sudo cp /etc/ssh/ssh_config /etc/ssh/ssh_config_copy
sudo rm /etc/ssh/ssh_config

cat <<ssh_content >> /etc/ssh/ssh_config
Host *
#   ForwardAgent no
#   ForwardX11 no
#   ForwardX11Trusted yes
#   PasswordAuthentication yes
#   HostbasedAuthentication no
#   GSSAPIAuthentication no
#   GSSAPIDelegateCredentials no
#   GSSAPIKeyExchange no
#   GSSAPITrustDNS no
#   BatchMode no
#   CheckHostIP yes
#   AddressFamily any
#   ConnectTimeout 0
#   StrictHostKeyChecking ask
#   IdentityFile ~/.ssh/id_rsa
#   IdentityFile ~/.ssh/id_dsa
#   IdentityFile ~/.ssh/id_ecdsa
#   IdentityFile ~/.ssh/id_ed25519
	 Port ${ssh_port}
#   Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc
#   MACs hmac-md5,hmac-sha1,umac-64@openssh.com
#   EscapeChar ~
#   Tunnel no
#   TunnelDevice any:any
#   PermitLocalCommand no
#   VisualHostKey no
#   ProxyCommand ssh -q -W %h:%p gateway.example.com
#   RekeyLimit 1G 1h
#   UserKnownHostsFile ~/.ssh/known_hosts.d/%k
		SendEnv LANG LC_*
		HashKnownHosts yes
		GSSAPIAuthentication yes
ssh_content

sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config_copy
sudo rm /etc/ssh/sshd_config

cat <<sshd_content >> /etc/ssh/sshd_config
PermitRootLogin yes


# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Include /etc/ssh/sshd_config.d/*.conf

Port ${ssh_port}
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin prohibit-password
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
#AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
KbdInteractiveAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the KbdInteractiveAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via KbdInteractiveAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and KbdInteractiveAuthentication to 'no'.
UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem sftp  /usr/lib/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
# X11Forwarding no
# AllowTcpForwarding no
# PermitTTY no
# ForceCommand cvs server
sshd_content

#  restart sshd service
systemctl reload ssh
systemctl reload sshd
systemctl restart ssh
systemctl restart sshd

# set up a firewall with ufw.
sudo apt-get install ufw
sudo ufw default allow outgoing
sudo ufw default deny incoming
sudo ufw allow ${ssh_port}/tcp comment 'SSH'
sudo ufw allow http comment 'HTTP'
sudo ufw allow https comment 'HTTPS'
 yes | sudo ufw enable


sudo apt-get install -y fail2ban
rm /etc/fail2ban/jail.local
touch /etc/fail2ban/jail.local

cat << fail2ban_ban >> /etc/fail2ban/jail.local
[ssh]
enabled = true
banaction = iptables-multiport
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
findtime = 43200
bantime = 86400
fail2ban_ban

sudo systemctl restart fail2ban
echo "Congratulations! Your setup is done."
echo "Database user: ${db_user}, password: ${db_password}, and name: ${db_name}."
echo "The AzureCast instance can be accessed at https://${domain_name}."
echo "Now SSH port is ${ssh_port}."
