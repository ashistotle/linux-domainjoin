#!/bin/bash
set +x

#############################################################################################
# This script uses SSSD to domain join a Linux VM to Active Directory                       #
#                                                                                           #
# This script performs the below steps for domain joining                                   #
#       -performs pre-checks (script running as root, parameters passed)                    #
#       -install the required packages                                                      #
#       -edit hosts file entries                                                            #
#       -create krb5.conf file                                                              #
#       -realm join host to AD                                                              #
#       -edit sssd.conf file                                                                #
#       -edit sshd_config file to allow Password Auth                                       #
#       -add domain users and groups as well as provide sudo privileges                     #
#       -optionally, create an A record in AD Domain Contorller and update weekly           #
#                                                                                           #
# Inputs:                                                                                   #
#       1. Domain to which the machine is to be joined                                      #
#       2. Domain Admin ID which will be used for domain joining                            #
#       3. Password for the above Domain Admin ID                                           #
#       4. Comma separated list of OU structure starting from innermost folder to outermost #
#       5. Optional, comma separated list of domain accounts to be added as admins          #
#       6. Optional, comma separated list of domain groups to be added as admins            #
#       7. Optional, hostname of primary DC server                                          #
#       8. Optional, flag to run nsupdate (default is no)                                   #
#       9. Optional, flag to suppress minor errors (default is no)                          #
#       (Apart from input param 1, no other input should contain domain name)               #
#                                                                                           #
# Output:                                                                                   #
#       Exit code based on failure (1-18) or success (0). Look below.                       #
#       All messages are written to syslog:                                                 #
#        - For RHEL: grep "DJScript" /var/log/messages                                      #
#        - For Ubuntu: grep "DJScript" /var/log/syslog                                      #
#                                                                                           #
# Author: Ashis Chakraborty                                                                 #
#                                                                                           #
# Create Date: 2nd Aug 2024                                                                 #
# Update Log:                                                                               #
#       - 7th Aug 2024 | Added code to suppress minor errors                                #
#                                                                                           #
#                                                                                           #
#########################################################################################################################################################################################
#	Exit code |  Status code   |		Description                                                                                                                             #
#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------#
#	1	  | 0fxdjcsru01	   |	This script needs to be run with root privileges. Please login as root and run this script again. Use -h for help.                              #
#	1	  | 0fxdjcsip01	   |	Invalid option provided in command line. Please provide valid options only. Use -h for help.                                                    #
#	1	  | 0fxdjcspa01	   |	Option requires an argument. Please provide an argument to the specified option. Use -h for help.                                               #
#	1	  | 0fxdjcspc01	   |	Missing required arguments. Provide all mandatory options and arguments. Use -h for help.                                                       #
#	2	  | 0fxdjcspi02	   |	Installation of necessary packages for domain joining failed.                                                                                   #
#	3	  | 0fxdjcsip03	   |	IP Address of the machine could not be retrieved.                                                                                               #
#	4	  | 0fxdjcshn04	   |	Calculated hostname evaluates to "localhost".                                                                                                   #
#	5	  | 0fxdjcshn05	   |	Hostname of the machine could not be retrieved.                                                                                                 #
#	6  (S)    | 0fxdjcshf06	   |	Host file updates for domain joining failed.                                                                                                    #
#	7	  | 0fxdjcskb07	   |	krb5 config file not updated.                                                                                                                   #
#	8	  | 0fxdjcsdj08	   |	Domain joining failed due to some error. See output.                                                                                            #
#	9	  | 0fxdjcssd09	   |	New sssd config file not updated. Check file permissions or try again.                                                                          #
#	10	  | 0fxdjcsdj10	   |	sssd service restart post sssd config changes failed. Check sssd config file and fix as required.                                               #
#	11	  | 0fxdjcssh11	   |	PasswordAuthentication could not be set to yes in sshd config file. Check file permissions or try again.                                        #
#	12 (S)    | 0fxdjcssh12	   |	sshd service restart post sshd config changes failed. Check sshd config file and fix as required.                                               #
#	13	  | 0fxdjcsaa13	   |	Provided Admin Account could not be added to sudoers group and cannot be used to login to this machine (Script does not exit).                  #
#	14 (S)    | 0fxdjcsag14	   |	Some error occurred while trying to add Admin group to sudoers. ALL changes made by script to sudoers file will be reverted. Check faulty file. #
#	15 (S)    | 0fxdjcsnu15	   |	nsupdate script creation failed                                                                                                                 #
#	16 (S)    | 0fxdjcsnu16	   |	nsupdate script execution failed                                                                                                                #
#	17 (S)    | 0fxdjcsnu17	   |	nsupdate script failed to be scheduled through crontab                                                                                          #
#	18 (S)    | 0fxdjcsnu18	   |	nsupdate script execution failed due to some unknown error                                                                                      #
#########################################################################################################################################################################################
#	(S) -> Minor error and can be suppressed. If not suppressed, script fails and exits at that error. To suppress minor errors, use flag -s (Not Recommended)                  #
#########################################################################################################################################################################################

# Function to display help
function help() {
	echo "Usage: $0 -d domain -i osp_id -p osp_password -o ou_list [-a admin_accounts] [-g admin_groups] [-c domain_controller] [-n]"
	echo "-d: Domain name (required)"
	echo "-i: OSP ID (required)"
	echo "-p: OSP password (required)"
	echo "-o: OU list (comma-separated, required)"
	echo "-a: Admin accounts (comma-separated, optional)"
	echo "-g: Admin groups (comma-separated, optional)"
	echo "-c: Domain controller hostname (optional)"
	echo "-n: Run nsupdate (optional)"
	echo "-s: Suppress minor errors (optional, NOT RECOMMENDED)"
	exit 0
}

function log() {
	local message="$1"
	local level="${2:-ERROR}"  # Default log level is error

	timestamp=$(date +%Y-%m-%d_%H:%M:%S)
	formatted_message="${timestamp} - $level: [DJScript] $message"

	echo "$formatted_message"
	logger -t "$(basename $0)" -p "$level" "$formatted_message"
}

#Check that the script is being run as root user
if ([ `id | cut -d"=" -f2 | cut -d"(" -f1` -ne 0 ]) then		
	log "This script needs to be run with root privileges. Please login as root and run this script again {Status code: 0fxdjcsru01}."
	exit 1
fi

log "Script running with root privileges." "INFO"

DOMAIN=""
OSPID=""
OSPPWD=""
NSTDOULST=""
ADMINACCTS=""
ADMINGRPS=""
DCSERVER=""
NSUPDT=false
SUPPERRS=false

#Get parameters
while getopts ":hd:i:p:o:a:g:c:ns" opt; do
	case $opt in
		h)
			help
			;;
		d)
			DOMAIN="$OPTARG"
			;;
		i)
			OSPID="$OPTARG"
			;;
		p)
			OSPPWD="$OPTARG"
			;;
		o)
			NSTDOULST=`echo $OPTARG | tr -d " "`
			;;
		a)
			ADMINACCTS=`echo $OPTARG | tr -d " "`
			;;
		g)
			ADMINGRPS=`echo $OPTARG | tr -d " "`
			;;
		c)
			DCSERVER="$OPTARG"
			;;
		n)
			NSUPDT=true
			;;
		s)
			SUPPERRS=true
			;;
		\?)
			log "Invalid option: -$OPTARG. Use -h for help. {Status code: 0fxdjcsip01}."
			exit 1
			;;
		:)
			log "Option -$OPTARG requires an argument. Use -h for help. {Status code: 0fxdjcspa01}."
			exit 1
			;;
	esac
done

# Check for mandatory arguments
if [ -z "$DOMAIN" ] || [ -z "$OSPID" ] || [ -z "$OSPPWD" ] || [ -z "$NSTDOULST" ]; then
    log "Missing required arguments. Use -h for help. {Status code: 0fxdjcspc01}."
    exit 1
fi

if [ $SUPPERRS ]; then
	log "You have chosen to suppress minor errors! This option is not recommended as it may cause serious problems with domain joining." "INFO"
fi

PSTFIX=`date '+%d%m%Y%H%M%S'`

if [ -f /etc/sssd/sssd.conf ]; then
	log "Old sssd.conf file found. Taking backup: /etc/sssd/sssd.conf_old.$PSTFIX" "INFO"
	cp -f "/etc/sssd/sssd.conf" "/etc/sssd/sssd.conf_old.$PSTFIX"
fi	

log "Script running with following parameters: Domain=$DOMAIN, OSP_ID=$OSPID, OSP_PWD=#####, OU=$NSTDOULST, Admin_Accts=$ADMINACCTS, Admin_Groups=$ADMINGRPS, DC_Server=$DCSERVER, Setup_nsupdate=$NSUPDT, Suppress_Minor_Errors=$SUPPERRS." "INFO"

#Check if hostname already contains domain and remove it
if [[ `echo "${DCSERVER}" | grep -ic "${DOMAIN}"` -gt 0 ]];then
	DCSERVER=`echo "${DCSERVER}" | awk -F"." '{print $1}'`
fi

#Convert domain to upper and lower case
DMNUCS="${DOMAIN^^}"
DMNLCS="$(echo "$DMNUCS" | tr '[:upper:]' '[:lower:]')"

#Convert domain to DC format
IFS='.' read -r -a domain_parts <<< "$DMNUCS"
DCFRMT="DC=${domain_parts[0]}"
for domain_part in "${domain_parts[@]:1}"; do
  DCFRMT+=","
  DCFRMT+="DC=$domain_part"
done

#Convert Nested OU list to OU format
IFS=',' read -r -a ou_parts <<< "$NSTDOULST"
OUFRMT="OU=${ou_parts[0]}"
for ou_part in "${ou_parts[@]:1}"; do
  OUFRMT+=","
  OUFRMT+="OU=$ou_part"
done

#Get the OS type
OS=`grep "^ID=" /etc/os-release |cut -d "=" -f2`

#Run commands based on OS type
if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]];then
	IPADDR=`hostname -i | awk '{print $1}'`
	
	#Install necessary packages
	apt-get -y install sssd realmd adcli sssd-tools sssd-ad krb5-user dnsutils	
else
	IPADDR=`hostname -I | awk '{print $1}'`
	
	#Install necessary packages
	yum -y install sssd realmd oddjob krb5-workstation openldap-clients bind-utils	
fi

#Check if package installation was successful
if [ $? -ne 0 ]
then
	log "Installation of necessary packages for domain joining failed {Status code: 0fxdjcspi02}."
	exit 2
else
	log "Installation of necessary packages for domain joining completed." "INFO"
fi

#Check if IP Address was retrieved
if [ -n "$IPADDR" ]
then
	log "IP Address of machine retrieved - $IPADDR" "INFO"
else
	log "IP Address of the machine could not be retrieved {Status code: 0fxdjcsip03}."
	exit 3
fi

#Retrieve Hostname and FQDN
HOSTN=`hostname -f`

#Check if Hostname was correctly retrieved
if [ -n "$HOSTN" ]
then
	if [[ `echo "${HOSTN}" | grep -ic localhost` -gt 0 ]];then
		log "Calculated hostname evaluates to localhost {Status code: 0fxdjcshn04}."
		exit 4
	fi
	log "Calculated hostname of machine evaluated - $HOSTN" "INFO"
else
	log "Hostname of the machine could not be retrieved {Status code: 0fxdjcshn05}."
	exit 5
fi

#Check if hostname already contains domain and remove it
if [[ `echo "${HOSTN}" | grep -ic "${DOMAIN}"` -gt 0 ]];then
	HOSTN=`echo "${HOSTN}" | awk -F"." '{print $1}'`
fi

#Backup Host file and Resolv conf
cp -f /etc/hosts /etc/hosts_djbkp.$PSTFIX
cp -f /etc/resolv.conf /etc/resolv.conf_djbkp.$PSTFIX

#Add domain to resolv.conf file
grep -q ^"domain $DMNLCS" /etc/resolv.conf || sed -i '/^search/a\domain '"$DMNLCS"'' /etc/resolv.conf

#Add Host entries to host file of DC host name
grep -q ^$IPADDR /etc/hosts || sed -i '$s/$/\n'"$IPADDR $HOSTN $HOSTN.$DMNUCS"'/' /etc/hosts

#Check if host file update was successful
if [ $? -ne 0 ]
then
	log "Host file updates for domain joining failed {Status code: 0fxdjcshf06}."
	if [ ! $SUPPERRS ]; then
		exit 6
	fi
else
	log "Host file successfully updated for domain joining." "INFO"
fi

if [ -n "$DCSERVER" ]
then
	DCSRVRIP=`nslookup $DCSERVER.$DMNLCS | tail -2 | grep ^Address | cut -d":" -f2 | tr -d " "`
	#Add domain controller <-- Check if this is required
	grep -q ^"$DCSRVRIP" /etc/hosts || sed -i '$s/$/\n'"$DCSRVRIP $DCSERVER $DCSERVER.$DMNLCS"'/' /etc/hosts
	#Check if host file update was successful
	if [ $? -ne 0 ]
	then
		log "Host file updates for domain joining failed {Status code: 0fxdjcshf06}."
		if [ ! $SUPPERRS ]; then
			exit 6
		fi
	else
		log "Host file successfully updated for domain joining." "INFO"
	fi
fi

#Backup /etc/krb5.conf
cp -f /etc/krb5.conf /etc/krb5.conf_djbkp.$PSTFIX

#Create /etc/krb5.conf.d if not present
if [ ! -d /etc/krb5.conf.d ]
then
	mkdir -p /etc/krb5.conf.d
fi

#Create the file /etc/krb5.conf
echo "# Configuration snippets may be placed in this directory as well" > /etc/krb5.conf
echo "includedir /etc/krb5.conf.d/" >> /etc/krb5.conf
echo "" >> /etc/krb5.conf
echo "includedir /var/lib/sss/pubconf/krb5.include.d/" >> /etc/krb5.conf
echo "[logging]" >> /etc/krb5.conf
echo " default = FILE:/var/log/krb5libs.log" >> /etc/krb5.conf
echo " kdc = FILE:/var/log/krb5kdc.log" >> /etc/krb5.conf
echo " admin_server = FILE:/var/log/kadmind.log" >> /etc/krb5.conf
echo "" >> /etc/krb5.conf
echo "[libdefaults]" >> /etc/krb5.conf
echo " default_realm = $DMNUCS" >> /etc/krb5.conf
echo " dns_lookup_realm = true" >> /etc/krb5.conf
echo " ticket_lifetime = 24h" >> /etc/krb5.conf
echo " renew_lifetime = 7d" >> /etc/krb5.conf
echo " forwardable = true" >> /etc/krb5.conf
echo " rdns = false" >> /etc/krb5.conf
echo " pkinit_anchors = /etc/pki/tls/certs/ca-bundle.crt" >> /etc/krb5.conf
echo " default_ccache_name = KEYRING:persistent:%{uid}" >> /etc/krb5.conf
echo " #Added as per Confluence" >> /etc/krb5.conf
echo " default_tkt_enctypes = aes256-cts aes128-cts rc4-hmac" >> /etc/krb5.conf
echo " default_tgs_enctypes = aes256-cts aes128-cts rc4-hmac" >> /etc/krb5.conf
echo " permitted_enctypes = aes256-cts aes128-cts rc4-hmac" >> /etc/krb5.conf
echo "[realms]" >> /etc/krb5.conf
echo " $DMNUCS = {" >> /etc/krb5.conf
echo "kdc = $DMNLCS" >> /etc/krb5.conf
echo "admin_server = $DMNLCS" >> /etc/krb5.conf
echo " }" >> /etc/krb5.conf
echo "" >> /etc/krb5.conf
echo " $DMNUCS = {" >> /etc/krb5.conf
echo "  kdc = $DMNLCS" >> /etc/krb5.conf
echo "  admin_server = $DMNLCS" >> /etc/krb5.conf
echo " }" >> /etc/krb5.conf
echo "" >> /etc/krb5.conf
echo "[domain_realm]" >> /etc/krb5.conf
echo " $DMNLCS = $DMNUCS" >> /etc/krb5.conf
echo " .$DMNLCS = $DMNUCS" >> /etc/krb5.conf

#Check that /etc/krb5.conf is not zero byte
if [ -s /etc/krb5.conf ]
then
	log "krb5 configuration update completed." "INFO"
else
	log "krb5 config file not updated {Status code: 0fxdjcskb07}."
	exit 7
fi

#Leave realm if already joined
echo "$OSPPWD" | realm leave $DMNLCS -v
sleep 5

#Realm join using OSP ID and Password
if [ -n "$DCSERVER" ]
then
	log "Domain join using DC Server $DCSERVER.$DMNLCS." "INFO"
	echo "$OSPPWD" | realm join --computer-ou="$OUFRMT,$DCFRMT" --user="$OSPID" "$DCSERVER.$DMNLCS" -v
else
	echo "$OSPPWD" | realm join --computer-ou="$OUFRMT,$DCFRMT" --user="$OSPID" $DMNLCS -v
fi

#Check if realm join was successful
if [ $? -ne 0 ]
then
	log "Domain joining failed {Status code: 0fxdjcsdj08}."
	exit 8
else
	log "Domain joining successful - $HOSTN,$OUFRMT,$DCFRMT,$DCSERVER" "INFO"
fi

#Backup default /etc/sssd/sssd.conf
cp -f /etc/sssd/sssd.conf /etc/sssd/sssd.conf_djbkp.$PSTFIX

#Re-create the file /etc/sssd/sssd.conf
echo "[nss]" > /etc/sssd/sssd.conf
echo "filter_groups = root" >> /etc/sssd/sssd.conf
echo "filter_users = root" >> /etc/sssd/sssd.conf
echo "reconnection_retries = 3" >> /etc/sssd/sssd.conf
echo "" >> /etc/sssd/sssd.conf
echo "[pam]" >> /etc/sssd/sssd.conf
echo "reconnection_retries = 3" >> /etc/sssd/sssd.conf
echo "pam_id_timeout = 7200" >> /etc/sssd/sssd.conf
echo "get_domains_timeout = 7200" >> /etc/sssd/sssd.conf
echo "" >> /etc/sssd/sssd.conf
echo "[sssd]" >> /etc/sssd/sssd.conf
echo "domains = $DMNLCS" >> /etc/sssd/sssd.conf
echo "config_file_version = 2" >> /etc/sssd/sssd.conf
echo "services = nss, pam" >> /etc/sssd/sssd.conf
echo "" >> /etc/sssd/sssd.conf
echo "[domain/$DMNLCS]" >> /etc/sssd/sssd.conf
#if [ -n "$DCSERVER" ]
#then
#	echo "ad_server = $DCSERVER.$DMNLCS" >> /etc/sssd/sssd.conf
#fi
echo "ad_domain = $DMNLCS" >> /etc/sssd/sssd.conf
echo "krb5_realm = $DMNUCS" >> /etc/sssd/sssd.conf
echo "realmd_tags = manages-system joined-with-adcli" >> /etc/sssd/sssd.conf
#echo "cache_credentials =" >> /etc/sssd/sssd.conf
echo "id_provider = ad" >> /etc/sssd/sssd.conf
echo "krb5_store_password_if_offline = True" >> /etc/sssd/sssd.conf
echo "ldap_id_mapping = True" >> /etc/sssd/sssd.conf
echo "use_fully_qualified_names = False" >> /etc/sssd/sssd.conf
echo "override_homedir = /home/%u" >> /etc/sssd/sssd.conf
echo "override_shell = /bin/bash" >> /etc/sssd/sssd.conf
echo "access_provider = simple" >> /etc/sssd/sssd.conf
if [ -f /etc/sssd/sssd.conf_old.$PSTFIX ]; then
	#Carry over earlier values and check for duplicates
	ADMINGRPOLD=`grep ^simple_allow_groups /etc/sssd/sssd.conf_old.$PSTFIX | cut -d"=" -f2 | tr -d " "`
	ADMINGRPNEW="$ADMINGRPOLD,$ADMINGRPS"
	ADMINGRPS=`echo $ADMINGRPNEW | sed 's/^,//' | sed 's/,$//' | tr "," "\n" | uniq | tr '\n' ',' | sed '$s/,$/\n/' | tr -d "\""`

	ADMINACCTSOLD=`grep ^simple_allow_users /etc/sssd/sssd.conf_old.$PSTFIX | cut -d"=" -f2 | tr -d " "`
	ADMINACCTSNEW="$ADMINACCTSOLD,$ADMINACCTS"
	ADMINACCTS=`echo $ADMINACCTSNEW | sed 's/^,//' | sed 's/,$//' | tr "," "\n" | uniq | tr '\n' ',' | sed '$s/,$/\n/' | tr -d "\""`
	
	log "Copied admin account/group from old sssd.conf file /etc/sssd/sssd.conf_old.$PSTFIX. New values:" "INFO"
	log "Admin Accounts: $ADMINACCTS" "INFO"
	log "Admin Groups: $ADMINGRPS" "INFO"	
fi
echo "simple_allow_groups = $ADMINGRPS" >> /etc/sssd/sssd.conf
echo "simple_allow_users = $ADMINACCTS" >> /etc/sssd/sssd.conf

#Check that /etc/sssd/sssd.conf is not zero byte
if [ -s /etc/sssd/sssd.conf ]
then
	log "New sssd configuration update completed." "INFO"
else
	log "New sssd config file not updated {Status code: 0fxdjcssd09}."
	exit 9
fi

#Make sure /etc/sssd/sssd.conf permissions are 600 and is owned by root user
chmod 600 /etc/sssd/sssd.conf
chown root:root /etc/sssd/sssd.conf

#Start and enable the sssd service:
systemctl enable sssd.service
systemctl restart sssd.service

#Check if sssd service restart was successful
if [ $? -ne 0 ]
then
	log "sssd service restart post sssd config changes failed {Status code: 0fxdjcsdj10}."
	exit 10
else
	log "sssd service restart post sssd config changes was successful." "INFO"
fi

#Backup /etc/ssh/sshd_config
cp -f /etc/ssh/sshd_config /etc/ssh/sshd_config_djbkp.$PSTFIX

#Check if multiple rows contain PasswordAuthentication
if [ `grep -c 'PasswordAuthentication' /etc/ssh/sshd_config` -gt 1 ]
then
	log "Multiple lines containing PasswordAuthentication found in sshd_config file. These extra lines will be truncated." "INFO"
	#Remove all extra lines except for first occurrence
	DELLINES=`grep -n PasswordAuthentication /etc/ssh/sshd_config  | awk -F":" '{print $1"d;"}' | awk 'NR > 1' | tr -d "\n" | sed 's/;$//'`
	sed -i "$RMVLINES" /etc/ssh/sshd_config
fi

#change Password authentication to Yes on the file /etc/ssh/sshd_config
sed -i '/^#\?PasswordAuthentication/s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

#Check PasswordAuthentication is set to yes in /etc/ssh/sshd_config file
if [ `grep ^PasswordAuthentication /etc/ssh/sshd_config | awk '{print $NF}' | grep -ic yes` -eq 1 ]
then
	log "PasswordAuthentication is set to yes in sshd config file." "INFO"
else
	log "PasswordAuthentication could not be set to yes in sshd config file {Status code: 0fxdjcssh11}."
	exit 11
fi

#Start the sssd service
systemctl restart sshd.service

#Check if sssd service restart was successful
if [ $? -ne 0 ]
then
	log "sshd service restart post sshd config changes failed  {Status code: 0fxdjcssh12}."	
	log "Attempting to restore sshd file and restart sshd service. Please note that domain joining may fail even after this step." "INFO"
	
	#Restore sshd file
	mv -f /etc/ssh/sshd_config_djbkp.$PSTFIX /etc/ssh/sshd_config
	
	#Start the sssd service
	systemctl restart sshd.service
	if [ ! $SUPPERRS ]; then
		exit 12
	fi
else
	log "sshd service restart post sshd config changes was successful." "INFO"
fi

#Add admin accounts to sudoers group
for ADMINACCT in `echo $ADMINACCTS | tr "," " "`
do
	#Check if the domain admin account exists
	id $ADMINACCT > /dev/null

	if [ $? -ne 0 ]
	then
		log "Account $ADMINACCT was not detected and cannot be used to login to this machine." "INFO"
	else	
		if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]];then
			usermod -aG sudo $ADMINACCT
			
			#Test if the admin accounts were added to sudoers group
			if [ `grep ^sudo /etc/group | grep -ic $ADMINACCT` -eq 0 ]; then
				log "Account $ADMINACCT could not be added to sudoers group and cannot be used to login to this machine {Status code: 0fxdjcsaa13}. NO EXIT."
			else
				log "Account $ADMINACCT is added to sudoers group." "INFO"
			fi
		else
			usermod -aG wheel $ADMINACCT
			
			#Test if the admin accounts were added to sudoers group
			if [ `grep ^wheel /etc/group | grep -ic $ADMINACCT` -eq 0 ]; then
				log "Account $ADMINACCT could not be added to sudoers group and cannot be used to login to this machine {Status code: 0fxdjcsaa13}. NO EXIT."
			else
				log "Account $ADMINACCT is added to sudoers group." "INFO"
			fi
		fi
	fi
done

#Take backup of sudoers file
cp -f /etc/sudoers /etc/sudoers_djbkp.$PSTFIX
if [ -f /etc/sudoers.d/djscript ]; then
	cp -f /etc/sudoers.d/djscript /etc/djscript-sudoers_djbkp.$PSTFIX
fi

#Add admin groups to sudoers
for ADMINGRP in `echo $ADMINGRPS | tr "," " "`
do
	getent group $ADMINGRP
	
	if [ $? -eq 0 ]; then
		log "Admin group $ADMINGRP found. Attempting to add to sudoers." "INFO"
		#Construct the sudoers line
		SUDOLINE="%${ADMINGRP} ALL=(ALL:ALL) ALL"

		#Check if the line already exists
		if grep -Fxq "${SUDOLINE}" /etc/sudoers; then
			log "Admin group $ADMINGRP already present in /etc/sudoers. Skipping." "INFO"
		else
			#Check if the djscript file is present in sudoers.d
			if [ -f /etc/sudoers.d/djscript ]; then
				#Check if the line already exists
				if grep -Fxq "${SUDOLINE}" /etc/sudoers.d/djscript; then
					log "Admin group $ADMINGRP already present in /etc/sudoers.d/djscript. Skipping." "INFO"
				else
					echo "${SUDOLINE}" | tee -a /etc/sudoers.d/djscript
					log "Admin group $ADMINGRP added to /etc/sudoers.d/djscript." "INFO"
				fi
			else
				#Create the djscript file within sudoers.d
				touch /etc/sudoers.d/djscript
				chmod 0440 /etc/sudoers.d/djscript
				log "Sudoers file /etc/sudoers.d/djscript created." "INFO"
				
				echo "${SUDOLINE}" | tee -a /etc/sudoers.d/djscript
				log "Admin group $ADMINGRP added to /etc/sudoers.d/djscript." "INFO"
			fi
		
			# Use visudo to check if the djscript file is correct
			visudo -c -f /etc/sudoers.d/djscript
		
			if [ $? -ne 0 ]
			then
				log "Some error occurred while trying to add Admin group $ADMINGRP to sudoers {Status code: 0fxdjcsag14}."
				log "Reverting ALL changes to sudoers file. Faulty file: /tmp/djscript_djbkp.$PSTFIX.faulty" "INFO"
				cp /etc/sudoers.d/djscript /tmp/djscript_djbkp.$PSTFIX.faulty
				mv /etc/djscript-sudoers_djbkp.$PSTFIX /etc/sudoers.d/djscript
				if [ ! $SUPPERRS ]; then
					exit 14
				fi
			else
				log "Admin group $ADMINGRP added to sudoers." "INFO"
			fi
		fi
	else
		log "Admin group $ADMINGRP was not detected and cannot be used to login to this machine." "INFO"
	fi	
done

#Create the script /etc/network/if-up.d/nsupdate.sh
if $NSUPDT; then
	#Create the folder, if not present
	if [ ! -d /etc/network/if-up.d ]
	then
		mkdir -p /etc/network/if-up.d
	fi
	
	echo '#!/bin/bash' > /etc/network/if-up.d/nsupdate.sh
	echo '' >> /etc/network/if-up.d/nsupdate.sh
	echo '################################################################################' >> /etc/network/if-up.d/nsupdate.sh
	echo '# This scriptlet is used to create an A record in AD Domain Contorller         #' >> /etc/network/if-up.d/nsupdate.sh
	echo '# This scriptlet adds the DNS entry for the specific hostname mapping with IP  #' >> /etc/network/if-up.d/nsupdate.sh
	echo '#                                                                              #' >> /etc/network/if-up.d/nsupdate.sh
	echo '# This scriptlet needs to be executed during domain joining                    #' >> /etc/network/if-up.d/nsupdate.sh
	echo '#       as well as scheduled through cron job                                  #' >> /etc/network/if-up.d/nsupdate.sh
	echo '#       to execute every Monday at 6AM server time                             #' >> /etc/network/if-up.d/nsupdate.sh
	echo '#                                                                              #' >> /etc/network/if-up.d/nsupdate.sh
	echo '# Author: Ashis Chakraborty                                                    #' >> /etc/network/if-up.d/nsupdate.sh
	echo '#                                                                              #' >> /etc/network/if-up.d/nsupdate.sh
	echo '#    To manually create the schedule in crontab:                               #' >> /etc/network/if-up.d/nsupdate.sh
	echo '#           crontab -e                                                         #' >> /etc/network/if-up.d/nsupdate.sh
	echo '#           0 6 * * 1 /etc/network/if-up.d/nsupdate.sh 2>&1 /tmp/nsupdate.log  #' >> /etc/network/if-up.d/nsupdate.sh
	echo '################################################################################' >> /etc/network/if-up.d/nsupdate.sh
	echo "SUPPERRS=$SUPPERRS" >> /etc/network/if-up.d/nsupdate.sh
	echo '' >> /etc/network/if-up.d/nsupdate.sh
	echo 'echo $0' >> /etc/network/if-up.d/nsupdate.sh
	echo '#Prepare the nsupdate configuration script' >> /etc/network/if-up.d/nsupdate.sh
	echo "echo "server $DMNUCS" > /tmp/nsupdate.conf" >> /etc/network/if-up.d/nsupdate.sh
	echo "echo "update delete ${HOSTN}.${DMNUCS} A" >> /tmp/nsupdate.conf" >> /etc/network/if-up.d/nsupdate.sh
	echo "echo "update add ${HOSTN}.${DMNUCS} 3600 A ${IPADDR}" >> /tmp/nsupdate.conf" >> /etc/network/if-up.d/nsupdate.sh
	echo 'echo "send quit" >> /tmp/nsupdate.conf' >> /etc/network/if-up.d/nsupdate.sh
	echo '' >> /etc/network/if-up.d/nsupdate.sh
	echo '#Initialize kerberos keys' >> /etc/network/if-up.d/nsupdate.sh
	echo "kinit -k ${HOSTN}\$" >> /etc/network/if-up.d/nsupdate.sh
	echo '' >> /etc/network/if-up.d/nsupdate.sh
	echo '#Execute the nsupdate command with the desired configuration script' >> /etc/network/if-up.d/nsupdate.sh
	echo 'nsupdate -gddd /tmp/nsupdate.conf' >> /etc/network/if-up.d/nsupdate.sh
	echo '' >> /etc/network/if-up.d/nsupdate.sh
	echo '#Check exit status of nsupdate command' >> /etc/network/if-up.d/nsupdate.sh
	echo 'if [[ $? -eq 0 ]]; then' >> /etc/network/if-up.d/nsupdate.sh
	echo '	echo "*********** THE NSUPDATE SCRIPT HAS COMPLETED SUCCESSFULLY **********"' >> /etc/network/if-up.d/nsupdate.sh
	echo '	logger "INFO: [DJScript] The nsupdate script ran successfully"' >> /etc/network/if-up.d/nsupdate.sh
	echo 'else' >> /etc/network/if-up.d/nsupdate.sh
	echo '	echo "!!!!!!!!!!! THE NSUPDATE SCRIPT FAILED EXECUTION !!!!!!!!!!"' >> /etc/network/if-up.d/nsupdate.sh
	echo '	logger "ERROR: [DJScript] The nsupdate script did not run successfully"' >> /etc/network/if-up.d/nsupdate.sh
	echo '	if [ ! $SUPPERRS ]; then' >> /etc/network/if-up.d/nsupdate.sh
	echo '		return 111' >> /etc/network/if-up.d/nsupdate.sh
	echo '	fi' >> /etc/network/if-up.d/nsupdate.sh
	echo 'fi' >> /etc/network/if-up.d/nsupdate.sh
	echo '' >> /etc/network/if-up.d/nsupdate.sh
	echo '#Create crontab entry, if not already present' >> /etc/network/if-up.d/nsupdate.sh
	echo 'if [[ $(crontab -l | egrep -v "^(#|$)" | grep -q nsupdate.sh; echo $?) == 1 ]]; then' >> /etc/network/if-up.d/nsupdate.sh
	echo '	set -f' >> /etc/network/if-up.d/nsupdate.sh
	echo '	crontab -l > /tmp/tempcrontab.tmp' >> /etc/network/if-up.d/nsupdate.sh
	echo " 	echo '0 6 * * 1 /etc/network/if-up.d/nsupdate.sh 2>&1 /tmp/nsupdate.log' >> /tmp/tempcrontab.tmp" >> /etc/network/if-up.d/nsupdate.sh
	echo ' 	cat /tmp/tempcrontab.tmp | crontab -' >> /etc/network/if-up.d/nsupdate.sh
	echo '  if [[ $? -eq 0 ]]; then' >> /etc/network/if-up.d/nsupdate.sh
	echo '  	rm -f /tmp/tempcrontab.tmp' >> /etc/network/if-up.d/nsupdate.sh
	echo '     	echo "*********** THE NSUPDATE SCRIPT HAS BEEN SCHEDULED SUCCESSFULLY **********"' >> /etc/network/if-up.d/nsupdate.sh
	echo '		logger "INFO: [DJScript] The nsupdate script was scheduled successfully"' >> /etc/network/if-up.d/nsupdate.sh
	echo '  else' >> /etc/network/if-up.d/nsupdate.sh
	echo '     	echo "!!!!!!!!!!! THE NSUPDATE SCRIPT FAILED TO BE SCHEDULED SUCCESSFULLY !!!!!!!!!!"' >> /etc/network/if-up.d/nsupdate.sh
	echo '		echo "Please check crontab and replace with temporary file at: /tmp/tempcrontab.tmp"' >> /etc/network/if-up.d/nsupdate.sh
	echo '		logger "ERROR: [DJScript] The nsupdate script could not be scheduled successfully"' >> /etc/network/if-up.d/nsupdate.sh
	echo '		if [ ! $SUPPERRS ]; then' >> /etc/network/if-up.d/nsupdate.sh
	echo '			return 121' >> /etc/network/if-up.d/nsupdate.sh
	echo '		fi' >> /etc/network/if-up.d/nsupdate.sh
	echo '  fi' >> /etc/network/if-up.d/nsupdate.sh
	echo '	set +f' >> /etc/network/if-up.d/nsupdate.sh
	echo 'fi' >> /etc/network/if-up.d/nsupdate.sh
	echo '' >> /etc/network/if-up.d/nsupdate.sh
	echo '#Wait for 5 seconds and restart the network service' >> /etc/network/if-up.d/nsupdate.sh
	echo 'sleep 5s' >> /etc/network/if-up.d/nsupdate.sh
	echo '#systemctl restart NetworkManager' >> /etc/network/if-up.d/nsupdate.sh
	echo 'return 0' >> /etc/network/if-up.d/nsupdate.sh
	
	#Check that /etc/network/if-up.d/nsupdate.sh is not zero byte
	if [ -s /etc/network/if-up.d/nsupdate.sh ]
	then		
		#Change mode of the nsupdate file to 777
		chmod 777 /etc/network/if-up.d/nsupdate.sh
		
		log "/etc/network/if-up.d/nsupdate.sh script creation completed. Initiating nsupdate execution." "INFO"
		
		#Execute the nsupdate script
		. /etc/network/if-up.d/nsupdate.sh
		
		RTNVAL=$?
		
		#Change the lines starting with return to exit to make the script standalone
		sed -i 's/return/exit/g' /etc/network/if-up.d/nsupdate.sh
		
		if [ $RTNVAL -eq 0 ]
		then
			log "nsupdate script execution completed successfully." "INFO"
		elif [ $RTNVAL -eq 111 ]
		then
			log "nsupdate script execution failed {Status code: 0fxdjcsnu16}."
			if [ ! $SUPPERRS ]; then
				exit 16
			fi
		elif [ $RTNVAL -eq 121 ]
		then
			log "nsupdate script failed to be scheduled through crontab {Status code: 0fxdjcsnu17}."
			if [ ! $SUPPERRS ]; then
				exit 17
			fi
		else
			log "nsupdate script execution failed due to some unknown error {Status code: 0fxdjcsnu18}."
			if [ ! $SUPPERRS ]; then
				exit 18
			fi
		fi	
	else
		log "nsupdate script creation failed {Status code: 0fxdjcsnu15}."
		if [ ! $SUPPERRS ]; then
			exit 15
		fi
	fi
fi

#Script execution completed
log "Domain join script execution completed." "INFO"
exit 0
