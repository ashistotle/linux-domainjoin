#!/bin/bash
set +x
################################################################################
# This script uses SSSD to domain join a Linux VM to Active Directory          #
#                                                                              #
# This script performs the below steps for domain joining                      #
#       -performs pre-checks (script running as root, parameters passed)       #
#       -install the required packages                                         #
#       -edit hosts file entries                                               #
#       -create krb5.conf file                                                 #
#       -realm join host to AD                                                 #
#       -edit sssd.conf file                                                   #
#       -edit sshd_config file                                                 #
#       -add domain users and provide sudo privileges                          #
#       -create an A record in AD Domain Contorller                            #
#       -create a cron job to maintain the A record every week                 #
#                                                                              #
# Inputs:                                                                      #
#       1. Domain to which the machine is to be joined                         #
#       2. Domain Admin ID which will be used for domain joining               #
#       3. Password for the above Domain Admin ID                              #
#       4. Nested OU structure starting from innermost, comma separated list   #
#       5. Comma separated list of domain accounts to be added as admins       #
#       6. Comma separated list of domain groups to be added as admins         #
#       (Apart from input param 1, no other input should contain domain name)  #
#                                                                              #
# Output:                                                                      #
#       Exit code based on failure (1-18) or success (0)                       #
#       All messages are written to syslog                                     #
#           For RHEL: grep "DJScript" /var/log/messages                        #
#           For Ubuntu: grep "DJScript" /var/log/syslog                        #
#                                                                              #
# Author: Ashis Chakraborty                                                    #
#                                                                              #
# Create Date: 22 July 2024                                                    #
# Update Date:                                                                 #
# Update Log:                                                                  #
#       -<Date> | <Update>                                                     #
#       -29/07/2024 | Changed OU structure to take comma separated             #
#                      nested OU list                                          #
#                                                                              #
#                                                                              #
################################################################################

#How to run the script
#. ./linux_domain_join_sssd_v1.sh "<DOMAIN>" "<OSP_ID>" '<OSP_PWD>' "<NESTED,OU,LIST>" "<ADMIN_ACCT>" "<ADMIN_GROUP>"

#Azure Servers
#. ./linux_domain_join_sssd_v1.sh "ad005.onehc.net" "<OSP_ID>" '<OSP_PASSWORD>' "Servers,_Central,CHN,RA133" "z004vyxa-a01" "RA133_G_HC-CoreOps-Admins,SH103_MADiS_132924_G"

#TE DC Servers
#. ./linux_domain_join_sssd_v1.sh "ad005.onehc.net" "<OSP_ID>" '<OSP_PASSWORD>' "Non_Windows_Servers,SNX,Servers,_Central,Siecloud,IN,RA104" "z004vyxa-a01" "RA133_G_HC-CoreOps-Admins"

#Check that the script is being run as root user
if ([ `id | cut -d"=" -f2 | cut -d"(" -f1` -ne 0 ]) then		
	logger "ERROR: [DJScript] This script needs to be run with root privileges. Please login as root and run this script again {Status code: 0fxdjcsru01}."
	exit 1
fi

logger "INFO: [DJScript] Script running with root privileges."

#Check that there are exactly 6 input parameters passed, if not, then exit
if [ $# -lt 6 ]
then
	logger "ERROR: [DJScript] Not all expected parameters have been passed: $@ {Status code: 0fxdjcspc01}."
	exit 1
fi

logger "INFO: [DJScript] Script running with following parameters: Domain=$1, OSP_ID=$2, OSP_PWD=#####, OU=$4, Admin_Accts=$5, Admin_Groups=$6."

DOMAIN="$1"
OSPID="$2"
OSPPWD="$3"
#OURA="$4"
#OURGN="$5"
NSTDOULST=`echo $4 | tr -d " "`
ADMINACCTS=`echo $5 | tr -d " "`
#ADMINGRP="RA133_G_ADM-MPCD-Admins@ad005.onehc.net"
ADMINGRP=`echo $6 | tr -d " "`
#OULVL1="Servers"
#OULVL2="_Central"
DCSERVER=$7

#Customization based on Region. Only specific regions should be allowed.
#AVLBLRGNS="ANZ ASE CHN EUW GWC JPE USE USW"

#if [[ ! " $AVLBLRGNS " =~ " $OURGN " ]]; then
#  logger "ERROR: [DJScript] $OURGN is not a valid region. Allowed regions are: $AVLBLRGNS {Status code: 0fxdjcsar01}."
#  exit 1
#fi

PSTFIX=`date '+%d%m%Y%H%M%S'`
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
	logger "ERROR: [DJScript] Installation of necessary packages for domain joining failed {Status code: 0fxdjcspi02}."
	exit 2
else
	logger "INFO: [DJScript] Installation of necessary packages for domain joining completed."
fi

#Check if IP Address was retrieved
if [ -n "$IPADDR" ]
then
	logger "INFO: [DJScript] IP Address of machine retrieved - $IPADDR"
else
	logger "ERROR: [DJScript] IP Address of the machine could not be retrieved {Status code: 0fxdjcsip03}."
	exit 3
fi

#Retrieve Hostname and FQDN
HOSTN=`hostname -f`

#Check if Hostname was correctly retrieved
if [ -n "$HOSTN" ]
then
	if [[ `echo "${HOSTN}" | grep -ic localhost` -gt 0 ]];then
		logger "ERROR: [DJScript] Calculated hostname evaluates to localhost {Status code: 0fxdjcshn04}."
		exit 4
	fi
	logger "INFO: [DJScript] Calculated hostname of machine evaluated - $HOSTN"
else
	logger "ERROR: [DJScript] Hostname of the machine could not be retrieved {Status code: 0fxdjcshn05}."
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
grep -q ^"domain $DMNLCS" /etc/resolv.conf || sed -i '/search reddog.microsoft.com/a\domain '"$DMNLCS"'' /etc/resolv.conf

#Add Host entries to host file of DC host name
grep -q ^$IPADDR /etc/hosts || sed -i '$s/$/\n'"$IPADDR $HOSTN $HOSTN.$DMNUCS"'/' /etc/hosts

#Check if host file update was successful
if [ $? -ne 0 ]
then
	logger "ERROR: [DJScript] Host file updates for domain joining failed {Status code: 0fxdjcshf06}."
	exit 6
else
	logger "INFO: [DJScript] Host file successfully updated for domain joining."
fi

if [ $# -eq 7 ]
then
	#Add domain controller <-- Check if this is required
	grep -q '^129.103.4.39' /etc/hosts || sed -i '$s/$/\n129.103.4.39 DEMCHAHC01A DEMCHAHC01A.ad005.onehc.net/' /etc/hosts
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
	logger "INFO: [DJScript] krb5 configuration update completed."
else
	logger "ERROR: [DJScript] krb5 config file not updated {Status code: 0fxdjcskb07}."
	exit 7
fi

#Leave realm if already joined
echo "$OSPPWD" | realm leave $DMNLCS -v
sleep 5


#Realm join using OSP ID and Password
if [ $# -eq 7 ]
then
	echo "$OSPPWD" | realm join --computer-ou="$OUFRMT,$DCFRMT" --user="$OSPID" DEMCHAHC01A.ad005.onehc.net -v
else
	echo "$OSPPWD" | realm join --computer-ou="$OUFRMT,$DCFRMT" --user="$OSPID" $DMNLCS -v
fi

#Check if realm join was successful
if [ $? -ne 0 ]
then
	logger "ERROR: [DJScript] Domain joining failed {Status code: 0fxdjcsdj08}."
	exit 8
else
	logger "INFO: [DJScript] Domain joining successful - $HOSTN,$OUFRMT,$DCFRMT"
fi

#Backup /etc/sssd/sssd.conf
cp -f /etc/sssd/sssd.conf /etc/sssd/sssd.conf_djbkp.$PSTFIX

#Re-create the file /etc/krb5.conf
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
if [ $# -eq 7 ]
then
	echo "ad_server = demchahc01a.ad005.onehc.net" >> /etc/sssd/sssd.conf
fi
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
echo "simple_allow_groups = $ADMINGRP" >> /etc/sssd/sssd.conf
echo "simple_allow_users = $ADMINACCTS" >> /etc/sssd/sssd.conf

#Check that /etc/sssd/sssd.conf is not zero byte
if [ -s /etc/sssd/sssd.conf ]
then
	logger "INFO: [DJScript] sssd configuration update completed."
else
	logger "ERROR: [DJScript] sssd config file not updated {Status code: 0fxdjcssd09}."
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
	logger "ERROR: [DJScript] sssd service restart post sssd config changes failed {Status code: 0fxdjcsdj10}."
	exit 10
else
	logger "INFO: [DJScript] sssd service restart post sssd config changes was successful."
fi

#Backup /etc/ssh/sshd_config
cp -f /etc/ssh/sshd_config /etc/ssh/sshd_config_djbkp.$PSTFIX

#change the Password authentication to Yes on the /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config

#Check PasswordAuthentication is set to yes in /etc/ssh/sshd_config file
if [ `grep ^PasswordAuthentication /etc/ssh/sshd_config | awk '{print $NF}' | grep -ic yes` -eq 1 ]
then
	logger "INFO: [DJScript] PasswordAuthentication is set to yes in sshd config file."
else
	logger "ERROR: [DJScript] PasswordAuthentication could not be set to yes in sshd config file {Status code: 0fxdjcssh11}."
	exit 11
fi

#Start the sssd service
systemctl restart sshd.service

#Check if sssd service restart was successful
if [ $? -ne 0 ]
then
	logger "ERROR: [DJScript] sshd service restart post sshd config changes failed  {Status code: 0fxdjcssh12}."	
	logger "INFO: [DJScript] Attempting to restore sshd file and restart sshd service. Please note that domain joining will fail even after this step."
	
	#Restore sshd file
	mv -f /etc/ssh/sshd_config_djbkp.$PSTFIX /etc/ssh/sshd_config
	
	#Start the sssd service
	systemctl restart sshd.service
	
	exit 12
else
	logger "INFO: [DJScript] sshd service restart post sshd config changes was successful."
fi

#TUSERID=`echo $ADMINACCTS | cut -d, -f1`

#Add admin accounts to sudoers group
for ADMINACCT in `echo $ADMINACCTS | tr "," " "`
do
	#Check if the domain admin account exists
	id $ADMINACCT

	if [ $? -ne 0 ]
	then
		logger "WARN: [DJScript] Account $ADMINACCT was not found {Status code: 0fxdjcsaa13}."
		logger "WARN: [DJScript] This account $ADMINACCT cannot be used to login to this machine. This doesn't stop the domain join script."
	else	
		if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]];then
			usermod -aG sudo $ADMINACCT
			
			#Test if the admin accounts were added to sudoers group
			if [ `grep ^sudo /etc/group | grep -ic $ADMINACCT` -eq 0 ]; then
				logger "WARN: [DJScript] Account $ADMINACCT is not added to sudoers group {Status code: 0fxdjcssg14}."
				logger "WARN: [DJScript] This account $ADMINACCT cannot be used to login to this machine. This doesn't stop the domain join script."				
			else
				logger "INFO: [DJScript] Account $ADMINACCT is added to sudoers group."
			fi
		else
			usermod -aG wheel $ADMINACCT
			
			#Test if the admin accounts were added to sudoers group
			if [ `grep ^wheel /etc/group | grep -ic $ADMINACCT` -eq 0 ]; then
				logger "WARN: [DJScript] Account $ADMINACCT is not added to sudoers group {Status code: 0fxdjcssg14}."
				logger "WARN: [DJScript] This account $ADMINACCT cannot be used to login to this machine. This doesn't stop the domain join script."
			else
				logger "INFO: [DJScript] Account $ADMINACCT is added to sudoers group."
			fi
		fi
	fi
done

#if [[ "$7" == "" ]]; then

#Create the script /etc/network/if-up.d/nsupdate.sh

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
echo '	echo "*********** THE SCRIPT HAS RUN SUCCESSFULLY. PLEASE CHECK MANUALLY IN CASE OF ISSUES. **********"' >> /etc/network/if-up.d/nsupdate.sh
echo '	logger "INFO: [DJScript] The nsupdate script ran successfully"' >> /etc/network/if-up.d/nsupdate.sh
echo 'else' >> /etc/network/if-up.d/nsupdate.sh
echo '	echo "!!!!!!!!!!! THE SCRIPT DID NOT RUN SUCCESSFULLY. PLEASE CHECK MANUALLY FOR ERRORS. !!!!!!!!!!"' >> /etc/network/if-up.d/nsupdate.sh
echo '	logger "ERROR: [DJScript] The nsupdate script did not run successfully"' >> /etc/network/if-up.d/nsupdate.sh
echo '	return 111' >> /etc/network/if-up.d/nsupdate.sh
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
echo '     	echo "*********** THE SCRIPT HAS BEEN SCHEDULED SUCCESSFULLY **********"' >> /etc/network/if-up.d/nsupdate.sh
echo '		logger "INFO: [DJScript] The nsupdate script was scheduled successfully"' >> /etc/network/if-up.d/nsupdate.sh
echo '  else' >> /etc/network/if-up.d/nsupdate.sh
echo '     	echo "!!!!!!!!!!! THE SCRIPT COULD NOT BE SCHEDULED SUCCESSFULLY !!!!!!!!!!"' >> /etc/network/if-up.d/nsupdate.sh
echo '		echo "Please check crontab and replace with temporary file at: /tmp/tempcrontab.tmp"' >> /etc/network/if-up.d/nsupdate.sh
echo '		logger "INFO: [DJScript] The nsupdate script could not be scheduled successfully"' >> /etc/network/if-up.d/nsupdate.sh
echo '		return 121' >> /etc/network/if-up.d/nsupdate.sh
echo '  fi' >> /etc/network/if-up.d/nsupdate.sh
echo '	set +f' >> /etc/network/if-up.d/nsupdate.sh
echo 'fi' >> /etc/network/if-up.d/nsupdate.sh
echo '' >> /etc/network/if-up.d/nsupdate.sh
echo '#Wait for 5 seconds and restart the network service' >> /etc/network/if-up.d/nsupdate.sh
echo 'sleep 5s' >> /etc/network/if-up.d/nsupdate.sh
#echo 'systemctl restart NetworkManager' >> /etc/network/if-up.d/nsupdate.sh
echo 'return 0' >> /etc/network/if-up.d/nsupdate.sh

#Check that /etc/network/if-up.d/nsupdate.sh is not zero byte
if [ -s /etc/network/if-up.d/nsupdate.sh ]
then
	logger "INFO: [DJScript] nsupdate script creation completed."
	
	#Change mode of the nsupdate file to 777
	chmod 777 /etc/network/if-up.d/nsupdate.sh
	
	#Execute the nsupdate script
	. /etc/network/if-up.d/nsupdate.sh
	
	RTNVAL=$?
	
	#Change the lines starting with return to exit to make the script standalone
	sed -i 's/return/exit/g' /etc/network/if-up.d/nsupdate.sh
	
	if [ $RTNVAL -eq 0 ]
	then
		logger "INFO: [DJScript] nsupdate script execution completed."		
	elif [ $RTNVAL -eq 111 ]
	then
		logger "ERROR: [DJScript] nsupdate script execution failed {Status code: 0fxdjcsnu16}."
		exit 16
	elif [ $RTNVAL -eq 121 ]
	then
		logger "ERROR: [DJScript] nsupdate script failed to be scheduled through crontab {Status code: 0fxdjcsnu17}."
		exit 17
	else
		logger "ERROR: [DJScript] nsupdate script execution failed due to some unknown error {Status code: 0fxdjcsnu18}."
		exit 18
	fi	
else
	logger "ERROR: [DJScript] nsupdate script creation failed {Status code: 0fxdjcsnu15}."
	exit 15
fi

#fi

#Script execution completed
logger "INFO: [DJScript] Domain join script execution completed."
exit 0