#!/bin/bash

################################################################################
# This script is used to create an A record in AD Domain Contorller            #
# This script adds the DNS entry for the specific hostname mapping with IP     #
#                                                                              #
# This script needs to be executed during domain joining                       #
#       as well as scheduled through cron job                                  #
#       to execute every Monday at 6AM server time                             #
#                                                                              #
# Author: Ashis Chakraborty                                                    #
#                                                                              #
#    To create the file under specific folder:                                 #
#           mkdir -p /etc/network/if-up.d                                      #
#           vi /etc/network/if-up.d/nsupdate.sh                                #
#           chmod 777 /etc/network/if-up.d/nsupdate.sh                         #
#                                                                              #
#    To manually create the schedule in crontab:                               #
#           crontab -e                                                         #
#           0 6 * * 1 /etc/network/if-up.d/nsupdate.sh 2>&1 /tmp/nsupdate.log  #
################################################################################

echo `date`

DOMAIN="example.com"

#Get the OS type
OS=`grep "^ID=" /etc/os-release |cut -d "=" -f2`

#Get the IP address based on OS type
if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]];then
	ipAddr=$(hostname -i)
else
	ipAddr=$(hostname -I)
fi

#Check if hostname already contains domain
if [[ `echo "${HOSTNAME}" | grep -c "${DOMAIN}"` -gt 0 ]];then
	HOSTNAME=`echo "${HOSTNAME}" | awk -F"." '{print $1}'`
fi

#Prepare the nsupdate configuration script
echo "server $DOMAIN" > /tmp/nsupdate.conf
echo "update delete ${HOSTNAME}.${DOMAIN} A" >> /tmp/nsupdate.conf
echo "update add ${HOSTNAME}.${DOMAIN} 3600 A ${ipAddr}" >> /tmp/nsupdate.conf
echo "send quit" >> /tmp/nsupdate.conf

#Initialize kerberos keys
kinit -k ${HOSTNAME}\$

#Execute the nsupdate command with the desired configuration script
nsupdate -gddd /tmp/nsupdate.conf

#Check exit status of nsupdate command
if [[ $? -eq 0 ]]; then
	echo '*********** THE NSUPDATE SCRIPT HAS COMPLETED SUCCESSFULLY **********'
else
	echo '!!!!!!!!!!! THE NSUPDATE SCRIPT DID NOT COMPLETE SUCCESSFULLY !!!!!!!!!!'
	exit 111
fi

#Create crontab entry, if not already present
if [[ $(crontab -l | egrep -v "^(#|$)" | grep -q 'nsupdate.sh'; echo $?) == 1 ]]; then
	set -f 	
	crontab -l > /tmp/tempcrontab.tmp
 	echo '0 6 * * 1 /etc/network/if-up.d/nsupdate.sh 2>&1 /tmp/nsupdate.log' >> /tmp/tempcrontab.tmp
 	cat /tmp/tempcrontab.tmp | crontab -
  	if [[ $? -eq 0 ]]; then
   		rm -f /tmp/tempcrontab.tmp
     	echo '*********** THE NSUPDATE SCRIPT HAS BEEN SCHEDULED SUCCESSFULLY **********'
     else
      	echo '!!!!!!!!!!! THE NSUPDATE SCRIPT COULD NOT BE SCHEDULED SUCCESSFULLY !!!!!!!!!!'
		echo 'Please check crontab and replace with temporary file at: /tmp/tempcrontab.tmp'
		exit 121
  	fi
	set +f
fi

#Wait for 5 seconds and restart the network service
sleep 5s
#systemctl restart NetworkManager