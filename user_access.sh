#!/bin/bash
set +x

#############################################################################################
# This script is used to create a new user and assign a random password to it               #
#                                                                                           #
#                                                                                           #
# Author: Ashis Chakraborty                                                                 #
#                                                                                           #
# Create Date: 12th Nov 2024                                                                #
# Update Log:                                                                               #
#       - <Date> | <Update Comments>                                                        #
#                                                                                           #
#                                                                                           #
#############################################################################################

#Function to display help
function help() {
	echo "Usage: $0 -u user_name [-l local_user] [-p password] [-g group_name] [-r request_number] [-n requestor_mail] [-d additional_comments] [-a] [-f pam_safe]"
	echo "-u: User name (comma-separated, required if no group is provided)"
	echo "-l: Local user for domain joined system (comma-separated, optional)"
	echo "-p: Password for the user(s) (optional)"
	echo "-g: User group name (comma-separated, optional)"
	echo "-r: Request number (optional)"
	echo "-n: Requestor name or mail ID (optional)"
	echo "-d: Request details - additional comments for user creation (optional)"
	echo "-a: Make user/group as Admin (optional)"
	echo "-f: PAM safe of user for onboarding to Cyberark (optional)"
	echo "-s: Suppress minor errors (optional, NOT RECOMMENDED)"
	exit 0
}

SCRIPTNAME=`basename $0`

#Function for logging
function log() {
	local message="$1"
	local level="${2:-ERROR}"  # Default log level is error

	timestamp=$(date +%Y-%m-%d_%H:%M:%S)
	formatted_message="${timestamp} - $level: [UserAccess] $message"

	echo "$formatted_message"
	#logger -t "$(basename $0)" -p "$level" "$formatted_message"
	logger -t "$SCRIPTNAME" -p "$level" "$formatted_message"
}

#Function to generate a random password
function genranpass() {
    local password_length=16
    tr -dc 'A-Za-z0-9!@#$%^&*()_+' < /dev/urandom | head -c $password_length
}

#Function to create unique list from provided random list
function createuniqlist() {
	local inputlist="$1"

	#Convert the list to an array
	IFS=',' read -r -a array <<< "$inputlist"

	#Use an associative array to track unique values
	declare -A unique

	#Loop through the array and add unique values to the associative array
	for item in "${array[@]}"; do
	    unique["$item"]=1
	done

	#Extract unique values into a new array
	unique_array=("${!unique[@]}")

	return $unique_array
}

#Check that the script is being run as root user
if ([ `id | cut -d"=" -f2 | cut -d"(" -f1` -ne 0 ]) then		
	log "This script needs to be run with root privileges. Please login as root and run this script again {Status code: 0fxuacsru01}."
	exit 1
fi

log "Script running with root privileges." "INFO"

USRNAME=
LCLUSR=
USRPASS=
GRPNAME=
REQNUM="(Not provided)"
REQRMAIL="(Not provided)"
REQRDTLS=""
MKADMIN=
USRSAFE=
SUPPERRS=
RANDOMPASS=""
REALMNAME=""
DOMAINJOINTAG=0

#Get parameters
while getopts ":hu:p:g:r:n:d:af:s" opt; do
	case $opt in
		h)
			help
			;;
		u)
			USRNAME="$OPTARG"
			;;
		l)
			LCLUSR="$OPTARG"
			;;
		p)
			USRPASS="$OPTARG"
			;;
		g)
			GRPNAME="$OPTARG"
			;;
		r)
			REQNUM="$OPTARG"
			;;
		n)
			REQRMAIL="$OPTARG"
			;;
		d)
			REQRDTLS="$OPTARG"
			;;
        a)
			MKADMIN=true
			;;
		f)
			USRSAFE="$OPTARG"
			;;
        s)
			SUPPERRS=true
			;;
		\?)
			log "Invalid option: -$OPTARG. Use -h for help. {Status code: 0fxuacsip01}."
			exit 1
			;;
		:)
			log "Option -$OPTARG requires an argument. Use -h for help. {Status code: 0fxuacspa01}."
			exit 1
			;;
	esac
done

#Check for mandatory arguments
if [ -z "$USRNAME" ] && [ -z "$GRPNAME" ]; then
	echo "$USRNAME" "$GRPNAME"
    log "Missing required arguments. Use -h for help. {Status code: 0fxuacspc01}."
	log "Provide at least one of -u or -g options along with required parameters to proceed." "INFO"
    exit 1
fi

if [ $SUPPERRS ]; then
	echo $SUPPERRS
	log "Caution: You have chosen to suppress minor errors! This option is not recommended as it may cause serious problems." "INFO"
fi

PSTFIX=`date '+%d%m%Y%H%M%S'`

#Convert comma-separated string to an array
USERNAMES=`createuniqlist "$USRNAME"`
GROUPNAMES=`createuniqlist "$GRPNAME"`
LOCALUSERS=`createuniqlist "$LCLUSR"`

#Check if multiple users as well as groups are provided
if [ ${#USERNAMES[@]} -gt 1 ] && [ ${#GROUPNAMES[@]} -gt 1 ]; then
	log "Caution: Multiple users and groups are provided. All users (${USERNAMES[@]}) will be added to all groups (${GROUPNAMES[@]})." "INFO"
fi

#Check if machine is domain joined
if [ `realm list | wc -l` -gt 0 ]; then
	DOMAINJOINTAG=1
	#Find the domain name
	REALMNAME=`realm list | grep realm-name | cut -d: -f2 | cut -d. -f1 | tr -d " "`
fi

#Check if group is requested
if [ -z "$GRPNAME" ]; then
	#If group name is not provided and system is not domain joined, create group same as username
	log "Group name has not been provided. Group(s) with name same as username(s) will be created." "INFO"
	GRPNAME="$USRNAME"
else
	#Add user name to the list of provided group names	
	GRPNAME="$GRPNAME,$USRNAME"
fi

#Loop for all provided groups
for GROUPNAME in "${GROUPNAMES[@]}"; do
	#Create group either based on provided group name or user name if group name is not provided
	if getent group "$GROUPNAME" > /dev/null 2>&1; then
		log "Group $GROUPNAME already exists. Ignoring." "INFO"
	#If group does not exist, create it
	else
		sudo groupadd "$GROUPNAME"
			#Check if the group was created
		if getent group "$GROUPNAME" > /dev/null 2>&1; then
			log "Local group $GROUPNAME has been successfully created." "INFO"
		else
			log "Local group $GROUPNAME could not be created {Status code: 0fxuagpct02}."
			if [ ! $SUPPERRS ]; then
				exit 2
			fi
		fi
	fi
done

#Check if user is requested, if yes then create or add else do nothing
if [ -z "$USRNAME" ]; then
	log "User name has not been provided. Not doing anything." "INFO"
else
	#Loop for all provided user names
	for USERNAME in "${USERNAMES[@]}"; do
		if id "$USERNAME" &>/dev/null; then
			log "User $USERNAME already exists." "INFO"
		#If user does not exist, create and add to all groups
		else
			#If username is part of the group names provided, remove it from the groups list else take the whole group list as secondary groups
           	SCNDRYGROUPS=$(echo "${GRPNAME//,/}" | sed "s/\b$USERNAME\b//g" | tr -s ' ' ',' | sed 's/^,//;s/,$//')

			#Logic to add comment to the new user if no comments are provided
			if [ -z "$REQRDTLS" ]; then
				if [ -z "$REQNUM" ]; then
					if [ -z "$REQRMAIL" ]; then
						REQRDTLS="Automated creation on $(date +%Y-%m-%d_%H:%M:%S)"
					else
						REQRDTLS="Automated creation on $(date +%Y-%m-%d_%H:%M:%S) by $REQRMAIL"
					fi
				else
					if [ -z "$REQRMAIL" ]; then
						REQRDTLS="Automated creation on $(date +%Y-%m-%d_%H:%M:%S) through $REQNUM"
					else
						REQRDTLS="Automated creation on $(date +%Y-%m-%d_%H:%M:%S) by $REQRMAIL through $REQNUM"
					fi					
				fi
			fi

			log "useradd -m -g $USERNAME -G $SCNDRYGROUPS -c \"$REQRDTLS\" $USERNAME" "INFO"
			#Create the user with provided user name and primary group as user name and secondary groups
			sudo useradd -m -g "$USERNAME" -G "$SCNDRYGROUPS" -c "$REQRDTLS" "$USERNAME" #Add logic to add requestor details

			#Check if the user was created
			if id "$USERNAME" &>/dev/null; then
				log "Local user $USERNAME has been successfully created with following comment: $REQRDTLS." "INFO"
			else
				log "Local user $USERNAME could not be created {Status code: 0fxuaurct03}."
				exit 3
			fi

			#Check if password is provided, else create random passowrd and assign
			if [ -z "$USRPASS" ]; then
				#Assign a random password
				USRPASS=$(genranpass)
			fi

			#Assign password to newly created user
			echo "$USERNAME:$USRPASS" | sudo chpasswd

			if [ $? -eq 0 ]; then
				log "Local user $USERNAME has been assigned a password: $USRPASS." "INFO"
			else
				log "Local user $USERNAME could not be assigned a password, assign one manually {Status code: 0fxuaurct04}."
				if [ ! $SUPPERRS ]; then
					exit 4
				fi
			fi
		fi
	done
fi

#Add logic to add group(s) as admin - users part of these groups will automatically inherit sudo access
if [ $MKADMIN ]; then

	#Take backup of sudoers file
	cp -f /etc/sudoers /etc/sudoers_djbkp.$PSTFIX
	if [ -f /etc/sudoers.d/djscript ]; then
		cp -f /etc/sudoers.d/djscript /etc/djscript-sudoers_djbkp.$PSTFIX
	fi

	for ADMINGRP in "${GROUPNAMES[@]}"; do

		if [ "$ADMINGRP" != "localusers" ]; then	#Find means to not consider localusers group
		
			getent group $ADMINGRP

			if [ $? -eq 0 ]; then
				log "Group $ADMINGRP found. Attempting to add to sudoers." "INFO"
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
						log "Some error occurred while trying to add Admin group $ADMINGRP to sudoers {Status code: 0fxuagrag05}."
						log "Reverting ALL changes to sudoers file. Faulty file: /tmp/djscript_djbkp.$PSTFIX.faulty" "INFO"
						cp /etc/sudoers.d/djscript /tmp/djscript_djbkp.$PSTFIX.faulty
						mv /etc/djscript-sudoers_djbkp.$PSTFIX /etc/sudoers.d/djscript
						if [ ! $SUPPERRS ]; then
							exit 5
						fi
					else
						log "Admin group $ADMINGRP added to sudoers." "INFO"
					fi
				fi
			else
				log "Admin group $ADMINGRP was not detected and cannot be used to login to this machine." "INFO"
			fi
		fi
	done
fi

log "Request successfully completed. Requested Users/Groups have been created and/or added as admin." "INFO"

exit 0