#!/bin/bash
set +x

#############################################################################################
# This script is used to create a new user and assign a random password to user             #
# 	The script can also be used to create a local Linux group and/or add users to the group #
#	The script can also be used for adding a user or group to sudoers						#
#																							#
#       -performs pre-checks (script running as root, parameters passed)                    #
#       -check if system is domain joined                                                   #
#       -check if groups are requested, else add local groups to be created                 #
#       -create requested and required local groups, ignore for existing and AD groups      #
#       -create requested users, ignore for existing and AD users                           #
#       -assign password to newly created local user(s)				                        #
#       -add requested users to requested and required groups, ignore for AD groups         #
#       -add groups to sudoers so that users can inherit admin privileges                   #
#                                                                                           #
# Inputs:                                                                                   #
#       1. Comma separated list of Username(s) that need to be created (local only) or 		#
#			added (local or AD) to group (if group-names are provided)						#
#       2. Optional, Password that can be assigned to newly created local user(s)           #
#			Please note that if multiple local users are being requested to be created		#
#			same password will be assigned to all newly created local users					#
#       3. Optional if username provided, Group-name(s) that need to be created (local only)#
#			or that need to be added to sudoers	(both local group or AD group)				#
#			or to which user(s) (both local or AD) need to be added to						#
#       4. Optional, request number used to reques the user/group creation/addition			#
#       5. Optional, requestor mail ID												        #
#       6. Optional, request details - additional comments for user creation	            #
#       7. Optional, flag to make user/group as admin (default is no)                       #
#       8. Optional, PAM Safe of user where credentials would be stored                     #
#       9. Optional, flag to suppress minor errors (default is no)                          #
#                                                                                           #
# Output:                                                                                   #
#       Exit code based on failure (1-10) or success (0). Look below.                       #
#       All messages are written to syslog:                                                 #
#        - For RHEL: grep "UserAccess" /var/log/messages                                    #
#        - For Ubuntu: grep "UserAccess" /var/log/syslog                                    #
#                                                                                           #
#                                                                                           #
# Author: Ashis Chakraborty                                                                 #
#                                                                                           #
# Create Date: 27th Nov 2024                                                                #
# Update Log:                                                                               #
#       - 23rd Jan 2025 | Updated to include domain users and groups                        #
#                                                                                           #
#                                                                                           #
#############################################################################################
#########################################################################################################################################################################################
#	Exit code |  Status code   |		Description                                                                                                                             #
#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------#
#	1	  | 0fxuacsru01	   |	This script needs to be run with root privileges. Please login as root and run this script again. Use -h for help.                              #
#	2	  | 0fxuacsip02	   |	Invalid option provided in command line. Please provide valid options only. Use -h for help.                                                    #
#	2	  | 0fxuacspa02	   |	Option requires an argument. Please provide an argument to the specified option. Use -h for help.                                               #
#	2	  | 0fxuacspc02	   |	Missing required arguments. Provide all mandatory options and arguments. Use -h for help.                                                       #
#	3 (S)	  | 0fxuagpct03	   |	Local group could not be created.               							                                                                    #
#	4	  | 0fxuaurct04	   |	Local user could not be created.					                                                                                            #
#	5 (S)	  | 0fxuaurct05	   |	Local user could not be assigned a password.                                                                                                    #
#	6 (S)	  | 0fxuagpad06	   |	DJUSERS local group does not exist.                                                                                                 			#
#	7 (S)     | 0fxuagpad07	   |	LCLUSERS local group does not exist.                                                                                                			#
#	8 (S)	  | 0fxuagpad08	   |	AD user could not be added to local group.                                                                                                      #
#	9 (S)	  | 0fxuagpad09	   |	User could not be added to DJUSERS local group.                                                                                                 #
#	10 (S)	  | 0fxuagpad10	   |	User could not be added to LCLUSERS local group.                                                                                                #
#	11 (S)	  | 0fxuaadmg11	   |	Some error occurred while trying to add Admin group to sudoers. ALL changes made by script to sudoers file will be reverted. Check faulty file. #
#########################################################################################################################################################################################
#	(S) -> Minor error and can be suppressed. If not suppressed, script fails and exits at that error. To suppress minor errors, use flag -s (Not Recommended)                  #
#########################################################################################################################################################################################


#Function to display help
function help() {
	#echo "Usage: $0 -u user_name [-l local_user] [-p password] [-g group_name] [-r request_number] [-n requestor_mail] [-d additional_comments] [-a] [-f pam_safe] [-s]"
	echo "Usage: $0 -u user_name [-p password] [-g group_name] [-r request_number] [-n requestor_mail] [-d additional_comments] [-a] [-f pam_safe] [-s]"
	echo "-u: User name (comma-separated, required if no group is provided)"
	#echo "-l: Local user for domain joined system (comma-separated, optional)"
	echo "-p: Password for the user(s) (optional)"
	echo "-g: User group name (comma-separated, required if no user is provided)"
	echo "-r: Request number (optional)"
	echo "-n: Requestor mail ID (optional)"
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
function genrandpass() {
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

#Function to extract username before @
extract_before_at() {
    local username="$1"
    echo "${username%%@*}"
}

#Function to remove a value from the specified array by value
remove_value_from_array() {
    local array_name="$1"
    local value="$2"
    local temp_array=()
    local found=0

    # Use indirect referencing to access the array
    eval "local array=(\"\${${array_name}[@]}\")"

    for element in "${array[@]}"; do
        if [[ "$element" == "$value" ]]; then
            found=1
        else
            temp_array+=("$element")
        fi
    done

    # Update the original array with the new values
    eval "$array_name=(\"\${temp_array[@]}\")"

    if [[ $found -eq 1 ]]; then
        log "Value '$value' removed from $array_name." "INFO"
    else
        log "Value '$value' not found in $array_name." "INFO"
    fi
}

#Function to add a value to the specified array
add_value_to_array() {
    local array_name="$1"
    local value="$2"

    # Use indirect referencing to add the value to the array
    eval "$array_name+=(\"$value\")"
}

#Retrieve Hostname and FQDN
HOSTN=`hostname -f`

#Check that the script is being run as root user
if ([ `id | cut -d"=" -f2 | cut -d"(" -f1` -ne 0 ]) then		
	log "This script needs to be run with root privileges. Please login as root and run this script again {Status code: 0fxuacsru01}."
	exit 1
fi

log "Script running with root privileges." "INFO"

USRNAME=""
LCLUSR=""
USRPASS=""
GRPNAME=""
REQNUM=""
REQRMAIL=""
REQRDTLS=""
MKADMIN="false"
USRSAFE=""
SUPPERRS="false"
RANDOMPASS=""
REALMNAME=""
DOMAINJOINTAG=0
COLLATEDATA=0	#Only works for single new local user input. Incorrect output for multiple/domain/existing users.
ADMINGROUPS=()
DJUSERS=()
LCLUSERS=()

#Get parameters
#while getopts ":hu:l:p:g:r:n:d:af:s" opt; do
while getopts ":hu:p:g:r:n:d:af:s" opt; do
	case $opt in
		h)
			help
			;;
		u)
			USRNAME="$OPTARG"
			;;
		#l)
		#	LCLUSR="$OPTARG"
		#	;;
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
			MKADMIN="true"
			;;
		f)
			USRSAFE="$OPTARG"
			;;
        s)
			SUPPERRS="true"
			;;
		\?)
			log "Invalid option: -$OPTARG. Use -h for help. {Status code: 0fxuacsip02}."
			exit 2
			;;
		:)
			log "Option -$OPTARG requires an argument. Use -h for help. {Status code: 0fxuacspa02}."
			exit 2
			;;
	esac
done

#Check for mandatory arguments
if [ -z "$USRNAME" ] && [ -z "$GRPNAME" ]; then
	echo "$USRNAME" "$GRPNAME"
    log "Missing required arguments. Use -h for help. {Status code: 0fxuacspc02}."
	log "Provide at least one of -u or -g options along with required parameters to proceed." "INFO"
    exit 2
fi

if [ "$SUPPERRS" = "true" ]; then
	echo $SUPPERRS
	log "Caution: You have chosen to suppress minor errors! This option is not recommended as it may cause serious problems." "INFO"
fi

PSTFIX=`date '+%d%m%Y%H%M%S'`

#Check if machine is domain joined
if [ `realm list | wc -l` -gt 0 ]; then
	DOMAINJOINTAG=1
	#Find the domain name
	REALMNAME=`realm list | grep realm-name | cut -d: -f2 | cut -d. -f1 | tr -d " "`
	log "The system $HOSTN is added to domain $REALMNAME." "INFO"
else
	log "The system $HOSTN is not added to domain." "INFO"
fi

#Check if local group is requested
if [ -z "$GRPNAME" ]; then
	if [ $DOMAINJOINTAG -eq 0 ]; then
		#If group name is not provided and system is not domain joined, create group LCLUSERS
		log "Group name has not been provided. A new local group with name as LCLUSERS will be created." "INFO"
		GRPNAME="LCLUSERS"
	else
		#If group name is not provided and system is domain joined, create new group DJUSERS
		log "Group name has not been provided. Two new local groups with name as LCLUSERS and DJUSERS will be created." "INFO"
		GRPNAME="LCLUSERS,DJUSERS"
	fi
fi

#Convert comma-separated string to an array
USERNAMES=$(createuniqlist "$USRNAME")
GROUPNAMES=$(createuniqlist "$GRPNAME")
#LOCALUSERS=`createuniqlist "$LCLUSR"`

#log "Input users: (${USERNAMES[@]}) | Input groups: (${GROUPNAMES[@]})." "INFO"

#Check if multiple users as well as groups are provided
if [ ${#USERNAMES[@]} -gt 1 ] && [ ${#GROUPNAMES[@]} -gt 1 ]; then
	log "Caution: Multiple users and groups are provided. All users (${USERNAMES[@]}) might be added to all groups (${GROUPNAMES[@]})." "INFO"
else
	log "Input users: (${USERNAMES[@]}) | Input groups: (${GROUPNAMES[@]})." "INFO"
fi

#Loop for all provided groups
for GROUPNAME in "${GROUPNAMES[@]}"; do
	#Remove any domains from group name, if present
	GROUPNAME=$(extract_before_at "$GROUPNAME")
	log "Checking and/or creating group: $GROUPNAME" "INFO"
	
	if getent group "$GROUPNAME" > /dev/null 2>&1; then
		#Check if group already exists, then don't do anything
		log "Group $GROUPNAME already exists. Ignoring." "INFO"			
	else
		#If group does not exist, create local group
		#Create local group based on provided group name or user name if group name is not provided
		#Local group will also be created even if system is domain joined and provided group name is not found in AD

		log "Attempting to create group: $GROUPNAME." "INFO"
		sudo groupadd "$GROUPNAME"
		
		#Check if the group was created
		if getent group "$GROUPNAME" > /dev/null 2>&1; then
			log "Local group $GROUPNAME has been successfully created." "INFO"
		else
			log "Local group $GROUPNAME could not be created {Status code: 0fxuagpct03}."
			if [ "$SUPPERRS" = "false" ]; then
				exit 3
			fi
		fi
	fi
done

#Check if user is requested, if yes then create, else do nothing
if [ -z "$USRNAME" ]; then
	log "User name has not been provided. Not doing anything." "INFO"
else
	#Loop for all provided user names
	for USERNAME in "${USERNAMES[@]}"; do

		#Remove any domains from group name, if present
		USERNAME=$(extract_before_at "$USERNAME")
		log "Checking and/or creating user: $USERNAME" "INFO"

		#If user does not exist, create user
		if id "$USERNAME" &>/dev/null; then
			log "User $USERNAME already exists." "INFO"		
		else
			#If username is part of the group names provided, remove it from the groups list else take the whole group list as secondary groups
           	#SCNDRYGROUPS=$(echo "${GRPNAME//,/}" | sed "s/\b$USERNAME\b//g" | tr -s ' ' ',' | sed 's/^,//;s/,$//')

			log "Attempting to create user: $USERNAME." "INFO"

			#Logic to create entry with user details, credentials and PAM safe
			if [ $COLLATEDATA -eq 1 ]; then
				USRDTLS="Please find user details below:\n"
			fi

			#REQRMAIL=$(extract_before_at "$REQRMAIL")

			#Logic to add comment to the new user if no comments are provided
			if [ -z "$REQRDTLS" ]; then
				if [ -z "$REQNUM" ]; then
					if [ -z "$REQRMAIL" ]; then
						REQRDTLS="Automated creation on $(date +%Y-%m-%d_%H:%M:%S)"
					else
						REQRDTLS="Automated creation on $(date +%Y-%m-%d_%H:%M:%S) by $REQRMAIL"
						if [ $COLLATEDATA -eq 1 ]; then
							USRDTLS+="\nUser Name/Mail: $REQRMAIL"
						fi
					fi
				else
					if [ -z "$REQRMAIL" ]; then
						REQRDTLS="Automated creation on $(date +%Y-%m-%d_%H:%M:%S) through $REQNUM"
						if [ $COLLATEDATA -eq 1 ]; then
							USRDTLS+="\nRequest Number: $REQNUM"
						fi
					else
						REQRDTLS="Automated creation on $(date +%Y-%m-%d_%H:%M:%S) by $REQRMAIL through $REQNUM"
						if [ $COLLATEDATA -eq 1 ]; then
							USRDTLS+="\nUser Mail ID: $REQRMAIL"
							USRDTLS+="\nRequest Number: $REQNUM"
						fi
					fi					
				fi
			fi

			#log "useradd -m -g $USERNAME -G $SCNDRYGROUPS -c \"$REQRDTLS\" $USERNAME" "INFO"
			#Create the user with provided user name and primary group as user name and secondary groups
			#sudo useradd -m -g "$USERNAME" -G "$SCNDRYGROUPS" -c "$REQRDTLS" "$USERNAME" 

			#Create the user
			sudo useradd -m -c "$REQRDTLS" "$USERNAME"

			#Check if the user was created
			if id "$USERNAME" &>/dev/null; then
				log "Local user $USERNAME has been successfully created with following comment: $REQRDTLS." "INFO"
			else
				log "Local user $USERNAME could not be created {Status code: 0fxuaurct04}."
				exit 4
			fi

			#Check if password is provided, else create random passowrd and assign
			if [ -z "$USRPASS" ]; then
				log "User password is not provided, random password will be generated." "INFO"
				#Assign a random password
				USRPASS=$(genrandpass)
			fi

			#Assign password to newly created user
			echo "$USERNAME:$USRPASS" | sudo chpasswd

			if [ $? -eq 0 ]; then
				#log "Local user $USERNAME has been assigned a password: $USRPASS." "INFO"
				log "Local user $USERNAME has been assigned a password." "INFO"
			else
				log "Local user $USERNAME could not be assigned a password, assign one manually {Status code: 0fxuaurct05}."
				if [ "$SUPPERRS" = "false" ]; then
					exit 5
				fi
			fi

			if [ $COLLATEDATA -eq 1 ]; then
				USRDTLS+="\nUser ID: $USERNAME"
				USRDTLS+="\nUser Password: $USRPASS"
				USRDTLS+="\nUser PAM Safe: $USRSAFE"
			fi
		fi
	done
fi

#Logic to add user to group, if user is provided
if [ ! -z "$USRNAME" ]; then

	log "Attempting to add user(s) to group(s)." "INFO"

	#All users are added to all groups
	#If UID or GID is greater than 60000, then consider as domain joined user/group
	#Loop through all groups and users and create list of DJ groups
	#Based on DJ users or not, add to DJUSERS or LCLUSERS
	#Add DJUSERS and LCLUSERS to list of DJ Groups (if any)
	#If make admin, add groups to sudoers as admin

	remove_value_from_array "GROUPNAMES" "DJUSERS"
	remove_value_from_array "GROUPNAMES" "LCLUSERS"
	
	#Logic if array elements are not available, i.e. no groups were provided and only DJUSERS and/or LCLUSERS exist
	if [[ ${#GROUPNAMES[@]} -eq 0 ]]; then	
		#Loop for all users
		for USERNAME in "${USERNAMES[@]}"; do
			#Remove any domains from group name, if present
			USERNAME=$(extract_before_at "$USERNAME")

			if id "$USERNAME" &>/dev/null; then
			log "User $USERNAME exists, now checking if user is local or AD user." "INFO"

			#Extract user ID
			USERUID=`id -u $USERNAME`

			#Check if user is AD user or local and add to local groups lists accordingly
			if [ $USERUID -gt 60000 ]; then
				#User if AD user
				if getent group "DJUSERS" > /dev/null 2>&1; then
					log "User $USERNAME is an AD user, adding to local group DJUSERS." "INFO"								
					add_value_to_array "DJUSERS" "$USERUID"
				else
					log "Group DJUSERS does not exist. Cannot add $USERNAME to the group. {Status code: 0fxuagpad06}."
					if [ "$SUPPERRS" = "false" ]; then
						exit 6
					fi
				fi
			else
				#User is not AD user
				if getent group "LCLUSERS" > /dev/null 2>&1; then
					log "User $USERNAME is a local user, adding to local group LCLUSERS." "INFO"
					add_value_to_array "LCLUSERS" "$USERUID"
				else
					log "Group LCLUSERS does not exist. Cannot add $USERNAME to the group. {Status code: 0fxuagpad07}."
					if [ "$SUPPERRS" = "false" ]; then
						exit 7
					fi
				fi
			fi
		done
	else
		#Loop through all groups (if array elements are available)
		for GROUPNAME in "${GROUPNAMES[@]}"; do
			#Remove any domains from group name, if present
			GROUPNAME=$(extract_before_at "$GROUPNAME")

			#Check if group exists and is AD group
			if getent group "$GROUPNAME" > /dev/null 2>&1; then
				#Group exists, now check if AD group
				log "Group $GROUPNAME exists, now checking if group is AD group or local." "INFO"

				#Extract group ID
				GROUPGID=`getent group "$GROUPNAME" | cut -d: -f3`
				if [ $GROUPGID -gt 60000 ]; then
					#Group is AD group, add to admin group list for use later
					log "The group $GROUPNAME is an AD group. Can't add any users to this group through this script. Please contact your AD admin." "INFO"				
					add_value_to_array "ADMINGROUPS" "$GROUPNAME"
				else
					#Group is not AD group, hence considered as local group				
					#If user is AD user, add to given local group and DJUSERS, else add to given local group and LCLUSERS
					for USERNAME in "${USERNAMES[@]}"; do

						#Remove any domains from group name, if present
						USERNAME=$(extract_before_at "$USERNAME")

						if id "$USERNAME" &>/dev/null; then
							log "User $USERNAME exists, now checking if user is local or AD user." "INFO"

							#Extract user ID
							USERUID=`id -u $USERNAME`

							#Check if user is AD user or local and add to local groups lists accordingly
							if [ $USERUID -gt 60000 ]; then
								log "User $USERNAME is an AD user, adding to local group $GROUPNAME and local group DJUSERS list." "INFO"								
								add_value_to_array "DJUSERS" "$USERUID"
							else
								log "User $USERNAME is a local user, adding to local group $GROUPNAME and local group LCLUSERS list." "INFO"
								add_value_to_array "LCLUSERS" "$USERUID"
							fi

							#In any case, if the user exists then add to the specified group name
							sudo usermod -aG $GROUPNAME $USERNAME

							if [ $? -eq 0 ]; then
								log "AD user $USERNAME has been added to group $GROUPNAME." "INFO"
							else
								log "AD user $USERNAME could not be added to group $GROUPNAME. {Status code: 0fxuagpad08}."
								if [ "$SUPPERRS" = "false" ]; then
									exit 8
								fi
							fi
						else
							log "User $USERNAME does not exist. Not doing anything." "INFO"
						fi
					done
				fi
			else
				log "Group $GROUPNAME does not exist. Not doing anything." "INFO"
			fi
		done
	fi

	#Logic to add the users in the arrays to DJUSERS and LCLUSERS groups respectively

	#If the array DJUSERS is not empty and the local group DJUSERS exists
	if [[ ${#DJUSERS[@]} -ne 0 ]] && getent group DJUSERS > /dev/null 2>&1; then
		#Loop for all users in the array DJUSERS and add them to the group DJUSERS
		for DJUSER in "${DJUSERS[@]}"; do
			sudo usermod -aG DJUSERS $DJUSER
			# Check if the user was added to the group
			if id -nG "$DJUSER" | grep -qw "DJUSERS"; then
    			log "User $DJUSER was successfully added to the group DJUSERS." "INFO"
			else
    			log "Failed to add user $DJUSER to the group DJUSERS. {Status code: 0fxuagpad09}."
				if [ "$SUPPERRS" = "false" ]; then
					exit 9
				fi
			fi
		done
	fi

	#If the array LCLUSERS is not empty and the local group LCLUSERS exists
	if [[ ${#LCLUSERS[@]} -ne 0 ]] && getent group LCLUSERS > /dev/null 2>&1; then
		#Loop for all users in the array LCLUSERS and add them to the group LCLUSERS
		for LCLUSER in "${LCLUSERS[@]}"; do
			sudo usermod -aG LCLUSERS $LCLUSER
			# Check if the user was added to the group
			if id -nG "$LCLUSER" | grep -qw "LCLUSERS"; then
    			log "User $LCLUSER was successfully added to the group LCLUSERS." "INFO"
			else
    			log "Failed to add user $LCLUSER to the group LCLUSERS. {Status code: 0fxuagpad10}."
				if [ "$SUPPERRS" = "false" ]; then
					exit 10
				fi
			fi
		done
	fi
fi

#Ensure LCLUSERS and DJUSERS are in the ADMINGROUPS array
add_value_to_array "ADMINGROUPS" "LCLUSERS"
add_value_to_array "ADMINGROUPS" "DJUSERS"

if [ $COLLATEDATA -eq 1 ]; then
	USRDTLS+="\nGroups that user is member of: ${ADMINGROUPS[@]}"
fi

#Add logic to add group(s) as admin - users part of these groups will automatically inherit sudo access
if [ "$MKADMIN" = "true" ]; then

	#Take backup of sudoers file
	cp -f /etc/sudoers /etc/sudoers_djbkp.$PSTFIX
	if [ -f /etc/sudoers.d/djscript ]; then
		cp -f /etc/sudoers.d/djscript /etc/djscript-sudoers_djbkp.$PSTFIX
	fi

	for ADMINGRP in "${ADMINGROUPS[@]}"; do

		if [ "$ADMINGRP" != "localusers" ]; then	#Find means to not consider localusers group
		
			getent group $ADMINGRP	#Check if the group exists

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
						log "Some error occurred while trying to add Admin group $ADMINGRP to sudoers {Status code: 0fxuaadmg11}."						
						mv /etc/sudoers.d/djscript /tmp/djscript_djbkp.$PSTFIX.faulty
						if [ -f /etc/djscript-sudoers_djbkp.$PSTFIX ]; then
							mv /etc/djscript-sudoers_djbkp.$PSTFIX /etc/sudoers.d/djscript
						fi
						log "Reverting ALL changes to sudoers file(s). Faulty file: /tmp/djscript_djbkp.$PSTFIX.faulty" "INFO"
						if [ "$SUPPERRS" = "false" ]; then
							exit 11
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
	if [ $COLLATEDATA -eq 1 ]; then
		USRDTLS+="\nGroup(s) that user is part of are added as admin groups. Hence, user has inherited sudo access."
	fi
fi

if [ $COLLATEDATA -eq 1 ]; then
	echo -e $USRDTLS > /tmp/$USRDTLS.dat
	#Logic to send mail can be added here
fi

log "Request successfully completed. Requested Users/Groups have been created and/or added as admin." "INFO"

exit 0