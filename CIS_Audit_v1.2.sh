#!/bin/zsh
###############################################################################
#                                                                             
#                                        
#                                                                             
# Copyright (C) Thursday, March 2, 2023, Chippewa Limited Liability Co.                                       
#                                                                             
# This script is the property of Chippewa Limited Liability Co. and is intended for internal     
# use only. This script may not be distributed, reproduced, or used in any    
# manner without the expressed written consent of Chippewa Limited Liability Co..                
#                                                                             
# This script is provided "AS IS" and WITHOUT WARRANTY OF ANY KIND,           
# EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED     
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.         
#                                                                             
# Permission is hereby granted to Parachute Inc..  Parachute Inc. may use this script    
# for the purpose of ascertaining posture of macOS clients  during the course of .
#                                                                             
###############################################################################
#sudo or root requirement
if [[ $(id -u) -ne 0 ]]; then
	echo "Please run as sudo or as root."
	exit 5
fi
###############################################################
################### Reporting Function ########################
###############################################################
start=$(date +%s)
file=/Library/Application\ Support/Security\ Audit/CIS_Report_$start.csv
##Reporting Function
function report() {
# Format the string to be appended to the CSV file
local message=$(printf '\n%s,%s,%s,%s' "$(date)" "$1" "$2" "$3")
# Append the formatted string to the CSV file
sudo printf '%s' "$message" >> $file
}
#Construct Report
if [ ! -d "/Library/Application\ Support/Security\ Audit" ]; then
	sudo mkdir "/Library/Application\ Support/Security\ Audit"
fi
sudo chown root:admin /Library/Application\ Support/Security\ Audit
sudo chmod 750 /Library/Application\ Support/Security\ Audit
sudo echo "Timestamp,Test,PASS/FAIL,Notes" > $file
###############################################################################
#Create password settings xml file for querying later. 
passwordXML=/Library/Application\ Support/Security\ Audit/passwordRequirements.xml
sudo /usr/bin/pwpolicy -getaccountpolicies | tail -n +2 > $passwordXML

###############################################################################
#1.1 Ensure All Apple-provided Software Is Current (Automated)
###############################################################################
last_successful_update=$(/usr/bin/sudo defaults read /Library/Preferences/com.apple.SoftwareUpdate | grep -e LastFullSuccessfulDate | awk '{print $3}' | tr -d '"')
if [[ $(date -j -f "%Y-%m-%d" "$last_successful_update" +"%s") -lt $(date -v-30d +%s) ]]; then
	report 1.1 FAIL
else
	report 1.1 PASS
fi 
###############################################################################
#1.2 Ensure Auto Update Is Enabled (Automated)
###############################################################################
automatic_check_enabled=$(/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('AutomaticCheckEnabled').js
EOS
)
if [ "$automatic_check_enabled" == "true" ]; then
	report 1.2 PASS
else
	report 1.2 FAIL
fi
###############################################################################
#1.3 Ensure Download New Updates When Available Is Enabled (Automated)
###############################################################################
automatic_download_enabled=$(/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('AutomaticDownload').js
EOS
)
if [ "$automatic_download_enabled" == "true" ]; then
	report 1.3 PASS
else
	report 1.3 FAIL
fi
###############################################################################
#1.4 Ensure Install of macOS Updates Is Enabled (Automated)
###############################################################################
automatically_install_macos_updates=$(/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate')\
.objectForKey('AutomaticallyInstallMacOSUpdates').js
EOS
)

if [ "$automatically_install_macos_updates" == "true" ]; then
	report 1.4 PASS
else
	report 1.4 FAIL
fi
###############################################################################
#1.5 Ensure Install Application Updates from the App Store Is Enabled (Automated)
###############################################################################
auto_update_enabled=$(/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
function run() {
	let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.commerce').objectForKey('AutoUpdate'));
	let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate').objectForKey('AutomaticallyInstallAppUpdates'));
	if (pref1 == 1 || pref2 == 1) {
		return "true";
	} else {
		return "false";
	}
}
EOS
)
			
if [ "$auto_update_enabled" == "true" ]; then
	report 1.5 PASS
else
	report 1.5 FAIL
fi
###############################################################################
#1.6 Ensure Install Security Responses and System Files Is Enabled (Automated)
###############################################################################
config_data_install_enabled=$(/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
function run() {
	let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate').objectForKey('ConfigDataInstall'));
	let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate').objectForKey('CriticalUpdateInstall'));
	if (pref1 == 1 && pref2 == 1) {
		return "true";
	} else {
		return "false";
	}
}
EOS
)
					
if [ "$config_data_install_enabled" == "true" ]; then
	report 1.6 PASS
else
	report 1.6 FAIL
fi
###############################################################################
#1.7 Ensure Software Update Deferment Is Less Than or Equal to 30 Days (Automated)
###############################################################################
enforced_update_delay=$(/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess')\
.objectForKey('enforcedSoftwareUpdateDelay').js
EOS
)
		
if [ -z "$enforced_update_delay" ] || [ "$enforced_update_delay" -le 30 ]; then
	report 1.7 PASS
else
	report 1.7 FAIL
fi
###############################################################################
#2.2.1 Ensure Firewall Is Enabled (Automated)
###############################################################################
firewall_enabled=$(/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
function run() {
	let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.alf').objectForKey('globalstate'));
	let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall').objectForKey('EnableFirewall'));
	if (pref1 == 1 || pref1 == 2 || pref2 == "true") {
		return "true";
	} else {
		return "false";
	}
}
EOS
)
					
if [ "$firewall_enabled" == "true" ]; then
	report 2.2.1 PASS
else
	report 2.2.1 FAIL
fi
###############################################################################
#2.2.2 Ensure Firewall Stealth Mode Is Enabled (Automated)
###############################################################################
stealth_mode_enabled=$(/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
function run() {
	let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.alf').objectForKey('stealthenabled'));
	let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall').objectForKey('EnableStealthMode'));
	if (pref1 == 1 || pref2 == "true") {
		return "true";
	} else {
		return "false";
	}
}
EOS
)
					
if [ "$stealth_mode_enabled" == "true" ]; then
	report 2.2.2 PASS
else
	report 2.2.2 FAIL
fi
###############################################################################
#2.3.1.1 Ensure AirDrop Is Disabled (Automated)
###############################################################################
for username in $(dscl . -list /Users | grep -v '_' | awk '$0 !~ "root|daemon|nobody|Guest" { print $1 }'); do
			disable_airdrop=$(/usr/bin/sudo -u "$username" /usr/bin/defaults read com.apple.NetworkBrowser DisableAirDrop 2>/dev/null)
			
if [ -z "$disable_airdrop" ]; then
	report 2.3.1.1 INCONCLUSIVE "for user $username"
	elif [ "$disable_airdrop" == "1" ]; then
		report 2.3.1.1 PASS "for user $username"
	else
		report 2.3.1.1 FAIL "for user $username"
	fi
done
###############################################################################
#2.3.1.2 Ensure AirPlay Receiver Is Disabled (Automated)
###############################################################################
for username in $(dscl . -list /Users | grep -v '_' | awk '$0 !~ "root|daemon|nobody|Guest" { print $1 }'); do
			airplay_receiver_enabled=$(/usr/bin/sudo -u "$username" /usr/bin/osascript -l JavaScript << EOS
	$.NSUserDefaults.alloc.initWithSuiteName('com.apple.controlcenter')\
	.objectForKey('AirplayRecieverEnabled').js
EOS
	)
			
			if [ "$airplay_receiver_enabled" == "true" ]; then
				report 2.3.1.2 PASS "for user $username"
			elif [ "$airplay_receiver_enabled" == "false" ]; then
				report 2.3.1.2 FAIL "for user $username"
			else
				report 2.3.1.2 INCONCLUSIVE "for user $username"
			fi
		done
###############################################################################
#2.3.2.1 Ensure Set Time and Date Automatically Is Enabled (Automated)
###############################################################################
using_network_time=$(/usr/bin/sudo /usr/sbin/systemsetup -getusingnetworktime | awk '{print $3}')
		
		if [ "$using_network_time" == "On" ]; then
			report 2.3.2.1 PASS
		else
			report 2.3.2.1 FAIL
		fi
###############################################################################
#2.3.2.2 Ensure Time Is Set Within Appropriate Limits (Automated)
###############################################################################
network_time_server=$(/usr/bin/sudo /usr/sbin/systemsetup -getnetworktimeserver | awk '/Network Time Server:/{print $NF}')
		
		sntp_output=$(/usr/bin/sudo /usr/bin/sntp $network_time_server | awk '{print$1}' | cut -c2-)
		
		if (( $(echo "$sntp_output <= 270 && $sntp_output >= -270" | bc -l) )); then
			report 2.3.2.2 PASS
		else
			report 2.3.2.2 FAIL
		fi
###############################################################################
#2.3.3.1 Ensure DVD or CD Sharing Is Disabled (Automated)
###############################################################################
odsa=$(/usr/bin/sudo /bin/launchctl list | grep -c com.apple.ODSAgent)
		
		if (( odsa == 0 )); then
			report 2.3.3.1 PASS
		else
			report 2.3.3.1 FAIL
		fi
###############################################################################
#2.3.3.2 Ensure Screen Sharing Is Disabled (Automated)
###############################################################################
screensharing=$(/usr/bin/sudo /bin/launchctl list | grep -c com.apple.screensharing)
		
		if (( screensharing == 0 )); then
			report 2.3.3.2 PASS
		else
			report 2.3.3.2 FAIL
		fi
###############################################################################
#2.3.3.3 Ensure File Sharing Is Disabled (Automated)
###############################################################################
smbd=$(/usr/bin/sudo /bin/launchctl list | grep -c "com.apple.smbd")
		
		if (( smbd == 0 )); then
			report 2.3.3.3 PASS
		else
			report 2.3.3.3 FAIL
		fi
###############################################################################
#2.3.3.4 Ensure Printer Sharing Is Disabled (Automated)
###############################################################################
printers_disabled=$(/usr/bin/sudo /usr/sbin/cupsctl | grep -c "_share_printers=0")
		
		if (( printers_disabled == 1 )); then
			report 2.3.3.4 PASS
		else
			report 2.3.3.4 FAIL
		fi
###############################################################################
#2.3.3.5 Ensure Remote Login Is Disabled (Automated)
###############################################################################
remote_login_enabled=$(/usr/bin/sudo /usr/sbin/systemsetup -getremotelogin | awk '{print $NF}')
		
		if [[ "$remote_login_enabled" == "Off" ]]; then
			report 2.3.3.5 PASS
		else
			report 2.3.3.5 FAIL
		fi
###############################################################################
#2.3.3.6 Ensure Remote Management Is Disabled (Automated)
###############################################################################
ps_output=$(/usr/bin/sudo /bin/ps -ef)
grep_output=$(echo "$ps_output" | /usr/bin/grep -e "[A]RDAgent")
		
		if [[ -n "$grep_output" ]]; then
			report 2.3.3.6 FAIL
		else
			report 2.3.3.6 PASS
		fi
###############################################################################
#2.3.3.7 Ensure Remote Apple Events Is Disabled (Automated)
###############################################################################
remote_apple_events=$(/usr/bin/sudo /usr/sbin/systemsetup -getremoteappleevents)
		
		if [[ "$remote_apple_events" == *"Off"* ]]; then
			report 2.3.3.7 PASS
		else
			report 2.3.3.7 FAIL
		fi
###############################################################################
#2.3.3.8 Ensure Internet Sharing Is Disabled (Automated)
###############################################################################
internet_sharing=$(/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')\
.objectForKey('forceInternetSharingOff').js
EOS
)
		if [[ "$internet_sharing" == "true" ]]; then
			report 2.3.3.8 PASS
		else
			report 2.3.3.8 FAIL
		fi
###############################################################################
#2.3.3.11 Ensure Bluetooth Sharing Is Disabled (Automated)
###############################################################################
for username in $(dscl . -list /Users UniqueID | awk '$2 >= 501 {print $1}'); do
			bluetooth_enabled=$(/usr/bin/sudo -u "$username" /usr/bin/defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled 2>/dev/null || echo "0")
			if [ "$bluetooth_enabled" -eq 0 ]; then
				report 2.3.3.11 PASS "for user $username"
			else
				report 2.3.3.11 FAIL "for user $username"
			fi
		done
###############################################################################
#2.3.4.2 Ensure Time Machine Volumes Are Encrypted If Time Machine Is Enabled (Automated)
###############################################################################
time_machine_status=$(sudo /usr/bin/defaults read /Library/Preferences/com.apple.TimeMachine.plist | grep -c NotEncrypted)
		
		if [[ $time_machine_status -eq 1 ]]; then
			report 2.3.4.2 PASS
		else
			report 2.3.4.2 FAIL
		fi
###############################################################################
#2.4.1 Ensure Show Wi-Fi status in Menu Bar Is Enabled (Automated)
###############################################################################
for username in $(ls /Users); do
			if [ "$username" == "Shared" ] || [ "$username" == "Guest" ]; then
				continue
			fi
			
			wifi_enabled=$(/usr/bin/sudo -u "$username" /usr/bin/defaults -currentHost read com.apple.controlcenter.plist WiFi 2>/dev/null)
			if [ "$wifi_enabled" == "1" ]; then
				report 2.4.1 PASS "for user $username"
			elif [ "$wifi_enabled" == "0" ]; then
				report 2.4.1 FAIL "for user $username"
			else
				report 2.4.1 INCONCLUSIVE "for user $username"
			fi
		done
###############################################################################
#2.4.2 Ensure Show Bluetooth Status in Menu Bar Is Enabled (Automated)
###############################################################################
#Note:  I believe 18 may be an incorrect value to be searching for... I think 
#       we'll get false negatives with the latest macOS ventura versions.  The 
#       on value appears to be 2, and the off value appears to be 8.
###############################################################################
# Get list of user accounts
		user_list=$(dscl . list /Users | grep -v '^_')
		
		# Loop through each user account
		for user in ${user_list}; do
			# Get the value of Bluetooth setting
			bluetooth_setting=$(/usr/bin/sudo -u ${user} /usr/bin/defaults -currentHost read com.apple.controlcenter.plist Bluetooth 2>/dev/null)
			
			# Check if the setting is equal to 18
			if [[ ${bluetooth_setting} -eq 18 ]]; then
				report 2.4.2 PASS "for user $user"
			elif [[ ${bluetooth_setting} -eq 2 || ${bluetooth_setting} -eq 8 ]]; then
				report 2.4.2 FAIL "for user $user"
			else
				report 2.4.2 INCONCLUSIVE "for user $user"
			fi
		done
###############################################################################
#2.5.1 Audit Siri Settings
###############################################################################
# Get list of all user accounts
		# Get list of users
		users=$(dscl . list /Users | grep -v '^_')
		
		# Initialize variable to track failures
		fail=0
		
		# Loop through users
		for user in $users; do
			# Check if Siri is enabled
			siri_result=$(/usr/bin/sudo -u $user /usr/bin/defaults read com.apple.Siri.plist 2>/dev/null | grep -c 'LockscreenEnabled = 1')
			
			# Check if Assistant is enabled
			assistant_result=$(/usr/bin/sudo -u $user /usr/bin/defaults read com.apple.assistant.support.plist 'Assistant Enabled' 2>/dev/null | grep -c '1')
			
			# If either result is non-zero, increment failure count
			if [ $siri_result -ne 0 ] || [ $assistant_result -ne 0 ]; then
				((fail++))
				report 2.5.1 FAIL "for user $username"
			fi
		done
		
		# If there were no failures, print success message
		if [ $fail -eq 0 ]; then
			report 2.5.1 PASS
		fi
###############################################################################
#2.6.3 Ensure Limit Ad Tracking Is Enabled (Automated)
###############################################################################
# Get list of all non-system users
		users=$(dscl . -list /Users | grep -v "^_" | grep -v "^daemon" | grep -v "^nobody" | grep -v "^root")
		
		# Set the preference key we're checking for in a variable
		pref_key="allowApplePersonalizedAdvertising"
		
		# Loop through each user and check the value of the preference key
		for user in $users; do
			pref_value=$(/usr/bin/sudo -u $user /usr/bin/defaults read /Users/$user/Library/Preferences/com.apple.AdLib.plist $pref_key 2>/dev/null)
			if [ "$pref_value" = "0" ]; then
				report 2.6.3 PASS "for user $user"
			elif [ "$pref_value" = "1" ]; then
				report 2.6.3 FAIL "for user $user"
			else
				report 2.6.3 INCONCLUSIVE "for user $user"
			fi
		done
###############################################################################
#2.6.4 Ensure Gatekeeper Is Enabled (Automated)
###############################################################################
spctl_status=$(/usr/bin/sudo /usr/sbin/spctl --status)
		if [ "$spctl_status" = "assessments enabled" ]; then
			report 2.6.4 PASS
		else
			report 2.6.4 FAIL
		fi
###############################################################################
#2.6.5 Ensure FileVault Is Enabled (Automated)
###############################################################################
Filevault=$(/usr/bin/sudo /usr/bin/fdesetup status 2>&1)
		
		if [[ "$Filevault" == "FileVault is On." ]]; then
			report 2.6.5 PASS
		else
			report 2.6.5 FAIL
		fi
###############################################################################
#2.6.7 Ensure an Administrator Password Is Required to Access System-Wide Preferences (Manual)
###############################################################################
AdminRequired=$(/usr/bin/sudo /usr/bin/security authorizationdb read system.preferences 2> /dev/null | grep -A1 shared | grep false)
		# Check if the result is empty
		if [ -z "$AdminRequired" ]; then
			report 2.6.7 FAIL
		else
			report 2.6.7 PASS
		fi
###############################################################################
#2.8.1 Audit Universal Control Settings (Manual)
###############################################################################
		dscl . -list /Users | grep -v "^_" | grep -v "^daemon" | grep -v "^nobody" | grep -v "^root" | while read user; do
			uc_disabled=$(/usr/bin/sudo -u "$user" /usr/bin/defaults -currentHost read com.apple.universalcontrol Disable 2> /dev/null)
			uc_magic_edges_disabled=$(/usr/bin/sudo -u "$user" /usr/bin/defaults -currentHost read com.apple.universalcontrol DisableMagicEdges 2> /dev/null)
			
			if [ "$uc_disabled" == "1" ] && [ "$uc_magic_edges_disabled" == "1" ]; then
				report 2.8.1 PASS "for user $user"
			else
				report 2.8.1 FAIL "for user $user"
			fi
		done
###############################################################################
#2.9.1 Ensure Power Nap Is Disabled for Intel Macs (Automated)
###############################################################################
powernap_enabled=$(/usr/bin/sudo /usr/bin/pmset -g custom | /usr/bin/grep -c 'powernap 1')
		
		if [ "$powernap_enabled" == "1" ]; then
			report 2.9.1 FAIL
		else
			report 2.9.1 PASS
		fi
###############################################################################
#2.9.2 Ensure Wake for Network Access Is Disabled (Automated)
###############################################################################
womp=($(sudo pmset -g custom | grep -o 'womp *[0-9]*'))
		
		if [ "${#womp[@]}" -eq 0 ]; then
			report 2.9.2 PASS
		elif [[ "${womp[@]}" =~ "1" ]]; then
			report 2.9.2 FAIL
		else
			report 2.9.2 PASS
		fi
###############################################################################
#2.10.1 Ensure an Inactivity Interval of 20 Minutes Or Less for the Screen Saver Is Enabled (Automated)
###############################################################################
users=("alyssa" "chris" "cohoon.io")
		
		# Loop through the users
		for user in "${users[@]}"
		do
			# Check if screensaver idle time is less than or equal to 1200 seconds (20 minutes)
			idle_time=$(/usr/bin/sudo -u "$user" /usr/bin/osascript -l JavaScript << EOS
function run() {
	let pref1 =
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver')
	.objectForKey('idleTime'))
	if ( pref1 <= 1200 ) {
		return("true")
	} else {
		return("false")
} }
EOS
)
						if [ "$idle_time" == "true" ]; then
							report 2.10.1 PASS "for user $users"
						else
							report 2.10.1 FAIL "for user $users"
						fi
						done
###############################################################################
#2.10.2 Ensure a Password is Required to Wake the Computer From Sleep or Screen Saver Is Enabled (Automated)
###############################################################################
passwordOnWake=$(/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
function run() { let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver').objectForKey('askForPassword')); let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver').objectForKey('askForPasswordDelay')); if (pref1 == 1 && pref2 <= 5) { return("true"); } else { return("false"); } }
EOS
)
				
				if [ "$passwordOnWake" == "true" ]; then
					report 2.10.2 PASS
				else
					report 2.10.2 FAIL
				fi
###############################################################################
#2.10.3 Ensure a Custom Message for the Login Screen Is Enabled (Automated)
###############################################################################
customMessage=$(/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
let loginWindowText = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow').objectForKey('LoginwindowText'));
if (loginWindowText == null) {
	console.log("null");
	$.exit(1);
} else {
	console.log(loginWindowText.js);
}
EOS
)

if [[ $result == "" ]]; then
	report 2.10.3 FAIL
else
	report 2.10.3 PASS
fi
###############################################################################
#2.10.4 Ensure Login Window Displays as Name and Password Is Enabled (Automated)
###############################################################################
nameAndPassword=$(/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('SHOWFULLNAME').js
EOS
)
	
	if [ "$result" == "true" ]; then
		report 2.10.4 PASS
	else
		report 2.10.4 FAIL
	fi
###############################################################################
#2.10.5 Ensure Show Password Hints Is Disabled (Automated)
###############################################################################
hint=$(sudo /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow')\
.objectForKey('RetriesUntilHint').js
EOS
)

if [[ -z "$hint" || "$hint" == "0" ]]; then
	report 2.10.5 PASS
else
	report 2.10.5 FAIL
fi
###############################################################################
#2.11.1 Ensure Users' Accounts Do Not Have a Password Hint (Automated)
###############################################################################
hints=$(/usr/bin/sudo /usr/bin/dscl . -list /Users hint)
	
	if [[ -z "$hints" ]]; then
		report 2.11.1 PASS
	else
		report 2.11.1 FAIL
	fi
###############################################################################
#2.11.2 Audit Touch ID and Wallet & Apple Pay Settings (Manual)
###############################################################################
report 2.11.2 INCONCLUSIVE No programatic method to verify
###############################################################################
#2.12.1 Ensure Guest Account Is Disabled (Automated)
###############################################################################
guest=$(/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
function run() {
	let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX').objectForKey('DisableGuestAccount'));
	let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow').objectForKey('GuestEnabled'));
	if (pref1 == 1 || pref2 == 0) {
		return("true");
	} else {
		return("false");
	}
}
EOS
)				
				if [[ "$guest" == "true" ]]; then
					report 2.12.1 PASS
				else
					report 2.12.1 FAIL
				fi
###############################################################################
#2.12.2 Ensure Guest Access to Shared Folders Is Disabled (Automated)
###############################################################################
smb_guest_access_disabled=$(/usr/bin/sudo /usr/sbin/sysadminctl -smbGuestAccess status 2> /dev/null | /usr/bin/grep -i 'SMB guest access disabled')
		
		if [[ -z $smb_guest_access_disabled ]]; then
			report 2.12.2 PASS
		else
			report 2.12.2 FAIL
		fi
###############################################################################
#2.12.3 Ensure Automatic Login Is Disabled (Automated)
###############################################################################
autoLogin=$(/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
function run() {
	let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow').objectForKey('com.apple.login.mcx.DisableAutoLoginClient'));
	let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow').objectForKey('autoLoginUser'));
	if ( pref1 == 1 || pref2 == null ) {
		return("true");
	} else {
		return("false");
	}
} 
EOS
)
					if [[ "$autoLogin" == "true" ]]; then
						report 2.12.3 PASS
					else
						report 2.12.3 FAIL
					fi
###############################################################################
#2.13.1 Audit Passwords System Preference Setting (Manual)
###############################################################################
report 2.13.1 INCONCLUSIVE No programatic method to verify
###############################################################################
#2.14.1 Audit Notification & Focus Settings (Manual)
###############################################################################
report 2.14.1 INCONCLUSIVE No programatic method to verify
###############################################################################
#3.1 Ensure Security Auditing Is Enabled (Automated)
###############################################################################
securityAudit=$(/usr/bin/sudo /bin/launchctl list | /usr/bin/grep -i auditd)
		
		if [ -z "$securityAudit" ]; then
			report 3.1 FAIL
		else
			status=$(echo "$securityAudit" | awk '{print $2}')
			process=$(echo "$securityAudit" | awk '{print $3}')
			if [ "$status" == "0" ] && [ "$process" == "com.apple.auditd" ]; then
				report 3.1 PASS
			else
				report 3.1 FAIL
			fi
		fi
###############################################################################
#3.3 Ensure install.log Is Retained for 365 or More Days and No Maximum Size (Automated)
###############################################################################
ttl_value=$(/usr/bin/sudo /usr/bin/grep -Eoi 'ttl=[0-9]{3,}' /etc/asl/com.apple.install)
max_file=$(/usr/bin/sudo /usr/bin/grep -i all_max= /etc/asl/com.apple.install)
		
		# Check if the ttl value is greater than or equal to 365
		if [[ -n $ttl_value ]] && (( $(echo "$ttl_value" | cut -d "=" -f2) >= 365 )) && [[ -z $max_file ]]; then
			report 3.3 PASS
		else
			report 3.3 FAIL
		fi
###############################################################################
#3.4 Ensure Security Auditing Retention Is Enabled (Automated)
###############################################################################
expire_after=$(/usr/bin/sudo /usr/bin/grep -e "^expire-after" /etc/security/audit_control | cut -d: -f2)
		
		if [[ $expire_after =~ .*[oO][rR].*[kKmMbBtTgG] ]] && [[ $expire_after =~ [6-9][0-9]|[1-9][0-9]{2,}|[1-9]G|[1-9][0-9]+[Mk] ]]; then
			report 3.4 PASS
		else
			report 3.4 FAIL
		fi
###############################################################################
#3.5 Ensure Access to Audit Records Is Controlled (Automated)
###############################################################################
dir_size_etc=$(sudo ls -n $(sudo grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | awk '{s+=$3} END {print s}')
file_size_etc=$(sudo ls -n $(sudo grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | awk '{s+=$4} END {print s}')
num_files_etc=$(sudo ls -l $(sudo grep '^dir' /etc/security/audit_control | awk -F: '{print $2}') | awk '!/-r--r-----|current|total/{print $1}' | wc -l | tr -d ' ')
dir_size_var=$(sudo ls -n $(sudo grep '^dir' /var/audit/ 2>/dev/null | awk -F: '{print $2}') 2>/dev/null | awk '{s+=$3} END {print s}')
file_size_var=$(sudo ls -n $(sudo grep '^dir' /var/audit/ 2>/dev/null | awk -F: '{print $2}') 2>/dev/null | awk '{s+=$4} END {print s}')
num_files_var=$(sudo ls -l $(sudo grep '^dir' /var/audit/ 2>/dev/null | awk -F: '{print $2}') 2>/dev/null | awk '!/-r--r----- |current|total/{print $1}' | wc -l | tr -d ' ')
# Sum up the values
total=$(($dir_size_etc + $file_size_etc + $num_files_etc + $dir_size_var + $file_size_var + $num_files_var))
		
# Check if the total is greater than 0
if [ $total -gt 0 ]
then
	report 3.5 Fail
else
	report 3.5 Pass
fi
###############################################################################
#3.6 Ensure Firewall Logging Is Enabled and Configured (Automated)
###############################################################################
firewall_logging=$(/usr/bin/sudo /usr/bin/osascript -l JavaScript << EOS
function run() {
	let pref1 =
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')\
	.objectForKey('EnableLogging').js
	let pref2 =
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')\
	.objectForKey('LoggingOption').js
	let pref3 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.alf')\
	.objectForKey('loggingenabled').js
	let pref4 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.alf')\
	.objectForKey('loggingoption').js
	if ( ( pref1 == true && pref2 == "detail" ) || ( pref3 == 1 && pref4 == 2 )
){
		return("true")
	} else {
		return("false")
	}
}
EOS
)
					
					# Verify the result
					if [[ "$firewall_logging" == "true" ]]; then
						report 3.6 Pass
					else
						report 3.6 Fail
					fi
###############################################################################
#4.2 Ensure HTTP Server Is Disabled (Automated)
###############################################################################
httpd=$(/usr/bin/sudo /bin/launchctl list | /usr/bin/grep -c "org.apache.httpd")

		if [ $httpd == 0 ]; then
			report 4.2 PASS
		else
			report 4.2 FAIL
		fi
###############################################################################
#4.3 Ensure NFS Server Is Disabled (Automated)
###############################################################################
nfs=$(/usr/bin/sudo /bin/launchctl list | /usr/bin/grep -c com.apple.nfsd)
		if [ $nfs == 0 ] || [ -f /etc/exports ]; then
			report 4.3 PASS
		else
			report 4.3 FAIL
		fi
###############################################################################
#5.1.1 Ensure Home Folders Are Secure (Automated)
###############################################################################
count=$(/usr/bin/sudo /usr/bin/find /Users -maxdepth 1 -type d -not -name '.' -exec /bin/ls -ld {} \; | /usr/bin/awk '{if ($1 ~ /^d.rwx------/ || $1 ~ /^d.rwx--x--x/) print $0}' | /usr/bin/wc -l | /usr/bin/tr -d ' ')
		if [ $count -gt 0 ]; then
			report 5.1.1 FAIL
		else
			report 5.1.1 PASS
		fi
###############################################################################
#5.1.2 Ensure System Integrity Protection Status (SIP) Is Enabled (Automated)
###############################################################################
sip=$(/usr/bin/sudo /usr/bin/csrutil status | awk '{print$5}' | sed 's/[^[:alpha:]]//g')

		if [ "$sip" == "enabled" ]; then
			report 5.1.2 PASS
		else
			report 5.1.2 FAIL
		fi
###############################################################################
#5.1.3 Ensure Apple Mobile File Integrity (AMFI) Is Enabled (Automated)
###############################################################################
amfi=$(/usr/bin/sudo /usr/sbin/nvram -p | /usr/bin/grep -c "amfi_get_out_of_my_way=1")
		
		if [[ $amfi -eq 0 ]]; then
			report 5.1.3 PASS
		elif [[ $amfi -eq 1 ]]; then
			report 5.1.3 FAIL
		else
			report 5.1.3 INCONCLUSIVE
		fi
###############################################################################
#5.1.4 Ensure Sealed System Volume (SSV) Is Enabled (Automated)
###############################################################################
authenticated_root_status=$(/usr/bin/sudo /usr/bin/csrutil authenticated-root status | awk '{print $NF}')
		
		if [[ "$authenticated_root_status" == "enabled" ]]; then
			report 5.1.4 PASS
		elif [[ "$authenticated_root_status" == "disabled" ]]; then
			report 5.1.4 FAIL
		else
			report 5.1.4 INCONCLUSIVE
		fi
###############################################################################
#5.1.5 Ensure Appropriate Permissions Are Enabled for System Wide Applications (Automated)
###############################################################################
world_writable_apps=$(/usr/bin/sudo /usr/bin/find /Applications -iname "*\.app" -type d -perm -2 -ls | /usr/bin/wc -l | /usr/bin/xargs)
		
		if [[ "$world_writable_apps" -eq 0 ]]; then
			report 5.1.5 PASS
		elif [[ "$world_writable_apps" -gt 0 ]]; then
			report 5.1.5 FAIL
		else
			report 5.1.5 INCONCLUSIVE
		fi
###############################################################################
#5.1.6 Ensure No World Writable Files Exist in the System Folder (Automated)
###############################################################################
world_writable_system_directories=$(/usr/bin/sudo /usr/bin/find /System/Volumes/Data/System -type d -perm -2 -ls | /usr/bin/grep -v "Drop Box" | /usr/bin/wc -l | /usr/bin/xargs)
		
		if [[ "$world_writable_system_directories" -eq 0 ]]; then
			report 5.1.6 PASS
		else
			report 5.1.6 FAIL
		fi
###############################################################################
#5.2.1 Ensure Password Account Lockout Threshold Is Configured (Automated)
###############################################################################
#		max_failed_auth=$( 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeMaximumFailedAuthentications"]/following-sibling::integer[1]/text()' -)
		
		if [[ "$max_failed_auth" == "" ]]; then
			report 5.2.1 FAIL "Configuration profile not installed for maximum failed authentication attempts"
		elif [[ "$max_failed_auth" -le 5 ]]; then
			report 5.2.1 PASS
		else
			report 5.2.1 FAIL "Maximum failed authentication attempts is greater than 5"
		fi
###############################################################################
#5.2.2 Ensure Password Minimum Length Is Configured (Automated)
###############################################################################
		minPassword=$(xmllint $passwordXML | grep -E 'Contain at least [0-9]+ characters\.' | sed 's/[^0-9]//g')
		if [ $minPassword -ge 15 ]; then
			report 5.2.2 PASS
		else
			report 5.2.2 FAIL
		fi
###############################################################################
#5.2.7 Ensure Password Age Is Configured (Automated)
###############################################################################
passExpiry=$(xmllint --xpath "//key[text()='policyAttributeExpiresEveryNDays']/following-sibling::integer[1]/text()" $passwordXML)

		if [ $passExpiry -ge 360 ]; then
			report 5.2.7 PASS
		else
			report 5.2.7 FAIL
		fi
###############################################################################
#5.2.8 Ensure Password History Is Configured (Automated)
###############################################################################
passHistory=$(xmllint --xpath "//*[contains(text(), 'Not be the same as the previous 15 passwords')]" $passwordXML | grep -E 'Not be the same as the previous [0-9]+ passwords\.' | sed 's/[^0-9]//g')
	
		if [ $passHistory -ge 15 ]; then
			report 5.2.8 PASS
		else
			report 5.2.8 FAIL
		fi
		
###############################################################################
#5.3.1 Ensure all user storage APFS volumes are encrypted (Manual)
###############################################################################
echo "check Jamf Pro for FV status"

###############################################################################
#5.3.2 Ensure all user storage CoreStorage volumes are encrypted (Manual)
###############################################################################
		# Run the command and save the output to a variable
		CoreStorage=$(/usr/bin/sudo /usr/sbin/diskutil cs list)
		
		# Check if the output contains "No CoreStorage logical volume groups found"
		if echo "$CoreStorage" | grep -q "No CoreStorage logical volume groups found"; then
			# Set the variable to true if the output contains the above string
			report 5.3.2 PASS
		else
			# Set the variable to false otherwise
			report 5.3.2 FAIL
		fi
###############################################################################
#5.4 Ensure the Sudo Timeout Period Is Set to Zero (Automated)
###############################################################################
sudoTimeout=$(/usr/bin/sudo /usr/bin/sudo -V | /usr/bin/grep -c "Authentication timestamp timeout: 0.0 minutes")
		
		# Check if the output is equal to 1 and report the result
		if [ "$output" == "1" ]; then
			report 5.4 PASS
		else
			report 5.4 FAIL
		fi
###############################################################################
#5.5 Ensure a Separate Timestamp Is Enabled for Each User/tty Combo (Automated)
###############################################################################
userTTY=$(/usr/bin/sudo /usr/bin/sudo -V | /usr/bin/grep -c "Type of authentication timestamp record: tty")
		
		# Check if the output is equal to 1 and report the result
		if [ "$userTTY" -eq 1 ]; then
			report 5.5 PASS
		else
			report 5.5 FAIL
		fi
###############################################################################
#5.6 Ensure the "root" Account Is Disabled (Automated)
###############################################################################
rootDisabled=$(/usr/bin/sudo /usr/bin/dscl . -read /Users/root AuthenticationAuthority 2>&1)
		
		# Check if the output contains the string "No such key: AuthenticationAuthority" and report the result
		if echo "$rootDisabled" | grep -q "No such key: AuthenticationAuthority"; then
			report 5.6 PASS
		else
			report 5.6 FAIL
		fi
###############################################################################
#5.7 Ensure an Administrator Account Cannot Login to Another User's Active and Locked Session (Automated)
###############################################################################
lockout=$(/usr/bin/sudo /usr/bin/security authorizationdb read system.login.screensaver 2>&1 | /usr/bin/grep -c 'use-login-window-ui')
		
		# Check if the output is equal to 0 and report the result
		if [ "$lockout" -eq 1 ]; then
			report 5.7 PASS
		else
			report 5.7 FAIL
		fi
###############################################################################
#5.9 Ensure Legacy EFI Is Valid and Updating (Automated)
###############################################################################
chipSet=$(/usr/bin/sudo /usr/sbin/sysctl -n machdep.cpu.brand_string)
		if [[  "$chipSet" == *"Apple"* ]]; then
			report 5.9 PASS
		else
			t2=$(/usr/bin/sudo /usr/sbin/system_profiler SPiBridgeDataType | grep "T2")
			if [[  "$t2" == "Model Name: Apple T2 Security Chip" ]]; then
				report 5.9 PASS
			else
				firmwareUpToDate=$(/usr/bin/sudo /usr/libexec/firmwarecheckers/eficheck/eficheck --integrity-check)
				if [[ "$firmwareUpToDate" == *"Primary allowlist version match found. No changes detected in primary hashes"* ]]; then
					running=$(/usr/bin/sudo /bin/launchctl list | /usr/bin/grep com.apple.driver.eficheck)
					if [[ "$running" == "Result: - 0 com.apple.driver.eficheck" ]]; then
						report 5.9 PASS
					else
						report 5.9 FAIL
					fi
				fi
			fi
		fi
###############################################################################
#5.10 Ensure the Guest Home Folder Does Not Exist (Automated)
###############################################################################
		if [ -d "/Users/Guest" ]; then
			report 5.10 FAIL
		else
			report 5.10 PASS
		fi
###############################################################################
#6.1.1 Ensure Show All Filename Extensions Setting is Enabled (Automated)
###############################################################################
users=$(dscl . -list /Users | grep -v "^_" | grep -v "^daemon" | grep -v "^nobody" | grep -v "^root")
		
		# Set the preference key we're checking for in a variable
		pref_key="AppleShowAllExtensions"
		
		# Loop through each user and check the value of the preference key
		for user in $users; do
			pref_value=$(/usr/bin/sudo -u $user /usr/bin/defaults read /Users/$user/Library/Preferences/.GlobalPreferences.plist $pref_key 2>/dev/null)
			if [ "$pref_value" = "1" ]; then
				report 6.1.1 PASS "for $user"
			else
				report 6.1.1 FAIL "for $user"
			fi
		done
###############################################################################
#6.3.1 Ensure Automatic Opening of Safe Files in Safari Is Disabled (Automated)
###############################################################################
users=$(dscl . -list /Users | grep -v "^_" | grep -v "^daemon" | grep -v "^nobody" | grep -v "^root")
		
		# Set the preference key we're checking for in a variable
		pref_key="AutoOpenSafeDownloads"
		
		# Loop through each user and check the value of the preference key
		for user in $users; do
			pref_value=$(/usr/bin/sudo -u $user /usr/bin/defaults read /Users/$user/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari $pref_key 2>/dev/null)
			if [ "$pref_value" = "1" ]; then
				report 6.3.1 FAIL "for $user"
			else
				report 6.3.1 PASS "for $user"
			fi
		done
###############################################################################
#6.3.3 Ensure Warn When Visiting A Fraudulent Website in Safari Is Enabled (Automated)
###############################################################################
		#need to research method to gather this... CIS Benchmark documentation is innacurate
###############################################################################
#6.3.6 Ensure Advertising Privacy Protection in Safari Is Enabled (Automated)
###############################################################################	
		#need to research method to gather this... CIS Benchmark documentation is innacurate
###############################################################################
#6.4.1 Ensure Secure Keyboard Entry Terminal.app Is Enabled (Automated)
###############################################################################
		users=$(dscl . -list /Users | grep -v "^_" | grep -v "^daemon" | grep -v "^nobody" | grep -v "^root")
		
		# Set the preference key we're checking for in a variable
		pref_key="SecureKeyboardEntry"
		
		# Loop through each user and check the value of the preference key
		for user in $users; do
			pref_value=$(/usr/bin/sudo -u $user /usr/bin/defaults read -app Terminal $pref_key 2>/dev/null)
			if [ "$pref_value" = "1" ]; then
				report 6.4.1 PASS "for user $user"
			elif [ "$pref_value" = "0" ]; then
				report 6.4.1 FAIL "for user $user"
			else
				report 6.4.1 INCONCLUSIVE "for user $user"
			fi
		done
###############################################################################

		
echo "File is located at $file"