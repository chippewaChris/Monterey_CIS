#!/bin/zsh
###############################################################################
#                                                                             
# -                  CIS Benchmark Assessment Network Configurations EA                     
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
###############################################################################
file=$(ls -t /Library/Application\ Support/Security\ Audit | head -n 1)
log="/Library/Application Support/Security Audit/$file"
fail=$(grep ",4." "$log" | grep -c "FAIL" )
threshold=1 #user modifiable to allow for leniancy 

if [ $fail -ge $threshold ]; then
	echo "<result>FAIL</result>"
else
	echo "<result>PASS</result>"
fi