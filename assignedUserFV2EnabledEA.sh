#!/bin/bash
#
# Author: Johan McGwire - Yohan @ Macadmins Slack - Johan@McGwire.tech
# Updated: James Purvis - jpu234 @ University of Kentucky - jpu234@uky.edu
#
# Description: This script Extension attribute reports if the assigned user in JAMF has a secureToken

url="https://https://draugr.sl.uky.edu:8443/"
client_id="facb5db2-9e61-4113-893a-b7f3811e6050"
client_secret="wvmGv9a3V5bS-J98Q_f51MGWtSU_EVc7IO-ZkIKLciGs-ztUX_wCAf3c8BWyQfqL"

getAccessToken() {
	response=$(curl --silent --location --request POST "${url}/api/oauth/token" \
 	 	--header "Content-Type: application/x-www-form-urlencoded" \
 		--data-urlencode "client_id=${client_id}" \
 		--data-urlencode "grant_type=client_credentials" \
 		--data-urlencode "client_secret=${client_secret}")
 	access_token=$(echo "$response" | plutil -extract access_token raw -)
 	token_expires_in=$(echo "$response" | plutil -extract expires_in raw -)
 	token_expiration_epoch=$(($current_epoch + $token_expires_in - 1))
}

checkTokenExpiration() {
 	current_epoch=$(date +%s)
    if [[ token_expiration_epoch -ge current_epoch ]]
    then
        echo "Token valid until the following epoch time: " "$token_expiration_epoch"
    else
        echo "No valid token available, getting new token"
        getAccessToken
    fi
}

invalidateToken() {
	responseCode=$(curl -w "%{http_code}" -H "Authorization: Bearer ${access_token}" $url/api/v1/auth/invalidate-token -X POST -s -o /dev/null)
	if [[ ${responseCode} == 204 ]]
	then
		echo "Token successfully invalidated"
		access_token=""
		token_expiration_epoch="0"
	elif [[ ${responseCode} == 401 ]]
	then
		echo "Token already invalid"
	else
		echo "An unknown error occurred invalidating the token"
	fi
}

checkTokenExpiration
curl -H "Authorization: Bearer $access_token" $url/api/v1/jamf-pro-version -X GET
checkTokenExpiration
#invalidateToken
#curl -H "Authorization: Bearer $access_token" $url/api/v1/jamf-pro-version -X GET


# Checking for the policy receipt
if [[ -f "/Library/Receipts/.AssignedUserGivenToken" ]]; then

    # If receipt exsits then there is no reason to go on, just report true
    echo "<result>True</result>"
    exit 0

# Check to see if some other method ended up with the user getting a secure token
else
    # Getting the serial number
    serialNum=$(ioreg -c IOPlatformExpertDevice -d 2 | awk -F\" '/IOPlatformSerialNumber/{print $(NF-1)}')

    # Getting the JAMF Assigned Username
    assignedUser=/usr/bin/curl -s -k -u "$API_USER:$API_PASSWORD" -X GET -H "accept: application/xml" "${url}JSSResource/computers/serialnumber/${serialNum}" | xmllint --xpath '//computer/location/username/text()' -
    # Making sure the assigned user is not null and in the secureTokenList
    if [[ "$assignedUser" != "" && ! $(sysadminctl -secureTokenStatus "$assignedUser" 2>&1 | grep -v "ENABLED") ]]; then
        echo "<result>True</result>"
    else
        echo "<result>False</result>"
    fi
fi

# Exiting with zero becuase it's an EA and I don't care about the return code
exit 0
