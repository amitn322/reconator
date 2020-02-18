#!/bin/bash
skip_ports=""
current_dir=`pwd`

enum_users="root user admin"
unknown_ports=""

BLACK="\033[30m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
PINK="\033[35m"
CYAN="\033[36m"
WHITE="\033[37m"
NORMAL="\033[0;39m"
#art

cat << "EOF"

 
  ____                            _             
 |  _ \ ___  ___ ___  _ __   __ _| |_ ___  _ __ 
 | |_) / _ \/ __/ _ \| '_ \ / _` | __/ _ \| '__|
 |  _ <  __/ (_| (_) | | | | (_| | || (_) | |   
 |_| \_\___|\___\___/|_| |_|\__,_|\__\___/|_|   
                                                

EOF


#Utility functions

function printOk()
{
	printf "$1: $GREEN $2 OK \n $NORMAL"
}

function printWarn()
{
	echo -e "$1: $YELLOW $2 WARNING\n $NORMAL"
}

function printError()
{
	echo -e "$1: $RED $2 FAIL \n $NORMAL"
}

function removeColorCodes()
{
	sed -i 's/\x1B\[[0-9;]\+[A-Za-z]//g' $1
}


function printHeader()
{
	printf "\n"
	printf "$BLUE"
	printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '|'
	printf "$RED"
	printf "$BLUE|$RED $1"
	printf "\n"
	printf "$BLUE"
	printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '|'
	printf "\n"
	printf "$NORMAL"

}


function subHeader() {
    echo -e "\n\n`tput setaf 3`[*] $1 `tput sgr0`"
}

function taskHeader() {
    echo -e "\n\n`tput setaf 5`[*] $1 `tput sgr0`"
}

function checkURLExists()
{
	checkURL=$1
	statusCode=`curl --output /dev/null  --write-out %{http_code} --silent --head --fail $checkURL`
	
	if [ $statusCode -eq 200 ];then
		printOk "$checkURL" "$statusCode"
		robotExists=yes
	else 
		printError "$checkURL" "$statusCode" 

	fi
	
}

function curlURL()
{
	#url => $1
	statusCode=`curl --output /dev/null  --write-out %{http_code} --silent --head --fail $1`
	if [ $statusCode -eq 200 ];then
		curl --silent $1
	else 
		printError "$checkURL" "${statusCode}"
	fi
	
}


function checkFTPUpload()
{	
	echo "ftp upload test" > ftptest.txt
	outputFile=${report_dir}/${openPort}.txt
	#$1=> username, $2=>password
	ftpLogin=`ftp -n $ftpServer <<SCRIPT
	user $1 $2
	
	put ftptest.txt
SCRIPT`
	subHeader "Checking anonymous ftp upload"
	
	
	echo $ftpLogin | grep -i 'fail\|not enough\|denied' 
	
	if [ $? -eq 0 ];then
		printError "Anonymous FTP Upload" 
	else 
		printOk "Anonymous FTP Upload"
	fi
	
	echo $ftpLogin 

}

#nmap

function NMAP()
{
    taskHeader "Running NMAP on $target"
	nmap -sT -sC -sV -PN -r -n -p- -T4 $1 -oA ${report_dir}/nmapOutput
    }
function PARSE_NMAP()
{
   grep -i open ${report_dir}/nmapOutput.gnmap | awk '{printf "%s\t", $2;
      for (i=4;i<=NF;i++) {
        split($i,a,"/");
        if (a[2]=="open") printf ",%s",a[1];}
      print ""}' | sed -e 's/,//' > ${report_dir}/openPorts.txt
    
    }

#enum 
function FTP() #21
{	
	outputFile=${report_dir}/${openPort}.txt
	taskHeader "Enumerating FTP: $target:$openPort"
	USER=anonymous
	PASSWD=anonymous
	ftpServer=$target
	subHeader "Checking Anonymous FTP Access"
	ftpLogin=`ftp -n $ftpServer <<SCRIPT
	user $USER $PASSWD
	quit
SCRIPT`
	
	
	echo $ftpLogin | grep -i 'failed' 
	
	if [ $? -eq 0 ];then
		echo $ftpLogin
		printError "Anonymous FTP Not Allowed" 
	else 
		echo $ftpLogin
		printOk "Anonymous FTP Allowed"
		
		checkFTPUpload $USER $PASSWD
	fi
	
	#nmap -p ${openPort} --script=*ftp* ${target} -oN ${outputFile} --append-output
}

function SSH() #22
{
	outputFile=${report_dir}/${openPort}.txt
	#nmap -p ${openPort} --script=*ssh* ${target} -oN ${outputFile} --append-output
	echo "Please follow SSH Checklist" | tee -a $outputFile

}

function TELNET() #23
{
	outputFile=${report_dir}/${openPort}.txt
	echo "Grabbing Telnet Banner" | tee -a $outputFile
	echo "" | nc -nv -w1 $targetIP 23 | tee -a $outputFile
	#nmap -p ${openPort} --script=*telnet* ${target} -oN ${outputFile} --append-output
	echo "Try Default Credentials" | tee -a $outputFile
	echo "Try usernames and passwords from other sources" | tee -a $outputFile
}

function SMTP() #25
{
	outputFile=${report_dir}/${openPort}.txt
	taskHeader "Enumerating SMTP"
	for user in $enum_users;do
		smtp-user-enum -M VRFY -u $user -t $target | tee -a $outputFile
	done 
	
	echo "Grabbing Banner" | tee -a $outputFile
	echo "" | nc -nv -w1 $targetIP 25 | tee -a $outputFile
	#nmap -p ${openPort} --script=*smtp* ${target} -oN ${outputFile} --append-output
}

function WEB() #80,443
{
	
	outputFile=${report_dir}/${openPort}.txt
	if [ $openPort -eq 443 ];then 
		url="https://${targetIP}:${openPort}"
		subHeader "Port 443, so checking SSL" 
		sslscan ${target}:${openPort} | tee -a $outputFile
	else 
		url="http://${target}:${openPort}"
	fi
	
	robotsURL=$url/robots.txt
	
	taskHeader "Enumerating Web Server: $target:$openPort"

	robotsContent=`curlURL $robotsURL`
	
	
	
	checkURLExists "${robotsURL}"
	
	if [ "$robotExists" == 'yes' ];then
		echo  "Contents of Robots.txt \n $robotsContent" | tee -a $outputFile
		subHeader "You might want to access these urls and Check !"
		printOk "Directories found in robots.txt file"
		subHeader "Running dirb against directories found in robots.txt"
		for folder in `echo "$robotsContent" | grep -v ENUMERROR | grep -iv 'user-agent'| awk {'print $2'}`;do
			dirb ${url}${folder} /usr/share/wordlists/dirb/common.txt -o ${report_dir}/dirbOutput.txt
			wpcheck=`echo $folder | grep -i wordpress`
			wpcheck2=`curl ${url}${folder}/wp-login.php --silent | grep -io username`
			
			echo $wpcheck $wpcheck2 | grep -i 'wordpress\|username' 
			
			if [ $? -eq 0 ];then 
				printf " $CYAN Looks like wordpress, enumerating Wordpress at ${url}${folder}\n"
				wpscan --url ${url}${folder} -e vpt,u --disable-tls-checks | tee -a ${report_dir}/wpscan.txt
			fi

		done
	else 
		printError "${robotsURL}" >> $outputFile 
	fi
	
	subHeader "Running dirb against: $target:$openPort"
	dirb ${url} /usr/share/wordlists/dirb/common.txt -o ${report_dir}/dirbOutput.txt
	subHeader "Running Nikto against: $target:$openPort"
    nikto -h ${url} -o ${report_dir}/niktoOutput.txt
	
	subHeader "Checking HTTP Allowed Methods"
	curl -v -X OPTIONS $url --silent | tee -a $outputFile
	#nmap -p ${openPort} --script=*http* ${target} -oN ${outputFile} --append-output
	
	echo "Make sure to check source of the pages for any clue" | tee -a $outputFile

	
    }

function POP() #110
{
	outputFile=${report_dir}
	#nmap -p ${openPort} --script=*pop3* ${target} -oN ${outputFile} --append-output
}
	
function RPCBIND() #111
{
	outputFile=${report_dir}/${openPort}.txt
	subHeader "Running RPC Client"
	rpcclient -U "" $target -c netshareenumall;netsharegetinfo;enumdomusers;getdompwinfo;srvinfo | tee -a $outputFile
	rpcinfo -p $target | tee -a $outputFile
	#nmap -p ${openPort} --script=*rpc* ${target} -oN ${outputFile} --append-output
	
}

function MSRPC() #135
{	
	outputFile=${report_dir}/${openPort}.txt
	print "Try RPC DCOM Exploit - ms03_026_dcom, 67.c ? " | tee -a $outputFile
	#nmap -p ${openPort} --script=*rpc* ${target} -oN ${outputFile} --append-output
}

function SAMBA() #139,445
{
	outputFile=${report_dir}/${openPort}.txt
	subHeader "Running Samba Enum"
	smbOut=${report_dir}/smb.txt 

	smbclient -L $target -N | tee -a $outputFile
	nmblookup -A $target | tee -a $outputFile
	enum4linux -a $target > ${report_dir}/enum4linux.txt 
	#nmap -p ${openPort} --script=*smb* ${target} -oN ${outputFile} --append-output
}

function NFS() #2049
{
	outputFile=${report_dir}/${openPort}.txt
	taskHeader "Enumerating NFS: $target:$openPort"
	showmount -e $target | tee -a $outputFile
}

function RDP() #3389
{
	outputFile=${report_dir}/${openPort}.txt
	#nmap -p ${openPort} --script=*rdp* ${target} -oN ${outputFile} --append-output
}





function ENUM_PORT()
{
    case $2 in 
		
		"21")
			FTP
			;;
		"22")
			SSH
			;;
		"23")
			TELNET
			;;
		"25")
			SMTP
			;;
		"80" | "443" | "8080")
			WEB #$1 $2
			;;
		# "110")
			# POP
			# ;;
		"111")
			RPCBIND
			;;
		# "135")
			# MSRPC
			# ;;
		"139" | "445")
			SAMBA
			;;
		# "161" | "162" )
			# SNMP
			# ;;
		
		*)
			echo -e "Please perform manual investigation for port $RED $2 $NORMAL"
			;;
	esac		
    }

#script start 

if [ -z $1 ];then
	echo "Usage $0 <ipaddress>"
	echo "Multiple IP addresses can be separated by space"
	exit 1
fi

printf "Version: $GREEN 1.0 $NORMAL \n\n\n"
printf "Author: $GREEN Amit! $NORMAL \n\n\n"
printf "$RED Legal Disclaimer:$GREEN This script is built for educational and authorized enumeration purposes. Do not use this for illegal purposes."

output_dir="${current_dir}/reconator"
if [ -d "$output_dir" ];then
	printOk "Report Directory $output_dir"
else 
	printError "Report Directory $output_dir"
	mkdir ${output_dir}
	printOk "Create Report Directory $output_dir"
	
fi 

####TESTING####
# target=192.168.44.150
# openPorts="80 21"
# for port in $openPorts;do
	# ENUM_PORT $target $port
# done
# exit

############


for target in "$@"
    do
        printHeader "Processing target: ${target} `date`"
		report_dir="${output_dir}/${target}"
		printOk "Creating Ouptut Directory $report_dir for target ${target}"
		mkdir $report_dir
        NMAP $target        
        PARSE_NMAP $target        
        openPorts=`awk {'print $2'} ${report_dir}/openPorts.txt | sed "s/,/ /g"`
		subHeader "Starting Service Enumeration for Open Ports: $openPorts"
        for openPort in $openPorts;do
            case "$openPort" in
                "21" | "22" | "23" | "25" | "53" | "69" | "80" | "443"  | "110" | "111" | "135" | "139" | "445" | "161" | "162" | "1443" | "1521" | "2049" | "2100" | "3306" | "3339" | "3389")
             
					ENUM_PORT $target $openPort
                    ;;
                *)
      
					unknown_ports="${unknown_ports} ${openPort}"
                    ;;
            esac
        done
    done


subHeader "$RED These are unknown ports, that require manual investigation$NORMAL"
echo $unknown_ports
