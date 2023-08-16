#!/bin/bash

#Penetration Testing Project - Vulner
#Student Name : Samson Xiao
#Student Code : s30
#Class Code : cfc0202
#Lecturer : Kar Wei

sgtime=$(TZ=Asia/Singapore date +%FT%T)

function RESTART()
{
read -p 'Do you want to go to the start? [Y/N]?' restart
				echo ' '
				case $restart in
					y | Y | Yes | yes)
						echo 'Going to the top!'
						cd ..
						bash vulner.sh
					;;
					n | N | No | no)
						echo 'Oh well.. Exiting then! Byebye!'
						exit
					;;
				esac	
}

function BRUTEFORCE()
{
read -p "Do you want to specify a user and password list? [Y/N]" OPTION
echo ' '
	case $OPTION in
		Y|y)
			echo 'Please specify full path for user list'
			echo 'Example - /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt'
			read UserList
			echo ' '
			echo 'Please specify full path for password list.'
			echo 'Example - /usr/share/wordlists/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt'
			read PassList
			echo ' '
			echo 'Commencing Bruteforce in 3 seconds..'
			sleep 3
			sudo hydra -L $UserList -P $PassList $bruteforceIP $bruteforceSERVICE -o /var/log/VulnerScanLogs/$bruteforceIP/$bruteforceSERVICE.creds
		;;
		
		N|n)
			echo 'Using Default Userlist..'
			echo ' '
			read -p "Generate password list? [Y/N]" PASSWORD
			echo ' '
			case $PASSWORD in
				y | Y)
					echo 'Please choose minimum length of password'
					read passMin
					echo 'Please choose maximum length of password'
					read passMax
					echo 'Please type out chars, numbers or special chars to include in password'
					echo 'Example - 0123456789abcdefghijklmnop!@#$'
					echo 'Warning - a longer password list will take a longer time for attack to complete'
					read passChars
					echo 'Generating password list.'
					crunch $passMin $passMax $passChars > pass.lst
					echo ' '
					echo 'Commencing Bruteforce in 3 seconds..'
					sleep 3
					sudo hydra -L /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -P pass.lst $bruteforceIP $bruteforceSERVICE -o /var/log/VulnerScanLogs/$bruteforceIP/$bruteforceSERVICE.creds
				;;
				
				n | N)
					echo 'Using Default Password list'
					echo 'Commencing Bruteforce in 3 seconds..'
					sleep 3
					sudo hydra -L /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt $bruteforceIP $bruteforceSERVICE -o /var/log/VulnerScanLogs/$bruteforceIP/$bruteforceSERVICE.creds
				;;	
			esac
		;;
		esac

echo ' '		
echo 'Bruteforce complete. Results saved to /var/log/VulnerScanLogs/$bruteforceIP'
echo "$sgtime BruteForce completed." >> /var/log/VulnerScanLogs/Vulnscan.log
echo "$sgtime BruteForce results_saved_to /var/log/VulnerScanLogs/Credentials" >> /var/log/VulnerScanLogs/Vulnscan.log
}


sudo mkdir /var/log/VulnerScanLogs 2> /dev/null
echo 'Commencing Project Vulner in..'
echo '3..'
sleep 1
echo '2..'
sleep 1
echo '1..'
sleep 1
sudo touch /var/log/VulnerScanLogs/Vulnscan.log 2> /dev/null
sudo chmod 777 /var/log/VulnerScanLogs/Vulnscan.log 2> /dev/null
mkdir Vulners 2> /dev/null
cd Vulners 
echo ' '

read -p "Please select your usage for today.
1. Mapping LAN devices and Vuln Scans <RUN THIS FIRST for FIRST TIMER
2. Bruteforcing known devices from previous scans (Please do Options 1 before this.)
3. Display previous results (Obviously needs the previous 2 to be done for any results) " CHOICE
echo ' '
case $CHOICE in
	1)
		echo "Scanning LAN for live hosts.. This might take a while..."
		echo "$sgtime Scan Live_host_scan_started." >> /var/log/VulnerScanLogs/Vulnscan.log
		sudo touch hostip.txt
		sudo chmod 777 hostip.txt
		sudo ifconfig eth0 | grep -w inet | awk '{print $2}' > hostip.txt
		host=$(cat hostip.txt)
		sudo netdiscover -r $host -PN > livehosts.txt
		echo ' '
		
		ValidHostCheck=$(cat livehosts.txt | wc -l)
		if [ $ValidHostCheck -ge 1 ]
		then
			echo 'Live hosts found..'
			echo ' '
			cat livehosts.txt
		else
			echo 'Live hosts not found..'
			RESTART
			exit
		fi
		
		cat livehosts.txt | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' > IPtoEnum.txt
		foundhost=$(cat IPtoEnum.txt | wc -l)
		echo ' '
		echo "$foundhost live devices found"
		echo "$sgtime Detection $foundhost live_devices_found" >> /var/log/VulnerScanLogs/Vulnscan.log
		echo ' '
		sleep 5

		echo 'Enumerating live hosts..'
		echo 'This will take a while..'
		echo "$sgtime Enumeration started" >> /var/log/VulnerScanLogs/Vulnscan.log
		echo ' '
		
		for ip in $(cat IPtoEnum.txt)
		do
			echo "Scanning $ip for open ports.."
			sudo mkdir /var/log/VulnerScanLogs/$ip 2> /dev/null
			sudo nmap $ip -sV --open -p- -oN /var/log/VulnerScanLogs/$ip/Enumeration.txt -v0
			sudo chmod 755 /var/log/VulnerScanLogs/$ip/Enumeration.txt
			echo "Enumeration for $ip is done, results saved to /var/log/VulnerScanLogs/$ip"
			echo "$sgtime Enumeration $ip completed" >> /var/log/VulnerScanLogs/Vulnscan.log
			echo "$sgtime Enumeration results_saved_to /var/log/VulnerScanLogs/$ip" >> /var/log/VulnerScanLogs/Vulnscan.log
			echo ' '
		done
		
		echo ' '
		sleep 5
		echo 'Starting Vulnerabilities scan on all live hosts'
		echo 'This might take a while..'
		echo "$sgtime VulnScan started" >> /var/log/VulnerScanLogs/Vulnscan.log
		echo ' '
		
		for eachip in $(cat IPtoEnum.txt)
		do 
			echo "Scanning $eachip for vulnerabilities.."
			sudo nmap -sV --script vuln --open $eachip -oN /var/log/VulnerScanLogs/$eachip/Vulns.txt -v0
			sudo chmod 755 /var/log/VulnerScanLogs/$eachip/Vulns.txt
			echo "Vulnerabilities scan for $eachip is done, results saved to /var/log/VulnerScanLogs/$eachip"
			echo "$sgtime VulnScan $eachip completed" >> /var/log/VulnerScanLogs/Vulnscan.log
			echo "$sgtime VulnScan results_saved_to /var/log/VulnerScanLogs/$eachip" >> /var/log/VulnerScanLogs/Vulnscan.log
			echo ' '
	
		done
		
		echo ' '
		read -p 'Do you want to view Vulnerabilities scan results? [yes/no]?' VIEWVULN
		echo ' '
		case $VIEWVULN in
			y | Y | Yes | yes)
				echo 'Please choose from the following addresses to display results.'
				cat IPtoEnum.txt
				read ChosenIP
				echo "Displaying $ChosenIP vulnerabilities."
				echo ' '
				sleep 3
				cat /var/log/VulnerScanLogs/$ChosenIP/Vulns.txt
				echo ' '
				RESTART
	
			;;	
			n | N | No | no)
				echo 'LAN enumerations and vulnerabilities scans are completed.'
				echo 'All results are saved in /var/log/VulnerScanLogs'
				RESTART
			;;
			*)
				echo 'Invalid choice'
				echo ' '
				RESTART
			;;
		esac
	;;
	2)
		option1done=$(ls | grep IPtoEnum.txt | wc -l)
		if [ $option1done -ge 1 ]
		then
			echo 'Choose a host to bruteforce from list below'
			echo "$sgtime BruteForce started" >> /var/log/VulnerScanLogs/Vulnscan.log
			cat IPtoEnum.txt
			read chosenbruteforceIP
			
			validbruteIP=$(cat IPtoEnum.txt | grep -w $chosenbruteforceIP | wc -l)

			if [ $validbruteIP == 1 ]
			then
				echo 'Valid IP chosen'
				echo ' '
				bruteforceableIP=$(cat /var/log/VulnerScanLogs/$chosenbruteforceIP/Vulns.txt | grep open | grep -w "ftp\|rdp\|rlogin\|smb\|smtp\|ssh\|telnet" | wc -l)
				if [ $bruteforceableIP -ge 1 ]
				then
					echo "Bruteforceable services FOUND on $chosenbruteforceIP"
					bruteforceIP=$chosenbruteforceIP
					bruteforceSERVICE=$(cat /var/log/VulnerScanLogs/$chosenbruteforceIP/Vulns.txt | grep open | grep -w "ftp\|rdp\|rlogin\|smb\|smtp\|ssh\|telnet" | awk '{print $3}' | head -1)
					BRUTEFORCE
					echo ' '
					RESTART
				else
					echo "Bruteforceable services NOT FOUND on $chosenbruteforceIP"
					RESTART
				fi
			else
				echo 'Invalid IP chosen'
				RESTART
			fi
		else
			echo 'Told you to scan first right? Restarting Script.'
			echo ' '
			cd ..
			bash vulner.sh
		fi
		echo ' '
	;;
	3)
		echo 'Displaying known hosts..'
		sleep 2
		echo ' '
		cat IPtoEnum.txt
		echo ' '
		read -p "Please enter IP from list above to view results " enteredIP
		
		validIP=$(cat IPtoEnum.txt | grep -w $enteredIP | wc -l)
		
		if [ $validIP == 1 ]
		then
			validEnum=$(ls /var/log/VulnerScanLogs/$enteredIP | grep -w Enumeration.txt | wc -l)
			validVulnscan=$(ls /var/log/VulnerScanLogs/$enteredIP | grep -w Vulns.txt | wc -l)
			validBruteCred=$(ls /var/log/VulnerScanLogs/$enteredIP | grep .creds | wc -l)
			echo ' '
			echo 'Valid IP entered'
			read -p "
			1) Enumeration results
			2) Vulnerabilities scan results
			3) Bruteforce Credentials
			Please select option to proceed [1/2/3] " options
			echo ' '
				case $options in
					1)
						if [ $validEnum == 1 ]
						then
							echo "Displaying enumeration results for $enteredIP"
							cat /var/log/VulnerScanLogs/$enteredIP/Enumeration.txt
							echo ' '
							RESTART
						else
							echo 'No enumeration results found'
							echo 'Try scanning again.'
							echo ' '
							RESTART
						fi
					;;
					
					
					2)
						if [ $validVulnscan == 1 ]
						then
							echo "Displaying vulnerabilities for $enteredIP"
							cat /var/log/VulnerScanLogs/$enteredIP/Vulns.txt
							echo ' '
							RESTART
						else
							echo 'No vulnerabilities found'
							echo 'Try scanning again.'
							echo ' '
							RESTART
						fi
					;;
					
					3)
						if [ $validBruteCred -ge 1 ]
						then
							echo "Displaying bruteforce results for $enteredIP"
							echo ' '
							ls /var/log/VulnerScanLogs/$enteredIP | grep .creds
							read -p "
							Enter service's creds to view from list above.
							[ftp/rdp/rlogin/smb/smtp/ssh/telnet]" service
							echo ' '
							
							validService=$(ls /var/log/VulnerScanLogs/$enteredIP | grep -w $service | wc -l)
							
							
							if [ $validService == 1 ]
							then
								echo 'Valid service entered..'
								echo "Displaying $service Bruteforce credentials"
								echo ' '
								cat /var/log/VulnerScanLogs/$enteredIP/$service.creds
								echo ' '
								RESTART
							else
								echo ' '
								echo 'Invalid service entered..'
								echo ' '
								RESTART
							fi
						else
							echo 'No bruteforce results found'
							echo 'Try bruteforcing again.'
							echo ' '
							RESTART
						fi
					;;
					
					*)
						echo 'Invalid choice'
						echo ' '
						RESTART
					;;
				esac	
			
		else
			echo ' '
			echo 'Invalid IP entered'
			RESTART
		fi
		
	;;	
	
	*)
		echo 'Invalid choice'
		echo ' '
		RESTART
	;;
esac

#end of script
