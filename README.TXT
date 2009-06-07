
##################################################################################
#					        			 	 #
#  					        				 # 
#  			WEPBuster 1.0                				 #
#					        				 #
#					        				 #
#  Author: Mark Jayson Alvarez	                				 #
#  Date Started: April 2009 		        				 #
#										 #
#										 #
#										 #
#  DESCRIPTION:									 #
#									       	 #
#  This small utility was written for Information Security Professionals to    	 #
#  aid in conducting Wireless Security Assessment. The program executes        	 #
#  various utilities included in the aircrack-ng suite, a set of tools for     	 #
#  auditing wireless networks, in order to obtain the WEP encryption key of	 #
#  a wireless access point. aircrack-ng can be obtained from 			 #
#  http://www.aircrack-ng.org 							 #
#									         #
#   									       	 #
#  OUTPUT: (owned.txt)								 #
#										 #
#      BSSID           CHANNEL  SSID	       KEY	      TIMESTAMP	 	 #
#  										 #
#  00:21:29:7D:5E:EB === 11 === Zakhal === 08:6D:38:15:30 === 1243883642         #
#  00:12:29:1D:E1:B3 === 1 === amnah === 68:28:1a:3c:20 === 1243883642           #
#										 #
#										 #
#  USAGE:				        				 #
#									         #
#  perl wepbuster [channel/s] (or any combination, space separated )\n"; 	 #
#  perl wepbuster (sort | connect) [HOST | IP]  (Defaults to: gateway)\n";     	 #
#										 #
#										 #
#  Typically, one would invoke the program without any arguments. Doing this	 #
#  will set the mode to 'crack' and will try to crack all wep-enabled access     #
#  points within the range on each of those non-overlapping channels depending   #
#  on which country was specified (1, 6, 11 for US) and (1, 5, 9, 13 for EU)     #
#										 #
#  Given an argument of numbers, mode will be set to 'crack' and will crack all  #
#  APs on those particular channel/s specified.		 			 #
#										 #
#  If passed with a 'sort' argument, followed by an optional IP address or a     #
#  hostname, the program will try to sort the list of cracked access points 	 #
#  (obtained after running 'crack' mode) in the order of increasing ping round	 #
#  trip time to the gateway or to the IP address or hostname specified.		 #
#										 #
#  If passed with a 'connect' argument, followed by an optional IP address or a  #
#  hostname, the program will try to connect to each access point included in    # 
#  in the list of cracked access points. The program exits once connection is    #
#  verified, e.g, if it can successfully ping the gateway or the IP address or   #
#  hostname specified. 								 #
#  										 #
#										 # 
#										 #
#  RECOMMENDED MODIFICATIONS:							 #
#										 #
#  The following modifications to the source and header file of the two	       	 #
#  aircrack-ng utilities (aircrack-ng, airodump-ng), are not required but will   #
#  make the decryption of WEP key more accurate (in terms of number of IVs       #
#  needed in order to obtain the key.						 #
#										 #
#										 #
#  1.) Instead of 5000, change PTW_TRY_STEP to 100 to make cracking more	 # 
#    accurate (in terms of number of IVs needed to crack the key)		 #
#										 #
#    Look for this line below in "aircrack-ng.h" 				 #
#    PTW_TRY_STEP  #5000   							 #
#										 #
#										 #
#  2.) The script relies heavily on reading and parsing the .csv file output of  #
#    airodump-ng. As such, instead of airodump-ng waiting for 20 seconds before  #
#    writing the .csv text output, it is recommended that you make it 2 seconds. #
#    If not changing this line below, you should set $airodumpwait and $scan_dur #
#    ration to at least more than 20 to avoid getting errors. A value of 23      #
#    should be safe.	 							 #
#										 #
#    Look for this line below in "airodump-ng.c"				 #
#    if( time( NULL ) - tt1 >= 20)  						 #
#										 #
#										 #
#  REQUIRED PERL MODULES:							 #
#										 #
#  The only module used in this script is the module "Term::ReadKey". This 	 #
#  module is used when when the 'Enter' key is pressed, e.g, if the user wants   #
#  to skip injecting into a particular Access Point. This module can be		 # 
#  obtained from "http://search.cpan.org".					 #
#										 #
#  A typical installation procedure of any perl module consists of the follo-    #
#  wing steps:									 #
#  										 #
#  perl Makefile.PL								 #
#  make										 #
#  make install									 #
#   										 #
#  On Debian systems, this can be installed using apt-get			 #
#  e.g, "apt-get install libterm-readkey-perl"					 #
#										 #
#										 #
#  REQUIRED APPLICATION								 #
#  - macchanger	 (www.alobbs.com/macchanger)					 #
#     This tool is used for spoofing the mac address when the AP is using	 #
#     mac address filtering							 #
#										 #
#										 #
#										 #
#  TESTING PLATFORM:								 #
#										 #
#  During the development, this program was tested inside an Ubuntu Linux	 #
#  installation, using Alfa AWUS036H with R8187 driver. 			 #
#  The access points tested were Aztech DSL605EW and Linksys WAG54G2		 #
#										 #
#										 #
#  WARNINGS:									 #
#										 #
#  Other linux platforms, were not tested. The wireless card mentioned above	 #
#  is the only card that was used, others are not guaranteed to work without     #
#  making any changes. I don't have all the necessary hardwares to test.	 #
#  I'm leaving this work to the community. Please contribute so that everyone    #
#  can benefit.									 #
#										 #
#									         #
#  FINAL THOUGHTS:							         #
#										 #
#										 #
#  This is the first program I have provided to the opensource community.	 # 
#  I hope you'll find it useful. Donations are welcome if you do =). 		 #
#  Send them to my paypal account: markjayson.alvarez@gmail.com 		 #
#										 # 
#  Please use this program in a good way and remember:				 #
# 										 #
# "Morality works best when chosen not when mandated"				 #
#			                - Larry Wall				 #
#					Author, Perl Programming Language	 #
#										 #
#  LINKS									 #
#   										 #
#  Project Page: http://code.google.com/p/wepbuster 		 		 #
#  Demo Videos: http://www.youtube.com/user/wif1bust3r				 #
#										 #
##################################################################################




Steps Taken During The Program Execution:

The following steps provides a detailed breakdown of the steps taken 
during the program execution. This should be read along the actual 
source code. 


1. Run airmon-ng and put each wireless card into monitor mode, obtaining the monitor
   interface name created in the process
   
2. Obtain the macaddress by parsing ifconfig(8) output

3. Argument verification:
 - Can accept 'sort' and 'connect' followed by an optional IP address or a hostname;
 - Can accept either combination of 1, 6, 11 for US non-overlapping channels and
   1, 5, 9, 13 for EU non-overlapping channels
 - If no valid channels were entered, defaults to all channels on the $country specified

4. Verify existence of cracked APs list ("owned.txt") before running 'sort' or 'connect' mode.

5. Scan each of the specified channels for certain duration and build 
   an overall list of wep-enabled access points including all the clients currently 
   associated to each.

   `airodump-ng monitor_interface -t wep -c  channel -n -w $filename 2>&1`;


6. Verify that at least one access point was found during the initial scan, before 
   proceeding.  

7. Read the list of cracked APs (if there is any), so that later, we can skip APs 
   that have been cracked already. It is also useful for modes 'sort' and 'connect'
    so that we will know if we can connect to an AP (given the existence of the key)

8. Read the list of "bad APs" (if there's any). If this list exists, those APs listed
   will be skipped. Useful in case the program stalls on an unusually behaving AP.

9. Read the list of "known APs" (if there's any). If this list exists, only those 
   APs that are listed will be processed. Useful to avoid illegally cracking APs 
   that we're not allowed to.

10. Process the modes:
 10.1 MODE 'CRACK'
  - process "bad APs" list. Skip the AP if it is listed.
  - process "known APs" list. Skip the AP if it is not listed.
  - process "cracked APs" list. Skip AP if it is included in the list and at most 
    15 days old since the day the key was found
  - REVEAL HIDDEN SSID
    - Send deauth broadcast for 3 times. 

      `aireplay-ng -0 1 -a bssid inject_interface -h mac_address 2>&1`;

     If there's any associated clients found in the initial scan, send each client directed 
     deauth plus 2 deauth broadcast only. 

       `aireplay-ng -0 1 -a bssid inject_interface -h mac_address -c client_macaddress 2>&1`;

     User can press 'enter' key to send two more deauth broadcasts.

    - If the SSID cannot be revealed, just name it as 'hidden'
  - pkill airodump-ng and aireplay-ng just to make sure no other aircrack process 
    is running before we begin.
  - delete all dump files in the current directory.
  - set the channel and rate
  - CHECK FOR MAC ADDRESS FILTERING and SHARED KEY AUTHENTICATION
    - Do an initial fakeauth and check if AP is using mac filtering or SKA.

     'aireplay-ng -1 1 -a bssid inject_interface -e 'ssid' -h mac_address -D 2>&1'

    - If AP is filtered, check if we have any associated client to spoof our mac 
      address with.
    - If there is, spoof our mac using "macchanger", otherwise, skip the AP. 
  - Run fakeauth with keep-alives in the background

	
	'aireplay-ng -1 6000 -o 1 -q 10 -a bssid inject_interface -e 'ssid' -h mac_address' 

  - Run airodump in the background and dump only data destined to the AP

     'airodump-ng monitor_interface -t wep -u 20 -d bssid -c channel -w inject_dump  2>&1'

  - Run arp replay attack in the background

     'aireplay-ng inject_interface -3  -b bssid -h mac_address 2>&1'

  - KEEP COUNTING IVs EVERY 2 SLEEPS AND DISPLAY THE COUNT EVERY 10 SLEEPS
   - if IV count is less than 100 after 20 sleeps, send deauth broadcast twice with 
     2 sleeps interval

	 'aireplay-ng -0 1 -a bssid inject_interface -h mac_address'

   - if IV count is less than 100 after 40 sleeps, try rebroadcast attack (-p 0841)

         'aireplay-ng inject_interface -2 -p 0841 -b bssid -c FF:FF:FF:FF:FF:FF -h mac_address  2>&1'

   - if IV count is less than 100 after 60 sleeps, skip the AP
   - if still injecting after 30 minutes worth of sleeps, try to send reassociate 
     request once (in case when we are injecting to an AP that has suddenly rebooted)

	aireplay-ng -1 1 -a bssid inject_interface -e 'ssid' -h mac_address`;

   - after 1 hour worth of sleeps, and we're still injecting, skip the AP.
  - BEGIN CRACKING THE KEY
   - if we have collected $min_iv (17000) start cracking the key using aircrack-ng.

         'aircrack-ng -q -b 'bssid' inject_dump-01.cap'

   - add the key in "cracked APs (owned.txt)" list once found
   - if key cannot be found after $crack_timeout (15 minutes), skip the AP
  - If we suddently get an error code while injecting, skip the AP. Possible presence 
    of WIPS


 10.2 MODE 'SORT'
   - Verify if the AP is included in the list of owned APs. If it is not, we cannot 
     connect to it because we don't have the key, therefore, we won't be able to get 
     the RTT. So we'll skip it.
   - If we have the key, will get the RTT and record it. The RTT refers to our gateway 
     RTT or if we have specified a host, we'll get the ping RTT of that instead. e.g,
     "perl wepbuster sort www.google.com"
   - Once we have all the RTT for each AP, sort them and write the output into
     "owned_rtt.txt"
   - Finally, rearrange "owned.txt" such that the order of the APs follows that of the
      "owned_rtt.txt";


 10.3 MODE 'CONNECT'
   - read "owned.txt" sequencially and connect to each. Connection will be verified if 
     we can ping the gateway or whatever host we specified in the command line. e.g, 
     "perl wepbuster connect www.google.com"
   - once connected to an AP, we're done.

11. During mode sort and connect, when testing for connectivity, we initially set our 
    IP address manually to 192.168.1.150 and gateway to 192.168.1.1. If we cannot 
    'connect', we try to obtain IP address via DHCP using dhclient.
