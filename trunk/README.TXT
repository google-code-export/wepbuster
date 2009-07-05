
##################################################################################
#					        			 	 #
#  					        				 # 
#	  			WEPBuster 1.0            			 #
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
#  OUTPUT: 									 #
#										 #	
#   (owned.txt)								 	 #
#										 #
#      BSSID           CHANNEL  SSID	       KEY	      TIMESTAMP	 	 #
#  										 #
#  00:21:29:7D:5E:EB === 11 === Zakhal === 08:6D:38:15:30 === 1243883642         #
#  00:12:29:1D:E1:B3 === 1 === amnah === 68:28:1a:3c:20 === 1243883642           #
#										 #
#										 #
#   (owned_rtt.txt)								 #
#										 #
#   BSSID      CHANNEL       SSID   KEY   TIMESTAMP    AVERAGE RTT (PACKET LOSS) #
#										 #
# 00:21:29:7D:5E:EB === 11 === ap1 === 08:6D:38:15:30 === 183642 === 7.2(0% loss)#
# 00:12:29:1D:E1:B3 === 1 === ap2 === 68:28:1a:3c:20 === 124642 === 9.3(10% loss)#
#										 #
#										 #
#   (found_ap.txt)								 #
#										 #
#   BSSID	CHANNEL		SSID						 #
#										 #
#  00:21:29:7D:5E:EB    11     Zakhal 						 #
#  00:12:29:1D:E1:B3     1     amnah 						 #
#										 #
#										 #
#  USAGE:				        				 #
#									         #
#  perl wepbuster [channel/s] (or any combination, space separated )" 	 	 #
#  perl wepbuster (sort | connect) [HOST | IP]  (Defaults to: gateway)"     	 #
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
#  RECOMMENDED MODIFICATIONS (OPTIONAL):					 #
#										 #
#  Starting with 1.0 beta_0.6, wepbuster now works with the vanilla aircrack-ng  #
#  releases (aircrack-ng 1.0 rc4 and above). The first modification to the  	 #
#  source code of aircrack-ng will increase the accuracy in terms of   		 # 
#  the number of IVs needed in order to crack the WEP key. The second one will   #
#  shorten the amount of time aireplay-ng will wait before trying a new data     #
#  packet for fragmentation attack.						 #
#										 #
#  1.) Instead of 5000, change PTW_TRY_STEP to 100 to tell aircrack-ng to start  #
#    cracking the WEP key again (from a previous failed attempt) as soon as it   #
#    has collected 100 new IVs.							 #
#										 #
#    Look for this line below in "aircrack-ng.h" 				 #
#    PTW_TRY_STEP  #5000   							 #
#										 #
#										 #
#   2.) When IVs did not go beyond 300 after 30 sleeps, wepbuster will try       #
#     aireplay-ng's fragmentation attack (-5).					 # 
#										 #
#										 #
#     To shorten the amount of tries when there is no answer from the AP,  	 #
#     change "round > 10" to "round > 2"					 #
#										 #
#     PCT; printf("No answer, repeating...\n");					 #
#     ....									 #
#     ....									 #
#     if (round > 10)								 #
#										 #
#   In most occassions, fragmentation attack results in a very quick creation    #
#   of forged arp packets that can be used for arp replay attack which is a      #
#   fast way to generate unique IVs for the quickest WEP cracking technique so 	 #
#   far, the PTW attack. Changing the value above will further increase the      # 
#   speed of fragmentation attack.						 #
#										 #
#										 #
#										 #
#  REQUIREMENTS:								 #
#										 #
#  - aircrack-ng 1.0 rc4 and above 						 #
#										 #
#  - perl installation with standard libraries (threading support)  	 	 #
#     - perl modules (http://search.cpan.org)			 		 #
#        - Term::ReadKey							 #
#        - Expect.pm 								 #
#										 #
#  - macchanger	 (www.alobbs.com/macchanger)					 #
#										 #
#  - miscellaneous unix programs						 #
#	- ifconfig, iwconfig, rm, pkill, stty, cp, touch, mv, route, ping, 	 #
#         dhclient, netstat							 #
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
# 										 #
##################################################################################




Steps Taken During The Program Execution:

The following steps provides a detailed breakdown of the steps taken 
during the program execution. This should be read along the actual 
source code. 


1. Run airmon-ng and put each wireless card into monitor mode, obtaining the monitor
   interface name created in the process
   
2. Obtain the macaddress by parsing ifconfig(8) output

3. Argument verification:
 - Can accept 'sort' and 'connect' followed by an optional IP address or a hostname
 - Can accept either combination of 1, 6, 11 for US non-overlapping channels and
   1, 5, 9, 13 for EU non-overlapping channels
 - If no valid channels were entered, defaults to all channels on the $country specified

4. Verify existence of cracked APs list ("owned.txt") before running 'sort' or 'connect' mode.

5. Scan each of the specified channels for certain duration and build 
   an overall list of wep-enabled access points including all the clients currently 
   associated to each.

   `airodump-ng monitor_interface -t wep -c  channel -n -w $filename 2>&1`


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

      `aireplay-ng -0 1 -a bssid inject_interface -h mac_address 2>&1`

     If there's any associated clients found in the initial scan, send each client directed 
     deauth plus 2 deauth broadcast only. 

       `aireplay-ng -0 1 -a bssid inject_interface -h mac_address -c client_macaddress 2>&1`

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
  - Run fakeauth with keep-alives (reassociate every 15 minutes)  in the background

	'aireplay-ng -1 900 -o 1 -q 10 -a bssid inject_interface -e 'ssid' -h mac_address' 

  - Run airodump in the background and dump only data destined to the AP

     'airodump-ng monitor_interface -t wep -u 20 -d bssid -c channel --output-format pcap,csv -w inject_dump  2>&1'

  - Run arp replay attack in the background

     'aireplay-ng inject_interface -3  -b bssid -h mac_address 2>&1'

  - KEEP COUNTING IVs EVERY 1 SLEEP AND DISPLAY THE COUNT EVERY 5 SLEEPS
   - if IV count is less than 100 after 10 sleeps, send deauth broadcast twice with 
     2 sleeps interval

	 'aireplay-ng -0 1 -a bssid inject_interface -h mac_address'

   - if IV count is less than 300 after 30 sleeps, try fragmentation attack (-5) for $frag_timeout seconds (unless there is no at all IV) 
     Note that we're only reading a copy of the collected dump so far.  

	'aireplay-ng -5 inject_interface -b bssid -r inject_dump-01.cap.tmp -h mac_address'

   - if attack was successful, we build an arp packet using the keystream found

        'packetforge-ng -0 -a bssid -h mac_address -k 255.255.255.255 -l 255.255.255.255 -y keystream_xor -w forged_arp.cap'
   
   - then we replay it for 3 seconds. (we already have an aireplay-ng -3 running so we only need this one until the first 
     aireplay-ng -3 picks up our forged arp.
        
	'aireplay-ng inject_interface -3 -r forged_arp.cap -b bssid -h mac_address 2>&1'

   - when fragmentation exits, either because it has ran out of data or it has timed out, we launch rebroadcast attack (-p 0841) 

         'aireplay-ng inject_interface -2 -p 0841 -b bssid -c FF:FF:FF:FF:FF:FF -h mac_address  2>&1'

   - after 20 minutes and we're still trying... This is taking forever, we'll skip the ap

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
   - If we have the key, will get the RTT w/packet loss and record it. The RTT refers to our gateway 
     RTT or if we have specified a host, we'll get the ping RTT of that instead. e.g,
     "perl wepbuster sort www.google.com"
   - Once we have all the RTT for each AP, sort them and write the output into
     "owned_rtt.txt"
   - Finally, rearrange "owned.txt" such that the order of the APs follows that of the
      "owned_rtt.txt"


 10.3 MODE 'CONNECT'
   - read "owned.txt" sequencially and connect to each. Connection will be verified if 
     we can ping the gateway or whatever host we specified in the command line. e.g, 
     "perl wepbuster connect www.google.com"
   - once connected to an AP, we're done.

11. During mode sort and connect, when testing for connectivity, we initially set our 
    IP address manually to 192.168.1.150 and gateway to 192.168.1.1. If we cannot 
    'connect', we try to obtain IP address via DHCP using dhclient.
