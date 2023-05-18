Hive Case Automation made by A1C RDS.

v1.0.

GUI:

1.  Run app.py

2.  Open 127.0.0.1:8050 in your browser

3.  In arkime, export the .csv for all sessions with columns:
    "firstPacket,lastPacket,srcIp,srcGEO,srcPort,dstIp,dstGEO,dstPort,http.uri,communityId",
    Drop it in the .csv drop area.

4.  Compile all pcaps into a single pcap in arkime, that way you can pull all of the http items and stuff for hashing. This can be done using the arrow in the top right of the Arkime window.
    a. Save all observables from the .pcap
    b. Drop all observables into the observable drop area.
5.  Submit, then copy the output into your hive case.

CLI:

1.  Compile all pcaps into a single pcap in arkime, that way you can pull all of the http items and stuff for hashing. This can be done using the arrow in the top right of the Arkime window.
    a. Create a directory named 'case-files' in root.
    b. Save all pcap items into the 'case-files' directory. NOT THE PCAP ITSELF.

2.  In arkime, export the .csv for all sessions with columns:
    "srcIp,srcPort,dstIp,dstPort,communityId",
    and name it 'sessions.csv'. Save it in the root dir.

3.  Run ./format.py using the command:
    "python3 ./format.py",
    when you're in the hivetool directory.

4.  Enter the correct information as prompted.

5.  Take the outputted file and copy it's contents into the hive case.

Game.

Installation:

1.  In the root directory of the application, execute 'pip install -r requirements.txt'

2.  Edit ./app.py, and replace HOST_PORT and HOST_IP at the bottom with your preferred port and IP.

3.  Execute 'python3 ./app.py'

4.  The website is now running on the port that you specified, and the IP that you specified.
