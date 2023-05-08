Hive Case Automation made by A1C RDS.

v1.

1.  Compile all pcaps into a single pcap in arkime, that way you can pull all of the http items and stuff for hashing. This can be done using the arrow in the top right of the Arkime window.
    a. Create a directory named 'case-files' in root.
    b. Save all pcap items into the 'case-files' directory. NOT THE PCAP ITSELF.

2.  In arkime, export the .csv for all sessions with columns:
    "firstPacket,lastPacket,srcIp,srcGEO,srcPort,dstIp,dstGEO,dstPort,http.uri,communityId",
    and name it 'sessions.csv'. Save it in the root dir.

3.  Run ./format.py using the command:
    "python3 ./format.py",
    when you're in the hivetool directory.

4.  Enter the correct information as prompted.

5.  Take the outputted file and copy it's contents into the hive case.

Game.

RDS
