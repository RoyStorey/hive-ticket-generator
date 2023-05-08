from datetime import datetime
import csv
import glob
import hashlib
import os

os.remove('./hashedfiles')

filenames = glob.glob("./case-files/*")
filehashes = []

i = 1
for filename in filenames:
    with open(filename, 'rb') as inputfile:
        data = inputfile.read()
        with open('hashedfiles','a') as file:
            file.write(hashlib.md5(data).hexdigest() + '\n')
            filehashes.append( ' ' + str(i) + '. ' + hashlib.md5(data).hexdigest())
            i = i+1



dataFile = open(r"sessions.csv")
dataFromCSV = csv.reader(dataFile,delimiter=',', skipinitialspace=True)
j = 1
SrcIP, DstIP, SrcPorts, DstPorts, CommIDs  = [], [], [], [], []
next(dataFromCSV)
for row in dataFromCSV:
    if ' ' + row[2] not in SrcIP:
        SrcIP.append(' ' + row[2])
    if ' ' + row[4] not in SrcPorts:
        SrcPorts.append(' ' + row[4])
    if ' ' + row[5] not in DstIP:
        DstIP.append(' ' + row[5])
    if ' ' + row[7] not in DstPorts:
        DstPorts.append(' ' + row[7])
    if str(j) + '. ' + row[9] not in CommIDs:
        CommIDs.append(str(j) + '. ' + row[9])
        j = j+1




now = datetime.now()
dt_string = now.strftime("%m/%d/%Y %H:%M:%S")




class formattedHiveCase:
    timeObserved = dt_string
    initials = input('Operator Initials:\n')
    sourceIP = ','.join(SrcIP)
    sourcePorts = ','.join(SrcPorts)
    destinationIP = ','.join(DstIP)
    destinationPorts = ','.join(DstPorts)
    communityIds = '\n'.join(CommIDs)
    ids = input('IDs:\n')
    observableHashes = '\n'.join(filehashes)
    mitreVectors = input('MITRE ATT&CK Vectors:\n')
    suricataAlerts = input('Suricata Alerts:\n')
    description = input('Description:\n')
    recommendedSolution = input('Recommended Solution:\n')


# print(formattedHiveCase)

print("**Time Observed:** ", formattedHiveCase.timeObserved, "by " + formattedHiveCase.initials +  "\n\n**Src IP:** " + formattedHiveCase.sourceIP + "\n**Src Ports:** " + formattedHiveCase.sourcePorts + "\n\n**Dst IP:** " + formattedHiveCase.destinationIP + "\n**Dst Ports:** " + formattedHiveCase.destinationPorts + "\n\n**Community IDs:**\n" + formattedHiveCase.communityIds + "\n\n**IDs:**\n" + formattedHiveCase.ids + "\n\n**Observables/Hashes:**\n" + formattedHiveCase.observableHashes + "\n\n**MITRE Vectors of Attack** " + formattedHiveCase.mitreVectors + "\n\n**Suricata Alerts:** " + formattedHiveCase.suricataAlerts + "\n\n**Description:** " + formattedHiveCase.description + "\n\n**Recommended Solution:** " + formattedHiveCase.recommendedSolution)
