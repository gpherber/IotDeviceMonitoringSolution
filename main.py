import monitoringConfig as config
import monitoringPackets as monitor
import monitoringMysql as mysql
from datetime import datetime
from pprint import pprint

## helper functions

def isHostStillTraining(dateNow,dateThen,trainingTime):
    """Determines the training status based on the given dates and times, returns a Boolean."""
    differenceDays = (dateNow - dateThen).days
    if differenceDays >= trainingTime:
        return False
    else: 
        return True 

def normalize(value, minValue, maxValue):
    if (maxValue - minValue) != 0:
        normalized = (value - minValue) / (maxValue - minValue)
    else:
        normalized = 1
    return normalized

def getDatabaseConnection():
    connection = mysql.mysqlConnect(
        config.dbinfo.host,
        config.dbinfo.user,
        config.dbinfo.password,
        config.dbinfo.database
    )
    return connection

def doesHostExist (SrcMAC):
    cursor = mysql.mysqlGetHost(getDatabaseConnection(),SrcMAC)
    if cursor.rowcount > 0:
        return True
    else:
        return False

def getHostDateOfCreation(SrcMAC):
    cursor = mysql.mysqlGetHost(getDatabaseConnection(),SrcMAC)
    row = cursor.fetchone()
    return row['DateOfCreation']

def doesPacketEntryExist(packetHash):
    cursor = mysql.mysqlGetPacketFromHash(
        getDatabaseConnection(),
        packetHash
    )
    if cursor.rowcount < 1:
        return False
    else:
        return True

def isPacketSuspicious(packet):
    hostKnown = getHostDateOfCreation(packet.eth.src)
    hostTraining = isHostStillTraining(datetime.now(),hostKnown,config.monitoring.trainingTime)
    if hostTraining:
        print (f"{packet.eth.src} is Training")
        return False
    else:
        packetHash = mysql.getPacketHash(packet)
        if doesPacketEntryExist(packetHash):
            print (f"{packet.eth.src} is not Training but packet isnt Suspicious")
            return False
        else:
            print (f"{packet.eth.src} is not Training but packet is Suspicious")
            return True

def getNewProbability(previousProbability, complexity):
    adjustedComplexity = 0.51 - complexity
    oneMinusProbability = 1 - previousProbability
    probability = (adjustedComplexity * oneMinusProbability) + previousProbability
    return probability

def isHostCompromised(HostMAC):
    probability = mysql.getHostCompromisedProbability(
                    getDatabaseConnection(),
                    HostMAC
                )
    if probability > 0.90:
        return True
    else:
        return False

def getTotalPacketsSentByHost(hostMAC,connection):
    ## Get Total Number of Packets Sent from Host
    sql = f"SELECT SUM(Count) FROM entries WHERE MACAddress = '{hostMAC}'"

    cursor = connection.cursor()
    cursor.execute(sql)
    numberOfPackets = int(cursor.fetchone()['SUM(Count)'])
    return numberOfPackets

def getTotalNumberOfUniqueEntriesForHost(hostMAC,connection):
    ## get number of different destinations
    sql = f"SELECT COUNT(*) FROM entries WHERE MACAddress = '{hostMAC}'"
    cursor = connection.cursor()
    cursor.execute(sql)
    numberOfDestinations = cursor.fetchone()['COUNT(*)']
    return numberOfDestinations

def getAveragePacketsPerDestination(numberOfPackets,numberOfDestinations):
    averagePacketsPerDestination = numberOfPackets / numberOfDestinations
    return averagePacketsPerDestination

def getHighestPacketCount(connection):
    return mysql.mysqlGetHighPacketCount(connection)['MAX(Count)']

def calculateComplexity(averagePacketsPerDestination,minValue,maxValue):
    if averagePacketsPerDestination == 1:
        complexity = 0
    else:
        complexity = normalize(averagePacketsPerDestination,minValue,maxValue)
    return complexity

def updateComplexity(connection, complexity, MACAddress):
    sql = f"UPDATE Monitoring.hosts SET Complexity = '{complexity}' WHERE MACAddress = '{MACAddress}';"
    cursor = connection.cursor()
    cursor.execute(sql)
    connection.commit()

## main code ##

def main():
    while True:
        ## returns a number of packets prefiltered to include only outbound local traffic and tcp/udp 
        packets = monitor.get_packets(config.monitoring.monitoringInterface,config.monitoring.packetsPerCapture)

        # process the traffic
        for packet in packets:
            mysql.mysqlAddOrUpdateDevice(getDatabaseConnection(),packet)
                
            suspicious = isPacketSuspicious(packet)
            if suspicious:

                previousProbability = mysql.getHostCompromisedProbability(
                    getDatabaseConnection(),
                    packet.eth.src
                )

                complexity = mysql.getHostComplexity(
                    getDatabaseConnection(),
                    packet.eth.src
                )

                probability = getNewProbability(previousProbability,complexity)
                        
                print (f"Previous Probability: {previousProbability} Complexity: {complexity} New Probablility: {probability}")

                mysql.setHostCompromisedProbability(
                    getDatabaseConnection(),
                    probability,
                    packet.eth.src
                )

                        ################# future work #######################
                        # allow user override of suspicious activity        #
                        # some changes to a devices behaviour may be normal #
                        # for instance activating a new service on a device #
                        #####################################################
            
            else:
                # Add or update packet entry in database
                mysql.mysqlAddOrUpdatePacketEntry(
                    getDatabaseConnection(),
                    packet
                )

        ## after all packets are processed

        # Update complexity of each device (under configured training time)
        cursor = mysql.mysqlGetListOfHosts(getDatabaseConnection())

        while True:
            row = cursor.fetchone()
            if row == None:
                break

            DateOfCreation = row['DateOfCreation']
            IP = row['IP']
            MACAddress = row['MACAddress']

            if isHostStillTraining(datetime.now(),DateOfCreation,config.monitoring.trainingTime):

                averagePacketsPerDestination = getAveragePacketsPerDestination(
                    getTotalPacketsSentByHost(
                        MACAddress,
                        getDatabaseConnection()
                    ),
                    getTotalNumberOfUniqueEntriesForHost(
                        MACAddress,
                        getDatabaseConnection()
                    )
                )
                max = getHighestPacketCount(getDatabaseConnection())
                min = 1
                complexity = calculateComplexity(averagePacketsPerDestination,min,max)

                updateComplexity(getDatabaseConnection(),complexity,MACAddress)
            if (isHostCompromised(MACAddress)):
                print(f"Host with MAC Address {MACAddress} and IP {IP} is Compromised")

if __name__ == '__main__':
    main()