import pymysql.cursors
import hashlib
import monitoringDetails as details

def mysqlConnect (host,user,password,database):
# Connect to the database
    connection = pymysql.connect(host=host,
                             user=user,
                             password=password,
                             database=database,
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor)

    return connection

def mysqlAddOrUpdateDevice(connection,packet):
    with connection:
        with connection.cursor() as cursor:
            sql = f"SELECT * FROM Monitoring.hosts WHERE MACAddress = '{packet.eth.src}';"
            numberOfRows = cursor.execute(sql)
            if numberOfRows > 0:
               sql = f"UPDATE Monitoring.hosts SET IP = '{packet.ip.src}' WHERE MACAddress = '{packet.eth.src}';"
               cursor.execute(sql)
               connection.commit()
               return True
            else:
                #create entry
                hostFriendlyName = details.get_mac_details(packet.eth.src)
                sql = f"INSERT INTO Monitoring.hosts(`MACAddress`,`FriendlyName`,`Complexity`,`IP`,`DateOfCreation`,`ProbabilityOfBeingCompromised`) VALUES ('{packet.eth.src}', '{hostFriendlyName}', 0, '{packet.ip.src}', NOW(), 0.5);"
                cursor.execute(sql)
                connection.commit()
                return True

def mysqlAddOrUpdatePacketEntry(connection,packet):
    with connection:
        with connection.cursor() as cursor:
            hash = getPacketHash(packet)
            protocol = packet.transport_layer   # protocol type
            sql = f"INSERT INTO entries (EntryHash, MACAddress, SrcIP, DstIP, DstPort, Count, DateFirstSeen) VALUES('{hash}', '{packet.eth.src}', '{packet.ip.src}', '{packet.ip.dst}', '{packet[protocol].dstport}', '1', NOW()) ON DUPLICATE KEY UPDATE Count = Count + 1"
            cursor.execute(sql)
            connection.commit()
            return True

def mysqlGetListOfHosts(connection):
    with connection:
        with connection.cursor() as cursor:
            sql = "SELECT * FROM Monitoring.hosts"
            cursor.execute(sql)
            return cursor

def getHostComplexity(connection,MACAddress):
    with connection:
        with connection.cursor() as cursor:
            sql = f"SELECT Complexity FROM Monitoring.hosts WHERE MACAddress = '{MACAddress}'"
            cursor.execute(sql)
            return cursor.fetchone()['Complexity']            

def getHostCompromisedProbability(connection,MACAddress):
    with connection:
        with connection.cursor() as cursor:
            sql = f"SELECT ProbabilityOfBeingCompromised FROM Monitoring.hosts WHERE MACAddress = '{MACAddress}'"
            cursor.execute(sql)
            return cursor.fetchone()['ProbabilityOfBeingCompromised']

def setHostCompromisedProbability(connection,probability,MACAddress):
    with connection:
        with connection.cursor() as cursor:
            sql = f"UPDATE Monitoring.hosts SET ProbabilityOfBeingCompromised = '{probability}' WHERE MACAddress = '{MACAddress}'"
            cursor.execute(sql)
            connection.commit()
            return True


def mysqlGetHost(connection, MACAddress):
    with connection:
        with connection.cursor() as cursor:
            sql = f"SELECT * FROM Monitoring.hosts WHERE MACAddress = '{MACAddress}'"
            cursor.execute(sql)
            return cursor

def mysqlGetHighPacketCount(connection):
    with connection:
        with connection.cursor() as cursor:
            sql = f"SELECT MAX(Count) FROM Monitoring.entries"
            cursor.execute(sql)
            count = cursor.fetchone()
            return count

def mysqlGetPacketFromHash(connection, packetHash):
    with connection:
        with connection.cursor() as cursor:
            sql = f"SELECT * FROM Monitoring.entries WHERE EntryHash = '{packetHash}'"
            cursor.execute(sql)
            return cursor

def getPacketHash(packet):
    macaddress = packet.eth.src
    protocol = packet.transport_layer   # protocol type
    dst_addr = packet.ip.dst            # destination address
    dst_port = packet[protocol].dstport   # destination port
    hash = hashlib.md5()
    tmpvar = str(macaddress) + str(dst_addr) + str(dst_port)
    hash.update(tmpvar.encode())
    hashValue = hash.hexdigest()
    return hashValue