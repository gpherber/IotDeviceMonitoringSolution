/*!40101 SET NAMES utf8 */;
/*!40014 SET FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET SQL_NOTES=0 */;
CREATE DATABASE /*!32312 IF NOT EXISTS*/ Monitoring /*!40100 DEFAULT CHARACTER SET utf8mb4 */;
USE Monitoring;

DROP TABLE IF EXISTS entries;
CREATE TABLE `entries` (
  `EntryHash` varchar(255) NOT NULL,
  `MACAddress` varchar(255) NOT NULL,
  `SrcIP` varchar(255) NOT NULL,
  `DstIP` varchar(255) NOT NULL,
  `DstPort` int NOT NULL,
  `Count` int NOT NULL,
  `DateFirstSeen` datetime NOT NULL,
  PRIMARY KEY (`EntryHash`),
  UNIQUE KEY `EntryHash` (`EntryHash`),
  KEY `MACAddress` (`MACAddress`),
  CONSTRAINT `entries_ibfk_1` FOREIGN KEY (`MACAddress`) REFERENCES `hosts` (`MACAddress`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS hosts;
CREATE TABLE `hosts` (
  `MACAddress` varchar(255) NOT NULL,
  `FriendlyName` varchar(255) DEFAULT NULL,
  `Complexity` float DEFAULT NULL,
  `IP` varchar(255) NOT NULL,
  `DateOfCreation` datetime NOT NULL,
  `ProbabilityOfBeingCompromised` float DEFAULT NULL,
  PRIMARY KEY (`MACAddress`),
  UNIQUE KEY `MACAddress` (`MACAddress`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;