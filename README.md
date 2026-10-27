# Zeek Nmap scan detection (Network Security, Assignment 10)

Zeek script that detects Nmap scans in the CIC-IDS2017 snippet pcap
(provided as assignment_lecture10.pcap in the lecture zip).

## Run
    zeek -C -r <pcap file> scans.zeek
    cat notice.log | zeek-cut note msg id.orig_h

Zeek writes notice.log in the current folder. Run it in an empty folder.

## Detected scans
| Scan | Detector | Threshold |
|---|---|---|
| sS | history ShR (open port, RST without ACK) | 5 distinct ports |
| sT | history ShAR (open port, handshake then RST) | 5 distinct ports |
| sV and sR | history starting with ShAD from a source marked as scanner | 3 distinct ports |
| sU | UDP connection with state S0 (no reply) | 20 distinct ports |
| sO | packets in unknown_transport flows | 50 packets |

sR produces the same traffic as sV, so one detector covers both.
A source is marked as scanner after 100 distinct closed ports (history Sr).

## Notices
- Each scan raises a Notice when its threshold is reached. The counting then starts over.
- The notice message contains the number of previous notices for the same scan,
  for example: "sS from 172.16.0.1: 5 distinct ports. Previous notices for this scan: 0".
- Thresholds are constants in lines 7 to 12 of scans.zeek. A lower threshold gives more notices.
- Counting uses a 5 minute window (&create_expire).

## Result on the provided pcap
78 sS, 80 sT, 19 sV/sR, 5 sU and 1 sO notices.
