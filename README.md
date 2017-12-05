# trapsim
Injects simulated snmp v2c trap into Smarts trap collector using information from the device.

The program forms Overture/Accedian specific snmp v2c trap by querying device for available alarm definitions and endpoints
then sends trap to EMC trap collector server (Smarts v8 and v9)

The pre-requisites are:
1) Device's FQDN must resolve in DNS or /etc/hosts
2) Device must be discovered by Smarts
3) Device must respond to v2c snmp queries
4) Program must be run from server where dmctl and sm_snmp commands are available
