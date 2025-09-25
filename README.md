# vpn-fix-localhost
##How to use
nano ~/fix-localhost-lan-docker.sh   # paste the script
chmod +x ~/fix-localhost-lan-docker.sh

### Run it (does NOT change default route)
./fix-localhost-lan-docker.sh

### If GP forced full-tunnel and you want LAN as default again:
./fix-localhost-lan-docker.sh --restore-default

### Custom interface/gateway (if yours differ):
LAN_IF=enp5s0 LAN_GW=192.168.1.1 ./fix-localhost-lan-docker.sh
