#!/bin/sh 

# -------------------------------------------------------------------------- # 
#                                                                            # 
# This contextualization script configures the VyOS VM's network             # 
# interfaces on startup. Configuration is commited and saved on startup.     # 
#									     # 
# VyOS is a community fork of Vyatta, a Linux-based network operating system #
# that provides software-based network routing, firewall, and VPN            #
# functionality (http://vyos.net)                                            #
#									     # 
# This script contains code developed by OpenNebula Project and C12G Labs    #
# see copyright message below						     #
#                                                                            # 
# Licensed under the Apache License, Version 2.0 (the "License"); you may    # 
# not use this file except in compliance with the License. You may obtain    # 
# a copy of the License at                                                   # 
#                                                                            # 
# http://www.apache.org/licenses/LICENSE-2.0                                 # 
#                                                                            # 
# Unless required by applicable law or agreed to in writing, software        # 
# distributed under the License is distributed on an "AS IS" BASIS,          # 
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   # 
# See the License for the specific language governing permissions and        # 
# limitations under the License.                                             # 
#--------------------------------------------------------------------------- # 

# -------------------------------------------------------------------------- #
# Copyright 2002-2015, OpenNebula Project (OpenNebula.org), C12G Labs        #
# Copyright 2015, Miguel Angel Alvarez Cabrerizo (http://artemit.com.es)     # 
# Copyright 2022-23,                                                         # 
#   George Louthan <george@southwestccdc.com> <duplico@dupli.co> and         #
#   TALON Cyber League, Inc. <talon@southwestccdc.com>                       #
#                                                                            #
# Licensed under the Apache License, Version 2.0 (the "License"); you may    #
# not use this file except in compliance with the License. You may obtain    #
# a copy of the License at                                                   #
#                                                                            #
# http://www.apache.org/licenses/LICENSE-2.0                                 #
#                                                                            #
# Unless required by applicable law or agreed to in writing, software        #
# distributed under the License is distributed on an "AS IS" BASIS,          #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   #
# See the License for the specific language governing permissions and        #
# limitations under the License.                                             #
#--------------------------------------------------------------------------- #

if [ -f /mnt/context.sh ]
then
  . /mnt/context.sh
fi

WRAPPER=/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper 
$WRAPPER begin 

# Let's start the SSH service
$WRAPPER set service ssh

# Set system host-name 
if [ -n "$HOSTNAME" ]
then
  $WRAPPER set system host-name $HOSTNAME
fi

# Set vyos user ssh key
if [ -n "$SSH_PUBLIC_KEY" ]
then
  keyname=`echo $SSH_PUBLIC_KEY | cut -f 3 -d " "`
  key=`echo $SSH_PUBLIC_KEY | cut -f 2 -d " "`
  type=`echo $SSH_PUBLIC_KEY | cut -f 1 -d " "`
  if [ -z $keyname ]
  then
    keyname="opennebula"
  fi
  $WRAPPER set system login user vyos authentication public-keys $keyname key $key
  $WRAPPER set system login user vyos authentication public-keys $keyname type $type
fi


# Many tools to define network parameters

mac2ip() { 
    mac=$1 
    let ip_a=0x`echo $mac | cut -d: -f 3` 
    let ip_b=0x`echo $mac | cut -d: -f 4` 
    let ip_c=0x`echo $mac | cut -d: -f 5` 
    let ip_d=0x`echo $mac | cut -d: -f 6` 
    ip="$ip_a.$ip_b.$ip_c.$ip_d" 
    echo $ip 
} 

get_mac() { 
    ethtool -P $1 | cut -d ' ' -f 3
} 

get_interfaces() { 
    IFCMD="/sbin/ifconfig -a" 
    $IFCMD | grep ^eth | cut -d ':' -f 1 
} 

### Thanks to: https://forum.openwrt.org/viewtopic.php?pid=220781#p220781
mask2cdr ()
{
   # Assumes there's no "255." after a non-255 byte in the mask
   local x=${1##*255.}
   set -- 0^^^128^192^224^240^248^252^254^ $(( (${#1} - ${#x})*2 )) ${x%%.*}
   x=${1%%$3*}
   echo $(( $2 + (${#x}/4) ))
}

IFACES=`get_interfaces` 

for DEV in $IFACES; do
    MAC=`get_mac $DEV` 
    IP=`mac2ip $MAC`
    MASK=24

    IFACE_IP=${DEV^^}_IP
    IFACE_MASK=${DEV^^}_MASK

    if [ -n ${!IFACE_IP} ]
    then
      IP=${!IFACE_IP}
    fi

    if [ -n ${!IFACE_MASK} ]
    then
      MASK=`mask2cdr ${!IFACE_MASK}`
    fi

    $WRAPPER set interfaces ethernet $DEV address $IP/$MASK
    $WRAPPER set interfaces ethernet $DEV duplex auto 
    $WRAPPER set interfaces ethernet $DEV speed auto 
done 

if [ -n "$ETH0_GATEWAY" ]
then
  $WRAPPER set protocols static route 0.0.0.0/0 next-hop "$ETH0_GATEWAY"
fi

if [ -n "$ETH0_DNS" ]
then
  $WRAPPER set system name-server $ETH0_DNS
fi

$WRAPPER commit 
$WRAPPER end 
