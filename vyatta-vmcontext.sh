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

##### Determine whether we're in OpenNebula at all.
##############################################################################

# This script is run after the context CD is already mounted. So,
#  check to see if context exists. If not, exit. If so, let's go.
if [ -f /mnt/context.sh ]
then
  echo "Detected OpenNebula context. Contextualizing."
  . /mnt/context.sh
else
  echo "No OpenNebula context detected. Proceeding with boot."
  exit
fi

# If we get here, we're in OpenNebula and need to contextualize.

##### Helper functions
##############################################################################

# Derive a likely unique IP address from a MAC address.
#  We use this if there's no IP provided by context.
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

# Get the short name of the guest's network interfaces.
# Note: this depends on their staying in the old eth0,eth1... style.
get_interfaces() { 
  IFCMD="/sbin/ifconfig -a" 
  $IFCMD | grep ^eth | cut -d ':' -f 1 
} 

# Thanks to: https://forum.openwrt.org/viewtopic.php?pid=220781#p220781
mask2cdr ()
{
  # Assumes there's no "255." after a non-255 byte in the mask
  local x=${1##*255.}
  set -- 0^^^128^192^224^240^248^252^254^ $(( (${#1} - ${#x})*2 )) ${x%%.*}
  x=${1%%$3*}
  echo $(( $2 + (${#x}/4) ))
}

##### Start using VyOs
##############################################################################

# VyOS needs its system's commands wrapped with this command begin and end:
WRAPPER=/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper 
$WRAPPER begin 

##### Services
##############################################################################

$WRAPPER set service ssh

##### Host name
##############################################################################

if [ -n "$HOSTNAME" ]
then
  $WRAPPER set system host-name $HOSTNAME
fi

##### SSH keys
##############################################################################

# Set vyos user ssh key
if [ -n "$SSH_PUBLIC_KEY" ]
then
  # The third field is the key comment.
  keyname=`echo $SSH_PUBLIC_KEY | cut -f 3 -d " "`
  # Second field is the key material.
  key=`echo $SSH_PUBLIC_KEY | cut -f 2 -d " "`
  # First field is the key type.
  type=`echo $SSH_PUBLIC_KEY | cut -f 1 -d " "`

  # Check to see whether the key comment is blank.
  if [ -z $keyname ]
  then
    # Add a default comment, as it's optional.
    # TODO: should add an auto-increment token at the beginning, here.
    keyname="opennebula"
  fi

  # Save the key.
  $WRAPPER set system login user vyos authentication public-keys $keyname key $key
  $WRAPPER set system login user vyos authentication public-keys $keyname type $type
fi

##### Networking
##############################################################################

# Grab the local names of our NICs.
GUEST_NIC_NAMES=`get_interfaces`

# For each,
for GUEST_NIC_NAME in $GUEST_NIC_NAMES; do

  ##### Generate some reasonable defaults to optional context data.
    # MAC-based IP address selection:
  CURR_NIC_MAC=`get_mac $GUEST_NIC_NAME` 
  IP=`mac2ip $CURR_NIC_MAC`
  # Default to a /24
  MASK=24

  ##### Derive important context variable names:
  CONTEXT_VAR_NIC_ADDRESS=${GUEST_NIC_NAME^^}_IP
  CONTEXT_VAR_NIC_MASK=${GUEST_NIC_NAME^^}_MASK
  CONTEXT_VAR_GATEWAY=${GUEST_NIC_NAME^^}_GATEWAY

  ##### Select network options
  # If context provides an IP address, set it.
  if [ -n ${!CONTEXT_VAR_NIC_ADDRESS} ]
  then
    IP=${!CONTEXT_VAR_NIC_ADDRESS}
  fi
  # If context provides a netmask, set it.
  if [ -n ${!CONTEXT_VAR_NIC_MASK} ]
  then
    MASK=`mask2cdr ${!CONTEXT_VAR_NIC_MASK}`
  fi

  ##### If this interface has a gateway set, add it with a default route.
  # (However, if this device IS the gateway, we obviously don't want that.)
  if [ -n ${!CONTEXT_VAR_GATEWAY} ] && [ ${!CONTEXT_VAR_GATEWAY} != ${!CONTEXT_VAR_NIC_ADDRESS} ]
  then
    $WRAPPER set protocols static route 0.0.0.0/0 next-hop ${!CONTEXT_VAR_GATEWAY}
  fi

  ##### Write the configuration.
  $WRAPPER set interfaces ethernet $GUEST_NIC_NAME address $IP/$MASK
  $WRAPPER set interfaces ethernet $GUEST_NIC_NAME duplex auto 
  $WRAPPER set interfaces ethernet $GUEST_NIC_NAME speed auto 

done 

# TODO: Possibly not this:
if [ -n "$ETH0_DNS" ]
then
  $WRAPPER set system name-server $ETH0_DNS
fi

##### Done---commit.
##############################################################################

$WRAPPER commit 
$WRAPPER end 
