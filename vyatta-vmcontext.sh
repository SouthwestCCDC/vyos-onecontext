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

##### Clear whatever the existing config is.
# TODO: Try this
# $WRAPPER begin
# $WRAPPER load /opt/vyatta/etc/config.boot.default
# $WRAPPER commit
# $WRAPPER end

$WRAPPER begin 

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

##### Host Networking
##############################################################################

# Grab the local names of our NICs.
GUEST_NIC_NAMES=`get_interfaces`

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
  CONTEXT_VAR_DNS=${GUEST_NIC_NAME^^}_DNS

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

  ##### Set up any management VRF
  IFACE_VRF=""
  if [ "$MGT_IFACE" = $GUEST_NIC_NAME ]
  then
    $WRAPPER set vrf name management table 100
    $WRAPPER set vrf name management description OOB
    $WRAPPER set interfaces ethernet $GUEST_NIC_NAME vrf management
    IFACE_VRF="vrf management"
  fi

  ##### If this interface has a gateway set, add it with a default route.
  # (However, if this device IS the gateway, we obviously don't want that.)
  if [ -n "${!CONTEXT_VAR_GATEWAY}" ] && [ "${!CONTEXT_VAR_GATEWAY}" != "${!CONTEXT_VAR_NIC_ADDRESS}" ]
  then
    $WRAPPER set protocols $IFACE_VRF static route 0.0.0.0/0 next-hop ${!CONTEXT_VAR_GATEWAY}
  fi

  ##### Write the configuration.
  $WRAPPER set interfaces ethernet $GUEST_NIC_NAME address $IP/$MASK
  $WRAPPER set interfaces ethernet $GUEST_NIC_NAME duplex auto 
  $WRAPPER set interfaces ethernet $GUEST_NIC_NAME speed auto 

  ##### Configure DNS if present in context on this interface.
  if [ -n "${!CONTEXT_VAR_DNS}" ]
  then
    $WRAPPER set system name-server ${!CONTEXT_VAR_DNS}
  fi

done 

##### Routes
##############################################################################

# Read the multi-line GW_NETS context, one route per line.
while IFS= read -r ROUTE_LINE
do
  # If the line is empty, skip it.
  if [ -z "$ROUTE_LINE" ]
  then
    break
  fi

  # Tokenize with spaces.
  ROUTE=($ROUTE_LINE)
  # First token is the interface name (as seen by the guest)
  ROUTE_IFACE=${ROUTE[0]}
  # Second token is the network in CIDR notation with a slash
  ROUTE_DEST=${ROUTE[1]}
  # Third token is optionally the gateway.
  ROUTE_GW=${ROUTE[2]}

  # If the gateway was not provided, set it to the interface's default GW.
  if [ -z "$ROUTE_GW" ]
  then
    ROUTE_GW_VAR=${ROUTE_IFACE^^}_GATEWAY
    ROUTE_GW=${!ROUTE_GW_VAR}
  fi

  # If a management interface is being used, and routes are specified on the
  #  management interface, add them to the management VRF.
  IFACE_VRF=""
  if [ $ROUTE_IFACE = $MGT_IFACE ]
  then
    IFACE_VRF="vrf management"
  fi

  # Execute the configuration.
  $WRAPPER set protocols $IFACE_VRF static route $ROUTE_DEST next-hop $ROUTE_GW

done <<< "$GW_NETS"

##### Services
##############################################################################

if [ -n $MGT_IFACE ]
then
  $WRAPPER set service ssh vrf management
else
  $WRAPPER set service ssh
fi

##### Firewall: NAT
##############################################################################

##### SNAT

# Here, we're receiving rules of the following form, one per line:
# IFACE_OUT [SRC_NETWORK/SRC_MASK]

RULE_NO=10000

while IFS= read -r NAT_RULE_LINE
do
  # If the line is empty, end.
  if [ -z "$NAT_RULE_LINE" ]
  then
    break
  fi

  # Tokenize with spaces.
  NAT_RULE=($NAT_RULE_LINE)
  # First token is the interface name (as seen by the guest)
  NAT_IFACE=${NAT_RULE[0]}
  # Second token is the optional source network in CIDR notation with a slash
  NAT_SRC=${NAT_RULE[1]}

  # Set the outbound interface to masquerade.
  $WRAPPER set nat source rule $RULE_NO outbound-interface $NAT_IFACE
  $WRAPPER set nat source rule $RULE_NO translation address masquerade

  # If a source network is provided, restrict the rule to it.
  if [ -n "$NAT_SRC" ]
  then
    $WRAPPER set nat source rule $RULE_NO source address $NAT_SRC
  fi

  let "RULE_NO+=1"
done <<< "$NAT_OUT_IFACES"

##### DNAT
# Here, we're receiving rules of the following form, one per line:
#  IFACE_IN DEST_ADDR TRANSLATED_ADDR
# TODO: Allow port forwards

RULE_NO=20000

while IFS= read -r NAT_RULE_LINE
do
  # If the line is empty, end.
  if [ -z "$NAT_RULE_LINE" ]
  then
    break
  fi

  # Tokenize with spaces.
  NAT_RULE=($NAT_RULE_LINE)
  # First token is the inbound interface name (as seen by the guest)
  NAT_IFACE_IN=${NAT_RULE[0]}
  # Second is the untranslated destination address
  NAT_DEST=${NAT_RULE[1]}
  # Fourth is the translated destination address
  NAT_TRANSLATION=${NAT_RULE[2]}
  # Get the netmask for the inbound interface from context.
  CONTEXT_VAR_NIC_MASK=${NAT_IFACE_IN^^}_MASK
  PREFIXLEN=`mask2cdr ${!CONTEXT_VAR_NIC_MASK}`

  $WRAPPER set nat destination rule $RULE_NO inbound-interface $NAT_IFACE_IN
  $WRAPPER set nat destination rule $RULE_NO destination address $NAT_DEST
  $WRAPPER set nat destination rule $RULE_NO protocol ip
  $WRAPPER set nat destination rule $RULE_NO translation address $NAT_TRANSLATION
  
  # Add the destination address to the inbound interface.
  $WRAPPER set interfaces ethernet $NAT_IFACE_IN address $NAT_DEST/$PREFIXLEN
  
  let "RULE_NO+=1"
done <<< "$NAT_DNATS"

##### SCORING RELAY 1:1 NATS
# Here, we're receiving rules of the following form, one per line:
#  RELAY_IN_IFACE RELAY_ADDR_PREFIX PIVOT_OUT_IFACE TARGET_ADDR_PREFIX [PIVOT_GATEWAY]

RULE_NO=40000

while IFS= read -r NAT_RULE_LINE
do
  # If the line is empty, end.
  if [ -z "$NAT_RULE_LINE" ]
  then
    break
  fi

  # Tokenize with spaces.
  NAT_RULE=($NAT_RULE_LINE)
  
  RELAY_IN_IFACE=${NAT_RULE[0]}
  RELAY_ADDR_PREFIX=${NAT_RULE[1]}
  PIVOT_OUT_IFACE=${NAT_RULE[2]}
  TARGET_ADDR_PREFIX=${NAT_RULE[3]}
  PIVOT_GW=${NAT_RULE[4]} # Optional

  # RELAY_PREFIXLEN is the CIDR prefixlen of the relay network
  CONTEXT_VAR_NIC_MASK=${RELAY_IN_IFACE^^}_MASK
  RELAY_PREFIXLEN=`mask2cdr ${!CONTEXT_VAR_NIC_MASK}`

  # Add gateway if provided
  if [ -n "$PIVOT_GW" ]
  then
    # TODO: implement
  fi

  # Stuff sent out PIVOT_OUT_IFACE gets its source address changed to MASQ.
  $WRAPPER set nat source rule $RULE_NO outbound-interface $PIVOT_OUT_IFACE
  $WRAPPER set nat source rule $RULE_NO translation address masquerade

  for last_octet in {1..255}
  do
    # And stuff to RELAY_ADDR_PREFIX.x gets its destination changed to TARGET_ADDR_PREFIX.x
    $WRAPPER set nat destination rule $RULE_NO inbound-interface $RELAY_IN_IFACE
    $WRAPPER set nat destination rule $RULE_NO destination address $RELAY_ADDR_PREFIX.$last_octet
    $WRAPPER set nat destination rule $RULE_NO translation address $TARGET_ADDR_PREFIX.$last_octet
    # Add the interface address: 
    $WRAPPER set interfaces ethernet $RELAY_IN_IFACE $RELAY_ADDR_PREFIX.$last_octet/$RELAY_PREFIXLEN
    
    let "RULE_NO+=1"
  done

done <<< "$SCORING_RELAY_NATS"

##### Done---commit.
##############################################################################

$WRAPPER commit 
$WRAPPER end 

echo "Contextualized. OK to delete /opt/vyatta/sbin/vyatta-vmcontext.sh"
