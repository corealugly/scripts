#!/bin/bash

set -x
set -eo pipefail
shopt -s lastpipe

POSITIONAL_ARGS=()

_HELP="\
Usage: $(basename $0) [OPTIONS]

Options:
  -i|--interface  STRING  search client ip in interface config
  -m|--merge              add client *.conf to interface.conf
  -4|--get_next_ipv4      get next free ip
  -a|--create_user UUID   add new user
  -d|--delete_user UUID   delete user by uuid
  -l|--list_user          get list user uuid 
"

if [[ $# == 0 ]]; then set -- "-h"; fi

while [[ $# -gt 0 ]]; do
  case $1 in
    -i|--interface)
      INTERFACE="${2}"
      CREATE_INTERFACE=true
      shift # past argument
      shift # past value
      ;;
    -m|--merge)
      MERGE=true
      shift # past argument
      #shift # past value
      ;;
    -4|--get_next_ipv4)
      GET_NEXT_IPV4=true
      shift # past argument
      ;;
    -a|--create_user)
      CLIENT_UUID="${2}"
      CREATE_USER=true
      shift # past argument
      shift # past value
      ;;
    -d|--delete_user)
      CLIENT_UUID="${2}"
      DELETE_USER=true
      shift # past argument
      shift # past value
      ;;
    -l|--list_user)
      LIST_USER=true
      shift # past argument
      ;;
    -h|--help)
      echo "${_HELP}"
      exit 0
      shift # past argument
      shift # past value
      ;;
    -*|--*)
      echo "Unknown option ${1}"
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("${1}") # save positional arg
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

INTERFACE=${INTERFACE:-''}
CLIENT_UUID=${CLIENT_UUID:-''}
CREATE_USER="${CREATE_USER:-false}"
DELETE_USER=${DELETE_USER:-false}
GET_NEXT_IPV4="${GET_NEXT_IPV4:-false}"
LIST_USER="${LIST_USER:-false}"
MERGE="${MERGE:-false}"

function main() {
    dpkg -s wireguard &> /dev/null || (echo "Пакет wireguard НЕ установлен"; exit 1;);

    if ${LIST_USER}; then get_list_user; exit 0; fi
    if ${GET_NEXT_IPV4}; then VERBOSE=true find_next_ipv4; exit 0; fi
    if ${CREATE_USER}; then create_user; exit 0; fi
    if ${DELETE_USER}; then delete_user; exit 0; fi
    #if ${CREATE_INTERFACE}; then create_wg_interface_config; exit 0; fi
    if ${MERGE}; then merge; exit 0; fi

}

function merge() {
local wg_interface=${INTERFACE:-'wg0'}

#remove Peers from ${wg_interface}.conf 
sed -i '/\[Peer\]/,$d;' /etc/wireguard/${wg_interface}.conf 
sed -i ':a; /^\n*$/ { $d; N; ba; }' /etc/wireguard/${wg_interface}.conf 

mapfile -t clients < <(find /etc/wireguard/clients/ -iname "*.${wg_interface}.server.conf")
for client in ${clients[@]};
do
    echo "" >> /etc/wireguard/${wg_interface}.conf
    cat ${client} >> /etc/wireguard/${wg_interface}.conf
done

cat << EOF
------
file: /etc/wireguard/${wg_interface}.conf
------
$(cat /etc/wireguard/${wg_interface}.conf)
EOF
}

function asksure() {
local message="${1:-'Are you sure'}"
echo -n "${message} (Y/N)? "
while read -r -n 1 -s answer; do
  if [[ $answer = [YyNn] ]]; then
    [[ $answer = [Yy] ]] && retval=0
    [[ $answer = [Nn] ]] && retval=1
    break
  fi
done

echo # just a final linefeed, optics...

return $retval
}

function create_wg_interface_config() {
local wg_interface=${INTERFACE:-''}
local wg_port=${PORT:-'51820'}
local wg_address_cidr=${ADDRESS_CIRD:-'172.0.0.1/24'}

if [[ -z "${wg_interface}" ]]; then echo "ERROR: interface not set"; return 1; fi
if [[ -e /etc/wireguard/${wg_interface}.key  ||
      -e /etc/wireguard/${wg_interface}.pub  ||
      -e /etc/wireguard/${wg_interface}.conf ]]; then  echo "ERROR: interface /etc/wireguard/${wg_interface}.* exist";
                                                       find /etc/wireguard/ -iname "${wg_interface}.*";
						       return 1; fi

umask 077
wg genkey > /etc/wireguard/${wg_interface}.key
wg pubkey < /etc/wireguard/${wg_interface}.key > /etc/wireguard/${wg_interface}.pub

cat > /etc/wireguard/${wg_interface}.conf << EOF
[Interface]
ListenPort = ${wg_port}
Address = ${wg_address_cidr}
PostUp = wg set %i private-key /etc/wireguard/%i.key
EOF
}


function delete_user() {
    # Регулярное выражение для UUID
    regex='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    if [[ ${CLIENT_UUID} =~ $regex ]]; then
        #"find /etc/wireguard/clients/ -iname \"*${USER}*\"  -delete"
        echo "find /etc/wireguard/clients/ -iname \"*${CLIENT_UUID}*\"  -delete"
    fi
}

function find_next_ipv4() {
    local verbose=${VERBOSE:-false}
    if ! [[ -d /etc/wireguard/clients ]]; then echo "INFO: /etc/wireguard/clients/ directory not exist"; mkdir /etc/wireguard/clients/ -p; fi
    #if [[ ${INTERFACE} != '' ]]; then
    #    NETWORK_LIST_IPV4=$(sed -nr "/^\[Peer\]/ { :l /^AllowedIPs =/ { s/.*=[ ]*//; p; }; n; b l; }" /etc/wireguard/${INTERFACE}.conf | awk -F ',' '{print $1}')
    #    #NETWORK_LIST_IPV6=$(sed -nr "/^\[Peer\]/ { :l /^AllowedIPs =/ { s/.*=[ ]*//; p; }; n; b l; }" /etc/wireguard/${INTERFACE}.conf | awk -F ',' '{print $2}')
    #else
    for client in $(find /etc/wireguard/clients/ -iname '*.client.conf' );
    do
        NETWORK_LIST_IPV4="$(sed -nr "/^Address/{ s/.*=[ ]*//; p; } " ${client} | awk -F ',' '{print $1}') ${NETWORK_LIST_IPV4}"
    done
    #fi

    for cidr in ${NETWORK_LIST_IPV4};
    do 
    	IP=$(awk -F '/' '{print $1}' <<< ${cidr});
            awk -F '.' '{print $0 " " $1 * 256 * 256 * 256 + $2 * 256 * 256 + $3 * 256 + $4}' <<< ${IP};
    done | sort -hk 2 | tail -n 1 | awk '{print $1}' | ipv4_max=$(</dev/stdin); [ -z "${ipv4_max}" ] && ipv4_max='172.0.0.1'

    #echo "ipv4_max: ${ipv4_max}"
    if ${verbose}; then
        echo $(get_next_ipv4 ${ipv4_max})
        #get_next_ipv6 ${ipv6_max}
    else
        echo $(get_next_ipv4 ${ipv4_max} | awk '{print $NF}')
    fi
}

function create_user() {
local wg_interface=${INTERFACE:-'wg0'}
local client_uuid=${CLIENT_UUID:-$(cat /proc/sys/kernel/random/uuid)}
if ! [[ -e /etc/wireguard/${wg_interface}.conf ]]; then 
    echo "INFO: /etc/wireguard/${wg_interface}.conf not exist";
    if (asksure "Create intreface: ${wg_interface}"); then create_wg_interface_config; fi
fi
if ! [[ -d /etc/wireguard/clients ]]; then echo "INFO: /etc/wireguard/clients/ directory not exist"; mkdir /etc/wireguard/clients/ -p; fi

client_ipv4="$(find_next_ipv4)/32"
wg genkey > /etc/wireguard/clients/${client_uuid}.${wg_interface}.key
client_psk=$(wg genpsk)
client_private=$(cat /etc/wireguard/clients/${client_uuid}.${wg_interface}.key)
client_public=$(wg pubkey < /etc/wireguard/clients/${client_uuid}.${wg_interface}.key)
server_ip=$(curl -q https://ifconfig.me)
server_private=$(cat /etc/wireguard/${wg_interface}.key)
server_public=$(cat /etc/wireguard/${wg_interface}.pub)

cat > /etc/wireguard/clients/${client_uuid}.${wg_interface}.server.conf << EOF
[Peer]  
PublicKey = ${client_public}
PresharedKey = ${client_psk}
AllowedIPs = ${client_ipv4} 
Endpoint = ${server_ip}:51820
EOF

cat > /etc/wireguard/clients/${client_uuid}.${wg_interface}.client.conf << EOF
[Interface]
Address = ${client_ipv4}
DNS = 1.1.1.1
ListenPort = 25694
MTU = 1280
PrivateKey = ${client_private}

[Peer]
AllowedIPs = 172.0.0.0/24
Endpoint = ${server_ip}:51820
PersistentKeepalive = 25
PresharedKey = ${client_psk}
PublicKey = ${server_public}
EOF
}

function get_list_user() {
    find /etc/wireguard/clients/ -iname '*.client.conf' | awk -F '/' '{print $NF}' | awk -F '.' '{print $1}'
}

function get_next_ipv4() {
    local ip="${1}"

    if [[ -z "${ip}" ]]; then echo "ERROR: need 1 arg"; return 1; fi

    for iter in `seq 4`;
    do
        ip_octets+=(${ip%%.*})
        ip=${ip#*.*}
    done

    counter=$(( (${ip_octets[0]}<<24) + \
	        (${ip_octets[1]}<<16) + \
		(${ip_octets[2]}<<8) + \
		 ${ip_octets[3]} ))
    
    ((counter+=1))
    
    # Преобразуем число в IP-адрес
    printf "Next ipv4: %d.%d.%d.%d\n" \
        $(( (counter >> 24) & 255 )) \
        $(( (counter >> 16) & 255 )) \
        $(( (counter >> 8)  & 255 )) \
        $((  counter        & 255 ))
}

function get_next_ipv6() {
    echo "#todo ipv6 in future"
}

main
exit $?
