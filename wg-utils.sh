#!/bin/bash

#set -x
set -eo pipefail
shopt -s lastpipe

POSITIONAL_ARGS=()

_HELP="\
Usage: $(basename $0) [OPTIONS]

Options:
  -i|--interface  STRING  search client ip in interface config
  -4|--get_next_ipv4      get next free ip
  -l|--list_user          get list user uuid 
  -a|--add_user           add new user
  -d|--delete_user STRING delete user by uuid
"

if [[ $# == 0 ]]; then set -- "-h"; fi

while [[ $# -gt 0 ]]; do
  case $1 in
    -i|--interface)
      INTERFACE="${2}"
      shift # past argument
      shift # past value
      ;;
    -4|--get_next_ipv4)
      GET_NEXT_IPV4=true
      shift # past argument
      ;;
    -a|--add_user)
      ADD_USER=true
      shift # past argument
      ;;
    -l|--list_user)
      LIST_USER=true
      shift # past argument
      ;;
    -d|--delete_user)
      USER="${2}"
      DELETE_USER=true
      shift # past argument
      shift # past value
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
      #echo "hello"
      POSITIONAL_ARGS+=("${1}") # save positional arg
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

INTERFACE=${INTERFACE:-'wg0'}
USER=${USER:-''}
DELETE_USER=${DELETE_USER:-false}
GET_NEXT_IPV4="${GET_NEXT_IPV4:-false}"
LIST_USER="${LIST_USER:-false}"
ADD_USER="${ADD_USER:-false}"

function main() {
    dpkg -s wireguard &> /dev/null || (echo "Пакет wireguard НЕ установлен"; exit 1;);

    if ${LIST_USER}; then get_list_user; exit 0; fi
    if ${GET_NEXT_IPV4}; then VERBOSE=true find_next_ipv4; exit 0; fi
    if ${ADD_USER} && [[  ${INTERFACE} != '' ]];then echo "hello"; exit 0; add_new_user; exit 0; fi
    if [[ ${DELETE_USER} ]]; then delete_user; exit 0; fi

}

function delete_user() {
    # Регулярное выражение для UUID
    regex='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    if [[ ${USER} =~ $regex ]]; then
        #"find /etc/wireguard/clients/ -iname \"*${USER}*\"  -delete"
        echo "find /etc/wireguard/clients/ -iname \"*${USER}*\"  -delete"
    fi
}

function find_next_ipv4() {
    local verbose=${VERBOSE:-false}
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
    done | sort -hk 2 | tail -n 1 | awk '{print $1}' | ipv4_max=$(</dev/stdin)
    
    if ${VERBOSE}; then 
        echo $(get_next_ipv4 ${ipv4_max})
        #get_next_ipv6 ${ipv6_max}
    else
        echo $(get_next_ipv4 ${ipv4_max} | awk '{print $NF}')
    fi
}


function add_new_user() {
mkdir /etc/wireguard/clients/ -p

client_ipv4=$(find_next_ipv4)/32
wg_interface="${INTERFACE}"

client_uuid=$(cat /proc/sys/kernel/random/uuid)
wg genkey > ${client_uuid}.key
client_psk=$(wg genpsk)
client_private=$(cat ${client_uuid}.key)
client_public=$(wg pubkey < ${client_uuid}.key)
server_ip=$(curl -q https://ifconfig.me)
server_private=$(cat /etc/wireguard/${wg_interface}.key)
server_public=$(cat /etc/wireguard/${wg_interface}.pub)

cat > ${client_uuid}.server.conf << EOF
[Peer]
PublicKey = ${client_public}
PresharedKey = ${client_psk}
AllowedIPs = ${client_ipv4} 
Endpoint = ${server_ip}:51820
EOF

cat > ${client_uuid}.client.conf << EOF
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
