#!/bin/bash

#set -x
set -eo pipefail
shopt -s lastpipe

#initialise default variable
CREATE=false
DELETE=false
FORCE=false
LIST_USER=false
NEXT_IPV4=false
NEXT_IPV6=false
INTERFACE='wg0'
PORT="51820"
IPV4_CIDR='172.0.0.1/24'
IPV6_CIDR='fd00::1/64'
CLIENT_UUID=$(cat /proc/sys/kernel/random/uuid)

POSITIONAL_ARGS=()

function show_help { 
    cat << EOF
Usage: ${0} [GLOBAL_OPTIONS] <action> [ACTION_OPTIONS]

Global Options:
  -h, --help         Show this help message

Available Actions:
  server   
    Options:
      -c,--create           Create interface
      -d,--delete           Delete interface
      -i,--interface STRING WG interface name
      -p,--port      STRING port
      -4,--ipv4             add ipv4 subnet for wg private network
      -6,--ipv6             add ipv6 subnet for wg private network
      -m,--merge            add client *.server.conf to wg*.conf
  client   
    Options:
      -c,--create           Create client config
      -d,--delete           Delete client config
      -i,--interface STRING WG intreface name
      -u,--uuid      STRING client uuid  *.key *.wg*.server.conf *.wg*.client.conf
      --next_ipv4           get next free ip
      --next_ipv6           get next free ip
      -l,--list_user        get list user uuid

EOF
    exit 0
}

if [[ $# == 0 ]]; then set -- "-h"; fi


# Функция для обработки ошибок
die() {
    echo "Error: $1" >&2
    exit 1
}

# Парсинг глобальных опций
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        server|client)
            ACTION="$1"
            shift
            # Переходим к парсингу опций действия
            break
            ;;
        --)
            shift
            INPUT_FILES+=("$@")
            break
            ;;
        -*)
            die "Unknown global option: $1"
            ;;
        *)
            # Если встретили не-опцию до указания действия
            die "Action must be specified before input files"
            ;;
    esac
done

while [[ $# -gt 0 ]]; do
  case ${ACTION} in
    server)
      case $1 in
        -c|--create)
          CREATE=true
          shift 
          ;;
        -d|--delete)
          DELETE=true
          shift 
          ;;
        #-f|--force)
        #  FORCE=true
        #  shift
        #  ;;
        -i|--interface)
          if [[ -z "$2" || "$2" == -* ]]; then
              echo "ERROR: name not specified for $1" >&2
              exit 1
          fi
          INTERFACE=${2}
          shift 2
          ;;
        -p|--port)
          PORT=${2}
          shift 2
          ;;
        -4|--ipv4)
          IPV4_CIDR=${2}
          shift 2
          ;;
        -6|--ipv6)
	  IPV6_CIDR=${2}
          shift 2
          ;;
        -m|--merge)
          MERGE=true
          shift 
          ;;
        -*|--*)
          echo "Unknown option ${1}"
          exit 1
          ;;
        *)
          POSITIONAL_ARGS+=("${1}") # save positional arg
          shift
          ;;
      esac
      ;;

    client)
      case $1 in
        -c|--create)
          CREATE=true
          shift 
          ;;
        -d|--delete)
          DELETE=true
          shift 
          ;;
        #-f|--force)
        #  FORCE=true
        #  shift
        #  ;;
        -i|--interface)
          INTERFACE="${2}"
          shift 2
          ;;
        -n|--name|--comment)
          if [[ -z "$2" || "$2" == -* ]]; then
              echo "ERROR: name not specified for $1" >&2
              exit 1
          fi
          COMMENT="${2}"
          shift 2 
          ;;
        -u|--uuid)
          CLIENT_UUID="${2}"
          shift 2
          ;;
        -l|--list_user)
          LIST_USER=true
          shift
          ;;
        --next_ipv4)
          NEXT_IPV4=true
          shift 
          ;;
        --next_ipv6)
	  NEXT_IPV6=true
          shift 
          ;;
        -*|--*)
          echo "Unknown option ${1}"
          exit 1
          ;;
        *)
          POSITIONAL_ARGS+=("${1}") # save positional arg
          shift
          ;;
      esac
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

function main() {
    dpkg -s wireguard &> /dev/null || (echo "Пакет wireguard НЕ установлен"; exit 1;);

    case ${ACTION} in
        client)
            if ${NEXT_IPV4}; then VERBOSE=true find_next_ipv4; exit 0; fi
            #if ${NEXT_IPV6}; then VERBOSE=true find_next_ipv6; exit 0; fi
            if ${LIST_USER}; then get_list_user; exit 0; fi
            if ${CREATE}; then create_client; exit 0; fi
            if ${DELETE}; then delete_client; exit 0; fi
	    ;;
	server)
            if ${CREATE}; then create_wg_interface_config; exit 0; fi
            if ${DELETE}; then delete_wg_interface_config; exit 0; fi
            if ${MERGE}; then merge; exit 0; fi
	    ;;
    esac    
}

function merge() {
local wg_interface=${INTERFACE:-'wg0'}

if ! [[ -e /etc/wireguard/${wg_interface}.conf ]]; then 
    echo "INFO: /etc/wireguard/${wg_interface}.conf not exist";
    if (asksure "Create intreface: ${wg_interface}"); then create_wg_interface_config; fi
fi

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

function delete_wg_interface_config() {
local wg_interface=${INTERFACE:-''}
if [[ -z "${wg_interface}" ]]; then die "interface not set"; fi
if (asksure "Delete intreface: ${wg_interface}"); then 
    find /etc/wireguard/ -maxdepth 1 \
                         -type f \
                         -regextype posix-extended  \
                         -iregex ".*${wg_interface}\.(conf|key|pub)$" \
                         -print \
                         -delete
fi
}

function create_wg_interface_config() {
local wg_interface=${INTERFACE:-'wg0'}
local wg_port=${PORT:-'51820'}
local wg_ipv4_cidr=${IPV4_CIDR:-'172.0.0.1/24'}
#local wg_ipv6_cidr=${IPV6_CIDR:-'fd00::1/64'}

if [[ -z "${wg_interface}" ]]; then die "interface not set"; fi
if [[ -e /etc/wireguard/${wg_interface}.key  ||
      -e /etc/wireguard/${wg_interface}.pub  ||
      -e /etc/wireguard/${wg_interface}.conf ]]; then
    find /etc/wireguard/ -iname "${wg_interface}.*";
    die "interface /etc/wireguard/${wg_interface}.* exist";
fi

umask 077
wg genkey > /etc/wireguard/${wg_interface}.key
wg pubkey < /etc/wireguard/${wg_interface}.key > /etc/wireguard/${wg_interface}.pub

cat > /etc/wireguard/${wg_interface}.conf << EOF
[Interface]
ListenPort = ${wg_port}
Address = ${wg_ipv4_cidr}
#Address = ${wg_ipv6_cidr}
PostUp = wg set %i private-key /etc/wireguard/%i.key
EOF

echo "Created ${wg_interface} - key, pub, config"
find /etc/wireguard/ -maxdepth 1 \
                     -type f \
                     -regextype posix-extended  \
                     -iregex ".*${wg_interface}\.(conf|key|pub)$" \
                     -print 
}

function delete_client() {
    local wg_interface=${INTERFACE}
    local client_uuid=${CLIENT_UUID}

    # Регулярное выражение для UUID
    regex='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

    if [[ ${client_uuid} =~ $regex &&
	  -e /etc/wireguard/clients/${client_uuid}.${wg_interface}.key ]] &&
	  (asksure "Delete client: ${client_uuid}"); then
        find /etc/wireguard/clients/ -maxdepth 1 \
		                     -type f \
				     -iname "*${client_uuid}*" \
				     -print \
				     -delete
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

function create_client() {
local wg_interface=${INTERFACE:-'wg0'}
local client_uuid=${CLIENT_UUID:-$(cat /proc/sys/kernel/random/uuid)}
if [[ ${COMMENT} != '' ]]; then
    local comment="#Comment: ${COMMENT:-''}"
else
    local comment=''
fi

if ! [[ -e /etc/wireguard/${wg_interface}.conf ]]; then 
    echo "INFO: /etc/wireguard/${wg_interface}.conf not exist";
    if (asksure "Create intreface: ${wg_interface}"); then create_wg_interface_config; fi
fi
if ! [[ -d /etc/wireguard/clients ]]; then 
    echo "INFO: /etc/wireguard/clients/ directory not exist";
    mkdir /etc/wireguard/clients/ -p; fi

if find /etc/wireguard/clients/ -maxdepth 1 \
	                        -name "*${client_uuid}*" \
				-print \
				-quit | grep -q .; then 
    die "/etc/wireguard/clients/${client_uuid}.* exist";
fi

#todo - add options from args 
client_ipv4="$(find_next_ipv4)/32"
umask 077
client_private=$(wg genkey | tee /etc/wireguard/clients/${client_uuid}.${wg_interface}.key)
client_public=$(wg pubkey < /etc/wireguard/clients/${client_uuid}.${wg_interface}.key)
client_psk=$(wg genpsk)
server_private=$(cat /etc/wireguard/${wg_interface}.key)
server_public=$(cat /etc/wireguard/${wg_interface}.pub)
server_ip=$(curl -qs https://ifconfig.me)

cat > /etc/wireguard/clients/${client_uuid}.${wg_interface}.server.conf << EOF
[Peer] ${comment}  
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

cat << EOF
Created key, client/server config
*.key: /etc/wireguard/clients/${client_uuid}.${wg_interface}.key
*.server.conf: /etc/wireguard/clients/${client_uuid}.${wg_interface}.server.conf
*.client.conf: /etc/wireguard/clients/${client_uuid}.${wg_interface}.client.conf
EOF

}

function get_list_user() {
    if ! [[ -d /etc/wireguard/clients ]]; then
        echo "INFO: /etc/wireguard/clients/ directory not exist";
	echo "INFO: Creating /etc/wireguard/clients/"
	mkdir /etc/wireguard/clients/ -p; fi
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
