#!/bin/bash

CONF_DIRECTORY="./CONF"
FILE_CONF="$CONF_DIRECTORY/config.conf"

if [ -f $FILE_CONF ];
then
	source $FILE_CONF
fi

function clean {
    cleaned="$(echo $1 | sed -e 's/\;/ /g' | sed -e ':a;N;$!ba;s/\n/,/g')"
    echo $cleaned
}

function log {
    if [ "$debug" == "1" ];
    then
        echo "$(date +%d/%m/%y-%H:%M:%S) - $1" >> $FILE_LOG
    fi
}

function inicializar_directorio {
	if [ ! -d $1 ];
	then
		mkdir -p $1
	fi
}

function inicializar_archivo {
	if [ ! -f $1 ];
	then
		touch $1
	fi
}

function blackList {
    log "Ingresando a ${FUNCNAME[0]}."
	inicializar_archivo $FILE_BLACK_LIST
    res="no_existe"
    INPUT=$FILE_BLACK_LIST
    IFS=";"
    while read IP DES
    do
        if [ "$1" == "$IP" ] ;
        then
            res="existe"
            log "El host $1, $res en la lista negra."
        fi        
    done<$INPUT
    echo $res
}

function inicializar_conf {
	inicializar_directorio $CONF_DIRECTORY
	echo 'debug=1' >> "$FILE_CONF"
	echo 'ssh_ports=(22 57032)' >> "$FILE_CONF"
	echo 'networks=(10.0.30.0)' >> "$FILE_CONF"
	echo 'rdp_ports=(3389)' >> "$FILE_CONF"
	echo 'backups=(/etc /var /home /root /opt/bacula)' >> "$FILE_CONF"
	echo 'TEMP_DIRECTORY=./TEMP' >> "$FILE_CONF"
	echo 'LOGS_DIRECTORY=./LOGS' >> "$FILE_CONF"
	echo 'OUTS_DIRECTORY=./OUTS' >> "$FILE_CONF"
	echo 'BACKUPS_DIRECTORY=./BACKUPS' >> "$FILE_CONF"
	echo 'SCRIPTS_DIRECTORY=./SCRIPTS' >> "$FILE_CONF"
	echo 'REPORTS_DIRECTORY=$OUTS_DIRECTORY/$(date +%d%m%y)' >> "$FILE_CONF"
	echo 'FILE_REPORT_HORIZONTAL=$REPORTS_DIRECTORY/informe_horizontal_$(date +%d%m%y).csv' >> "$FILE_CONF"
	echo 'FILE_REPORT_VERTICAL=$REPORTS_DIRECTORY/informe_vertical_$(date +%d%m%y).txt' >> "$FILE_CONF"
	echo 'FILE_REPORT_STATISTICS=$REPORTS_DIRECTORY/informe_estadisticas_$(date +%d%m%y).txt' >> "$FILE_CONF"
	echo 'FILE_LOG=$LOGS_DIRECTORY/log_informe_$(date +%d%m%y).log' >> "$FILE_CONF"
	echo 'FILE_CREDENTIALS=$CONF_DIRECTORY/credentials.csv' >> "$FILE_CONF"
	echo 'FILE_IPS=$CONF_DIRECTORY/ips.csv' >> "$FILE_CONF"
	echo 'FILE_IPS_PORTS=$CONF_DIRECTORY/ips_ports.csv' >> "$FILE_CONF"
	echo 'FILE_IPS_PORTS_USER_PASS=$CONF_DIRECTORY/ips_ports_user_pass.csv' >> "$FILE_CONF"
	echo 'FILE_IPS_PORTS_USER_PASS_SO=$CONF_DIRECTORY/ips_ports_user_pass_so.csv' >> "$FILE_CONF"
	echo 'FILE_BLACK_LIST=$CONF_DIRECTORY/blacklist.csv' >> "$FILE_CONF"
}

function inicializar_estructura {
	while read line;
	do
		if [[ "$(echo $line | awk -F'=' '{print $1}')" == *"DIRECTORY"* ]];
		then
			var=$(echo $line | awk -F'=' '{print $1}')
            inicializar_directorio ${!var}
		#elif [[ "$line" == *"FILE"* ]];
		#then
		#	var=$(echo $line | awk -F'=' '{print $1}')
        #    inicializar_archivo ${!var}
		fi
	done < $FILE_CONF
}


function getAccessData { 
    log "Ingresando a ${FUNCNAME[0]}."
    INPUT=$FILE_CREDENTIALS
    IFS=";"
    while read USER PASS 
    do
        if [ "$debug" == "1" ];
        then
            log "Probando $USER y $(echo $PASS | base64) en server : $1:$2"
        fi
        hi="$(sshpass -p "$PASS" ssh -t -o StrictHostKeyChecking=no -n -p "$2" "$USER"@"$1" "echo hi 2>/dev/null" 2>/dev/null)"
        if [ "$hi" == "hi" ];
        then
            credential="$USER $PASS"
            log "Encontradas Credenciales de server $1."
            break
        fi
    done<$INPUT
	
    if [ "$credential" == "" ];
    then
        log "Credenciales para servidor $1:$2 invalidas."
    else
        echo $credential
    fi
}

function generarIps {
	log "Ingresando a ${FUNCNAME[0]}."
    for i in "${networks[@]}"
    do
        filtro=$(echo $i | awk -F'.' '{print $1"."$2"."$3"."}')
		nmap -sL -n $i/24 | grep "$filtro" | grep -vw "${filtro}0\|${filtro}1\|${filtro}255" | awk '{print $5}'> $FILE_IPS
    done
}

function getAccessPort {
    log "Ingrensando a método : ${FUNCNAME[0]} con parámetro : $1"
	
	for i in "${ssh_ports[@]}"
	do
		flag=$(nmap -Pn -host-timeout 20s -p $i $1|grep 'open'|grep tcp|awk '{print $1}'|sed 's/\/tcp//g'|sort|uniq)
		if [ ! "$flag" == "" ] ;
		then
			port="SSH;$i"
			break
		fi
	done
	
	if [ "$port" == "" ];
	then
		for j in "${rdp_ports[@]}"
		do
			flag=$(nmap -Pn -host-timeout 20s -p $j $1|grep 'open'|grep tcp|awk '{print $1}'|sed 's/\/tcp//g'|sort|uniq)
			if [ ! "$flag" == "" ] ;
			then
				port="RDP;$j"
				break
			fi

			if [ "$port" == "" ];
			then
				port="NO_ACCESS_PROTOCOL;NO_ACCESS_PORT"
			fi
		done
	fi
    echo "$port"
}

function generarPuertosAccesoServidores {
    log "Ingresando a ${FUNCNAME[0]}"
    IFS=";"
    while read IP;
    do
        PUERTO=$(getAccessPort $IP)
        log "Puerto de acceso indentificado para servidor $IP : $PUERTO..."
        echo "$IP;$PUERTO" >> $FILE_IPS_PORTS
    done < $FILE_IPS
}

function generarDatosAccesoServidores {
    log "Ingresando a ${FUNCNAME[0]}"
    IFS=";"
    while read IP PROTOCOL PUERTO;
    do
        if [ "$PROTOCOL" == "SSH" ];
        then
            if [ "$(blackList $IP)" == "no_existe" ];
            then
                credentials="$(getAccessData $IP $PUERTO)"
                if [ ! $credentials == "" ];
                then
                    user="$(echo "$credentials"| awk '{print $1}')"
                    pass="$(echo "$credentials" | awk '{print $2}')"
                else
                    user="unknown"
                    pass="unknown"
                fi
                echo "$IP;$PROTOCOL;$PUERTO;$user;$pass" >> $FILE_IPS_PORTS_USER_PASS
            fi
        fi
    done < $FILE_IPS_PORTS
}

function generarSoServidores {
    log "Ingresando a ${FUNCNAME[0]}"
    IFS=";"
    while read IP PROTOCOL PUERTO USER PASS;
    do
        if [ ! "$USER" == "unknown" ];
        then
            SO="$(getSo $IP $PUERTO $PASS $USER)"
			echo "$IP;$PROTOCOL;$PUERTO;$USER;$PASS;$SO" >> $FILE_IPS_PORTS_USER_PASS_SO
        fi
    done < $FILE_IPS_PORTS_USER_PASS
}

function getHosts {
    log "Ingresando a ${FUNCNAME[0]}."
    hosts=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 cat /etc/hosts | grep -v "#")
    cleaned="$(clean $hosts)"
    echo "$cleaned"
}

function getUsers {
    log "Ingresando a ${FUNCNAME[0]}."
    users=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 cat /etc/passwd | awk -F':' '{print $1}' 2>/dev/null)
    cleaned="$(clean $users)"
    echo "$cleaned"
}

function getGroups {
    log "Ingresando a ${FUNCNAME[0]}."
    groups=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 'cat /etc/group 2>/dev/null' 2>/dev/null)
    cleaned="$(clean $groups)"
    echo "$cleaned"
}

function getEnv {
    log "Ingresando a ${FUNCNAME[0]}."
    env=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 'env 2>/dev/null' 2>/dev/null)
    if [ "$env" == "" ];
    then
        env=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 'printenv 2>/dev/null' 2>/dev/null)        
    fi
    cleaned="$(clean $env)"
    echo "$cleaned"
}

function getRoutes {
    log "Ingresando a ${FUNCNAME[0]}."
    routes=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 'route -n 2>/dev/null' 2>/dev/null)
    if [ "$routes" == "" ];
    then
        routes=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 'netstat -rn 2>/dev/null' 2>/dev/null)
        if [ "$routes" == "" ];
        then
            routes=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 'ip route list 2>/dev/null' 2>/dev/null)
        fi
    fi
    echo "$routes"
}

function getActiveServices {
    log "Ingresando a ${FUNCNAME[0]}."
	if [ "$4" == "root" ];
	then
		activeServices=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "systemctl list-units --type=service --state=active 2>/dev/null" 2>/dev/null)
		if [ "$activeServices" == "" ];
		then
			activeServices=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "service --status-all 2>/dev/null" 2>/dev/null)
		fi
	else
		activeServices=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "echo $3 | sudo systemctl list-units --type=service --state=active 2>/dev/null" 2>/dev/null)
		if [ "$activeServices" == "" ];
		then
			activeServices=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "echo $3 | sudo service --status-all 2>/dev/null" 2>/dev/null)
		fi
	fi	
    echo $activeServices
}

function getCrons  {
    log "Ingresando a ${FUNCNAME[0]}."
	if [ "$4" == "root" ];
	then
		cron=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "find /var/spool/cron/ -type f -exec echo {} \; -exec cat {} \; 2>/dev/null" 2>/dev/null)
		if [ "$cron" == "" ];
		then
			cron=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "cat /var/spool/cron/* 2>/dev/null" 2>/dev/null)
		fi
	else
		cron=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "echo $3 | sudo find /var/spool/cron/ -type f -exec echo {} \; -exec cat {} \; 2>/dev/null" 2>/dev/null)
		if [ "$cron" == "" ];
		then
			cron=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "echo $3 | sudo cat /var/spool/cron/* 2>/dev/null" 2>/dev/null)
		fi
	fi
    echo "$cron"
}

function getTimezone  {
    log "Ingresando a ${FUNCNAME[0]}."
	timezone=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "timedatectl 2>/dev/null" 2>/dev/null)
	if [ "$timezone" == "" ];
	then
		timezone=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "cat /etc/sysconfig/clock 2>/dev/null" 2>/dev/null)
	fi
    echo "$timezone"
}

function getLimits {
    log "Ingresando a ${FUNCNAME[0]}."
    limits=$(sshpass -p $3 ssh -o ConnectTimeout=60 -q -n -p $2 $4@$1 "ulimit -a 2>/dev/null" 2>/dev/null)
    echo "$limits"
}

function getSysConf {
    log "Ingresando a ${FUNCNAME[0]}."
    sysconfctl=$(sshpass -p $3 ssh -o ConnectTimeout=60 -q -n -p $2 $4@$1 "cat /etc/sysctl.conf 2>/dev/null" 2>/dev/null)
    echo "$sysconfctl"
}

function getIpLink {
    log "Ingresando a ${FUNCNAME[0]}."
    ipLink=$(sshpass -p $3 ssh -o ConnectTimeout=60 -q -n -p $2 $4@$1 "ip link 2>/dev/null" 2>/dev/null)
    echo "$ipLink"
}

function getOpenPorts {
    log "Ingresando a ${FUNCNAME[0]}."
    if [ "$2" == "" ] && [ "$3" == "" ] && [ "$4" == "" ];
    then
        ports="$(nmap --host-timeout 1m -p 1-65535 $1 | grep 'open' | awk '{print $1" "$3}' 2>/dev/null)"
        if [ "$ports" == "" ];
        then
            ports="$(nmap --host-timeout 1m -Pn $1 | grep 'open' | awk '{print $1" "$3}' 2>/dev/null)"
        fi
    else
        ports=$(sshpass -p $3 ssh -o ConnectTimeout=60 -q -n -p $2 $4@$1 netstat -utan | grep LISTEN | awk '{print $4}' | awk -F':' '{print $NF}' |sort | uniq 2>/dev/null)
    fi
    cleaned="$(clean $ports)"
    echo "$cleaned"
}

function getConections {
    log "Ingresando a ${FUNCNAME[0]}."
    connections=$(sshpass -p $3 ssh -o ConnectTimeout=60 -q -n -p $2 $4@$1 netstat -nat | awk '{print $6}'| sed -e '1,2d' | sort | uniq -c | sort -r| awk '{print $2":"$1}')
    cleaned="$(clean $connections)"
    echo "$cleaned"
}

function getSshUsers {
    log "Ingresando a ${FUNCNAME[0]}."
    ssh=$(sshpass -p "$3" ssh -o ConnectTimeout=10 -q -n -p $2 "$4"@"$1" cat /etc/security/ssh_us.allow 2>/dev/null 2>/dev/null)
    if [ "$ssh" == '' ];
    then
        ssh=$(sshpass -p "$3" ssh -o ConnectTimeout=10 -q -n -p $2 "$4"@"$1" cat /etc/security/ssh.allow 2>/dev/null 2>/dev/null)
    fi
    if [ "$ssh" == '' ];
    then
        echo "Indefinido"
    fi
    echo "$ssh"
}

function getNisService {
    log "Ingresando a ${FUNCNAME[0]}."
    nis=$(sshpass -p "$3" ssh -t -o ConnectTimeout=10 -q -n -p $2 "$4"@"$1" " /etc/init.d/ypbind status 2>/dev/null" 2>/dev/null)
    if [ "$nis" == '' ];
    then
        nis=$(sshpass -p "$3" ssh -t -o ConnectTimeout=10 -q -n -p $2 "$4"@"$1" " cat /etc/security/ssh.allow 2>/dev/null | grep Active" 2>/dev/null)
    fi
    if [ "$nis" == '' ];
    then
        echo "Indefinido"
    fi
    cleaned="$(clean $nis)"
    echo "$cleaned"
}

function getSo {
	log "Ingresando a método : ${FUNCNAME[0]} con parámetro $1"
	redhat_file=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "cat /etc/redhat-release 2>/dev/null |sed 's/ //g'" )
	if [ ! "$redhat_file" == ""  ];
	then
		so="$redhat_file"
	else
		debian_file="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 lsb_release -a 2>/dev/null | grep Description 2>/dev/null |awk '{print $2" "$3" "$4" "$5}' |sed 's/ //g' 2>/dev/null)"
		if [ ! "$debian_file" == "" ];
		then
			so="$debian_file"
		else
			osrelease="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 cat /etc/os-release | grep PRETTY_NAME  | awk -F'=' '{print $2}' | sed 's/ //g' | sed 's/\"//g'  2>/dev/null)"
			if [ ! "$osrelease" == "" ];
			then
				 so="$osrelease"
			else
				hostnamectl="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 hostnamectl | grep "Operating System" | awk -F':' '{print $2}' | sed 's/ //g'  2>/dev/null)"
				if [ ! "$hostnamectl" == "" ];
				then 
					so="$hostnamectl"
				else
					so="unknown"
					log "NO se pudo indentificar el SO del server $1"
				fi
			fi
		fi
	fi        

    echo $so
}

function getPostgresqlService {
    log "Ingresando a ${FUNCNAME[0]}."
    psql=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "/etc/init.d/postgresql* status 2>/dev/null" 2>/dev/null)
    
    if [ "$psql" == '' ];
    then
        psql=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "systemctl -l | grep postgresql 2>/dev/null"  2>/dev/null)
        psql=$(echo $psql | awk '{print $1}')
        
        if [ "$psql" == '' ];
        then
             echo "Indefinido"
        else 
            cleaned="$(clean $psql)"
            echo "$cleaned"
        fi
    else
        cleaned="$(clean $psql)"
        echo "$cleaned"
    fi
}

function getRam {
    log "Ingresando a ${FUNCNAME[0]}."
    memory=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "cat /proc/meminfo | grep MemTotal")
	memory_in_kbs=$(echo $memory | awk '{print $2}')
	memory_in_gbs=$(echo "$memory_in_kbs/1024/1024" |bc )
    echo $memory_in_gbs"GB"
}

function getCpuModel {
    log "Ingresando a ${FUNCNAME[0]}."
    model="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 cat /proc/cpuinfo|grep 'odel name'|sed -e 's/ //g' -e 's/\t//g' -e 's/\r$//' |awk -F':' '{print $2}'|uniq)"
    cleaned="$(clean $model)"
    echo $cleaned
}

function getCpus {
    log "Ingresando a ${FUNCNAME[0]}."
    cpus="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 cat /proc/cpuinfo|grep processor|awk '{print $1}'|sed -e 's/ //g'|wc -l)"
    echo $cpus"CPU" 

}

function getMountPoints {
    log "Ingresando a ${FUNCNAME[0]}."
    disk=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 cat /etc/fstab | grep -v '#'  2>/dev/null)
    echo "$disk"
}

function getFileSystem {
    log "Ingresando a ${FUNCNAME[0]}."
    fileSystem=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 df -h | awk '{print $1,$2,$6}' 2>/dev/null)
	cleaned="$(clean $fileSystem)"
    echo "$cleaned"
}

function getHostname {
    log "Ingresando a ${FUNCNAME[0]}."
    hostname=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 hostname 2>/dev/null)
    echo "$hostname"
}

function getIps {
    log "Ingresando a ${FUNCNAME[0]}."
    ips=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1  ifconfig  2>/dev/null | awk '{print $2}' | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}" 2>/dev/null )
    if [ "$ips" == "" ];
    then
        ips=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 ip a 2>/dev/null | awk '{print $2}' | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}" 2>/dev/null)
    fi

    if [ "$ips" == "" ];
    then
        ips=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "hostname -I 2>/dev/null" 2>/dev/null)
    fi
    cleaned="$(clean $ips)"
    echo "$cleaned"
}

function getKernel {
    log "Ingresando a ${FUNCNAME[0]}."
    
    kernel=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "uname -r  2>/dev/null" 2>/dev/null )
    
    if [ "$kernel" == "" ];
    then
        kernel=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "cat /proc/vesion | awk '{print $3}' 2>/dev/null" 2>/dev/null)
    fi

    if [ "$kernel" == "" ];
    then
        kernel=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "hostname -I 2>/dev/null" 2>/dev/null)
    fi
    cleaned="$(clean $kernel)"
    echo "$cleaned"
}

function getDependencies {
    log "Ingresando a ${FUNCNAME[0]}."
    
    dependencies=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "rpm -qa  2>/dev/null" 2>/dev/null )
    
    if [ "$dependencies" == "" ];
    then
        dependencies=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "apt list --installed 2>/dev/null" 2>/dev/null)
    fi

    if [ "$dependencies" == "" ];
    then
        dependencies=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "dpkg -l | awk '{print $2":"$3}' 2>/dev/null" 2>/dev/null)
    fi
    cleaned="$(clean $dependencies)"
    echo "$cleaned"
}

function getBlocks {
    log "Ingresando a ${FUNCNAME[0]}."
    lsblk=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "lsblk  2>/dev/null" 2>/dev/null )
    echo "$lsblk"
}

function getBlockId {
    log "Ingresando a ${FUNCNAME[0]}."
	if [ "$4" == "root" ];
	then
		blkid=$(sshpass -p $3  ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "blkid 2>/dev/null")
	else
		blkid=$(sshpass -p $3  ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "echo $3 | sudo blkid 2>/dev/null")
	fi
    echo "$blkid"
}

function getFdisk {
    log "Ingresando a ${FUNCNAME[0]}."
	if [ "$4" == "root" ];
	then
		fdisk=$(sshpass -p $3  ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "fdisk -l 2>/dev/null")
	else
		fdisk=$(sshpass -p $3  ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "echo $3 | sudo fdisk -l 2>/dev/null")
	fi
    echo "$fdisk"
}

function getIptables {
    log "Ingresando a ${FUNCNAME[0]}."
	if [ "$4" == "root" ];
	then
		iptables=$(sshpass -p $3  ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "iptables -L 2>/dev/null")
	else
		iptables=$(sshpass -p $3  ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "echo $3 | sudo iptables -L 2>/dev/null")
	fi
    echo "$iptables"
}

function getSesStatus {
    log "Ingresando a ${FUNCNAME[0]}."
	if [ "$4" == "root" ];
	then
		sestatus=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "sestatus 2>/dev/null" 2>/dev/null)
	else
		sestatus=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "echo $3 | sudo sestatus 2>/dev/null" 2>/dev/null)
	fi    
    echo $sestatus

}

function getEnforce {
    log "Ingresando a ${FUNCNAME[0]}."
	if [ "$4" == "root" ];
	then
		getenforce=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "getenforce 2>/dev/null" 2>/dev/null)
	else
		getenforce=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "echo $3 | sudo getenforce 2>/dev/null" 2>/dev/null)
	fi    
    echo $getenforce
}

function getAudit {
    log "Ingresando a ${FUNCNAME[0]}."
	if [ "$4" == "root" ];
	then
		audit=$(sshpass -p $3  ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "auditctl -l 2>/dev/null")
	else
		audit=$(sshpass -p $3  ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "echo $3 | sudo auditctl -l 2>/dev/null")
	fi
    echo "$audit"
}

function getDns {
    log "Ingresando a ${FUNCNAME[0]}."

    dns3="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 cat /etc/resolv.conf |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"  2>/dev/null)"

    if [ "$dns3" == "" ];
    then
        dns2=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 grep -R DNS /etc/sysconfig/network-scripts/ | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3} 2>/dev/null" 2>/dev/null )
        if [  "$dns2" == "" ];
        then
            dns1=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 cat /etc/network/interfaces | grep dns-nameservers  | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3} 2>/dev/null" 2>/dev/null )
            if [ "$dns1"  == "" ];
            then
                dns="undefined"
            else
                cleaned="$(clean $dns1)"
            fi
        else
            cleaned="$(clean $dns2)"
        fi
    else
        cleaned="$(clean $dns3)"
    fi

    echo "$cleaned"
    
}

function getMysqlVersion {
    log "Ingresando a ${FUNCNAME[0]}."
    mysql=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 "$4"@"$1" "mysql --version | grep mysql | sed -e 's/ //g' 2>/dev/null" 2>/dev/null)
    cleaned="$(clean $mysql)"
    echo "$cleaned"
     
}

function getPostgresqlVersion {
    log "Ingresando a ${FUNCNAME[0]}."
    postgresql=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 "$4"@"$1" "psql --version 2>/dev/null | grep psql | sed -e 's/ //g' 2>/dev/null" 2>/dev/null)
    cleaned="$(clean $postgresql)"
}

function getPostgresqlServiceState {
    log "Ingresando a ${FUNCNAME[0]}."
    
    psql=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1  systemctl status postgresql* | grep Active | awk '{print $1" "$2" "$3}'  2>/dev/null)
    
    if [ "$psql" == '' ];
    then
        psql=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1  systemctl -l | grep postgresql | awk '{print $1" "$2" "$3" "$4}'  2>/dev/null)
        if [ "$psql" == '' ];
        then
            psql=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "/etc/init.d/postgresql* status 2>/dev/null" 2>/dev/null)
        fi
    fi
    
    cleaned="$(clean $psql)"
    echo "$cleaned"
}

function getMysqlServiceState {
    log "Ingresando a ${FUNCNAME[0]}."

    mysql=$(echo $3 | sshpass -p $3 ssh -o ConnectTimeout=10 -q -n  -p $2 "$4"@"$1" "sudo /etc/init.d/mysqld* status | grep mysqld 2>/dev/null" 2>/dev/null)
    
    if [ "$mysql" == '' ];
    then
        mysql=$(echo $3 | sshpass -p $3 ssh -o ConnectTimeout=10 -q -n  -p $2 "$4"@"$1" "sudo /etc/init.d/MYSQL* status | grep MYSQL 2>/dev/null" 2>/dev/null)
        if [ "$mysql" == '' ];
        then
            mysql=$(echo $3 | sshpass -p $3 ssh -o ConnectTimeout=10 -q -n  -p $2 "$4"@"$1" sudo systemctl status MYSQL*  |grep Active |awk '{print $1" "$2" "$3}' 2>/dev/null 2>/dev/null)
            if [ "$mysql" == '' ];
            then
                mysql=$(echo $3 | sshpass -p $3 ssh -t -o ConnectTimeout=10 -q -n  -p $2 "$4"@"$1" sudo systemctl status mysql* |grep Active |awk '{print $1" "$2" "$3}' 2>/dev/null 2>/dev/null)
            fi
        fi
    fi

    cleaned="$(clean $mysql)"
    echo "$cleaned"
}

function reboots {
    log "Ingresando a ${FUNCNAME[0]}."
    IFS=";"
    while read IP PORT USER PASS SO
    do  
        log "Ingresando a equipo : $IP"
        if [ "$PORT" == "NO_SSH" ] || [ "$PORT" == "NO_PING" ];
        then
            log "Equipo : $IP, registra $PORT "
        else
            date=$(sshpass -p $PASS ssh -o ConnectTimeout=10 -q -n -p $PORT $USER@$IP "last | grep reboot")

        fi 
        log "Saliendo de equipo : $IP"
        
        echo "$IP;$date" >> $REBOOTS_REPORT
    done<$FILE_IPS_PORTS_USER_PASS
}

function traer_archivo {
    IFS=";"
    while read IP PORT USER PASS SO FILE
    do  
        log "Ingresando a equipo : $IP"
        if [ "$PORT" == "NO_SSH" ] || [ "$PORT" == "NO_PING" ];
        then
            log "Equipo : $IP, registra $PORT "
        else
                mkdir "$(date +%d%m%y)_$IP"
                if [[ "$SO" == *"Cent"* ]];
                then
                    sshpass -p $PASS scp -P $PORT $USER@$IP:"$FILE" ./"$(date +%d%m%y)_$IP"/
                elif [[ "$SO" == *"Red"* ]];
                then
                    sshpass -p $PASS scp -P $PORT $USER@$IP:"$FILE" ./"$(date +%d%m%y)_$IP"/
                else
                    sshpass -p $PASS scp -P $PORT $USER@$IP:"$FILE" ./"$(date +%d%m%y)_$IP"/
                fi 
        fi 
        log "Saliendo de equipo : $IP"
    done<$FILE_IPS_PORTS_USER_PASS
}

function file_exist {
    log "Ingresando a ${FUNCNAME[0]}."
    file="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1  cat $5 2>/dev/null)"
    
    log "*$file*"
    if [ ! "$file" == "" ];
    then
        echo SI
        log "archivo $5 EXISTE en $1"
    else
        echo NO
        log "archivo $5 NO existe en $1"
    fi
}

function directory_exist {
    log "Ingresando a ${FUNCNAME[0]}."
    directory=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1  "if [ -d $5 ]; then echo true; else echo false;fi")
    echo $directory
}

function generarBackups {
	log "Ingresando a ${FUNCNAME[0]}."
    for i in "${backups[@]}"
    do
		IFS=";" 
		while read ip protocolo puerto user pass so
		do
			if [ "$(directory_exist $ip $puerto $pass $user $i)" == "true" ];
			then
				inicializar_directorio "$BACKUPS_DIRECTORY/$ip"
				sshpass -p $pass scp -r -P $puerto $user@$ip:"$i" "$BACKUPS_DIRECTORY/$ip/"
			fi
		done < $FILE_IPS_PORTS_USER_PASS_SO
    done
	mv "$BACKUPS_DIRECTORY/$ip" "$BACKUPS_DIRECTORY/$ip_$(date +%d%m%y-%H%M%S)"
}
 
 function getJavaTomcat {
     log "Ingresando a ${FUNCNAME[0]}."
     javaVersion="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 java -version 2>/dev/null)"
     tomcatPath="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 ps -fea | grep java | grep tomcat | awk -F'-Dcatalina.home=' '{print $2}' | awk '{print $1}' 2>/dev/null)"

    if [ ! $tomcatPath == "" ];
    then
        tomcatVersion="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 $tomcatPath/bin/version.sh 2>/dev/null | grep number | awk '{print $3}' 2>/dev/null)"
        tomcatApps="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 ls -d "$tomcatPath/webapps/*/" 2>/dev/null)"
        cleaned="$(clean $tomcatApps)"
        if [ "$javaVersion" == "" ];
        then
            javaPath="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 ps -fea | grep java | grep tomcat | awk '{print $8}' 2>/dev/null)"
            javaVersion="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "'$javaPath'" -version 2>&1 | head -n 1)"
        fi
    else
        tomcatVersion="NA"
        tomcatPath="NA"
        tomcatApps="NA"
        cleaned="NA"
    fi

    if [ "$javaVersion" == "" ];
    then
        javaVersion="NA"
        javaPath="NA"
    fi

     echo "$javaVersion;$javaPath;$tomcatVersion;$tomcatPath;$cleaned"
 }

function generarEstadisticas {
	log "Ingresando a ${FUNCNAME[0]}."
	inicializar_directorio $REPORTS_DIRECTORY
	echo "Estadisticas de Servidores:" >> $FILE_REPORT_STATISTICS
	echo "Cantidad de servidores identificados : $(cat $FILE_IPS_PORTS | wc -l)" >> $FILE_REPORT_STATISTICS
	echo "Reporte de cantidades de SO:" >> $FILE_REPORT_STATISTICS
	cat $FILE_IPS_PORTS | awk -F';' '{print $2}' | sort | uniq -c  | sed -e 's/RDP/WINDOWS/g' -e 's/SSH/LINUX/g' -e 's/NO_ACCESS_PROTOCOL/DESCONOCIDO/g' >> $FILE_REPORT_STATISTICS
	echo "Reporte Passwords Conocidos en SO's Linux:" >> $FILE_REPORT_STATISTICS
	cat $FILE_IPS_PORTS_USER_PASS | awk -F';' '{print $4}' | sort | uniq -c | sed -e 's/root/Conocido/g' -e 's/unknown/Desconocido/g' >> $FILE_REPORT_STATISTICS
	echo "Reporte de SO's general:" >> $FILE_REPORT_STATISTICS
	echo "Servidores Centos : $(cat $FILE_IPS_PORTS_USER_PASS_SO | grep CentOS | wc -l)" >> $FILE_REPORT_STATISTICS
	echo "Servidores Red Hat : $(cat $FILE_IPS_PORTS_USER_PASS_SO | grep RedHat | wc -l)" >> $FILE_REPORT_STATISTICS
	echo "Servidores Debian : $(cat $FILE_IPS_PORTS_USER_PASS_SO | grep Debian | wc -l)" >> $FILE_REPORT_STATISTICS
	echo "Servidores Ubuntu : $(cat $FILE_IPS_PORTS_USER_PASS_SO | grep Ubuntu | wc -l)" >> $FILE_REPORT_STATISTICS
	echo "Reporte de SO's específico:" >> $FILE_REPORT_STATISTICS
	cat $FILE_IPS_PORTS_USER_PASS_SO | awk -F';' '{print $6}' | sort | uniq -c >> $FILE_REPORT_STATISTICS
}

function generarInformeServidores {
	log "Ingresando a método : ${FUNCNAME[0]}."
	
	inicializar_directorio $REPORTS_DIRECTORY
	
    echo "IP;IPS;PROTOCOLO;PUERTO;SO;KERNEL;HOSTNAME;DNS;CPU;CPU_MODEL;RAM;OPEN_PORTS;CONNECTIONS;FILE_SYSTEMS;MYSQL_VERSION;PSQL_VERSION;JAVA_VERSION;JAVA_PATH;TOMCAT_VERSION;TOMCAT_PATH;TOMCAT_APPS;USUARIOS;GRUPOS;VARIABLES" >> $FILE_REPORT_HORIZONTAL 
    
    IFS=";" 
    while read ip protocolo puerto user pass so
    do 
		ips="$(getIps $ip $puerto $pass $user)"
		kernel="$(getKernel $ip $puerto $pass $user)"
		hostname="$(getHostname $ip $puerto $pass $user)"
		dns="$(getDns $ip $puerto $pass $user)"
		mysqlVersion="$(getMysqlVersion $ip $puerto $pass $user)"
		psqlVersion="$(getPostgresqlVersion $ip $puerto $pass $user)"
		cpus="$(getCpus $ip $puerto $pass $user)"
		cpu_model="$(getCpuModel $ip $puerto $pass $user)"
		ram="$(getRam $ip $puerto $pass $user)"
		ports="$(getOpenPorts $ip $puerto $pass $user)"
		connections="$(getConections $ip $puerto $pass $user)"
		fileSystems="$(getFileSystem $ip $puerto $pass $user)"
		tomcat="$(getJavaTomcat $ip $puerto $pass $user)"
		users="$(getUsers $ip $puerto $pass $user)"
		groups="$(getGroups $ip $puerto $pass $user)"
		env="$(getEnv $ip $puerto $pass $user)"
		activeServices="$(getActiveServices $ip $puerto $pass $user)"
		routes="$(getRoutes $ip $puerto $pass $user)"
		crones="$(getCrons $ip $puerto $pass $user)"
		sesStatus="$(getSesStatus $ip $puerto $pass $user)"
		mountPoints="$(getMountPoints $ip $puerto $pass $user)"
		dependencies="$(getDependencies $ip $puerto $pass $user)"
		blocks="$(getBlocks $ip $puerto $pass $user)"
		blocksId="$(getBlockId $ip $puerto $pass $user)"
		diskList="$(getFdisk $ip $puerto $pass $user)"
		iptables="$(getIptables $ip $puerto $pass $user)"
		timezone="$(getTimezone $ip $puerto $pass $user)"
		audit="$(getAudit $ip $puerto $pass $user)"
		ipLink="$(getIpLink $ip $puerto $pass $user)"
		limits="$(getLimits $ip $puerto $pass $user)"

		echo "$ip;$ips;$protocolo;$puerto;$so;$kernel;$hostname;$dns;$cpus;$cpu_model;$ram;$ports;$connections;$fileSystems;$mysqlVersion;$psqlVersion;$tomcat;$users;$groups;$env" >> $FILE_REPORT_HORIZONTAL 

		echo "IP : $ip" >> $FILE_REPORT_VERTICAL
		echo "Nombre : $hostname" >> $FILE_REPORT_VERTICAL
		echo "Cantidad de CPU's : $cpus" >> $FILE_REPORT_VERTICAL
		echo "Modelo de CPU : $cpu_model" >> $FILE_REPORT_VERTICAL
		echo "Cantidad Memoria RAM : $ram" >> $FILE_REPORT_VERTICAL
		echo "Zona Hoaria:" >> $FILE_REPORT_VERTICAL
		echo "$timezone" >> $FILE_REPORT_VERTICAL
		echo "Limites:" >> $FILE_REPORT_VERTICAL
		echo "$limits" >> $FILE_REPORT_VERTICAL
		echo "Direcciones IP : $ips" >> $FILE_REPORT_VERTICAL
		echo "Puerto SSH : $puerto" >> $FILE_REPORT_VERTICAL
		echo "Puertos Abiertos : $ports" >> $FILE_REPORT_VERTICAL
		echo "Conexiones : $connections" >> $FILE_REPORT_VERTICAL
		echo "Listado de discos:" >> $FILE_REPORT_VERTICAL
		echo "$diskList" >> $FILE_REPORT_VERTICAL
		echo "Sistema de archivos : $fileSystems" >> $FILE_REPORT_VERTICAL
		echo "Bloques:">> $FILE_REPORT_VERTICAL
		echo "$blocks:">> $FILE_REPORT_VERTICAL
		echo "Identificadores de bloques:">> $FILE_REPORT_VERTICAL
		echo "$blocksId">> $FILE_REPORT_VERTICAL
		echo "Sistema Operativo : $so" >> $FILE_REPORT_VERTICAL
		echo "DNS's : $dns" >> $FILE_REPORT_VERTICAL
		echo "Versión MySql : $mysqlVersion" >> $FILE_REPORT_VERTICAL
		echo "Versión PosgreSQL : $psql" >> $FILE_REPORT_VERTICAL
		echo "Información de Tomcat : $tomcat" >> $FILE_REPORT_VERTICAL
		echo "Usuarios: $users" >> $FILE_REPORT_VERTICAL
		echo "Grupos: $groups" >> $FILE_REPORT_VERTICAL
		echo "Variables de Entorno: $env" >> $FILE_REPORT_VERTICAL
		echo "Servicios Activos:" >> $FILE_REPORT_VERTICAL
		echo "$activeServices" >> $FILE_REPORT_VERTICAL
		echo "Rutas:" >> $FILE_REPORT_VERTICAL
		echo "$routes" >> $FILE_REPORT_VERTICAL
		echo "Reglas Firewall:" >> $FILE_REPORT_VERTICAL
		echo "$iptables" >> $FILE_REPORT_VERTICAL
		echo "Crones:" >> $FILE_REPORT_VERTICAL
		echo "$crones" >> $FILE_REPORT_VERTICAL
		echo "SES Status:" >> $FILE_REPORT_VERTICAL
		echo "$sesStatus" >> $FILE_REPORT_VERTICAL
		echo "Puntos de Montaje:" >> $FILE_REPORT_VERTICAL
		echo "$mountPoints" >> $FILE_REPORT_VERTICAL
		echo "Dependencias:" >> $FILE_REPORT_VERTICAL
		echo "$dependencies" >> $FILE_REPORT_VERTICAL
		echo "Reglas Auditoria:" >> $FILE_REPORT_VERTICAL
		echo "$audit" >> $FILE_REPORT_VERTICAL
		echo "" >> $FILE_REPORT_VERTICAL
    done < $FILE_IPS_PORTS_USER_PASS_SO
}

function consolidar {
	cp $FILE_IPS $REPORTS_DIRECTORY
	cp $FILE_IPS_PORTS $REPORTS_DIRECTORY
	cp $FILE_IPS_PORTS_USER_PASS $REPORTS_DIRECTORY 
	cp $FILE_IPS_PORTS_USER_PASS_SO $REPORTS_DIRECTORY
	mv $REPORTS_DIRECTORY $OUTS_DIRECTORY/$(date +%d%m%y-%H%M%S)
}

function iniciar {
    echo "Buscando configuración en : $FILE_CONF"
	if [ ! -f $FILE_CONF ];
	then
		echo "Archivo de configuración no encontrado."
		echo "Generando archivo de configuración."
		inicializar_conf
		if [ -f $FILE_CONF ];
		then
			echo "Archivo de configuración creado exitosamente."
			source $FILE_CONF
			echo "Archivo de configuración cargado exitosamente : $FILE_CONF"
		else
			echo "Imposible cargar archivo de configuración : $FILE_CONF"
		fi
	fi
}

function reiniciar {
	rm -rf $FILE_IPS
	rm -rf $FILE_IPS_PORTS
	rm -rf $FILE_IPS_PORTS_USER_PASS
	rm -rf $FILE_IPS_PORTS_USER_PASS_SO
	rm -rf $FILE_CONF
}

function rutinaBase {
        log "Ingresando a método : ${FUNCNAME[0]}."

        inicializar_directorio $REPORTS_DIRECTORY

        IFS=";"
        while read ip protocolo puerto user pass so
        do
		echo "Acción de la rutina..."
                #salida="$(metodo $ip $puerto $pass $user)"
        done < $FILE_IPS_PORTS_USER_PASS_SO
}

function copy_ssh_key {
    log "Ingresando a ${FUNCNAME[0]}."
    out="$(sshpass -p $3 ssh-copy-id -o StrictHostKeyChecking=no $4@$1 2>/dev/null)"
    log "*$out*"
}

function create_user {
    log "Ingresando a ${FUNCNAME[0]}."
    out="$(file="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 adduser $5 2>/dev/null)")"
    log "*$out*"
}

function set_user_password {
    log "Ingresando a ${FUNCNAME[0]}."
    out="$(file="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 passwd $5 $6 2>/dev/null)")"
    log "*$out*"
}

function add_user_wheel {
    log "Ingresando a ${FUNCNAME[0]}."
    out="$(file="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 usermod -a -G wheel $5 2>/dev/null)")"
    log "*$out*"
}

function create_sudo_user_centos {
    log "Ingresando a ${FUNCNAME[0]}."
	sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "useradd $5" 2>/dev/null
	sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "echo $5 >> /etc/security/ssh_us.allow" 2>/dev/null
	sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "usermod -aG wheel $5" 2>/dev/null
	sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "yes $6 | passwd  $5" 2>/dev/null
}

function rutinaBase {
        log "Ingresando a método : ${FUNCNAME[0]}."

        inicializar_directorio $REPORTS_DIRECTORY

        IFS=";"
        while read ip protocolo puerto user pass so
        do
		echo "Acción de la rutina..."
                #salida="$(metodo$ip $puerto $pass $user)"
        done < $FILE_IPS_PORTS_USER_PASS_SO
}

case $1 in
  start)
	iniciar
	inicializar_estructura
  ;;
  restart)
	reiniciar
	iniciar
	inicializar_estructura
  ;;
  set-list)
		if [ "$2" == "" ];
		then
			echo "Usando Ips en el archivo : $FILE_IPS"
			sed -i '/FILE_IPS=/d' $FILE_CONF
			echo 'FILE_IPS=$CONF_DIRECTORY/ips.csv' >> $FILE_CONF
		elif [ "$2" == "scan" ];
		then
			echo "Generando Ips de los segmentos en : ${networks[*]}"
			generarIps
			echo "Ips generadas en archivo : $FILE_IPS : $(cat $FILE_IPS | wc -l)"
		else
			if [ ! "$2" == "" ] && [ -f "$2" ];
			then
				echo "Usando Ips en el archivo : $2"
				FILE_IPS="$2"
				sed -i '/FILE_IPS=/d' $FILE_CONF
				echo "FILE_IPS=$2" >> $FILE_CONF
			fi
		fi
    ;;
  build)
	generarPuertosAccesoServidores
	generarDatosAccesoServidores
	generarSoServidores
  ;;
  generate-reports)
	generarInformeServidores
	generarEstadisticas
	consolidar
  ;;
  generate-backups)
	generarBackups
  ;;
  *)
    	echo "./informer.sh start : inicia la configuración y las estructura de carpeta necesarias para funcionar"
	echo "./informer.sh set-list [vacio|scan|ruta_file] : define de donde se va a sacar la lista de IPs, vacio asigna el archivo por defecto, scan genera las Ips de los segmentos en el archivos de configuración , finalmente la ruta asigna dicho archivo"
	echo "./informer.sh build : crea la base de datos de servidores."
	echo "./informer.sh generate-reports : Genera los reportes de las base de datos de servidores construida."
	echo "./informer.sh generate-backups : Genera las copias de seguridad de las base de datos de servidores construida."
	
    ;;
esac
