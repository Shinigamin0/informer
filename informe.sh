#!/bin/bash

CONF_DIRECTORY="./CONF"
FILE_CONF="$CONF_DIRECTORY/config.conf"

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
    log "Ingresando a metodo BlackList"

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
	echo 'TEMP_DIRECTORY=./TEMP' >> "$FILE_CONF"
	echo 'LOGS_DIRECTORY=./LOGS' >> "$FILE_CONF"
	echo 'OUTS_DIRECTORY=./OUTS' >> "$FILE_CONF"
	echo 'SCRIPTS_DIRECTORY=./SCRIPTS' >> "$FILE_CONF"
	echo 'REPORTS_DIRECTORY=$OUTS_DIRECTORY/$(date +%d%m%y-%H%M)' >> "$FILE_CONF"
	echo 'FILE_REPORT_HORIZONTAL=$REPORTS_DIRECTORY/informe_horizontal_$(date +%d%m%y-%H%M).csv' >> "$FILE_CONF"
	echo 'FILE_REPORT_VERTICAL=$REPORTS_DIRECTORY/informe_vertical_$(date +%d%m%y-%H%M).txt' >> "$FILE_CONF"
	echo 'FILE_FINAL_SERVERS_LIST=$TEMP_DIRECTORY/servers_$(date +%d%m%y%H%M%S).csv' >> "$FILE_CONF"
	echo 'FILE_LOG=$LOGS_DIRECTORY/log_informe_$(date +%d%m%y).log' >> "$FILE_CONF"
	echo 'FILE_SERVERS=$TEMP_DIRECTORY/servers_$(date +%d%m%y)' >> "$FILE_CONF"
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
		elif [[ "$line" == *"FILE"* ]];
		then
			var=$(echo $line | awk -F'=' '{print $1}')
            inicializar_archivo ${!var}
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
    for i in "${networks[@]}"
    do
        filtro=$(echo $i | awk -F'.' '{print $1"."$2"."$3"."}')
		nmap -sL -n $i/24 | grep "$filtro" | grep -vw "${filtro}0\|${filtro}1\|${filtro}255" | awk '{print $5}'>> $FILE_IPS
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
			flag=$(nmap -Pn -host-timeout 20s -p $j $1|grep 'open\|filtered'|grep tcp|awk '{print $1}'|sed 's/\/tcp//g'|sort|uniq)
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
    log "Ingresando a metodo getHosts"
    hosts=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 cat /etc/hosts | grep -v "#")
    cleaned="$(clean $hosts)"
    echo "$cleaned"
}

function getUsers {
    log "Ingresando a metodo getUsers"
    users=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 cat /etc/passwd | awk -F':' '{print $1}' 2>/dev/null)
    cleaned="$(clean $users)"
    echo "$cleaned"
}

function getGroups {
    log "Ingresando a metodo getGroups"
    groups=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 'cat /etc/group 2>/dev/null' 2>/dev/null)
    cleaned="$(clean $groups)"
    echo "$cleaned"
}

function getEnv {
    log "Ingresando a metodo getEnv"
    env=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 'env 2>/dev/null' 2>/dev/null)
    if [ "$env" == "" ];
    then
        env=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 'printenv 2>/dev/null' 2>/dev/null)        
    fi
    cleaned="$(clean $env)"
    echo "$cleaned"
}

function getRoutes {
    log "Ingresando a metodo getRoutes"
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
    log "Ingresando a metodo getActiveServices"
    activeServices=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 'systemctl list-units --type=service --state=active 2>/dev/null' 2>/dev/null)
    echo $activeServices

}

function getSesStatus {
    log "Ingresando a metodo getSesStatus"
    sestatus=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 'sestatus 2>/dev/null' 2>/dev/null)
    echo $sestatus

}

function getCrons {
    log "Ingresando a metodo getCrons"
    crons=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 'cat /var/spool/cron/* | grep -v "#" 2>/dev/null' 2>/dev/null)
    cleaned="$(clean $crons)"
    echo "$cleaned"
}

function getOpenPorts {
    log "Ingresando a metodo OpenPorts"
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
    log "Ingresando a metodo getConections"
    connections=$(sshpass -p $3 ssh -o ConnectTimeout=60 -q -n -p $2 $4@$1 netstat -nat | awk '{print $6}'| sed -e '1,2d' | sort | uniq -c | sort -r| awk '{print $2":"$1}')
    cleaned="$(clean $connections)"
    echo "$cleaned"
}

function getSshUsers {
    log "Ingresando a metodo getSshUsers"
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
    log "Ingresando a metodo getNisService"
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
    log "Ingresando a metodo getPostgresqlService"

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
    log "Ingresando a metodo getRam"
    memory=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 echo $(grep MemTotal /proc/meminfo |awk '{print $2}') / 1024^2 | bc 2>/dev/null)
    cleaned="$(clean $memory)"
    echo $cleaned"GB"
}

function getCpuModel {
    log "Ingresando a metodo getCpuModel"
    model="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 cat /proc/cpuinfo|grep 'odel name'|sed -e 's/ //g' -e 's/\t//g' -e 's/\r$//' |awk -F':' '{print $2}'|uniq)"
    cleaned="$(clean $model)"
    echo $cleaned
}

function getCpus {
    log "Ingresando a metodo getCpus"
    cpus="$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 cat /proc/cpuinfo|grep processor|awk '{print $1}'|sed -e 's/ //g'|wc -l)"
    echo $cpus"CPU" 

}

function getMountPoints {
    log "Ingresando a metodo getMountPoints"
    disk=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 cat /etc/fstab | grep -v '#'  | sed -e ':a;N;$!ba;s/\n/,/g'  2>/dev/null)
    echo "$disk"
}

function getFileSystem {
    log "Ingresando a metodo getFileSystem"
    fileSystem=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 df -h | awk '{print $1,$2,$6}' | sed -e ':a;N;$!ba;s/\n/,/g' 2>/dev/null)
    echo "$fileSystem"
}

function getHostname {
    log "Ingresando a metodo getHostName"
    hostname=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 hostname 2>/dev/null)
    echo "$hostname"
}

function getIps {
    log "Ingresando a metodo Ips"
    
    ips=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1  ifconfig  2>/dev/null | awk '{print $2}' | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}" 2>/dev/null )
    
    if [ "$ips" == "" ];
    then
        ips=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 ip a 2>/dev/null | awk '{print $2}' | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}" 2>/dev/null)
    fi

    if [ "$ips" == "" ];
    then
        ips=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 $4@$1 "hostname -I 2>/dev/null" 2>/dev/null)
    fi
    
    echo "$(echo $ips | sed -e 's/\;/ /g' | sed -e ':a;N;$!ba;s/\n/,/g')"
}

function getDns {
    log "Ingresando a metodo getDns"

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
    log "Ingresando a metodo getMysqlVersion"
    mysql=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 "$4"@"$1" "mysql --version | grep mysql | sed -e 's/ //g' 2>/dev/null" 2>/dev/null)
    cleaned="$(clean $mysql)"
    echo "$cleaned"
     
}

function getPostgresqlVersion {
    log "Ingresando a metodo getPostgresqlVersion"
    postgresql=$(sshpass -p $3 ssh -o ConnectTimeout=10 -q -n -p $2 "$4"@"$1" "psql --version 2>/dev/null | grep psql | sed -e 's/ //g' 2>/dev/null" 2>/dev/null)
    cleaned="$(clean $postgresql)"
}

function getPostgresqlServiceState {
    log "Ingresando a metodo getPostgresqlServiceState"
    
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
    log "Ingresando a metodo getMysqlServiceState"

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
    log "Ingresando a metodo reboots"
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
    log "Validando existencia de archivo $5 en $1"
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
 
 function getJavaTomcat {
     log "Ingresando a metodo getJavaTomcat"
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

function generarInformeServidores {

    log "Iniciando generacion de informe - $(date +%H:%M)..."
    
    if [ ! -f $REPORT_DIRECTORY ];
    then
        mkdir $REPORT_DIRECTORY
    fi

    echo "IP;PUERTO_SSH;SO;HOSTNAME;DNS;MYSQL_VERSION;PSQL;CPU;CPU_MODEL;RAM;IPS;OPEN_PORTS;CONNECTIONS;FILE_SYSTEMS;JAVA_VERSION;JAVA_PATH;TOMCAT_VERSION;TOMCAT_PATH;TOMCAT_APPS;USUARIOS;GRUPOS;VARIABLES;CRONES" >> $FILE 
    
    IFS=";"
    
    while read ip puerto user pass so
    do 
        if [ "$puerto" == "NO_SSH" ] || [ "$puerto" == "NO_PING" ] || [ "$puerto" == "" ] || [ "$user" == "unknown" ] ;
        then
            if [ "$puerto" == "NO_SSH" ] ;
            then
                ports="$(getOpenPorts $ip)"
                win="$(windows $ip)"
                if [ "$win" == "windows" ];
                then
                    echo "$ip;WINDOWS;$ports;" >> $FILE
                else
                    echo "$ip;$puerto;$ports;" >> $FILE
                fi                
            elif [ "$puerto" == "NO_PING" ] ;
            then
                echo "$ip;$puerto;" >> $FILE
            elif [  "$user" == "unknown" ] ;
            then
                echo "$ip;$puerto;unknown credentials;" >> $FILE
            fi
        else
            existe="$(blackList $ip)"
            
            if [ "$existe" == "existe" ];
            then
                log " INFORME - Servidor $ip EXISTE en lista negra. - $(date +%H:%M)..."
                echo "$ip;$puerto;LISTA_NEGRA;" >> $FILE
            else
                log "Trabajando en $ip :"
                echo "Trabajando en $ip :"
                echo "Extrayendo version Mysql"
                mysqlVersion="$(getMysqlVersion $ip $puerto $pass $user)"
                echo "Extrayendo version PostgreSQL"
                psql="$(getPostgresqlVersion $ip $puerto $pass $user)"
                echo "Extrayendo hostname"
                hostname="$(getHostname $ip $puerto $pass $user)"
                echo "Extrayendo CPUs"
                cpus="$(getCpus $ip $puerto $pass $user)"
                echo "Extrayendo CPU Model"
                cpu_model="$(getCpuModel $ip $puerto $pass $user)"
                echo "Extrayendo RAM"
                ram="$(getRam $ip $puerto $pass $user)"
                echo "Extrayendo IPs"
                ips="$(getIps $ip $puerto $pass $user)"
                echo "Extrayendo Ports"
                ports="$(getOpenPorts $ip $puerto $pass $user)"
                echo "Extrayendo Connections"
                connections="$(getConections $ip $puerto $pass $user)"
                echo "Extrayendo FileSystem"
                fileSystems="$(getFileSystem $ip $puerto $pass $user)"
                echo "Extrayendo DNS"
                dns="$(getDns $ip $puerto $pass $user)"
                echo "Extrayendo version Java y Tomcat"
                tomcat="$(getJavaTomcat $ip $puerto $pass $user)"
                echo "Extrayendo Usuarios"
                users="$(getUsers $ip $puerto $pass $user)"
                echo "Extrayendo Grupos"
                groups="$(getGroups $ip $puerto $pass $user)"
                echo "Extrayendo Env"
                env="$(getEnv $ip $puerto $pass $user)"
                echo "Extrayendo Active Services"
                activeServices="$(getActiveServices $ip $puerto $pass $user)"
                echo "Extrayendo Routes"
                routes="$(getRoutes $ip $puerto $pass $user)"
                echo "Extrayendo Crones"
                crones="$(getCrons $ip $puerto $pass $user)"
                echo "Extrayendo SES Status"
                sesStatus="$(getSesStatus $ip $puerto $pass $user)"

                echo "$ip;$puerto;$so;$hostname;$dns;$mysqlVersion;$psql;$cpus;$cpu_model;$ram;$ips;$ports;$connections;$fileSystems;$tomcat;$users;$groups;$env;$crones" >> $FILE

                echo "IP : $ip" >> $FILE_VERTICAL
                echo "Nombre : $hostname" >> $FILE_VERTICAL
                echo "Cantidad de CPU's : $cpus" >> $FILE_VERTICAL
                echo "Modelo de CPU : $cpu_model" >> $FILE_VERTICAL
                echo "Cantidad Memoria RAM : $ram" >> $FILE_VERTICAL
                echo "Direcciones IP : $ips" >> $FILE_VERTICAL
                echo "Puerto SSH : $puerto" >> $FILE_VERTICAL
                echo "Puertos Abiertos : $ports" >> $FILE_VERTICAL
                echo "Conexiones : $connections" >> $FILE_VERTICAL
                echo "Sistema de archivos : $fileSystems" >> $FILE_VERTICAL
                echo "Sistema Operativo : $so" >> $FILE_VERTICAL
                echo "DNS's : $dns" >> $FILE_VERTICAL
                echo "Versión MySql : $mysqlVersion" >> $FILE_VERTICAL
                echo "Versión PosgreSQL : $psql" >> $FILE_VERTICAL
                echo "Información de Tomcat : $tomcat" >> $FILE_VERTICAL
                echo "Usuarios: $users" >> $FILE_VERTICAL
                echo "Grupos: $groups" >> $FILE_VERTICAL
                echo "Variables de Entorno: $env" >> $FILE_VERTICAL
                echo "Servicios Activos: $activeServices" >> $FILE_VERTICAL
                echo "Rutas: $routes" >> $FILE_VERTICAL
                echo "Crones: $crones" >> $FILE_VERTICAL
                echo "SES Status: $sesStatus" >> $FILE_VERTICAL
                echo "" >> $FILE_VERTICAL

            fi
            
        fi
    done < $FILE_IPS_PORTS_USER_PASS_SO

    momento="$(date +%d%m%y%H%M%S)"
    new_name_file="$(echo $FILE | sed -e 's/.csv//g')"
    mv $FILE $new_name_file"_$momento.csv"
    new_name_file_vertical="$(echo $FILE_VERTICAL | sed -e 's/.txt//g')"
    mv $FILE_VERTICAL $new_name_file_vertical"_$momento.txt"

    rm -f $FILE_IPS_PORTS
    rm -f $FILE_IPS_PORTS_USER_PASS
    mv $FILE_IPS_PORTS_USER_PASS_SO $FILE_FINAL_LIST
    
    log "Terminando generación de informe bases de datos - $(date +%H:%M)..."
    
}


case $1 in
  start)
    echo "Buscando configuración en : $FILE_CONF"
	if [ -f $FILE_CONF ];
	then
		source $FILE_CONF
		echo "Archivo de configuración cargado exitosamente : $FILE_CONF"
	else
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
	inicializar_estructura
    ;;
  set-list)
		source $FILE_CONF
		if [ "$2" == "" ];
		then
			echo "Usando Ips en el archivo : $FILE_IPS"
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
		source $FILE_CONF
		generarPuertosAccesoServidores
		generarDatosAccesoServidores
		generarSoServidores
  ;;
  generate-reports)

    ;;
 local)
    generarListaServidores_local
    generarSistemaOperativo
    generarInformeServidores
    ;;
 validacion)
    if [ -f "$2" ];
    then
	    log "Archivo $2 existe."
	    FILE_IPS="$2"
	    generarListaServidores_file
	    generarSistemaOperativo
        
    else
	    log "Archivo $2 NO existe."
	    echo "Archivo $2 NO existe"
    fi
    ;;
  *)
    echo "./informer.sh start : inicia la configuración y las estructura de carpeta necesarias para funcionar"
    echo "./informer.sh set-list [vacio|scan|ruta_file] : define de donde se va a sacar la lista de IPs, vacio asigna el archivo por defecto, scan genera las Ips de los segmentos en el archivos de configuración , finalmente la ruta asigna dicho archivo"
    echo "./informer.sh build : crea la base de datos de servidores."
    echo "file : en atención a un listado de ips que entra como parámetro genera el informe."
    echo "validacion: solo velida si se tiene acceso por ssh a la lista de servidores."
    ;;
esac
