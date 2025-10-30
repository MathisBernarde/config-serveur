#!/usr/bin/env bash
#
# This script evaluates HTTP servers of students.
# It read configuration from a CSV file with the format:
# student_pk;lastname;firstname;email;username;gid;password;port

homedir=/home/2025/a2-bic
bindir=opt/bichttpd/usr/sbin
srvdir=opt/bichttpd/srv/http
srcdir=bichttpd

declare -A checks
declare -A comments
checks[01]="check_src_exists"
comments[01]="Un fichier source existe dans le répertoire de développement"
checks[02]="check_iscript_exists"
comments[02]="Un script d'installation existe dans le répertoire de développement"
checks[03]="check_bin_exists"
comments[03]="Un binaire existe dans le répertoire d'installation"
checks[04]="check_exec_exists"
comments[04]="Un exécutable ELF existe dans le répertoire d'installation"
checks[05]="check_srv_listens"
comments[05]="Un service est en écoute sur le port dédié"
checks[06]="check_resp_200"
comments[06]="Le service répond avec un Status-Code 200 a une requête valide"
checks[07]="check_resp_400"
comments[07]="Le service répond avec un Status-Code 400 a une requête invalide"
checks[08]="check_set_port"
comments[08]="Une option permet de spécifier le port d'écoute"
checks[09]="check_invalid_port_char"
comments[09]="Le service renvoie une erreur pour un port invalide (lettres)"
checks[10]="check_invalid_port_overflow"
comments[10]="Le service renvoie une erreur pour un port invalide (>65535)"
checks[11]="check_use_fork"
comments[11]="Le service utilise l'appel système fork"
checks[12]="check_has_worker"
comments[12]="Le service dispose d'un worker pour gérer les requêtes"
checks[13]="check_debug_mode"
comments[13]="Une option permet d'activer le mode debug"
checks[14]="check_debug_mode_stderr"
comments[14]="Une option permet d'activer le mode debug qui écrit sur la sortie d'erreur"
checks[15]="check_memory"
comments[15]="L'exécutable ne provoque pas de fuite mémoire"
checks[16]="check_valid_method"
comments[16]="Le service n'accepte que les méthode GET HEAD et POST"
checks[17]="check_valid_version"
comments[17]="Le service n'accepte que la version HTTP/1.0"
checks[18]="check_resp_404"
comments[18]="Le service répond avec un Status-Code 404 pour un fichier inexistant"
checks[19]="check_header_date"
comments[19]="Le header contient un champs Date"
checks[20]="check_header_length"
comments[20]="Le header contient un champs Content-Length"
checks[21]="check_set_secure"
comments[21]="Une option permet de spécifier le mode sécurisé"
checks[22]="check_tls"
comments[22]="Le service accepte une connexion TLS"
checks[23]="check_log"
comments[23]="Le service produit un fichier de log valide"
checks[24]="check_set_conf"
comments[24]="Une option permet de spécifier un fichier de configuration"

function print_help ()
{
	echo "Usage: $0 [OPTIONS] INFILE"
	echo ""
	echo "Options:"
	echo "  -h              Print this help and exit."
	echo "  -p              Generate results."
	echo "  -v              Enable verbose mode."
}

function check ()
{
	_key=$1
	_username=$2
	_port=$3

	[ ${verbose} ] && echo "===> Test ${_key}: ${comments[${_key}]}"
	eval ${checks[${_key}]}
	_value=$?
	[ ${verbose} ] && echo "=> ${_username}: ${_value}"
	return ${_value}
}

function check_src_exists ()
{
	[ -f ${homedir}/${_username}/${srcdir}/bichttpd.c ] &&
		grep -q "main.*(.*)" ${homedir}/${_username}/${srcdir}/bichttpd.c
}

function check_iscript_exists ()
{
	[ -f ${homedir}/${_username}/${srcdir}/install.sh -a \
		-x ${homedir}/${_username}/${srcdir}/install.sh ] &&
		grep -q "^#!" ${homedir}/${_username}/${srcdir}/install.sh
}

function check_bin_exists ()
{
	[ -f ${homedir}/${_username}/${bindir}/bichttpd -a \
	  -x ${homedir}/${_username}/${bindir}/bichttpd ]
}

function check_exec_exists ()
{
	file ${homedir}/${_username}/${bindir}/bichttpd |
		grep -q "ELF 64-bit LSB pie executable"
}

function check_srv_listens ()
{
	netstat -an | grep -q ":${_port}.*LISTEN"
}

function check_resp_200 ()
{
	_hash=$(tr -dc '[:alnum:]' </dev/urandom | head -c 64)
	echo "<html></html> 2>/dev/null" > ${homedir}/${_username}/${srvdir}/${_hash}
	nc -w 1 localhost ${_port} < <(echo "GET /${_hash} HTTP/1.0") |
		grep -q "HTTP/.*200"
	_value=$?
	rm -f ${homedir}/${_username}/${srvdir}/${_hash}
	return ${_value}
}

function check_resp_400 ()
{
	nc -w 1 localhost ${_port} < <(echo "FOO") |
		grep -q "HTTP/.*400"
}

function check_set_port ()
{
	_shiftedport=$((${_port}+1000))
	${homedir}/${_username}/${bindir}/bichttpd -p ${_shiftedport} 2>/dev/null &
	_pid=$(ps -x | grep "${homedir}/${_username}/${bindir}/bichttpd" | grep -v "grep" | tail -n 1 | awk '{print $1}')
	netstat -an | grep -q ":${_shiftedport}.*LISTEN"
	_value=$?
	kill ${_pid} 2>/dev/null
	return ${_value}
}

function check_invalid_port_char ()
{
	_value=1
	_err=$(mktemp)
	_ret=$(mktemp)
	coproc srv { ${homedir}/${_username}/${bindir}/bichttpd -p abc 2>${_err} ; echo $? > ${_ret} ; }
	_pid=$(ps -x | grep "${homedir}/${_username}/${bindir}/bichttpd" | grep -v "grep" | tail -n 1 | awk '{print $1}')
	if grep -q "Invalid argument" ${_err} && grep -q "1" ${_ret} ; then
		_value=0
	fi
	if [ ${_pid} ] ; then
		_value=1
		kill ${_pid} 2>/dev/null
	fi
	rm -f ${_err} ${_ret}
	return ${_value}
}

function check_invalid_port_overflow ()
{
	_value=1
	_err=$(mktemp)
	_ret=$(mktemp)
	coproc srv { ${homedir}/${_username}/${bindir}/bichttpd -p 123456 2>${_err} ; echo $? > ${_ret} ; }
	_pid=$(ps -x | grep "${homedir}/${_username}/${bindir}/bichttpd" | grep -v "grep" | tail -n 1 | awk '{print $1}')
	if grep -q "Invalid argument" ${_err} && grep -q "1" ${_ret} ; then
		_value=0
	fi
	if [ ${_pid} ] ; then
		_value=1
		kill ${_pid} 2>/dev/null
	fi
	rm -f ${_err} ${_ret}
	return ${_value}
}

function check_use_fork ()
{
	objdump -d ${homedir}/${_username}/${bindir}/bichttpd | grep -q "fork"
}

function check_has_worker ()
{
	if ! netstat -an | grep ${_port} | grep -q LISTEN ; then
		return 1
	fi
	_out=$(mktemp)
	_clitime=$(mktemp)
	coproc cli { _cstart=$(date +%s) ; nc -w 2 localhost ${_port} > ${_out} ; _cstop=$(date +%s) ; echo "$((_cstop-_cstart))" > ${_clitime} ; }
	_start=$(date +%s)
	nc -w 1 localhost ${_port} < <(echo "GET /") > /dev/null
	_stop=$(date +%s)
	wait ${cli_PID}
	if [ ! -s ${_out} -a $((_stop-_start)) -lt 1 -a $(cat ${_clitime}) -eq 2 ] ; then
		_value=0
	else
		_value=1
	fi
	rm -f ${_out} ${_clitime}
	return ${_value}
}

function check_debug_mode ()
{
	_out=$(mktemp)
	_shiftedport=$((${_port}+1000))
	${homedir}/${_username}/${bindir}/bichttpd -d -p ${_shiftedport} > ${_out} 2>&1 &
	_pid=$(ps -x | grep "${homedir}/${_username}/${bindir}/bichttpd" | grep -v "grep" | tail -n 1 | awk '{print $1}')
	grep -q "\[bichttpd\] Trying to bind to" ${_out}
	_value=$?
	kill ${_pid} 2> /dev/null
	rm -f ${_out}
	return ${_value}
}

function check_debug_mode_stderr ()
{
	_out=$(mktemp)
	_shiftedport=$((${_port}+1000))
	${homedir}/${_username}/${bindir}/bichttpd -d -p ${_shiftedport} 2> ${_out} &
	_pid=$(ps -x | grep "${homedir}/${_username}/${bindir}/bichttpd" | grep -v "grep" | tail -n 1 | awk '{print $1}')
	grep -q "\[bichttpd\] Trying to bind to" ${_out}
	_value=$?
	kill ${_pid} 2> /dev/null
	rm -f ${_out}
	return ${_value}
}

function check_memory ()
{
	_out=$(mktemp)
	_shiftedport=$((${_port}+1000))
	coproc vg { valgrind --leak-check=full ${homedir}/${_username}/${bindir}/bichttpd -p ${_shiftedport} > ${_out} 2>&1 ; }
	_pid=$(ps -x | grep "valgrind.*${homedir}/${_username}/${bindir}/bichttpd -p ${_shiftedport}" | grep -v "grep" | tail -n 1 | awk '{print $1}')
	if [ ! ${_pid} ] ; then
		_value=1
	else
		sleep 1
		kill ${_pid} 2> /dev/null
		wait ${vg_PID}
		_nbytes=$(grep "in use at exit" ${_out} | sed -E -e 's|^.*in use at exit: ([0-9,]+) bytes.*$|\1|' -e 's|,||g')
		if [ ${_nbytes} -eq 0 ] ; then
			_value=0
		else
			_value=1
		fi
	fi
	rm -f ${_out}
	return ${_value}
}

function check_valid_method ()
{
	nc -w 1 localhost ${_port} < <(echo "GET/ /index.html HTTP/1.0") |
		grep -q "HTTP.*400"
}

function check_valid_version ()
{
	nc -w 1 localhost ${_port} < <(echo "GET / HTTP/2.0") |
		grep -q "HTTP.*400"
}

function check_resp_404 ()
{
	_hash=$(tr -dc '[:alnum:]' </dev/urandom | head -c 64)
	nc -w 1 localhost ${_port} < <(echo "GET /${_hash} HTTP/1.0") |
		grep -q "HTTP.*404"
}

function check_header_date ()
{
	nc -w 1 localhost ${_port} < <(echo "GET / HTTP/1.0") |
		grep "Date:" | grep $(date +%Y) | grep -q $(date +%H)
}

function check_header_length ()
{
	nc -w 1 localhost ${_port} < <(echo "GET / HTTP/1.0") |
		grep -q -E "Content-Length: [0-9]+"
}

function check_set_secure ()
{
	_err=$(mktemp)

	_shiftedport=$((${_port}+1000))
	${homedir}/${_username}/${bindir}/bichttpd -p ${_shiftedport} -d -s 2>${_err} >/dev/null &
	_pid=$(ps -x | grep "${homedir}/${_username}/${bindir}/bichttpd" | grep -v "grep" | tail -n 1 | awk '{print $1}')
	grep -q "\[bichttpd\] TLS connection enabled" ${_err}
	_value=$?
	kill ${_pid} 2>/dev/null
	rm -f ${_err}
	return ${_value}
}

function check_tls ()
{
	_shiftedport=$((${_port}+1000))

	${homedir}/${_username}/${bindir}/bichttpd -p ${_shiftedport} -s &
	_pid=$(ps -x | grep "${homedir}/${_username}/${bindir}/bichttpd" | grep -v "grep" | tail -n 1 | awk '{print $1}')
	openssl s_client -timeout 1 -connect localhost:${_shiftedport} < <(echo "GET / HTTP/1.0")
	_value=$?
	kill ${_pid} 2> /dev/null
	return ${_value}
}

function check_log ()
{
	_req=$(tr -dc A'-Za-z0-9' </dev/urandom | head -c 64)
	_logfile=$(mktemp --suffix=.log)

	_shiftedport=$((${_port}+1000))
	${homedir}/${_username}/${bindir}/bichttpd -p ${_shiftedport} -l ${_logfile} >/dev/null 2>&1 &
	_pid=$(ps -x | grep "${homedir}/${_username}/${bindir}/bichttpd" | grep -v "grep" | tail -n 1 | awk '{print $1}')
	nc -w 1 localhost ${_shiftedport} < <(echo "GET /${_req} HTTP/1.0") >/dev/null 2>&1
	grep -q -E "2024\ \"GET /${_req} HTTP/1.0\" 404" ${_logfile}
	_value=$?
	kill ${_pid} 2>/dev/null
	rm -f ${_logfile}
	return ${_value}
}

function check_set_conf ()
{
	_conffile=$(mktemp)
	_randport=$((RANDOM%100+59000))

	cat > ${_conffile} << EOF
[bichttpd]
port = ${_randport}

EOF
	${homedir}/${_username}/${bindir}/bichttpd -c ${_conffile} >/dev/null 2>&1 &
	_pid=$(ps -x | grep "${homedir}/${_username}/${bindir}/bichttpd" | grep -v "grep" | tail -n 1 | awk '{print $1}')
	netstat -an | grep -q ":${_randport}.*LISTEN"
	_value=$?
	kill -9 ${_pid} 2>/dev/null
	rm -f ${_conffile}
	return ${_value}
}

function clean_remaining_process ()
{
	while ps -x | grep "bichttpd" | grep -v "grep" ; do
		_pid=$(ps -x | grep "bichttpd" | grep -v "grep" | tail -n 1 | awk '{print $1}')
		kill -9 ${_pid}
	done
}

while getopts "hpv" opt ; do
	case ${opt} in
		h) print_help && exit 0 ;;
		p) publish="yes" ;;
		v) verbose="yes" ;;
		*) >&2 print_help && exit 1 ;;
	esac
done
if [ ${publish} ] ; then
	shift
fi
if [ ${verbose} ] ; then
	shift
fi

if [ $# -lt 1 ] ; then
	>&2 print_help
	exit 1
fi
filename=$1

timestamp=$(date +%Y%m%d%H%M)
evaldir=/root/adm/eval-${timestamp}
evalprefix=eval
mkdir -p ${evaldir}
for key in ${!checks[@]} ; do
	echo "student_pk;${comments[${key}]}" > ${evaldir}/eval-${key}.csv
	sed -e "1d" ${filename} | while read line ; do
		studentpk=$(echo ${line} | cut -d';' -f1)
		username=$(echo ${line} | cut -d';' -f5)
		port=$(echo ${line} | cut -d';' -f8)
		check ${key} ${username} ${port}
		ret=$?
		ok=0
		if [ ${ret} == 0 ] ; then
			ok=1
		fi
		echo "${username};${ok}" >> ${evaldir}/eval-${key}.csv
	done
done
	paste -d ';' ${evaldir}/${evalprefix}-01.csv \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-02.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-03.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-04.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-05.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-06.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-07.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-08.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-09.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-10.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-11.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-12.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-13.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-14.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-15.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-16.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-17.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-18.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-19.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-20.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-21.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-22.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-23.csv) \
		<(cut -d ';' -f 2 ${evaldir}/${evalprefix}-24.csv) > ${evaldir}/tests-http-${timestamp}.csv
clean_remaining_process	
if [ ${publish} ] ; then
	cp ${evaldir}/tests-http-${timestamp}.csv /var/www/pub/psr/archives
	sed -e 's|;|,|g' ${evaldir}/tests-http-${timestamp}.csv  | /usr/bin/pandoc -f csv -t html --standalone --metadata=title:"PSR Automatic Server Tests" --metadata=maxwidth:none > /var/www/pub/psr/index.html
fi
#rm -rf ${evaldir}
