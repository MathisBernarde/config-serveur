exit
pwd
ls
-F
ls -F
touch CR.md
touch cr.md
mkdir -p dev/src
mkdir -p app/bin
cd dev/src
nano serveur.c
cd dev/src
cd ..
cd . .
cd ..
ls
cd bichttpd/
ls
cd ..
ls
cd bichttpd/
./install.sh
ls
cd ..
ls
cd opt
./install.sh
cd bichttpd/
ls
./install.sh
./
./install.sh
.bichttpd/install.sh
.bichttpd/
./bichttpd/
./bichttpd/install.sh
ls
cd bichttpd
./install.sh
..
/..
..
...
../
tree
cd/a
cd-
help
cd -P
tmux new -s bichttpd
tmux ls
gcc -Wall -Werror bichttpd.c -o bichttpd
cd bichttpd
gcc -Wall -Werror bichttpd.c -o bichttpd
./bichttpd -d
curl -v http://localhost:8080/
curl -v http://iot.devinci.fr:8080/
python3 -m http.server 42116 --bind 0.0.0.0
curl -v http://iot.devinci.fr:8080/
curl -v http://iot.devinci.fr:8080/
./bichttpd
curl -v http://iot.devinci.fr:8080/
tmux ls
curl -v http://iot.devinci.fr:8080/
ls
cd
opt/bichttpd/usr/sbin
./
./opt/bichttpd/usr/sbin/bichttpd 
./bichttpd/bichttpd 
./opt/bichttpd/usr/sbin/bichttpd 
exit
./bichttpd
cd bichttpd
./bichttpd
ssh -i mb242602.key -p 13022 mb242602@iot.devinci.fr
curl -v http://iot.devinci.fr:8080/
temux
cd bichttpd
tmux ls
tmux new -s bichttpd
temux ls
tmux ls
./bichttpd
tmux new -s bichttpd
tmux ls
ls
gcc -Wall -Werror bichttpd.c -o bichttpd
tmux kill-session -t bichttpd
tmux new -s bichttpd
tmux ls
tmux new -s bichttpd './bichttpd'
ls -l

gcc -Wall -Werror bichttpd.c -o bichttpd
tmux new -s bichttpd './bichttpd'
tmux kill-session -t bichttpd
gcc -Wall -Werror bichttpd.c -o bichttpd
tmux new -s bichttpd './bichttpd'
tmux ls
gcc -Wall -Werror bichttpd.c -o bichttpd
cd bichttpd
gcc -Wall -Werror bichttpd.c -o bichttpd
./install.sh
cd ..
cd etc/esilv/psr
cd /etc/esilv/psr
vim eval.sh
cd ..
# Navigue vers ton répertoire de développement
cd ~/bichttpd
# Compile
gcc -Wall -Werror bichttpd.c -o bichttpd
# Installe
./install.sh
~/opt/bichttpd/usr/sbin/bichttpd -p abc
~/opt/bichttpd/usr/sbin/bichttpd -p 99999
# Navigue vers ton répertoire de développement
cd ~/bichttpd
# Compile
gcc -Wall -Werror bichttpd.c -o bichttpd
# Installe
./install.sh
~/opt/bichttpd/usr/sbin/bichttpd -p abc
~/opt/bichttpd/usr/sbin/bichttpd -p 99999
cd ~/etc/esilv/psr
vim eval.sh
cd ~/etc/esilv/psr
vim eval.sh
cd ~/etc/esilv/psr
cd /etc/esilv/psr
vim eval.sh
cd ..
cd ..*
cd ..
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt -subj "/C=FR/ST=IDF/L=Paris/O=Devinci/CN=iot.devinci.fr"
cd bichttpd
cd /bichttpd
cd
cd bichttpd
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt -subj "/C=FR/ST=IDF/L=Paris/O=Devinci/CN=iot.devinci.fr"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt -subj "/C=FR/ST=IDF/L=Paris/O=Devinci/CN=iot.devinci.fr"
#!/bin/bash
# Script d’installation pour bichttpd
set -e
# Base d’installation
BASE_DIR="$HOME/opt/bichttpd"
echo "Création de l’arborescence dans $BASE_DIR ..."
mkdir -p "$BASE_DIR/usr/sbin"
mkdir -p "$BASE_DIR/etc"
mkdir -p "$BASE_DIR/var/log"
mkdir -p "$BASE_DIR/srv/http"
# Génération des certificats TLS s'ils n'existent pas
if [ ! -f "./server.crt" ] || [ ! -f "./server.key" ]; then     echo "Génération du certificat et de la clé TLS autosignés...";     openssl req -x509 -nodes -days 365 -newkey rsa:2048     -keyout server.key -out server.crt     -subj "/C=FR/ST=IDF/L=Paris/O=Devinci/CN=iot.devinci.fr"; fi
# Compilation automatique si le binaire n’existe pas ou si le code source est plus récent
# Ajout de -lssl et -lcrypto pour lier la librairie OpenSSL
if [ ! -f "./bichttpd" ] || [ "bichttpd.c" -nt "bichttpd" ]; then     echo "Compilation de bichttpd.c avec OpenSSL...";     gcc -Wall -Werror bichttpd.c -o bichttpd -lssl -lcrypto; fi
# Installation du binaire et des certificats
echo "Installation du binaire et des certificats..."
cp ./bichttpd "$BASE_DIR/usr/sbin/"
chmod +x "$BASE_DIR/usr/sbin/bichttpd"
# Copie des clés dans le répertoire du binaire
cp ./server.crt "$BASE_DIR/usr/sbin/"
cp ./server.key "$BASE_DIR/usr/sbin/"
echo "Installation terminée."
echo "Binaire installé dans $BASE_DIR/usr/sbin/"
pkill bichttpd
chmod +x install.sh
./install.sh
ls -l ~/opt/bichttpd/usr/sbin/
cd ~/opt/bichttpd/usr/sbin/
./bichttpd -s -p 8443
curl -k https://localhost:8443
openssl s_client -connect localhost:42116
