#!/bin/bash

# Preguntar por el token de Ubuntu Pro y almacenarlo en una variable
read -p "Introduce tu token de Ubuntu Pro: " token

# Configurar la seguridad del SSH
# Preguntar por el puerto que el usuario desea utilizar para SSH
read -p "Ingrese el puerto que desea utilizar para SSH: " portssh

# Almacenar la ruta del archivo de configuración de SSH
SSHD_CONFIG="/etc/ssh/sshd_config"

echo "Configurando la seguridad del SSH..."

# Cambiar el puerto
sed -i "s/#Port 22/Port $portssh/" $SSHD_CONFIG

# Desactivar el login del usuario root y más configuraciones
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' $SSHD_CONFIG
sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding no/g' $SSHD_CONFIG
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 2/g' $SSHD_CONFIG
sed -i 's/#Compression delayed/Compression no/g' $SSHD_CONFIG
sed -i 's/#LogLevel INFO/LogLevel VERBOSE/g' $SSHD_CONFIG
sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/g' $SSHD_CONFIG
sed -i 's/#MaxSessions 10/MaxSessions 2/g' $SSHD_CONFIG
sed -i 's/#TCPKeepAlive yes/TCPKeepAlive no/g' $SSHD_CONFIG
sed -i 's/X11Forwarding yes/X11Forwarding no/g' $SSHD_CONFIG
sed -i 's/#AllowAgentForwarding yes/AllowAgentForwarding no/g' $SSHD_CONFIG


# Reiniciar el servicio SSH para aplicar los cambios
systemctl restart sshd

echo "Configuracion de SSH completada."

# Crear el usuario alex y anadirlo al grupo sudo
echo "Creando el usuario 'alex' y anadiendolo al grupo sudo..."
useradd -m -s /bin/bash alex
usermod -aG sudo alex
echo "Usuario 'alex' creado y anadido al grupo sudo."

#Actualizaciones del sistema
apt update -y
apt upgrade -y
apt dist-upgrade -y
apt autoremove -y
apt autoclean -y

#Corrigiendo permisos en archivos sensibles
chmod 400 /boot/grub/grub.cfg
chmod 700 /etc/cron.monthly
chmod 700 /etc/cron.daily
chmod 700 /etc/cron.d
chmod 700 /etc/cron.hourly
chmod 700 /etc/cron.weekly
chmod 600 /etc/ssh/sshd_config
chmod 600 /etc/crontab

# Anadir una tarea cron para actualizar y mejorar el sistema diariamente a las 5 de la manana
echo "Anadiendo tarea cron para actualizar y mejorar el sistema diariamente a las 5 de la manana..."
(crontab -l 2>/dev/null; echo "0 5 * * * sudo apt update -y && sudo apt upgrade -y && sudo apt dist-upgrade -y && sudo apt autoremove -y && sudo apt autoclean -y && sudo reboot") | crontab -
echo "Tarea cron anadida."

echo "Configurando ubuntu Pro y hardening nivel gubernamental (DISA-STIG)"
pro attach $token
apt update -y && sudo apt install ubuntu-advantage-tools -y
pro status
pro enable usg
pro enable livepatch
pro enable realtime-kernel
pro status
ua enable usg
apt install usg
ua enable fips-updates
usg fix disa_stig

echo "Bloqueando medios extraibles"
systemctl daemon-reload
systemctl disable cdrom-service
echo "install usb-storage /bin/true" > /etc/modprobe.d/usb_storage.conf

echo "Deshabilitar protocolos inseguros poco usados: tipc, freevxfs, hfs, cramfs, jffs2, dccp, sctp, rds, hfsplus, udf"
echo -e "install tipc /bin/true" > /etc/modprobe.d/secure.conf
echo -e "install freevxfs /bin/true" > /etc/modprobe.d/secure.conf
echo -e "install hfs /bin/true" > /etc/modprobe.d/secure.conf
echo -e "install cramfs /bin/true" > /etc/modprobe.d/secure.conf
echo -e "install jffs2 /bin/true" > /etc/modprobe.d/secure.conf
echo -e "install dccp /bin/true" > /etc/modprobe.d/secure.conf
echo -e "install sctp /bin/true" > /etc/modprobe.d/secure.conf
echo -e "install rds /bin/true" > /etc/modprobe.d/secure.conf
echo -e "install hfsplus /bin/true" > /etc/modprobe.d/secure.conf
echo -e "install udf /bin/true" > /etc/modprobe.d/secure.conf

echo "Activando ufw y configurando puertos permitidos"
# Función para permitir puertos específicos
permit_ports() {
    ports=("$@")
    for port in "${ports[@]}"; do
        sudo ufw allow "$port/tcp"
        echo "Permitido el puerto $port/tcp"
    done
}

# Configurar UFW
apt update
apt install -y ufw
ufw enable
ufw default deny incoming
ufw default allow outgoing

# Permitir los puertos por defecto
default_allow_ports=(80 443 8443 8447 $portssh)
permit_ports "${default_allow_ports[@]}"

# Preguntar si desea permitir puertos adicionales
read -p "¿Desea permitir puertos adicionales? (n/N para no permitir): " response

if [[ "$response" =~ ^(n|N)$ ]]; then
    echo "No se permitirán puertos adicionales."
else
    read -p "Ingrese los puertos a permitir, separados por espacios: " -a additional_ports
    permit_ports "${additional_ports[@]}"
fi

# Verificar las reglas actuales de UFW
sudo ufw status verbose

echo "Firewall configurado"

echo "Bloqueando ping desde el kernel"
sysctl -p
echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all

echo "Eliminando compiladores y software no usado"

#!/bin/bash

# Funcion para eliminar y purgar paquetes
remove_and_purge() {
    package="$1"
    if dpkg -l | grep -q "^ii  $package "; then
        read -p "¿Desea eliminar y purgar $package? (y/N): " response
        if [[ "$response" =~ ^(y|Y)$ ]]; then
            apt remove -y "$package"
            apt purge -y "$package"
            echo "$package ha sido eliminado y purgado."
        else
            echo "$package no sera eliminado."
        fi
    else
        echo "$package no esta instalado."
    fi
}

# Lista de herramientas a eliminar y purgar
tools=(gcc cc clang g++ nc nmap curl telnet wget)

# Actualizar lista de paquetes
apt update

# Iterar sobre cada herramienta y preguntar al usuario
for tool in "${tools[@]}"; do
    remove_and_purge "$tool"
done

# Limpiar los paquetes que ya no se necesitan
apt autoremove -y
apt clean

# Preguntar al usuario si desea deshabilitar el USB
read -p "¿Desea deshabilitar el USB? (Y/N): " DISABLE_USB

if [[ "$DISABLE_USB" == "Y" || "$DISABLE_USB" == "y" ]]; then
    echo "Deshabilitando USB..."

    # Deshabilitar el acceso a /media
    chmod 000 /media

    # Deshabilitar el almacenamiento USB
    echo -e "install usb-storage /bin/true" > /etc/modprobe.d/usb_storage.conf
    for i in /sys/bus/usb/devices/usb*/authorized; do echo 0 > $i; done
    for i in /sys/bus/usb/devices/usb*/authorized_default; do echo 0 > $i; done

    echo "USB deshabilitado."
else
    echo "El USB no será deshabilitado."
fi

#Message disclaimer
printf “WARNING : Unauthorized access to this system is forbidden and will be” > /etc/issue
printf “prosecuted by law. By accessing this system, you agree that your actionsn” >> /etc/issue
printf “may be monitored if unauthorized usage is suspected.n” >> /etc/issue
cat /etc/issue > /etc/issue.net

#Change UMASK
grep -q “UMASK.*022” /etc/login.defs
(($? == 0)) && sed -i 's/022/027/g' /etc/login.defs
grep -q “umask 027” /etc/profile
(($? == 1)) && echo -e “umask 027” >> /etc/profile
grep -q “umask 027” /etc/bash.bashrc
(($? == 1)) && echo -e “umask 027” >> /etc/bash.bashrc

#Set disable IPv6
cat /etc/*rele*|grep Ubuntu|grep 22.04 && sed -i 's/GRUB_CMDLINE_LINUX=””/GRUB_CMDLINE_LINUX=”ipv6.disable=1″/g' /etc/default/grub

#Configuracion politica de contraseñas y bloqueo de
#Crear common-password

password requisite pam_pwquality.so retry=3 minlen=12 minclass=4 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1
password [success=1 default=ignore] pam_unix.so obscure yescrypt remember=15
password requisite pam_deny.so
password required pam_permit.so

#Crear common-auth
auth required pam_faillock.so preauth audit silent deny=3 unlock_time=900
auth [success=2 default=ignore] pam_unix.so nullok
auth [success=1 default=ignore] pam_sss.so nullok

auth [default=die] pam_faillock.so authfail audit deny=3 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=3 unlock_time=900
auth requisite pam_deny.so
auth required pam_permit.so
auth optional pam_cap.so

apt install -y libpam-pwquality
sed -i 's/PASS_MAX_DAYS/#PASS_MAX_DAYS/g' /etc/login.defs && sed -i 's/PASS_MIN_DAYS/#PASS_MIN_DAYS/g' /etc/login.defs && printf “n##CIBERnPASS_MAX_DAYS 90nPASS_MIN_DAYS 1nSHA_CRYPT_MIN_ROUNDS 10000n” >> /etc/login.defs
echo 'TMOUT=900' >> /etc/profile
cp -f /home/osboxes/hardening/common-auth /etc/pam.d/common-auth && chown root:root /etc/pam.d/common-auth && chmod 644 /etc/pam.d/common-auth
cp -f /home/osboxes/hardening/common-password /etc/pam.d/common-password && chown root:root /etc/pam.d/common-password && chmod 644 /etc/pam.d/common-password

echo "Proceso completado."



echo "Todas las tareas se han completado exitosamente."
