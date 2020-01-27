#!/bin/bash
# You can use this script and modify the bl_website() in modules/web_beacon/web_beacon.py
full_path=$(realpath $0)
dir_path=$(dirname $full_path)
echo "Downloading https://sebsauvage.net/hosts/host"
wget -q https://sebsauvage.net/hosts/hosts -O $dir_path/utils/hosts.txt
echo "Done"
echo "Updating cron job wget https://sebsauvage.net/hosts/hosts "
line="5 0 * * * $dir_path/utils/wget_BL.sh"
(echo "$line" ) | crontab -
echo "Done"