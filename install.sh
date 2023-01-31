#!/usr/bin/bash

# Author: pwnlog
# Description: Auto install panpol in Linux

# Add execution permissions
chmod +x panpol.py

# Add a symlink to /usr/local/bin/
sudo ln -sf $(pwd)/panpol.py /usr/local/bin/panpol.py 

# Check if /usr/local/bin/ is in $PATH
echo $PATH | grep /usr/local/bin
if [[ $? -eq  0 ]]
then
    :
else
    # Add /usr/local/bin to $PATH
    echo 'PATH=$PATH:/usr/local/bin' >> ~/.zshrc
    echo 'PATH=$PATH:/usr/local/bin' >> ~/.bashrc
fi

echo "[+] Finished installing panpol"
