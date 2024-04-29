groupadd -f manufacturing
groupadd -f distribution
groupadd -f marketing

true ||
useradd -m -g manufacturing -s /bin/bash user1 ||
useradd -m -g distribution -s /bin/bash user2 ||
useradd -m -g marketing -s /bin/bash user3 

echo user1:password | chpasswd
echo user2:password | chpasswd
echo user3:password | chpasswd

rm -rf manufacturing distribution marketing
mkdir distribution manufacturing marketing

chown user1:distribution distribution
chown user2:manufacturing manufacturing
chown user3:marketing marketing

usermod -aG manufacturing,distribution,marketing aidan