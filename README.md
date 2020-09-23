# libnexmonkali

Version of libnexmon.so from https://github.com/seemoo-lab/nexmon for buiding and usage in Kali Nethunter Chroot with the Huawei Nexus 6p.
<P>There is a prebuilt version of libnexmonkali.so available in the repo. This needs to be installed to /usr/lib/ in the kali chroot.

# What's changed?
<P>This is a <B>replacement</B> for the `kalilibnexmon.so` that ships in Kali NetHunter 2020.3 in `/system/lib64/kalilibnexmon.so`.
<P>This version adds ioctl() support for SIOCSIWFREQ and SIOCGIWFREQ, meaning that programs that use ioctl calls will be able to directly get/set the channel of the onboard wifi instead of relying on the `nexutil` tool.
<P>Additionally, it adds a 50 millisecond delay after each injected frame, which seems to eliminate driver crashes when doing deauths with aireplay-ng.




# Steps to Build

Clone the repo:
  git clone https://github.com/dracode/libnexmonkali

Build:
  make
  
Install:
  make install
