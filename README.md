# libnexmonkali

Version of libnexmon.so from https://github.com/seemoo-lab/nexmon for buiding and usage in Kali Nethunter Chroot with the Huawei Nexus 6p.
<P>There is a prebuilt version of libnexmonkali.so available in the repo. This needs to be installed to /usr/lib/ in the kali chroot.

# What's changed?
<P>This is a <B>replacement</B> for the `kalilibnexmon.so` that ships in Kali NetHunter 2020.3 in `/system/lib64/kalilibnexmon.so`.
<P>This version adds ioctl() support for SIOCSIWFREQ and SIOCGIWFREQ, meaning that programs that use ioctl calls will be able to directly get/set the channel of the onboard wifi instead of relying on the `nexutil` tool.
<P>Additionally, it adds a 50 millisecond delay after each injected frame, which seems to eliminate driver crashes when doing deauths with aireplay-ng.


# How does it work?

We are intercepting the `nl_send_auto_complete` function that programs such as airodump-ng and kismet use to initiate a Netlink message, asking the kernel to tell the driver to change channels.
We pass that message on to the kernel as usual, but also read the message and set the channel appropriately ourselves.
Because this isn't the real driver, we won't send anything back to the program -- but airodump-ng and kismet don't bother to listen for replies anyway, so that's okay.
Programs like `iw` do listen for a reply message, which we can't fake.  They will complain that the channel change didn't work, but it actually did.

```
root@kali:~# nexutil -k
chanspec: 0x1006, 6
root@kali:~# LD_PRELOAD=/root/libnexmonkali/libnexmonkali.so iw dev wlan0 set channel 36
command failed: Operation not supported (-95)
root@kali:~# nexutil -k
chanspec: 0xd024, 36
```


# Steps to Build

Clone the repo:
  git clone https://github.com/dracode/libnexmonkali

Build:
  make
  
Install:
  make install

Use:
  LD_PRELOAD=/path/to/libnexmonkali.so airodump-ng wlan0

