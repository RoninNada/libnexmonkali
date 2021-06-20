# What <B>is</B> `libnexmonkali`?
It's an alternate version of libnexmon.so from https://github.com/seemoo-lab/nexmon for building and usage in Kali Nethunter Chroot.

It's a wrapper that will allow standard Linux wifi tools such as the `aircrack-ng` suite to use the onboard wifi interfaces on some mobile phones.

There are prebuilt versions of `libnexmonkali.so` available in the repo for the Nexus 5 and Nexus 6P.

# What's changed in this version from the stock NetHunter one?
This is a <B>replacement</B> for the `kalilibnexmon.so` that currently ships in Kali NetHunter, that implements a few improvements.

This version adds ioctl() support for SIOCSIWFREQ and SIOCGIWFREQ, meaning that programs that use ioctl calls will be able to directly get/set the channel of the onboard wifi instead of relying on the `nexutil` tool.

Additionally, it adds a 50 millisecond delay after each injected frame, which seems to eliminate driver crashes when doing deauths with aireplay-ng.

Now it's also intercepting `netlink` messages, which is a newer method for programs to tell drivers to do things like change wifi channels.  The intent is to allow more programs to function with the non-standard wifi drivers found on the Nexus 5 and 6P.  It's not a full implementation, but it helps some.

# How does the `netlink` part work?
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
Do the following from within your Kali NetHunter chroot environment.

Clone the repo:
  `git clone https://github.com/dracode/libnexmonkali`

Install dependencies:
  `apt install libnl-3-dev`
  
Build:
  `make`
  
Install:
  `make install`

Use:
  `LD_PRELOAD=/path/to/libnexmonkali.so airodump-ng wlan0`

