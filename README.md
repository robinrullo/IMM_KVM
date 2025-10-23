# Based on μDRAC https://github.com/nickroethemeier/udrac

### IMM KVM Launcher for Windows, Linux and OSX

## Currently Supported

* IBM System X IMM I KVM

## Build Dependencies

* Python 3.10 or greater
* PyInstaller

## Some Important Notes

This GUI launcher is based on "reverse engineered" interactions with the out-of-band management card.

**Absolutly no respect or effort has been made toward security**, and often the password is literally handed to the java
code via argument...

**WARNING**: Due to the nature of connecting to OOB server management, *ALL SSL ISSUES ARE BYPASSED AND IGNORED*

## Extra Important License Notes

This launcher package contains code from MANY sources including

* Java JRE, from Sun Microsystems / Oracle
* IBM Video Viewer KVM / Avocent Corporation

These external libraries are included as part simply because they are annoying to acquire. If anyone cares please let me
know.

## To setup proxy
Use stunnel 5.68: https://www.stunnel.org/archive/5.x/

Add this to conf:
```properties
[imm]
client = yes
accept = 127.0.0.1:9443
connect = <IMM/KVM IP>:443
sslVersion = TLSv1
debug = 7
```