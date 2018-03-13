# Tracebox

[![Build Status](https://travis-ci.org/tracebox/tracebox.png?branch=master)](https://travis-ci.org/tracebox/tracebox) [![CircleCI](https://circleci.com/gh/tracebox/tracebox.svg?style=svg)](https://circleci.com/gh/tracebox/tracebox)

[Tracebox](http://www.tracebox.org) is a tool that allows to detect middleboxes on any paths, i.e., between a source and any destination. Tracebox can be viewed as a tool similar to traceroute as it uses ICMP replies to identify changes in the packets. The fact that tracebox is able to detect middleboxes comes from the observation that ICMP messages are often not as defined in RFC792. Indeed it is quite common to receive a ICMP Time-to-Live exceeded message with the original datagram instead of 64 bits as described in the standard. This is caused by operating systems configured to reply with full ICMP (e.g., Linux, Cisco IOS-XR, etc.) as well as the ICMP Multi-Part Messages extension that standardize the fact that routers using MPLS tunnels replies and ICMP message containing the full datagram.

## Install

### Mac OS X (Using Homebrew)

Yosemite and El Capitan users need to first ensure they installed the full command line developer tools provided by Apple using `xcode-select --install`

    brew install tracebox

### Linux

Requirements: 

*Debian*

    apt-get install autotools autoconf automake libtool liblua5.2-dev libpcap-dev libjson0 libjson0-dev libcurl4-gnutls-dev lua-ldoc libnetfilter-queue-dev lua5.2

*Fedora (24)*

    dnf install autoconf automake libtool lua-devel libpcap-devel json-c-devel gnutls-devel lua-ldoc libnetfilter_queue-devel

To build:

    $ ./bootstrap.sh
    $ ./configure [--prefix=install_prefix [--enable-tests][--enable-curl]]
    $ make
    # make install

You can [grab the latest build here](https://circleci-tkn.rhcloud.com/api/v1/project/tracebox/tracebox/tree/master/latest/artifacts/tracebox_latest_amd64.deb) (source package or *.deb).

We rely on [CircleCI] to generate the build packages, if the above link fails,
you can try to retrieve them manually by browsing to [the tracebox project
build status](https://circleci.com/gh/tracebox/tracebox),
selecting the latest build and then downloading the *.deb packages in the Artifacts tab.

### OpenWRT

The package is available at http://github.com/tracebox/openwrt.

Inside the OpenWRT SDK:

    $ echo "src-git tracebox git://github.com/tracebox/openwrt.git" >> feeds.conf.default
    $ ./scripts/feeds install -a tracebox
    $ make menuconfig # select tracebox in "Network"
    $ make package/tracebox/compile # should generate a package in bin/<target>/packages/tracebox_*.ipk

This is currently unmaintained.

### Android

An Android build script is available at https://github.com/tracebox/android

Your phone will need to be rooted.

## Documentation

Upon installation, see `man tracebox` and in `/usr/local/share/doc/tracebox`

The Lua API is (should) be documented and is available at http://tracebox.org/lua_doc.
It can be generated using [LDoc](https://github.com/stevedonovan/LDoc) from the doc directory (see config.ld):

    $ ldoc .

The documentation should be created under doc/html

## JSON Output Format

More detailled information about the successive hops can be obtained using the -j option,
this will as well change the output mode to JSON.

As the output will be buffered, you SHOULD make use of the max hop parameter
(-m) if the target node does not answer in order to get the partial trace.

```javascript
{
    "addr"     : "IP of the destination",
    "name"     : "Name of the destination [Optional]",
    "max_hops" : "Number of maximum hops",
    "Hops"     : [ /* Array containing each hop information */
        {
            "hop"           : "Corresponding TTL/hop limit",
            "from"          : "IP address of that hop",
            "delay"         : "Delay between the probe and the reply (usec)",
            "name"          : "Name of the hop [Optional]",
            "Modifications" : [
                // if tracebox was called with -v :
                    "Name of the modification" : {
                        "Expected" : "Value injected",
                        "Received" : "Value receveid"
                    },
                // else:
                    "Name of the modification"
            ],
            "Additions"    : [
                // if tracebox was called with -v :
                    {
                        "Name of the modification" : {
                            "Info": "Information added"
                        },
                    }
                // else:
                    "Name of the field(s) added"
            ],
            "Deletions"     : [
                // if tracebox was called with -v :
                    {
                        "Name of the modification" : {
                            "Info": "Information deleted"
                        },
                    }
                // else:
                    "Name of the field(s) deleted"
            ],
            "ICMPExtension" : /*[Optional]*/ [
                //if tracebox was called with -v :
                    {
                        "Name of the extension" : {
                            "Info": "Information of the extension"
                        }
                    },
                // else:
                    "Name of the extension(s)"

            ]
        }
    ]
}
```
