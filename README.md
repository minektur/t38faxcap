# t38faxcap
Command line utility to extract T.38 fax images from PCAP files and export them as TIFF files.

You put in a pcap file that has a sip-phone call with a fax that has T38-sent  pages in it.

You get out a set of tiff files representing each page that was sent via T38.

## Dependencies
* This depends on the *fax2tiff* program (part of the *libtiff-tools* packages on ubuntu/rhel/alma/etc)
* This also depends on *tshark* (command-line companion to libraries) being installed.
* Your virtual environment will need the *pyshark* python package and all it's dependencies to interact with tshark

I've only tested this in linux (and WSL2 under win11).  It would probably work under other
operating systems if you get the dependencies and virtual environment right.

## Usage

    $uv run capfax.py -h
    usage: capfax.py [-h] [-d] [-s] filename.pcap

    Extract t38 page images from fax call in pcap file.

    positional arguments:
      filename.pcap  input pcap file

    options:
      -h, --help     show this help message and exit
      -d, --debug    enable debug logging
      -s, --save     save intermediate files for debugging


## Method of Operation
This program works by:

1) Leveraging tshark's udp fragment reassembly and the t38 disscector to get T38 payloads from
   sets of udptl packets

2) Removing fax framing/padding and guesses at some metadata (e.g. T4 encoding scheme) which
   are all probably available in the pcap file in the actual conversation between the fax 
   machines, but instead of digging around for that, I can infer the necessary stuff from the
   data itself

3) Saving the data to a temp file and calls fax2tiff from the libtiff-tools package to convert the
   T4 RLE encoded data to a normal tiff file in the current working directory, sequentially numbered
   in the order they are found in the PCAP.

The conversion command is something like this:

fax2tiff -2 -M -o test.tiff captured-data.g3

## Example
There is an included example.pcap which has a single fax call in it with a one page fax.  Extract it
to find my secret message.

## braindead software
This software is full of ugly hacks that aren't good production code, but which work for me for 
the situation I need it in.  For instance, We guess which encoding is used by looking for end-of-page 
markers and use that to supply the right command line options to fax2tiff.  Also the pyshark library
doesn't parse/expose the data I need, at least in an easily usable form, so I grope around in it's
internals to get the data.  I wouldn't be surprised if this stops working in some future version of pyshark
in which case I'll have to do things the hard way, but as they say "sufficient unto the day is the 
evil thereof".

## missing functionality
I don't have any examples of T.6 MMR encoding and this software doesn't support it

No support for TPKT over TCP for the same reasons.

This software expects that your pcap will contain packets for only one phone call - you can filter as needed
in wireshark/tcpdump/tshark.  Alternatively, you can just print out pages interleaved from many faxes in the
same pcap file, in the order that each image becomes complete with a t4-non-ecm-sig-end packet.

