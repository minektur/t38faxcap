#!/usr/bin/env python
import pyshark
import re
from pathlib import Path
import subprocess
import tempfile
import logging
import argparse


# type 7 packets are the t4-non-ecm-sig-end - the last packet in a multi-fragment send of t4 data.  These
# can also have a sub field that is of type 6 that has error-recovery data (duplicate of prev packet)
#  at least in the pcaps I've examined.  Anyway, tshark will have a list of all the reassmebled packet data
# so we look for type7 which are the 'last packet' and then grope around in tshark's output to actually find
# the data since pyshark doesn't automatically make it available

""" tshark exposes this data in the xml, but pyshark doesn't put it in to an
    easy to access field.  This shows up in the disector output on the last fragment
    of an HDLC field in wireshark/tshark's analysis - it is synthetically generated
    by the disector and printed in the text tshark emits, but it's not in the XML.
    I don't really want to have to reassemble HDLC fragments myself when tshark
    already does it so I grope around in the string output and grab all the data myself.

    ugh.  This is probably wrong/brittle but it's working right now... """
def get_all_fragments_t38(pkt):
    layer = pkt.t38
    fragments = {}
    for f in layer._get_all_fields_with_alternates():
        if f.name == 't38.fragment' and f.raw_value and f.showname:
            m = re.match(r'Frame: (\d+), payload: (\d+)-(\d+)', f.showname)
            if m:
                offset = int(m.group(2))
                fragments[offset] = bytes.fromhex(f.raw_value)
    return b''.join(data for _, data in sorted(fragments.items()))

def guess_encoding(data):
    """ 
    1d encoding uses "000000000001" as EOL
    2d encoding uses "0000000000011" as EOL

    At the end of the page you always find 6 consecutive EOL markers.

    Look for these and guess encoding based on which we find.  The bit patterns
    are definitely not required to be byte-aligned so quick-and-dirty check

    return values:  -1:error   1: 1d   2:2d
    """

    bits = "".join(format(b, "08b") for b in data)

    one_eop = "000000000001"*6
    two_eop = "0000000000011"*6

    if one_eop in bits:
        ret = 1
    elif two_eop in bits:
        ret = 2
    else: 
        logging.debug(f"Encoding not detected!")
        ret = -1

    logging.debug(f"Encoding guessed as {ret}d")
    return ret



def remove_padding_and_framing(data):
    """ 
    take the full udp payload and remove pre-page framing up to EOL token
    and optionally remove the post T4 padding that most fax machines send
    In our case we're going to ignore the end padding since our decoder
    doesn't seem to care if extra crap is there, and it makes us not have
    to care whether we're doign 1D or 2D encoding (e.g. don't need to know
    the final EOP format).  This also frees us from caring about whether our
    bitstream is 8-bit aligned which is IS at the beginning, but may not be
    at the end.

    return the buffer minus the beginning training/framing
    """
    # alwyas the beginning of the first line looks like this 
    BEG = "000000000001"

    #for 2d encoded it is EOL+1, for 1d encoded, omit the extra 1
    #END = (BEG + "1") * 6

    #for the beginning, we could just take everything up to the first \x00 off, 
    # but if we decide later we want to trim the end too, this is necessary because
    # the end might not be byte aligned
    bits = "".join(format(b, "08b") for b in data)
    start = bits.find(BEG)
    #end = bits.find(END)
    
    #if start == -1 or end == -1:
    if start == -1:
        #logging.debug("Can't find beginning or end token in stream.")
        logging.debug("Can't find beginning token in the stream.")
        return b''

    #bits = bits[start:end+78]
    bits = bits[start:]
    # not sure this works for the last byte if we're not byte aligned
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

def check_training(data):
    """ 
    too much trouble to figure out how to tell in the pcap when the udp stream is for training/timing
    vs actually sending image data. we can just skip these, this is an emperical heuristic I guessed at
    """
    if len(data) < 1000:
        logging.debug("Training/Check sequence")
        return b""
    return data
    

def g3_to_tif(data, outputfile, savefiles, encoding):
    """
    we use fax2tiff to convert g3/T.4 stream to tif - imagemagick also kinda works, but
    this has more control over things.

    you pass the data and a filename, this writes a tempfile and converts it to tiff into
    that file.

    savefiles -> keep intermediate g3 files for debugging 
    encoding -> 1, 2  for 1d or 2d
    """
    output_path = Path(outputfile)
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="g3_fax_", suffix=".bin", delete=False) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)

        logging.debug(f"temp file  {tmp_path}")

        result = subprocess.run(
            ["/usr/bin/fax2tiff", f"-{encoding}", "-M", "-o", str(output_path), str(tmp_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )

        if result.returncode != 0:
            raise RuntimeError(result.stderr or result.stdout or "fax2tiff failed")

        return str(output_path)

    finally:
        if tmp_path is not None and not savefiles:
            tmp_path.unlink()


def commandline():
    parser = argparse.ArgumentParser(
        description="Extract t38 page images from fax call in pcap file."
    )

    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="enable debug logging"
    )

    parser.add_argument(
        "-s", "--save",
        action="store_false",
        help="save intermediate files for debugging"
    )

    parser.add_argument(
        "infile",
        metavar="filename.pcap",
        help="input pcap file"
    )

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

    return args


def main():
    args = commandline()
    cap = pyshark.FileCapture(args.infile, display_filter='t38.field_type == 7')
    i = 0
    for pkt in cap:
        data =  get_all_fragments_t38(pkt)
        if len(data) == 0:
            logging.debug(f"{pkt.number}: No data.")
            continue

        data =  remove_padding_and_framing(data)
        if len(data) == 0:
            logging.debug(f"{pkt.number}: Can't find EOL sequence at start of data.")
            continue

        data = check_training(data)
        if len(data) == 0:
            logging.debug(f"{pkt.number}: Training/Check sequence.")
            continue

        encoding = guess_encoding(data)
        if encoding == -1:
            logging.debug(f"{pkg.number}: error checking encoding format.")
            continue

        fname = f"extract{i}.tif"
        print(f"Pkt:{pkt.number} Length:{len(data)} -  saving as {fname}")
        try:
            g3_to_tif(data, fname, args.save, encoding)
        except RuntimeError as e: 
            logging.debug(f"{pkt.number}: {e} Some kind of decode error - might still produce an image.")
        i+=1


if __name__ == "__main__":
    main()
