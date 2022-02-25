/** @file
    Decoder for solar inverter monitoring system.
    Copyright (C) 2022 Lawrence Rust, lvr at softsystem dot co dot uk

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

/**
    The monitoring system sends 2 different packets every ~20 seconds.

    Frequency 433.95 MHz, modulation FSK_PCM, bit period 255 microseconds.

    The following Flex decoder will capture the raw data:
    rtl_433 -f 433.95M -s256000 -Y classic\
        -X'n=Solar,m=FSK_PCM,s=254,l=254,r=3000,preamble=0x2dd4'

    Raw packet layout:
    - 3 bytes of 0xaa
    - 2 sync bytes: 0x2d 0xd4
    - 286 or 199 bits of 4b6b encoded data

    4b6b encoding maps 4-bit data into a 6-bit DC balanced line code providing
    2 bits of error detection and potential correction.

    The decoded packet has the following layout:
    - 4 byte header: 0x52 05 D4 B1 or 0x52 03 D4 B1.
    - 3 or 5 groups of data in the form: TT NN DD..
      where TT is the data type and NN is the byte count of data DD.
    - 1 byte checksum
*/

#include "decoder.h"

#define PREFIX "solar_4b6b"

/*
 * 4b/6b decode
 * https://ntrs.nasa.gov/archive/nasa/casi.ntrs.nasa.gov/20160010301.pdf
 * There are 4+6+6+4 unique balanced (3x1+3x0) 6-bit codes
 */
static uint8_t decode_4b6b (uint8_t byte)
{
    switch (byte)
    {
#if 0 /* NASA original */
    case 026: return 0x0;
    case 045: return 0x1;
    case 046: return 0x2;
    case 043: return 0x3;
    case 054: return 0x4;
    case 015: return 0x5;
    case 016: return 0x6;
    case 013: return 0x7;
    case 064: return 0x8;
    case 061: return 0x9;
    case 062: return 0xa;
    case 023: return 0xb;
    case 034: return 0xc;
    case 031: return 0xd;
    case 032: return 0xe;
    case 051: return 0xf;
#else
    case 026: return 0x0;
    case 045: return 0x9;
    case 046: return 0xa;
    case 043: return 0xb;
    case 054: return 0x8;
    case 015: return 0x1;
    case 016: return 0x2;
    case 013: return 0x3;
    case 064: return 0xc;
    case 061: return 0xd;
    case 062: return 0xe;
    case 023: return 0x7;
    case 034: return 0x4;
    case 031: return 0x5;
    case 032: return 0x6;
    case 051: return 0xf;
#endif

    /* Control codes */
    case 070: return 0xf0;
    case 007: return 0xf1;
    case 052: return 0xf2;
    case 025: return 0xf3;

    /* Invalid codes */
    default:  return 0xff;
    }
}

/* List of fields to appear in the `-F csv` output */
static char *output_fields[] = {
        "model",    "id",
        "Output_VA","Output_V",                          /* Type 0x5203 msgs */
        "Input_V",  "Type_15", "Total_KWH", "Today_KWH", /* Type 0x5205 msgs */
        "Flags",    "Unknown",
        "mic",
        NULL
};

/* Indices into output_fields */
enum Keys {
        kModel = 0, kID,
        kType02, kType11,
        kType14, kType15, kType16, kType17,
        kType10, kTypeUnk,
        kMIC
};

static inline const char *key2str (enum Keys k)
{
    return output_fields[ k];
}

static int decode_message (r_device * const decoder, bitbuffer_t *bb,
        unsigned row, unsigned bitpos)
{
    enum  {
        kBits = 6,      /* 4b6b bit length => 1 nybble */
        kMinMsg = 5,    /* 4 byte header + checksum */
        kMaxMsg = 48,
        kValues = 8
    };

    bitbuffer_t bytes = {0};
    uint8_t buf[ kMaxMsg];
    char id[12];
    data_t *data;

    int code, chk;
    unsigned bits, len, i;

    /* Check min/max message length */
    bits = bb->bits_per_row[ row];
    if (bits < bitpos + kMinMsg * 2 * kBits)
    {
        if (decoder->verbose > 0)
            bitbuffer_printf ( bb, PREFIX ":vv Message too short ");
        return DECODE_ABORT_LENGTH;
    }

    if (bits > bitpos + kMaxMsg * 2 * kBits)
    {
        if (decoder->verbose > 0)
            bitbuffer_printf ( bb, PREFIX ":vv Message too long ");
        return DECODE_ABORT_LENGTH;
    }

    /* Decode the 4b6b encoded message */
    for (i = bitpos; i + kBits <= bits; i += kBits)
    {
        uint8_t c = bitrow_get_byte (bb->bb[row], i) >> (8 - kBits);
        uint8_t n = decode_4b6b (c);
        if (n > 0xf)
        {
            if (decoder->verbose > 0)
            {
                //decoder_output_bitbufferf (decoder,
                bitbuffer_printf (
                        bb, PREFIX ":vv Bad 6b code %#o %#x @%u ", c, c, i);
            }
            return DECODE_FAIL_SANITY;
        }

        bitbuffer_add_bit (&bytes, !!(n & 0x08));
        bitbuffer_add_bit (&bytes, !!(n & 0x04));
        bitbuffer_add_bit (&bytes, !!(n & 0x02));
        bitbuffer_add_bit (&bytes, !!(n & 0x01));
    }

    bits = bytes.bits_per_row[0];
    if (sizeof (buf) * 8 < bits)
    {
        fprintf (stderr, PREFIX ": Decoded message too long\n");
        return DECODE_FAIL_SANITY;
    }
    bitbuffer_extract_bytes (&bytes, 0, 0, buf, bits);

    /* Message integrity check */
    len = bits / 8 - 1;
    code = buf[ len];
    chk = 0xff & add_bytes (buf, len);
    if (chk != code)
    {
        if (decoder->verbose >= 1)
        {
            //decoder_output_bitbufferf (decoder,
            bitbuffer_printf (
                    &bytes,
                    PREFIX ":vv Incorrect CHECKSUM 0x%02x != 0x%02x\n",
                    chk, code);
        }
        return DECODE_FAIL_MIC;
    }

    if (decoder->verbose >= 1)
    {
        decoder_output_bitbuffer (decoder,
        //bitbuffer_printf (
                &bytes, PREFIX ":vv Decoded msg");
    }

    /* Grab the 4 byte header '0x52[03,05]d4b1' and print it as an ID
     * NB buf[1] probably contains the no. data fields following
     */
    i = 0;
    snprintf (id, sizeof (id), "%02X%02X-%02X%02X",
            buf[i], buf[i + 1], buf[i + 2], buf[i + 3]);
    i += 4;

    /* Create the data structure, ready for the decoder_output_data function. */
    /* clang-format off */
    data = data_make (
            key2str (kModel),   "Device Type",  DATA_STRING, "Solar monitor 4b6b",
            key2str (kID),      "ID",           DATA_STRING, id,
            NULL);
    /* clang-format on */

    if (NULL == data)
        return DECODE_FAIL_SANITY;

    /* Parse the remaining message into printable values */
    while (i < len)
    {
        unsigned const type = buf[i++];
        unsigned const cnt = buf[i++];
        unsigned n;
        enum Keys key;
        struct Value
        {
            char name[12];
            char text[14];
        } value;

        /* Grab cnt bytes of little endian data */
        switch (cnt)
        {
        case 0:
            n = 0;
            break;
        case 1:
            n = buf[i];
            i += 1;
            break;
        case 2:
            n = buf[i] | ((unsigned)buf[i+1] << 8);
            i += 2;
            break;
        case 3:
            n = buf[i] | ((unsigned)buf[i+1] << 8) | ((unsigned)buf[i+2] << 16);
            i += 3;
            break;
        case 4:
            n = buf[i] | ((unsigned)buf[i+1] << 8)
                    | ((unsigned)buf[i+2] << 16) | ((unsigned)buf[i+3] << 24);
            i += 4;
            break;
        default:
            fprintf (stderr,
                    PREFIX ": Unknown data type %#x length %#x", type, cnt);
            i += cnt;
            continue;
        }

        /* Set field name and format the value */
        value.name[0] = '\0'; /* Default to key name */
        switch (type)
        {
        case 0x10:
            /* Always last. Normally 0 but 0x81 during mains failure */
            if (!n)
                continue;
            key = kType10;
            snprintf (value.text, sizeof (value.text), "%#x", n);
            break;

            /* type 0x5203 msgs */
        case 0x11:
            /* Inverter Vout. 2 bytes, x0.1Vac. 0 on mains fail, 2152..2584 */
            key = kType11;
            //snprintf (value.name, sizeof (value.name), "OutputV_%02X", type);
            snprintf (value.text, sizeof (value.text), "%.1f Vac", n * 0.1);
            break;
        case 0x02:
            /* Inverter power. 2 bytes, x0.1VA. 0 on mains fail, 0..38446 */
            key = kType02;
            //snprintf (value.name, sizeof (value.name), "OutputVA_%02X", type);
            snprintf (value.text, sizeof (value.text), "%.1f VA", n * 0.1);
            break;

             /* type 0x5205 msgs */
        case 0x14:
            /* PV voltage (100Vdc threshold). 2 bytes, x0.1Vdc. 989..2760 */
            key = kType14;
            //snprintf (value.name, sizeof (value.name), "InputV_%02X", type);
            snprintf (value.text, sizeof (value.text), "%.1f Vdc", n * 0.1);
            break;
        case 0x15:
            /* ?Function 1 byte, always 0 */
            if (!n)
                continue;
            key = kType15;
            snprintf (value.text, sizeof (value.text), "%#x", n);
            break;
        case 0x16:
            /* Generated total kWH. 3 bytes, x0.1kWH. tracks type 0x17 */
            key = kType16;
            //snprintf (value.name, sizeof (value.name), "GenTotal_%02X", type);
            snprintf (value.text, sizeof (value.text), "%.1f kWH", n * 0.1);
            break;
        case 0x17:
            /* Generated today kWH. 1 byte, x0.1kWH. 0 when dark, 0..80 */
            key = kType17;
            //snprintf (value.name, sizeof (value.name), "GenToday_%02X", type);
            snprintf (value.text, sizeof (value.text), "%.1f kWH", n * 0.1);
            break;

        default:
            key = kTypeUnk;
            snprintf (value.name, sizeof (value.name), "Unknown_%02X", type);
            snprintf (value.text, sizeof (value.text), "%#x", n);
            break;
        }

        /* clang-format off */
        data = data_append (data, key2str (key),
                            value.name[0] ? value.name : NULL,
                            DATA_STRING, value.text, NULL);
        /* clang-format on */
        if (NULL == data)
            return DECODE_FAIL_SANITY;
    }

    /* clang-format off */
    data = data_append (data, key2str (kMIC), "Integrity",
                        DATA_STRING, "CHECKSUM", NULL);
    /* clang-format on */

    decoder_output_data (decoder, data);

    return 1; /* Message successfully decoded */
}

static int decode_callback (r_device *decoder, bitbuffer_t *bb)
{
    static const uint8_t pre[] = { 0x2d, 0xd4 };
    const unsigned prelen = 8 * sizeof (pre);
    int n;

    if (bb->num_rows != 1 || bb->bits_per_row[ 0] <= prelen)
    {
        return DECODE_ABORT_LENGTH;
    }

    if ((n = bitbuffer_search (bb, 0, 0, pre, prelen)) >= bb->bits_per_row[ 0])
    {
        if (decoder->verbose >= 2)
            fprintf (stderr, PREFIX ":vv Missing prefix\n");
        return DECODE_ABORT_EARLY;
    }

    return decode_message (decoder, bb, 0, n + prelen);
}

r_device solar_4b6b = {
        .name           = "Solar monitor 4b6b",
        .modulation     = FSK_PULSE_PCM,
        .short_width    = 254,
        .long_width     = 254,
        .reset_limit    = 254*7,
        .decode_fn      = &decode_callback,
        .disabled       = 0,
        .fields         = output_fields,
};
