/** @file
    GEO mimim+ energy monitor

    Copyright (C) 2022 Lawrence Rust, lvr at softsystem dot co dot uk

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

/**
 * The GEO minim+ energy monitor comprises a sensor unit and a display unit.
 * https://assets.geotogether.com/sites/4/20170719152420/Minim-Data-sheet.pdf
 *
 * The sensor unit is supplied with a detachable current transformer that is
 * clipped around the live wire feeding the monitored device. The sensor unit
 * is powered by 3x AA batteries that provide for ~2 years of operation. It
 * transmits a short (5mS) data packet every ~3 seconds.
 *
 * Frequency 868.29 MHz, bit period 25 microseconds (40kbps), modulation FSK_PCM
 *
 * The display unit requires a 5V supply, provided by the supplied mains/USB
 * adapter. The display and sensor units are paired during initial power on
 * or as follows:
 *
 * 1. On the display, hold down the <- and +> buttons together for 3 seconds.
 * 2. At the next screen, hold down the middle button for 3 seconds until the
 *    display shows “Pair?”
 * 3. On the sensor, press and hold the pair button (next to the red light)
 *    until the red LED light illuminates.
 * 4. Release the pair button and the LED flashes as the transmitter pairs.
 * 5. The display should now read “Paired CT"
 *
 * When paired the display listens for sensor packets and then transmits a
 * summary packet using the same protocol.
 *
 * The following Flex decoder will capture the raw data:
 * rtl_433 -f 868.29M -s1024000 -Y classic\
 *         -X'n=minim+,m=FSK_PCM,s=24,l=24,r=3000,preamble=0x7bb9'
*/

#include <locale.h>
#include <time.h>

#include "decoder.h"

/**
GEO minim+ current sensor.

Packet layout:

- 24 bit preamble of alternating 0s and 1s
- 2 sync bytes: 0x7b 0xb9
- 4 byte header: 0x3f 0x06 0x29 0x05
- 5 data bytes
- CRC16

The following Flex decoder will capture the raw sensor data:
rtl_433 -f 868.29M -s1024000 -Y classic\
        -X'n=minim+ sensor,m=FSK_PCM,s=24,l=24,r=3000,preamble=0x7bb93f'

Data format string:

    ID:24h VA:13d 3x UP:24d CRC:16h

    VA: Big endian power x10VA, bit14 = 5VA
    UP: Big endian uptime x9 seconds
*/
static int geo_minim_ct_sensor_decode(r_device * const decoder,
        const uint8_t buf[], unsigned len)
{
    unsigned n, secs,mins, hours, va, flags4;
    char up[32];
    char id[12];

    if (len != 11)
    {
        decoder_output_bitrowf(decoder, buf, 8 * len,
            "geo_minim: Incorrect length. Expected 11 got %u bytes", len);
        return DECODE_ABORT_LENGTH;
    }

    snprintf(id, sizeof(id),
            "%02X%02X%02X%02X", buf[0], buf[1], buf[2], buf[3]);

    /* Uptime in ~9 second intervals */
    n = 9 * (buf[8] + (buf[7] << 8) + (buf[6] << 16));

    /* Convert to days,hours,minutes,seconds */
    secs = n % 60;
    n /= 60;
    mins = n % 60;
    n /= 60;
    hours = n % 24;
    n /= 24;
    snprintf(up, sizeof(up), "%uday %02u:%02u:%02u", n, hours, mins, secs);

    /* Bytes 4 & 5 appear to be the instantaneous VA x10.
     * When scaled by the 'Fine Tune' setting (power factor [0.88]) set on the
     * display unit it matches the Watts value in display messages.
     */
    va = 10 * (buf[5] + ((buf[4] & 0x0f) << 8));
    if (buf[4] & 0x40)
        va += 5;

    /* TODO: what are the flag bits in buf[4] (0x30)?
     * Battery OK, Fault?
     */
    flags4 = buf[4] & ~0x4f;

    /* clang-format off */
    data_t *data = data_make(
            "model",    "Device",       DATA_STRING, "GEO minim+ CT sensor",
            "id",       "ID",           DATA_STRING, id,
            "va",       "VA",           DATA_INT, va,
            "flags4",   "Flags",        DATA_COND, flags4 != 0x30, DATA_FORMAT, "%#x", DATA_INT, flags4,
            "uptime",   "Uptime",       DATA_STRING, up,
            "mic",      "Integrity",    DATA_STRING, "CRC",
            NULL);
    /* clang-format on */

    decoder_output_data(decoder, data);

    return 1; /* Message successfully decoded */
}


/**
GEO minim+ display.

Packet layout:

- 24 bit preamble of alternating 0s and 1s
- 2 sync bytes: 0x7b 0xb9
- 4 byte header: 0xea 0x01 0x35 0x2a
- 42 data bytes
- CRC16

The following Flex decoder will capture the raw display data:
rtl_433 -f 868.29M -s1024000 -Y classic\
        -X'n=minim+ display,m=FSK_PCM,s=24,l=24,r=3000,preamble=0x7bb9ea'

Data format string:

    ID:24h PWR:15d 1x 64x WH:11d 5x 64x 48x MIN:8d HRS:8d DAYS:16d 96x CRC:16h

    PWR: Instantaneous power, little endian
    WH: Watt-hours in last 15 minutes, little endian
    MIN,HRS,DAYs since 1/1/2007, little endian
*/
static int geo_minim_display_decode(r_device * const decoder,
        const uint8_t buf[], unsigned len)
{
    uint8_t const zeroes[8] = { 0 };
    uint8_t const aaes[5] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
    uint8_t const trailer[12] = {
            0xaa, 0xff, 0xff, 0, 0, 0, 0, 0xaa, 0xff, 0xaa, 0xaa, 0 };
    unsigned watts, wh, flags5, flags15;

//#define GEO_ZERO_WH 0     /* Accumulate watt-hour measurements */
//#define GEO_ZERO_WH ~0U   /* Take 1st wh reading as zero reference */
#ifdef GEO_ZERO_WH
    static unsigned s_watt_hours = GEO_ZERO_WH;
    static unsigned s_last;
#endif
    struct tm t = {0};
    char now[20];
    char id[12];

    if (len != 48)
    {
        decoder_output_bitrowf(decoder, buf, 8 * len,
                "geo_minim: Incorrect length. Expected 48, got %u bytes", len);
        return DECODE_ABORT_LENGTH;
    }

    /* Report unexpected values */
    if (memcmp(zeroes, buf + 6, sizeof(zeroes)))
    {
        decoder_output_bitrowf(decoder, buf + 6, 8 * sizeof(zeroes),
                "geo_minim: Nonzero @6");
//        return DECODE_FAIL_SANITY;
    }

    if (memcmp(zeroes, buf + 16, sizeof(zeroes)))
    {
        decoder_output_bitrowf(decoder, buf + 16, 8 * sizeof(zeroes),
                "geo_minim: Nonzero @16");
//        return DECODE_FAIL_SANITY;
    }

    if (memcmp(aaes, buf + 24, sizeof(aaes)))
    {
        decoder_output_bitrowf(decoder, buf + 24, 8 * sizeof(aaes),
                "geo_minim: Not 0xaa @24");
//        return DECODE_FAIL_SANITY;
    }

    if (buf[29] != 0x00)
    {
        decoder_output_messagef(decoder,
                "geo_minim: Expected 0x00 but got %#x @29", buf[29]);
//        return DECODE_FAIL_SANITY;
    }

    if (memcmp(trailer, buf + 34, sizeof(trailer)))
    {
        decoder_output_bitrowf(decoder, buf + 34, 8 * sizeof(trailer),
                "geo_minim: Bad trailer @34");
//        return DECODE_FAIL_SANITY;
    }

    snprintf(id, sizeof(id),
            "%02X%02X%02X%02X", buf[0], buf[1], buf[2], buf[3]);

    /* Instantaneous power: 300W => 60: 1 = 5W */
    watts = 5 * (buf[4] + ((buf[5] & 0x7f) << 8));
    /* TODO: what is bit7? */
    flags5 = buf[5] & ~0x7f;

    /* Energy: 480W => 8/min: 1 = 0.06kWm = 0.001kWh */
    wh = buf[14] + ((buf[15] & 0x7) << 8);
    /* TODO: what are bits 3..7 ? 0x40 normally, Battery OK, Fault? */
    flags15 = buf[15] & ~0x7;

#if GEO_ZERO_WH
    /* Take 1st wh reading as zero reference */
    if (s_watt_hours == GEO_ZERO_WH)
        s_watt_hours = -wh;
#endif

#ifdef GEO_ZERO_WH
    /* detect watt-hour rollover - every 15 minutes */
    if (wh < s_last)
        s_watt_hours += s_last; /* rollover */
    s_last = wh;
    wh += s_watt_hours;
#endif

    /* Date/time @30..33 */
    t.tm_sec = 0;
    t.tm_min = buf[33] & 0x3f;
    t.tm_hour = buf[32] & 0x1f;
    /* Day 0 = 1/1/2007 */
    t.tm_mday = 1 + buf[30] + (buf[31] << 8);
    t.tm_mon = 1 - 1;
    t.tm_year = 2007 - 1900;
    t.tm_isdst = -1;
    mktime(&t);

    setlocale(LC_TIME, "");
    strftime(now, sizeof(now), "%H:%M %x", &t);

    /* Create the data structure, ready for the decoder_output_data function. */
    /* clang-format off */
    data_t *data = data_make(
            "model",    "Device",       DATA_STRING, "GEO minim+ display",
            "id",       "ID",           DATA_STRING, id,
            "watts",    "Watts",        DATA_FORMAT, "%u", DATA_INT, watts,
            "kwh",      "kWh",          DATA_FORMAT, "%.3f", DATA_DOUBLE, wh * 0.001,
            "time",     "Time",         DATA_STRING, now,
            "flags5",   "Flags5",       DATA_COND, flags5 != 0,
                                                DATA_FORMAT, "%#x", DATA_INT, flags5,
            "flags15",  "Flags15",      DATA_COND, flags15 != 0x40,
                                                DATA_FORMAT, "%#x", DATA_INT, flags15,
            "mic",      "Integrity",    DATA_STRING, "CRC",
            NULL);
    /* clang-format on */

    decoder_output_data(decoder, data);

    return 1; /* Message successfully decoded */
}

static int decode_minim_message(r_device * const decoder, bitbuffer_t *bb,
        unsigned row, unsigned bitpos)
{
    uint8_t buf[128];
    unsigned bits = bb->bits_per_row[ row];

    /* Extract frame header */
    unsigned const hdr_len = 4;
    unsigned const hdr_bits = hdr_len * 8;
    if (bitpos + hdr_bits >= bits)
        return DECODE_ABORT_LENGTH;

    bits -= bitpos;
    bitbuffer_extract_bytes(bb, row, bitpos, buf, hdr_bits);

    /* Determine frame type. Assume:
     * buf[0] = message type
     * buf[1], buf[2] = session ID from pairing
     * buf[3] = data byte length
     */
    uint8_t const header1[] = {
            0xea, /* 0x01, 0x35, 0x2a */ }; /* Display */
    uint8_t const header2[] = {
            0x3f, /* 0x06, 0x29, 0x05 */ }; /* CT sensor */
    enum EType { kTypeDisplay, kTypeCT } type;
    if (!memcmp(header1, buf, sizeof(header1)))
    {
        type = kTypeDisplay;
    }
    else if (!memcmp(header2, buf, sizeof(header2)))
    {
        type = kTypeCT;
    }
    else
    {
        decoder_output_messagef(decoder,
                "geo_minim: Unknown header %02x%02x%02x%02x",
                buf[0], buf[1], buf[2], buf[3]);
        return DECODE_ABORT_EARLY;
    }

    unsigned bytes = bits / 8;
    if (bytes > sizeof(buf))
    {
        decoder_output_bitbufferf(decoder, bb,
                "geo_minim: Too big - %u bits", bits);
//        return DECODE_ABORT_LENGTH;
        bytes = sizeof(buf);
    }

    /* Check offset to crc16 using data_len @ header[3] */
    unsigned crc_len = hdr_len + buf[3];
    if (crc_len + 2 > bytes)
    {
        decoder_output_messagef(decoder,
                "geo_minim: Truncated - got %u of %u bytes", bytes, crc_len +2);
        return DECODE_FAIL_SANITY;
    }

    /* Extract byte-aligned data */
    bitbuffer_extract_bytes(
            bb, row, bitpos + hdr_bits, buf + hdr_bits / 8, bytes * 8);

    /* Message Integrity Check */
    unsigned crc = crc16(buf, crc_len, 0x8005, 0);
    unsigned crc_rcvd = (buf[ crc_len] << 8) | buf[ crc_len +1];
    if (crc != crc_rcvd)
    {
        decoder_output_bitrowf(decoder, buf, (crc_len + 2) * 8,
                "geo_minim: Bad CRC. Expected %04X got %04X", crc, crc_rcvd);
        return DECODE_FAIL_MIC;
    }

    switch (type)
    {
    case kTypeDisplay:
        return geo_minim_display_decode(decoder, buf, bytes);

    case kTypeCT:
        return geo_minim_ct_sensor_decode(decoder, buf, bytes);
    }

    return DECODE_FAIL_SANITY;
}

/* List of fields to appear in the `-F csv` output */
static char *output_fields[] = {
        "model",
        "id",
        "mic",
        "watts",
        "kwh",
        "time",
        NULL
};

static int minim_callback(r_device *decoder, bitbuffer_t *bb)
{
    uint8_t const pre[] = { 0x55, 0x55 };
    const unsigned prelen = 8 * sizeof(pre);
    uint8_t const syn[] = { 0x7b, 0xb9 };
    const unsigned synlen = 8 * sizeof(syn);
    int n;

    if (bb->num_rows != 1)
        return DECODE_ABORT_LENGTH;

    if (bb->bits_per_row[ 0] <= prelen)
        return DECODE_ABORT_LENGTH;

    if ((n = bitbuffer_search(bb, 0, 0, pre, prelen)) >= bb->bits_per_row[ 0])
        return DECODE_ABORT_EARLY;

    if (bb->bits_per_row[ 0] <= n + prelen + synlen)
        return DECODE_ABORT_LENGTH;

    if ((n = bitbuffer_search(bb, 0, n + prelen, syn, synlen))
            >= bb->bits_per_row[ 0])
    {
        if (decoder->verbose >= 1)
            decoder_output_bitbufferf(decoder, bb, "geo_minim:vv No sync");
        return DECODE_ABORT_EARLY;
    }

    if ((n = decode_minim_message(decoder, bb, 0, n + synlen)) <= 0)
        return n;

    return 1;
}

r_device geo_minim = {
        .name           = "GEO minim+ energy monitor",
        .modulation     = FSK_PULSE_PCM,
        .short_width    = 24,
        .long_width     = 24,
        .reset_limit    = 3000,
        .decode_fn      = &minim_callback,
        .disabled       = 0,
        .fields         = output_fields,
};
