#!/usr/bin/env python3
"""
Generates high-resolution 512x512 icon.png and logo.png for Home Assistant Add-on.
Uses pure Python standard library (zlib, struct, math).
"""

import math
import struct
import zlib


def create_png(filename, size=512):
    center = size / 2.0
    corner_r = size * 0.22
    pad = 24.0
    box_min = pad
    box_max = size - pad
    inner_box_min = pad + 12.0
    inner_box_max = size - pad - 12.0
    inner_corner_r = corner_r - 12.0

    rows = []

    for y in range(size):
        row = bytearray([0])  # filter byte: 0 = None
        for x in range(size):
            # Calculate distance to squircle box
            cx = min(max(x, box_min + corner_r), box_max - corner_r)
            cy = min(max(y, box_min + corner_r), box_max - corner_r)
            dist = math.hypot(x - cx, y - cy)

            if dist > corner_r:
                # Outside squircle -> transparent
                row.extend([0, 0, 0, 0])
                continue

            # Base gradient: Deep Slate / Navy (#0f172a to #0369a1)
            t = (x + y * 1.2) / (2.2 * size)
            t = min(max(t, 0.0), 1.0)
            r = int(15 * (1 - t) + 3 * t)
            g = int(23 * (1 - t) + 105 * t)
            b = int(42 * (1 - t) + 161 * t)
            a = 255

            # Border antialiasing & accent
            edge_dist = corner_r - dist
            if edge_dist < 4:
                # Outer border accent (#38bdf8)
                blend = edge_dist / 4.0
                r = int(r * (1 - blend) + 56 * blend)
                g = int(g * (1 - blend) + 189 * blend)
                b = int(b * (1 - blend) + 248 * blend)
                a = int(255 * min(1.0, edge_dist))

            # Inner ambient border
            icx = min(max(x, inner_box_min + inner_corner_r), inner_box_max - inner_corner_r)
            icy = min(max(y, inner_box_min + inner_corner_r), inner_box_max - inner_corner_r)
            idist = math.hypot(x - icx, y - icy)
            if abs(idist - inner_corner_r) < 1.5 and idist <= inner_corner_r + 2:
                r = int(r * 0.5 + 56 * 0.5)
                g = int(g * 0.5 + 189 * 0.5)
                b = int(b * 0.5 + 248 * 0.5)

            # Shield Geometry: Top=96, Bottom=364, Width=120 on each side (136 to 376)
            # Normalised inside shield test
            in_shield = False
            sy = y - 96
            if 0 <= sy <= 268:
                if sy < 52:
                    # Top angled slope
                    max_w = (sy / 52.0) * 120.0
                    if abs(x - center) <= max_w:
                        in_shield = True
                else:
                    # Curved taper towards bottom tip at (center, 364)
                    rem_h = 268 - 52
                    prog = (sy - 52) / float(rem_h)
                    # Parabolic taper
                    max_w = 120.0 * (1.0 - (prog**1.4))
                    if abs(x - center) <= max_w:
                        in_shield = True

            if in_shield:
                # Dark interior with slight glass opacity
                r = int(r * 0.25 + 15 * 0.75)
                g = int(g * 0.25 + 23 * 0.75)
                b = int(b * 0.25 + 42 * 0.75)

            # Shield Border (Gradient #38bdf8 to #818cf8)
            # Distance approximation to shield edge
            if 90 <= y <= 370 and abs(x - center) <= 126:
                # Check if near shield boundary
                if (
                    abs(y - (148 - abs(x - center) * (52 / 120.0))) < 4
                    and abs(x - center) <= 120
                    and y < 152
                ):
                    r, g, b = 56, 189, 248
                elif y >= 148:
                    rem_h = 268 - 52
                    prog = max(0.0, min(1.0, (y - 148) / float(rem_h)))
                    expected_w = 120.0 * (1.0 - (prog**1.4))
                    if abs(abs(x - center) - expected_w) < 4:
                        # Blend between cyan (#38bdf8) and indigo (#818cf8)
                        blend_s = y / 364.0
                        r = int(56 * (1 - blend_s) + 129 * blend_s)
                        g = int(189 * (1 - blend_s) + 140 * blend_s)
                        b = int(248 * (1 - blend_s) + 248 * blend_s)

            # Wi-Fi Arcs (AP Radio)
            # Center at (256, 232)
            d_ap = math.hypot(x - center, y - 232)
            # Outer arc (radius 78..86, angle within top 160 deg)
            if 77 <= d_ap <= 85 and y < 215 and abs(x - center) < 80:
                r, g, b = 56, 189, 248
            # Inner arc (radius 46..54, angle within top 140 deg)
            elif 45 <= d_ap <= 53 and y < 225 and abs(x - center) < 50:
                r, g, b = 14, 165, 233
            # Center AP Dot (radius <= 10)
            elif d_ap <= 10:
                r, g, b = 248, 250, 252

            # Switch Box: x in [186, 326], y in [266, 318] (width 140, height 52)
            if 186 <= x <= 326 and 266 <= y <= 318:
                # Switch housing
                r, g, b = 30, 41, 59
                # Border
                if x in (186, 187, 325, 326) or y in (266, 267, 317, 318):
                    r, g, b = 71, 85, 105

                # 4 RJ45 Ports
                ports = [
                    (200, 218, "ok"),
                    (226, 244, "ok"),
                    (252, 270, "alert"),  # Port 3: Link Degradation
                    (278, 296, "ok"),
                ]
                for px1, px2, status in ports:
                    # Port cutout (y 274..296)
                    if px1 <= x <= px2 and 274 <= y <= 296:
                        r, g, b = 15, 23, 42
                        if x in (px1, px2) or y in (274, 296):
                            r, g, b = (51, 65, 85) if status != "alert" else (239, 68, 68)

                    # Port LED indicator (y 304..312)
                    mid_x = (px1 + px2) / 2.0
                    d_led = math.hypot(x - mid_x, y - 308)
                    if d_led <= 4.0:
                        if status == "ok":
                            r, g, b = 16, 185, 129  # Vibrant Green OK
                        else:
                            r, g, b = 239, 68, 68  # Red Alert LED

            # Diagnostic Pulse Wave at bottom: y around 408
            if 110 <= x <= 400 and abs(y - 408) < 32:
                # Segment coordinates:
                # (110, 408) -> (190, 408) -> (210, 380) -> (235, 436) -> (260, 392) -> (285, 418) -> (305, 408) -> (395, 408)
                pulse_segs = [
                    ((110, 408), (190, 408)),
                    ((190, 408), (210, 380)),
                    ((210, 380), (235, 436)),
                    ((235, 436), (260, 392)),
                    ((260, 392), (285, 418)),
                    ((285, 418), (305, 408)),
                    ((305, 408), (395, 408)),
                ]
                for (x1, y1), (x2, y2) in pulse_segs:
                    # Point to line segment distance
                    dx = x2 - x1
                    dy = y2 - y1
                    len_sq = dx * dx + dy * dy
                    u = max(0.0, min(1.0, ((x - x1) * dx + (y - y1) * dy) / float(len_sq)))
                    lx = x1 + u * dx
                    ly = y1 + u * dy
                    if math.hypot(x - lx, y - ly) <= 3.2:
                        r, g, b = 56, 189, 248
                        break

            # Status dot at end of pulse
            if math.hypot(x - 395, y - 408) <= 6.0:
                r, g, b = 16, 185, 129

            row.extend([r, g, b, a])
        rows.append(row)

    raw_data = b"".join(rows)
    compressed = zlib.compress(raw_data, 9)

    png = bytearray(b"\x89PNG\r\n\x1a\n")
    # IHDR chunk
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    png.extend(
        struct.pack(">I", 13)
        + b"IHDR"
        + ihdr
        + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr))
    )
    # IDAT chunk
    png.extend(
        struct.pack(">I", len(compressed))
        + b"IDAT"
        + compressed
        + struct.pack(">I", zlib.crc32(b"IDAT" + compressed))
    )
    # IEND chunk
    png.extend(
        struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND"))
    )

    with open(filename, "wb") as f:
        f.write(png)
    print(f"Generated {filename} ({len(png)} bytes)")


if __name__ == "__main__":
    create_png("icon.png", 512)
    create_png("logo.png", 512)
