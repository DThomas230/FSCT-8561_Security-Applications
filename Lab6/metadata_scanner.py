import os
import sys
import csv
import base64
import struct
import datetime
from pathlib import Path
import exifread
from PIL import Image, ExifTags

# =========================================================================
# Helper utilities
# =========================================================================

def get_image_paths(folder: str) -> list[Path]:
    """Return sorted list of image files in *folder*."""
    exts = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp", ".gif", ".webp"}
    paths = sorted(
        p for p in Path(folder).iterdir()
        if p.is_file() and p.suffix.lower() in exts
    )
    if not paths:
        sys.exit(f"[!] No image files found in '{folder}'.")
    return paths


def safe_str(value) -> str:
    """Convert an EXIF tag value to a readable string."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace").strip("\x00 ")
        except Exception:
            return value.hex()
    return str(value).strip()


def try_base64_decode(text: str) -> str | None:
    """Return decoded text if *text* is valid Base64, else None."""
    if not text or len(text) < 4:
        return None
    try:
        decoded = base64.b64decode(text, validate=True).decode("utf-8")
        # Only accept if the result is printable
        if decoded.isprintable() and len(decoded) >= 2:
            return decoded
    except Exception:
        pass
    return None


# =========================================================================
# Part 1 — Metadata Extraction
# =========================================================================

# Fields of interest for structured table
FIELDS_OF_INTEREST = [
    "GPS GPSLatitude", "GPS GPSLatitudeRef",
    "GPS GPSLongitude", "GPS GPSLongitudeRef",
    "EXIF DateTimeOriginal", "EXIF CreateDate",
    "Image DateTime", "EXIF ModifyDate",
    "Image Make", "Image Model",
    "Image Software",
    "EXIF UserComment", "Image ImageDescription",
    "EXIF MakerNote", "Image Copyright",
    "GPS GPSDestDistance",
]


def extract_metadata_exifread(filepath: Path) -> dict:
    """Use ExifRead to extract all EXIF tags from an image."""
    with open(filepath, "rb") as f:
        tags = exifread.process_file(f, details=True)
    return {k: safe_str(v) for k, v in tags.items()}


def extract_metadata_pillow(filepath: Path) -> dict:
    """Use Pillow to extract EXIF tags (provides additional coverage)."""
    result = {}
    try:
        img = Image.open(filepath)
        exif_data = img._getexif()  # Returns dict {tag_id: value}
        if exif_data:
            for tag_id, value in exif_data.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                result[tag_name] = safe_str(value)
        # Also grab PNG text chunks (tEXt / iTXt / zTXt)
        if hasattr(img, "text"):
            for k, v in img.text.items():
                result[f"PNG:{k}"] = safe_str(v)
        # Pillow info dict can also hold metadata
        for k, v in img.info.items():
            if isinstance(v, (str, bytes)):
                key = f"Info:{k}" if k not in result else k
                result[key] = safe_str(v)
    except Exception:
        pass
    return result


def extract_all_metadata(filepath: Path) -> dict:
    """Merge metadata from both ExifRead and Pillow."""
    meta = extract_metadata_exifread(filepath)
    meta.update(extract_metadata_pillow(filepath))
    return meta


def build_summary_row(filepath: Path, meta: dict) -> dict:
    """Build a single-row summary dict for the structured table."""
    def find(keys):
        """Search meta for the first matching key (case-insensitive partial)."""
        for k in keys:
            # Exact match first
            if k in meta and meta[k]:
                return meta[k]
            # Partial / case-insensitive fallback
            kl = k.lower()
            for mk, mv in meta.items():
                if kl in mk.lower() and mv:
                    return mv
        return ""

    return {
        "File": filepath.name,
        "GPSLatitude": find(["GPS GPSLatitude", "GPSLatitude"]),
        "GPSLongitude": find(["GPS GPSLongitude", "GPSLongitude"]),
        "DateTimeOriginal": find(["EXIF DateTimeOriginal", "DateTimeOriginal"]),
        "CreateDate": find(["EXIF CreateDate", "CreateDate"]),
        "ModifyDate": find(["Image DateTime", "EXIF ModifyDate", "ModifyDate", "DateTime"]),
        "CameraMake": find(["Image Make", "Make"]),
        "CameraModel": find(["Image Model", "Model"]),
        "Software": find(["Image Software", "Software"]),
        "UserComment": find(["EXIF UserComment", "UserComment"]),
        "ImageDescription": find(["Image ImageDescription", "ImageDescription"]),
    }


# =========================================================================
# Part 2 — Covert Channel Detection
# =========================================================================

# Metadata keys commonly abused for covert channels
COVERT_KEYS = [
    "UserComment", "ImageDescription", "MakerNote",
    "Software", "Copyright", "GPSDestDistance",
    "EXIF UserComment", "Image ImageDescription",
    "EXIF MakerNote", "Image Software", "Image Copyright",
    "GPS GPSDestDistance",
    # PNG text chunks
    "PNG:Comment", "PNG:Description", "PNG:Secret",
    "PNG:Author", "PNG:Software",
]


def detect_covert_channels(meta: dict) -> list[dict]:
    """
    Search metadata for potential hidden messages.
    Returns a list of findings: {field, raw_value, decoded, is_suspicious}.
    """
    findings = []
    checked = set()

    for target_key in COVERT_KEYS:
        tl = target_key.lower()
        for mk, mv in meta.items():
            if mk.lower() in checked:
                continue
            if tl in mk.lower() or mk.lower() in tl:
                if not mv:
                    continue
                checked.add(mk.lower())
                decoded = try_base64_decode(mv)
                suspicious = bool(decoded) or len(mv) > 80
                findings.append({
                    "field": mk,
                    "raw_value": mv,
                    "decoded": decoded or "",
                    "is_suspicious": suspicious,
                })

    # Also scan ALL fields for anything base64-like or unusually long
    for mk, mv in meta.items():
        if mk.lower() in checked or not mv:
            continue
        decoded = try_base64_decode(mv)
        if decoded or len(mv) > 200:
            findings.append({
                "field": mk,
                "raw_value": mv[:120] + ("…" if len(mv) > 120 else ""),
                "decoded": decoded or "",
                "is_suspicious": True,
            })

    return findings


def extract_secret_fragment(findings: list[dict]) -> str:
    """Return the best-guess secret fragment from covert-channel findings."""
    for f in findings:
        if f["decoded"]:
            return f["decoded"]
    for f in findings:
        if f["is_suspicious"]:
            return f["raw_value"]
    return ""


# =========================================================================
# Part 3 — Timestamp Consistency Checks
# =========================================================================

EXIF_TIME_FMT = "%Y:%m:%d %H:%M:%S"


def parse_exif_time(s: str) -> datetime.datetime | None:
    """Try to parse a standard EXIF datetime string."""
    for fmt in (EXIF_TIME_FMT, "%Y-%m-%d %H:%M:%S", "%Y:%m:%d"):
        try:
            return datetime.datetime.strptime(s.strip(), fmt)
        except (ValueError, AttributeError):
            continue
    return None


def get_filesystem_times(filepath: Path) -> dict:
    """Return filesystem Created / Modified / Accessed times."""
    stat = filepath.stat()
    return {
        "fs_modified": datetime.datetime.fromtimestamp(stat.st_mtime),
        "fs_created": datetime.datetime.fromtimestamp(stat.st_ctime),
        "fs_accessed": datetime.datetime.fromtimestamp(stat.st_atime),
    }


def check_timestamp_consistency(filepath: Path, meta: dict) -> dict:
    """
    Compare EXIF timestamps with filesystem MAC times.
    Returns a dict with comparison results and anomaly flag.
    """
    fs = get_filesystem_times(filepath)
    result = {**fs, "exif_times": {}, "anomalies": []}

    time_keys = [
        "EXIF DateTimeOriginal", "DateTimeOriginal",
        "EXIF CreateDate", "CreateDate",
        "Image DateTime", "DateTime", "ModifyDate",
    ]

    for key in time_keys:
        for mk, mv in meta.items():
            if key.lower() in mk.lower() and mv:
                dt = parse_exif_time(mv)
                if dt:
                    result["exif_times"][mk] = dt

    # Detect anomalies -----------------------------------------------
    for tag, exif_dt in result["exif_times"].items():
        # EXIF time far from filesystem modified time (>1 day difference)
        diff = abs((exif_dt - fs["fs_modified"]).total_seconds())
        if diff > 86400:  # more than 24 hours
            result["anomalies"].append(
                f"{tag} ({exif_dt}) differs from filesystem modified "
                f"({fs['fs_modified']}) by {diff/3600:.1f} hours"
            )

    # Check EXIF internal ordering (original should be <= modified)
    exif_vals = list(result["exif_times"].values())
    for i in range(len(exif_vals)):
        for j in range(i + 1, len(exif_vals)):
            if exif_vals[i] > exif_vals[j]:
                result["anomalies"].append(
                    "Impossible EXIF time sequence detected"
                )
                break

    return result


# =========================================================================
# Part 4 — Quantization / Double-JPEG Compression Detection
# =========================================================================

def detect_double_jpeg(filepath: Path) -> dict:
    """
    Detect signs of double JPEG compression.
    - Checks for multiple JFIF/Exif markers or quantization tables.
    - Examines DCT quantization table values for non-standard patterns.
    Returns a dict with findings.
    """
    result = {"is_jpeg": False, "markers_found": 0,
              "quantization_tables": 0, "suspicious": False, "notes": []}

    # Only applies to JPEG files
    if filepath.suffix.lower() not in (".jpg", ".jpeg"):
        result["notes"].append("Not a JPEG file — skipping compression check.")
        return result

    result["is_jpeg"] = True

    try:
        data = filepath.read_bytes()
    except Exception as e:
        result["notes"].append(f"Could not read file: {e}")
        return result

    # Count SOI (Start Of Image) markers — multiple can indicate editing
    soi_count = data.count(b"\xff\xd8")
    result["markers_found"] = soi_count
    if soi_count > 1:
        result["suspicious"] = True
        result["notes"].append(
            f"Multiple SOI markers ({soi_count}) — possible embedded JPEG or double compression."
        )

    # Count DQT (Define Quantization Table) markers
    dqt_count = data.count(b"\xff\xdb")
    result["quantization_tables"] = dqt_count
    if dqt_count > 2:
        result["suspicious"] = True
        result["notes"].append(
            f"Unusual number of quantization tables ({dqt_count}) — may indicate re-compression."
        )

    # Use Pillow to check quantization tables for non-standard values
    try:
        img = Image.open(filepath)
        qtables = img.quantization
        if qtables:
            for idx, table in qtables.items():
                vals = list(table)
                # Standard JPEG tables usually start with small values
                # Very flat tables suggest the image was re-saved
                if len(set(vals)) < 10:
                    result["suspicious"] = True
                    result["notes"].append(
                        f"Quantization table {idx} has very low variance — possible re-compression."
                    )
    except Exception:
        pass

    if not result["notes"]:
        result["notes"].append("No double-compression artifacts detected.")

    return result


def detect_editing_traces(filepath: Path, meta: dict) -> list[str]:
    """Flag editing software mentioned in metadata."""
    editors = [
        "photoshop", "gimp", "lightroom", "snapseed", "afterlight",
        "vsco", "canva", "paint", "acdsee", "affinity",
    ]
    traces = []
    for mk, mv in meta.items():
        if not mv:
            continue
        vl = mv.lower()
        for ed in editors:
            if ed in vl:
                traces.append(f"'{mk}' mentions editing software: {mv}")
                break
    return traces


# =========================================================================
# Part 5 — Risk Scoring
# =========================================================================

def compute_risk_score(
    secret_fragment: str,
    meta: dict,
    ts_result: dict,
    jpeg_result: dict,
    editing_traces: list[str],
) -> tuple[int, list[str]]:
    """
    Assign a risk score based on forensic findings.

    Scoring rubric:
        Hidden secret found          → +10
        GPS / privacy leak           → +5
        Timestamp anomaly            → +5
        Editing / compression signs  → +5
    """
    score = 0
    reasons = []

    # Hidden secret
    if secret_fragment:
        score += 10
        reasons.append(f"Covert channel secret detected (+10)")

    # GPS / Privacy leak
    gps_present = any(
        "gps" in k.lower() and ("lat" in k.lower() or "lon" in k.lower())
        and v
        for k, v in meta.items()
    )
    if gps_present:
        score += 5
        reasons.append("GPS coordinates present — privacy leak (+5)")

    # Timestamp anomaly
    if ts_result.get("anomalies"):
        score += 5
        reasons.append("Timestamp anomaly detected (+5)")

    # Editing / compression
    if editing_traces or jpeg_result.get("suspicious"):
        score += 5
        reasons.append("Editing or double-compression artifacts (+5)")

    return score, reasons


# =========================================================================
# Report helpers
# =========================================================================

DIVIDER = "=" * 72


def print_report(image_reports: list[dict]):
    """Print a formatted console report for all images."""
    print(f"\n{DIVIDER}")
    print("  FORENSIC IMAGE METADATA SCANNER — REPORT")
    print(DIVIDER)

    for rpt in image_reports:
        print(f"\n{'─' * 72}")
        print(f"  Image: {rpt['file']}")
        print(f"{'─' * 72}")

        # Part 1 — Metadata summary
        print("\n  [Part 1] Metadata Summary")
        row = rpt["summary"]
        for k, v in row.items():
            if k == "File":
                continue
            print(f"    {k:20s}: {v if v else '(none)'}")

        # Part 2 — Covert channels
        print("\n  [Part 2] Covert Channel Analysis")
        if rpt["covert_findings"]:
            for f in rpt["covert_findings"]:
                label = "⚠ SUSPICIOUS" if f["is_suspicious"] else "  OK"
                print(f"    {label} | {f['field']}: {f['raw_value'][:80]}")
                if f["decoded"]:
                    print(f"             └─ Decoded: {f['decoded']}")
        else:
            print("    No covert channel indicators found.")

        if rpt["secret_fragment"]:
            print(f"    ★ Secret fragment: {rpt['secret_fragment']}")

        # Part 3 — Timestamp consistency
        print("\n  [Part 3] Timestamp Consistency")
        ts = rpt["timestamp_check"]
        print(f"    FS Modified : {ts['fs_modified']}")
        print(f"    FS Created  : {ts['fs_created']}")
        if ts["exif_times"]:
            for tag, dt in ts["exif_times"].items():
                print(f"    EXIF {tag}: {dt}")
        if ts["anomalies"]:
            for a in ts["anomalies"]:
                print(f"    ⚠ ANOMALY: {a}")
        else:
            print("    No timestamp anomalies detected.")

        # Part 4 — Editing / compression
        print("\n  [Part 4] Editing & Compression Detection")
        for note in rpt["jpeg_check"]["notes"]:
            print(f"    {note}")
        if rpt["editing_traces"]:
            for t in rpt["editing_traces"]:
                print(f"    ⚠ {t}")

        # Part 5 — Risk score
        print(f"\n  [Part 5] Risk Score: {rpt['risk_score']}")
        for r in rpt["risk_reasons"]:
            print(f"    • {r}")

    # Reconstructed secret
    print(f"\n{DIVIDER}")
    print("  RECONSTRUCTED SECRET")
    print(DIVIDER)
    fragments = [
        (rpt["file"], rpt["secret_fragment"])
        for rpt in image_reports if rpt["secret_fragment"]
    ]
    if fragments:
        for fname, frag in fragments:
            print(f"    {fname:25s} → {frag}")
        full_secret = " ".join(f for _, f in fragments)
        print(f"\n    ► Full secret: {full_secret}")
    else:
        print("    No secret fragments found in any image.")

    # Summary risk table
    print(f"\n{DIVIDER}")
    print("  RISK SUMMARY TABLE")
    print(DIVIDER)
    print(f"  {'Image':<25s} {'Risk':>5s}  Reasons")
    print(f"  {'─'*25} {'─'*5}  {'─'*35}")
    for rpt in image_reports:
        reasons_short = "; ".join(rpt["risk_reasons"]) if rpt["risk_reasons"] else "None"
        print(f"  {rpt['file']:<25s} {rpt['risk_score']:>5d}  {reasons_short}")
    print()


def export_csv(image_reports: list[dict], output_path: str):
    """Write results to a CSV file."""
    fieldnames = [
        "File", "GPSLatitude", "GPSLongitude",
        "DateTimeOriginal", "CreateDate", "ModifyDate",
        "CameraMake", "CameraModel", "Software",
        "UserComment", "ImageDescription",
        "SecretFragment", "TimestampAnomaly",
        "EditingTraces", "CompressionSuspicious",
        "RiskScore", "RiskReasons",
    ]

    rows = []
    for rpt in image_reports:
        row = dict(rpt["summary"])
        row["SecretFragment"] = rpt["secret_fragment"]
        row["TimestampAnomaly"] = "; ".join(rpt["timestamp_check"]["anomalies"])
        row["EditingTraces"] = "; ".join(rpt["editing_traces"])
        row["CompressionSuspicious"] = rpt["jpeg_check"]["suspicious"]
        row["RiskScore"] = rpt["risk_score"]
        row["RiskReasons"] = "; ".join(rpt["risk_reasons"])
        rows.append(row)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] CSV report saved to: {output_path}")


# =========================================================================
# Main
# =========================================================================

def scan_images(folder: str):
    """Run the full forensic scan pipeline on all images in *folder*."""
    images = get_image_paths(folder)
    print(f"[+] Found {len(images)} image(s) in '{folder}'.\n")

    image_reports = []

    for img_path in images:
        # Part 1 — Metadata extraction
        meta = extract_all_metadata(img_path)
        summary = build_summary_row(img_path, meta)

        # Part 2 — Covert channel detection
        covert = detect_covert_channels(meta)
        secret = extract_secret_fragment(covert)

        # Part 3 — Timestamp consistency
        ts_check = check_timestamp_consistency(img_path, meta)

        # Part 4 — Editing / compression detection
        jpeg_check = detect_double_jpeg(img_path)
        editing = detect_editing_traces(img_path, meta)

        # Part 5 — Risk scoring
        risk_score, risk_reasons = compute_risk_score(
            secret, meta, ts_check, jpeg_check, editing
        )

        image_reports.append({
            "file": img_path.name,
            "summary": summary,
            "all_meta": meta,
            "covert_findings": covert,
            "secret_fragment": secret,
            "timestamp_check": ts_check,
            "jpeg_check": jpeg_check,
            "editing_traces": editing,
            "risk_score": risk_score,
            "risk_reasons": risk_reasons,
        })

    # Output ---------------------------------------------------------------
    print_report(image_reports)

    csv_path = os.path.join(folder, "..", "metadata_report.csv")
    export_csv(image_reports, csv_path)


# =========================================================================
# Entry point
# =========================================================================

if __name__ == "__main__":
    target_folder = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "Images"
    )
    scan_images(target_folder)
