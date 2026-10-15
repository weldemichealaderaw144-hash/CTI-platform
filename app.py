
from flask import Flask, jsonify, request, send_from_directory
from pathlib import Path
from urllib.parse import urlparse
import hashlib
import ipaddress
import sqlite3
import os
import requests
import json
import re
import shutil
import subprocess
import tempfile
import yara
import pefile
import zipfile
from office_analyzer import analyze_office_package
import xml.etree.ElementTree as ET
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = BASE_DIR / "uploads"
DATABASE = DATA_DIR / "iocs.db"

DATA_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__)

# Limit uploaded files to 25 MB.
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_type TEXT NOT NULL,
                indicator_value TEXT NOT NULL,
                sha256 TEXT,
                assessment TEXT NOT NULL,
                evidence TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)


initialize_database()


@app.get("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "Weldemicheal CTI Platform",
        "message": "Backend is running"
    })




@app.post("/api/virustotal/ip")
def virustotal_ip_report():
    data = request.get_json(silent=True) or {}
    value = data.get("indicator", "")

    if not isinstance(value, str):
        return jsonify({"error": "Indicator must be a string"}), 400

    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return jsonify({"error": "Enter a valid IP address"}), 400

    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return jsonify({
            "error": "VirusTotal API key is not configured"
        }), 503

    url = (
        "https://www.virustotal.com/api/v3/ip_addresses/"
        + str(address)
    )

    headers = {
        "x-apikey": api_key,
        "accept": "application/json"
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=15
        )
    except requests.RequestException:
        app.logger.warning("VirusTotal request failed")
        return jsonify({
            "error": "Could not connect to VirusTotal"
        }), 502

    if response.status_code == 401:
        return jsonify({
            "error": "VirusTotal rejected the API key. Check your configuration."
        }), 502

    if response.status_code == 403:
        return jsonify({
            "error": "VirusTotal denied access. Check your account permissions and API limits."
        }), 502

    if response.status_code == 404:
        return jsonify({
            "error": "No IP report was found for this indicator."
        }), 404

    if response.status_code == 429:
        return jsonify({
            "error": "VirusTotal rate limit reached. Try again later."
        }), 429

    if response.status_code != 200:
        app.logger.warning(
            "VirusTotal returned HTTP %s",
            response.status_code
        )
        return jsonify({
            "error": "VirusTotal returned an unexpected response."
        }), 502

    try:
        result = response.json()
        attributes = result["data"]["attributes"]
    except (ValueError, KeyError, TypeError):
        return jsonify({
            "error": "VirusTotal returned an invalid report."
        }), 502

    stats = attributes.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    if malicious > 0:
        assessment = "Flagged as malicious by one or more vendors"
    elif suspicious > 0:
        assessment = "Flagged as suspicious by one or more vendors"
    elif stats:
        assessment = (
            "No malicious or suspicious detections in the "
            "available analysis; this does not prove safety"
        )
    else:
        assessment = "Insufficient analysis data"

    return jsonify({
        "source": "VirusTotal",
        "indicator": str(address),
        "assessment": assessment,
        "reputation": attributes.get("reputation"),
        "country": attributes.get("country"),
        "network_owner": attributes.get("as_owner"),
        "analysis_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected
        },
        "last_analysis_date": attributes.get(
            "last_analysis_date"
        ),
        "report_url": (
            "https://www.virustotal.com/gui/ip-address/"
            + str(address)
        ),
        "message": (
            "These results reflect VirusTotal's available data. "
            "Vendor detections require analyst review and do not "
            "independently establish maliciousness."
        )
    })
@app.post("/api/virustotal/url")
def virustotal_url_report():
    import base64
    from urllib.parse import urlsplit

    data = request.get_json(silent=True) or {}
    value = data.get("indicator", "")

    if not isinstance(value, str):
        return jsonify({"error": "URL must be a string"}), 400

    value = value.strip()

    if not value or len(value) > 2048:
        return jsonify({"error": "Enter a valid URL"}), 400

    try:
        parsed = urlsplit(value)

        if (
            parsed.scheme.lower() not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("Invalid URL")

        # Validate the port if one was supplied.
        _ = parsed.port

    except ValueError:
        return jsonify({
            "error": "Enter a valid HTTP or HTTPS URL"
        }), 400

    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return jsonify({
            "error": "VirusTotal API key is not configured"
        }), 503

    # VirusTotal identifies URLs using unpadded URL-safe Base64.
    url_id = (
        base64.urlsafe_b64encode(value.encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )

    api_url = (
        "https://www.virustotal.com/api/v3/urls/"
        + url_id
    )

    headers = {
        "x-apikey": api_key,
        "accept": "application/json"
    }

    try:
        response = requests.get(
            api_url,
            headers=headers,
            timeout=15
        )
    except requests.RequestException:
        app.logger.warning("VirusTotal URL request failed")
        return jsonify({
            "error": "Could not connect to VirusTotal"
        }), 502

    if response.status_code == 401:
        return jsonify({
            "error": "VirusTotal rejected the API key"
        }), 502

    if response.status_code == 403:
        return jsonify({
            "error": "VirusTotal denied access. Check account permissions"
        }), 502

    if response.status_code == 404:
        return jsonify({
            "error": (
                "No existing URL report was found. "
                "This lookup does not submit a new scan."
            )
        }), 404

    if response.status_code == 429:
        return jsonify({
            "error": "VirusTotal rate limit reached. Try again later"
        }), 429

    if response.status_code != 200:
        app.logger.warning(
            "VirusTotal URL request returned HTTP %s",
            response.status_code
        )
        return jsonify({
            "error": "VirusTotal returned an unexpected response"
        }), 502

    try:
        result = response.json()
        attributes = result["data"]["attributes"]
    except (ValueError, KeyError, TypeError):
        return jsonify({
            "error": "VirusTotal returned an invalid URL report"
        }), 502

    stats = attributes.get("last_analysis_stats") or {}

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    if malicious > 0:
        assessment = (
            "Flagged as malicious by one or more vendors"
        )
    elif suspicious > 0:
        assessment = (
            "Flagged as suspicious by one or more vendors"
        )
    elif stats:
        assessment = (
            "No malicious or suspicious detections in the "
            "available analysis; this does not prove safety"
        )
    else:
        assessment = "Insufficient analysis data"

    return jsonify({
        "source": "VirusTotal",
        "indicator": value,
        "assessment": assessment,
        "reputation": attributes.get("reputation"),
        "analysis_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected
        },
        "last_analysis_date": attributes.get(
            "last_analysis_date"
        ),
        "report_url": (
            "https://www.virustotal.com/gui/url/" + url_id
        ),
        "message": (
            "Results reflect VirusTotal's available data. "
            "Vendor detections require analyst review and do "
            "not independently establish maliciousness. "
            "SSL validity and live website behavior are not "
            "verified by this URL report alone."
        )
    })


def classify_indicator(value):
    """Validate an IOC without claiming it is malicious."""

    value = value.strip()

    if not value:
        return None, None, "Indicator cannot be empty"

    # Try an IP address first.
    try:
        address = ipaddress.ip_address(value)
        return "ip", str(address), None
    except ValueError:
        pass

    # Recognize a URL with an explicit scheme.
    candidate = value if "://" in value else f"https://{value}"

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname

        if (
            parsed.scheme not in ("http", "https")
            or not hostname
            or any(char.isspace() for char in value)
        ):
            return None, None, "Enter a valid IP address, domain, or URL"

        # Accept an IP literal used as a URL hostname.
        try:
            ipaddress.ip_address(hostname)
            return "url", candidate, None
        except ValueError:
            pass

        # Basic domain-name validation.
        domain = hostname.rstrip(".")
        labels = domain.split(".")

        if (
            len(domain) > 253
            or len(labels) < 2
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not all(c.isalnum() or c == "-" for c in label)
                for label in labels
            )
        ):
            return None, None, "The domain or URL format is invalid"

        return "url", candidate, None

    except (ValueError, UnicodeError):
        return None, None, "Unable to parse the indicator"


@app.post("/api/validate")
def validate_indicator():
    data = request.get_json(silent=True) or {}
    value = data.get("indicator", "")

    if not isinstance(value, str):
        return jsonify({"error": "Indicator must be a string"}), 400

    indicator_type, normalized, error = classify_indicator(value)

    if error:
        return jsonify({"error": error}), 400

    return jsonify({
        "indicator_type": indicator_type,
        "indicator": normalized,
        "assessment": "Not assessed",
        "message": (
            "Format validated only. No reputation lookup or threat "
            "intelligence assessment has been performed."
        )
    })


@app.post("/api/file/hash")
def hash_uploaded_file():
    uploaded = request.files.get("file")

    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "Select a file first"}), 400

    # Hash the file in memory. Never execute it or save it to disk.
    sha256 = hashlib.sha256()
    size = 0

    while True:
        chunk = uploaded.stream.read(1024 * 1024)

        if not chunk:
            break

        size += len(chunk)
        sha256.update(chunk)

    return jsonify({
        "filename": os.path.basename(uploaded.filename),
        "size_bytes": size,
        "sha256": sha256.hexdigest(),
        "assessment": "Not assessed",
        "message": (
            "SHA-256 calculated. A hash alone does not establish "
            "whether a file is malicious."
        )
    })

@app.post("/api/file/static-analysis")
def static_file_analysis():
    uploaded = request.files.get("file")

    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "Select a file first"}), 400

    filename = os.path.basename(uploaded.filename)

    if not filename:
        return jsonify({"error": "Invalid filename"}), 400

    # Keep analysis tools isolated from the permanent upload directory.
    with tempfile.TemporaryDirectory(prefix="cti-static-") as temp_dir:
        sample_path = os.path.join(temp_dir, "sample.bin")

        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        size = 0

        try:
            with open(sample_path, "wb") as sample:
                while True:
                    chunk = uploaded.stream.read(1024 * 1024)

                    if not chunk:
                        break

                    size += len(chunk)

                    if size > app.config["MAX_CONTENT_LENGTH"]:
                        return jsonify({
                            "error": "File exceeds the 25 MB upload limit"
                        }), 413

                    sha256.update(chunk)
                    md5.update(chunk)
                    sample.write(chunk)

            result = {
                "filename": filename,
                "size_bytes": size,
                "sha256": sha256.hexdigest(),
                "md5": md5.hexdigest(),
                "file_type": "Unavailable",
                "pe_metadata": None,
                "strings": [],
                "indicators": {
                    "urls": [],
                    "ipv4_addresses": []
                },
                "yara": {
                    "status": "Not run",
                    "matches": []
                },
                "capa": {
                    "status": "Not run",
                    "output": ""
                },
                "assessment": "Not assessed",
                "message": (
                    "Static analysis only. No sample was executed. "
                    "Tool findings require analyst review."
                )
            }

            # Identify the file by its contents.
            file_command = shutil.which("file")

            if file_command:
                try:
                    completed = subprocess.run(
                        [file_command, "-b", sample_path],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False
                    )

                    if completed.returncode == 0:
                        result["file_type"] = (
                            completed.stdout.strip()[:500]
                        )
                    else:
                        result["file_type"] = "Identification failed"

                except subprocess.TimeoutExpired:
                    result["file_type"] = "Identification timed out"

            # Extract PE metadata when the file is a Windows PE.
            try:
                pe = pefile.PE(sample_path, fast_load=True)

                result["pe_metadata"] = {
                    "machine": hex(pe.FILE_HEADER.Machine),
                    "number_of_sections": (
                        pe.FILE_HEADER.NumberOfSections
                    ),
                    "timestamp": (
                        pe.FILE_HEADER.TimeDateStamp
                    ),
                    "entry_point": (
                        hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                    ),
                    "image_base": (
                        hex(pe.OPTIONAL_HEADER.ImageBase)
                    )
                }

                pe.close()

            except (pefile.PEFormatError, OSError, AttributeError):
                result["pe_metadata"] = None

            # Extract printable strings without executing the sample.
            strings_command = shutil.which("strings")
            extracted_text = ""

            if strings_command:
                try:
                    completed = subprocess.run(
                        [strings_command, "-a", "-n", "6", sample_path],
                        capture_output=True,
                        text=True,
                        errors="replace",
                        timeout=15,
                        check=False
                    )

                    if completed.returncode == 0:
                        extracted_text = completed.stdout[:1_000_000]
                        result["strings"] = (
                            extracted_text.splitlines()[:200]
                        )

                except subprocess.TimeoutExpired:
                    result["strings_status"] = "Timed out"
                         # Analyze DOCX structure without executing its contents.
                        # Inspect modern Office documents without executing content.
            result["office_analysis"] = analyze_office_package(
                sample_path
            )

            office = result["office_analysis"]

            if office.get("document_text"):
                extracted_text += "\n" + office["document_text"]

            if office.get("external_relationships"):
                relationship_targets = " ".join(
                    item.get("target", "")
                    for item in office["external_relationships"]
                )
                extracted_text += "\n" + relationship_targets

            if office.get("document_text"):
                result["strings"] = list(dict.fromkeys(
                    result["strings"]
                    + [office["document_text"]]
                ))[:200]


                        # Analyze supported modern Office packages only.
            office_extensions = {
                ".docx",
                ".xlsx",
                ".xlsm",
                ".pptx",
            }

            extension = os.path.splitext(filename)[1].lower()

            if extension in office_extensions:
                result["office_analysis"] = analyze_office_package(
                    sample_path
                )
            else:
                result["office_analysis"] = {
                    "status": "Skipped: unsupported Office extension"
                }

            office = result["office_analysis"]

            # Use extracted Office text for IOC extraction.
            # Keep the full document text in office_analysis,
            # rather than adding it as one huge strings entry.
            if office.get("document_text"):
                extracted_text += "\n" + office["document_text"]

            # Include external relationship targets in IOC extraction.
            relationships = office.get("external_relationships", [])

            for relationship in relationships:
                target = relationship.get("target", "")

                if target:
                    extracted_text += "\n" + target



            # Extract candidate URLs and IPv4 addresses from strings.
            url_pattern = re.compile(
                r"https?://[^\s\"'<>]+",
                re.IGNORECASE
            )

            ipv4_pattern = re.compile(
                r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
            )

            urls = list(dict.fromkeys(
                url_pattern.findall(extracted_text)
            ))

            ips = []

            for candidate in ipv4_pattern.findall(extracted_text):
                try:
                    address = ipaddress.ip_address(candidate)

                    if address.version == 4:
                        ips.append(candidate)

                except ValueError:
                    continue

            result["indicators"]["urls"] = urls[:100]
            result["indicators"]["ipv4_addresses"] = (
                list(dict.fromkeys(ips))[:100]
            )

            # Run YARA only when a rules file or rules directory
            # has been explicitly configured.
            rules_path = os.getenv("YARA_RULES_PATH")

            if not rules_path:
                result["yara"]["status"] = (
                    "Skipped: YARA_RULES_PATH is not configured"
                )

            elif not os.path.exists(rules_path):
                result["yara"]["status"] = (
                    "Skipped: configured rules path does not exist"
                )

            else:
                try:
                    if os.path.isfile(rules_path):
                        rules = yara.compile(filepath=rules_path)

                    else:
                        rule_files = {}

                        for root, _, files in os.walk(rules_path):
                            for rule_file in files:
                                if rule_file.endswith((".yar", ".yara")):
                                    full_path = os.path.join(
                                        root, rule_file
                                    )

                                    namespace = os.path.relpath(
                                        full_path, rules_path
                                    ).replace(os.sep, "_")

                                    rule_files[namespace] = full_path

                        if not rule_files:
                            raise ValueError(
                                "No .yar or .yara files found"
                            )

                        rules = yara.compile(filepaths=rule_files)

                    matches = rules.match(
                        sample_path,
                        timeout=10
                    )

                    result["yara"] = {
                        "status": "Completed",
                        "matches": [
                            {
                                "rule": match.rule,
                                "namespace": match.namespace
                            }
                            for match in matches
                        ]
                    }

                except Exception as exc:
                    app.logger.warning(
                        "YARA scan failed: %s", type(exc).__name__
                    )

                    result["yara"]["status"] = (
                        "Failed: rules could not be compiled or scanned"
                    )

            # Run capa as a separate process with a time limit.
            capa_command = shutil.which("capa")

            if not capa_command:
                result["capa"]["status"] = (
                    "Skipped: capa executable not found"
                )

            else:
                try:
                    completed = subprocess.run(
                        [capa_command, "-q", sample_path],
                        capture_output=True,
                        text=True,
                        errors="replace",
                        timeout=45,
                        check=False
                    )

                    if completed.returncode == 0:
                        result["capa"] = {
                            "status": "Completed",
                            "output": completed.stdout[:12000]
                        }

                    else:
                        result["capa"] = {
                            "status": "Failed or unsupported file format",
                            "output": (
                                completed.stderr or completed.stdout
                            )[:3000]
                        }

                except subprocess.TimeoutExpired:
                    result["capa"]["status"] = "Timed out"

                except OSError:
                    result["capa"]["status"] = (
                        "Could not start capa"
                    )

            return jsonify(result)

        except Exception:
            app.logger.exception("Static file analysis failed")
                      # Run CAPA only when PE metadata confirms a Windows
            # Portable Executable was successfully parsed.
            # This avoids sending Office documents and PDFs to CAPA.
            if result["pe_metadata"] is None:
                result["capa"]["status"] = (
                    "Skipped: file was not identified as a valid PE"
                )

            else:
                capa_command = shutil.which("capa")

                if not capa_command:
                    result["capa"]["status"] = (
                        "Skipped: capa executable not found"
                    )

                else:
                    try:
                        completed = subprocess.run(
                            [capa_command, "-q", sample_path],
                            capture_output=True,
                            text=True,
                            errors="replace",
                            timeout=45,
                            check=False
                        )

                        if completed.returncode == 0:
                            result["capa"] = {
                                "status": "Completed",
                                "output": completed.stdout[:12000]
                            }

                        else:
                            result["capa"] = {
                                "status": "Failed",
                                "output": (
                                    completed.stderr
                                    or completed.stdout
                                )[:3000]
                            }

                    except subprocess.TimeoutExpired:
                        result["capa"]["status"] = "Timed out"

                    except OSError:
                        result["capa"]["status"] = (
                            "Could not start capa"
                        )

        except Exception:
            app.logger.exception("Static file analysis failed")
            return jsonify({
                "error": "Static file analysis failed safely"
            }), 500

@app.post("/api/network/analyze")
def analyze_network_capture():
    """Analyze a PCAP/PCAPNG capture using TShark."""

    uploaded_file = request.files.get("capture")

    if not uploaded_file or not uploaded_file.filename:
        return jsonify({"error": "Please upload a network capture."}), 400

    extension = Path(uploaded_file.filename).suffix.lower()

    if extension not in {".pcap", ".pcapng", ".cap"}:
        return jsonify({
            "error": "Unsupported format. Upload PCAP, PCAPNG, or CAP."
        }), 400

    # Check that the file resembles a supported capture format.
    magic = uploaded_file.stream.read(4)
    uploaded_file.stream.seek(0)

    pcap_signatures = {
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
    }
    pcapng_signature = b"\x0a\x0d\x0d\x0a"

    if magic not in pcap_signatures and magic != pcapng_signature:
        return jsonify({
            "error": "The uploaded file does not have a recognized PCAP or PCAPNG header."
        }), 400

    tshark = shutil.which("tshark")

    if not tshark:
        return jsonify({
            "error": "TShark is not installed or is not available in PATH."
        }), 503

    temporary_path = None

    try:
        # Use a temporary file and remove it after analysis.
        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=extension,
            dir=UPLOAD_DIR,
            delete=False
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            shutil.copyfileobj(uploaded_file.stream, temporary_file)

        # Analyze no more than the first 5,000 packets in this version.
        command = [
            tshark,
            "-n",
            "-r", str(temporary_path),
            "-T", "fields",
            "-E", "separator=\t",
            "-e", "frame.number",
            "-e", "_ws.col.Protocol",
            "-e", "ip.src",
            "-e", "ipv6.src",
            "-e", "ip.dst",
            "-e", "ipv6.dst",
            "-e", "dns.qry.name",
            "-c", "5000",
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=45,
            check=False
        )

        if result.returncode != 0:
            app.logger.warning(
                "TShark could not analyze an uploaded capture."
            )
            return jsonify({
                "error": "TShark could not parse this capture file."
            }), 400

        protocol_counts = {}
        source_ips = set()
        destination_ips = set()
        dns_queries = set()
        packet_count = 0

        for line in result.stdout.splitlines():
            fields = line.split("\t")

            if not fields or not fields[0].strip():
                continue

            packet_count += 1

            # Fields: number, protocol, IPv4 source, IPv6 source,
            # IPv4 destination, IPv6 destination, DNS query.
            fields += [""] * (7 - len(fields))

            protocol = fields[1].strip() or "Unknown"
            protocol_counts[protocol] = (
                protocol_counts.get(protocol, 0) + 1
            )

            for value in (fields[2], fields[3]):
                value = value.strip()
                if value:
                    source_ips.add(value)

            for value in (fields[4], fields[5]):
                value = value.strip()
                if value:
                    destination_ips.add(value)

            for value in fields[6].split(","):
                value = value.strip()
                if value:
                    dns_queries.add(value)

        if packet_count == 0:
            return jsonify({
                "error": "No packets could be read from this capture."
            }), 400

        return jsonify({
            "status": "success",
            "filename": Path(uploaded_file.filename).name,
            "packets_analyzed": packet_count,
            "packet_limit": 5000,
            "protocol_counts": protocol_counts,
            "source_ips": sorted(source_ips)[:100],
            "destination_ips": sorted(destination_ips)[:100],
            "dns_queries": sorted(dns_queries)[:100],
            "note": (
                "Statistics describe the analyzed packets, up to the "
                "first 5,000. IP addresses and DNS queries are limited "
                "to 100 unique values each."
            )
        })

    except subprocess.TimeoutExpired:
        return jsonify({
            "error": "Network analysis timed out. Try a smaller capture."
        }), 408

    except OSError:
        app.logger.exception("Network capture analysis failed.")
        return jsonify({
            "error": "The network analysis tool could not be executed."
        }), 500

    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                app.logger.warning(
                    "Could not remove a temporary network capture."
                )
@app.errorhandler(413)
def file_too_large(_error):
    return jsonify({
        "error": "File exceeds the 25 MB upload limit"
    }), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
