
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
    """Perform static file analysis without executing the sample."""

    uploaded = request.files.get("file")

    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "Select a file first"}), 400

    filename = os.path.basename(uploaded.filename)

    if not filename:
        return jsonify({"error": "Invalid filename"}), 400

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0

    with tempfile.TemporaryDirectory(prefix="cti-static-") as temp_dir:
        sample_path = os.path.join(temp_dir, "sample.bin")

        try:
            # Save the sample temporarily and calculate its hashes.
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
                "strings_status": "Not run",
                "office_analysis": {
                    "status": "Not applicable"
                },
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
                    "Static analysis only. The sample was not "
                    "executed. Findings require analyst review."
                )
            }

            extracted_text = ""

            # -------------------------------------------------
            # 1. Identify file type
            # -------------------------------------------------
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

            # -------------------------------------------------
            # 2. Extract Windows PE metadata
            # -------------------------------------------------
            try:
                pe = pefile.PE(sample_path, fast_load=True)

                result["pe_metadata"] = {
                    "machine": hex(pe.FILE_HEADER.Machine),
                    "number_of_sections": (
                        pe.FILE_HEADER.NumberOfSections
                    ),
                    "timestamp": pe.FILE_HEADER.TimeDateStamp,
                    "entry_point": hex(
                        pe.OPTIONAL_HEADER.AddressOfEntryPoint
                    ),
                    "image_base": hex(
                        pe.OPTIONAL_HEADER.ImageBase
                    )
                }

                pe.close()

            except (
                pefile.PEFormatError,
                OSError,
                AttributeError
            ):
                result["pe_metadata"] = None

            # -------------------------------------------------
            # 3. Extract printable strings
            # -------------------------------------------------
            strings_command = shutil.which("strings")

            if strings_command:
                try:
                    completed = subprocess.run(
                        [
                            strings_command,
                            "-a",
                            "-n",
                            "6",
                            sample_path
                        ],
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

                        result["strings_status"] = "Completed"
                    else:
                        result["strings_status"] = "Failed"

                except subprocess.TimeoutExpired:
                    result["strings_status"] = "Timed out"

            else:
                result["strings_status"] = (
                    "Skipped: strings executable not found"
                )

            # -------------------------------------------------
            # 4. Analyze supported Office document packages
            # -------------------------------------------------
            office_extensions = {
                ".docx",
                ".xlsx",
                ".xlsm",
                ".pptx"
            }

            extension = Path(filename).suffix.lower()

            if extension in office_extensions:
                try:
                    office = analyze_office_package(sample_path)

                    if not isinstance(office, dict):
                        office = {
                            "status": "Unexpected analyzer response"
                        }

                    result["office_analysis"] = office

                    document_text = office.get("document_text", "")

                    if isinstance(document_text, str):
                        extracted_text += "\n" + document_text

                    relationships = office.get(
                        "external_relationships",
                        []
                    )

                    if isinstance(relationships, list):
                        for relationship in relationships:
                            if not isinstance(relationship, dict):
                                continue

                            target = relationship.get("target", "")

                            if isinstance(target, str):
                                extracted_text += "\n" + target

                except Exception:
                    app.logger.exception(
                        "Office document analysis failed"
                    )

                    result["office_analysis"] = {
                        "status": "Analysis failed"
                    }

            else:
                result["office_analysis"] = {
                    "status": "Skipped: unsupported Office extension"
                }

            # -------------------------------------------------
            # 5. Extract candidate URLs and IPv4 addresses
            # -------------------------------------------------
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
                        ips.append(str(address))

                except ValueError:
                    continue

            result["indicators"]["urls"] = urls[:100]

            result["indicators"]["ipv4_addresses"] = (
                list(dict.fromkeys(ips))[:100]
            )

            # -------------------------------------------------
            # 6. Run YARA if rules have been configured
            # -------------------------------------------------
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
                        rules = yara.compile(
                            filepath=rules_path
                        )

                    else:
                        rule_files = {}

                        for root, _, filenames in os.walk(rules_path):
                            for rule_filename in filenames:
                                if rule_filename.endswith(
                                    (".yar", ".yara")
                                ):
                                    full_path = os.path.join(
                                        root,
                                        rule_filename
                                    )

                                    namespace = os.path.relpath(
                                        full_path,
                                        rules_path
                                    ).replace(os.sep, "_")

                                    rule_files[namespace] = full_path

                        if not rule_files:
                            raise ValueError(
                                "No YARA rule files were found"
                            )

                        rules = yara.compile(
                            filepaths=rule_files
                        )

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

                except Exception:
                    app.logger.exception("YARA analysis failed")

                    result["yara"]["status"] = (
                        "Failed: rules could not be compiled or scanned"
                    )

            # -------------------------------------------------
            # 7. Run CAPA only on successfully parsed PE files
            # -------------------------------------------------
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
                            [
                                capa_command,
                                "-q",
                                sample_path
                            ],
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

            return jsonify(result)

        except Exception:
            app.logger.exception(
                "Static file analysis failed"
            )

            return jsonify({
                "error": "Static file analysis failed safely"
            }), 500
@app.errorhandler(413)
def file_too_large(_error):
    return jsonify({
        "error": "File exceeds the 25 MB upload limit"
    }), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
