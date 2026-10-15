import zipfile
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath


MAX_ENTRIES = 2000
MAX_UNCOMPRESSED_SIZE = 50 * 1024 * 1024
MAX_XML_SIZE = 5 * 1024 * 1024
MAX_TEXT_LENGTH = 20000
MAX_RELATIONSHIPS = 100


def analyze_office_package(sample_path):
    """
    Inspect modern Office ZIP/XML packages without executing content.

    Supports DOCX, XLSX, XLSM, and PPTX.
    Does not claim that structural indicators alone prove malware.
    """
    result = {
        "status": "Not a recognized modern Office package",
        "format": None,
        "archive_entries": 0,
        "document_text": "",
        "external_relationships": [],
        "macro_artifacts": [],
        "embedded_objects": [],
        "warnings": [],
    }

    try:
        if not zipfile.is_zipfile(sample_path):
            return result

        with zipfile.ZipFile(sample_path, "r") as archive:
            entries = archive.infolist()
            names = {entry.filename for entry in entries}

            if len(entries) > MAX_ENTRIES:
                result["status"] = "Skipped: too many archive entries"
                return result

            total_size = sum(entry.file_size for entry in entries)
            if total_size > MAX_UNCOMPRESSED_SIZE:
                result["status"] = "Skipped: expanded archive exceeds limit"
                return result

            if "[Content_Types].xml" not in names:
                return result

            package_formats = {
                "word/document.xml": "DOCX",
                "xl/workbook.xml": "XLSX/XLSM",
                "ppt/presentation.xml": "PPTX",
            }

            detected = next(
                (
                    label
                    for path, label in package_formats.items()
                    if path in names
                ),
                None,
            )

            if not detected:
                return result

            result["format"] = detected
            result["status"] = "Office package inspected"
            result["archive_entries"] = len(entries)

            result["macro_artifacts"] = sorted(
                name for name in names
                if (
                    name.lower().endswith("vbaproject.bin")
                    or name.lower().endswith("vbadata.xml")
                )
            )[:100]

            result["embedded_objects"] = sorted(
                name for name in names
                if (
                    "/embeddings/" in f"/{name}"
                    or "/activex/" in f"/{name.lower()}"
                )
            )[:100]

            # Read external relationships from package XML.
            relationships = []

            for entry in entries:
                name = entry.filename

                if not name.endswith(".rels"):
                    continue

                if entry.file_size > 2 * 1024 * 1024:
                    result["warnings"].append(
                        f"Skipped oversized relationship file: {name}"
                    )
                    continue

                try:
                    root = ET.fromstring(archive.read(entry))

                    for element in root.iter():
                        if not element.tag.endswith("Relationship"):
                            continue

                        if element.attrib.get("TargetMode") == "External":
                            relationships.append({
                                "source": name,
                                "target": element.attrib.get(
                                    "Target", ""
                                )[:2000],
                                "type": element.attrib.get(
                                    "Type", ""
                                )[-100:],
                            })

                            if len(relationships) >= MAX_RELATIONSHIPS:
                                break

                except ET.ParseError:
                    result["warnings"].append(
                        f"Invalid relationship XML: {name}"
                    )

                if len(relationships) >= MAX_RELATIONSHIPS:
                    break

            result["external_relationships"] = relationships

            # Select XML files that commonly contain readable content.
            if detected == "DOCX":
                text_files = [
                    name for name in names
                    if (
                        name == "word/document.xml"
                        or (
                            name.startswith("word/header")
                            and name.endswith(".xml")
                        )
                        or (
                            name.startswith("word/footer")
                            and name.endswith(".xml")
                        )
                    )
                ]
            elif detected == "XLSX/XLSM":
                text_files = [
                    name for name in names
                    if (
                        name.startswith("xl/sharedStrings")
                        or (
                            name.startswith("xl/worksheets/")
                            and name.endswith(".xml")
                        )
                        or name == "xl/workbook.xml"
                    )
                ]
            else:
                text_files = [
                    name for name in names
                    if (
                        name.startswith("ppt/slides/slide")
                        and name.endswith(".xml")
                    )
                ]

            text_parts = []
            text_length = 0

            for name in sorted(text_files)[:100]:
                info = archive.getinfo(name)

                if info.file_size > MAX_XML_SIZE:
                    result["warnings"].append(
                        f"Skipped oversized content XML: {name}"
                    )
                    continue

                try:
                    root = ET.fromstring(archive.read(info))

                    for element in root.iter():
                        if element.tag.endswith("}t") and element.text:
                            remaining = MAX_TEXT_LENGTH - text_length
                            if remaining <= 0:
                                break

                            value = element.text[:remaining]
                            text_parts.append(value)
                            text_length += len(value)

                    if text_length >= MAX_TEXT_LENGTH:
                        result["warnings"].append(
                            "Extracted text reached the configured limit"
                        )
                        break

                except ET.ParseError:
                    result["warnings"].append(
                        f"Invalid content XML: {name}"
                    )

            result["document_text"] = " ".join(text_parts)

    except (
        zipfile.BadZipFile,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        result["status"] = "Inspection failed"
        result["warnings"].append(type(exc).__name__)

    return result
