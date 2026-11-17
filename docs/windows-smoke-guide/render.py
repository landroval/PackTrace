"""Generate the corrected Windows guide and exact UTF-8/BOM PowerShell blocks.

Usage: python render.py NEW_OUTPUT_DIRECTORY [--scripts-only]
Requires ReportLab only for PDF generation; never executes the examples.
"""

import re
import shutil
import sys
from html import escape
from pathlib import Path

SOURCE = Path(__file__).with_name("guide.md")
NAMES = (
    "01-verificar.ps1", "02-preparar.ps1", "03-comprobar.ps1",
    "04-json.ps1", "05-entorno.ps1",
)


def render(destination, scripts_only=False):
    text = SOURCE.read_text(encoding="utf-8")
    blocks = re.findall(r"```powershell\n(.*?)```", text, re.S)
    assert len(blocks) == len(NAMES), "Expected five PowerShell blocks"
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    for name, block in zip(NAMES, blocks):
        # A BOM preserves non-ASCII text when read by Windows PowerShell 5.1.
        (destination / name).write_bytes(b"\xef\xbb\xbf" + block.replace("\n", "\r\n").encode("utf-8"))
    shutil.copyfile(SOURCE, destination / "guide.md")
    shutil.copyfile(Path(__file__).with_name("verify-samples.ps1"), destination / "verify-samples.ps1")

    if scripts_only:
        return

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.pdfbase.pdfmetrics import stringWidth
    from reportlab.platypus import KeepTogether, Paragraph, Preformatted, SimpleDocTemplate, Spacer

    styles = getSampleStyleSheet()
    styles["BodyText"].fontSize = 9
    styles["BodyText"].leading = 13
    story = []
    for part in re.split(r"(```powershell\n.*?```)", text, flags=re.S):
        if part.startswith("```powershell\n"):
            code = part.removeprefix("```powershell\n").removesuffix("```").rstrip()
            width = max(stringWidth(line, "Courier", 1) for line in code.splitlines())
            style = styles["Code"].clone("PowerShell")
            style.fontSize = min(8, (A4[0] - 88) / width)
            style.leading = style.fontSize + 3
            style.backColor = colors.HexColor("#f0f3f6")
            story.extend([KeepTogether([Preformatted(code, style)]), Spacer(1, 10)])
        else:
            for paragraph in part.strip().split("\n\n"):
                if not paragraph.strip():
                    continue
                level = len(paragraph) - len(paragraph.lstrip("#"))
                style = styles[{1: "Title", 2: "Heading1", 3: "Heading2"}.get(level, "BodyText")]
                content = paragraph.lstrip("# ") if level else paragraph
                story.extend([Paragraph(escape(content), style), Spacer(1, 6)])

    def footer(canvas, document):
        canvas.setFont("Helvetica", 8)
        canvas.drawString(36, 20, "PackTrace 0.1.0-alpha.1 / guia corregida r1 / datos ficticios")
        canvas.drawRightString(A4[0] - 36, 20, str(document.page))

    SimpleDocTemplate(
        str(destination / "PackTrace-Windows-Guia-pruebas-v0.1.0-alpha.1-corregida-r1.pdf"),
        pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36,
        title="PackTrace Windows - Guia de pruebas corregida r1",
    ).build(story, onFirstPage=footer, onLaterPages=footer)


if __name__ == "__main__":
    render(sys.argv[1], scripts_only="--scripts-only" in sys.argv[2:])
