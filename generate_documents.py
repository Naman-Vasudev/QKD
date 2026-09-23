"""
Script to generate Ghost_Protocol.pdf and Ghost_Protocol.docx
"""

import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement
from docx.oxml.ns import qn


def build_pdf(filename: str):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Define custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0F2942"),
        spaceAfter=6,
    )

    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#0550AE"),
        spaceAfter=15,
    )

    h1_style = ParagraphStyle(
        "Heading1_Custom",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0F2942"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        "Body_Custom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14.5,
        textColor=colors.HexColor("#1F2937"),
        spaceAfter=8,
    )

    bold_body_style = ParagraphStyle(
        "BoldBody_Custom",
        parent=body_style,
        fontName="Helvetica-Bold",
    )

    table_text_style = ParagraphStyle(
        "TableText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#1F2937"),
    )

    table_header_style = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11.5,
        textColor=colors.white,
    )

    story = []

    # Title & Subtitle
    story.append(Paragraph("Progress report - Ghost_Protocol", title_style))
    story.append(Paragraph("TEAM NAME: Ghost_Protocol &nbsp;|&nbsp; PROBLEM STATEMENT 5 &nbsp;|&nbsp; DATE: 08 SEPTEMBER 2026", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0F2942"), spaceAfter=14))

    # 1. Name of the Problem Statement
    story.append(Paragraph("1. Name of the Problem Statement", h1_style))
    p1_text = "Quantum-Inspired Cyber Threat Detection Framework for Teleportation-Based Quantum Digital Signature Security"
    story.append(Paragraph(f"<b>{p1_text}</b>", body_style))
    story.append(Spacer(1, 4))

    # 2. Abstract of overall proposed idea
    story.append(Paragraph("2. Abstract of Overall Proposed Idea", h1_style))
    p2_text = (
        "Quantum Digital Signature (QDS) protocols provide information-theoretic security against quantum algorithms "
        "such as Shor's algorithm, which compromise classical public-key cryptography. This project presents a "
        "non-machine-learning, quantum-inspired cyber threat detection framework tailored for teleportation-based QDS "
        "systems. The architecture integrates a classical pre-processing module utilizing SHA-256 hashing and 256-bit "
        "secret key XOR encoding with a 3-qubit quantum teleportation pipeline. Alice prepares Pauli eigenstates across a "
        "deterministic Z/X/Y basis schedule, transmitting them via Bell-state EPR pairs and conditional Pauli corrections. "
        "Bob performs projective measurements to verify signature authenticity against calibrated baseline channel noise (p0). "
        "The core threat detection engine replaces artificial intelligence with an exact Binomial upper-tail hypothesis "
        "testing model (P(K &ge; k | n, p0)). The framework detects five physical threat vectors: channel tampering "
        "(Pauli-X bit-flips), signature forgery (K=0 assumption), impersonation (Bernoulli guessing), quantum interception "
        "(intercept-resend measurement collapse), and replay attacks (digest Hamming distance analysis). Verified on Qiskit "
        "AerSimulator and validated on physical IBM Quantum QPUs via Qiskit Runtime, the system guarantees deterministic "
        "acceptance of legitimate signatures, low computational complexity, and robust security guarantees."
    )
    story.append(Paragraph(p2_text, body_style))
    story.append(Spacer(1, 4))

    # 3. Work done/implemented till 8 PM today i.e. 08/09/2026
    story.append(Paragraph("3. Work Done / Implemented Till 8 PM Today (08/09/2026)", h1_style))
    p3_text = (
        "Fully implemented end-to-end QDS protocol, exact Binomial threat detector, 5 physical attack models "
        "(channel tampering, forgery, impersonation, interception, replay), 70-test regression suite, Streamlit research "
        "laboratory UI, 256-qubit experimental trace inspector, and optional IBM Quantum QPU integration with Streamlit Cloud deployment."
    )
    story.append(Paragraph(p3_text, body_style))
    story.append(Spacer(1, 4))

    # 4. Work left
    story.append(Paragraph("4. Work Left", h1_style))
    p4_text = (
        "Phase 6 enhancements: integrating session nonces for same-message replay prevention, benchmarking hardware "
        "execution latency across multiple IBM QPUs under varying queue depths, expanding key agreement protocols for "
        "multi-recipient verification, and generating comparative benchmarking reports against classical ECDSA signatures."
    )
    story.append(Paragraph(p4_text, body_style))
    story.append(Spacer(1, 4))

    # 5. Challenges faced
    story.append(Paragraph("5. Challenges Faced", h1_style))
    c1_text = (
        "<b>1. Quantum Measurement Collapse & Basis Invariance Handling:</b> "
        "Designing physical attack models (channel tampering, intercept-resend) without fabricating error rates "
        "required precise simulation of quantum eigenstate projections. Handling basis-wise invariance (X|+&gt; = |+&gt;) "
        "while capturing state collapse during out-of-basis Eve measurements required custom Qiskit circuit pipelines."
    )
    c2_text = (
        "<b>2. Hardware API & UI Execution Compatibility:</b> "
        "Integrating optional physical IBM Quantum QPU execution (qiskit-ibm-runtime) alongside local AerSimulator "
        "required handling account channel differences (ibm_cloud vs ibm_quantum), managing non-blocking job execution, "
        "and resolving cloud dependency requirements (pylatexenc) while ensuring zero exposure of sensitive API keys."
    )
    story.append(Paragraph(c1_text, body_style))
    story.append(Paragraph(c2_text, body_style))
    story.append(Spacer(1, 10))

    # Deliverables Verification Matrix Table
    story.append(Paragraph("Deliverables Verification Matrix (Codebase Mapping)", h1_style))

    table_data = [
        [
            Paragraph("S.No", table_header_style),
            Paragraph("Expected Deliverable", table_header_style),
            Paragraph("Key Components / Metrics", table_header_style),
            Paragraph("Codebase Implementation & File Mapping", table_header_style),
        ],
        [
            Paragraph("1", table_text_style),
            Paragraph("<b>Mathematical Model of Teleportation-based QDS</b>", table_text_style),
            Paragraph("Bell-state entanglement, 3-qubit teleportation, Pauli corrections (Z<sup>c0</sup>X<sup>c1</sup>), 6 Pauli eigenstates", table_text_style),
            Paragraph("• <code>qds/states.py</code>: 6 Pauli eigenstates, Z/X/Y basis matrices.<br/>• <code>qds/teleportation.py</code>: 3-qubit Bell pair, Pauli corrections.<br/>• <code>qds/circuit_visualization.py</code>: Statevector & Bloch formulas.", table_text_style),
        ],
        [
            Paragraph("2", table_text_style),
            Paragraph("<b>Quantum-Inspired Threat Detection Framework</b>", table_text_style),
            Paragraph("Non-ML core detection engine for forgery, impersonation, replay, and channel tampering", table_text_style),
            Paragraph("• <code>statistics/detector.py</code>: Exact Binomial upper-tail test (P(K &ge; k | n, p0)).<br/>• <code>evaluation/runner.py</code>: Comparative security sweeps.", table_text_style),
        ],
        [
            Paragraph("3", table_text_style),
            Paragraph("<b>Signature Generation & Verification Module</b>", table_text_style),
            Paragraph("QKD simulation, Signature generation, Verification algorithm with Pauli corrections", table_text_style),
            Paragraph("• <code>qds/encoding.py</code>: SHA-256 digest (D), XOR key mixing (b<sub>i</sub> = d<sub>i</sub> &oplus; K<sub>i</sub>), basis schedule.<br/>• <code>qds/verification.py</code>: Bob-side projective measurement readout.<br/>• <code>core/backend.py</code>: AerSimulator adapter.", table_text_style),
        ],
        [
            Paragraph("4", table_text_style),
            Paragraph("<b>Attack Simulation Module</b>", table_text_style),
            Paragraph("Simulation of cyber threats: Forgery, Impersonation, Replay, Channel Tampering", table_text_style),
            Paragraph("• <code>attacks/channel.py</code>: Pauli-X channel noise.<br/>• <code>attacks/forgery.py</code>: Digest-only forgery (K=0).<br/>• <code>attacks/impersonation.py</code>: Bernoulli(0.5) guessing.<br/>• <code>attacks/interception.py</code>: Intercept-resend collapse.<br/>• <code>attacks/replay.py</code>: Replay & Hamming distance.", table_text_style),
        ],
        [
            Paragraph("6", table_text_style),
            Paragraph("<b>Software Framework / Prototype</b>", table_text_style),
            Paragraph("Simulation environment, Verification interface, Threat detection dashboard, Event logging", table_text_style),
            Paragraph("• <code>app.py</code>: Streamlit web dashboard with 7 sections, 256-qubit outcome maps, Qiskit drawer.<br/>• <code>core/hardware.py</code>: Real IBM Quantum QPU execution.<br/>• <code>tests/</code>: 70 unit tests, 100% passing.", table_text_style),
        ],
    ]

    col_widths = [0.4 * inch, 1.6 * inch, 2.2 * inch, 2.8 * inch]
    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0F2942")),
        ('ALIGN', (0, 0), (0, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CDD1D7")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F8F9FA")]),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
    ]))

    story.append(t)

    doc.build(story)
    print(f"PDF built successfully: {filename}")


def build_docx(filename: str):
    doc = docx.Document()

    # Set page margins to 0.75 inch
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(0.75)
        section.bottom_margin = Inches(0.75)
        section.left_margin = Inches(0.75)
        section.right_margin = Inches(0.75)

    # Title
    p_title = doc.add_paragraph()
    r_title = p_title.add_run("Progress report - Ghost_Protocol")
    r_title.bold = True
    r_title.font.name = "Arial"
    r_title.font.size = Pt(20)
    r_title.font.color.rgb = RGBColor(15, 41, 66)

    # Subtitle
    p_sub = doc.add_paragraph()
    r_sub = p_sub.add_run("TEAM NAME: Ghost_Protocol  |  PROBLEM STATEMENT 5  |  DATE: 08 SEPTEMBER 2026")
    r_sub.bold = True
    r_sub.font.name = "Arial"
    r_sub.font.size = Pt(10.5)
    r_sub.font.color.rgb = RGBColor(5, 80, 174)

    # 1. Name of Problem Statement
    h1 = doc.add_heading(level=1)
    r_h1 = h1.add_run("1. Name of the Problem Statement")
    r_h1.font.name = "Arial"
    r_h1.font.color.rgb = RGBColor(15, 41, 66)

    p1 = doc.add_paragraph()
    r1 = p1.add_run("Quantum-Inspired Cyber Threat Detection Framework for Teleportation-Based Quantum Digital Signature Security")
    r1.bold = True
    r1.font.name = "Calibri"
    r1.font.size = Pt(11)

    # 2. Abstract
    h2 = doc.add_heading(level=1)
    r_h2 = h2.add_run("2. Abstract of Overall Proposed Idea")
    r_h2.font.name = "Arial"
    r_h2.font.color.rgb = RGBColor(15, 41, 66)

    p2 = doc.add_paragraph()
    r2 = p2.add_run(
        "Quantum Digital Signature (QDS) protocols provide information-theoretic security against quantum algorithms "
        "such as Shor's algorithm, which compromise classical public-key cryptography. This project presents a "
        "non-machine-learning, quantum-inspired cyber threat detection framework tailored for teleportation-based QDS "
        "systems. The architecture integrates a classical pre-processing module utilizing SHA-256 hashing and 256-bit "
        "secret key XOR encoding with a 3-qubit quantum teleportation pipeline. Alice prepares Pauli eigenstates across a "
        "deterministic Z/X/Y basis schedule, transmitting them via Bell-state EPR pairs and conditional Pauli corrections. "
        "Bob performs projective measurements to verify signature authenticity against calibrated baseline channel noise (p0). "
        "The core threat detection engine replaces artificial intelligence with an exact Binomial upper-tail hypothesis "
        "testing model (P(K >= k | n, p0)). The framework detects five physical threat vectors: channel tampering "
        "(Pauli-X bit-flips), signature forgery (K=0 assumption), impersonation (Bernoulli guessing), quantum interception "
        "(intercept-resend measurement collapse), and replay attacks (digest Hamming distance analysis). Verified on Qiskit "
        "AerSimulator and validated on physical IBM Quantum QPUs via Qiskit Runtime, the system guarantees deterministic "
        "acceptance of legitimate signatures, low computational complexity, and robust security guarantees."
    )
    r2.font.name = "Calibri"
    r2.font.size = Pt(11)

    # 3. Work Done
    h3 = doc.add_heading(level=1)
    r_h3 = h3.add_run("3. Work Done / Implemented Till 8 PM Today (08/09/2026)")
    r_h3.font.name = "Arial"
    r_h3.font.color.rgb = RGBColor(15, 41, 66)

    p3 = doc.add_paragraph()
    r3 = p3.add_run(
        "Fully implemented end-to-end QDS protocol, exact Binomial threat detector, 5 physical attack models "
        "(channel tampering, forgery, impersonation, interception, replay), 70-test regression suite, Streamlit research "
        "laboratory UI, 256-qubit experimental trace inspector, and optional IBM Quantum QPU integration with Streamlit Cloud deployment."
    )
    r3.font.name = "Calibri"
    r3.font.size = Pt(11)

    # 4. Work Left
    h4 = doc.add_heading(level=1)
    r_h4 = h4.add_run("4. Work Left")
    r_h4.font.name = "Arial"
    r_h4.font.color.rgb = RGBColor(15, 41, 66)

    p4 = doc.add_paragraph()
    r4 = p4.add_run(
        "Phase 6 enhancements: integrating session nonces for same-message replay prevention, benchmarking hardware "
        "execution latency across multiple IBM QPUs under varying queue depths, expanding key agreement protocols for "
        "multi-recipient verification, and generating comparative benchmarking reports against classical ECDSA signatures."
    )
    r4.font.name = "Calibri"
    r4.font.size = Pt(11)

    # 5. Challenges Faced
    h5 = doc.add_heading(level=1)
    r_h5 = h5.add_run("5. Challenges Faced")
    r_h5.font.name = "Arial"
    r_h5.font.color.rgb = RGBColor(15, 41, 66)

    pc1 = doc.add_paragraph()
    rc1_title = pc1.add_run("1. Quantum Measurement Collapse & Basis Invariance Handling: ")
    rc1_title.bold = True
    rc1_body = pc1.add_run(
        "Designing physical attack models (channel tampering, intercept-resend) without fabricating error rates "
        "required precise simulation of quantum eigenstate projections. Handling basis-wise invariance (X|+> = |+>) "
        "while capturing state collapse during out-of-basis Eve measurements required custom Qiskit circuit pipelines."
    )

    pc2 = doc.add_paragraph()
    rc2_title = pc2.add_run("2. Hardware API & UI Execution Compatibility: ")
    rc2_title.bold = True
    rc2_body = pc2.add_run(
        "Integrating optional physical IBM Quantum QPU execution (qiskit-ibm-runtime) alongside local AerSimulator "
        "required handling account channel differences (ibm_cloud vs ibm_quantum), managing non-blocking job execution, "
        "and resolving cloud dependency requirements (pylatexenc) while ensuring zero exposure of sensitive API keys."
    )

    # Deliverables Verification Matrix Table
    h_tbl = doc.add_heading(level=1)
    r_htbl = h_tbl.add_run("Deliverables Verification Matrix (Codebase Mapping)")
    r_htbl.font.name = "Arial"
    r_htbl.font.color.rgb = RGBColor(15, 41, 66)

    table_data = [
        ("S.No", "Expected Deliverable", "Key Components / Metrics", "Codebase Implementation & File Mapping"),
        ("1", "Mathematical Model of Teleportation-based QDS", "Bell-state entanglement, 3-qubit teleportation, Pauli corrections (Z^(c0) X^(c1)), 6 Pauli eigenstates", "• qds/states.py: 6 Pauli eigenstates, Z/X/Y basis matrices.\n• qds/teleportation.py: 3-qubit Bell pair, Pauli corrections.\n• qds/circuit_visualization.py: Statevector & Bloch formulas."),
        ("2", "Quantum-Inspired Threat Detection Framework", "Non-ML core detection engine for forgery, impersonation, replay, and channel tampering", "• statistics/detector.py: Exact Binomial upper-tail test (P(K >= k | n, p0)).\n• evaluation/runner.py: Comparative security sweeps."),
        ("3", "Signature Generation & Verification Module", "QKD simulation, Signature generation, Verification algorithm with Pauli corrections", "• qds/encoding.py: SHA-256 digest (D), XOR key mixing (b_i = d_i XOR K_i), basis schedule.\n• qds/verification.py: Bob-side projective measurement readout.\n• core/backend.py: AerSimulator adapter."),
        ("4", "Attack Simulation Module", "Simulation of cyber threats: Forgery, Impersonation, Replay, Channel Tampering", "• attacks/channel.py: Pauli-X channel noise.\n• attacks/forgery.py: Digest-only forgery (K=0).\n• attacks/impersonation.py: Bernoulli(0.5) guessing.\n• attacks/interception.py: Intercept-resend collapse.\n• attacks/replay.py: Replay & Hamming distance."),
        ("6", "Software Framework / Prototype", "Simulation environment, Verification interface, Threat detection dashboard, Event logging", "• app.py: Streamlit web dashboard with 7 sections, 256-qubit outcome maps, Qiskit drawer.\n• core/hardware.py: Real IBM Quantum QPU execution.\n• tests/: 70 unit tests, 100% passing."),
    ]

    tbl = doc.add_table(rows=len(table_data), cols=4)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER

    for row_idx, row in enumerate(table_data):
        for col_idx, cell_value in enumerate(row):
            cell = tbl.cell(row_idx, col_idx)
            cell.text = cell_value
            # Styling header
            if row_idx == 0:
                cell.paragraphs[0].runs[0].font.bold = True
                cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)
                shading_elm = OxmlElement('w:shd')
                shading_elm.set(qn('w:val'), 'clear')
                shading_elm.set(qn('w:color'), 'auto')
                shading_elm.set(qn('w:fill'), '0F2942')
                cell._tc.get_or_add_tcPr().append(shading_elm)

    doc.save(filename)
    print(f"DOCX built successfully: {filename}")


if __name__ == "__main__":
    pdf_path = "Ghost_Protocol.pdf"
    docx_path = "Ghost_Protocol.docx"

    build_pdf(pdf_path)
    build_docx(docx_path)
