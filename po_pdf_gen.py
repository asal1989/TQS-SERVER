#!/usr/bin/env python3
"""Generate a PO PDF in BCIM format from JSON data passed as file argument."""
import sys, json, os
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, HRFlowable, PageBreak)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

W, H = A4

# ── Load data ──────────────────────────────────────────────────────────────────
data_file = sys.argv[1]
out_file  = sys.argv[2]
with open(data_file) as f:
    data = json.load(f)

po       = data.get('po', {})
items    = data.get('items', [])
vendor   = data.get('vendor', {})
settings = data.get('settings', {})

# ── Helper styles ──────────────────────────────────────────────────────────────
def S(name, **kw):
    return ParagraphStyle(name, fontName=kw.pop('font','Helvetica'),
        fontSize=kw.pop('size',8), leading=kw.pop('leading',10),
        spaceAfter=0, spaceBefore=0, **kw)

sN   = S('N')
sB   = S('B', font='Helvetica-Bold')
sSm  = S('Sm', size=7, leading=9)
sSmB = S('SmB', size=7, leading=9, font='Helvetica-Bold')
sCtr = S('Ctr', alignment=TA_CENTER)
sCtrB= S('CtrB', alignment=TA_CENTER, font='Helvetica-Bold')
sRgt = S('Rgt', alignment=TA_RIGHT)
sRgtB= S('RgtB', alignment=TA_RIGHT, font='Helvetica-Bold')
sSmC = S('SmC', size=7, leading=9, alignment=TA_CENTER)
sSmCB= S('SmCB', size=7, leading=9, alignment=TA_CENTER, font='Helvetica-Bold')
sSmR = S('SmR', size=7, leading=9, alignment=TA_RIGHT)
sSmRB= S('SmRB', size=7, leading=9, alignment=TA_RIGHT, font='Helvetica-Bold')

def P(t, s=None): return Paragraph(str(t or ''), s or sN)
def PB(t): return Paragraph(str(t or ''), sB)
def Psm(t): return Paragraph(str(t or ''), sSm)
def PsmB(t): return Paragraph(str(t or ''), sSmB)
def PsmC(t): return Paragraph(str(t or ''), sSmC)
def PsmCB(t): return Paragraph(str(t or ''), sSmCB)
def PsmR(t): return Paragraph(str(t or ''), sSmR)
def PsmRB(t): return Paragraph(str(t or ''), sSmRB)
def fmtN(v):
    try:
        v = float(v)
        if v == int(v): return f"{int(v):,}"
        return f"{v:,.2f}"
    except: return str(v or '')
def fmtQ(v):
    try: return f"{float(v):.2f}"
    except: return str(v or '')

# ── Company info (from settings or defaults) ───────────────────────────────────
co_name   = settings.get('company_name','BCIM ENGINEERING PRIVATE LIMITED')
co_wing   = settings.get('company_wing','"B" Wing, Divyasree Chambers.')
co_addr   = settings.get('company_addr','No. 11, O\'Shaugnessy Road, Bangalore - 560025')
co_gstin  = settings.get('company_gstin','29AAHCB6485A1ZL')
co_footer = settings.get('company_footer','"B" Wing, DivyaSree Chambers, No. 11, O\'Shaugnessy Road,  Bangalore-560 025.')
form_no   = po.get('form_no') or settings.get('form_no','BCIM-PUR-F-03')

# ── PO fields ──────────────────────────────────────────────────────────────────
po_number   = po.get('po_number','')
po_date     = po.get('po_date','')
project     = po.get('site_code','') or po.get('description','')
po_req_no   = po.get('po_req_no','')
po_req_date = po.get('po_req_date','')
approval_no = po.get('approval_no','')
narration   = po.get('narration','')
deliv_addr  = po.get('delivery_address','')
deliv_cont  = po.get('delivery_contact','')

# Vendor
v_name    = po.get('vendor','')
v_addr    = vendor.get('address','')
v_city    = vendor.get('city','')
v_email   = vendor.get('email','')
v_phone   = vendor.get('phone','')
v_contact = vendor.get('contact_person','')
v_gstin   = vendor.get('gstin','')

# ── Compute totals ─────────────────────────────────────────────────────────────
subtotal = sum(float(it.get('amount',0) or 0) for it in items)
po_total = float(po.get('po_value', subtotal) or subtotal)

# ── Page template ──────────────────────────────────────────────────────────────
def make_page(canvas, doc):
    canvas.saveState()
    pw = doc.width + doc.leftMargin + doc.rightMargin
    canvas.setFont('Helvetica-Bold', 8)
    canvas.drawRightString(pw - 8*mm, H - 8*mm, form_no)
    canvas.setFont('Helvetica', 7)
    canvas.line(10*mm, 18*mm, pw - 10*mm, 18*mm)
    canvas.drawCentredString(pw/2, 13*mm, co_name)
    canvas.drawCentredString(pw/2,  9*mm, co_footer)
    total_pages = getattr(doc, '_pageCount', '?')
    canvas.drawRightString(pw - 10*mm, 9*mm, f'Page {doc.page} of {canvas._pageNumber}')
    canvas.restoreState()

# We'll use a two-pass for page count; for now set to dynamic
class MyDoc(SimpleDocTemplate):
    def handle_pageEnd(self):
        self._pageCount = self.page
        super().handle_pageEnd()

doc = MyDoc(out_file, pagesize=A4,
    leftMargin=12*mm, rightMargin=10*mm,
    topMargin=14*mm, bottomMargin=24*mm)

story = []

# ── HEADER ─────────────────────────────────────────────────────────────────────
logo_box = Table([
    [P('<b>3</b>', ParagraphStyle('lg', fontName='Helvetica-Bold', fontSize=22,
       textColor=colors.HexColor('#1a5276'), alignment=TA_CENTER))],
    [P('BCIM', ParagraphStyle('bc', fontName='Helvetica-Bold', fontSize=13,
       textColor=colors.HexColor('#1a5276'), alignment=TA_CENTER))]
], colWidths=[20*mm], rowHeights=[11*mm, 7*mm])
logo_box.setStyle(TableStyle([
    ('ALIGN',(0,0),(-1,-1),'CENTER'),('VALIGN',(0,0),(-1,-1),'MIDDLE'),
    ('BOX',(0,0),(-1,-1),1.5,colors.HexColor('#1a5276')),
]))

co_block = Table([
    [PB(co_name)],
    [Psm(co_wing)],
    [Psm(co_addr)],
    [PsmB(f'GSTIN : {co_gstin}')],
], colWidths=[92*mm], style=[
    ('TOPPADDING',(0,0),(-1,-1),1.5),('BOTTOMPADDING',(0,0),(-1,-1),1.5),
    ('LEFTPADDING',(0,0),(-1,-1),0),('RIGHTPADDING',(0,0),(-1,-1),0),
])

hdr = Table([[
    logo_box, co_block,
    P('PURCHASE ORDER', ParagraphStyle('pt', fontName='Helvetica-Bold',
      fontSize=13, alignment=TA_CENTER, leading=16))
]], colWidths=[24*mm, 94*mm, 69*mm])
hdr.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'MIDDLE')]))
story.append(hdr)
story.append(HRFlowable(width='100%', thickness=1.5, color=colors.black))
story.append(Spacer(1,2*mm))

# ── ADDRESS + PO INFO ──────────────────────────────────────────────────────────
po_info = Table([
    [Psm('Project:'),      PsmB(project)],
    [Psm('PO No:'),        PsmB(po_number)],
    [Psm('Date:'),         PsmB(po_date)],
    [Psm('PO Req No:'),    Psm(po_req_no)],
    [Psm('PO Req Date:'),  Psm(po_req_date)],
    [Psm('Approval No:'),  Psm(approval_no)],
], colWidths=[26*mm, 50*mm], style=[
    ('ALIGN',(0,0),(-1,-1),'LEFT'),('VALIGN',(0,0),(-1,-1),'TOP'),
    ('TOPPADDING',(0,0),(-1,-1),1.5),('BOTTOMPADDING',(0,0),(-1,-1),1.5),
    ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#cccccc')),
])

v_lines = [[PB(f'M/s. {v_name}')]]
if v_addr:   v_lines.append([Psm(v_addr)])
if v_city:   v_lines.append([Psm(v_city)])
if v_email:  v_lines.append([Psm(f'Email: {v_email}')])
if v_phone:  v_lines.append([Psm(f'Contact person: {v_contact}  Mob: {v_phone}' if v_contact else f'Phone: {v_phone}')])
if v_gstin:  v_lines.append([Psm(f'GST No: {v_gstin}')])

addr_block = Table([[Psm('To,')]] + v_lines, colWidths=[100*mm], style=[
    ('TOPPADDING',(0,0),(-1,-1),1.5),('BOTTOMPADDING',(0,0),(-1,-1),1.5),
    ('LEFTPADDING',(0,0),(-1,-1),0),('RIGHTPADDING',(0,0),(-1,-1),0),
])

addr_row = Table([[addr_block, po_info]], colWidths=[107*mm, 80*mm])
addr_row.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP')]))
story.append(addr_row)
story.append(Spacer(1,2*mm))

# ── DELIVERY ADDRESS ───────────────────────────────────────────────────────────
story.append(Table([[PsmB('DELIVERY ADDRESS:-')]], colWidths=[187*mm], style=[
    ('LINEBELOW',(0,0),(-1,-1),0.5,colors.black),
    ('BOTTOMPADDING',(0,0),(-1,-1),1),
]))
deliv_lines = [[PsmB(f'Project: {project}')]]
if deliv_addr:
    for line in deliv_addr.split('\n'):
        deliv_lines.append([Psm(line)])
if deliv_cont:
    deliv_lines.append([Psm(f'Contact Person: {deliv_cont}')])
story.append(Table(deliv_lines, colWidths=[187*mm], style=[
    ('TOPPADDING',(0,0),(-1,-1),1.5),('BOTTOMPADDING',(0,0),(-1,-1),1.5),
    ('LEFTPADDING',(0,0),(-1,-1),0),
]))
story.append(Spacer(1,1*mm))
story.append(Psm('We hereby place an order on you for supply of the following materials with same terms and conditions as per original order.'))
story.append(Spacer(1,1.5*mm))

# ── LINE ITEMS TABLE ───────────────────────────────────────────────────────────
# Columns: Sl No | Description | UOM | Qty | Rate | Basic Amt | GST% | GST Amt | Total Amt | HEADS
col_w = [9*mm, 65*mm, 12*mm, 14*mm, 18*mm, 20*mm, 10*mm, 18*mm, 20*mm, 15*mm]

tbl_rows = [[PsmCB('Sl No'), PsmCB('Description'), PsmCB('UOM'),
             PsmCB('Qty'), PsmCB('Rate'), PsmCB('Basic Amt'),
             PsmCB('GST%'), PsmCB('GST Amt'), PsmCB('Total Amt'), PsmCB('HEADS')]]

for it in items:
    desc    = str(it.get('description','')).replace('\n','<br/>')
    rate    = it.get('rate','')
    rate_str= fmtN(rate) if rate not in ('','0',0,None) else ''
    basic   = float(it.get('amount',0) or 0)
    gst_pct = float(it.get('gst_pct',18) or 0)
    gst_amt = float(it.get('gst_amt',0) or round(basic*gst_pct/100,2))
    tot_amt = float(it.get('total_amt',0) or (basic+gst_amt))
    gst_str = f'{int(gst_pct)}%' if gst_pct else '0%'
    tbl_rows.append([
        PsmC(str(it.get('sl_no',''))),
        Psm(desc),
        PsmC(str(it.get('uom',''))),
        PsmR(fmtQ(it.get('quantity',0))),
        PsmR(rate_str),
        PsmR(fmtN(basic) if basic else ''),
        PsmC(gst_str),
        PsmR(fmtN(gst_amt) if gst_amt else ''),
        PsmR(fmtN(tot_amt) if tot_amt else ''),
        PsmC(str(it.get('heads',''))),
    ])

item_style = TableStyle([
    ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#d6e4f0')),
    ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#aaaaaa')),
    ('ALIGN',(0,0),(-1,-1),'CENTER'),
    ('ALIGN',(1,1),(1,-1),'LEFT'),
    ('ALIGN',(3,1),(5,-1),'RIGHT'),  # Qty, Rate, Basic Amt
    ('ALIGN',(7,1),(8,-1),'RIGHT'),  # GST Amt, Total Amt
    ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
    ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
    ('FONTSIZE',(0,0),(-1,-1),7),
    ('TOPPADDING',(0,0),(-1,-1),2),('BOTTOMPADDING',(0,0),(-1,-1),2),
    ('LEFTPADDING',(1,0),(1,-1),3),
    ('BACKGROUND',(8,1),(-1,-1),colors.HexColor('#f0f7ff')),  # Total col light tint
])

# Span HEADS column for consecutive same values
def apply_head_spans(style, rows):
    heads = [(i+1, str(r[9].text if hasattr(r[9],'text') else '')) for i,r in enumerate(rows[1:])]
    i = 0
    while i < len(heads):
        val = ''
        try: val = items[i].get('heads','')
        except: pass
        if val:
            j = i
            while j+1 < len(heads):
                try: nxt = items[j+1].get('heads','')
                except: nxt = ''
                if not nxt: j += 1
                else: break
            if j > i:
                style.add('SPAN',(9,i+1),(9,j+1))
                style.add('VALIGN',(9,i+1),(9,j+1),'MIDDLE')
        i += 1

apply_head_spans(item_style, tbl_rows)

items_tbl = Table(tbl_rows, colWidths=col_w, repeatRows=1)
items_tbl.setStyle(item_style)
story.append(items_tbl)
story.append(Spacer(1,2*mm))

# ── TOTALS ─────────────────────────────────────────────────────────────────────
total_basic = sum(float(it.get('amount',0) or 0) for it in items)
total_gst   = sum(float(it.get('gst_amt',0) or round(float(it.get('amount',0) or 0)*float(it.get('gst_pct',18) or 0)/100,2)) for it in items)
grand       = total_basic + total_gst
if grand == 0: grand = po_total or total_basic

# Group GST by rate for breakdown
from collections import defaultdict
gst_groups = defaultdict(float)
for it in items:
    pct = float(it.get('gst_pct',18) or 0)
    ga  = float(it.get('gst_amt',0) or round(float(it.get('amount',0) or 0)*pct/100,2))
    if ga > 0: gst_groups[pct] += ga

total_rows = [['','', PsmB('Sub Total'), PsmRB(fmtN(total_basic))]]
for pct in sorted(gst_groups.keys()):
    # Find item nos for this rate
    nos = [str(it.get('sl_no','')) for it in items if float(it.get('gst_pct',18) or 0)==pct and float(it.get('gst_amt',0) or 0)>0]
    label = f'GST @ {int(pct)}%'
    if nos: label += f' (item {nos[0]}-{nos[-1]})' if len(nos)>1 else f' (item {nos[0]})'
    total_rows.append(['','', Psm(label), PsmR(fmtN(gst_groups[pct]))])

total_rows.append(['','', PsmB('Grand Total'), PsmRB(fmtN(grand))])

totals_tbl = Table(total_rows, colWidths=[80*mm, 30*mm, 55*mm, 22*mm])
totals_tbl.setStyle(TableStyle([
    ('ALIGN',(2,0),(-1,-1),'RIGHT'),('VALIGN',(0,0),(-1,-1),'MIDDLE'),
    ('TOPPADDING',(0,0),(-1,-1),2),('BOTTOMPADDING',(0,0),(-1,-1),2),
    ('LINEABOVE',(2,-1),(3,-1),0.8,colors.black),
    ('FONTNAME',(2,-1),(3,-1),'Helvetica-Bold'),
]))
story.append(totals_tbl)
story.append(Spacer(1,1*mm))

# Amount in words (simple)
def num_to_words(n):
    try:
        n = int(round(n))
        ones = ['','One','Two','Three','Four','Five','Six','Seven','Eight','Nine',
                'Ten','Eleven','Twelve','Thirteen','Fourteen','Fifteen','Sixteen',
                'Seventeen','Eighteen','Nineteen']
        tens = ['','','Twenty','Thirty','Forty','Fifty','Sixty','Seventy','Eighty','Ninety']
        def below_1000(n):
            if n < 20: return ones[n]
            elif n < 100: return tens[n//10] + (' ' + ones[n%10] if n%10 else '')
            else: return ones[n//100] + ' Hundred' + (' ' + below_1000(n%100) if n%100 else '')
        if n == 0: return 'Zero'
        parts = []
        if n >= 10000000:
            parts.append(below_1000(n//10000000) + ' Crore'); n %= 10000000
        if n >= 100000:
            parts.append(below_1000(n//100000) + ' Lakh'); n %= 100000
        if n >= 1000:
            parts.append(below_1000(n//1000) + ' Thousand'); n %= 1000
        if n > 0: parts.append(below_1000(n))
        return ' '.join(parts) + ' Only.'
    except: return ''

words = num_to_words(grand)
story.append(PB(f'Rupees: {words}'))
story.append(Spacer(1,2*mm))

if narration:
    story.append(Table([[Psm(f'<u>Narration:</u> {narration}')]], colWidths=[187*mm]))
    story.append(Spacer(1,2*mm))

# ── TERMS & CONDITIONS ─────────────────────────────────────────────────────────
tc_list = [
    'All Bills and DCs should contain the Reference of the Concerned PO .',
    'All materials supplied will be subject to inspections & test when received at our site.',
    'Final Bill shall be cleared after Certification by the Concerned Engg & on actual measurements taken at Site.',
    'If any Goods damaged or rejected must be replaced inimediately at the suppliers own expenses.',
    'Payment : 60 Days from the date of supply',
    'Lead Time : Within 2-3 days from the date of order',
    'Bill Requirement: Bill must carry details of Specific Order number, site acceptance signature along with seal, buyer and supplier GST number, HSN Code, Bill number, LUT details, Transporter challan etc.',
    'Quantity Certification: Quantity mentioned in the Order may be approximate, actual & mutually certified measurement will be accounted for the payment.',
    'Price Escalation: Above mentioned in price is absolute frozen for this Order, in case of any price escalation "after" or "before/in-between" will be considered breach of Contract terms & will not be entertained.',
    'Cancellation: Time is of the essence in this order. Buyer reserves the right to cancel this order, or any portion of this order, without liability, if; (1) delivery is not made when and as specified; (b) Seller fails to meet contract commitments as to exact time, price, quality or quantity.',
    'Any dispute or difference shall be referred to two arbitrators. All disputes shall be subject to jurisdiction of courts at Bangalore.',
    'GST TERMS: TDS as applicable under Income Tax Laws and the GST Laws shall be deducted at applicable rates.',
    'NOTE: 3 Copies of Tax invoice (original, duplicate & triplicate) to be submitted along with each consignment supply.',
    'Order to be acknowledged and accepted or to be reverted if any changes within 4 hours. If not it will be considered as accepted.',
]

story.append(PB('Terms &amp; Conditions:'))
tc_rows = [[Psm(str(i+1)), Psm(txt)] for i,txt in enumerate(tc_list)]
tc_tbl = Table(tc_rows, colWidths=[8*mm, 179*mm])
tc_tbl.setStyle(TableStyle([
    ('VALIGN',(0,0),(-1,-1),'TOP'),('ALIGN',(0,0),(0,-1),'RIGHT'),
    ('TOPPADDING',(0,0),(-1,-1),1.5),('BOTTOMPADDING',(0,0),(-1,-1),1.5),
    ('LEFTPADDING',(0,0),(0,-1),0),('RIGHTPADDING',(0,0),(0,-1),3),
]))
story.append(tc_tbl)
story.append(Spacer(1,8*mm))

# ── SIGNATURE ROW ──────────────────────────────────────────────────────────────
sig_data = [[
    Table([[Psm('Checked by')],[Spacer(1,8*mm)],[Psm(po_date)]], colWidths=[55*mm],
          style=[('TOPPADDING',(0,0),(-1,-1),1),('BOTTOMPADDING',(0,0),(-1,-1),1)]),
    Table([[PsmCB('Director')]], colWidths=[77*mm],
          style=[('ALIGN',(0,0),(-1,-1),'CENTER'),('VALIGN',(0,0),(-1,-1),'BOTTOM')]),
    Table([[PsmRB('Managing Director')]], colWidths=[55*mm],
          style=[('ALIGN',(0,0),(-1,-1),'RIGHT'),('TOPPADDING',(0,0),(-1,-1),1)]),
]]
sig_tbl = Table(sig_data, colWidths=[55*mm, 77*mm, 55*mm])
sig_tbl.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'BOTTOM')]))
story.append(sig_tbl)

# ── Build ──────────────────────────────────────────────────────────────────────
doc.build(story, onFirstPage=make_page, onLaterPages=make_page)
print(f'PDF generated: {out_file}')
