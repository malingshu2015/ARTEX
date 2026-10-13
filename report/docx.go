package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
)

// DOCX renders the report as an editable Word document without external tools.
func DOCX(in Input) ([]byte, error) {
	findings := sortedFindings(in.Findings)
	severityCounts := countSeverities(findings)

	var body strings.Builder
	paragraph(&body, "Kicker", "ARTEX  /  SECURITY ASSESSMENT")
	paragraph(&body, "Title", "安全评估报告")
	paragraph(&body, "Subtitle", safeReportText(nz(in.Title, "未命名任务")))
	paragraph(&body, "Small", "授权范围内使用 · CONFIDENTIAL")
	paragraph(&body, "Heading2", "评估目标")
	paragraph(&body, "BodyText", safeReportText(nz(in.Goal, "未指定")))
	paragraph(&body, "Small", "报告生成时间 · "+in.GeneratedAt.Format("2006-01-02 15:04:05"))
	paragraph(&body, "Small", "任务状态 · "+statusLabel(in.TaskStatus))

	paragraphWithProps(&body, "Heading1", "01 执行摘要", ` <w:pageBreakBefore/>`)
	criticalAndHigh := severityCounts["critical"] + severityCounts["high"]
	paragraph(&body, "BodyText", fmt.Sprintf("截至报告生成时间，任务记录中共有 %d 项已确认发现，其中严重及高危 %d 项。统计只包含本任务 finding 记录，不将探索意图或一般事实计为漏洞。任务尚未结束时，本报告为阶段性结果。", len(findings), criticalAndHigh))
	assetTotal := 0
	for _, count := range in.AssetCounts {
		assetTotal += count
	}
	writeSummaryTable(&body, []summaryCell{
		{label: "确认发现", value: fmt.Sprintf("%d", len(findings))},
		{label: "高危及以上", value: fmt.Sprintf("%d", criticalAndHigh), fill: "F8E9DF", color: "A84935"},
		{label: "涉及资产", value: fmt.Sprintf("%d", assetTotal)},
	})
	paragraph(&body, "Small", "发现严重度分布")
	severityCells := []summaryCell{
		{label: "严重", value: fmt.Sprintf("%d", severityCounts["critical"]), fill: "F8E4E0", color: "A63A32"},
		{label: "高危", value: fmt.Sprintf("%d", severityCounts["high"]), fill: "F8E9DF", color: "C26132"},
		{label: "中危", value: fmt.Sprintf("%d", severityCounts["medium"]), fill: "F4EEDC", color: "9B742B"},
		{label: "低危", value: fmt.Sprintf("%d", severityCounts["low"]), fill: "E5F0ED", color: "397A70"},
		{label: "信息", value: fmt.Sprintf("%d", severityCounts["info"]), fill: "EDF0F2", color: "64748B"},
	}
	writeSummaryTable(&body, severityCells)

	paragraph(&body, "Heading1", "02 测试范围与方法")
	paragraph(&body, "BodyText", "任务目标："+safeReportText(nz(in.Goal, "未指定")))
	paragraph(&body, "BodyText", "任务状态："+statusLabel(in.TaskStatus))
	if len(in.Scopes) == 0 {
		paragraph(&body, "BodyText", "显式范围条目：未单独登记；范围以本任务关联资产为准。排除项未在任务记录中说明。")
	} else {
		for _, scope := range in.Scopes {
			value := scope.Value
			switch scope.Kind {
			case "root_domain", "subdomain":
				value = scope.Domain
			case "ip", "cidr":
				value = scope.Net
			case "company":
				value = nz(scope.CompanyName, value)
			}
			paragraph(&body, "BodyText", scopeKindLabel(scope.Kind)+"："+safeReportText(nz(value, "未提供值")))
		}
	}
	if in.StartedAt.IsZero() {
		paragraph(&body, "Small", "开始时间：任务记录未提供")
	} else {
		paragraph(&body, "Small", "开始时间："+in.StartedAt.Format("2006-01-02 15:04:05"))
	}
	if in.CompletedAt.IsZero() {
		paragraph(&body, "Small", "结束时间：尚未记录完成时间")
	} else {
		paragraph(&body, "Small", "结束时间："+in.CompletedAt.Format("2006-01-02 15:04:05"))
	}
	paragraph(&body, "BodyText", "汇总接口未提供完整执行阶段、工具版本或测试限制记录，本报告不对此类内容作推断。")

	paragraph(&body, "Heading1", "03 资产概览")
	assetTypes := make([]string, 0, len(in.AssetCounts))
	for assetType := range in.AssetCounts {
		assetTypes = append(assetTypes, assetType)
	}
	sort.Strings(assetTypes)
	if len(assetTypes) == 0 {
		paragraph(&body, "BodyText", "未统计到资产。")
	} else {
		cells := make([]summaryCell, 0, len(assetTypes))
		for _, assetType := range assetTypes {
			cells = append(cells, summaryCell{
				label: assetTypeLabel(assetType),
				value: fmt.Sprintf("%d", in.AssetCounts[assetType]),
			})
		}
		rows := make([][]summaryCell, 0, (len(cells)+2)/3)
		for len(cells) > 0 {
			end := min(len(cells), 3)
			rows = append(rows, cells[:end])
			cells = cells[end:]
		}
		writeSummaryRows(&body, rows)
	}
	paragraph(&body, "Small", "仅统计本任务关联资产，不含系统内其他任务资产。")

	paragraph(&body, "Heading1", "04 风险分布与优先级")
	paragraph(&body, "BodyText", "严重性采用任务记录等级。当前数据未提供统一的可能性/影响评分，因此不生成风险矩阵或重新定级。")
	writeSummaryTable(&body, severityCells)
	paragraph(&body, "Heading1", "05 攻击链复盘")
	paragraph(&body, "BodyText", "当前报告输入未包含可核验的完整事件时间线和节点关系；本报告不把多个发现拼接成已发生的攻击链。请结合 ARTEX 探索链路核对后再补充。")
	paragraph(&body, "Heading1", "06 已确认发现")
	if len(findings) == 0 {
		paragraph(&body, "BodyText", "本次未确认漏洞。")
	} else {
		for i, finding := range findings {
			name := nz(finding.Name, nz(finding.VulnClass, "未分类"))
			paragraph(&body, "Heading2", fmt.Sprintf("%02d  [%s] %s", i+1, strings.ToUpper(nz(finding.Severity, "INFO")), safeReportText(name)))
			paragraph(&body, "Small", fmt.Sprintf("发现编号 F-%04d · 类别 %s · 严重性 %s", finding.ID, safeReportText(nz(finding.VulnClass, "未分类")), severityLabel(finding.Severity)))
			assets := in.FindingAssets[finding.ID]
			if len(assets) == 0 {
				paragraph(&body, "Small", "受影响资产：发现记录未关联资产")
			} else {
				paragraph(&body, "Small", "受影响资产："+safeReportText(strings.Join(assets, "、")))
			}
			if strings.TrimSpace(finding.Summary) != "" {
				paragraph(&body, "BodyText", "记录摘要："+safeReportText(finding.Summary))
			}
			paragraph(&body, "Small", fmt.Sprintf("证据索引：在 ARTEX 发现详情中按节点编号 %d 查看原始验证记录；本报告不复制原始 PoC 或会话/凭据值。", finding.ID))
			paragraph(&body, "BodyText", "整改建议："+remediationFor(finding))
		}
	}

	paragraph(&body, "Heading1", "07 攻击面与覆盖限制")
	paragraph(&body, "BodyText", "本报告仅反映已登记的确认发现与任务关联资产。未测试资产、未触发问题、被阻断或未完成的测试方向不等同于安全通过；当前汇总数据不足以计算完整覆盖率。")
	paragraph(&body, "Heading1", "08 复测情况")
	paragraph(&body, "BodyText", "当前汇总数据未包含逐项复测结果；所有修复状态均标记为未在本报告数据中验证。修复完成后应按原资产与条件复测，并记录时间、结果及证据。")
	paragraph(&body, "Heading1", "09 整改路线图")
	writeSummaryTable(&body, []summaryCell{
		{label: "紧急处置", value: fmt.Sprintf("严重/高危 %d 项：优先控制影响并修复根因，再完成复测。", criticalAndHigh)},
		{label: "短期整改", value: fmt.Sprintf("中危 %d 项：按业务影响和依赖排序，关联复测证据。", severityCounts["medium"])},
		{label: "持续加固", value: fmt.Sprintf("低危 %d 项：纳入代码、配置与监控改进。", severityCounts["low"])},
	})
	paragraph(&body, "Small", "路线图按严重性分组，不指定未确认的负责人或完成日期。")
	paragraph(&body, "Heading1", "10 附录与口径")
	paragraph(&body, "BodyText", "只统计本任务 finding 节点；fact、intent 与一般资产不计为漏洞。原始请求/响应、命令输出及详细 PoC 保留在 ARTEX 对应发现详情中，通过发现编号定位。导出文本对邮箱及明显的密钥/口令字段进行遮蔽。")

	document := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>` + body.String() +
		`<w:sectPr><w:footerReference w:type="default" r:id="rId2"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1360" w:bottom="1440" w:left="1360" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr></w:body></w:document>`

	files := [][2]string{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/></Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`},
		{"word/_rels/document.xml.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/></Relationships>`},
		{"word/document.xml", document},
		{"word/styles.xml", docxStyles},
		{"word/footer1.xml", docxFooter},
	}

	var output bytes.Buffer
	archive := zip.NewWriter(&output)
	for _, file := range files {
		writer, err := archive.Create(file[0])
		if err != nil {
			return nil, fmt.Errorf("create docx part %s: %w", file[0], err)
		}
		if _, err := writer.Write([]byte(file[1])); err != nil {
			return nil, fmt.Errorf("write docx part %s: %w", file[0], err)
		}
	}
	if err := archive.Close(); err != nil {
		return nil, fmt.Errorf("finish docx archive: %w", err)
	}
	return output.Bytes(), nil
}

type summaryCell struct {
	label string
	value string
	fill  string
	color string
}

func writeSummaryTable(out *strings.Builder, cells []summaryCell) {
	if len(cells) == 0 {
		return
	}
	writeSummaryRows(out, [][]summaryCell{cells})
}

func writeSummaryRows(out *strings.Builder, rows [][]summaryCell) {
	columns := 0
	for _, row := range rows {
		columns = max(columns, len(row))
	}
	if columns == 0 {
		return
	}
	const tableWidth = 9180
	columnWidth := tableWidth / columns
	out.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="9180" w:type="dxa"/><w:tblLayout w:type="fixed"/><w:tblBorders>` +
		`<w:top w:val="single" w:sz="4" w:color="E5E1D8"/><w:left w:val="single" w:sz="4" w:color="E5E1D8"/>` +
		`<w:bottom w:val="single" w:sz="4" w:color="E5E1D8"/><w:right w:val="single" w:sz="4" w:color="E5E1D8"/>` +
		`<w:insideH w:val="single" w:sz="4" w:color="E5E1D8"/><w:insideV w:val="single" w:sz="4" w:color="E5E1D8"/>` +
		`</w:tblBorders><w:tblCellMar><w:top w:w="140" w:type="dxa"/><w:left w:w="120" w:type="dxa"/><w:bottom w:w="140" w:type="dxa"/><w:right w:w="120" w:type="dxa"/></w:tblCellMar></w:tblPr><w:tblGrid>`)
	for range columns {
		fmt.Fprintf(out, `<w:gridCol w:w="%d"/>`, columnWidth)
	}
	out.WriteString(`</w:tblGrid>`)
	for _, row := range rows {
		out.WriteString(`<w:tr><w:trPr><w:cantSplit/></w:trPr>`)
		for i := range columns {
			var cell summaryCell
			if i < len(row) {
				cell = row[i]
			}
			if cell.fill == "" {
				cell.fill = "FCFBF8"
			}
			if cell.color == "" {
				cell.color = "24373D"
			}
			fmt.Fprintf(out, `<w:tc><w:tcPr><w:tcW w:w="%d" w:type="dxa"/><w:shd w:fill="%s"/><w:vAlign w:val="center"/></w:tcPr>`, columnWidth, cell.fill)
			writeTableCellParagraph(out, cell.label, "64748B", "18", false)
			writeTableCellParagraph(out, cell.value, cell.color, "30", true)
			out.WriteString(`</w:tc>`)
		}
		out.WriteString(`</w:tr>`)
	}
	out.WriteString(`</w:tbl>`)
}

func writeTableCellParagraph(out *strings.Builder, text, color, size string, bold bool) {
	out.WriteString(`<w:p><w:pPr><w:jc w:val="center"/><w:spacing w:before="0" w:after="20"/></w:pPr><w:r><w:rPr>`)
	if bold {
		out.WriteString(`<w:b/>`)
	}
	out.WriteString(`<w:color w:val="` + color + `"/><w:sz w:val="` + size + `"/></w:rPr><w:t xml:space="preserve">`)
	_ = xml.EscapeText(out, []byte(xmlSafeText(text)))
	out.WriteString(`</w:t></w:r></w:p>`)
}

func paragraph(out *strings.Builder, style, text string) {
	paragraphWithProps(out, style, text, "")
}

func paragraphWithProps(out *strings.Builder, style, text, extra string) {
	out.WriteString(`<w:p><w:pPr><w:pStyle w:val="`)
	out.WriteString(style)
	out.WriteString(`"/>`)
	out.WriteString(extra)
	out.WriteString(`</w:pPr><w:r><w:t xml:space="preserve">`)
	_ = xml.EscapeText(out, []byte(xmlSafeText(text)))
	out.WriteString(`</w:t></w:r></w:p>`)
}

func xmlSafeText(text string) string {
	var safe strings.Builder
	for _, r := range text {
		if r == '\t' || r == '\n' || r == '\r' ||
			(r >= 0x20 && r <= 0xD7FF) || (r >= 0xE000 && r <= 0xFFFD) ||
			(r >= 0x10000 && r <= 0x10FFFF) {
			safe.WriteRune(r)
		}
	}
	return safe.String()
}

const docxStyles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
 <w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Aptos" w:hAnsi="Aptos" w:eastAsia="Microsoft YaHei"/><w:color w:val="24364B"/><w:sz w:val="22"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="160" w:line="360" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
 <w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
 <w:style w:type="paragraph" w:styleId="Kicker"><w:name w:val="Kicker"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="1800" w:after="320"/></w:pPr><w:rPr><w:color w:val="008A9B"/><w:b/><w:sz w:val="20"/><w:caps/></w:rPr></w:style>
 <w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="240" w:after="260"/></w:pPr><w:rPr><w:color w:val="12304A"/><w:b/><w:sz w:val="68"/></w:rPr></w:style>
 <w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="500"/></w:pPr><w:rPr><w:color w:val="008A9B"/><w:sz w:val="32"/></w:rPr></w:style>
 <w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="360" w:after="180"/><w:pBdr><w:bottom w:val="single" w:sz="8" w:space="6" w:color="008A9B"/></w:pBdr></w:pPr><w:rPr><w:color w:val="12304A"/><w:b/><w:sz w:val="34"/></w:rPr></w:style>
 <w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="260" w:after="100"/></w:pPr><w:rPr><w:color w:val="12304A"/><w:b/><w:sz w:val="26"/></w:rPr></w:style>
 <w:style w:type="paragraph" w:styleId="BodyText"><w:name w:val="Body Text"/><w:basedOn w:val="Normal"/></w:style>
 <w:style w:type="paragraph" w:styleId="Small"><w:name w:val="Small"/><w:basedOn w:val="Normal"/><w:rPr><w:color w:val="64748B"/><w:sz w:val="18"/></w:rPr></w:style>
 <w:style w:type="paragraph" w:styleId="Bullet"><w:name w:val="Bullet"/><w:basedOn w:val="Normal"/><w:pPr><w:ind w:left="360"/></w:pPr></w:style>
 <w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/><w:basedOn w:val="Normal"/><w:pPr><w:ind w:left="240"/><w:spacing w:after="30"/><w:shd w:fill="F1F5F9"/></w:pPr><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:eastAsia="Microsoft YaHei"/><w:color w:val="334155"/><w:sz w:val="18"/></w:rPr></w:style>
</w:styles>`

const docxFooter = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:jc w:val="center"/><w:pBdr><w:top w:val="single" w:sz="4" w:space="6" w:color="CBD5E1"/></w:pBdr></w:pPr><w:r><w:rPr><w:color w:val="64748B"/><w:sz w:val="18"/></w:rPr><w:t>ARTEX · 安全评估报告　　</w:t></w:r><w:fldSimple w:instr="PAGE"><w:r><w:t>1</w:t></w:r></w:fldSimple></w:p></w:ftr>`
