package report

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestDOCXContainsEditableReportSections(t *testing.T) {
	finding := &db.Node{Payload: json.RawMessage(`{"name":"跨站脚本","severity":"high","summary":"输入未经过滤。","evidence":{"poc":"<script>alert(1)</script>"}}`)}
	content, err := DOCX(Input{
		Title:       "示例任务",
		Goal:        "验证授权范围内的 Web 安全\x01",
		GeneratedAt: time.Date(2026, 10, 11, 12, 30, 0, 0, time.UTC),
		AssetCounts: map[string]int{"app": 2, "ip": 1},
		Findings:    []*db.Node{finding},
	})
	if err != nil {
		t.Fatalf("DOCX() error = %v", err)
	}

	archive, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("DOCX output is not a ZIP package: %v", err)
	}
	parts := make(map[string]string)
	for _, file := range archive.File {
		if file.Name != "word/document.xml" && file.Name != "word/styles.xml" {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			t.Fatalf("open %s: %v", file.Name, err)
		}
		data, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil {
			t.Fatalf("read %s: %v", file.Name, err)
		}
		parts[file.Name] = string(data)
	}

	for _, want := range []string{"安全评估报告", "示例任务", "执行摘要", "测试范围与方法", "资产概览", "风险分布与优先级", "攻击链复盘", "已确认发现", "复测情况", "整改路线图", "附录与口径", "IP 地址", "跨站脚本", "输入未经过滤。"} {
		if !strings.Contains(parts["word/document.xml"], want) {
			t.Errorf("document.xml does not contain %q", want)
		}
	}
	if strings.Contains(parts["word/document.xml"], "&lt;script&gt;") {
		t.Error("document.xml should reference the evidence record instead of embedding a raw PoC")
	}
	if got := strings.Count(parts["word/document.xml"], `<w:tbl>`); got < 3 {
		t.Errorf("document.xml has %d summary tables, want at least 3", got)
	}
	for _, want := range []string{"确认发现", "高危及以上", "严重", "中危", "应用"} {
		if !strings.Contains(parts["word/document.xml"], want) {
			t.Errorf("document.xml summary does not contain %q", want)
		}
	}
	if !strings.Contains(parts["word/styles.xml"], `styleId="Heading1"`) {
		t.Error("styles.xml does not define the report heading style")
	}
	if strings.ContainsRune(parts["word/document.xml"], '\x01') {
		t.Error("document.xml contains a character that is invalid in XML 1.0")
	}
}
