package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestMarkdownUsesConsultingStructureAndRedactsSensitiveText(t *testing.T) {
	finding := &db.Node{
		ID:      42,
		Payload: json.RawMessage(`{"name":"未授权跨站脚本","vulnclass":"xss","severity":"high","summary":"password=EXAMPLE_PASSWORD; security-test@example.invalid 可触发" ,"evidence":{"poc":"cookie=EXAMPLE_SESSION"}}`),
	}
	markdown := Markdown(Input{
		Title:       "示例任务",
		Goal:        "评估授权 Web 资产",
		GeneratedAt: time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC),
		TaskStatus:  "running",
		AssetCounts: map[string]int{"root_domain": 1, "endpoint": 4},
		Scopes:      []db.TaskScope{{Kind: "root_domain", Domain: "example.org"}},
		Findings:    []*db.Node{finding},
		FindingAssets: map[int64][]string{
			42: {"https://example.org"},
		},
	})

	for _, want := range []string{
		"## 01 执行摘要", "## 02 测试范围与方法", "## 03 资产概览", "## 04 风险分布与优先级",
		"## 05 攻击链复盘", "## 06 已确认发现", "## 08 复测情况", "## 09 整改路线图",
		"F-0042", "example.org", "已脱敏", "[邮箱已脱敏]",
	} {
		if !strings.Contains(markdown, want) {
			t.Errorf("Markdown report does not contain %q", want)
		}
	}
	for _, unwanted := range []string{"EXAMPLE_PASSWORD", "security-test@example.invalid", "cookie=EXAMPLE_SESSION", "## 5×5 风险矩阵"} {
		if strings.Contains(markdown, unwanted) {
			t.Errorf("Markdown report unexpectedly contains %q", unwanted)
		}
	}
}
