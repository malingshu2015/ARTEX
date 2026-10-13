// Package report renders a consulting-style report from confirmed findings,
// task-scoped assets, and the task's declared scope.
package report

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Input contains only data that can be traced to ARTEX records. Missing scope,
// methodology, evidence, and retest data are reported as missing rather than
// inferred from worker intents.
type Input struct {
	Title         string
	Goal          string
	GeneratedAt   time.Time
	TaskStatus    string
	StartedAt     time.Time
	CompletedAt   time.Time
	AssetCounts   map[string]int
	Scopes        []db.TaskScope
	Findings      []*db.Node
	FindingAssets map[int64][]string
}

type findingView struct {
	ID        int64
	VulnClass string
	Name      string
	Severity  string
	Summary   string
}

func parseFinding(n *db.Node) findingView {
	var p struct {
		VulnClass string `json:"vulnclass"`
		Name      string `json:"name"`
		Severity  string `json:"severity"`
		Summary   string `json:"summary"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return findingView{ID: n.ID, VulnClass: p.VulnClass, Name: p.Name, Severity: strings.ToLower(strings.TrimSpace(p.Severity)), Summary: p.Summary}
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}

var (
	secretAssignment = regexp.MustCompile(`(?i)(\b(?:password|passwd|token|api[_-]?key|authorization|cookie|secret|private[_-]?key)\b\s*[:=]\s*)([^\s,;]+)`)
	emailAddress     = regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)
)

// Markdown returns the consulting-style report. Raw PoC bodies are intentionally
// kept in the finding detail record and referenced here by finding ID; report
// exports must not copy reusable credentials, session values, or callback payloads.
func Markdown(in Input) string {
	findings := sortedFindings(in.Findings)
	severityCounts := countSeverities(findings)
	assetTotal := 0
	for _, count := range in.AssetCounts {
		assetTotal += count
	}
	criticalAndHigh := severityCounts["critical"] + severityCounts["high"]
	status := nz(in.TaskStatus, "未知")
	generatedAt := in.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now()
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# 渗透测试报告 — %s\n\n", nz(in.Title, "未命名任务"))
	fmt.Fprintf(&b, "- **任务目标**：%s\n", nz(in.Goal, "未指定"))
	fmt.Fprintf(&b, "- **生成时间**：%s\n", generatedAt.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "- **任务状态**：%s\n", statusLabel(status))
	fmt.Fprintf(&b, "- **确认发现**：**%d** 个\n", len(findings))
	fmt.Fprintf(&b, "- **高危及以上**：%d 个\n", criticalAndHigh)
	b.WriteString("- **资产**：")
	writeAssetCounts(&b, in.AssetCounts)
	b.WriteString("\n\n")

	b.WriteString("## 01 执行摘要\n\n")
	if len(findings) == 0 {
		b.WriteString("截至本报告生成时间，任务记录中没有已确认的安全发现。该结论仅代表当前已登记结果，不表示所有资产均不存在风险。\n\n")
	} else {
		fmt.Fprintf(&b, "截至 %s，任务记录中共有 **%d 项已确认发现**，其中严重/高危 **%d 项**。统计仅包含 ARTEX 中登记为漏洞的 finding，不将探索意图、一般事实或待验证猜测计入漏洞数量。\n\n",
			generatedAt.Format("2006-01-02 15:04"), len(findings), criticalAndHigh)
		b.WriteString("管理层应优先安排严重及高危问题的风险控制与修复；其余问题按影响范围和复测结果纳入后续整改。任务尚未结束时，本报告为阶段性结果。\n\n")
	}
	fmt.Fprintf(&b, "| 指标 | 数量 | 说明 |\n|---|---:|---|\n| 已确认发现 | %d | 来自本任务 finding 记录 |\n| 严重 | %d | 按记录中的严重性统计 |\n| 高危 | %d | 按记录中的严重性统计 |\n| 中危 | %d | 按记录中的严重性统计 |\n| 低危 | %d | 按记录中的严重性统计 |\n| 任务关联资产 | %d | 仅统计本任务关联的资产，按类别汇总 |\n\n",
		len(findings), severityCounts["critical"], severityCounts["high"], severityCounts["medium"], severityCounts["low"], assetTotal)

	b.WriteString("## 02 测试范围与方法\n\n")
	fmt.Fprintf(&b, "- **任务目标**：%s\n", nz(in.Goal, "未指定"))
	fmt.Fprintf(&b, "- **任务关联资产**：%d 项（见资产类别统计）\n", assetTotal)
	fmt.Fprintf(&b, "- **执行状态**：%s\n", statusLabel(status))
	if !in.StartedAt.IsZero() {
		fmt.Fprintf(&b, "- **开始时间**：%s\n", in.StartedAt.Format("2006-01-02 15:04:05"))
	} else {
		b.WriteString("- **开始时间**：任务记录未提供\n")
	}
	if !in.CompletedAt.IsZero() {
		fmt.Fprintf(&b, "- **结束时间**：%s\n", in.CompletedAt.Format("2006-01-02 15:04:05"))
	} else {
		b.WriteString("- **结束时间**：尚未记录完成时间\n")
	}
	b.WriteString("- **测试范围声明**：以下范围来自任务显式范围记录；未登记的排除项保持未说明。\n")
	writeScopes(&b, in.Scopes)
	b.WriteString("\n本报告按已确认漏洞记录和任务关联资产汇总。当前汇总接口不提供完整的执行阶段清单、工具版本或测试限制记录，因此不将其推断为已执行的方法或覆盖范围。\n\n")

	b.WriteString("## 03 资产概览\n\n")
	if len(in.AssetCounts) == 0 {
		b.WriteString("任务未关联可用于统计的资产。\n\n")
	} else {
		b.WriteString("| 资产类别 | 数量 |\n|---|---:|\n")
		for _, assetType := range sortedKeys(in.AssetCounts) {
			fmt.Fprintf(&b, "| %s | %d |\n", assetTypeLabel(assetType), in.AssetCounts[assetType])
		}
		b.WriteString("\n")
	}
	b.WriteString("资产数按本任务的资产关联关系统计，不使用系统内其他任务的全局资产数量。\n\n")

	b.WriteString("## 04 风险分布与优先级\n\n")
	b.WriteString("严重性分布如下。任务记录未提供统一的可能性/影响分值，故不绘制风险矩阵，也不对记录的等级重新打分。\n\n")
	b.WriteString("| 严重性 | 数量 | 建议优先级 |\n|---|---:|---|\n")
	for _, row := range []struct{ severity, priority string }{
		{"critical", "立即制定控制与修复计划"}, {"high", "优先修复并安排复测"}, {"medium", "纳入短期整改"}, {"low", "纳入持续加固"},
	} {
		fmt.Fprintf(&b, "| %s | %d | %s |\n", severityLabel(row.severity), severityCounts[row.severity], row.priority)
	}
	b.WriteString("\n")

	b.WriteString("## 05 攻击链复盘\n\n")
	b.WriteString("当前报告输入包含漏洞摘要与资产关联，但未包含可在本报告中核验的完整事件时间线及节点关系。本版不把多个发现拼接成已发生的攻击链；请在 ARTEX 探索链路中核对原始关联后再补充。\n\n")

	b.WriteString("## 06 已确认发现\n\n")
	if len(findings) == 0 {
		b.WriteString("当前没有已确认漏洞记录。\n\n")
	} else {
		for i, finding := range findings {
			name := nz(finding.Name, nz(finding.VulnClass, "未分类"))
			fmt.Fprintf(&b, "### %d. [%s] %s\n\n", i+1, strings.ToUpper(nz(finding.Severity, "info")), safeReportText(name))
			fmt.Fprintf(&b, "- **发现编号**：F-%04d\n", finding.ID)
			fmt.Fprintf(&b, "- **漏洞类别**：%s\n", safeReportText(nz(finding.VulnClass, "未分类")))
			fmt.Fprintf(&b, "- **严重性**：%s（采用任务记录等级，未重新评分）\n", severityLabel(finding.Severity))
			assets := in.FindingAssets[finding.ID]
			if len(assets) == 0 {
				b.WriteString("- **受影响资产**：发现记录未关联资产\n")
			} else {
				fmt.Fprintf(&b, "- **受影响资产**：%s\n", safeReportText(strings.Join(assets, "、")))
			}
			fmt.Fprintf(&b, "- **记录摘要**：%s\n", safeReportText(nz(finding.Summary, "发现记录未提供摘要")))
			fmt.Fprintf(&b, "- **证据索引**：在 ARTEX 发现详情中按节点编号 %d 查看原始验证记录；本报告不复制原始 PoC 或会话/凭据值。\n", finding.ID)
			fmt.Fprintf(&b, "- **整改建议**：%s\n\n", remediationFor(finding))
		}
	}

	b.WriteString("## 07 攻击面与覆盖限制\n\n")
	b.WriteString("本报告只反映已登记的确认发现和任务关联资产。未测试资产、未触发问题、被阻断或未完成的测试方向不等同于安全通过；本报告生成接口未读取完整执行日志，无法据此计算覆盖率或形成未发现问题的保证。\n\n")

	b.WriteString("## 08 复测情况\n\n")
	b.WriteString("当前汇总数据未包含与本次发现逐项对应的复测结果。所有修复状态均标记为“未在本报告数据中验证”；修复完成后应使用相同资产与条件复测，并记录结果、时间及证据。\n\n")

	b.WriteString("## 09 整改路线图\n\n")
	b.WriteString("| 阶段 | 处理对象 | 建议动作 | 验收条件 |\n|---|---|---|---|\n")
	fmt.Fprintf(&b, "| 紧急处置 | 严重、高危共 %d 项 | 由系统负责人确认影响面，优先实施临时控制并修复根因 | 对应发现复测通过，相关访问控制与业务流程回归正常 |\n", criticalAndHigh)
	fmt.Fprintf(&b, "| 短期整改 | 中危共 %d 项 | 按业务影响与修复依赖排序，逐项整改 | 复测记录与证据已关联到发现 |\n", severityCounts["medium"])
	fmt.Fprintf(&b, "| 持续加固 | 低危共 %d 项 | 结合发布周期完成配置、代码和监控改进 | 完成回归检查并记录遗留风险 |\n\n", severityCounts["low"])
	b.WriteString("本路线图按严重性分组，不指定未确认的负责人或完成日期。\n\n")

	b.WriteString("## 10 附录与口径\n\n")
	b.WriteString("- **统计口径**：只统计本任务当前列出的 finding 节点；不把 fact、intent 或一般资产当作漏洞。\n")
	b.WriteString("- **证据查阅**：原始请求/响应、命令输出及详细 PoC 保留在 ARTEX 对应发现记录中，通过发现编号定位。\n")
	b.WriteString("- **隐私处理**：导出文本会对邮箱与明显的密钥/口令字段做遮蔽，不复制原始会话值或可复用令牌。\n")
	b.WriteString("- **状态说明**：任务仍在运行时，本报告为生成时点的阶段性快照；重新打开报告会按最新已登记数据重新生成。\n")
	return b.String()
}

func sortedFindings(nodes []*db.Node) []findingView {
	findings := make([]findingView, 0, len(nodes))
	for _, node := range nodes {
		if node != nil {
			findings = append(findings, parseFinding(node))
		}
	}
	sort.SliceStable(findings, func(i, j int) bool { return sevRank[findings[i].Severity] < sevRank[findings[j].Severity] })
	return findings
}

func countSeverities(findings []findingView) map[string]int {
	counts := map[string]int{}
	for _, finding := range findings {
		severity := finding.Severity
		if _, ok := sevRank[severity]; !ok {
			severity = "info"
		}
		counts[severity]++
	}
	return counts
}

func writeAssetCounts(b *strings.Builder, counts map[string]int) {
	keys := sortedKeys(counts)
	if len(keys) == 0 {
		b.WriteString("暂无统计")
		return
	}
	for i, key := range keys {
		if i > 0 {
			b.WriteString("、")
		}
		fmt.Fprintf(b, "%s %d", key, counts[key])
	}
}

func writeScopes(b *strings.Builder, scopes []db.TaskScope) {
	if len(scopes) == 0 {
		b.WriteString("- **显式范围条目**：未单独登记；范围以本任务关联资产为准。\n")
		return
	}
	b.WriteString("- **显式范围条目**：\n")
	for _, scope := range scopes {
		value := scope.Value
		switch scope.Kind {
		case "root_domain", "subdomain":
			value = scope.Domain
		case "ip", "cidr":
			value = scope.Net
		case "company":
			value = nz(scope.CompanyName, value)
		}
		fmt.Fprintf(b, "  - %s：%s", scopeKindLabel(scope.Kind), safeReportText(nz(value, "未提供值")))
		if scope.Reason != "" {
			fmt.Fprintf(b, "（%s）", safeReportText(scope.Reason))
		}
		b.WriteByte('\n')
	}
}

func remediationFor(f findingView) string {
	text := strings.ToLower(f.VulnClass + " " + f.Name + " " + f.Summary)
	switch {
	case strings.Contains(text, "xss"), strings.Contains(text, "跨站脚本"):
		return "对输出按 HTML/JavaScript/URL 上下文进行编码，避免不安全的 HTML 拼接；限制上传内容的同源执行能力，并通过内容安全策略降低脚本执行影响。"
	case strings.Contains(text, "idor"), strings.Contains(text, "未授权"), strings.Contains(text, "越权"), strings.Contains(text, "访问控制"):
		return "在服务端对每个对象和操作执行身份、角色及资源归属校验，采用默认拒绝策略；为匿名、跨用户和边界 ID 编写授权回归测试。"
	case strings.Contains(text, "session fixation"), strings.Contains(text, "会话固定"), strings.Contains(text, "sessid"):
		return "认证成功及权限变化时重新生成会话标识；为会话 Cookie 设置 HttpOnly、Secure、SameSite，并提供会话失效机制。"
	case strings.Contains(text, "information disclosure"), strings.Contains(text, "信息泄露"), strings.Contains(text, "堆栈"), strings.Contains(text, "错误信息"):
		return "生产环境关闭详细错误回显和堆栈输出，向客户端返回统一错误编号；将完整异常写入受控服务端日志并限制访问。"
	case strings.Contains(text, "upload"), strings.Contains(text, "上传"):
		return "上传接口增加授权与业务校验，使用扩展名、MIME 和文件特征联合验证；文件存放于不可执行位置或独立域，并限制 SVG 等活动内容。"
	case strings.Contains(text, "sql"), strings.Contains(text, "注入"), strings.Contains(text, "injection"):
		return "使用参数化查询并避免拼接用户输入；在服务端校验数据类型和边界，配置数据库最小权限，并对关键查询增加回归测试。"
	case strings.Contains(text, "captcha"), strings.Contains(text, "验证码"), strings.Contains(text, "爆破"), strings.Contains(text, "暴力"):
		return "验证码或一次性验证码由服务端生成、校验并限制尝试次数；增加速率限制、失败退避和异常告警，避免由客户端控制安全校验强度。"
	default:
		return "该发现记录未包含足够的根因与修复细节；请在 ARTEX 发现详情中结合原始证据补充具体整改方案与验收标准。"
	}
}

func safeReportText(text string) string {
	text = secretAssignment.ReplaceAllString(text, "$1[已脱敏]")
	text = emailAddress.ReplaceAllString(text, "[邮箱已脱敏]")
	return strings.TrimSpace(text)
}

func scopeKindLabel(kind string) string {
	labels := map[string]string{"company": "企业", "root_domain": "根域名", "subdomain": "子域名", "ip": "IP", "cidr": "网段", "icp": "备案号", "keyword": "关键词"}
	return nz(labels[kind], kind)
}

func assetTypeLabel(assetType string) string {
	labels := map[string]string{"root_domain": "根域名", "subdomain": "子域名", "ip": "IP 地址", "app": "应用", "service": "服务", "endpoint": "接口"}
	return nz(labels[assetType], assetType)
}

func severityLabel(severity string) string {
	labels := map[string]string{"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}
	return nz(labels[strings.ToLower(strings.TrimSpace(severity))], "未分级")
}

func statusLabel(status string) string {
	labels := map[string]string{"running": "运行中（阶段性报告）", "paused": "已暂停（阶段性报告）", "queued": "排队中", "created": "未开始", "done": "已完成", "failed": "失败", "timeout": "超时"}
	return nz(labels[status], status)
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func nz(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
