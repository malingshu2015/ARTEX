"use client";

import * as React from "react";

import { CheckIcon, CopyIcon, DownloadIcon, FileTextIcon, PrinterIcon } from "lucide-react";
import { createPortal } from "react-dom";
import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { copyText } from "@/lib/utils";

const reportMarkdownComponents: Components = {
  h1: ({ node: _node, ...props }) => (
    <h1 className="mt-9 mb-5 font-semibold text-2xl text-slate-900 tracking-tight" {...props} />
  ),
  h2: ({ node: _node, ...props }) => (
    <h2
      className="mt-10 mb-3 border-slate-200 border-b pb-2 font-semibold text-[#12304a] text-xl tracking-tight"
      {...props}
    />
  ),
  h3: ({ node: _node, ...props }) => <h3 className="mt-7 mb-2 font-semibold text-[#12304a] text-base" {...props} />,
  h4: ({ node: _node, ...props }) => <h4 className="mt-5 mb-2 font-semibold text-slate-800 text-sm" {...props} />,
  p: ({ node: _node, ...props }) => <p className="my-3 text-slate-700 leading-7" {...props} />,
  ul: ({ node: _node, ...props }) => (
    <ul className="my-3 list-disc space-y-1 pl-6 text-slate-700 leading-7" {...props} />
  ),
  ol: ({ node: _node, ...props }) => (
    <ol className="my-3 list-decimal space-y-1 pl-6 text-slate-700 leading-7" {...props} />
  ),
  li: ({ node: _node, ...props }) => <li className="pl-1" {...props} />,
  strong: ({ node: _node, ...props }) => <strong className="font-semibold text-slate-900" {...props} />,
  a: ({ node: _node, ...props }) => (
    <a className="text-[#087f8c] underline underline-offset-2" target="_blank" rel="noreferrer" {...props} />
  ),
  hr: () => <hr className="my-7 border-slate-200" />,
  blockquote: ({ node: _node, ...props }) => (
    <blockquote className="my-4 border-[#008a9b] border-l-4 bg-slate-50 px-4 py-2 text-slate-600" {...props} />
  ),
  pre: ({ node: _node, ...props }) => (
    <pre
      className="my-4 overflow-auto rounded-md border border-slate-200 bg-slate-50 p-4 text-slate-800 text-xs leading-6"
      {...props}
    />
  ),
  code: ({ node: _node, className, children, ...props }) => {
    const block = /language-/.test(className || "");
    return block ? (
      <code className={`font-mono ${className || ""}`} {...props}>
        {children}
      </code>
    ) : (
      <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-[0.9em] text-slate-800" {...props}>
        {children}
      </code>
    );
  },
  table: ({ node: _node, ...props }) => (
    <div className="my-5 overflow-x-auto">
      <table className="w-full border-collapse text-sm" {...props} />
    </div>
  ),
  th: ({ node: _node, ...props }) => (
    <th className="border border-slate-200 bg-slate-50 px-3 py-2 text-left font-semibold text-slate-800" {...props} />
  ),
  td: ({ node: _node, ...props }) => (
    <td className="border border-slate-200 px-3 py-2 align-top text-slate-700" {...props} />
  ),
};

type SeverityCount = { key: string; label: string; count: number; color: string; tint: string };
type AssetCount = { key: string; label: string; count: number };

const severityPalette = [
  { key: "critical", label: "严重", color: "#a63a32", tint: "#f8e4e0" },
  { key: "high", label: "高危", color: "#c26132", tint: "#f8e9df" },
  { key: "medium", label: "中危", color: "#b58a35", tint: "#f4eedc" },
  { key: "low", label: "低危", color: "#397a70", tint: "#e5f0ed" },
  { key: "info", label: "信息", color: "#71808a", tint: "#edf0f2" },
];

const assetLabels: Record<string, string> = {
  app: "应用",
  endpoint: "接口",
  ip: "IP 地址",
  root_domain: "根域名",
  service: "服务",
  subdomain: "子域名",
};

function parseSeverityCounts(severities: string[]): SeverityCount[] {
  const counts = new Map(severityPalette.map((item) => [item.key, 0]));
  for (const severity of severities) {
    const key = severityPalette.some((item) => item.key === severity) ? severity : "info";
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return severityPalette.map((item) => ({ ...item, count: counts.get(item.key) || 0 }));
}

function parseAssetCounts(report: string): AssetCount[] {
  const line = report.match(/^-\s+(?:\*\*)?资产(?:\*\*)?：([^\n]*)/m)?.[1] || "";
  return Array.from(line.matchAll(/([a-z_]+)\s+(\d+)/g), ([, key, count]) => ({
    key,
    label: assetLabels[key] || key,
    count: Number(count),
  })).sort((a, b) => b.count - a.count);
}

function withoutSummarySection(markdown: string): string {
  let skipping = false;
  return markdown
    .split("\n")
    .filter((line) => {
      if (/^##[ \t]+摘要[ \t]*$/.test(line)) {
        skipping = true;
        return false;
      }
      if (skipping && /^##[ \t]+/.test(line)) skipping = false;
      return !skipping;
    })
    .join("\n")
    .trim();
}

function ReportPaper({
  report,
  title,
  goal,
  generatedAt,
  findings,
  criticalAndHigh,
  assetCount,
  severityCounts,
  assetCounts,
}: {
  report: string;
  title: string;
  goal: string;
  generatedAt: string;
  findings: number;
  criticalAndHigh: number;
  assetCount: number;
  severityCounts: SeverityCount[];
  assetCounts: AssetCount[];
}) {
  const body = report
    .replace(/^#\s+.*(?:\r?\n|$)/m, "")
    .replace(/^-\s+\*\*任务目标\*\*：.*(?:\r?\n|$)/m, "")
    .replace(/^-\s+\*\*生成时间\*\*：.*(?:\r?\n|$)/m, "")
    .trim();
  const reportBody = withoutSummarySection(body);

  return (
    <article
      data-print-paper
      className="report-paper mx-auto min-h-[1120px] w-full max-w-[920px] overflow-hidden rounded-md border border-[#e5e1d8] bg-white shadow-sm"
    >
      <header className="report-cover relative overflow-hidden bg-[#1c3038] px-8 py-10 text-white sm:px-14 sm:py-14">
        <div className="absolute -top-28 -right-20 size-[360px] rounded-full border border-white/10" />
        <div className="absolute top-[-4.5rem] -right-2 size-[245px] rounded-full border border-white/10" />
        <div className="absolute right-0 bottom-0 h-1.5 w-2/5 bg-[#bd6849]" />
        <div className="relative">
          <div className="flex items-center justify-between border-white/20 border-b pb-5">
            <p className="flex items-center gap-2 font-semibold text-sm tracking-[0.16em]">
              <span className="size-2 rounded-full bg-[#d68b61]" /> ARTEX
            </p>
            <p className="text-[10px] text-white/65 tracking-[0.2em]">SECURITY REVIEW · CONFIDENTIAL</p>
          </div>
          <div className="mt-14 max-w-3xl sm:mt-20">
            <p className="font-semibold text-[#e4ae8b] text-xs tracking-[0.22em]">独立安全评估</p>
            <h1 className="mt-5 font-serif font-medium text-4xl tracking-tight sm:text-5xl">安全评估报告</h1>
            <p className="mt-5 max-w-2xl break-words text-[#e4e8e5] text-lg leading-8">{title}</p>
          </div>
          <div className="mt-14 grid gap-6 border-white/20 border-t pt-6 text-sm sm:mt-20 sm:grid-cols-[1.4fr_1fr_0.8fr]">
            <div>
              <p className="font-medium text-[#e4ae8b] text-[10px] tracking-[0.15em]">评估目标</p>
              <p className="mt-2 text-white/90 leading-6">{goal || "未指定"}</p>
            </div>
            <div>
              <p className="font-medium text-[#e4ae8b] text-[10px] tracking-[0.15em]">报告日期</p>
              <p className="mt-2 text-white/90 leading-6">{generatedAt || "—"}</p>
            </div>
            <div>
              <p className="font-medium text-[#e4ae8b] text-[10px] tracking-[0.15em]">使用范围</p>
              <p className="mt-2 text-white/90 leading-6">授权范围内</p>
            </div>
          </div>
        </div>
      </header>

      <main className="report-body px-6 py-8 sm:px-14 sm:py-12">
        <ReportOverview
          findings={findings}
          criticalAndHigh={criticalAndHigh}
          assetCount={assetCount}
          severityCounts={severityCounts}
          assetCounts={assetCounts}
        />
        <div className="mb-8 flex items-center justify-between border-[#e5e1d8] border-b pb-4 pt-2">
          <div>
            <p className="font-semibold text-[#bd6849] text-[10px] tracking-[0.2em]">REPORT BODY</p>
            <p className="mt-1 font-serif text-[#1c3038] text-xl">报告正文</p>
          </div>
          <span className="text-[10px] text-slate-400 tracking-[0.12em]">ARTEX · SECURITY REVIEW</span>
        </div>
        <div className="report-markdown">
          <ReactMarkdown remarkPlugins={[remarkGfm]} components={reportMarkdownComponents}>
            {reportBody}
          </ReactMarkdown>
        </div>
      </main>

      <footer className="report-footer mx-8 flex items-center justify-between border-[#e5e1d8] border-t py-5 text-[10px] text-slate-500 sm:mx-14">
        <span>ARTEX · 独立安全评估</span>
        <span>依据本任务记录的发现与证据生成</span>
      </footer>
    </article>
  );
}

function ReportOverview({
  findings,
  criticalAndHigh,
  assetCount,
  severityCounts,
  assetCounts,
}: {
  findings: number;
  criticalAndHigh: number;
  assetCount: number;
  severityCounts: SeverityCount[];
  assetCounts: AssetCount[];
}) {
  const highShare = findings > 0 ? Math.round((criticalAndHigh / findings) * 100) : 0;
  const chartRows = assetCounts.slice(0, 6);
  const maxAssetCount = Math.max(1, ...chartRows.map((item) => item.count));

  return (
    <section className="report-overview mb-12">
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3 border-[#e5e1d8] border-b pb-4">
        <div>
          <p className="font-semibold text-[#bd6849] text-[10px] tracking-[0.2em]">01 / EXECUTIVE SUMMARY</p>
          <h2 className="mt-1 font-serif text-[#1c3038] text-2xl">风险概览</h2>
        </div>
        <p className="text-xs text-slate-500">基于本任务已确认的发现与资产清单</p>
      </div>

      <div className="mb-5 grid gap-3 sm:grid-cols-3">
        <Metric label="确认发现" value={findings} detail="已登记的安全问题" />
        <Metric
          label="高危及以上"
          value={criticalAndHigh}
          detail={findings ? `占全部发现 ${highShare}%` : "暂无发现"}
          emphasis
        />
        <Metric label="涉及资产" value={assetCount} detail="本任务关联资产数" />
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <section className="rounded-md border border-[#e5e1d8] bg-[#fcfbf8] p-5 sm:p-6">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h3 className="font-semibold text-[#24373d] text-sm">发现严重度</h3>
              <p className="mt-1 text-xs text-slate-500">按风险等级分布</p>
            </div>
            <span className="font-mono text-[10px] text-slate-400">RISK MIX</span>
          </div>
          <div className="mt-5 flex flex-wrap items-center gap-5 sm:gap-7">
            <SeverityDonut counts={severityCounts} total={findings} />
            <div className="min-w-[150px] flex-1 space-y-2.5">
              {severityCounts
                .filter((item) => item.count > 0)
                .map((item) => (
                  <div key={item.key} className="flex items-center justify-between gap-4 text-xs">
                    <span className="flex items-center gap-2 text-slate-600">
                      <span className="size-2 rounded-full" style={{ backgroundColor: item.color }} />
                      {item.label}
                    </span>
                    <span className="font-semibold text-[#24373d] tabular-nums">{item.count}</span>
                  </div>
                ))}
              {findings === 0 && <p className="text-xs text-slate-500">暂无已确认发现</p>}
            </div>
          </div>
        </section>

        <section className="rounded-md border border-[#e5e1d8] bg-[#fcfbf8] p-5 sm:p-6">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h3 className="font-semibold text-[#24373d] text-sm">资产覆盖</h3>
              <p className="mt-1 text-xs text-slate-500">本次任务涉及的资产类别</p>
            </div>
            <span className="font-mono text-[10px] text-slate-400">ASSET MIX</span>
          </div>
          {chartRows.length > 0 ? (
            <div className="mt-5 space-y-3.5">
              {chartRows.map((item) => (
                <div key={item.key} className="grid grid-cols-[72px_1fr_42px] items-center gap-3 text-xs">
                  <span className="truncate text-slate-600">{item.label}</span>
                  <span className="h-2 overflow-hidden rounded-full bg-[#e9e7e1]">
                    <span
                      className="block h-full rounded-full bg-[#456b68]"
                      style={{ width: `${Math.max(2, (item.count / maxAssetCount) * 100)}%` }}
                    />
                  </span>
                  <span className="text-right font-semibold text-[#24373d] tabular-nums">{item.count}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="mt-5 text-xs text-slate-500">暂无资产统计</p>
          )}
        </section>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-x-3 gap-y-1 border-l-2 border-[#bd6849] bg-[#f7f3ed] px-4 py-3 text-xs text-slate-600">
        <span className="font-semibold text-[#24373d]">风险重点</span>
        <span>
          高危及以上发现 {criticalAndHigh} 项，占全部发现 {highShare}%。
        </span>
      </div>
    </section>
  );
}

function SeverityDonut({ counts, total }: { counts: SeverityCount[]; total: number }) {
  let offset = 0;
  return (
    <svg className="size-32 shrink-0" viewBox="0 0 120 120" role="img" aria-label={`共 ${total} 项发现的严重度分布`}>
      <circle cx="60" cy="60" r="43" fill="none" stroke="#e9e7e1" strokeWidth="12" />
      {total > 0 &&
        counts
          .filter((item) => item.count > 0)
          .map((item) => {
            const percentage = (item.count / total) * 100;
            const segment = (
              <circle
                key={item.key}
                cx="60"
                cy="60"
                r="43"
                fill="none"
                stroke={item.color}
                strokeWidth="12"
                strokeDasharray={`${percentage} ${100 - percentage}`}
                strokeDashoffset={-offset}
                pathLength="100"
                transform="rotate(-90 60 60)"
              />
            );
            offset += percentage;
            return segment;
          })}
      <text x="60" y="56" textAnchor="middle" className="fill-[#1c3038] font-serif text-[25px]">
        {total}
      </text>
      <text x="60" y="73" textAnchor="middle" className="fill-slate-500 text-[8px] tracking-[1.5px]">
        FINDINGS
      </text>
    </svg>
  );
}

function Metric({
  label,
  value,
  detail,
  emphasis = false,
}: {
  label: string;
  value: number;
  detail: string;
  emphasis?: boolean;
}) {
  return (
    <div className="border border-[#e5e1d8] bg-white px-4 py-4 sm:px-5">
      <p className="text-slate-500 text-[11px]">{label}</p>
      <p
        className={`mt-1 font-semibold font-serif text-3xl tabular-nums ${emphasis ? "text-[#a84935]" : "text-[#1c3038]"}`}
      >
        {value}
      </p>
      <p className="mt-1 text-[10px] text-slate-500">{detail}</p>
    </div>
  );
}

export function ReportTab({ taskId }: { taskId: string }) {
  const [report, setReport] = React.useState("");
  const [loading, setLoading] = React.useState(true);
  const [copied, setCopied] = React.useState(false);
  const [downloading, setDownloading] = React.useState(false);

  React.useEffect(() => {
    let active = true;
    setLoading(true);
    api
      .report(taskId)
      .then((text) => {
        if (active) setReport(text);
      })
      .catch(() => {
        if (active) setReport("");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [taskId]);

  const titleMatch = report.match(/^#\s+(.+)$/m);
  const reportTitle = (titleMatch?.[1] || "安全评估报告").replace(/^.*?渗透测试报告\s*[—-]\s*/, "");
  const goal = report.match(/^-\s+\*\*任务目标\*\*：(.+)$/m)?.[1] || "";
  const generatedAt = report.match(/^-\s+\*\*生成时间\*\*：(.+)$/m)?.[1] || "";
  const severities = Array.from(report.matchAll(/^###\s+\d+\.\s+\[([^\]]+)\]/gm), (match) => match[1].toLowerCase());
  const summaryFindings = Number(report.match(/(?:确认发现|已确认发现)：\s*\**(\d+)/)?.[1] || 0);
  const summaryHigh = Number(report.match(/高危\s*(\d+)/)?.[1] || 0);
  const findingsCount = severities.length || summaryFindings;
  const assetCounts = parseAssetCounts(report);
  const assetCount = assetCounts.reduce((sum, item) => sum + item.count, 0);
  const criticalAndHigh = severities.length
    ? severities.filter((severity) => severity === "critical" || severity === "high").length
    : summaryHigh;
  const severityCounts = parseSeverityCounts(severities);

  async function copy() {
    if (!report) return;
    const ok = await copyText(report);
    if (ok) {
      setCopied(true);
      toast.success("已复制 Markdown");
      window.setTimeout(() => setCopied(false), 1500);
    } else {
      toast.error("复制失败，请手动选择文本复制");
    }
  }

  function downloadMarkdown() {
    if (!report) return;
    const blob = new Blob([report], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `artex-task-${taskId}-report.md`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast.success("已下载 Markdown 报告");
  }

  async function downloadWord() {
    if (!report || downloading) return;
    setDownloading(true);
    try {
      const blob = await api.reportDocx(taskId);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `artex-task-${taskId}-report.docx`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast.success("已下载 Word 报告");
    } catch (error) {
      toast.error((error as Error).message || "Word 报告下载失败");
    } finally {
      setDownloading(false);
    }
  }

  const paper = report ? (
    <ReportPaper
      report={report}
      title={reportTitle}
      goal={goal}
      generatedAt={generatedAt}
      findings={findingsCount}
      criticalAndHigh={criticalAndHigh}
      assetCount={assetCount}
      severityCounts={severityCounts}
      assetCounts={assetCounts}
    />
  ) : null;

  let content: React.ReactNode;
  if (loading) {
    content = (
      <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed py-16 text-muted-foreground text-sm">
        <FileTextIcon className="size-8 opacity-40" />
        加载报告…
      </div>
    );
  } else if (report) {
    content = <div className="rounded-xl border bg-slate-100/70 p-3 sm:p-6">{paper}</div>;
  } else {
    content = (
      <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed py-16 text-muted-foreground text-sm">
        <FileTextIcon className="size-8 opacity-40" />
        暂无报告
      </div>
    );
  }

  return (
    <Card>
      <CardHeader className="flex-row flex-wrap items-center justify-between gap-3">
        <CardTitle className="flex items-center gap-2 text-sm">
          <FileTextIcon className="size-4" /> 报告预览
        </CardTitle>
        {report && (
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" onClick={() => window.print()}>
              <PrinterIcon /> 导出 PDF
            </Button>
            <Button size="sm" variant="outline" onClick={downloadWord} disabled={downloading}>
              <DownloadIcon /> {downloading ? "生成 Word…" : "下载 Word"}
            </Button>
            <Button size="sm" variant="outline" onClick={downloadMarkdown}>
              <DownloadIcon /> 下载 Markdown
            </Button>
            <Button size="sm" variant="outline" onClick={copy}>
              {copied ? <CheckIcon /> : <CopyIcon />} 复制
            </Button>
          </div>
        )}
      </CardHeader>
      <CardContent>{content}</CardContent>
      {typeof document !== "undefined" &&
        paper &&
        createPortal(
          <div data-print-root className="report-print-root">
            {paper}
          </div>,
          document.body,
        )}
    </Card>
  );
}
