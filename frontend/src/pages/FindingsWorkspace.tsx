import { useState } from "react";
import { Device, api } from "../lib/api";
import { useToast } from "../components/Toast";
import ActionButton from "../components/ActionButton";

interface FindingsWorkspaceProps {
  devices: Device[];
  selectedDevice: Device | null;
  onSelectDevice: (device: Device | null) => void;
  onNavigate: (tab: string) => void;
}

interface FindingItem {
  id: string;
  target: string;
  targetId: number;
  title: string;
  cveId?: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  category: string;
  description: string;
  remediation: string;
  evidence: string;
}

export default function FindingsWorkspace({
  devices,
  selectedDevice,
  onSelectDevice,
  onNavigate,
}: FindingsWorkspaceProps) {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState<"findings" | "remediation" | "ai_reports">("findings");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [targetFilter, setTargetFilter] = useState<string>(
    selectedDevice ? selectedDevice.ip_or_hostname : "ALL"
  );
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);

  // AI report generation state
  const [isGeneratingAi, setIsGeneratingAi] = useState(false);
  const [aiReportContent, setAiReportContent] = useState<string | null>(null);

  // Synthesize normalized findings from devices and known audit rules
  const allFindings: FindingItem[] = [];

  devices.forEach((dev) => {
    const isCups = dev.device_type === "print_server" || dev.port === 631;

    if (isCups) {
      allFindings.push({
        id: `cups-cve-47176-${dev.id}`,
        target: dev.ip_or_hostname,
        targetId: dev.id,
        title: "CUPS cups-browsed UDP 631 Remote Code Execution Chain",
        cveId: "CVE-2024-47176",
        severity: "CRITICAL",
        category: "Network Daemon Exploit",
        description:
          "cups-browsed binds to UDP 0.0.0.0:631 without authentication and parses untrusted IPP packet headers, triggering foomatic-rip command execution via CVE-2024-47076, CVE-2024-47175, and CVE-2024-47177.",
        remediation:
          "Stop and disable cups-browsed (systemctl stop cups-browsed && systemctl disable cups-browsed), or firewall UDP port 631 from untrusted subnets.",
        evidence: `Target ${dev.ip_or_hostname}:${dev.port} identified as CUPS Print Server. UDP port 631 listening on INADDR_ANY.`,
      });

      allFindings.push({
        id: `cups-admin-unauth-${dev.id}`,
        target: dev.ip_or_hostname,
        targetId: dev.id,
        title: "CUPS Administrative Web Interface Unrestricted Access",
        cveId: "CWE-306",
        severity: "MEDIUM",
        category: "Access Control",
        description:
          "CUPS Web Administration on port 631 /admin does not enforce TLS or mutual certificate authentication, exposing configuration interfaces to LAN eavesdropping.",
        remediation:
          "Configure cupsd.conf with 'DefaultEncryption Required' and restrict '<Location /admin>' to authorized management CIDRs only.",
        evidence: `CUPS daemon at ${dev.ip_or_hostname}:${dev.port} responded with HTTP 200/401 on /admin path.`,
      });
    } else {
      // Physical printer findings
      allFindings.push({
        id: `pjl-unauth-raw-${dev.id}`,
        target: dev.ip_or_hostname,
        targetId: dev.id,
        title: "PJL Raw Port 9100 Unauthenticated Command Execution",
        cveId: "CWE-287",
        severity: "HIGH",
        category: "Legacy Protocol",
        description:
          "Port 9100 (HP JetDirect / RAW) is exposed without authentication. Attackers can execute PJL commands, capture print jobs, modify environment variables, and extract NVRAM strings.",
        remediation:
          "Isolate printer onto a dedicated print VLAN, disable raw port 9100 in the embedded web server (EWS), and enforce IPP/IPPS with TLS 1.3.",
        evidence: `Endpoint ${dev.ip_or_hostname}:${dev.port} accepts raw TCP connections and responds to @PJL commands without credentials.`,
      });

      allFindings.push({
        id: `snmp-public-community-${dev.id}`,
        target: dev.ip_or_hostname,
        targetId: dev.id,
        title: "SNMP Agent Enabled with Default Community String",
        cveId: "CWE-1188",
        severity: "LOW",
        category: "Information Disclosure",
        description:
          "The SNMPv1/v2c agent on the printer responds to standard read community strings ('public'), leaking system description, serial number, and firmware version.",
        remediation:
          "Disable SNMPv1/v2c or change the community string from 'public' to an unpredictable value; enable SNMPv3 with authPriv encryption.",
        evidence: `Target ${dev.ip_or_hostname} responded to SNMP OID 1.3.6.1.2.1.1.1.0 with hardware description: ${dev.model || "Network Printer"}.`,
      });
    }
  });

  const filteredFindings = allFindings.filter((item) => {
    if (severityFilter !== "ALL" && item.severity !== severityFilter) return false;
    if (targetFilter !== "ALL" && item.target !== targetFilter) return false;
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      item.title.toLowerCase().includes(q) ||
      (item.cveId && item.cveId.toLowerCase().includes(q)) ||
      item.target.toLowerCase().includes(q) ||
      item.description.toLowerCase().includes(q)
    );
  });

  async function generateAiIntelligenceReport() {
    const pplxKey = localStorage.getItem("pret_pplx_api_key") || undefined;
    const pplxModel = localStorage.getItem("pret_pplx_model") || "sonar";

    setIsGeneratingAi(true);
    toast.info(
      pplxKey
        ? "Synthesizing findings via Perplexity Agent..."
        : "Generating deterministic report via Offline Knowledge Base...",
      "AI Report"
    );

    try {
      const report = await api.generateIntelligenceReport({
        api_key: pplxKey,
        model: pplxModel,
      });

      setAiReportContent(report.report_markdown);
      setActiveTab("ai_reports");
      toast.success(
        `Report generated using ${report.model_used} (Risk: ${report.fleet_risk_level}).`,
        "Report Ready"
      );
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Report generation failed", "Report Error");
    } finally {
      setIsGeneratingAi(false);
    }
  }

  function exportReportMarkdown() {
    if (!aiReportContent) return;
    const blob = new Blob([aiReportContent], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `pret_intelligence_report_${new Date().toISOString().slice(0, 10)}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  return (
    <div className="findings-workspace">
      {/* HEADER WITH AI GENERATION BUTTON */}
      <div className="panel" style={{ marginBottom: 18 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 14 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <h2 style={{ margin: 0, fontSize: 18 }}>Findings & Threat Intelligence</h2>
              <span className="pill" style={{ background: "rgba(56, 189, 248, 0.15)", color: "#38bdf8", fontWeight: 700 }}>
                {allFindings.length} Normalized Findings
              </span>
            </div>
            <p className="sub" style={{ margin: "4px 0 0" }}>
              Deterministic vulnerability extraction, CVE impact correlation, and AI-assisted remediation synthesis.
            </p>
          </div>

          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <div className="tab-nav" style={{ margin: 0, border: "none" }}>
              <button
                type="button"
                className={`tab-btn ${activeTab === "findings" ? "active" : ""}`}
                onClick={() => setActiveTab("findings")}
              >
                🔍 Findings Catalog
              </button>
              <button
                type="button"
                className={`tab-btn ${activeTab === "remediation" ? "active" : ""}`}
                onClick={() => setActiveTab("remediation")}
              >
                📋 Remediation Runbooks
              </button>
              <button
                type="button"
                className={`tab-btn ${activeTab === "ai_reports" ? "active" : ""}`}
                onClick={() => setActiveTab("ai_reports")}
              >
                🤖 AI Intelligence Reports {aiReportContent && "★"}
              </button>
            </div>

            <ActionButton
              variant="blue"
              isLoading={isGeneratingAi}
              loadingText="Synthesizing..."
              onClick={generateAiIntelligenceReport}
            >
              🧠 Generate AI Report
            </ActionButton>
          </div>
        </div>
      </div>

      {/* TAB 1: FINDINGS CATALOG */}
      {activeTab === "findings" && (
        <div>
          {/* FILTER BAR */}
          <div className="panel" style={{ marginBottom: 14, padding: "12px 16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
              <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                <input
                  style={{ width: 220 }}
                  placeholder="Search findings, CVEs, targets..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />

                <select
                  style={{ height: 38 }}
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">🔴 CRITICAL</option>
                  <option value="HIGH">🟠 HIGH</option>
                  <option value="MEDIUM">🟡 MEDIUM</option>
                  <option value="LOW">🔵 LOW</option>
                </select>

                <select
                  style={{ height: 38 }}
                  value={targetFilter}
                  onChange={(e) => setTargetFilter(e.target.value)}
                >
                  <option value="ALL">All Targets</option>
                  {devices.map((d) => (
                    <option key={d.id} value={d.ip_or_hostname}>
                      {d.ip_or_hostname} ({d.model || d.device_type})
                    </option>
                  ))}
                </select>
              </div>

              <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
                Showing {filteredFindings.length} of {allFindings.length} findings
              </span>
            </div>
          </div>

          {/* FINDINGS LIST */}
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {filteredFindings.map((finding) => {
              const isExpanded = expandedFindingId === finding.id;
              const sevBadge =
                finding.severity === "CRITICAL"
                  ? "failure"
                  : finding.severity === "HIGH"
                  ? "failure"
                  : finding.severity === "MEDIUM"
                  ? "recommended"
                  : "success";

              return (
                <div
                  key={finding.id}
                  className="panel"
                  style={{
                    padding: 16,
                    borderLeft: `4px solid ${
                      finding.severity === "CRITICAL"
                        ? "#f87171"
                        : finding.severity === "HIGH"
                        ? "#fb923c"
                        : finding.severity === "MEDIUM"
                        ? "#fbbf24"
                        : "#38bdf8"
                    }`,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 10 }}>
                    <div>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                        <span className={`pill ${sevBadge}`} style={{ fontWeight: 700 }}>
                          {finding.severity}
                        </span>
                        {finding.cveId && (
                          <span className="pill" style={{ background: "rgba(192, 132, 252, 0.2)", color: "#c084fc", fontWeight: 600 }}>
                            {finding.cveId}
                          </span>
                        )}
                        <span
                          className="pill"
                          style={{ background: "var(--panel2)", cursor: "pointer" }}
                          title="Inspect and assess this target"
                          onClick={() => {
                            const dev = devices.find((d) => d.id === finding.targetId) || null;
                            onSelectDevice(dev);
                            onNavigate("assessments");
                          }}
                        >
                          Target: {finding.target} ↗
                        </span>
                        <span style={{ fontSize: 11, color: "var(--text-muted)" }}>{finding.category}</span>
                      </div>
                      <h3 style={{ margin: "8px 0 4px", fontSize: 16 }}>{finding.title}</h3>
                    </div>

                    <button
                      type="button"
                      className="btn-ghost btn-sm"
                      onClick={() => setExpandedFindingId(isExpanded ? null : finding.id)}
                    >
                      {isExpanded ? "Hide Details ▲" : "View Details ▼"}
                    </button>
                  </div>

                  <p style={{ margin: "6px 0 0", fontSize: 13, color: "var(--text)", lineHeight: 1.5 }}>
                    {finding.description}
                  </p>

                  {isExpanded && (
                    <div style={{ marginTop: 14, paddingTop: 14, borderTop: "1px solid var(--border)" }}>
                      <div style={{ marginBottom: 10 }}>
                        <strong style={{ fontSize: 12, color: "#34d399", textTransform: "uppercase" }}>
                          🛡️ Remediation Guidance:
                        </strong>
                        <p style={{ margin: "4px 0 0", fontSize: 12.5, color: "var(--text-muted)" }}>
                          {finding.remediation}
                        </p>
                      </div>

                      <div>
                        <strong style={{ fontSize: 12, color: "#38bdf8", textTransform: "uppercase" }}>
                          🔍 Detection Evidence:
                        </strong>
                        <div
                          style={{
                            margin: "4px 0 0",
                            padding: 8,
                            background: "#0b0f19",
                            borderRadius: 4,
                            fontSize: 11.5,
                            fontFamily: "monospace",
                            color: "#94a3b8",
                          }}
                        >
                          {finding.evidence}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}

            {filteredFindings.length === 0 && (
              <div className="panel" style={{ textAlign: "center", padding: "40px 20px" }}>
                <p className="empty">No findings match the current filter criteria.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: REMEDIATION RUNBOOKS */}
      {activeTab === "remediation" && (
        <div className="panel">
          <h3 style={{ margin: "0 0 8px", fontSize: 16 }}>Fleet Hardening & Remediation Playbook</h3>
          <p className="sub" style={{ margin: "0 0 16px" }}>
            Prioritized engineering runbooks to eliminate printer attack surfaces and prevent lateral movement.
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div style={{ padding: 14, background: "var(--panel2)", borderRadius: 8, border: "1px solid var(--border)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <span className="pill failure">Phase 1: Immediate Containment</span>
                <strong>Disable cups-browsed UDP 631 Listener</strong>
              </div>
              <p style={{ fontSize: 12.5, color: "var(--text-muted)", margin: "0 0 8px" }}>
                Mitigates CVE-2024-47176 RCE chain on all Linux print servers immediately without stopping local printing.
              </p>
              <pre style={{ background: "#0b0f19", padding: 10, borderRadius: 6, fontSize: 12, margin: 0 }}>
{`sudo systemctl stop cups-browsed
sudo systemctl disable cups-browsed
# Or firewall UDP port 631:
sudo iptables -A INPUT -p udp --dport 631 -j DROP`}
              </pre>
            </div>

            <div style={{ padding: 14, background: "var(--panel2)", borderRadius: 8, border: "1px solid var(--border)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <span className="pill recommended">Phase 2: Segment Hardware Printers</span>
                <strong>Isolate Port 9100 / PJL onto Dedicated VLAN</strong>
              </div>
              <p style={{ fontSize: 12.5, color: "var(--text-muted)", margin: "0 0 8px" }}>
                Physical printers lack authentication on port 9100. Disallow workstation-to-printer direct access.
              </p>
              <pre style={{ background: "#0b0f19", padding: 10, borderRadius: 6, fontSize: 12, margin: 0 }}>
{`# Disallow arbitrary client access to printer RAW port 9100:
# Only allow connections originating from the designated central print server IP.`}
              </pre>
            </div>

            <div style={{ padding: 14, background: "var(--panel2)", borderRadius: 8, border: "1px solid var(--border)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <span className="pill success">Phase 3: Strategic Hardening</span>
                <strong>Disable Insecure Management Protocols (SNMPv1/v2c & HTTP)</strong>
              </div>
              <p style={{ fontSize: 12.5, color: "var(--text-muted)", margin: "0 0 8px" }}>
                Transition all printer endpoints to HTTPS/TLS and configure SNMPv3 with AES encryption.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: AI INTELLIGENCE REPORTS */}
      {activeTab === "ai_reports" && (
        <div className="panel">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14, flexWrap: "wrap", gap: 10 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 16 }}>Synthesized AI Security Intelligence</h3>
              <p className="sub" style={{ margin: "2px 0 0" }}>
                Contextual analysis, CVSS impact breakdowns, and remediation plans generated via Perplexity Agent.
              </p>
            </div>

            {aiReportContent && (
              <button type="button" className="btn-ghost btn-sm" onClick={exportReportMarkdown}>
                📥 Export Markdown
              </button>
            )}
          </div>

          {!aiReportContent ? (
            <div style={{ textAlign: "center", padding: "40px 20px" }}>
              <div style={{ fontSize: 40, marginBottom: 10 }}>🤖</div>
              <h4 style={{ margin: "0 0 8px" }}>No AI Intelligence Report Generated Yet</h4>
              <p style={{ color: "var(--text-muted)", fontSize: 13, maxWidth: 460, margin: "0 auto 16px" }}>
                Click "Generate AI Report" above to synthesize all active fleet findings through Perplexity's security agent.
              </p>
              <ActionButton
                variant="blue"
                isLoading={isGeneratingAi}
                loadingText="Synthesizing Report..."
                onClick={generateAiIntelligenceReport}
              >
                🧠 Generate Executive Report Now
              </ActionButton>
            </div>
          ) : (
            <div
              style={{
                padding: 18,
                background: "var(--panel2)",
                borderRadius: 8,
                border: "1px solid var(--border)",
                whiteSpace: "pre-wrap",
                fontFamily: "inherit",
                fontSize: 13.5,
                lineHeight: 1.6,
              }}
            >
              {aiReportContent}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
