import { useEffect, useState, useCallback } from "react";
import {
  api,
  Device,
  AdapterInfo,
  Job,
  AuditEntry,
  AuthorizedNetwork,
  NetworkRoute,
} from "../lib/api";
import { useToast } from "../components/Toast";
import Overview from "./Overview";
import AssetsWorkspace from "./AssetsWorkspace";
import AssessmentsWorkspace from "./AssessmentsWorkspace";
import FindingsWorkspace from "./FindingsWorkspace";
import ActivityWorkspace from "./ActivityWorkspace";
import SettingsWorkspace from "./SettingsWorkspace";
import JobLog from "../components/JobLog";

export type WorkspaceTab =
  | "overview"
  | "assets"
  | "assessments"
  | "findings"
  | "activity"
  | "settings";

function getTabFromHash(): WorkspaceTab {
  const hash = window.location.hash.replace("#", "").toLowerCase();
  const validTabs: WorkspaceTab[] = [
    "overview",
    "assets",
    "assessments",
    "findings",
    "activity",
    "settings",
  ];
  return validTabs.includes(hash as WorkspaceTab) ? (hash as WorkspaceTab) : "overview";
}

export default function Dashboard() {
  const { toast } = useToast();
  const [currentTab, setCurrentTab] = useState<WorkspaceTab>(getTabFromHash);

  // Shared Core State
  const [devices, setDevices] = useState<Device[]>([]);
  const [adapters, setAdapters] = useState<AdapterInfo[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [networks, setNetworks] = useState<AuthorizedNetwork[]>([]);
  const [routes, setRoutes] = useState<NetworkRoute[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);

  // Operational Controls
  const [safeMode, setSafeMode] = useState<boolean>(true);
  const [activeJobId, setActiveJobId] = useState<number | null>(null);

  // Connectivity & Health Telemetry
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const [lastRefreshedAt, setLastRefreshedAt] = useState<Date | null>(null);

  // Synchronize Tab with URL Hash
  const navigateToTab = useCallback((tab: WorkspaceTab) => {
    setCurrentTab(tab);
    window.location.hash = `#${tab}`;
  }, []);

  useEffect(() => {
    const handleHashChange = () => {
      setCurrentTab(getTabFromHash());
    };
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  // Fleet Polling & Refresh
  const refresh = useCallback(async () => {
    try {
      const [devs, adaps, auditLogs, jobsList] = await Promise.all([
        api.listDevices(),
        api.listAdapters(),
        api.auditLog(),
        api.listJobs().catch(() => []),
      ]);

      setDevices(devs);
      setAdapters(adaps);
      setAudit(auditLogs);
      setJobs(jobsList);
      setRefreshError(null);
      setLastRefreshedAt(new Date());

      // If a device is currently selected, refresh its reference
      if (selectedDevice) {
        const updated = devs.find((d) => d.id === selectedDevice.id);
        if (updated) setSelectedDevice(updated);
      }

      // Fetch network scope and routes whenever in settings or on mount
      if (networks.length === 0 || currentTab === "settings") {
        const [nets, rts] = await Promise.all([
          api.listNetworks().catch((err) => {
            toast.error(err instanceof Error ? err.message : "Failed to load networks", "Settings Error");
            return [];
          }),
          api.listRoutes().catch((err) => {
            toast.error(err instanceof Error ? err.message : "Failed to load routes", "Settings Error");
            return [];
          }),
        ]);
        setNetworks(nets);
        setRoutes(rts);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Backend connection lost";
      setRefreshError(msg);
    }
  }, [currentTab, selectedDevice, networks.length, toast]);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 6000);
    return () => clearInterval(interval);
  }, [refresh]);

  return (
    <div className="layout">
      {/* LATERAL WORKSPACE NAVIGATION */}
      <nav>
        <div style={{ padding: "0 4px 14px 4px", borderBottom: "1px solid var(--border)", marginBottom: 12 }}>
          <div style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)", letterSpacing: "0.05em" }}>
            Workspaces
          </div>
        </div>

        <a
          className={currentTab === "overview" ? "active" : ""}
          onClick={() => navigateToTab("overview")}
        >
          <span>🏠</span> Overview
        </a>
        <a
          className={currentTab === "assets" ? "active" : ""}
          onClick={() => navigateToTab("assets")}
        >
          <span>🖨️</span> Assets ({devices.length})
        </a>
        <a
          className={currentTab === "assessments" ? "active" : ""}
          onClick={() => navigateToTab("assessments")}
        >
          <span>🎯</span> Assessments
        </a>
        <a
          className={currentTab === "findings" ? "active" : ""}
          onClick={() => navigateToTab("findings")}
        >
          <span>🧠</span> Findings & Intelligence
        </a>
        <a
          className={currentTab === "activity" ? "active" : ""}
          onClick={() => navigateToTab("activity")}
        >
          <span>⚡</span> Activity ({jobs.length})
        </a>
        <a
          className={currentTab === "settings" ? "active" : ""}
          onClick={() => navigateToTab("settings")}
        >
          <span>⚙️</span> Settings & Scope
        </a>

        {/* ACTIVE TARGET QUICK STATUS IN SIDEBAR */}
        <div
          style={{
            marginTop: 28,
            padding: "12px",
            background: "var(--panel2)",
            borderRadius: 8,
            border: "1px solid var(--border)",
            fontSize: 12,
          }}
        >
          <div style={{ fontSize: 10.5, color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 700, marginBottom: 4 }}>
            Selected Target
          </div>
          {selectedDevice ? (
            <div>
              <div style={{ fontWeight: 700, color: "var(--text)" }}>{selectedDevice.ip_or_hostname}</div>
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                Port {selectedDevice.port} • {selectedDevice.device_type === "print_server" ? "CUPS" : "Printer"}
              </div>
              <button
                type="button"
                className="btn-ghost btn-sm"
                style={{ width: "100%", marginTop: 8, fontSize: 11, padding: "3px 6px" }}
                onClick={() => navigateToTab("assessments")}
              >
                Open in Console →
              </button>
            </div>
          ) : (
            <div style={{ color: "var(--text-muted)", fontSize: 11 }}>
              None selected. Pick a target from Assets or Assessments.
            </div>
          )}
        </div>
      </nav>

      {/* MAIN VIEWPORT */}
      <main>
        {/* REFRESH / STALE DATA ALERT BANNER */}
        {refreshError && (
          <div className="refresh-status-bar" role="alert">
            <span>
              ⚠️ <strong>Backend Reachability Warning:</strong> Displaying cached fleet data{" "}
              {lastRefreshedAt ? `(as of ${lastRefreshedAt.toLocaleTimeString()})` : ""}. {refreshError}
            </span>
            <button type="button" className="btn-ghost btn-sm" onClick={refresh}>
              ↻ Reconnect Now
            </button>
          </div>
        )}

        {/* RENDER ACTIVE WORKSPACE */}
        {currentTab === "overview" && (
          <Overview
            devices={devices}
            adapters={adapters}
            jobs={jobs}
            networks={networks}
            safeMode={safeMode}
            setSafeMode={setSafeMode}
            onNavigate={(t) => navigateToTab(t as WorkspaceTab)}
            onSelectDevice={(d) => setSelectedDevice(d)}
          />
        )}

        {currentTab === "assets" && (
          <AssetsWorkspace
            devices={devices}
            selectedDevice={selectedDevice}
            onSelectDevice={setSelectedDevice}
            onNavigateToAssessments={(dev) => {
              setSelectedDevice(dev);
              navigateToTab("assessments");
            }}
            onRefresh={refresh}
          />
        )}

        {currentTab === "assessments" && (
          <AssessmentsWorkspace
            devices={devices}
            selectedDevice={selectedDevice}
            adapters={adapters}
            safeMode={safeMode}
            onSelectDevice={setSelectedDevice}
            onRefresh={refresh}
            onJobStarted={(jobId) => setActiveJobId(jobId)}
          />
        )}

        {currentTab === "findings" && (
          <FindingsWorkspace
            devices={devices}
            selectedDevice={selectedDevice}
            onSelectDevice={setSelectedDevice}
            onNavigate={(t) => navigateToTab(t as WorkspaceTab)}
          />
        )}

        {currentTab === "activity" && (
          <ActivityWorkspace
            jobs={jobs}
            audit={audit}
            devices={devices}
            activeJobId={activeJobId}
            setActiveJobId={setActiveJobId}
            onRefresh={refresh}
          />
        )}

        {currentTab === "settings" && (
          <SettingsWorkspace
            networks={networks}
            routes={routes}
            safeMode={safeMode}
            setSafeMode={setSafeMode}
            onRefresh={refresh}
          />
        )}

        {/* ACTIVE JOB LIVE LOG / CONSOLE MODAL */}
        {activeJobId !== null && (
          <JobLog jobId={activeJobId} onClose={() => setActiveJobId(null)} />
        )}
      </main>
    </div>
  );
}
