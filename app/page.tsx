
"use client";

import { useRef, useState } from "react";
import {
  ShieldCheck,
  FolderOpen,
  Search,
  Upload,
  RefreshCw,
  AlertTriangle,
  Download,
  Info,
  FileSearch,
  X,
} from "lucide-react";

type Finding = {
  id: string;
  ruleId: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  file: string;
  line: number;
  explanation: string;
  fix: string;
  evidence: string;
};

type Result = {
  score: number;
  scannedFiles: number;
  skippedFiles: number;
  findings: Finding[];
  projectName: string;
};

// Retro pixel-art ShipSafe logo

function RetroShipLogo({ size = 32 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      xmlns="http://www.w3.org/2000/svg"
      shapeRendering="crispEdges"
      role="img"
      aria-label="ShipSafe sailing ship"
    >
      {/* Mast */}
      <rect x="30" y="5" width="3" height="43" fill="#172F49" />

      {/* Small flag */}
      <path d="M33 5 H45 V11 H37 V9 H33 Z" fill="#244C76" />

      {/* Rear triangular sail */}
      <path
        d="M28 14 H30 V37 H12 V33 H16 V28 H20 V23 H24 V18 H28 Z"
        fill="#315F89"
      />

      {/* Small lower-left sail */}
      <path
        d="M10 35 H28 V44 H13 V41 H10 Z"
        fill="#244C76"
      />

      {/* Large upper sail */}
      <path
        d="M34 14 H40 V17 H45 V21 H49 V29 H46 V33 H34 Z"
        fill="#244C76"
      />

      {/* Lower middle sail */}
      <path
        d="M34 34 H43 V37 H48 V45 H34 Z"
        fill="#244C76"
      />

      {/* Front triangular sail — same navy blue */}
      <path
        d="M49 24 H52 V29 H55 V33 H58 V38 H49 Z"
        fill="#315F89"
      />

      {/* Small sail highlights */}
      <rect x="36" y="18" width="7" height="2" fill="#527DA3" />
      <rect x="37" y="37" width="7" height="2" fill="#527DA3" />
      <rect x="15" y="37" width="7" height="2" fill="#527DA3" />

      {/* Deck */}
      <path d="M7 44 H59 V47 H7 Z" fill="#172F49" />
      <path d="M12 42 H55 V44 H12 Z" fill="#E6B85C" />

      {/* Hull */}
      <path
        d="M6 47 H59 L55 52 H50 L46 55 H17 L12 52 H9 Z"
        fill="#172F49"
      />

      {/* Blue hull surface */}
      <path
        d="M11 48 H55 L50 52 H17 L13 51 Z"
        fill="#315F89"
      />

      {/* Hull details */}
      <rect x="21" y="50" width="3" height="2" fill="#172F49" />
      <rect x="42" y="49" width="3" height="2" fill="#172F49" />

      {/* Golden trim */}
      <rect x="13" y="52" width="37" height="2" fill="#E6B85C" />

      {/* Turquoise pixel waves */}
      <path d="M3 57 H15 V59 H3 Z" fill="#259F91" />
      <path d="M18 59 H30 V61 H18 Z" fill="#259F91" />
      <path d="M34 57 H46 V59 H34 Z" fill="#259F91" />
      <path d="M49 59 H61 V61 H49 Z" fill="#259F91" />
    </svg>
  );
}


export default function Home() {
  const inputRef = useRef<HTMLInputElement>(null);

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");

  async function scan(file?: File) {
    if (!file) return;

    setBusy(true);
    setError("");
    setResult(null);
    setSelectedId(null);
    setSearch("");
    setSeverityFilter("all");

    try {
      const data = new FormData();
      data.append("file", file);

      const response = await fetch("/api/scan", {
        method: "POST",
        body: data,
      });

      const body = await response.json();

      if (!response.ok) {
        throw new Error(body.error || "Scan failed.");
      }

      const scanResult = body as Result;
      setResult(scanResult);
      setSelectedId(scanResult.findings[0]?.id ?? null);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Something went wrong."
      );
    } finally {
      setBusy(false);
      if (inputRef.current) inputRef.current.value = "";
    }
  }

  function resetScan() {
    setResult(null);
    setError("");
    setSelectedId(null);
    setSearch("");
    setSeverityFilter("all");
  }

  const counts = result
    ? {
        critical: result.findings.filter(
          (f) => f.severity === "critical"
        ).length,
        high: result.findings.filter(
          (f) => f.severity === "high"
        ).length,
        medium: result.findings.filter(
          (f) => f.severity === "medium"
        ).length,
        low: result.findings.filter(
          (f) => f.severity === "low"
        ).length,
      }
    : null;

  const visibleFindings =
    result?.findings.filter((finding) => {
      const matchesSearch =
        finding.title.toLowerCase().includes(search.toLowerCase()) ||
        finding.file.toLowerCase().includes(search.toLowerCase());

      const matchesSeverity =
        severityFilter === "all" ||
        finding.severity === severityFilter;

      return matchesSearch && matchesSeverity;
    }) ?? [];

  const selectedFinding =
    result?.findings.find((f) => f.id === selectedId) ?? null;

  return (
    <div className="desktop">
      <main className="app-window">
        {/* Application header */}
        <header className="title-bar">
          <div className="title-brand">
            <div className="title-logo">
              <RetroShipLogo size={25} />
            </div>
            <span>ShipSafe — Project Security Scanner</span>
          </div>
        </header>

        {/* Application menu */}
        <nav className="menu-bar">
          <button onClick={resetScan}>File</button>
          <button onClick={() => inputRef.current?.click()}>Scan</button>
          <button onClick={() => window.print()}>Reports</button>
          <button
            onClick={() =>
              document
                .getElementById("scan-notice")
                ?.scrollIntoView({ behavior: "smooth" })
            }
          >
            Help
          </button>
        </nav>

        <div className="workspace">
          {/* Sidebar */}
          <aside className="sidebar">
            <div className="sidebar-brand">
              <div className="big-shield">
                <RetroShipLogo size={65} />
              </div>
              <h1>ShipSafe</h1>
              <p>PROJECT SECURITY</p>
            </div>

            <div className="side-navigation">
              <div className="side-item active">
                <Search size={19} />
                <span>Scanner</span>
              </div>
            </div>

            <div className="sidebar-bottom">
              <div className="ready-light" />
              <span>{busy ? "Scanning..." : "Ready"}</span>
              <small>Version 1.0.0</small>
            </div>
          </aside>

          {/* Main application content */}
          <section className="main-content">
            <div className="top-panels">
              {/* Project upload */}
              <section className="retro-window upload-window">
                <div className="window-heading">
                  <div>
                    <FolderOpen size={17} />
                    <span>Project Scan</span>
                  </div>
                  <button
                    aria-label="Reset scan"
                    onClick={resetScan}
                    title="Reset scan"
                  >
                    <X size={14} />
                  </button>
                </div>

                <div className="upload-content">
                  <div className="upload-area">
                    <FolderOpen size={43} strokeWidth={1.5} />

                    <strong>
                      {result ? result.projectName : "Select a project ZIP"}
                    </strong>

                    <span>
                      {busy
                        ? "Analysing project files..."
                        : "Choose an archive to scan for security risks"}
                    </span>

                    <input
                      ref={inputRef}
                      type="file"
                      accept=".zip,application/zip"
                      onChange={(e) => scan(e.target.files?.[0])}
                    />

                    <button
                      className="retro-button choose-button"
                      disabled={busy}
                      onClick={() => inputRef.current?.click()}
                    >
                      <Upload size={16} />
                      {busy ? "Scanning..." : "Choose ZIP file"}
                    </button>
                  </div>

                  <p className="upload-hint">
                    ZIP files only · Maximum size: 20 MB
                  </p>

                  {error && <div className="error-message">{error}</div>}
                </div>
              </section>

              {/* Scan overview */}
              <section className="retro-window overview-window">
                <div className="window-heading">
                  <div>
                    <FileSearch size={17} />
                    <span>Scan Overview</span>
                  </div>
                </div>

                <div className="overview-content">
                  <div className="overview-numbers">
                    <div className="score-block">
                      <span>Security Score</span>

                      <strong className="score-number">
                        {result ? result.score : "--"}
                        <small>/100</small>
                      </strong>

                      <div className="score-track">
                        <div
                          className="score-fill"
                          style={{
                            width: `${result?.score ?? 0}%`,
                          }}
                        />
                      </div>
                    </div>

                    <div className="overview-stat">
                      <span>Findings</span>
                      <strong>
                        {result ? result.findings.length : "--"}
                      </strong>
                    </div>

                    <div className="file-stats">
                      <div>
                        <span>Files scanned</span>
                        <strong>{result?.scannedFiles ?? "--"}</strong>
                      </div>

                      <div>
                        <span>Files skipped</span>
                        <strong>{result?.skippedFiles ?? "--"}</strong>
                      </div>
                    </div>
                  </div>

                  <div className="severity-heading">
                    Severity Breakdown
                  </div>

                  <div className="severity-grid">
                    {(["critical", "high", "medium", "low"] as const).map(
                      (level) => (
                        <div className={`severity-box ${level}`} key={level}>
                          <strong>{counts ? counts[level] : "--"}</strong>
                          <span>
                            {level.charAt(0).toUpperCase() + level.slice(1)}
                          </span>
                        </div>
                      )
                    )}
                  </div>
                </div>
              </section>
            </div>

            {/* Security findings */}
            <section className="retro-window findings-window">
              <div className="findings-heading">
                <div className="findings-title">
                  <AlertTriangle size={19} />
                  <span>Security Findings</span>
                </div>

                <div className="finding-controls">
                  <div className="search-box">
                    <Search size={15} />
                    <input
                      placeholder="Search findings..."
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                    />
                  </div>

                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    aria-label="Filter by severity"
                  >
                    <option value="all">All severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              {!result ? (
                <div className="empty-state">
                  <div className="empty-icon">
                    <ShieldCheck size={43} />
                  </div>

                  <h2>Waiting for project scan</h2>

                  <p>
                    Choose a ZIP archive above to inspect your project.
                    Detected security issues will appear here.
                  </p>
                </div>
              ) : result.findings.length === 0 ? (
                <div className="empty-state success-state">
                  <ShieldCheck size={45} />

                  <h2>No findings detected!</h2>

                  <p>
                    No issues matched ShipSafe&apos;s current detection rules.
                    This does not guarantee that the project is secure.
                  </p>
                </div>
              ) : (
                <div className="findings-layout">
                  <div className="findings-table-wrap">
                    <table className="findings-table">
                      <thead>
                        <tr>
                          <th>#</th>
                          <th>Severity</th>
                          <th>Finding</th>
                          <th>File</th>
                          <th>Line</th>
                        </tr>
                      </thead>

                      <tbody>
                        {visibleFindings.map((finding, index) => (
                          <tr
                            key={finding.id}
                            className={
                              selectedId === finding.id ? "selected-row" : ""
                            }
                            onClick={() => setSelectedId(finding.id)}
                          >
                            <td>{index + 1}</td>

                            <td>
                              <span
                                className={`severity-tag ${finding.severity}`}
                              >
                                {finding.severity}
                              </span>
                            </td>

                            <td className="finding-name">
                              {finding.title}
                            </td>

                            <td className="file-name">{finding.file}</td>
                            <td>{finding.line}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>

                    {visibleFindings.length === 0 && (
                      <div className="no-matches">
                        No findings match your search.
                      </div>
                    )}
                  </div>

                  {/* Selected finding details */}
                  <aside className="finding-detail">
                    {selectedFinding ? (
                      <>
                        <div className="detail-top">
                          <span
                            className={`severity-tag ${selectedFinding.severity}`}
                          >
                            {selectedFinding.severity}
                          </span>

                          <span className="rule-id">
                            {selectedFinding.ruleId}
                          </span>
                        </div>

                        <h3>{selectedFinding.title}</h3>

                        <div className="detail-section">
                          <strong>Why it matters</strong>
                          <p>{selectedFinding.explanation}</p>
                        </div>

                        <div className="detail-section">
                          <strong>Suggested fix</strong>
                          <p>{selectedFinding.fix}</p>
                        </div>

                        <div className="detail-section">
                          <strong>Redacted evidence</strong>
                          <code>{selectedFinding.evidence}</code>
                        </div>

                        <div className="location-note">
                          <Info size={14} />
                          {selectedFinding.file}:{selectedFinding.line}
                        </div>
                      </>
                    ) : (
                      <div className="detail-placeholder">
                        <FileSearch size={30} />
                        <p>Select a finding to view its details.</p>
                      </div>
                    )}
                  </aside>
                </div>
              )}

              <div className="findings-footer">
                <span>
                  {result
                    ? `${visibleFindings.length} of ${result.findings.length} findings displayed`
                    : "No scan loaded"}
                </span>

                <button onClick={resetScan}>
                  <RefreshCw size={13} />
                  New scan
                </button>
              </div>
            </section>

            {/* Footer */}
            <footer className="app-footer" id="scan-notice">
              <div className="footer-message">
                <Info size={16} />

                <span>
                  ShipSafe performs a limited static scan. It does not execute
                  uploaded code, inspect Git history, or replace a professional
                  security review.
                </span>
              </div>

              <button
                className="retro-button export-button"
                onClick={() => window.print()}
              >
                <Download size={15} />
                Export / Print
              </button>
            </footer>
          </section>
        </div>
      </main>
    </div>
  );
}
