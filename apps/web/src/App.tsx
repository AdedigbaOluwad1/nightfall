import { useEffect, useMemo, useRef } from "react";
import { formatTrace, type Receipts } from "./events";
import { type Status, useNightfallSocket } from "./useNightfallSocket";

function socketUrl(): string {
  const fromQuery = new URLSearchParams(window.location.search).get("ws");
  return fromQuery ?? "ws://localhost:4317";
}

function Gauge({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="gauge">
      <div className="gauge-value">{value}</div>
      <div className="gauge-label">{label}</div>
      {sub ? <div className="gauge-sub">{sub}</div> : null}
    </div>
  );
}

function Receipt({
  title,
  tone,
  children,
}: {
  title: string;
  tone: string;
  children: React.ReactNode;
}) {
  return (
    <section className={`receipt tone-${tone}`}>
      <h2>{title}</h2>
      <div className="gauges">{children}</div>
    </section>
  );
}

function StatusDot({ status }: { status: Status }) {
  const label = status === "open" ? "live" : status === "connecting" ? "connecting" : "offline";
  return (
    <span className={`status status-${status}`}>
      <span className="dot" /> {label}
    </span>
  );
}

function ReceiptsPanel({ r }: { r: Receipts }) {
  const runLabel =
    r.run.status === "done" ? (r.run.haltedBy ? `done · ${r.run.haltedBy}` : "done") : r.run.status;
  return (
    <aside className="panel receipts-panel">
      <Receipt title="Scope" tone="scope">
        <Gauge label="gate" value={r.scope.armed ? "ARMED" : "—"} sub="deny-by-default" />
        <Gauge label="in scope" value={`${r.scope.hosts}h / ${r.scope.paths}p`} />
        <Gauge label="blocked" value={String(r.scope.blocked)} sub="out-of-scope refused" />
      </Receipt>
      <Receipt title="Bifrost" tone="bifrost">
        <Gauge label="calls" value={String(r.bifrost.calls)} sub={r.bifrost.model ?? ""} />
        <Gauge
          label="cost"
          value={`$${r.bifrost.costUsd.toFixed(4)}`}
          sub={r.bifrost.priceSource ?? ""}
        />
        <Gauge label="cache hits" value={String(r.bifrost.cacheHits)} />
      </Receipt>
      <Receipt title="Tavily" tone="tavily">
        <Gauge label="CVEs" value={String(r.tavily.cves)} sub="retrieved live" />
        <Gauge label="fresh" value={String(r.tavily.fresh)} sub="post-cutoff" />
      </Receipt>
      <Receipt title="Run" tone="run">
        <Gauge label="findings" value={String(r.run.findings)} />
        <Gauge label="steps" value={String(r.run.steps)} />
        <Gauge
          label="status"
          value={runLabel}
          sub={r.run.objectiveReached ? "objective reached" : ""}
        />
      </Receipt>
    </aside>
  );
}

export function App() {
  const url = useMemo(socketUrl, []);
  const { status, trace, receipts } = useNightfallSocket(url);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (trace.length === 0) return;
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [trace.length]);

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          nightfall ▸ <span className="brand-sub">live trace</span>
        </div>
        <StatusDot status={status} />
      </header>
      <main className="layout">
        <section className="panel trace-panel">
          {trace.length === 0 ? (
            <div className="empty">
              waiting for a run on <code>{url}</code> — start it with{" "}
              <code>nightfall serve --scope &lt;scope.yaml&gt;</code>
            </div>
          ) : (
            trace.map((item) => {
              const line = formatTrace(item);
              return (
                <div className={`line tone-${line.tone}`} key={item.seq}>
                  <span className="line-tag">{line.tag}</span>
                  <span className="line-text">{line.text}</span>
                </div>
              );
            })
          )}
          <div ref={endRef} />
        </section>
        <ReceiptsPanel r={receipts} />
      </main>
    </div>
  );
}
