import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { formatTrace, type Receipts } from "./events";
import { type Status, useNightfallSocket } from "./useNightfallSocket";

function socketUrl(): string {
  const fromQuery = new URLSearchParams(window.location.search).get("ws");
  return fromQuery ?? "ws://localhost:4317";
}

type Theme = "dark" | "light";

function systemTheme(): Theme {
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const saved = localStorage.getItem("nf-cc-theme");
      if (saved === "dark" || saved === "light") return saved;
    } catch {}
    return systemTheme();
  });

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("nf-cc-theme", theme);
    } catch {}
  }, [theme]);

  const toggle = useCallback(() => {
    setTheme((t) => (t === "dark" ? "light" : "dark"));
  }, []);

  return [theme, toggle];
}

function StatusChip({ status }: { status: Status }) {
  const label =
    status === "open" ? "armed · live" : status === "connecting" ? "connecting" : "offline";
  return (
    <span className={`status status-${status}`}>
      <span className="dot" /> {label}
    </span>
  );
}

function Row({
  title,
  desc,
  value,
  tone,
}: {
  title: string;
  desc: string;
  value: React.ReactNode;
  tone?: "ac" | "warnv";
}) {
  return (
    <div className="row">
      <div className="meta">
        <div className="t">{title}</div>
        <div className="d">{desc}</div>
      </div>
      <div className={`val${tone ? ` ${tone}` : ""}`}>{value}</div>
    </div>
  );
}

function Group({
  color,
  label,
  children,
}: {
  color: string;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="group">
      <div className="grouphead">
        <span className="pin" style={{ background: color }} /> {label}
      </div>
      {children}
    </div>
  );
}

function ReceiptsPanel({ r }: { r: Receipts }) {
  const runLabel =
    r.run.status === "done" ? (r.run.haltedBy ? `done · ${r.run.haltedBy}` : "done") : r.run.status;
  return (
    <aside className="panel">
      <div className="phead">
        <div className="lbl">
          <span className="dot" /> receipts
        </div>
        <span className="tag">measured · not asserted</span>
      </div>
      <div className="rail">
        <Group color="var(--accent)" label="scope gate">
          <Row
            title="Gate state"
            desc="no LLM in the path — pass/fail"
            value={
              r.scope.armed ? (
                <span className="badge-armed">ARMED</span>
              ) : (
                <span className="badge-idle">idle</span>
              )
            }
          />
          <Row
            title="In scope"
            desc="host · path allowed"
            value={
              <>
                {r.scope.hosts}
                <span className="u"> h</span> · {r.scope.paths}
                <span className="u"> p</span>
              </>
            }
          />
          <Row
            title="Blocked"
            desc="out-of-scope refused"
            value={String(r.scope.blocked)}
            tone={r.scope.blocked > 0 ? "warnv" : "ac"}
          />
        </Group>

        <Group color="var(--med)" label="bifrost gateway">
          <Row
            title="Model calls"
            desc={r.bifrost.model ?? "llama-3.3-70b · Cloudflare"}
            value={String(r.bifrost.calls)}
          />
          <Row
            title="Spend"
            desc={r.bifrost.priceSource ?? "catalog-priced per token"}
            value={<>${r.bifrost.costUsd.toFixed(4)}</>}
          />
          <Row title="Cache hits" desc="x-bifrost-cache-hit" value={String(r.bifrost.cacheHits)} />
        </Group>

        <Group color="var(--lime)" label="tavily grounding">
          <Row title="CVEs retrieved" desc="live advisory search" value={String(r.tavily.cves)} />
          <Row
            title="Fresh"
            desc="post-cutoff advisories"
            value={String(r.tavily.fresh)}
            tone="ac"
          />
        </Group>

        <Group color="var(--accent)" label="run">
          <Row
            title="Findings"
            desc="confirmed with evidence"
            value={String(r.run.findings)}
            tone={r.run.findings > 0 ? "ac" : undefined}
          />
          <Row title="Steps" desc="to objective" value={String(r.run.steps)} />
          <Row
            title="Status"
            desc={r.run.objectiveReached ? "objective reached" : "deterministic stop reason"}
            value={runLabel}
            tone={r.run.objectiveReached ? "ac" : undefined}
          />
        </Group>
      </div>
    </aside>
  );
}

interface TickerItem {
  id: string;
  node: React.ReactNode;
}

function tickerItems(r: Receipts): TickerItem[] {
  const items: TickerItem[] = [];
  if (r.scope.armed)
    items.push({
      id: "scope",
      node: (
        <>
          scope <b>armed</b> · {r.scope.hosts}h / {r.scope.paths}p in bounds
        </>
      ),
    });
  if (r.scope.blocked > 0)
    items.push({
      id: "blocked",
      node: (
        <>
          <b>{r.scope.blocked}</b> out-of-scope request(s) refused
        </>
      ),
    });
  items.push({
    id: "spend",
    node: (
      <>
        model spend <b>${r.bifrost.costUsd.toFixed(4)}</b> across {r.bifrost.calls} call(s)
      </>
    ),
  });
  if (r.tavily.cves > 0)
    items.push({
      id: "tavily",
      node: (
        <>
          tavily <b>{r.tavily.cves}</b> CVE(s) · {r.tavily.fresh} fresh
        </>
      ),
    });
  if (r.run.findings > 0)
    items.push({
      id: "findings",
      node: (
        <>
          <b>{r.run.findings}</b> confirmed finding(s)
        </>
      ),
    });
  if (r.run.haltedBy)
    items.push({
      id: "halted",
      node: (
        <>
          halted on <b>{r.run.haltedBy}</b>
        </>
      ),
    });
  items.push({
    id: "gate",
    node: (
      <>
        no LLM in the scope gate — <b>pass/fail</b>, not persuasion
      </>
    ),
  });
  items.push({
    id: "frozen",
    node: (
      <>
        every receipt reproducible from <b>frozen input</b>
      </>
    ),
  });
  return items;
}

export function App() {
  const url = useMemo(socketUrl, []);
  const { status, trace, receipts } = useNightfallSocket(url);
  const [, toggleTheme] = useTheme();
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (trace.length === 0) return;
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [trace.length]);

  const items = useMemo(() => tickerItems(receipts), [receipts]);
  const target = receipts.run.target ?? "awaiting run";

  return (
    <div className="app">
      <header className="topbar">
        <div className="wrap">
          <div className="mark">
            <span className="n">
              night<b>fall</b>
            </span>
            <span className="cc">control centre</span>
          </div>
          <div className="right">
            <StatusChip status={status} />
            <button type="button" className="tbtn" onClick={toggleTheme}>
              theme
            </button>
          </div>
        </div>
      </header>

      <div className="wrap kickerrow">
        <div className="kicker">
          autonomous web-app pentest agent
          <span>·</span>
          <span className="hl">{target}</span>
          {receipts.run.objective ? (
            <>
              <span>·</span>
              <span className="hl">{receipts.run.objective}</span>
            </>
          ) : null}
        </div>
      </div>

      <main className="wrap layout">
        <section className="panel">
          <div className="phead">
            <div className="lbl">
              <span className="dot" /> live trace
            </div>
            <span className="tag">ws · {new URL(url).host}</span>
          </div>
          <div className="trace">
            {trace.length === 0 ? (
              <div className="empty">
                waiting for a run on <code>{url}</code>
                <br />
                start it with <code>nightfall serve --scope &lt;scope.yaml&gt;</code>
              </div>
            ) : (
              trace.map((item) => {
                const line = formatTrace(item);
                return (
                  <div className={`ln tone-${line.tone}`} key={item.seq}>
                    <span className="k">{line.tag}</span>
                    <span className="v line-text">{line.text}</span>
                  </div>
                );
              })
            )}
            <div ref={endRef} />
          </div>
        </section>

        <ReceiptsPanel r={receipts} />
      </main>

      <div className="ticker">
        <div className="track">
          {items.map((it) => (
            <span className="it" key={`a-${it.id}`}>
              {it.node}
            </span>
          ))}
          {items.map((it) => (
            <span className="it" key={`b-${it.id}`}>
              {it.node}
            </span>
          ))}
        </div>
      </div>

      <div className="wrap foot">
        <span>
          Nightfall — autonomous web-app pentest agent. Runs only against authorized, isolated labs.
        </span>
        <span className="em">built to stay in bounds · with love, caffeine &amp; tokens</span>
      </div>
    </div>
  );
}
