//! `top` live dashboard (ratatui) and `serve` (Prometheus /metrics + a small HTML page).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::prelude::*;
use ratatui::widgets::{Bar, BarChart, BarGroup, Block, Borders, Paragraph, Row, Table};
use segfault_core::maps::is_loaded;
use segfault_core::stats::{ObsStats, Stats};

/// Runs the full-screen live counter view until 'q' or Esc.
pub fn top() -> Result<()> {
    if !is_loaded() {
        bail!("datapath not attached; run `segfault up` first");
    }
    enable_raw_mode()?;
    let mut out = std::io::stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    let mut term = Terminal::new(backend)?;
    let mut prev = Stats::read().unwrap_or_default();
    let res = run_top(&mut term, &mut prev);
    disable_raw_mode().ok();
    execute!(term.backend_mut(), LeaveAlternateScreen).ok();
    term.show_cursor().ok();
    res
}

/// Draw/poll loop for `top`.
fn run_top<B: Backend>(term: &mut Terminal<B>, prev: &mut Stats) -> Result<()> {
    loop {
        let s = Stats::read().unwrap_or_default();
        let o = ObsStats::read().unwrap_or_default();
        let admit = s.admitted();
        let block = s.blocked();
        let total = (admit + block).max(1);
        // Per-second deltas since the last frame.
        let d_admit = s.admitted().saturating_sub(prev.admitted());
        let d_block = s.blocked().saturating_sub(prev.blocked());
        *prev = s.clone();

        term.draw(|f| {
            let area = f.area();
            let rows = Layout::vertical([
                Constraint::Length(3),
                Constraint::Length(9),
                Constraint::Min(6),
                Constraint::Length(1),
            ])
            .split(area);

            let pct = 100.0 * admit as f64 / total as f64;
            let header = Paragraph::new(format!(
                "Segfault — admitted {admit} ({pct:.1}%)   blocked {block}   Δadmit {d_admit}/f  Δblock {d_block}/f"
            ))
            .block(Block::default().borders(Borders::ALL).title(" segfault top "));
            f.render_widget(header, rows[0]);

            let tiers = BarChart::default()
                .block(Block::default().borders(Borders::ALL).title(" queries by tier "))
                .bar_width(9)
                .data(BarGroup::default().bars(&[
                    Bar::default().label(Line::from("T0 unk")).value(s.get("queries_t0")),
                    Bar::default().label(Line::from("T1 ret")).value(s.get("queries_t1")),
                    Bar::default().label(Line::from("T2 prv")).value(s.get("queries_t2")),
                ]));
            f.render_widget(tiers, rows[1]);

            let drops = [
                ("source", s.get("drop_source")), ("prefix", s.get("drop_prefix")),
                ("pool", s.get("drop_pool")), ("heavy", s.get("drop_heavy")),
                ("banned", s.get("drop_banned")), ("slip (TX)", s.get("tx_slip")),
                ("cookie ok", s.get("cookie_ok")), ("promote T1", s.get("promote_t1")),
                ("nxdomain%", (o.nxdomain_ratio() * 100.0) as u64),
                ("tcp proofs", o.get("proofs")),
            ];
            let trows: Vec<Row> = drops
                .iter()
                .map(|(k, v)| Row::new(vec![k.to_string(), v.to_string()]))
                .collect();
            let table = Table::new(trows, [Constraint::Length(14), Constraint::Min(8)])
                .block(Block::default().borders(Borders::ALL).title(" reasons "));
            f.render_widget(table, rows[2]);

            f.render_widget(Paragraph::new("q / Esc to quit").style(Style::new().dim()), rows[3]);
        }).map_err(|e| anyhow::anyhow!("draw: {e}"))?;

        if event::poll(Duration::from_millis(500)).map_err(|e| anyhow::anyhow!("{e}"))?
            && let Event::Key(k) = event::read().map_err(|e| anyhow::anyhow!("{e}"))?
            && matches!(k.code, KeyCode::Char('q') | KeyCode::Esc)
        {
            return Ok(());
        }
    }
}

/// Serves Prometheus metrics at /metrics and a tiny auto-refreshing HTML page at / on localhost.
pub fn serve(port: u16) -> Result<()> {
    if !is_loaded() {
        bail!("datapath not attached");
    }
    let listener =
        TcpListener::bind(("127.0.0.1", port)).with_context(|| format!("bind 127.0.0.1:{port}"))?;
    println!("serving metrics on http://127.0.0.1:{port}/ (Ctrl-C to stop)");
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]);
        let path = req.split_whitespace().nth(1).unwrap_or("/");
        let (ctype, body) = if path.starts_with("/metrics") {
            ("text/plain; version=0.0.4", metrics_text())
        } else {
            ("text/html; charset=utf-8", dashboard_html(port))
        };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes());
    }
    Ok(())
}

/// Renders the counters in Prometheus exposition format.
fn metrics_text() -> String {
    let s = Stats::read().unwrap_or_default();
    let o = ObsStats::read().unwrap_or_default();
    let mut out = String::new();
    out.push_str("# HELP segfault_queries_total DNS queries seen by tier and reason.\n");
    out.push_str("# TYPE segfault_queries_total counter\n");
    for name in segfault_core::stats::REASONS {
        out.push_str(&format!(
            "segfault_ingress_total{{reason=\"{name}\"}} {}\n",
            s.get(name)
        ));
    }
    for name in segfault_core::stats::OBS {
        out.push_str(&format!(
            "segfault_egress_total{{kind=\"{name}\"}} {}\n",
            o.get(name)
        ));
    }
    out.push_str(&format!("segfault_admitted_total {}\n", s.admitted()));
    out.push_str(&format!("segfault_blocked_total {}\n", s.blocked()));
    out.push_str(&format!(
        "segfault_nxdomain_ratio {:.4}\n",
        o.nxdomain_ratio()
    ));
    out
}

/// A minimal self-refreshing HTML dashboard that reads /metrics.
fn dashboard_html(_port: u16) -> String {
    r#"<!doctype html><html><head><meta charset=utf-8><title>Segfault</title>
<style>body{font-family:system-ui;margin:2rem;background:#0f1115;color:#e6e6e6}
h1{font-size:1.2rem}table{border-collapse:collapse}td{padding:.2rem .8rem;border-bottom:1px solid #222}
.n{text-align:right;font-variant-numeric:tabular-nums}</style></head><body>
<h1>Segfault — live</h1><div id=app>loading…</div>
<script>async function tick(){
let t=await (await fetch('/metrics?'+Date.now())).text();let m={};
t.split('\n').forEach(l=>{let x=l.match(/^(segfault_[a-z_]+)(?:{[^}]*reason="([a-z0-9_]+)"|{[^}]*kind="([a-z0-9_]+)")?}?\s+([0-9.]+)/);
if(x)m[(x[2]||x[3]||x[1])]=x[4];});
let rows=[['Admitted',m['segfault_admitted_total']],['Blocked',m['segfault_blocked_total']],
['T0 unknown',m['queries_t0']],['T1 returning',m['queries_t1']],['T2 proven',m['queries_t2']],
['Drops: source',m['drop_source']],['Drops: prefix',m['drop_prefix']],['Drops: pool',m['drop_pool']],
['Drops: heavy',m['drop_heavy']],['Slips (TX)',m['tx_slip']],['Cookie OK',m['cookie_ok']],
['TCP proofs',m['proofs']],['NXDOMAIN ratio',m['segfault_nxdomain_ratio']]];
document.getElementById('app').innerHTML='<table>'+rows.map(r=>'<tr><td>'+r[0]+'</td><td class=n>'+(r[1]||'0')+'</td></tr>').join('')+'</table>';
}tick();setInterval(tick,1000);</script></body></html>"#
        .to_string()
}
