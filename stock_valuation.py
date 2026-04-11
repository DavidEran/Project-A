#!/usr/bin/env python3
"""
Stock Valuation Calculator
Fundamental analysis tool with Gemini-powered field hints.

Run:
    streamlit run stock_valuation.py
"""

import json
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import yfinance as yf

# ── Optional Gemini support ───────────────────────────────────────────────────
try:
    from google import genai as google_genai

    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

SAVE_FILE = Path(__file__).parent / "saved_analyses.json"

# ─────────────────────────────────────────────────────────────────────────────
# Page config
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Stock Valuation Calculator",
    page_icon="📈",
    layout="wide",
)

st.markdown(
    """
<style>
.scenario-card {
    border-radius: 12px;
    padding: 18px;
    margin: 6px 0;
    text-align: center;
}
.low-card  { background: rgba(239,68,68,0.08);  border: 1px solid rgba(239,68,68,0.35); }
.base-card { background: rgba(251,146,60,0.08); border: 1px solid rgba(251,146,60,0.35); }
.high-card { background: rgba(34,197,94,0.08);  border: 1px solid rgba(34,197,94,0.35); }
.hint-box {
    font-size: 0.76rem;
    color: #94a3b8;
    background: rgba(148,163,184,0.07);
    border-left: 2px solid #475569;
    padding: 4px 8px;
    border-radius: 0 6px 6px 0;
    margin: -8px 0 14px 0;
}
</style>
""",
    unsafe_allow_html=True,
)


# ─────────────────────────────────────────────────────────────────────────────
# Data helpers
# ─────────────────────────────────────────────────────────────────────────────
def fetch_stock_data(ticker: str) -> dict:
    t = yf.Ticker(ticker)
    info = t.info or {}

    # ── Historical revenue CAGR ──
    revenue_cagr = None
    try:
        fin = t.financials
        if fin is not None and not fin.empty and "Total Revenue" in fin.index:
            rev_series = fin.loc["Total Revenue"].dropna().sort_index(ascending=True)
            if len(rev_series) >= 2:
                oldest, newest = rev_series.iloc[0], rev_series.iloc[-1]
                n = len(rev_series) - 1
                if oldest > 0:
                    revenue_cagr = (newest / oldest) ** (1 / n) - 1
    except Exception:
        pass

    # ── Analyst 5-year EPS growth estimate ──
    analyst_growth = None
    try:
        ge = t.growth_estimates
        if ge is not None and not ge.empty:
            col = ticker.upper()
            if col in ge.columns and "5y" in ge.index:
                val = ge.loc["5y", col]
                if pd.notna(val):
                    analyst_growth = float(val)
    except Exception:
        pass

    # ── Historical net margins ──
    net_margins = []
    try:
        fin = t.financials
        if fin is not None and not fin.empty:
            if "Net Income" in fin.index and "Total Revenue" in fin.index:
                ni = fin.loc["Net Income"]
                rv = fin.loc["Total Revenue"]
                for col in fin.columns:
                    if pd.notna(ni.get(col)) and pd.notna(rv.get(col)) and rv[col] > 0:
                        net_margins.append(float(ni[col] / rv[col]))
    except Exception:
        pass

    safe_float = lambda v, default=None: (
        float(v) if v is not None and not (isinstance(v, float) and v != v) else default
    )

    return {
        "name": info.get("longName", ticker.upper()),
        "ticker": ticker.upper(),
        "current_price": safe_float(
            info.get("currentPrice") or info.get("regularMarketPrice")
        ),
        "shares_outstanding": safe_float(info.get("sharesOutstanding"), 0) / 1e9,
        "market_cap": safe_float(info.get("marketCap"), 0) / 1e9,
        "ttm_revenue": safe_float(info.get("totalRevenue"), 0) / 1e9,
        "pe_ratio": safe_float(info.get("trailingPE")),
        "forward_pe": safe_float(info.get("forwardPE")),
        "revenue_cagr_3yr": revenue_cagr,
        "analyst_growth_5yr": analyst_growth,
        "current_net_margin": net_margins[0] if net_margins else None,
        "avg_net_margin_3yr": (
            sum(net_margins[:3]) / len(net_margins[:3]) if net_margins else None
        ),
        "sector": info.get("sector", ""),
        "industry": info.get("industry", ""),
    }


def get_gemini_hints(stock_data: dict, api_key: str) -> dict:
    client = google_genai.Client(api_key=api_key)

    pe = stock_data.get("pe_ratio")
    fpe = stock_data.get("forward_pe")
    cagr = stock_data.get("revenue_cagr_3yr")
    margin = stock_data.get("current_net_margin")
    avg_margin = stock_data.get("avg_net_margin_3yr")
    ag = stock_data.get("analyst_growth_5yr")

    prompt = f"""You are a concise financial analyst.

Stock: {stock_data['name']} ({stock_data['ticker']})
Sector: {stock_data.get('sector', 'N/A')} | Industry: {stock_data.get('industry', 'N/A')}
Current Price: ${stock_data.get('current_price', 'N/A')}
TTM Revenue: ${stock_data.get('ttm_revenue', 0):.1f}B
3-yr Revenue CAGR: {f"{cagr*100:.1f}%" if cagr else "N/A"}
Analyst 5yr EPS growth: {f"{ag*100:.1f}%" if ag else "N/A"}
TTM Net Margin: {f"{margin*100:.1f}%" if margin else "N/A"}
3-yr Avg Net Margin: {f"{avg_margin*100:.1f}%" if avg_margin else "N/A"}
Trailing P/E: {pe or "N/A"} | Forward P/E: {fpe or "N/A"}

Write a SHORT hint (max 15 words) for each input field a user will fill in.
Be specific, cite the data above where relevant.

Respond ONLY with valid JSON (no markdown):
{{"growth_rate":"...", "margin":"...", "pe_low":"...", "pe_base":"...", "pe_high":"..."}}"""

    response = client.models.generate_content(
        model="gemini-2.0-flash", contents=prompt
    )
    text = response.text.strip()
    # Strip possible markdown fences
    if "```" in text:
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.split("```")[0].strip()
    return json.loads(text)


def hint(text: str):
    """Render a styled hint box."""
    if text:
        st.markdown(
            f'<div class="hint-box">💡 {text}</div>', unsafe_allow_html=True
        )


# ─────────────────────────────────────────────────────────────────────────────
# Calculation helpers
# ─────────────────────────────────────────────────────────────────────────────
def build_forecast(base_rev: float, growth: float, margin: float, start_year: int, n: int):
    rows = []
    for i in range(n + 1):
        rev = base_rev * (1 + growth / 100) ** i
        profit = rev * margin / 100
        rows.append({"Year": start_year + i, "Revenue ($B)": rev, "Margin (%)": margin, "Profit ($B)": profit})
    return rows


def build_scenarios(final_profit, pe_low, pe_base, pe_high, shares, current_price, n_years):
    out = {}
    for label, pe in [("Low", pe_low), ("Base", pe_base), ("High", pe_high)]:
        mkt_cap = final_profit * pe
        tp = mkt_cap / shares if shares > 0 else 0
        cagr = (tp / current_price) ** (1 / n_years) - 1 if current_price > 0 and n_years > 0 else 0
        out[label] = {"pe": pe, "market_cap": mkt_cap, "target_price": tp, "annual_return": cagr * 100}
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Persistence
# ─────────────────────────────────────────────────────────────────────────────
def load_analyses() -> dict:
    if SAVE_FILE.exists():
        try:
            return json.loads(SAVE_FILE.read_text())
        except Exception:
            return {}
    return {}


def save_analysis(ticker, inputs, forecast, scenarios):
    data = load_analyses()
    data[ticker] = {
        "ticker": ticker,
        "saved_at": datetime.now().isoformat(),
        "inputs": inputs,
        "forecast": forecast,
        "scenarios": scenarios,
    }
    SAVE_FILE.write_text(json.dumps(data, indent=2))


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Settings")
    gemini_key = st.text_input(
        "Gemini API Key (optional)",
        type="password",
        help="Enables AI-powered hints for each input field",
    )
    if not GEMINI_AVAILABLE:
        st.caption("Install `google-genai` to enable Gemini hints.")

    st.divider()
    st.header("💾 Saved Analyses")
    analyses = load_analyses()
    if analyses:
        for saved_ticker, saved_data in analyses.items():
            c1, c2 = st.columns([3, 1])
            c1.write(f"**{saved_ticker}** — {saved_data['saved_at'][:10]}")
            if c2.button("Load", key=f"load_{saved_ticker}"):
                st.session_state["load_request"] = saved_ticker
    else:
        st.caption("No saved analyses yet.")

# ─────────────────────────────────────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────────────────────────────────────
st.title("📈 Stock Valuation Calculator")
st.caption(
    "Enter your assumptions → get revenue forecast + target price scenarios (Low / Base / High)."
)

# ─────────────────────────────────────────────────────────────────────────────
# Ticker fetch bar
# ─────────────────────────────────────────────────────────────────────────────
tc, bc = st.columns([4, 1])
with tc:
    ticker_input = st.text_input(
        "Ticker", placeholder="e.g. GOOG, AAPL, MSFT, NVDA", label_visibility="collapsed"
    )
with bc:
    fetch_clicked = st.button("🔍 Fetch", use_container_width=True)

# ── Handle fetch ──────────────────────────────────────────────────────────────
if fetch_clicked and ticker_input.strip():
    with st.spinner(f"Fetching {ticker_input.upper()}…"):
        try:
            st.session_state["stock"] = fetch_stock_data(ticker_input.strip())
            st.session_state["hints"] = {}
            st.session_state["prefill"] = {}
        except Exception as exc:
            st.error(f"Could not fetch {ticker_input.upper()}: {exc}")

    if gemini_key and GEMINI_AVAILABLE and "stock" in st.session_state:
        with st.spinner("Getting Gemini hints…"):
            try:
                st.session_state["hints"] = get_gemini_hints(
                    st.session_state["stock"], gemini_key
                )
            except Exception as exc:
                st.warning(f"Gemini hints unavailable: {exc}")

# ── Handle load from sidebar ──────────────────────────────────────────────────
if "load_request" in st.session_state:
    req = st.session_state.pop("load_request")
    if req in analyses:
        saved = analyses[req]
        st.session_state["stock"] = {
            "ticker": req,
            "name": req,
            "current_price": None,
            "shares_outstanding": 0,
            "market_cap": 0,
            "ttm_revenue": 0,
            "pe_ratio": None,
            "forward_pe": None,
            "revenue_cagr_3yr": None,
            "analyst_growth_5yr": None,
            "current_net_margin": None,
            "avg_net_margin_3yr": None,
            "sector": "",
            "industry": "",
        }
        st.session_state["hints"] = {}
        st.session_state["prefill"] = saved["inputs"]

# ─────────────────────────────────────────────────────────────────────────────
# Main panel — only shown after a stock is loaded
# ─────────────────────────────────────────────────────────────────────────────
if "stock" not in st.session_state:
    st.info("Enter a ticker above and click Fetch to get started.")
    st.stop()

stock: dict = st.session_state["stock"]
hints: dict = st.session_state.get("hints", {})
prefill: dict = st.session_state.get("prefill", {})

st.divider()
st.subheader(f"{stock['name']} ({stock['ticker']})")
if stock.get("sector"):
    st.caption(f"📍 {stock['sector']}  ·  {stock.get('industry', '')}")

left, right = st.columns([5, 7], gap="large")

# ─────────────────────────────────────────────────────────────────────────────
# LEFT — Inputs
# ─────────────────────────────────────────────────────────────────────────────
with left:
    st.markdown("### 🎛️ Assumptions")

    # ── Current Price ──
    default_price = prefill.get("current_price") or stock.get("current_price") or 100.0
    current_price = st.number_input(
        "Current Price ($)",
        min_value=0.01,
        value=float(round(default_price, 2)),
        step=0.5,
        help="Current market price per share — your entry point.",
    )
    if stock.get("current_price"):
        hint(f"Market price: ${stock['current_price']:.2f}")

    # ── Shares Outstanding ──
    default_shares = prefill.get("shares") or stock.get("shares_outstanding") or 1.0
    shares = st.number_input(
        "Shares Outstanding (B)",
        min_value=0.001,
        value=float(round(default_shares, 3)),
        step=0.01,
        format="%.3f",
        help="Total diluted shares outstanding in billions — used to convert market cap to per-share price.",
    )
    mkt_hint = ""
    if stock.get("shares_outstanding"):
        mkt_hint = f"{stock['shares_outstanding']:.2f}B diluted shares"
        if stock.get("market_cap"):
            mkt_hint += f"  |  Mkt Cap: ${stock['market_cap']:.0f}B"
    if mkt_hint:
        hint(mkt_hint)

    # ── Base Revenue ──
    default_rev = prefill.get("base_revenue") or stock.get("ttm_revenue") or 10.0
    base_revenue = st.number_input(
        "Base Revenue ($B)",
        min_value=0.01,
        value=float(round(default_rev, 2)),
        step=1.0,
        help="Starting revenue for the forecast — typically TTM or latest FY revenue.",
    )
    if stock.get("ttm_revenue"):
        hint(f"TTM Revenue: ${stock['ttm_revenue']:.1f}B")

    # ── Revenue Growth Rate ──
    cagr_val = stock.get("revenue_cagr_3yr")
    ag_val = stock.get("analyst_growth_5yr")
    default_growth = prefill.get("growth_rate") or (cagr_val * 100 if cagr_val else 10.0)

    growth_hint_text = hints.get("growth_rate", "")
    if not growth_hint_text:
        parts = []
        if cagr_val:
            parts.append(f"3-yr Revenue CAGR: {cagr_val*100:.1f}%")
        if ag_val:
            parts.append(f"Analyst 5yr EPS est: {ag_val*100:.1f}%")
        growth_hint_text = "  |  ".join(parts)

    growth_rate = st.number_input(
        "Revenue Growth Rate (% / yr)",
        min_value=0.0,
        max_value=200.0,
        value=float(round(default_growth, 1)),
        step=0.5,
        help=growth_hint_text or "Your projected annual revenue growth rate.",
    )
    hint(growth_hint_text)

    # ── Net Margin ──
    cur_margin = stock.get("current_net_margin")
    avg_margin = stock.get("avg_net_margin_3yr")
    default_margin = prefill.get("margin") or (cur_margin * 100 if cur_margin else 20.0)

    margin_hint_text = hints.get("margin", "")
    if not margin_hint_text:
        parts = []
        if cur_margin:
            parts.append(f"TTM Net Margin: {cur_margin*100:.1f}%")
        if avg_margin:
            parts.append(f"3-yr avg: {avg_margin*100:.1f}%")
        margin_hint_text = "  |  ".join(parts)

    margin = st.number_input(
        "Net Profit Margin (%)",
        min_value=0.0,
        max_value=100.0,
        value=float(round(default_margin, 1)),
        step=0.5,
        help=margin_hint_text or "Net profit as % of revenue at the target year.",
    )
    hint(margin_hint_text)

    # ── Projection Years ──
    start_year = datetime.now().year
    n_years = st.slider("Projection Years", 1, 10, int(prefill.get("n_years", 5)))
    target_year = start_year + n_years
    st.caption(f"Forecast: {start_year} → {target_year}")

    st.markdown("---")
    st.markdown("**Valuation Multiples (P/E)**")

    pe_ratio = stock.get("pe_ratio")
    fwd_pe = stock.get("forward_pe")
    pe_hint_text = ""
    if pe_ratio:
        pe_hint_text = f"Trailing P/E: {pe_ratio:.1f}"
        if fwd_pe:
            pe_hint_text += f"  |  Fwd P/E: {fwd_pe:.1f}"

    default_pe_low  = int(prefill.get("pe_low",  20))
    default_pe_base = int(prefill.get("pe_base", 25))
    default_pe_high = int(prefill.get("pe_high", 30))

    pe_low = st.number_input(
        "Low Multiple",
        min_value=1,
        value=default_pe_low,
        help=hints.get("pe_low") or "Conservative scenario — what the market might assign in a pessimistic outlook.",
    )
    pe_base = st.number_input(
        "Base Multiple",
        min_value=1,
        value=default_pe_base,
        help=hints.get("pe_base") or "Fair-value scenario — typical multiple for this sector/quality.",
    )
    pe_high = st.number_input(
        "High Multiple",
        min_value=1,
        value=default_pe_high,
        help=hints.get("pe_high") or "Optimistic scenario — premium multiple if growth exceeds expectations.",
    )
    if pe_hint_text:
        hint(pe_hint_text)

# ─────────────────────────────────────────────────────────────────────────────
# RIGHT — Results
# ─────────────────────────────────────────────────────────────────────────────
with right:
    if base_revenue <= 0 or shares <= 0 or current_price <= 0:
        st.info("Complete the inputs on the left to see the forecast.")
        st.stop()

    forecast_rows = build_forecast(base_revenue, growth_rate, margin, start_year, n_years)
    final_profit = forecast_rows[-1]["Profit ($B)"]
    scenarios = build_scenarios(final_profit, pe_low, pe_base, pe_high, shares, current_price, n_years)

    # ── Forecast table ────────────────────────────────────────
    st.markdown("### 📊 Revenue & Profit Forecast")
    df_display = pd.DataFrame(forecast_rows).set_index("Year")
    df_display["Revenue ($B)"] = df_display["Revenue ($B)"].map("{:.2f}".format)
    df_display["Margin (%)"]   = df_display["Margin (%)"].map("{:.1f}%".format)
    df_display["Profit ($B)"]  = df_display["Profit ($B)"].map("{:.2f}".format)
    st.dataframe(df_display, use_container_width=True)

    # ── Revenue + Profit bar chart ────────────────────────────
    raw_years   = [r["Year"]          for r in forecast_rows]
    raw_revs    = [r["Revenue ($B)"]  for r in forecast_rows]
    raw_profits = [r["Profit ($B)"]   for r in forecast_rows]

    fig_rev = go.Figure()
    fig_rev.add_trace(go.Bar(x=raw_years, y=raw_revs,    name="Revenue", marker_color="#3b82f6", opacity=0.65))
    fig_rev.add_trace(go.Bar(x=raw_years, y=raw_profits, name="Profit",  marker_color="#22c55e", opacity=0.9))
    fig_rev.update_layout(
        barmode="overlay",
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        legend=dict(orientation="h", y=1.1),
        margin=dict(t=10, b=10, l=0, r=0),
        height=230,
        yaxis_title="$B",
        xaxis=dict(tickmode="linear", dtick=1),
    )
    st.plotly_chart(fig_rev, use_container_width=True)

    # ── Scenario cards ────────────────────────────────────────
    st.markdown("### 🎯 Target Price Scenarios")
    card_meta = {
        "Low":  ("🔴", "low"),
        "Base": ("🟠", "base"),
        "High": ("🟢", "high"),
    }
    c_low, c_base, c_high = st.columns(3)
    for col, (label, (emoji, css)) in zip(
        [c_low, c_base, c_high], card_meta.items()
    ):
        d = scenarios[label]
        ret_color = "#22c55e" if d["annual_return"] >= 0 else "#ef4444"
        ret_str = f"{'+'if d['annual_return']>=0 else ''}{d['annual_return']:.1f}%"
        with col:
            st.markdown(
                f"""
<div class="scenario-card {css}-card">
  <div style="font-weight:700;font-size:1rem;margin-bottom:10px">{emoji} {label}</div>
  <div style="color:#94a3b8;font-size:0.72rem">P/E Multiple</div>
  <div style="font-size:1.3rem;font-weight:700">{d['pe']}x</div>
  <br>
  <div style="color:#94a3b8;font-size:0.72rem">Target Price</div>
  <div style="font-size:1.5rem;font-weight:800">${d['target_price']:.1f}</div>
  <br>
  <div style="color:#94a3b8;font-size:0.72rem">Est. Market Cap</div>
  <div style="font-weight:600">${d['market_cap']:.0f}B</div>
  <br>
  <div style="color:#94a3b8;font-size:0.72rem">Annual Return</div>
  <div style="font-size:1.2rem;font-weight:700;color:{ret_color}">{ret_str}</div>
</div>
""",
                unsafe_allow_html=True,
            )

    # ── Price target range chart ──────────────────────────────
    st.markdown("### 📉 Price Target Range")
    labels = list(scenarios.keys())
    prices = [scenarios[s]["target_price"] for s in labels]
    colors = ["#ef4444", "#f97316", "#22c55e"]

    fig_tp = go.Figure()
    fig_tp.add_trace(
        go.Bar(
            x=labels,
            y=prices,
            marker_color=colors,
            text=[f"${p:.1f}" for p in prices],
            textposition="outside",
        )
    )
    fig_tp.add_hline(
        y=current_price,
        line_dash="dash",
        line_color="#94a3b8",
        annotation_text=f"  Current ${current_price:.1f}",
        annotation_position="right",
    )
    fig_tp.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(t=30, b=10, l=0, r=80),
        height=280,
        yaxis_title="Price ($)",
        showlegend=False,
    )
    st.plotly_chart(fig_tp, use_container_width=True)

    # ── Save ──────────────────────────────────────────────────
    if st.button("💾 Save Analysis", use_container_width=True):
        inputs_snapshot = {
            "current_price": current_price,
            "shares": shares,
            "base_revenue": base_revenue,
            "growth_rate": growth_rate,
            "margin": margin,
            "n_years": n_years,
            "pe_low": int(pe_low),
            "pe_base": int(pe_base),
            "pe_high": int(pe_high),
        }
        save_analysis(stock["ticker"], inputs_snapshot, forecast_rows, scenarios)
        st.success(f"✅ Saved analysis for {stock['ticker']}")
        st.rerun()

# ─────────────────────────────────────────────────────────────────────────────
# Comparison section
# ─────────────────────────────────────────────────────────────────────────────
analyses = load_analyses()
if len(analyses) >= 2:
    st.divider()
    with st.expander("⚖️ Compare Saved Analyses", expanded=False):
        selected = st.multiselect(
            "Select stocks to compare",
            list(analyses.keys()),
            default=list(analyses.keys())[:4],
        )
        if selected:
            comp_cols = st.columns(len(selected))
            for col, ticker_key in zip(comp_cols, selected):
                saved = analyses[ticker_key]
                inp = saved["inputs"]
                sc = saved["scenarios"]
                with col:
                    st.markdown(f"#### {ticker_key}")
                    st.caption(saved["saved_at"][:10])
                    st.metric("Growth Rate", f"{inp.get('growth_rate', 0):.1f}%/yr")
                    st.metric("Margin",      f"{inp.get('margin', 0):.1f}%")
                    st.markdown("**Target Prices**")
                    for scenario_label, sdata in sc.items():
                        ret = sdata["annual_return"]
                        st.metric(
                            label=f"{scenario_label} ({sdata['pe']}x P/E)",
                            value=f"${sdata['target_price']:.1f}",
                            delta=f"{'+'if ret>=0 else ''}{ret:.1f}%/yr",
                        )

            # Side-by-side target price chart
            fig_comp = go.Figure()
            bar_colors_comp = ["#ef4444", "#f97316", "#22c55e"]
            for sc_label, bar_color in zip(["Low", "Base", "High"], bar_colors_comp):
                fig_comp.add_trace(
                    go.Bar(
                        name=sc_label,
                        x=selected,
                        y=[analyses[t]["scenarios"][sc_label]["target_price"] for t in selected],
                        marker_color=bar_color,
                        opacity=0.85,
                    )
                )
            fig_comp.update_layout(
                barmode="group",
                plot_bgcolor="rgba(0,0,0,0)",
                paper_bgcolor="rgba(0,0,0,0)",
                legend=dict(orientation="h"),
                margin=dict(t=10, b=10),
                height=300,
                yaxis_title="Target Price ($)",
            )
            st.plotly_chart(fig_comp, use_container_width=True)
