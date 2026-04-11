#!/usr/bin/env python3
"""
Stock Valuation Calculator — FMP + Gemini
Run: streamlit run stock_valuation.py
"""

import html as html_mod
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st

try:
    from google import genai as google_genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

SAVE_FILE  = Path(__file__).parent / "saved_analyses.json"
FMP_STABLE = "https://financialmodelingprep.com/stable"
FMP_V3     = "https://financialmodelingprep.com/api/v3"


def _load_toml_secrets() -> dict:
    """Read .streamlit/secrets.toml directly — no st.secrets dependency."""
    path = Path(__file__).parent / ".streamlit" / "secrets.toml"
    if not path.exists():
        return {}
    try:
        import tomllib
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception as e:
        logger.warning("Could not load secrets.toml: %s", e)
        return {}

_SECRETS = _load_toml_secrets()


def get_secret(key: str) -> str:
    """Load from secrets.toml → env var → empty string."""
    return str(_SECRETS.get(key) or os.environ.get(key, ""))

# ─────────────────────────────────────────────────────────────────────────────
# Page config + CSS
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="Stock Valuation", page_icon="📈", layout="wide")

st.markdown("""
<style>
/* ── global ── */
[data-testid="stAppViewContainer"] { background: #0d1117; }
[data-testid="stSidebar"]          { background: #161b22; border-right: 1px solid #30363d; }
section.main > div                 { padding-top: 1.5rem; }

/* ── company header card ── */
.stock-header {
    background: linear-gradient(135deg, #1c2333 0%, #161b22 100%);
    border: 1px solid #30363d;
    border-radius: 14px;
    padding: 20px 26px;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 18px;
}
.stock-header img  { width: 52px; height: 52px; border-radius: 10px; object-fit: contain; background:#fff; padding:4px; }
.stock-header h2   { margin: 0; font-size: 1.35rem; color: #e6edf3; }
.stock-header span { font-size: 0.8rem; color: #8b949e; }
.sector-badge {
    display: inline-block;
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 20px;
    padding: 2px 10px;
    font-size: 0.73rem;
    color: #8b949e;
    margin-left: 6px;
}

/* ── metric pills (top row) ── */
.metric-row { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
.metric-pill {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 10px 18px;
    min-width: 120px;
    flex: 1;
}
.metric-pill .label { font-size: 0.7rem; color: #8b949e; margin-bottom: 4px; }
.metric-pill .value { font-size: 1.15rem; font-weight: 700; color: #e6edf3; }

/* ── section headers ── */
.section-title {
    font-size: 0.78rem;
    font-weight: 600;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: .08em;
    margin: 18px 0 10px;
    border-bottom: 1px solid #21262d;
    padding-bottom: 6px;
}

/* ── hint boxes ── */
.hint-box {
    font-size: 0.72rem;
    color: #8b949e;
    background: #161b22;
    border-left: 2px solid #388bfd;
    padding: 4px 10px;
    border-radius: 0 6px 6px 0;
    margin: -6px 0 14px;
}

/* ── scenario cards ── */
.sc-card {
    border-radius: 12px;
    padding: 20px 16px;
    text-align: center;
    height: 100%;
}
.sc-low  { background: rgba(248,81,73,.08);  border: 1px solid rgba(248,81,73,.35); }
.sc-base { background: rgba(210,153,34,.08); border: 1px solid rgba(210,153,34,.35); }
.sc-high { background: rgba(63,185,80,.08);  border: 1px solid rgba(63,185,80,.35); }
.sc-card .sc-label  { font-size: 0.75rem; color: #8b949e; margin-bottom: 2px; }
.sc-card .sc-value  { font-size: 1.3rem; font-weight: 800; color: #e6edf3; }
.sc-card .sc-sub    { font-size: 0.9rem; font-weight: 600; color: #e6edf3; }
.sc-card .sc-return { font-size: 1.1rem; font-weight: 700; }
.sc-card hr         { border-color: #30363d; margin: 10px 0; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# FMP helpers
# ─────────────────────────────────────────────────────────────────────────────
def _fmp_request(url: str, key: str, params: dict) -> any:
    p = dict(params)
    p["apikey"] = key
    r = requests.get(url, params=p, timeout=12)
    r.raise_for_status()
    data = r.json()
    if isinstance(data, dict) and ("Error Message" in data or "message" in data):
        msg = data.get("Error Message") or data.get("message", "Unknown FMP error")
        raise ValueError(msg)
    return data


def fetch_stock_data(ticker: str, api_key: str) -> dict:
    ticker = ticker.upper().strip()

    # Try stable API first (new FMP format), fall back to v3
    profile_list = income = analyst = None
    try:
        profile_list = _fmp_request(f"{FMP_STABLE}/profile",
                                    api_key, {"symbol": ticker})
        income       = _fmp_request(f"{FMP_STABLE}/income-statement",
                                    api_key, {"symbol": ticker, "period": "annual", "limit": 4})
        try:
            analyst  = _fmp_request(f"{FMP_STABLE}/analyst-estimates",
                                    api_key, {"symbol": ticker, "period": "annual", "limit": 5})
        except (requests.exceptions.RequestException, ValueError):
            analyst = []
    except (requests.exceptions.RequestException, ValueError):
        # Fall back to legacy v3 (ticker in path)
        profile_list = _fmp_request(f"{FMP_V3}/profile/{ticker}",      api_key, {})
        income       = _fmp_request(f"{FMP_V3}/income-statement/{ticker}", api_key, {"limit": 4})
        try:
            analyst  = _fmp_request(f"{FMP_V3}/analyst-estimates/{ticker}", api_key, {"limit": 5})
        except (requests.exceptions.RequestException, ValueError):
            analyst = []

    if not profile_list:
        raise ValueError(f"Ticker {ticker} not found.")
    p = profile_list[0]

    # Revenue CAGR from income statements
    revenue_cagr = None
    revenues = [r["revenue"] for r in income if r.get("revenue")]
    if len(revenues) >= 2:
        oldest, newest = revenues[-1], revenues[0]
        n = len(revenues) - 1
        if oldest > 0:
            revenue_cagr = (newest / oldest) ** (1 / n) - 1

    # Analyst revenue growth (CAGR across estimate years)
    analyst_rev_growth = None
    est_revs = [a.get("estimatedRevenueAvg", 0) for a in analyst if a.get("estimatedRevenueAvg")]
    if len(est_revs) >= 2:
        r0, r1 = est_revs[-1], est_revs[0]
        if r0 > 0:
            analyst_rev_growth = (r1 / r0) ** (1 / (len(est_revs) - 1)) - 1

    # Net margins
    margins = []
    for row in income:
        rev, ni = row.get("revenue", 0), row.get("netIncome", 0)
        if rev and rev > 0:
            margins.append(ni / rev)

    sf = lambda v, d=None: float(v) if v not in (None, "", "N/A") else d

    price  = sf(p.get("price"))
    mkt_cap = sf(p.get("mktCap"), 0) / 1e9

    # Try every field name FMP has used across API versions
    shares_raw = (p.get("sharesOutstanding")
               or p.get("outstandingShares")
               or p.get("commonStockSharesOutstanding")
               or 0)
    shares_b = sf(shares_raw, 0) / 1e9

    # Fallback: derive from market cap and price if still zero
    if shares_b == 0 and mkt_cap > 0 and price and price > 0:
        shares_b = mkt_cap / price  # $B / $ = B shares

    return {
        "name":               p.get("companyName", ticker),
        "ticker":             ticker,
        "logo":               p.get("image", ""),
        "sector":             p.get("sector", ""),
        "industry":           p.get("industry", ""),
        "current_price":      price,
        "shares_outstanding": shares_b,
        "market_cap":         mkt_cap,
        "ttm_revenue":        sf(revenues[0] if revenues else None, 0) / 1e9,
        "pe_ratio":           sf(p.get("pe")),
        "revenue_cagr":       revenue_cagr,
        "analyst_rev_growth": analyst_rev_growth,
        "current_margin":     margins[0] if margins else None,
        "avg_margin":         sum(margins[:3]) / len(margins[:3]) if margins else None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Gemini hints
# ─────────────────────────────────────────────────────────────────────────────
GEMINI_MODELS = [
    "gemini-2.5-flash-preview-04-17",
    "gemini-2.5-pro-preview-03-25",
    "gemini-1.5-flash",
    "gemini-1.5-pro",
]

def get_gemini_hints(s: dict, api_key: str) -> dict:
    client = google_genai.Client(api_key=api_key)

    cagr = f"{s['revenue_cagr']*100:.1f}%"       if s.get('revenue_cagr')       else 'N/A'
    ag   = f"{s['analyst_rev_growth']*100:.1f}%"  if s.get('analyst_rev_growth') else 'N/A'
    cm   = f"{s['current_margin']*100:.1f}%"      if s.get('current_margin')     else 'N/A'
    am   = f"{s['avg_margin']*100:.1f}%"          if s.get('avg_margin')         else 'N/A'
    pe   = str(s.get('pe_ratio') or 'N/A')

    prompt = f"""You are a sell-side equity research analyst writing decision-oriented hints for a stock valuation tool.

COMPANY: {s['name']} ({s['ticker']}) | SECTOR: {s.get('sector')} | INDUSTRY: {s.get('industry')}

DATA:
- TTM Revenue: ${s.get('ttm_revenue', 0):.1f}B
- 3yr Historical Revenue CAGR: {cagr}
- Analyst Consensus Revenue CAGR: {ag}
- TTM Net Margin: {cm}
- 3yr Average Net Margin: {am}
- Trailing P/E: {pe}

RESEARCH STANDARDS:
1. Every claim must cite the data above (e.g. "3yr CAGR: 12%")
2. Include a contrarian or downside note where relevant
3. Be decision-oriented — help the user pick a number
4. Max 20 words per hint

Return ONLY valid JSON (no markdown, no explanation):
{{"growth_rate":"...","margin":"...","pe_low":"...","pe_base":"...","pe_high":"..."}}"""

    last_exc = None
    for model in GEMINI_MODELS:
        try:
            r = client.models.generate_content(model=model, contents=prompt)
            text = r.text.strip()
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"): text = text[4:]
                text = text.split("```")[0].strip()
            try:
                return json.loads(text)
            except json.JSONDecodeError as je:
                # Bad JSON from this model — try the next one
                last_exc = ValueError(f"Gemini returned invalid JSON: {je}")
                continue
        except Exception as e:
            err = str(e)
            if any(k in err for k in ("404", "NOT_FOUND", "no longer available", "unavailable")):
                last_exc = e
                continue
            raise  # unexpected errors bubble up immediately
    raise last_exc or RuntimeError("All Gemini models exhausted")


# ─────────────────────────────────────────────────────────────────────────────
# Calculations
# ─────────────────────────────────────────────────────────────────────────────
def build_forecast(base_rev, growth_pct, margin_pct, start_year, n):
    rows = []
    for i in range(n + 1):
        rev    = base_rev * (1 + growth_pct / 100) ** i
        profit = rev * margin_pct / 100
        rows.append({"Year": start_year + i, "Revenue ($B)": rev,
                     "Margin (%)": margin_pct, "Profit ($B)": profit})
    return rows


def build_scenarios(profit, pe_low, pe_base, pe_high, shares, price, n):
    out = {}
    for label, pe in [("Low", pe_low), ("Base", pe_base), ("High", pe_high)]:
        mc = profit * pe
        tp = mc / shares if shares > 0 else 0
        ar = ((tp / price) ** (1 / n) - 1) * 100 if price > 0 and n > 0 else 0
        out[label] = {"pe": pe, "market_cap": mc, "target_price": tp, "annual_return": ar}
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Persistence
# ─────────────────────────────────────────────────────────────────────────────
def load_analyses():
    if SAVE_FILE.exists():
        try:
            return json.loads(SAVE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Could not load saved analyses: %s", e)
            return {}
    return {}

def save_analysis(ticker, inputs, forecast, scenarios):
    data = load_analyses()
    data[ticker] = {"ticker": ticker, "saved_at": datetime.now().isoformat(),
                    "inputs": inputs, "forecast": forecast, "scenarios": scenarios}
    SAVE_FILE.write_text(json.dumps(data, indent=2))


def hint(text):
    if text:
        safe = html_mod.escape(str(text))
        st.markdown(f'<div class="hint-box">💡 {safe}</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ API Keys")
    fmp_key    = st.text_input("FMP API Key",
                               value=get_secret("FMP_API_KEY"), type="password")
    gemini_key = st.text_input("Gemini API Key (optional)",
                               value=get_secret("GEMINI_API_KEY"), type="password")
    if not GEMINI_AVAILABLE:
        st.caption("Install `google-genai` for AI hints.")

    st.divider()
    st.markdown("### 💾 Saved")
    analyses = load_analyses()
    if analyses:
        for tk, sd in analyses.items():
            c1, c2 = st.columns([3, 1])
            c1.write(f"**{tk}** {sd['saved_at'][:10]}")
            if c2.button("Load", key=f"load_{tk}"):
                st.session_state["load_req"] = tk
    else:
        st.caption("No saved analyses yet.")


# ─────────────────────────────────────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("## 📈 Stock Valuation Calculator")
st.caption("Fundamental analysis · FMP data · Gemini AI hints")

# ─────────────────────────────────────────────────────────────────────────────
# Ticker bar
# ─────────────────────────────────────────────────────────────────────────────
tc, bc = st.columns([4, 1])
with tc:
    ticker_input = st.text_input("Ticker", placeholder="GOOG · AAPL · AMZN · NVDA",
                                 label_visibility="collapsed")
with bc:
    fetch_clicked = st.button("🔍 Fetch", use_container_width=True, type="primary")

# ── Fetch ────────────────────────────────────────────────────────────────────
if fetch_clicked and ticker_input.strip():
    if not fmp_key:
        st.error("Add your FMP API key in the sidebar.")
    else:
        with st.spinner(f"Fetching {ticker_input.upper()}…"):
            try:
                st.session_state["stock"]   = fetch_stock_data(ticker_input, fmp_key)
                st.session_state["hints"]   = {}
                st.session_state["prefill"] = {}
            except ValueError as e:
                st.error(f"Could not fetch {ticker_input.upper()}: {html_mod.escape(str(e))}")
            except requests.exceptions.HTTPError as e:
                code = e.response.status_code if e.response is not None else "?"
                st.error(f"FMP API returned HTTP {code}. Check your API key or try again later.")
                logger.error("FMP HTTP error: %s", e)
            except requests.exceptions.RequestException as e:
                st.error("Network error reaching FMP. Check your connection and try again.")
                logger.error("FMP request error: %s", e)

        if gemini_key and GEMINI_AVAILABLE and "stock" in st.session_state:
            with st.spinner("Getting Gemini hints…"):
                try:
                    st.session_state["hints"] = get_gemini_hints(
                        st.session_state["stock"], gemini_key)
                except Exception as e:
                    st.warning("Gemini hints unavailable. You can still use the tool manually.")
                    logger.warning("Gemini hints error: %s", e)

# ── Load saved ───────────────────────────────────────────────────────────────
if "load_req" in st.session_state:
    req = st.session_state.pop("load_req")
    if req in analyses:
        sv = analyses[req]
        st.session_state["stock"]   = {"ticker": req, "name": req, "logo": "", "sector": "",
                                        "industry": "", "current_price": None, "shares_outstanding": 0,
                                        "market_cap": 0, "ttm_revenue": 0, "pe_ratio": None,
                                        "revenue_cagr": None, "analyst_rev_growth": None,
                                        "current_margin": None, "avg_margin": None}
        st.session_state["hints"]   = {}
        st.session_state["prefill"] = sv["inputs"]

if "stock" not in st.session_state:
    st.info("Enter a ticker above and click **Fetch** to begin.")
    st.stop()

# ─────────────────────────────────────────────────────────────────────────────
# Company header
# ─────────────────────────────────────────────────────────────────────────────
s      = st.session_state["stock"]
hints  = st.session_state.get("hints", {})
prefill= st.session_state.get("prefill", {})

def _safe_img_url(url: str) -> str:
    """Allow only http/https image URLs from FMP's CDN."""
    url = str(url or "").strip()
    return url if url.startswith(("https://", "http://")) else ""

_e = html_mod.escape  # shorthand for escaping API-sourced strings

logo_url  = _safe_img_url(s.get("logo", ""))
logo_html = (f'<img src="{logo_url}" onerror="this.style.display=\'none\'">'
             if logo_url else "")
sector_badge = (f'<span class="sector-badge">{_e(s["sector"])}</span>'
                if s.get("sector") else "")
st.markdown(f"""
<div class="stock-header">
  {logo_html}
  <div>
    <h2>{_e(s['name'])} <span style="color:#8b949e;font-size:1rem">({_e(s['ticker'])})</span>{sector_badge}</h2>
    <span>{_e(s.get('industry',''))}</span>
  </div>
</div>
""", unsafe_allow_html=True)

# Metric pills
mc  = s.get("market_cap", 0)
pe  = s.get("pe_ratio")
cpr = s.get("current_price")
st.markdown(f"""
<div class="metric-row">
  <div class="metric-pill"><div class="label">Price</div>
    <div class="value">${f"{cpr:.2f}" if cpr else "—"}</div></div>
  <div class="metric-pill"><div class="label">Market Cap</div>
    <div class="value">${f"{mc:.0f}B" if mc else "—"}</div></div>
  <div class="metric-pill"><div class="label">TTM Revenue</div>
    <div class="value">${f"{s.get('ttm_revenue',0):.1f}B"}</div></div>
  <div class="metric-pill"><div class="label">P/E</div>
    <div class="value">{f"{pe:.1f}" if pe else "—"}</div></div>
  <div class="metric-pill"><div class="label">TTM Net Margin</div>
    <div class="value">{f"{s['current_margin']*100:.1f}%" if s.get('current_margin') else "—"}</div></div>
</div>
""", unsafe_allow_html=True)

st.divider()

# ─────────────────────────────────────────────────────────────────────────────
# Two-column layout
# ─────────────────────────────────────────────────────────────────────────────
left, right = st.columns([4, 6], gap="large")

# ── LEFT : Inputs ─────────────────────────────────────────────────────────────
with left:
    st.markdown('<div class="section-title">Stock Info</div>', unsafe_allow_html=True)

    cur_price = st.number_input("Current Price ($)",
        min_value=0.01,
        value=float(round(prefill.get("current_price") or cpr or 100, 2)),
        step=1.0)
    if cpr: hint(f"Market price: ${cpr:.2f}")

    shares = st.number_input("Shares Outstanding (B)",
        min_value=0.001, format="%.3f",
        value=float(round(prefill.get("shares") or s.get("shares_outstanding") or 1, 3)),
        step=0.01)
    if s.get("shares_outstanding"):
        hint(f"{s['shares_outstanding']:.2f}B diluted shares · Mkt Cap ${mc:.0f}B")

    base_rev = st.number_input("Base Revenue ($B)",
        min_value=0.01,
        value=float(round(prefill.get("base_revenue") or s.get("ttm_revenue") or 10, 2)),
        step=1.0)
    if s.get("ttm_revenue"): hint(f"TTM Revenue: ${s['ttm_revenue']:.1f}B")

    st.markdown('<div class="section-title">Growth Assumptions</div>', unsafe_allow_html=True)

    cagr_val = s.get("revenue_cagr")
    ag_val   = s.get("analyst_rev_growth")
    default_growth = prefill.get("growth_rate") or (cagr_val * 100 if cagr_val else 10.0)
    growth_hint = hints.get("growth_rate") or "  |  ".join(filter(None, [
        f"3-yr CAGR: {cagr_val*100:.1f}%" if cagr_val else None,
        f"Analyst est: {ag_val*100:.1f}%" if ag_val else None,
    ]))
    growth = st.number_input("Revenue Growth Rate (% / yr)",
        min_value=0.0, max_value=200.0, step=0.5,
        value=float(round(default_growth, 1)),
        help=growth_hint or "Your projected annual revenue growth.")
    hint(growth_hint)

    cm_val = s.get("current_margin")
    am_val = s.get("avg_margin")
    default_margin = prefill.get("margin") or (cm_val * 100 if cm_val else 20.0)
    margin_hint = hints.get("margin") or "  |  ".join(filter(None, [
        f"TTM Margin: {cm_val*100:.1f}%" if cm_val else None,
        f"3-yr avg: {am_val*100:.1f}%" if am_val else None,
    ]))
    margin = st.number_input("Net Profit Margin (%)",
        min_value=0.0, max_value=100.0, step=0.5,
        value=float(round(default_margin, 1)),
        help=margin_hint or "Net profit as % of revenue at target year.")
    hint(margin_hint)

    start_year = datetime.now().year
    n_years    = st.slider("Projection Years", 1, 10, int(prefill.get("n_years", 5)))
    st.caption(f"Forecast: **{start_year}** → **{start_year + n_years}**")

    st.markdown('<div class="section-title">Valuation Multiples (P/E)</div>', unsafe_allow_html=True)

    pe_hint = hints.get("pe_low") or (f"Current P/E: {pe:.1f}" if pe else "")
    pe_low  = st.number_input("Low Multiple",  min_value=1, value=int(prefill.get("pe_low", 20)),
                               help=pe_hint or "Conservative scenario.")
    pe_base = st.number_input("Base Multiple", min_value=1, value=int(prefill.get("pe_base", 25)),
                               help=hints.get("pe_base") or "Fair-value scenario.")
    pe_high = st.number_input("High Multiple", min_value=1, value=int(prefill.get("pe_high", 30)),
                               help=hints.get("pe_high") or "Optimistic scenario.")
    if pe_hint: hint(pe_hint)

# ── RIGHT : Results ───────────────────────────────────────────────────────────
with right:
    if base_rev <= 0 or shares <= 0 or cur_price <= 0:
        st.info("Complete inputs on the left to see the forecast.")
        st.stop()

    forecast  = build_forecast(base_rev, growth, margin, start_year, n_years)
    scenarios = build_scenarios(forecast[-1]["Profit ($B)"],
                                pe_low, pe_base, pe_high, shares, cur_price, n_years)

    # ── Forecast table ────────────────────────────────────────
    st.markdown('<div class="section-title">Revenue & Profit Forecast</div>', unsafe_allow_html=True)
    df = pd.DataFrame(forecast).set_index("Year")
    df["Revenue ($B)"] = df["Revenue ($B)"].map("{:.2f}".format)
    df["Margin (%)"]   = df["Margin (%)"].map("{:.1f}%".format)
    df["Profit ($B)"]  = df["Profit ($B)"].map("{:.2f}".format)
    st.dataframe(df, use_container_width=True)

    # ── Bar chart ─────────────────────────────────────────────
    yrs  = [r["Year"]         for r in forecast]
    revs = [r["Revenue ($B)"] for r in forecast]
    prfs = [r["Profit ($B)"]  for r in forecast]

    fig = go.Figure()
    fig.add_trace(go.Bar(x=yrs, y=revs, name="Revenue", marker_color="#388bfd", opacity=0.6))
    fig.add_trace(go.Bar(x=yrs, y=prfs, name="Profit",  marker_color="#3fb950", opacity=0.9))
    fig.update_layout(barmode="overlay", height=220,
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        legend=dict(orientation="h", y=1.15, font_color="#8b949e"),
        margin=dict(t=10, b=10, l=0, r=0),
        yaxis=dict(title="$B", gridcolor="#21262d", color="#8b949e"),
        xaxis=dict(tickmode="linear", dtick=1, color="#8b949e"))
    st.plotly_chart(fig, use_container_width=True)

    # ── Scenario cards ────────────────────────────────────────
    st.markdown('<div class="section-title">Target Price Scenarios</div>', unsafe_allow_html=True)
    c_low, c_base, c_high = st.columns(3)
    card_cfg = [
        (c_low,  "Low",  "sc-low",  "🔴", "#f85149"),
        (c_base, "Base", "sc-base", "🟡", "#d2a520"),
        (c_high, "High", "sc-high", "🟢", "#3fb950"),
    ]
    for col, label, css, emoji, ret_color in card_cfg:
        d   = scenarios[label]
        ret = d["annual_return"]
        ret_str = f"{'+'if ret>=0 else ''}{ret:.1f}%"
        with col:
            st.markdown(f"""
<div class="sc-card {css}">
  <div style="font-weight:700;font-size:0.95rem;margin-bottom:12px">{emoji} {label}</div>
  <div class="sc-label">P/E Multiple</div>
  <div class="sc-value">{d['pe']}x</div>
  <hr>
  <div class="sc-label">Target Price</div>
  <div style="font-size:1.6rem;font-weight:800;color:#e6edf3">${d['target_price']:.1f}</div>
  <hr>
  <div class="sc-label">Est. Market Cap</div>
  <div class="sc-sub">${d['market_cap']:.0f}B</div>
  <hr>
  <div class="sc-label">Annual Return ({n_years}yr)</div>
  <div class="sc-return" style="color:{ret_color}">{ret_str}</div>
</div>""", unsafe_allow_html=True)

    # ── Price range chart ─────────────────────────────────────
    st.markdown('<div class="section-title">Price Target Range</div>', unsafe_allow_html=True)
    labels = list(scenarios.keys())
    prices = [scenarios[l]["target_price"] for l in labels]
    fig2 = go.Figure()
    fig2.add_trace(go.Bar(x=labels, y=prices,
        marker_color=["#f85149", "#d2a520", "#3fb950"],
        text=[f"${p:.1f}" for p in prices], textposition="outside",
        textfont=dict(color="#e6edf3")))
    fig2.add_hline(y=cur_price, line_dash="dash", line_color="#8b949e",
        annotation_text=f"  Current ${cur_price:.1f}",
        annotation_font_color="#8b949e", annotation_position="right")
    fig2.update_layout(height=260,
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(t=30, b=10, l=0, r=80), showlegend=False,
        yaxis=dict(title="Price ($)", gridcolor="#21262d", color="#8b949e"),
        xaxis=dict(color="#8b949e"))
    st.plotly_chart(fig2, use_container_width=True)

    # ── Save ──────────────────────────────────────────────────
    if st.button("💾 Save Analysis", use_container_width=True):
        save_analysis(s["ticker"],
            {"current_price": cur_price, "shares": shares, "base_revenue": base_rev,
             "growth_rate": growth, "margin": margin, "n_years": n_years,
             "pe_low": int(pe_low), "pe_base": int(pe_base), "pe_high": int(pe_high)},
            [dict(r) for r in forecast], scenarios)
        st.success(f"✅ Saved {s['ticker']}")
        st.rerun()

# ─────────────────────────────────────────────────────────────────────────────
# Comparison
# ─────────────────────────────────────────────────────────────────────────────
analyses = load_analyses()
if len(analyses) >= 2:
    st.divider()
    with st.expander("⚖️ Compare Saved Analyses", expanded=False):
        selected = st.multiselect("Stocks", list(analyses.keys()),
                                  default=list(analyses.keys())[:4])
        if selected:
            cols = st.columns(len(selected))
            for col, tk in zip(cols, selected):
                sv  = analyses[tk]
                inp = sv["inputs"]
                sc  = sv["scenarios"]
                with col:
                    st.markdown(f"#### {tk}")
                    st.caption(sv["saved_at"][:10])
                    st.metric("Growth", f"{inp.get('growth_rate',0):.1f}%/yr")
                    st.metric("Margin", f"{inp.get('margin',0):.1f}%")
                    for lbl, d in sc.items():
                        ret = d["annual_return"]
                        st.metric(f"{lbl} ({d['pe']}x)",
                                  f"${d['target_price']:.1f}",
                                  f"{'+'if ret>=0 else ''}{ret:.1f}%/yr")

            fig3 = go.Figure()
            for lbl, clr in [("Low","#f85149"),("Base","#d2a520"),("High","#3fb950")]:
                fig3.add_trace(go.Bar(name=lbl, x=selected,
                    y=[analyses[t]["scenarios"][lbl]["target_price"] for t in selected],
                    marker_color=clr, opacity=0.85))
            fig3.update_layout(barmode="group", height=280,
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                legend=dict(orientation="h", font_color="#8b949e"),
                yaxis=dict(title="Target Price ($)", gridcolor="#21262d", color="#8b949e"),
                xaxis=dict(color="#8b949e"), margin=dict(t=10, b=10))
            st.plotly_chart(fig3, use_container_width=True)
