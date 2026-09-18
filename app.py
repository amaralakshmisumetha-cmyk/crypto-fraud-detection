import os
import time
import requests
import networkx as nx
import streamlit as st
import matplotlib.pyplot as plt

st.set_page_config(page_title="Crypto Fraud Detector", layout="wide")
st.title("Ethereum Real-Time Crypto Fraud Detector")

# Retrieve API key securely from Streamlit Secrets or Environment
API_KEY = st.secrets.get("ETHERSCAN_API_KEY", os.getenv("ETHERSCAN_API_KEY", ""))
BASE_URL = "https://api.etherscan.io/v2/api"

KNOWN_EXCHANGES = {
    "0x28c6c06298d514db089934071355e5743bf21d60": "Binance 14",
    "0x21a31ee1afc51d94c2efccaa2092ad1028285549": "Binance 15",
    "0xdfd5293d8e347dfe59e90efd55b2956a1343963d": "Binance 16",
    "0x9696f59e4d72e237be84ffd425dcad154bf96976": "Kraken",
    "0x503828976d22510aad0201ac7ec88293211d23da": "Coinbase"
}

KNOWN_RISKY = {
    "0x8576acc5c05d6ce88f4e49bf65bdf0c62f91353c": "OFAC-Sanctioned",
    "0x722122df12d4e14e13ac3b6895a86e84145b6967": "Tornado Cash 0.1 ETH",
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": "Tornado Cash 1 ETH",
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Tornado Cash 10 ETH",
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": "Tornado Cash 100 ETH"
}

def get_transactions(wallet_address, api_key):
    params = {
        "chainid": 1,
        "module": "account",
        "action": "txlist",
        "address": wallet_address,
        "startblock": 0,
        "endblock": 99999999,
        "page": 1,
        "offset": 50,
        "sort": "asc",
        "apikey": api_key
    }
    try:
        response = requests.get(BASE_URL, params=params, timeout=30)
        data = response.json()
        if data.get("status") == "1":
            return [
                {
                    "from": tx["from"],
                    "to": tx["to"],
                    "value_eth": int(tx["value"]) / 10**18,
                    "timestamp": tx["timeStamp"],
                    "hash": tx["hash"]
                }
                for tx in data.get("result", [])
            ]
    except Exception:
        pass
    return []

def trace_funds(start_address, api_key, max_hops=2, max_wallets_per_hop=3):
    G = nx.MultiDiGraph()
    visited = set()
    current_level = [start_address]

    for _ in range(max_hops):
        next_level = []
        for wallet in current_level:
            wallet_lower = wallet.lower()
            if wallet_lower in {w.lower() for w in visited}:
                continue
            visited.add(wallet)

            txs = get_transactions(wallet, api_key)
            time.sleep(0.25)

            outgoing = [
                tx for tx in txs
                if tx["from"].lower() == wallet_lower and tx["value_eth"] > 0 and tx["to"]
            ]
            outgoing.sort(key=lambda tx: tx["value_eth"], reverse=True)
            outgoing = outgoing[:max_wallets_per_hop]

            for tx in outgoing:
                G.add_edge(tx["from"], tx["to"], value_eth=tx["value_eth"])
                if tx["to"].lower() not in {w.lower() for w in visited}:
                    next_level.append(tx["to"])
        current_level = next_level
        if not current_level:
            break
    return G

def check_wallet_attribution(address):
    addr = address.lower()
    if addr in KNOWN_EXCHANGES:
        return {"type": "exchange", "label": KNOWN_EXCHANGES[addr]}
    if addr in KNOWN_RISKY:
        return {"type": "risky", "label": KNOWN_RISKY[addr]}
    return {"type": "unknown", "label": None}

def analyze_graph(G):
    return [
        {"wallet": node, **check_wallet_attribution(node)}
        for node in G.nodes()
        if check_wallet_attribution(node)["type"] != "unknown"
    ]

def calculate_risk_score(G, findings):
    score = 0
    reasons = []
    
    exchange_hits = [f for f in findings if f["type"] == "exchange"]
    if exchange_hits:
        score += 20
        reasons.append(f"Reached known exchange(s): {[f['label'] for f in exchange_hits]}")
        
    risky_hits = [f for f in findings if f["type"] == "risky"]
    if risky_hits:
        score += 60
        reasons.append(f"Touched flagged address(es): {[f['label'] for f in risky_hits]}")
        
    if G.number_of_nodes() > 8:
        score += 20
        reasons.append("High wallet density (possible layering pattern)")
        
    if not findings:
        score += 40
        reasons.append("Unidentified destination wallets in trace path")
        
    score = min(score, 100)
    risk_level = "LOW" if score < 30 else ("MEDIUM" if score < 60 else "HIGH")
    return {"score": score, "risk_level": risk_level, "reasons": reasons}

# UI Input Panel
user_key = st.text_input("Etherscan API Key", value=API_KEY, type="password")
target_wallet = st.text_input("Target Wallet Address", "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")

col1, col2 = st.columns(2)
hops = col1.slider("Max Hops", 1, 3, 2)
wallets_per_hop = col2.slider("Max Wallets / Hop", 1, 5, 3)

if st.button("Run Fraud Trace"):
    if not user_key:
        st.error("Please enter a valid Etherscan API key.")
    else:
        with st.spinner("Tracing transactions..."):
            G = trace_funds(target_wallet, user_key, max_hops=hops, max_wallets_per_hop=wallets_per_hop)
            findings = analyze_graph(G)
            risk = calculate_risk_score(G, findings)

        # Dashboard Metrics
        m1, m2, m3 = st.columns(3)
        m1.metric("Nodes Analyzed", G.number_of_nodes())
        m2.metric("Transactions Traced", G.number_of_edges())
        m3.metric("Risk Assessment", f"{risk['score']}/100 ({risk['risk_level']})")

        # Graph Plotting
        st.subheader("Transaction Network Graph")
        fig, ax = plt.subplots(figsize=(8, 4))
        pos = nx.spring_layout(G)
        nx.draw_networkx(G, pos, with_labels=False, node_size=300, node_color="skyblue", ax=ax)
        st.pyplot(fig)

        # Risk Factors Output
        st.subheader("Risk Factors")
        for r in risk["reasons"]:
            st.write(f"- {r}")

        if findings:
            st.subheader("Attributed Entities")
            st.json(findings)
