import { AlertResponse, AgentApproval, DriftCluster } from './types'

// Realistic seeded SOC alerts data
export const SEEDED_ALERTS: AlertResponse[] = [
  {
    id: 1042,
    timestamp: new Date(Date.now() - 1000 * 60 * 2).toISOString(),
    attack_type: 'HTTP_FLOOD',
    attack_category: 'DoS Attacks',
    severity_label: 'Critical',
    severity_score: 5,
    confidence: 0.994,
    anomaly_score: 0.998,
    is_anomaly: true,
    source_ip: '185.220.101.5',
    dest_ip: '192.168.1.10',
    is_acknowledged: false,
    raw_result: JSON.stringify({
      "Protocol": 6,
      "Flow Duration": 500000,
      "Total Fwd Packets": 8000,
      "Total Backward Packets": 50,
      "Flow Bytes/s": 23360000,
      "Flow Packets/s": 16100,
      "SYN Flag Count": 1,
      "ACK Flag Count": 50,
      "Destination Port": 80,
      "Model Breakdown": {
        "XGBoost": "HTTP_FLOOD (99.4%)",
        "Random Forest": "ATTACK (100.0%)",
        "LSTM": "ATTACK (100.0%)"
      }
    })
  },
  {
    id: 1041,
    timestamp: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
    attack_type: 'SQL_INJECTION',
    attack_category: 'Web Exploits',
    severity_label: 'High',
    severity_score: 4,
    confidence: 0.948,
    anomaly_score: 0.884,
    is_anomaly: false,
    source_ip: '45.33.32.156',
    dest_ip: '192.168.1.10',
    is_acknowledged: false,
    raw_result: JSON.stringify({
      "Protocol": 6,
      "Destination Port": 80,
      "Flow Duration": 2100000,
      "Total Fwd Packets": 42,
      "Total Backward Packets": 38,
      "Flow Bytes/s": 14200,
      "PSH Flag Count": 28,
      "Signature": "UNION SELECT 1,table_name FROM information_schema.tables"
    })
  },
  {
    id: 1040,
    timestamp: new Date(Date.now() - 1000 * 60 * 11).toISOString(),
    attack_type: 'SYN_FLOOD',
    attack_category: 'DDoS & Floods',
    severity_label: 'Critical',
    severity_score: 5,
    confidence: 0.999,
    anomaly_score: 0.995,
    is_anomaly: true,
    source_ip: '198.51.100.24',
    dest_ip: '192.168.1.1',
    is_acknowledged: false,
    raw_result: JSON.stringify({
      "Protocol": 6,
      "Destination Port": 80,
      "Flow Duration": 95000,
      "Total Fwd Packets": 6000,
      "Total Backward Packets": 0,
      "Flow Packets/s": 63150,
      "SYN Flag Count": 6000,
      "ACK Flag Count": 0
    })
  },
  {
    id: 1039,
    timestamp: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
    attack_type: 'BRUTE_FORCE_SSH',
    attack_category: 'Brute Force',
    severity_label: 'Medium',
    severity_score: 3,
    confidence: 0.887,
    anomaly_score: 0.650,
    is_anomaly: false,
    source_ip: '103.253.42.12',
    dest_ip: '192.168.1.22',
    is_acknowledged: false,
    raw_result: JSON.stringify({
      "Protocol": 6,
      "Destination Port": 22,
      "Flow Duration": 28000000,
      "Total Fwd Packets": 950,
      "Total Backward Packets": 920,
      "Flow Bytes/s": 18200,
      "Flow Packets/s": 66.8
    })
  },
  {
    id: 1038,
    timestamp: new Date(Date.now() - 1000 * 60 * 25).toISOString(),
    attack_type: 'PORT_SCAN',
    attack_category: 'Recon & Scans',
    severity_label: 'Low',
    severity_score: 2,
    confidence: 0.982,
    anomaly_score: 0.450,
    is_anomaly: false,
    source_ip: '77.88.55.66',
    dest_ip: '192.168.1.15',
    is_acknowledged: true,
    raw_result: JSON.stringify({
      "Protocol": 6,
      "Destination Port": 445,
      "Flow Duration": 1500,
      "Total Fwd Packets": 2,
      "Total Backward Packets": 0,
      "SYN Flag Count": 2
    })
  },
  {
    id: 1037,
    timestamp: new Date(Date.now() - 1000 * 60 * 40).toISOString(),
    attack_type: 'RANSOMWARE',
    attack_category: 'Malware & C2',
    severity_label: 'Critical',
    severity_score: 5,
    confidence: 0.965,
    anomaly_score: 0.992,
    is_anomaly: true,
    source_ip: '192.168.1.88',
    dest_ip: '192.168.1.5',
    is_acknowledged: true,
    raw_result: JSON.stringify({
      "Protocol": 6,
      "Destination Port": 445,
      "Flow Duration": 120000000,
      "Total Fwd Packets": 2400,
      "Total Backward Packets": 4800,
      "Flow Bytes/s": 450000,
      "Action": "High volume SMB encryption exfiltration"
    })
  },
  {
    id: 1036,
    timestamp: new Date(Date.now() - 1000 * 60 * 65).toISOString(),
    attack_type: 'ZERO_DAY_EXPLOIT',
    attack_category: 'Zero-Day & Infil',
    severity_label: 'Critical',
    severity_score: 5,
    confidence: 0.760,
    anomaly_score: 0.999,
    is_anomaly: true,
    source_ip: '91.240.118.17',
    dest_ip: '192.168.1.10',
    is_acknowledged: false,
    raw_result: JSON.stringify({
      "Protocol": 6,
      "Destination Port": 8088,
      "Flow Duration": 350000,
      "Total Fwd Packets": 1,
      "Total Backward Packets": 1,
      "URG Flag Count": 4,
      "Note": "Extreme autoencoder reconstruction error, zero match in supervised training set"
    })
  },
  {
    id: 1035,
    timestamp: new Date(Date.now() - 1000 * 60 * 90).toISOString(),
    attack_type: 'SLOWLORIS',
    attack_category: 'DoS Attacks',
    severity_label: 'High',
    severity_score: 4,
    confidence: 0.912,
    anomaly_score: 0.820,
    is_anomaly: false,
    source_ip: '195.12.50.8',
    dest_ip: '192.168.1.10',
    is_acknowledged: true,
    raw_result: JSON.stringify({
      "Protocol": 6,
      "Destination Port": 80,
      "Flow Duration": 65000000,
      "Total Fwd Packets": 120,
      "Total Backward Packets": 60,
      "Avg Packet Size": 3
    })
  }
]

// Seeded AI Agent Approvals Queue
export const SEEDED_AGENT_APPROVALS: AgentApproval[] = [
  {
    id: 'appr-01',
    agent: 'Threat Containment Sentinel',
    action: 'BLOCK_IP',
    target: '185.220.101.5',
    severity: 'Critical',
    rationale: 'Active volumetric HTTP_FLOOD attack (>16,100 pps) targeting core web server. Over 8,000 packets detected in 500ms.',
    evidence_alert_ids: [1042],
    created_at: new Date(Date.now() - 1000 * 60 * 3).toISOString(),
    status: 'pending_human_approval',
    proposed_by: 'AI Autonomous SOC Agent #04'
  },
  {
    id: 'appr-02',
    agent: 'Endpoint Quarantine Agent',
    action: 'ISOLATE_HOST',
    target: '192.168.1.88',
    severity: 'Critical',
    rationale: 'Internal host exhibiting sustained SMB ransomware encryption patterns across file shares with >4.8MB exfiltration.',
    evidence_alert_ids: [1037],
    created_at: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
    status: 'pending_human_approval',
    proposed_by: 'AI Host Forensic Agent #02'
  },
  {
    id: 'appr-03',
    agent: 'External OSINT Enrichment Agent',
    action: 'VIRUSTOTAL_SCAN',
    target: '45.33.32.156',
    severity: 'High',
    rationale: 'Perform deep VirusTotal IP reputation lookup and ASN threat scoring for origin of SQL Injection attack #1041.',
    evidence_alert_ids: [1041],
    created_at: new Date(Date.now() - 1000 * 60 * 8).toISOString(),
    status: 'approved',
    proposed_by: 'TI Threat Intel Agent',
    decided_by: 'analyst_ahmed (Tier 2)',
    decided_at: new Date(Date.now() - 1000 * 60 * 6).toISOString(),
    audit_comment: 'Approved for automated intelligence gathering'
  }
]

// Seeded Unknown Anomaly & Distribution Drift Clusters
export const SEEDED_DRIFT_CLUSTERS: DriftCluster[] = [
  {
    id: 'cluster-zero-alpha',
    cluster_name: 'Divergent High-URG Flag Anomaly',
    sample_count: 24,
    reconstruction_error_mean: 0.9984,
    divergent_features: ['URG Flag Count', 'Packet Length Variance', 'Fwd IAT Mean'],
    representative_flow: {
      "Protocol": 6,
      "Destination Port": 8088,
      "URG Flag Count": 4,
      "Flow Duration": 400000,
      "Packet Length Variance": 2840.5
    },
    first_detected: new Date(Date.now() - 1000 * 60 * 180).toISOString(),
    last_detected: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    severity: 'Critical',
    alert_ids: [1042, 1040, 1036],
  },
  {
    id: 'cluster-c2-poly',
    cluster_name: 'Polymorphic High-Entropy Flow',
    sample_count: 14,
    reconstruction_error_mean: 0.9892,
    divergent_features: ['Flow IAT Std', 'Down/Up Ratio', 'Fwd Avg Bytes/Bulk'],
    representative_flow: {
      "Protocol": 17,
      "Destination Port": 9999,
      "Flow Duration": 15000000,
      "Down/Up Ratio": 0.001
    },
    first_detected: new Date(Date.now() - 1000 * 60 * 320).toISOString(),
    last_detected: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    severity: 'High',
    alert_ids: [1037],
  }
]
