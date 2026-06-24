'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import Terminal from './Terminal';

const navSections = [
  {
    title: 'Overview',
    items: [{ label: 'Dashboard', href: '/', icon: '9679' }],
  },
  {
    title: 'Security Operations',
    items: [
      { label: 'Incidents & Alerts', href: '/incidents', icon: '9888' },
      { label: 'Detection Rules', href: '/rules', icon: '9878' },
      { label: 'Snort/Suricata', href: '/snort', icon: '128481' },
      { label: 'Threat Intelligence', href: '/threat-intel', icon: '9762' },
      { label: 'MITRE ATT&CK', href: '/mitre', icon: '127758' },
      { label: 'Compliance Dashboard', href: '/compliance', icon: '128203' },
      { label: 'Alerting', href: '/alerting', icon: '128276' },
    ],
  },
  {
    title: 'Monitoring',
    items: [
      { label: 'Network Monitoring', href: '/network-monitoring', icon: '128200' },
      { label: 'Web Traffic', href: '/web-traffic', icon: '127760' },
      { label: 'Host Monitoring', href: '/host-monitoring', icon: '128187' },
      { label: 'Network Assets', href: '/assets', icon: '128421' },
      { label: 'Remote Agents', href: '/agents', icon: '128268' },
    ],
  },
  {
    title: 'Detection & Analysis',
    items: [
      { label: 'PCAP Analysis', href: '/pcap-analysis', icon: '128220' },
      { label: 'Vulnerability Scanner', href: '/vulnscan', icon: '128295' },
      { label: 'File Integrity', href: '/fim', icon: '128196' },
      { label: 'ML Anomaly Detection', href: '/ml', icon: '129302' },
    ],
  },
  {
    title: 'Engineering',
    items: [
      { label: 'Engineering Tasks', href: '/tasks', icon: '9881' },
      { label: 'QA & Testing', href: '/qa', icon: '9887' },
      { label: 'SOAR Automation', href: '/soar', icon: '9889' },
      { label: 'Playbooks', href: '/playbooks', icon: '128214' },
    ],
  },
  {
    title: 'Governance',
    items: [
      { label: 'NIST CSF', href: '/framework', icon: '9879' },
      { label: 'Policies & Standards', href: '/security-plan', icon: '128220' },
    ],
  },
  {
    title: 'System',
    items: [
      { label: 'Setup', href: '/setup', icon: '9881' },
      { label: 'Log Collection', href: '/syslog', icon: '128231' },
      { label: 'Data Retention', href: '/retention', icon: '128190' },
    ],
  },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <h1>NIDS Workspace</h1>
        <div className="subtitle">Network Intrusion Detection System</div>
      </div>
      <nav className="sidebar-nav">
        {navSections.map((section) => (
          <div className="nav-section" key={section.title}>
            <div className="nav-section-title">{section.title}</div>
            {section.items.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className={`nav-item${pathname === item.href ? ' active' : ''}`}
              >
                <span className="icon">{String.fromCharCode(Number(item.icon))}</span>
                {item.label}
              </Link>
            ))}
          </div>
        ))}
      </nav>
      <Terminal />
    </aside>
  );
}
