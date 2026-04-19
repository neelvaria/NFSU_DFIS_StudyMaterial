**Need of Incident Response**

\- Rapid detection and containment (Prevent cyber attack \& Limit damage to data and system)

\- Business continuity (Minimize downtime \& protect critical services)

* Legal and Regulatory Compliance (Required under data protection laws \& Enable proper breach notification)
* Evidence preservation (Support Forensics investigation \& prevent evidence contamination)
* Organizational Preparation (Define roles and responsibilities \& Improves coordination among teams)

**------------------------------**

Incident Prioritization



**Efficient use of resources** (limited time and manpower; prioritization ensures resources are focused)

**Minimize Business impact** (High-impact incidents affecting critical systems or sensitive data are addressed first, reducing operational and financial losses.)

**Faster response to critical threats** (Urgent incidents that can escalate quickly)

**Prevent Incident Escalation** (Early handling of high-risk incidents prevents them from spreading or causing further damage.)

**Supports Business Continuity** (By focusing on incidents affecting mission-critical services, business operations are protected.)



**Impact:** Data Sensitive Business Disruption \& Legal Consequences)

**Urgency:** Speed of incident progression, Time sensitivity \& Active exploitation)



**Priority levels**

* **P1 (High Impact, High Urgency)** Immediate response required (e.g., active data breach, ransomware attack).
* **P2 (High Impact, Low Urgency)** Serious but not time-critical
* **P3 (Low Impact, High Urgency**) Requires quick action but limited damage
* **P4 (Low Impact, Low Urgency)** Minor incidents (e.g., non-critical system alert).



Incident prioritization allows organizations to respond intelligently, ensuring maximum risk reduction with available resources.

**------------------------------**

**Discuss incident prioritization with appropriate examples of impact and urgency**



It is a critical activity in incident response management that ensures limited response resources are allocated efficiently



Impact: refers to the extent of damage an incident causes to systems, data, business operations, reputation, or legal compliance.

Urgency: refers to how quickly an incident must be resolved to prevent escalation or further harm.



High Impact – High Urgency (Critical Priority)
These incidents cause severe damage and require immediate action.
Example:
A ransomware attack encrypting critical servers and actively spreading across the network.
Impact: High (data unavailability, business shutdown).
Urgency: High (rapid spread and increasing damage).

Action: Immediate containment, system isolation, and executive-level escalation.



High Impact – Low Urgency (High Priority)
These incidents can cause serious damage but are not immediately active.
Example:
A critical vulnerability discovered in a core banking or ERP system, but no exploitation has been detected yet.

Impact: High (potential compromise of sensitive data).
Urgency: Low (no active attack at the moment).

Action: Planned patching and mitigation within a defined timeframe.



Low Impact – High Urgency (Medium Priority)
These incidents require quick response but affect limited systems.
Example:
Malware detected on a single employee workstation connected to the network.
Impact: Low (limited to one system).
Urgency: High (risk of lateral movement).

Action: Immediate isolation of the system and malware removal.



Low Impact – Low Urgency (Low Priority)
Minor incidents with minimal risk and no immediate threat.
Example:
A failed login alert on a non-critical internal application with no further suspicious activity.

Impact: Low (no system or data compromise).
Urgency: Low (no active threat).

Action: Monitor and review during routine security operations.



Effective incident prioritization ensures critical threats are handled first, reducing overall risk and improving response efficiency, as emphasized across IRM literature.

Explain the steps or stages used in incident response



Preparation: This stage involves developing incident response policies, procedures, tools, and training staff to handle incidents effectively.
Activities
Incident response plan and playbooks
Security tools
Staff training

Example:
An organization sets up a Security Operations Center (SOC) and trains employees to identify phishing emails.



Identification: In this stage, potential security incidents are detected, analyzed, and confirmed.
Activities
Monitoring logs and alerts
IOC's
Determine incident scope and severity

Example:
SIEM alerts show unusual login attempts and file encryption activity, indicating a ransomware attack.



Containment: The goal of containment is to limit the spread and impact of the incident.
Activities
Isolating affected systems
Blocking malicious IP addresses
Disabling compromised account

Example:
Infected systems are disconnected from the network to prevent ransomware from spreading.



Eradication: This stage focuses on removing the root cause of the incident.
Activities
Remove malware
Closing backdoor

Example:
The ransomware is removed, and the phishing email vulnerability is addressed by updating email filters.



Recovery: Systems are restored to normal operation and monitored for any signs of recurrence.
Activities
Restoring data from backups
Validating system integrity

Example:
Encrypted files are restored from clean backups, and systems are brought back online.



Lessons learned: This final stage involves reviewing the incident to improve future response.
Activities:
Incident documentation
Root cause analysis
Policy and control improvements

Example:
The organization improves employee phishing awareness training and strengthens backup strategies.

---

Estimate the cost of a given incident (case study type question)



Direct Cost: Immediate and measurable expenses incurred during the incident.

Incident response and forensic investigation
System repair and recovery
Data restoration



Indirect Cost: Secondary costs that arise as a consequence of the incident.

Loss of productivity
Business disruption
Customer dissatisfaction



Tangible Cost: Costs that can be easily quantified in monetary terms.

Hardware and software replacement
Overtime wages for staff



Intangible Cost: Costs that are difficult to quantify but have long-term impact

Loss of reputation and brand value
Loss of customer trust



Operational Cost: Costs affecting daily business operations.

System downtime
Service interruptions



Legal and Compliance Cost: Costs related to legal obligations and regulatory requirements.

Legal Consultation fees
Regulatory penalties



Remediation and Prevention Costs: Costs incurred after the incident to prevent future occurrences.

Security updates
Policy Improvements



Accurate incident cost estimation enables better risk assessment, budgeting, and security investment decisions.

---

Describe the factors involved in estimating the cost of an incident



Scope of incident

Types of data owned

Business Downtime

Incident response time

Legal and compliance obligations

Reputation and customer trust

---

Compare disaster recovery with data backup



| Aspect            | Data Backup                                                     | Disaster Recovery                                                                 |

| ------------------| --------------------------------------------------------------- | --------------------------------------------------------------------------------- |

| Definition        | Process of creating copies of data to protect against data loss | Comprehensive plan to restore IT systems and business operations after a disaster |

| Scope             | Focuses only on data                                            | Covers data, applications, systems, networks, and business processes              |

| Objective         | To recover lost or corrupted data                               | To resume normal operations within acceptable time                                |

| Recovery Focus    | Data restoration                                                | Service and business continuity                                                   |

| Response Time     | Usually slower and manual                                       | Designed for rapid and automated recovery                                         |

| RTO / RPO         | Basic or undefined                                              | Clearly defined RTO and RPO objectives                                            |

| Tools Used        | Backup software, external drives, cloud storage                 | DR sites, replication, failover systems, DRaaS                                    |

| Testing Frequency | Occasional or ad-hoc                                            | Regularly tested through DR drills                                                |

| Cost              | Lower cost                                                      | Higher cost due to infrastructure and planning                                    |

| Use Case          | Accidental deletion, file corruption                            | Natural disasters, ransomware, data center failure                                |

---

**Discuss in detail disaster recovery technologies used in incident response management**



1. Data Technology Backups (Full incremental, and differential backups , On-site \& off-site backup \& Cloud backups)
2. Redundancy and Failover system (Redundant server and network components)
3. Replication Technologies (Real-time or near-real-time data replication and database storage replication)
4. Virtualization and Snapshot Technologies
5. Cloud-Based Disaster Recovery (DRaaS)

---

**How can virtualization help in incident response handling?**



1. Rapid system isolation
2. Snapshot and rollback
3. Isolation of Infected Systems
4. Forensics analysis
5. Safe Malware Analysis
6. Faster Recovery

---

**Using a suitable diagram, explain the types of incidents and their logging requirement**



1. **Malware Incidents**
   Logs required (Antivirus logs and EDR, **System event logs,** Process creation logs \& File integrity logs)
   Purpose (Identify malware, Trace infection \& Detect presence)
2. **Unauthorized Access/Intrusion**
   Logs required (Authentication, VPN, Privilege and Directory logs)
   Purpose: (Identify attacker entry point, Track lateral movements \& Compromised password)
3. **Network based attacks**
   Logs required (Firewall, IDS/IPS, NetFlow \& Router and switch logs)
   Purpose: (Identify attacker sources, Analyze attacks \& Measure attacks impact)
4. **Data Breach**
   Logs required (database access, File access, DLP \& Cloud access Logs)
   Purpose: (Identify accessed control, determine scope of breach \& Compliance reporting)
5. **Insider threat incident**
   Logs required: (user activity, File transfer \& USB and device control logs)
   Purpose: (Monitoring misuse of privilege \& Establish intent and timeline)
6. 

**---------------------------------**

**Logs Analysis**



Log analysis is the process of:

“Collecting, parsing, correlating, and interpreting log data to detect security incidents and understand system behavior.”



Objective

* Detect security incidents
* nvestigate incidents and reconstruct timelines
* Support compliance and auditing requirements
* Troubleshoot system and application issues



Logs capture from systems

1. OS system logs - Windows Event viewer(Security, system \& application)
2. Application logs - Web server, Database \& Email server
3. Security devices Logs - Firewall, IDS/IPS, Antivirus
4. Centralized logs - Log forwarding agents, SIEM Platform \& Secure log storage

**--------------------------**

**Write in detail about any log analysis tool using suitable data**



Log analysis tools help organizations collect, correlate, and analyze large volumes of logs.

Example: SIEM



Key Functions

1. **Log Collection** : Collects logs from servers, endpoints, network devices, and applications
   Example: Firewall, server, and application logs sent to the SIEM.
2. **Log Normalization**: Converts logs into standardized formats
   Firewall log + Windows log → standardized fields like time, IP, user, action.
3. **Correlation and alerting**: Detects pattern and indicate alerts, Generates real-time alerts
4. **Visualization and reporting:** Dashboards show trends, graphs, and alerts.



**Benefits**

* Centralized Visibility
* Real-time threat detection
* **Faster incidents response**



**Limitations**

* High implementation cost
* Requires tuning to reduce false positives

---

**Explain real-time log capture and analysis**



Real-time log capture and analysis enables immediate detection and response to security incidents.



Real time log analysis
It involves instantly analyzing incoming log data to detect anomalies, threats, or operational issues.



**Methods of Real-Time Log Capture**



Agents: Installed on hosts to forward logs instantly (e.g., Beats, SIEM agents)

Syslog: Sends logs over UDP/TCP to a central log server

Windows Event Forwarding: Streams Windows event logs in real time

APIs: Used by cloud and SaaS platforms to push logs



**Working Process (Step-by-Step)**

* **Event Generation:**
  A system event occurs (e.g., failed login attempt)



* **Immediate Log Capture**
  Log is sent to a central system via agent or syslog



* **Analysis Engine**
  Log is parsed, normalized, and correlated with other events



* **Detection and Alerting**
  If a rule is matched, an alert is raised



* **Response**
  Incident response team is notified for immediate action



Advantage

* Early detection
* Faster Containment
* Reduced dwell time



Challenge

* High data volume
* False positive
* Infrastructure overhead

**----------------------------**

**Discuss methods of network monitoring and how logs from network events are collected**



Network monitoring plays a crucial role in detecting and responding to network-based attacks



**Methods of Network monitoring**

1. Passive Monitoring: Packet Capture, NetFlow analysis
2. Active monitoring: Network Scanning, Synthetic info.
3. Security Monitoring: IDS/IPS, Firewall monitoring



**Network Log Collection**

* Firewalls generate traffic logs
* IDS/IPS produce alert logs
* Routers and switches provide flow records
* Logs forwarded to centralized SIEM

**-----------------------------**

**Write notes on enterprise solutions for incident response and recovery**



Enterprise incident response solutions integrate technology, automation, and analytics to improve detection, response, and recovery.



IR solution

1. **SIEM Platform** - Centralized log collection and correlation \& real time alerting
2. **SOAR Platform -** Automated response workflow \& Incident orchestration
3. **EndPoint detection and Response -** Endpoint visibility and control \& Threat containment
4. **Forensics and Investigation tools -** Disk and memory analysis \& Evidence preservation

**--------------------------------**

**When should a live response be performed, and what data should be collected?**



Live response refers to the process of collecting volatile data from a running system during an incident.



**When Should Live Response Be Performed?**

* The system is powered on and active
* Volatile data (RAM, Processes, network connections)
* Shutdown the system would destroy the evidence
* Incident is ongoing
* Business operation cannot be stopped immediately.



**Data collected**

1. **Volatile data -** Running process, Active network, logged-in user, Open files, RAM events
2. **System state information -** System date and time, uptime \& Environment variables
3. **Network Information** - ARP cache, Roting tables \& Listening ports
4. 

**-------------------------------------**

**Describe the steps in live data collection on Microsoft Windows systems**



Windows systems store significant volatile information that is lost upon shutdown



Steps

1. **Preparation** - Use trusted external device, document system details \& ensure minimal system impact
2. **Capture system info.** - Date \& time, system time \& OS version and hostname
3. **Collect running Processes -** List active process \& identify suspicious
4. **Collect Network info. -** Active connection , listening ports \& ARP Cache
5. **Capture Logged-in User -** Current user capture \& Preserve volatile memory
6. **Memory Acquisition -** Capture ram image \& preserve volatile malware artifact
7. **Preserve Collected Data** - Store on-write protected media

**--------------------------------**

**Describe live data collection on Unix-based system**



Unix and Linux systems are widely used in servers and cloud environments



**Steps**

1. **Record System Information -** Date \& time , Uptime \& kernel version
2. Identify Logged-in User - Active sessions \& privileged sessions
3. **Collect running process -** Process listing \& resources listing
4. **Collect Network info. -** Active connection , listening ports \& ARP Cache
5. **Memory Acquisition -** Capture ram image \& preserve volatile malware artifact
6. **Collect open file -** Identify files accessed by suspicious processes
7. Secure Evidence -
8. 

**-------------------------------------**

**Explain how to set up a network monitoring system and collect network logs**



Network monitoring systems provide visibility into traffic patterns, attacks, and anomalies



**Steps**

1. **Identify monitoring points -** Network gateways, Critical servers \& Internet-facing interfaces
2. **Deploy Monitoring Tools -** IDS/IPS, Flow monitoring \& Packet capture
3. **Enable Log generation -** Configure firewalls and routers \& Enable detailed logging.
4. **Centralize Log Collection -** Forward logs to SIEM \& Secure log storage
5. **Correlation and Alerting -** Define detection rules \& set alert
5. 
**----------------------------------------**

**Explain the structure and contents of an incident report**



An incident report is a formal document that records all aspects of a security incident



**Structure**

1. **Executive Summary -** Brief overview of the incident \& Business impact
2. **Incident Description -** Types of incident. date \& time \& system affected
3. **Detection and Analysis -** How the incident was detected \& Indicators of compromise
4. **Response Action -** Containment Steps, Eradication action \& Recovery
5. **Impact assessment -** Data affected, Downtime \& Financial loss
6. **Evidence and documentation -** Logs, Screenshot \& hash values
7. **Lesson learned -** Root cause \& preventives





























































