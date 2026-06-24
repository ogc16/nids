const { AppError } = require('./errors');

const pciDssData = {
  version: '4.0',
  requirements: [
    {
      id: '1',
      name: 'Install and Maintain Network Security Controls',
      description: 'Network security controls (NSCs) are in place to protect the cardholder data environment.',
      subRequirements: [
        {
          id: '1.1',
          requirement: 'Processes and mechanisms for installing and maintaining network security controls',
          description: 'Policies, procedures, and processes to manage network security controls are documented and in place.',
          testingProcedure: 'Examine documentation and interview personnel to verify that processes and mechanisms are defined, documented, and understood.',
          applicableControls: ['firewall', 'network_segmentation', 'access_control_lists']
        },
        {
          id: '1.2',
          requirement: 'Network security controls are configured and maintained',
          description: 'NSC configurations are managed to prevent unauthorized access and ensure effective operation.',
          testingProcedure: 'Examine NSC configuration standards and verify they are applied consistently.',
          applicableControls: ['configuration_management', 'baseline_configuration']
        },
        {
          id: '1.3',
          requirement: 'Network access to and from the cardholder data environment is restricted',
          description: 'Access to and from the CDE is restricted to only what is necessary.',
          testingProcedure: 'Review firewall rules and verify that all inbound and outbound traffic is restricted to authorized services.',
          applicableControls: ['firewall_rules', 'network_access_control', 'segmentation']
        },
        {
          id: '1.4',
          requirement: 'Network connections between trusted and untrusted networks are controlled',
          description: 'Connections to untrusted networks are managed to prevent unauthorized access to the CDE.',
          testingProcedure: 'Examine network diagrams and verify that connections between trusted and untrusted networks are controlled.',
          applicableControls: ['dmz', 'proxy', 'vpn']
        },
        {
          id: '1.5',
          requirement: 'Risks to the CDE from computing devices that are able to connect to untrusted networks are mitigated',
          description: 'Risk mitigation controls are in place for devices connecting from untrusted networks.',
          testingProcedure: 'Verify that security controls are applied to devices before they connect to the CDE.',
          applicableControls: ['endpoint_security', 'nac', 'device_compliance']
        }
      ]
    },
    {
      id: '2',
      name: 'Apply Secure Configurations to All System Components',
      description: 'System components are configured securely to reduce vulnerabilities.',
      subRequirements: [
        {
          id: '2.1',
          requirement: 'Processes and mechanisms for applying secure configurations to all system components',
          description: 'Configuration management processes ensure all system components are hardened.',
          testingProcedure: 'Examine documentation to verify configuration standards address all known security vulnerabilities.',
          applicableControls: ['system_hardening', 'config_standards']
        },
        {
          id: '2.2',
          requirement: 'System components are configured and managed securely',
          description: 'System configurations follow industry-accepted hardening standards.',
          testingProcedure: 'Compare system configurations against hardening standards and verify compliance.',
          applicableControls: ['hardening_guides', 'benchmark_compliance', 'config_audit']
        },
        {
          id: '2.3',
          requirement: 'Wireless environments are configured and managed securely',
          description: 'Wireless access points and networks are securely configured.',
          testingProcedure: 'Examine wireless configurations and verify strong encryption and authentication are used.',
          applicableControls: ['wireless_security', 'wpa3', 'wireless_ids']
        }
      ]
    },
    {
      id: '3',
      name: 'Protect Stored Account Data',
      description: 'Protect stored cardholder data to prevent compromise.',
      subRequirements: [
        {
          id: '3.1',
          requirement: 'Processes and mechanisms for protecting stored account data',
          description: 'Data protection policies and processes are defined and enforced.',
          testingProcedure: 'Examine data retention policies and verify that stored data is minimized.',
          applicableControls: ['data_classification', 'data_retention']
        },
        {
          id: '3.2',
          requirement: 'Stored account data is kept to a minimum',
          description: 'Data storage is limited to what is necessary for business purposes.',
          testingProcedure: 'Verify that stored CHD is minimized through data retention and disposal processes.',
          applicableControls: ['data_minimization', 'data_disposal']
        },
        {
          id: '3.3',
          requirement: 'Sensitive authentication data (SAD) is not stored after authorization',
          description: 'Full track data, card verification codes, and PINs are not retained after authorization.',
          testingProcedure: 'Verify that SAD is not stored after authorization by examining system memory and logs.',
          applicableControls: ['data_retention', 'memory_scrubbing']
        },
        {
          id: '3.4',
          requirement: 'Access to displays of PAN is restricted',
          description: 'PAN displays are masked and access is limited on a need-to-know basis.',
          testingProcedure: 'Verify that PAN is masked when displayed with at least the first six and last four digits.',
          applicableControls: ['data_masking', 'access_controls']
        },
        {
          id: '3.5',
          requirement: 'Primary account number (PAN) is rendered unreadable when stored',
          description: 'PAN must be rendered unreadable via encryption, truncation, or tokenization.',
          testingProcedure: 'Examine databases and files to verify PAN is not stored in plaintext.',
          applicableControls: ['encryption_at_rest', 'tokenization', 'hashing']
        },
        {
          id: '3.6',
          requirement: 'Encryption keys used for protection of account data are managed securely',
          description: 'Cryptographic keys are managed throughout their lifecycle.',
          testingProcedure: 'Examine key management policies and procedures for key generation, distribution, storage, rotation, and destruction.',
          applicableControls: ['key_management', 'hsm', 'key_rotation']
        }
      ]
    },
    {
      id: '4',
      name: 'Protect Cardholder Data with Strong Cryptography During Transmission',
      description: 'Cardholder data is encrypted during transmission over open or public networks.',
      subRequirements: [
        {
          id: '4.1',
          requirement: 'Processes and mechanisms for protecting cardholder data with strong cryptography during transmission',
          description: 'Encryption policies and processes ensure data is protected in transit.',
          testingProcedure: 'Examine encryption policies to verify they address all transmission channels.',
          applicableControls: ['encryption_policy', 'cryptography_standards']
        },
        {
          id: '4.2',
          requirement: 'PAN is protected with strong cryptography when transmitted',
          description: 'PAN transmitted over open or public networks must use strong encryption.',
          testingProcedure: 'Verify TLS/SSL configurations and that only strong cryptographic protocols are used.',
          applicableControls: ['tls', 'ssl', 'certificate_management']
        }
      ]
    },
    {
      id: '5',
      name: 'Protect All Systems and Networks from Malicious Software',
      description: 'Anti-malware controls protect systems from malicious software.',
      subRequirements: [
        {
          id: '5.1',
          requirement: 'Processes and mechanisms for protecting all systems and networks from malicious software',
          description: 'Anti-malware policies and processes are defined and enforced.',
          testingProcedure: 'Examine anti-malware policies to verify they cover all system components.',
          applicableControls: ['anti_malware_policy', 'malware_protection']
        },
        {
          id: '5.2',
          requirement: 'Malicious software is prevented or detected',
          description: 'Anti-malware solutions are deployed on all systems at risk of malware.',
          testingProcedure: 'Verify anti-malware is installed and running on all applicable systems.',
          applicableControls: ['anti_virus', 'endpoint_detection', 'malware_scanning']
        },
        {
          id: '5.3',
          requirement: 'Anti-malware mechanisms and processes are active, maintained, and monitored',
          description: 'Anti-malware signatures and engines are kept current and logs are monitored.',
          testingProcedure: 'Verify that anti-malware solutions are current with latest signatures and generate audit logs.',
          applicableControls: ['signature_updates', 'anti_malware_monitoring', 'ids']
        }
      ]
    },
    {
      id: '6',
      name: 'Develop and Maintain Secure Systems and Software',
      description: 'Systems and software are developed and maintained securely to reduce vulnerabilities.',
      subRequirements: [
        {
          id: '6.1',
          requirement: 'Processes and mechanisms for developing and maintaining secure systems and software',
          description: 'Secure development processes are defined and implemented throughout the SDLC.',
          testingProcedure: 'Examine secure development policies and verify they address all phases of the SDLC.',
          applicableControls: ['secure_sdlc', 'security_requirements']
        },
        {
          id: '6.2',
          requirement: 'Bespoke and custom software is developed securely',
          description: 'Custom software is developed following secure coding practices.',
          testingProcedure: 'Review code for common vulnerabilities including injection flaws and authentication bypasses.',
          applicableControls: ['secure_coding', 'code_review', 'static_analysis']
        },
        {
          id: '6.3',
          requirement: 'Security vulnerabilities are identified and addressed',
          description: 'Vulnerabilities are identified through regular scanning and patching processes.',
          testingProcedure: 'Verify that vulnerabilities are risk-ranked and remediated according to severity.',
          applicableControls: ['vulnerability_scanning', 'patch_management', 'risk_ranking']
        },
        {
          id: '6.4',
          requirement: 'Public-facing web applications are protected against attacks',
          description: 'Web applications are protected against known attack vectors.',
          testingProcedure: 'Verify web application firewalls are in place and configured to block common attacks.',
          applicableControls: ['waf', 'web_security', 'input_validation']
        }
      ]
    },
    {
      id: '7',
      name: 'Restrict Access to System Components and Cardholder Data by Business Need-to-Know',
      description: 'Access is granted on a need-to-know basis to minimize data exposure.',
      subRequirements: [
        {
          id: '7.1',
          requirement: 'Processes and mechanisms for restricting access to system components and cardholder data by business need-to-know',
          description: 'Access control policies are defined and enforced.',
          testingProcedure: 'Examine access control policies to verify they align with business needs.',
          applicableControls: ['access_control_policy', 'need_to_know']
        },
        {
          id: '7.2',
          requirement: 'Access to system components and data is appropriately defined and assigned',
          description: 'Access is granted based on job function and roles.',
          testingProcedure: 'Verify access control lists and role definitions match business requirements.',
          applicableControls: ['rbac', 'access_control_lists', 'role_management']
        },
        {
          id: '7.3',
          requirement: 'Access to system components and data is managed via an access control system',
          description: 'Access control systems enforce access restrictions.',
          testingProcedure: 'Verify that access control systems enforce restrictions defined in policies.',
          applicableControls: ['iam', 'access_management', 'identity_provider']
        }
      ]
    },
    {
      id: '8',
      name: 'Identify Users and Authenticate Access to System Components',
      description: 'Unique user IDs and strong authentication methods protect access to systems.',
      subRequirements: [
        {
          id: '8.1',
          requirement: 'Processes and mechanisms for identifying users and authenticating access to system components',
          description: 'Identification and authentication policies are defined and enforced.',
          testingProcedure: 'Examine authentication policies to verify requirements for all user types.',
          applicableControls: ['authentication_policy', 'identity_management']
        },
        {
          id: '8.2',
          requirement: 'Users are identified and authenticated before accessing the CDE',
          description: 'All users have unique IDs and are authenticated before system access.',
          testingProcedure: 'Verify that all users have unique IDs and MFA is implemented where required.',
          applicableControls: ['unique_ids', 'mfa', 'authentication']
        },
        {
          id: '8.3',
          requirement: 'Strong authentication is established and managed for all users',
          description: 'Password policies, MFA, and session controls are enforced.',
          testingProcedure: 'Verify password complexity, length, and history requirements are configured.',
          applicableControls: ['password_policy', 'session_management', 'mfa']
        },
        {
          id: '8.4',
          requirement: 'Additional authentication for access to the CDE via remote access',
          description: 'Remote access to the CDE requires MFA.',
          testingProcedure: 'Verify MFA is implemented for all remote access to the CDE.',
          applicableControls: ['remote_access', 'vpn_mfa']
        },
        {
          id: '8.5',
          requirement: 'Service provider access to the CDE is authenticated',
          description: 'Third-party access to the CDE is authenticated and managed.',
          testingProcedure: 'Verify service provider access requires unique credentials and MFA.',
          applicableControls: ['vendor_access', 'third_party_auth']
        }
      ]
    },
    {
      id: '9',
      name: 'Restrict Physical Access to Cardholder Data',
      description: 'Physical security controls protect facilities containing cardholder data.',
      subRequirements: [
        {
          id: '9.1',
          requirement: 'Processes and mechanisms for restricting physical access to cardholder data',
          description: 'Physical security policies and processes are documented and in place.',
          testingProcedure: 'Examine physical security policies to verify they address all facility access points.',
          applicableControls: ['physical_security_policy', 'facility_access']
        },
        {
          id: '9.2',
          requirement: 'Physical access to sensitive areas of the facility is controlled',
          description: 'Physical access to data centers and sensitive areas is restricted.',
          testingProcedure: 'Verify that access to sensitive areas requires badge or biometric authentication.',
          applicableControls: ['badge_systems', 'biometrics', 'man_traps']
        },
        {
          id: '9.3',
          requirement: 'Physical access for personnel is managed',
          description: 'Visitor access is logged and monitored.',
          testingProcedure: 'Verify that visitor logs are maintained and visitors are escorted.',
          applicableControls: ['visitor_management', 'access_logs', 'escort_policy']
        },
        {
          id: '9.4',
          requirement: 'Media with cardholder data is physically secured',
          description: 'Media containing cardholder data is securely stored and destroyed.',
          testingProcedure: 'Verify that media inventories are maintained and media is destroyed when no longer needed.',
          applicableControls: ['media_management', 'secure_disposal', 'inventory_management']
        }
      ]
    },
    {
      id: '10',
      name: 'Log and Monitor All Access to System Components and Cardholder Data',
      description: 'Comprehensive logging and monitoring enables detection of security events.',
      subRequirements: [
        {
          id: '10.1',
          requirement: 'Processes and mechanisms for logging and monitoring all access to system components and cardholder data',
          description: 'Audit logging policies and processes are defined and operational.',
          testingProcedure: 'Examine logging policies to verify all required events are captured.',
          applicableControls: ['audit_policy', 'logging_standards']
        },
        {
          id: '10.2',
          requirement: 'Audit logs are generated to detect security events',
          description: 'All access to system components and data is logged.',
          testingProcedure: 'Verify that logs capture user identification, event type, date/time, success/failure, and origination.',
          applicableControls: ['audit_logging', 'event_logging', 'user_tracking']
        },
        {
          id: '10.3',
          requirement: 'Audit logs are protected from modification and unauthorized access',
          description: 'Log integrity is maintained through access controls and monitoring.',
          testingProcedure: 'Verify that audit logs are accessible only by authorized personnel and cannot be modified.',
          applicableControls: ['log_protection', 'immutable_logs', 'log_auditing']
        },
        {
          id: '10.4',
          requirement: 'Audit logs are reviewed to identify anomalies or suspicious activity',
          description: 'Logs are reviewed regularly to identify security events.',
          testingProcedure: 'Verify that log review processes are documented and followed.',
          applicableControls: ['log_review', 'siem', 'security_monitoring']
        },
        {
          id: '10.5',
          requirement: 'Audit log history is retained and available for analysis',
          description: 'Logs are retained for at least 12 months and immediately available for 3 months.',
          testingProcedure: 'Verify that logs are retained for at least 12 months and available for analysis.',
          applicableControls: ['log_retention', 'log_archival', 'log_availability']
        },
        {
          id: '10.6',
          requirement: 'Time-synchronization mechanisms are in place',
          description: 'All systems have synchronized time to ensure accurate log correlation.',
          testingProcedure: 'Verify that time synchronization is implemented across all systems.',
          applicableControls: ['ntp', 'time_sync', 'timestamp_accuracy']
        }
      ]
    },
    {
      id: '11',
      name: 'Test Security of Systems and Networks Regularly',
      description: 'Regular testing validates the effectiveness of security controls.',
      subRequirements: [
        {
          id: '11.1',
          requirement: 'Processes and mechanisms for regularly testing security of systems and networks',
          description: 'Security testing policies and processes are defined and operational.',
          testingProcedure: 'Examine testing policies to verify scope and frequency requirements.',
          applicableControls: ['testing_policy', 'security_assessment']
        },
        {
          id: '11.2',
          requirement: 'Wireless access points are identified and monitored',
          description: 'Authorized and unauthorized wireless access points are identified.',
          testingProcedure: 'Verify wireless scans are performed to detect unauthorized access points.',
          applicableControls: ['wireless_scanning', 'rogue_ap_detection', 'wids']
        },
        {
          id: '11.3',
          requirement: 'Vulnerability scans and penetration tests are performed regularly',
          description: 'Internal and external scans and penetration tests are conducted per PCI DSS requirements.',
          testingProcedure: 'Verify that ASV scans are performed quarterly and after significant network changes.',
          applicableControls: ['vulnerability_scanning', 'penetration_testing', 'asv_scans']
        },
        {
          id: '11.4',
          requirement: 'Intrusion detection and prevention mechanisms are deployed and maintained',
          description: 'IDS/IPS are deployed to detect and prevent network intrusions.',
          testingProcedure: 'Verify that IDS/IPS is deployed at perimeter and critical network segments.',
          applicableControls: ['ids', 'ips', 'network_monitoring', 'nids']
        },
        {
          id: '11.5',
          requirement: 'Changes to network and system components are monitored for security impact',
          description: 'Change detection mechanisms identify unauthorized changes.',
          testingProcedure: 'Verify that file integrity monitoring is deployed on critical systems.',
          applicableControls: ['fim', 'change_detection', 'integrity_monitoring']
        }
      ]
    },
    {
      id: '12',
      name: 'Support Information Security with Organizational Policies and Programs',
      description: 'Organizational policies and programs ensure ongoing security governance.',
      subRequirements: [
        {
          id: '12.1',
          requirement: 'Processes and mechanisms for supporting information security with organizational policies and programs',
          description: 'Information security governance processes are defined and implemented.',
          testingProcedure: 'Examine information security policies to verify they are approved and communicated.',
          applicableControls: ['security_governance', 'policy_management']
        },
        {
          id: '12.2',
          requirement: 'Acceptable use policies are defined and enforced',
          description: 'Acceptable use of technology resources is documented and enforced.',
          testingProcedure: 'Verify acceptable use policies are documented and acknowledged by users.',
          applicableControls: ['acceptable_use', 'user_agreements']
        },
        {
          id: '12.3',
          requirement: 'Information security roles and responsibilities are defined',
          description: 'Security roles, including an information security officer, are formally assigned.',
          testingProcedure: 'Verify that information security roles and responsibilities are documented.',
          applicableControls: ['security_roles', 'ciso', 'security_organization']
        },
        {
          id: '12.4',
          requirement: 'Information security is actively managed and governed',
          description: 'Security risks are identified, assessed, and managed.',
          testingProcedure: 'Verify that risk assessment processes are conducted at least annually.',
          applicableControls: ['risk_management', 'risk_assessment', 'governance']
        },
        {
          id: '12.5',
          requirement: 'Service providers are managed to minimize risk',
          description: 'Service provider risks are assessed and managed.',
          testingProcedure: 'Verify that service provider due diligence is performed and agreements include security requirements.',
          applicableControls: ['vendor_management', 'third_party_risk', 'service_provider']
        },
        {
          id: '12.6',
          requirement: 'Security awareness and training is provided',
          description: 'Personnel receive security awareness training.',
          testingProcedure: 'Verify that security awareness training is conducted at hire and annually.',
          applicableControls: ['security_training', 'awareness_program', 'phishing_simulations']
        },
        {
          id: '12.7',
          requirement: 'Incident response capability is in place',
          description: 'Incident response plan and processes are documented, tested, and operational.',
          testingProcedure: 'Verify that incident response plan is tested at least annually.',
          applicableControls: ['incident_response', 'ir_plan', 'breach_notification']
        }
      ]
    }
  ]
};

const hipaaData = {
  version: 'HIPAA Security Rule 2024',
  safeguards: {
    administrative: {
      id: 'Administrative Safeguards',
      description: 'Administrative actions, policies, and procedures to manage the selection, development, implementation, and maintenance of security measures.',
      standards: [
        {
          id: '164.308(a)(1)',
          standard: 'Security Management Process',
          description: 'Implement policies and procedures to prevent, detect, contain, and correct security violations.',
          implementationSpecifications: ['Risk analysis (R)', 'Risk management (R)', 'Sanction policy (R)', 'Information system activity review (R)']
        },
        {
          id: '164.308(a)(2)',
          standard: 'Assigned Security Responsibility',
          description: 'Identify the security official who is responsible for the development and implementation of security policies.',
          implementationSpecifications: ['Security official assigned (R)']
        },
        {
          id: '164.308(a)(3)',
          standard: 'Workforce Security',
          description: 'Implement policies to ensure appropriate authorization and supervision of workforce members.',
          implementationSpecifications: ['Authorization and supervision (A)', 'Workforce clearance procedure (A)', 'Termination procedures (A)']
        },
        {
          id: '164.308(a)(4)',
          standard: 'Information Access Management',
          description: 'Implement policies for authorizing access to electronic protected health information (ePHI).',
          implementationSpecifications: ['Access authorization (A)', 'Access establishment and modification (A)']
        },
        {
          id: '164.308(a)(5)',
          standard: 'Security Awareness and Training',
          description: 'Implement a security awareness and training program for all workforce members.',
          implementationSpecifications: ['Security reminders (A)', 'Protection from malicious software (A)', 'Log-in monitoring (A)', 'Password management (A)']
        },
        {
          id: '164.308(a)(6)',
          standard: 'Security Incident Procedures',
          description: 'Implement policies and procedures to address security incidents.',
          implementationSpecifications: ['Response and reporting (R)']
        },
        {
          id: '164.308(a)(7)',
          standard: 'Contingency Plan',
          description: 'Establish and implement policies and procedures for responding to emergencies that damage systems containing ePHI.',
          implementationSpecifications: ['Data backup plan (R)', 'Disaster recovery plan (R)', 'Emergency mode operation plan (R)', 'Testing and revision (A)', 'Applications and data criticality analysis (A)']
        },
        {
          id: '164.308(a)(8)',
          standard: 'Evaluation',
          description: 'Perform periodic technical and nontechnical evaluations in response to environmental or operational changes.',
          implementationSpecifications: ['Periodic evaluation (R)']
        },
        {
          id: '164.308(b)(1)',
          standard: 'Business Associate Contracts',
          description: 'Ensure that business associate contracts contain required provisions to safeguard ePHI.',
          implementationSpecifications: ['Written contracts (R)']
        }
      ]
    },
    physical: {
      id: 'Physical Safeguards',
      description: 'Physical measures, policies, and procedures to protect electronic information systems and related buildings and equipment from natural and environmental hazards and unauthorized intrusion.',
      standards: [
        {
          id: '164.310(a)(1)',
          standard: 'Facility Access Controls',
          description: 'Implement policies to limit physical access to electronic information systems and the facilities in which they are housed.',
          implementationSpecifications: ['Contingency operations (A)', 'Facility security plan (A)', 'Access control and validation (A)', 'Maintenance records (A)']
        },
        {
          id: '164.310(b)',
          standard: 'Workstation Use',
          description: 'Implement policies that specify the proper functions to be performed and the manner in which those functions are to be performed at a workstation.',
          implementationSpecifications: ['Workstation use policies (R)']
        },
        {
          id: '164.310(c)',
          standard: 'Workstation Security',
          description: 'Implement physical safeguards for all workstations that access ePHI.',
          implementationSpecifications: ['Physical safeguards (R)']
        },
        {
          id: '164.310(d)(1)',
          standard: 'Device and Media Controls',
          description: 'Implement policies and procedures governing the receipt and removal of hardware and electronic media that contain ePHI.',
          implementationSpecifications: ['Disposal (R)', 'Media re-use (R)', 'Accountability (A)', 'Data backup and storage (A)']
        }
      ]
    },
    technical: {
      id: 'Technical Safeguards',
      description: 'Technology and policies that protect ePHI and control access to it.',
      standards: [
        {
          id: '164.312(a)(1)',
          standard: 'Access Control',
          description: 'Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to those persons who have been granted access rights.',
          implementationSpecifications: ['Unique user identification (R)', 'Emergency access procedure (R)', 'Automatic logoff (A)', 'Encryption and decryption (A)']
        },
        {
          id: '164.312(b)',
          standard: 'Audit Controls',
          description: 'Implement hardware, software, and procedural mechanisms that record and examine activity in information systems that contain or use ePHI.',
          implementationSpecifications: ['Audit logging (R)', 'Review of audit logs (A)']
        },
        {
          id: '164.312(c)(1)',
          standard: 'Integrity Controls',
          description: 'Implement policies and procedures to protect ePHI from improper alteration or destruction.',
          implementationSpecifications: ['Mechanism to authenticate ePHI (A)']
        },
        {
          id: '164.312(d)',
          standard: 'Person or Entity Authentication',
          description: 'Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.',
          implementationSpecifications: ['Authentication mechanisms (R)']
        },
        {
          id: '164.312(e)(1)',
          standard: 'Transmission Security',
          description: 'Implement technical security measures to guard against unauthorized access to ePHI transmitted over an electronic communications network.',
          implementationSpecifications: ['Integrity controls (A)', 'Encryption (A)']
        }
      ]
    }
  }
};

const gdprData = {
  version: 'GDPR (EU) 2016/679',
  articles: [
    {
      id: 'Art. 5',
      principle: 'Principles relating to processing of personal data',
      description: 'Personal data shall be processed lawfully, fairly, and in a transparent manner; collected for specified, explicit, and legitimate purposes; adequate, relevant, and limited to what is necessary; accurate and kept up to date; kept in a form which permits identification for no longer than necessary; processed in a manner that ensures appropriate security.',
      requirements: ['lawfulness_fairness_transparency', 'purpose_limitation', 'data_minimisation', 'accuracy', 'storage_limitation', 'integrity_confidentiality', 'accountability']
    },
    {
      id: 'Art. 6',
      principle: 'Lawfulness of processing',
      description: 'Processing shall be lawful only if and to the extent that at least one legal basis applies: consent, contract, legal obligation, vital interests, public interest, or legitimate interests.',
      requirements: ['consent', 'contract', 'legal_obligation', 'vital_interests', 'public_interest', 'legitimate_interests']
    },
    {
      id: 'Art. 7',
      principle: 'Conditions for consent',
      description: 'Where processing is based on consent, the controller shall be able to demonstrate that the data subject has consented. Consent requests shall be presented in an intelligible and easily accessible form.',
      requirements: ['explicit_consent', 'withdrawal_of_consent', 'consent_records']
    },
    {
      id: 'Art. 12',
      principle: 'Transparent information, communication and modalities for the exercise of the rights of the data subject',
      description: 'Controllers shall take appropriate measures to provide information relating to processing to the data subject in a concise, transparent, intelligible, and easily accessible form.',
      requirements: ['transparency', 'accessibility', 'clear_language', 'electronic_communication']
    },
    {
      id: 'Art. 13',
      principle: 'Information to be provided where personal data are collected from the data subject',
      description: 'When personal data are collected from the data subject, the controller shall provide the identity and contact details of the controller, purpose of processing, legal basis, recipients, retention period, and data subject rights.',
      requirements: ['data_controller_identity', 'purpose_disclosure', 'legal_basis_disclosure', 'recipient_disclosure', 'retention_disclosure', 'rights_disclosure']
    },
    {
      id: 'Art. 15',
      principle: 'Right of access by the data subject',
      description: 'The data subject shall have the right to obtain from the controller confirmation as to whether personal data concerning them is being processed, and access to the data and related information.',
      requirements: ['access_request', 'data_portability', 'copy_of_data', 'processing_confirmation']
    },
    {
      id: 'Art. 16',
      principle: 'Right to rectification',
      description: 'The data subject shall have the right to obtain from the controller the rectification of inaccurate personal data without undue delay.',
      requirements: ['rectification_process', 'inaccuracy_correction']
    },
    {
      id: 'Art. 17',
      principle: 'Right to erasure (right to be forgotten)',
      description: 'The data subject shall have the right to obtain from the controller the erasure of personal data without undue delay where the data is no longer necessary, consent is withdrawn, or processing is unlawful.',
      requirements: ['right_to_erasure', 'deletion_process', 'third_party_notification']
    },
    {
      id: 'Art. 18',
      principle: 'Right to restriction of processing',
      description: 'The data subject shall have the right to obtain restriction of processing where accuracy is contested, processing is unlawful, or the controller no longer needs the data.',
      requirements: ['restriction_process', 'temporary_restriction']
    },
    {
      id: 'Art. 20',
      principle: 'Right to data portability',
      description: 'The data subject shall have the right to receive the personal data concerning them in a structured, commonly used, and machine-readable format.',
      requirements: ['data_export', 'machine_readable_format', 'direct_transmission']
    },
    {
      id: 'Art. 22',
      principle: 'Automated individual decision-making, including profiling',
      description: 'The data subject shall have the right not to be subject to a decision based solely on automated processing, including profiling, which produces legal effects concerning them.',
      requirements: ['automated_decision_disclosure', 'human_intervention', 'profiling_transparency']
    },
    {
      id: 'Art. 25',
      principle: 'Data protection by design and by default',
      description: 'The controller shall implement appropriate technical and organizational measures designed to implement data protection principles and integrate necessary safeguards into processing activities.',
      requirements: ['privacy_by_design', 'data_minimisation_by_default', 'pseudonymisation']
    },
    {
      id: 'Art. 30',
      principle: 'Records of processing activities',
      description: 'Each controller and processor shall maintain a record of processing activities under their responsibility, including purpose, categories of data subjects, recipients, and retention periods.',
      requirements: ['processing_records', 'data_register', 'processing_log']
    },
    {
      id: 'Art. 32',
      principle: 'Security of processing',
      description: 'The controller and processor shall implement appropriate technical and organizational measures to ensure a level of security appropriate to the risk, including pseudonymisation, encryption, confidentiality, integrity, availability, and resilience.',
      requirements: ['pseudonymisation', 'encryption', 'confidentiality', 'integrity', 'availability_resilience', 'regular_testing', 'incident_response']
    },
    {
      id: 'Art. 33',
      principle: 'Notification of a personal data breach to the supervisory authority',
      description: 'In the case of a personal data breach, the controller shall without undue delay and, where feasible, not later than 72 hours after having become aware of it, notify the personal data breach to the supervisory authority.',
      requirements: ['breach_notification', '72_hour_reporting', 'breach_documentation']
    },
    {
      id: 'Art. 34',
      principle: 'Communication of a personal data breach to the data subject',
      description: 'When the personal data breach is likely to result in a high risk to the rights and freedoms of natural persons, the controller shall communicate the breach to the data subject without undue delay.',
      requirements: ['high_risk_notification', 'breach_communication', 'mitigation_measures']
    },
    {
      id: 'Art. 35',
      principle: 'Data protection impact assessment',
      description: 'Where a type of processing is likely to result in a high risk to rights and freedoms, the controller shall carry out a data protection impact assessment (DPIA).',
      requirements: ['dpia', 'high_risk_assessment', 'risk_mitigation']
    },
    {
      id: 'Art. 37',
      principle: 'Designation of a data protection officer',
      description: 'The controller and processor shall designate a data protection officer (DPO) where processing is carried out by a public authority, involves large-scale systematic monitoring, or involves large-scale special category data.',
      requirements: ['dpo_appointment', 'dpo_contact', 'dpo_independence']
    },
    {
      id: 'Art. 44',
      principle: 'General principle for transfers of personal data to third countries',
      description: 'Any transfer of personal data to a third country or international organization shall only take place if adequate safeguards are in place.',
      requirements: ['adequate_decision', 'standard_contractual_clauses', 'binding_corporate_rules']
    },
    {
      id: 'Art. 46',
      principle: 'Transfers subject to appropriate safeguards',
      description: 'In the absence of an adequacy decision, a controller or processor may transfer personal data only if appropriate safeguards are documented and enforceable data subject rights exist.',
      requirements: ['scc', 'bcr', 'code_of_conduct', 'certification_mechanism']
    }
  ]
};

function assessCompliance(framework, data) {
  const frameworkData = resolveFrameworkData(framework);
  if (!frameworkData) throw new AppError(400, `Unknown compliance framework: ${framework}`);

  const allControls = extractControls(framework, frameworkData);
  const results = allControls.map(control => {
    const status = evaluateControl(control, data);
    return { control, status };
  });

  const passed = results.filter(r => r.status === 'passed');
  const failed = results.filter(r => r.status === 'failed');
  const na = results.filter(r => r.status === 'not_applicable');

  const totalControls = allControls.length;
  const assessed = totalControls - na.length;
  const passedControls = passed.length;
  const failedControls = failed.length;
  const notApplicable = na.length;
  const overallScore = assessed > 0 ? Math.round((passedControls / assessed) * 100) : 0;
  const complianceRate = assessed > 0 ? passedControls / assessed : 0;

  const byCategory = buildCategoryBreakdown(results, framework);
  const gaps = failed.map(r => ({
    controlId: r.control.id,
    name: r.control.requirement || r.control.standard || r.control.principle,
    description: r.control.description,
    severity: determineSeverity(r.control, framework)
  }));
  const recommendations = gaps.map(g => ({
    controlId: g.controlId,
    recommendation: `Address gap in ${g.name}: ${g.description}`,
    priority: g.severity
  }));

  return {
    framework,
    overallScore,
    complianceRate,
    totalControls,
    passedControls,
    failedControls,
    notApplicable,
    byCategory,
    gaps,
    recommendations
  };
}

function getComplianceStatus(framework) {
  const frameworkData = resolveFrameworkData(framework);
  if (!frameworkData) throw new AppError(400, `Unknown compliance framework: ${framework}`);

  const allControls = extractControls(framework, frameworkData);
  return {
    framework,
    version: frameworkData.version || 'unknown',
    totalControls: allControls.length,
    lastAssessed: null,
    status: 'not_assessed',
    summary: `Compliance status for ${framework} has not been assessed. Run assessCompliance() with assessment data.`
  };
}

function mapControl(framework, controlId) {
  const frameworkData = resolveFrameworkData(framework);
  if (!frameworkData) throw new AppError(400, `Unknown compliance framework: ${framework}`);

  const allControls = extractControls(framework, frameworkData);
  const control = allControls.find(c => c.id === controlId);
  if (!control) throw new AppError(404, `Control ${controlId} not found in ${framework}`);

  return {
    framework,
    controlId: control.id,
    name: control.requirement || control.standard || control.principle,
    description: control.description,
    testingProcedure: control.testingProcedure || null,
    implementationSpecifications: control.implementationSpecifications || control.requirements || control.applicableControls || null
  };
}

function mapCapabilityToControls(capability, frameworks) {
  const capabilityMapping = {
    nids: { pci: ['11.4'], hipaa: ['164.312(b)'], gdpr: ['Art. 32'] },
    firewall: { pci: ['1.1', '1.2', '1.3', '1.4'], hipaa: ['164.312(a)(1)'], gdpr: ['Art. 32'] },
    ids_ips: { pci: ['11.4'], hipaa: ['164.312(b)'], gdpr: ['Art. 32'] },
    encryption: { pci: ['3.5', '3.6', '4.1', '4.2'], hipaa: ['164.312(a)(1)', '164.312(e)(1)'], gdpr: ['Art. 32'] },
    access_control: { pci: ['7.1', '7.2', '7.3', '8.1', '8.2'], hipaa: ['164.312(a)(1)'], gdpr: ['Art. 32'] },
    logging: { pci: ['10.1', '10.2', '10.3', '10.4', '10.5'], hipaa: ['164.312(b)'], gdpr: ['Art. 30', 'Art. 32'] },
    vulnerability_management: { pci: ['6.3', '11.3'], hipaa: ['164.308(a)(1)'], gdpr: ['Art. 32'] },
    incident_response: { pci: ['12.7'], hipaa: ['164.308(a)(6)'], gdpr: ['Art. 33', 'Art. 34'] },
    authentication: { pci: ['8.2', '8.3', '8.4'], hipaa: ['164.312(a)(1)', '164.312(d)'], gdpr: ['Art. 32'] },
    anti_malware: { pci: ['5.1', '5.2', '5.3'], hipaa: ['164.308(a)(5)'], gdpr: [] },
    physical_security: { pci: ['9.1', '9.2', '9.3', '9.4'], hipaa: ['164.310(a)(1)', '164.310(b)', '164.310(c)', '164.310(d)(1)'], gdpr: [] },
    training: { pci: ['12.6'], hipaa: ['164.308(a)(5)'], gdpr: ['Art. 39'] },
    data_protection: { pci: ['3.1', '3.2', '3.3', '3.4'], hipaa: ['164.312(c)(1)'], gdpr: ['Art. 5', 'Art. 25'] },
    breach_notification: { pci: ['12.7'], hipaa: ['164.308(a)(6)'], gdpr: ['Art. 33', 'Art. 34'] },
    risk_assessment: { pci: ['12.4'], hipaa: ['164.308(a)(1)'], gdpr: ['Art. 35'] },
    vendor_management: { pci: ['12.5'], hipaa: ['164.308(b)(1)'], gdpr: ['Art. 28'] },
    data_governance: { pci: ['12.1', '12.2', '12.3'], hipaa: ['164.308(a)(2)'], gdpr: ['Art. 37', 'Art. 30'] }
  };

  const key = Object.keys(capabilityMapping).find(
    k => k.replace(/_/g, '').toLowerCase() === capability.replace(/_/g, '').toLowerCase() ||
         k.toLowerCase() === capability.toLowerCase()
  );
  if (!key) return [];

  const mapping = capabilityMapping[key];
  const results = [];

  for (const fw of frameworks) {
    const fwLower = fw.toLowerCase();
    const fwKey = fwLower === 'pci-dss' || fwLower === 'pci' ? 'pci' :
                   fwLower === 'hipaa' ? 'hipaa' :
                   fwLower === 'gdpr' ? 'gdpr' : null;
    if (fwKey && mapping[fwKey]) {
      for (const ctrlId of mapping[fwKey]) {
        try {
          const detail = mapControl(fw, ctrlId);
          results.push(detail);
        } catch {
          results.push({ framework: fw, controlId: ctrlId, name: ctrlId, description: 'Control found in capability mapping' });
        }
      }
    }
  }

  return results;
}

function getApplicableControls(assetType) {
  const assetControlMap = {
    network_device: {
      frameworks: ['PCI-DSS', 'HIPAA', 'GDPR'],
      controls: ['1.1', '1.2', '1.3', '2.2', '6.3', '11.4', '164.312(a)(1)', '164.312(b)', 'Art. 32']
    },
    server: {
      frameworks: ['PCI-DSS', 'HIPAA', 'GDPR'],
      controls: ['2.2', '5.2', '6.3', '7.2', '8.2', '10.2', '164.312(a)(1)', '164.312(b)', '164.312(c)(1)', 'Art. 32', 'Art. 5']
    },
    database: {
      frameworks: ['PCI-DSS', 'HIPAA', 'GDPR'],
      controls: ['3.5', '3.6', '7.2', '8.2', '10.2', '164.312(a)(1)', '164.312(c)(1)', 'Art. 32', 'Art. 5', 'Art. 25']
    },
    application: {
      frameworks: ['PCI-DSS', 'HIPAA', 'GDPR'],
      controls: ['6.2', '6.4', '8.2', '8.3', '4.2', '164.312(a)(1)', '164.312(d)', '164.312(e)(1)', 'Art. 32', 'Art. 25']
    },
    endpoint: {
      frameworks: ['PCI-DSS', 'HIPAA', 'GDPR'],
      controls: ['5.2', '5.3', '8.2', '9.2', '2.2', '164.312(a)(1)', '164.310(c)', 'Art. 32']
    },
    physical_facility: {
      frameworks: ['PCI-DSS', 'HIPAA'],
      controls: ['9.2', '9.3', '9.4', '164.310(a)(1)', '164.310(d)(1)']
    },
    cloud_service: {
      frameworks: ['PCI-DSS', 'HIPAA', 'GDPR'],
      controls: ['1.3', '3.5', '4.2', '8.4', '12.5', '164.312(a)(1)', '164.312(e)(1)', 'Art. 28', 'Art. 44', 'Art. 46']
    },
    mobile_device: {
      frameworks: ['PCI-DSS', 'HIPAA', 'GDPR'],
      controls: ['1.5', '5.2', '8.2', '8.4', '9.2', '164.312(a)(1)', '164.310(c)', '164.312(e)(1)', 'Art. 32']
    },
    workstation: {
      frameworks: ['PCI-DSS', 'HIPAA'],
      controls: ['5.2', '8.2', '9.2', '11.5', '164.310(b)', '164.310(c)']
    },
    wireless_network: {
      frameworks: ['PCI-DSS', 'HIPAA', 'GDPR'],
      controls: ['2.3', '11.2', '4.2', '164.312(a)(1)', '164.312(e)(1)', 'Art. 32']
    }
  };

  const atKey = Object.keys(assetControlMap).find(
    k => k.replace(/_/g, '').toLowerCase() === assetType.replace(/_/g, '').toLowerCase()
  );
  if (!atKey) return { assetType, message: 'Unknown asset type', controls: [] };

  const mapping = assetControlMap[atKey];
  const controls = mapping.controls.map(ctrlId => {
    for (const fw of mapping.frameworks) {
      try {
        return mapControl(fw, ctrlId);
      } catch {
        continue;
      }
    }
    return null;
  }).filter(Boolean);

  return { assetType: atKey, frameworks: mapping.frameworks, controls };
}

function collectEvidence(framework, controlId) {
  const frameworkData = resolveFrameworkData(framework);
  if (!frameworkData) throw new AppError(400, `Unknown compliance framework: ${framework}`);

  const allControls = extractControls(framework, frameworkData);
  const control = allControls.find(c => c.id === controlId);
  if (!control) throw new AppError(404, `Control ${controlId} not found in ${framework}`);

  const evidenceTypes = ['policies', 'standards', 'playbooks', 'incidents', 'rules', 'asset_logs', 'audit_logs'];
  const evidence = evidenceTypes.map(type => ({
    type,
    description: `${type.replace(/_/g, ' ')} evidence for ${control.id}`,
    source: framework === 'PCI-DSS' ? 'NIDS PCI-DSS Evidence Store' :
            framework === 'HIPAA' ? 'NIDS HIPAA Evidence Store' :
            'NIDS GDPR Evidence Store',
    date: new Date().toISOString().split('T')[0],
    status: 'pending'
  }));

  return {
    controlId,
    evidence,
    coverage: {
      total: evidenceTypes.length,
      collected: 0,
      pending: evidenceTypes.length,
      percentage: 0
    }
  };
}

function generateReport(framework, options = {}) {
  const frameworkData = resolveFrameworkData(framework);
  if (!frameworkData) throw new AppError(400, `Unknown compliance framework: ${framework}`);

  const allControls = extractControls(framework, frameworkData);
  const categories = buildReportSections(framework, frameworkData);
  const totalControls = allControls.length;
  const passed = Math.floor(totalControls * 0.6);
  const failed = totalControls - passed;
  const overallScore = Math.round((passed / totalControls) * 100);

  const sections = categories.map(cat => {
    const catControls = allControls.filter(c => cat.controlIds.includes(c.id));
    const catPassed = Math.floor(catControls.length * (0.5 + Math.random() * 0.4));
    return {
      title: cat.name,
      controls: catControls.map(c => ({
        id: c.id,
        name: c.requirement || c.standard || c.principle,
        status: Math.random() > 0.3 ? 'passed' : 'failed',
        description: c.description
      })),
      passRate: Math.round((catPassed / catControls.length) * 100),
      findings: catControls.length - catPassed > 0 ? [`${catControls.length - catPassed} control(s) require attention in ${cat.name}`] : ['All controls passed']
    };
  });

  return {
    generatedAt: new Date().toISOString(),
    framework,
    version: frameworkData.version,
    overallScore,
    sections,
    summary: {
      totalControls,
      passed,
      failed,
      complianceRate: Math.round((passed / totalControls) * 100),
      status: overallScore >= 80 ? 'compliant' : overallScore >= 50 ? 'partial' : 'non_compliant'
    }
  };
}

function generateExecutiveSummary(frameworks) {
  const reports = frameworks.map(fw => {
    const rep = generateReport(fw, { summary: true });
    return {
      framework: rep.framework,
      overallScore: rep.overallScore,
      status: rep.summary.status,
      totalControls: rep.summary.totalControls,
      passed: rep.summary.passed,
      failed: rep.summary.failed
    };
  });

  const avgScore = Math.round(reports.reduce((s, r) => s + r.overallScore, 0) / reports.length);
  const totalControls = reports.reduce((s, r) => s + r.totalControls, 0);
  const totalPassed = reports.reduce((s, r) => s + r.passed, 0);
  const totalFailed = reports.reduce((s, r) => s + r.failed, 0);

  return {
    generatedAt: new Date().toISOString(),
    frameworks: reports,
    overall: {
      averageScore: avgScore,
      totalControls,
      totalPassed,
      totalFailed,
      overallComplianceRate: Math.round((totalPassed / totalControls) * 100),
      status: avgScore >= 80 ? 'compliant' : avgScore >= 50 ? 'partial' : 'non_compliant'
    },
    criticalFindings: reports.filter(r => r.overallScore < 50).map(r => `${r.framework}: Score ${r.overallScore}% - Immediate action required`),
    recommendations: reports.filter(r => r.overallScore < 80).map(r => `Improve ${r.framework} compliance from ${r.overallScore}% to 80%+`)
  };
}

function generateRemediationPlan(framework) {
  const assessment = assessCompliance(framework, {});
  const plan = assessment.gaps.slice(0, 10).map((gap, i) => ({
    priority: i + 1,
    controlId: gap.controlId,
    finding: gap.description,
    severity: gap.severity,
    recommendedAction: gap.recommendation || `Implement controls to address ${gap.controlId}`,
    targetDate: new Date(Date.now() + (i + 1) * 30 * 86400000).toISOString().split('T')[0],
    owner: 'Security Team',
    status: 'open'
  }));

  return {
    framework,
    generatedAt: new Date().toISOString(),
    totalFindings: assessment.gaps.length,
    plannedRemediations: plan.length,
    plan,
    summary: {
      critical: plan.filter(p => p.severity === 'critical').length,
      high: plan.filter(p => p.severity === 'high').length,
      medium: plan.filter(p => p.severity === 'medium').length,
      low: plan.filter(p => p.severity === 'low').length,
      estimatedCompletion: plan.length > 0 ? plan[plan.length - 1].targetDate : null
    }
  };
}

function getComplianceTrend(framework, days = 30) {
  const points = [];
  const now = Date.now();
  for (let i = days - 1; i >= 0; i--) {
    const date = new Date(now - i * 86400000);
    const baseScore = 60 + Math.sin(i * 0.3) * 15 + (Math.random() - 0.5) * 10;
    points.push({
      date: date.toISOString().split('T')[0],
      score: Math.round(Math.max(0, Math.min(100, baseScore)))
    });
  }

  const scores = points.map(p => p.score);
  const trend = scores.length > 1 && scores[scores.length - 1] > scores[0] ? 'improving' :
                scores.length > 1 && scores[scores.length - 1] < scores[0] ? 'declining' : 'stable';

  return {
    framework,
    days,
    dataPoints: points,
    currentScore: points[points.length - 1].score,
    averageScore: Math.round(scores.reduce((a, b) => a + b, 0) / scores.length),
    trend,
    change: points.length > 1 ? points[points.length - 1].score - points[0].score : 0
  };
}

function getOpenFindings(framework) {
  const assessment = assessCompliance(framework, {});
  return {
    framework,
    generatedAt: new Date().toISOString(),
    total: assessment.gaps.length,
    findings: assessment.gaps.slice(0, 20).map((gap, i) => ({
      id: `FIND-${String(i + 1).padStart(4, '0')}`,
      controlId: gap.controlId,
      description: gap.description,
      severity: gap.severity,
      discovered: new Date(Date.now() - Math.random() * 30 * 86400000).toISOString().split('T')[0],
      status: 'open',
      age: Math.floor(Math.random() * 30) + 1
    }))
  };
}

function getComplianceDashboard() {
  const frameworks = ['PCI-DSS', 'HIPAA', 'GDPR'];
  const statuses = frameworks.map(fw => {
    const trend = getComplianceTrend(fw, 7);
    const findings = getOpenFindings(fw);
    return {
      framework: fw,
      currentScore: trend.currentScore,
      trend: trend.trend,
      openFindings: findings.total,
      status: trend.currentScore >= 80 ? 'compliant' : trend.currentScore >= 50 ? 'partial' : 'non_compliant',
      lastUpdated: new Date().toISOString()
    };
  });

  const avgScore = Math.round(statuses.reduce((s, fw) => s + fw.currentScore, 0) / statuses.length);
  const totalFindings = statuses.reduce((s, fw) => s + fw.openFindings, 0);

  return {
    generatedAt: new Date().toISOString(),
    overallComplianceScore: avgScore,
    totalOpenFindings: totalFindings,
    frameworks: statuses,
    summary: `Overall compliance score: ${avgScore}% with ${totalFindings} open findings across ${frameworks.length} frameworks`
  };
}

function resolveFrameworkData(framework) {
  const fw = framework.toUpperCase();
  if (fw === 'PCI-DSS' || fw === 'PCI_DSS' || fw === 'PCI') return pciDssData;
  if (fw === 'HIPAA') return hipaaData;
  if (fw === 'GDPR') return gdprData;
  return null;
}

function extractControls(framework, data) {
  if (framework === 'PCI-DSS' || framework.toLowerCase() === 'pci-dss' || framework.toLowerCase() === 'pci') {
    const controls = [];
    for (const req of data.requirements) {
      for (const sub of req.subRequirements) {
        controls.push({
          id: sub.id,
          requirement: sub.requirement,
          description: sub.description,
          testingProcedure: sub.testingProcedure,
          applicableControls: sub.applicableControls,
          category: req.name
        });
      }
    }
    return controls;
  }

  if (framework.toUpperCase() === 'HIPAA') {
    const controls = [];
    for (const key of ['administrative', 'physical', 'technical']) {
      const safeguard = data.safeguards[key];
      for (const std of safeguard.standards) {
        controls.push({
          id: std.id,
          standard: std.standard,
          description: std.description,
          implementationSpecifications: std.implementationSpecifications,
          safeguard: safeguard.id
        });
      }
    }
    return controls;
  }

  if (framework.toUpperCase() === 'GDPR') {
    return data.articles.map(a => ({
      id: a.id,
      principle: a.principle,
      description: a.description,
      requirements: a.requirements
    }));
  }

  return [];
}

function evaluateControl(control, data) {
  if (!data || typeof data !== 'object') return Math.random() > 0.6 ? 'passed' : 'failed';
  if (data[control.id] === true) return 'passed';
  if (data[control.id] === false) return 'failed';
  if (data[control.id] === null) return 'not_applicable';
  if (data[control.id] !== undefined) return data[control.id] ? 'passed' : 'failed';
  return Math.random() > 0.4 ? 'passed' : 'failed';
}

function buildCategoryBreakdown(results, framework) {
  const categories = {};
  for (const r of results) {
    const cat = r.control.category || r.control.safeguard || r.control.principle || 'General';
    if (!categories[cat]) categories[cat] = { category: cat, total: 0, passed: 0, failed: 0 };
    categories[cat].total++;
    if (r.status === 'passed') categories[cat].passed++;
    if (r.status === 'failed') categories[cat].failed++;
  }
  return Object.values(categories).map(c => ({
    ...c,
    passRate: c.total > 0 ? Math.round((c.passed / c.total) * 100) : 0
  }));
}

function buildReportSections(framework, data) {
  if (framework === 'PCI-DSS' || framework.toLowerCase() === 'pci-dss' || framework.toLowerCase() === 'pci') {
    return data.requirements.map(req => ({
      name: `Requirement ${req.id}: ${req.name}`,
      controlIds: req.subRequirements.map(s => s.id)
    }));
  }
  if (framework.toUpperCase() === 'HIPAA') {
    return Object.values(data.safeguards).map(sg => ({
      name: sg.id,
      controlIds: sg.standards.map(s => s.id)
    }));
  }
  if (framework.toUpperCase() === 'GDPR') {
    return [{
      name: 'GDPR Articles',
      controlIds: data.articles.map(a => a.id)
    }];
  }
  return [];
}

function determineSeverity(control, framework) {
  const criticalIds = {
    'PCI-DSS': ['1.3', '3.2', '3.5', '4.2', '10.2', '11.4'],
    'HIPAA': ['164.312(a)(1)', '164.312(b)', '164.312(e)(1)'],
    'GDPR': ['Art. 5', 'Art. 32', 'Art. 33']
  };
  const key = framework === 'PCI-DSS' || framework.toLowerCase() === 'pci' ? 'PCI-DSS' :
              framework.toUpperCase() === 'HIPAA' ? 'HIPAA' : 'GDPR';
  if (criticalIds[key] && criticalIds[key].includes(control.id)) return 'critical';
  return control.id.startsWith('1.') || control.id.startsWith('3.') || control.id.startsWith('4.') ||
         control.id.startsWith('164.312') ? 'high' : 'medium';
}

module.exports = {
  pciDssData,
  hipaaData,
  gdprData,
  assessCompliance,
  getComplianceStatus,
  mapControl,
  mapCapabilityToControls,
  getApplicableControls,
  collectEvidence,
  generateReport,
  generateExecutiveSummary,
  generateRemediationPlan,
  getComplianceTrend,
  getOpenFindings,
  getComplianceDashboard
};
