Behavior-Based Detection of Internal Threats in On-Prem Healthcare Networks

MSc Cybersecurity and Forensics research project by U.P.B. WijayawardaneUniversity of Westminster

Project Purpose

This project implements an explainable, environment-aware risk-scoring framework for detecting and prioritising internal threats and lateral movement in on-prem healthcare networks.

The framework combines:

host security evidence;

internal network connection telemetry;

asset role and criticality;

trusted-host and communication-policy context;

short-window behavioural analysis; and

bounded temporal correlation between related host and network events.

The output is an analyst-oriented investigation record containing a bounded risk score, one of four ordered classifications, score components, correlation information and human-readable reasons.

The project is designed for controlled research and evaluation, not as a production-ready clinical security product.

Core Research Idea

A single security event may not be enough to determine whether internal activity is normal or suspicious.

For example, communication with a database may be expected from an EHR application server but unusual from a normal employee workstation. The framework therefore evaluates what happened, where it happened, whether the communication was expected, whether the recent behaviour was unusual, and whether related host evidence occurred within the configured correlation window.

Processing Flow

Virtual Healthcare Lab
        |
        +--------------------+
        |                    |
   Host telemetry       Network telemetry
        |                    |
        +---------+----------+
                  |
            Normalisation
                  |
           Asset Resolution
                  |
            Policy Checks
                  |
        Behavioural Analysis
                  |
          Contextual Scoring
                  |
      Host/Network Correlation
                  |
       Risk Classification
                  |
       OpenSearch / Wazuh
              Dashboard

Main Features

Environment-aware host and network telemetry processing.

Asset resolution using hospital-specific configuration.

Role-based communication policy evaluation.

Five-minute behavioural analysis window.

Five-minute bounded host/network correlation window.

Explainable score components and reasons.

Four ordered risk classifications.

Environment-isolated runtime data, output and log directories.

Duplicate-safe publishing to environment-specific OpenSearch aliases.

Hospital-profile validation, version creation, integrity verification, activation and rollback.

Controlled Chapter 6 evaluation workflow with multiple analysis variants.

Unit and resilience tests for the main processing components.

Risk Classification

The current scoring configuration uses a bounded total risk score from 0 to 30.

Risk Score

Classification

0-5

Legitimate

6-10

Low Suspicion

11-17

Suspicious

18-30

Likely Malicious

For a network event, the contextual network score is conceptually:

Network Risk = Asset Score + Policy Score + Behaviour Score

For an eligible correlated event:

Final Risk = Network Risk + Bounded Host-Evidence Contribution + Correlation Score

The final score is capped at the configured maximum.

Repository Structure

MSc_Research/
|
|-- config/
|   |-- base/
|   |   |-- risk_rules.yaml
|   |   |-- role_policies.yaml
|   |   `-- opensearch_index_mapping.json
|   |
|   |-- environments/
|   |   |-- healthcare-lab/
|   |   `-- hospital-a-prod/
|   |
|   |-- templates/
|   |   `-- hospital-profile-template.yaml
|   |
|   `-- uploads/
|
|-- data/
|   `-- <environment-id>/
|       |-- live_wazuh_events.json
|       |-- live_zeek_conn.log
|       `-- live_zeek_conn.json
|
|-- output/
|   `-- <environment-id>/
|       `-- scored_events.json
|
|-- logs/
|   `-- <environment-id>/
|       |-- live_pipeline.log
|       `-- live_pipeline_state.json
|
|-- evaluation/
|   `-- chapter6/
|       |-- final/
|       |-- derived/
|       |-- pilots/
|       |-- exploratory/
|       `-- scenario_ground_truth.csv
|
|-- scripts/
|   |-- live_pipeline.py
|   |-- onboard_environment.py
|   |-- manage_environment_versions.py
|   |-- research_preflight.py
|   |-- pipeline_health_check.py
|   |-- evaluate_chapter6.py
|   |-- save_final_run.ps1
|   `-- ...
|
|-- src/
|   |-- risk_engine.py
|   |-- behavior_analyzer.py
|   |-- asset_resolver.py
|   |-- policy_engine.py
|   |-- wazuh_live_collector.py
|   |-- zeek_log_parser.py
|   |-- push_scored_events.py
|   |-- opensearch_index_manager.py
|   |-- profile_validator.py
|   |-- profile_version_manager.py
|   |-- environment_registry.py
|   |-- environment_paths.py
|   `-- event_environment.py
|
|-- tests/
|   `-- test_*.py
|
|-- docs/
|   `-- test-pipeline.md
|
|-- requirements.txt
`-- README.md

Reference Healthcare Lab

The controlled virtual healthcare environment is maintained in a separate public repository:

Lab repository:https://github.com/PraveenWijayawardane/MSc-Research-Vagrant-Fils

The reference lab contains:

System

Reference IP

Purpose

Attacker VM

192.168.100.10

Controlled attack generation

User workstation

192.168.100.20

Normal employee activity

Admin workstation

192.168.100.21

Approved administrative activity

EHR application

192.168.100.30

Simulated healthcare application

EHR database

192.168.100.40

Simulated critical database

File server

192.168.100.50

Simulated shared healthcare records

Monitoring server

192.168.100.100

Wazuh manager/indexer/dashboard

Zeek sensor 01

192.168.100.110

Network sensor

Zeek sensor 02

192.168.100.120

Primary evaluated network sensor

The evaluated research configuration primarily uses Zeek Sensor 02 (192.168.100.120) and Zeek conn.log.

Requirements

Software Requirements

Risk Engine / Evaluation Workstation

Git

Python 3.10 or later

pip

PowerShell for the provided .ps1 helper scripts

OpenSSH/SCP if Zeek logs are copied remotely

Access to a Wazuh/OpenSearch indexer when live host collection or publishing is required

A web browser for Wazuh Dashboard visualisation

Full Virtual Lab

Oracle VirtualBox

HashiCorp Vagrant

Internet access during initial provisioning to download Vagrant boxes and security/software packages

Hardware virtualisation enabled in BIOS/UEFI

The Vagrant lab provisions Linux systems including Wazuh, Zeek, PostgreSQL, Samba and a small Flask-based EHR application.

Hardware Requirements

There is no formal minimum hardware benchmark for the Python-only risk engine.

For the complete reference Vagrant lab, the current Vagrantfile allocates approximately 38 GB of guest RAM and 20 virtual CPUs across all defined VMs. Host resources must also be reserved for the operating system and VirtualBox overhead.

Practical recommendation for running the full lab:

RAM: 48 GB minimum practical; 64 GB recommended.

CPU: 8 or more modern CPU cores/logical processors with virtualisation support; more is preferable because vCPUs are overcommitted.

Disk: at least 100 GB of free space is recommended for Vagrant boxes, VM disks, logs and evaluation artefacts.

Network: host-only/private virtual networking is required for the research subnet.

If resources are limited, start only the VMs required for the experiment.

Programming Languages, Libraries and Frameworks

Main Languages

Python

PowerShell

YAML

JSON

Ruby syntax in the Vagrantfile

Shell scripting inside Vagrant provisioning

Python Dependencies

The current requirements.txt contains:

requests
tzdata
PyYAML
python-dotenv

Purpose:

requests - communication with Wazuh/OpenSearch HTTP endpoints.

tzdata - timezone support where system timezone data is unavailable.

PyYAML - hospital profiles, policies and scoring configuration.

python-dotenv - local loading of secrets and endpoint settings from .env.

pytest is used for the repository tests but is not currently listed in requirements.txt. Install it separately when running the test suite:

python -m pip install pytest

Main Research Technologies

Wazuh - host-side telemetry and dashboard environment.

Zeek - internal network connection telemetry (conn.log).

OpenSearch / Wazuh Indexer - storage of scored investigation records.

Wazuh Dashboard - analyst-facing visualisation.

VirtualBox + Vagrant - controlled healthcare-style laboratory.

PostgreSQL - simulated EHR database.

Flask - simulated EHR application.

Samba - simulated healthcare file server.

Installation

1. Clone the Risk-Engine Repository

git clone https://github.com/PraveenWijayawardane/MSc_Research.git
cd MSc_Research

The final research implementation is maintained on the repository's current default research branch. Confirm the checked-out branch:

git branch --show-current

If required:

git checkout feature/automatic-startup-resilience

2. Create a Python Virtual Environment

Windows PowerShell:

python -m venv .venv
.\.venv\Scripts\Activate.ps1

Linux/macOS:

python3 -m venv .venv
source .venv/bin/activate

3. Install Dependencies

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

For tests:

python -m pip install pytest

Optional: Deploy the Full Virtual Healthcare Lab

Clone the separate lab repository:

git clone https://github.com/PraveenWijayawardane/MSc-Research-Vagrant-Fils.git
cd MSc-Research-Vagrant-Fils

Review the Vagrantfile before deployment, then:

vagrant up

Check VM status:

vagrant status

Security note: the reference Vagrant repository is a research lab, not a production deployment. Before final public submission, replace or remove any hard-coded lab passwords/test credentials from provisioning files and do not reuse them outside the isolated research environment.

Configuration

1. Environment Configuration

Environment-specific profiles are stored under:

config/environments/<environment-id>/

Current examples include:

config/environments/healthcare-lab/
config/environments/hospital-a-prod/

The configuration describes information such as:

hospital/environment ID;

timezone and business hours;

network zones;

asset roles;

asset criticality/sensitivity;

trust level;

approved or denied communication paths;

enabled telemetry sources; and

output index name.

Shared policies and risk rules are stored in:

config/base/role_policies.yaml
config/base/risk_rules.yaml

2. Local .env File

Create a local .env file in the project root.

Do not commit this file.

Example:

ENVIRONMENT_ID=healthcare-lab

# Wazuh alert collection
WAZUH_INDEXER_URL=https://127.0.0.1:9200
WAZUH_INDEX=wazuh-alerts-*
WAZUH_USERNAME=readall
WAZUH_PASSWORD=<set-locally>
WAZUH_VERIFY_TLS=false

# Risk-event publishing
# If omitted, the RISK_INDEXER_* settings can fall back to WAZUH_INDEXER_*.
RISK_INDEXER_URL=https://127.0.0.1:9200
RISK_INDEXER_USERNAME=<set-locally>
RISK_INDEXER_PASSWORD=<set-locally>
RISK_INDEXER_VERIFY_TLS=false
RISK_INDEXER_TIMEOUT_SECONDS=30

# Optional dashboard preflight check
WAZUH_DASHBOARD_URL=https://<dashboard-host-or-ip>/

# Optional remote Zeek collection
ZEEK_SSH_HOST=<zeek-host-or-ip>
ZEEK_SSH_USER=<ssh-user>
ZEEK_SSH_KEY=<path-to-private-key>
ZEEK_SSH_PORT=22
ZEEK_REMOTE_CONN_LOG=/home/vagrant/conn.log
ZEEK_STRICT_HOST_KEY_CHECKING=accept-new

If the live Zeek log is stored somewhere else, set ZEEK_REMOTE_CONN_LOG to the real path.

For the Vagrant Zeek installation itself, the normal live Zeek directory is:

/opt/zeek/logs/current/

The pipeline can also use a local Zeek source file with --zeek-local-source.

Credentials and Test Accounts

This is a controlled research project.

Typical lab-only account names include:

Account

Purpose

vagrant

VM provisioning/administration account

ehr_user

Simulated EHR database application role

readall

Default Wazuh indexer read username used by the collector unless overridden

Passwords are intentionally not documented in this README.

Set secrets locally using .env, Vagrant environment/provisioning variables, or a separate secure examiner note. Do not commit:

passwords;

private SSH keys;

Wazuh/OpenSearch credentials;

API tokens;

real patient information; or

production credentials.

No production healthcare credentials are required by this research project.

Dataset and Telemetry Preparation

No Machine-Learning Training Dataset Is Required

This project is a deterministic/contextual risk-scoring framework. It does not train an ML model.

The evaluation dataset is produced from controlled benign and attack scenarios in the virtual healthcare laboratory.

Live Runtime Inputs

The default environment-specific runtime inputs are:

data/<environment-id>/live_wazuh_events.json
data/<environment-id>/live_zeek_conn.log
data/<environment-id>/live_zeek_conn.json

The risk-engine output is:

output/<environment-id>/scored_events.json

Pipeline status is written to:

logs/<environment-id>/live_pipeline_state.json

Preparing Wazuh Input

Collect recent Wazuh alerts:

python .\src\wazuh_live_collector.py `
  --environment healthcare-lab `
  --size 100

The collector queries the configured wazuh-alerts-* index and writes environment-tagged JSON.

Preparing Zeek Input

Option A - use the live pipeline's configured SCP collection.

Option B - provide a local conn.log:

python .\scripts\live_pipeline.py `
  --environment healthcare-lab `
  --zeek-local-source C:\path\to\conn.log `
  --skip-publish

Option C - place the environment-specific conn.log in the expected data directory and run with:

python .\scripts\live_pipeline.py `
  --environment healthcare-lab `
  --skip-zeek-copy `
  --skip-publish

The Zeek parser converts conn.log to structured JSON before scoring.

Running the System

Recommended Preflight Check

Before a live run:

python .\scripts\research_preflight.py `
  --environment healthcare-lab

This checks the selected environment profile, runtime directories, pipeline lock, dashboard endpoint when configured, OpenSearch aliases/source index, and Zeek SSH/conn.log availability.

For an offline test without external services:

python .\scripts\research_preflight.py `
  --environment healthcare-lab `
  --skip-opensearch `
  --skip-zeek

Option 1 - Run One Complete Live Cycle

python .\scripts\live_pipeline.py `
  --environment healthcare-lab `
  --wazuh-size 100

Pipeline sequence:

collect recent Wazuh alerts;

obtain Zeek conn.log;

parse Zeek network telemetry;

run contextual scoring and correlation;

publish scored records through the environment-specific OpenSearch write alias;

persist logs and state.

Option 2 - Run Continuously

python .\scripts\live_pipeline.py `
  --environment healthcare-lab `
  --continuous `
  --interval-seconds 30

Stop with Ctrl+C.

The pipeline uses a per-environment lock to prevent multiple instances from processing the same hospital simultaneously.

Option 3 - Score Existing Telemetry Without Live Collection

If the environment-specific Wazuh and Zeek JSON files already exist:

python .\src\risk_engine.py `
  --environment healthcare-lab

This reads:

data/healthcare-lab/live_wazuh_events.json
data/healthcare-lab/live_zeek_conn.json

and writes:

output/healthcare-lab/scored_events.json

Custom files can also be supplied:

python .\src\risk_engine.py `
  --environment healthcare-lab `
  --wazuh-input C:\path\wazuh.json `
  --zeek-input C:\path\zeek.json `
  --output C:\path\scored_events.json

Option 4 - Validate Publishing Without Contacting OpenSearch

python .\src\push_scored_events.py `
  --environment healthcare-lab `
  --dry-run

This validates final-document preparation and duplicate event IDs without publishing.

Dashboard / OpenSearch Output

The publisher reads:

output/<environment-id>/scored_events.json

and writes environment-isolated documents to OpenSearch.

The index manager maintains environment-specific read/write aliases based on the configured base index.

Typical fields available for investigation include:

environment ID;

timestamp;

event source;

source/destination IP;

source/destination host and role;

destination port/service;

asset score;

policy score;

behaviour score;

host/Wazuh score;

correlation score;

final risk score;

classification;

policy name/action;

correlation flag;

matched evidence information; and

human-readable reasons.

The Wazuh Dashboard is used to visualise classification distribution, risk trends, source/target activity, policy outcomes, correlated events, critical-asset activity and detailed investigation records.

Adding a New Hospital Environment

A reusable hospital-profile template is provided at:

config/templates/hospital-profile-template.yaml

Create a new profile based on that template.

1. Validate the Profile

python .\scripts\onboard_environment.py `
  --profile .\config\uploads\pending\<hospital-profile>.yaml `
  --dry-run

A dry run validates the profile and shows the target version without modifying files.

2. Create an Inactive Version

python .\scripts\onboard_environment.py `
  --profile .\config\uploads\pending\<hospital-profile>.yaml `
  --create-version

New versions are inactive by default so they can be reviewed before activation.

3. List Versions

python .\scripts\manage_environment_versions.py `
  --environment <environment-id> `
  --list

4. Verify a Version

python .\scripts\manage_environment_versions.py `
  --environment <environment-id> `
  --verify <version-id>

5. Activate a Reviewed Version

python .\scripts\manage_environment_versions.py `
  --environment <environment-id> `
  --activate <version-id>

6. Show Current Version

python .\scripts\manage_environment_versions.py `
  --environment <environment-id> `
  --current

7. Roll Back if Required

python .\scripts\manage_environment_versions.py `
  --environment <environment-id> `
  --rollback

The same central risk-engine code can then operate with the newly activated hospital configuration.

Testing

Install pytest if necessary:

python -m pip install pytest

Run the full test suite:

python -m pytest -q

The repository includes tests covering:

asset resolution;

behavioural analysis;

policy evaluation;

contextual risk scoring;

event/environment handling;

multi-environment isolation;

OpenSearch index management;

hospital onboarding;

profile validation/version management;

live-pipeline execution and resilience;

duplicate-safe event publishing; and

research preflight/health checks.

Chapter 6 Evaluation

Model Training

Not applicable.

There is no trainable machine-learning model in the submitted framework. Evaluation compares deterministic analysis variants over controlled research scenarios.

Evaluation Variants

The evaluation script compares:

Severity-only host baseline.

Network-only contextual analysis.

Contextual analysis without correlation.

Full proposed framework.

Controlled Run Archive

A final run contains the relevant telemetry and metadata under:

evaluation/chapter6/final/<RUN-ID>/

The PowerShell helper can archive a completed run:

. .\scripts\save_final_run.ps1

Save-FinalRun `
  -RunID <RUN-ID> `
  -StartUTC <START-UTC> `
  -EndUTC <END-UTC>

The helper archives:

live_wazuh_events.json
live_zeek_conn.log
live_zeek_conn.json
scored_events.json
live_pipeline_state.json
pipeline_log_tail.txt
run_info.json

Generate Evaluation Metrics

python .\scripts\evaluate_chapter6.py `
  --environment healthcare-lab

Default input:

evaluation/chapter6/final/
evaluation/chapter6/scenario_ground_truth.csv

Default derived output:

evaluation/chapter6/derived/final/

Generated outputs include:

final_run_predictions.csv
binary_metrics.csv
binary_confusion_matrix.csv
four_class_metrics.csv
multiclass_confusion_matrix.csv
correlation_summary.csv
correlation_run_details.csv
evaluation_validation.json

The final submitted controlled evaluation contains 40 accepted runs. In that controlled binary attack-vs-benign evaluation, the full proposed framework achieved accuracy, precision, recall and F1 of 1.00, while exact four-level severity classification remained more difficult and is identified as an area for further calibration.

These results apply only to the controlled laboratory evaluation and must not be interpreted as guaranteed real-world hospital performance.

Health and Troubleshooting Commands

Check the current pipeline state:

Get-Content .\logs\healthcare-lab\live_pipeline_state.json -Raw |
  ConvertFrom-Json |
  Format-List *

Run a preflight check:

python .\scripts\research_preflight.py `
  --environment healthcare-lab

For a continuous pipeline, run the health checker:

python .\scripts\pipeline_health_check.py `
  --environment healthcare-lab

If a stale pipeline lock is detected:

python .\scripts\research_preflight.py `
  --environment healthcare-lab `
  --repair-stale-lock

External Services and Keys

Required for Full Live Operation

Wazuh/OpenSearch indexer endpoint.

Valid indexer username and password.

Zeek sensor or a supplied local conn.log.

SSH access/key when Zeek telemetry is copied remotely.

Wazuh Dashboard access for visualisation.

API Keys

No third-party cloud API key is required by the core research framework.

Secrets used for local infrastructure access must be supplied through environment variables or secure local configuration and must not be committed to Git.

Known Limitations

Evaluation was performed in a controlled virtual healthcare-style laboratory using synthetic/test activity rather than real hospital production traffic.

The evaluated network telemetry source is Zeek conn.log; broader protocol-specific Zeek logs were outside the evaluated core pipeline.

Behaviour analysis uses configured short windows and fixed thresholds; thresholds may require tuning for another hospital.

Host/network correlation is bounded to a configured time window rather than maintaining a persistent long-duration attack graph.

Correct correlation depends on accurate timestamps and clock synchronisation across hosts and sensors.

Correct contextual scoring depends on accurate hospital asset inventories, role definitions, trust levels and communication policies.

The current system is rule/context-driven rather than a self-learning ML model.

Binary attack-vs-benign classification was easier in the controlled evaluation than exact four-level severity calibration.

Broader healthcare traffic, longer observation periods and multi-site real-world validation are future work.

Live collection depends on connectivity to the Wazuh/OpenSearch environment and availability/freshness of the Zeek log source.

Security and Submission Notes

Before submitting the repository to examiners:

Confirm the repository is public or otherwise accessible without approval delays.

Confirm the final research branch is the repository default branch.

Remove temporary/debug files and unrelated artefacts from the repository root.

Remove __pycache__, virtual environments and unnecessary dependency folders from Git.

Confirm .env is ignored and not committed.

Remove or replace hard-coded lab passwords/test credentials from any public Vagrant/provisioning repository.

Remove private SSH keys, API tokens and indexer credentials.

Confirm all links in this README are accessible.

Run the test suite.

Run the research preflight and at least one offline/dry-run pipeline execution.

Confirm the evaluation CSV/JSON files open correctly.

Verify that the code in the repository corresponds to the final submitted thesis.

Research Scope and Ethical Use

This repository is intended for postgraduate cybersecurity research in a controlled environment.

No real patient data is required.

No real hospital system is required.

Attack scenarios should only be executed against systems owned or explicitly authorised for testing.

The lab data and example healthcare records are synthetic.

Author

U.P.B. WijayawardaneMSc Cybersecurity and ForensicsUniversity of Westminster

Research project: Behavior-Based Detection of Internal Threats in On-Prem Healthcare Networks
