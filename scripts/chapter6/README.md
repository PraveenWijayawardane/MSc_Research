Chapter 6 Controlled Scenario Scripts

These scripts automate the capture workflow, not the scientific conclusions.

They are aligned with the current scripts/evaluate_chapter6.py scenario definitions:

ID

Ground truth

Source

Destination

Port

Wazuh required

Zeek required

Correlation expected

B1

Benign

192.168.100.30

192.168.100.40

5432

No

Yes

No

B2

Benign

192.168.100.21

192.168.100.30

22

No

Yes

No

A1

Attack

192.168.100.20

192.168.100.40

22

Yes

Yes

Yes

A2

Attack

192.168.100.20

192.168.100.40

5432

No

Yes

No

A3

Attack

192.168.100.20

192.168.100.30

22

No

Yes

No

A4

Attack

192.168.100.20

192.168.100.50

445

No

Yes

No

A5

Attack

192.168.100.30

192.168.100.40

5432

Yes

Yes

Yes

U1

Attack

192.168.101.60

192.168.100.40

5432

No

Yes

No

Important topology note

The current environment profile maps:

192.168.100.20 -> user-pc-01

192.168.100.21 -> admin-pc-01

192.168.100.30 -> ehr-app-server-01

192.168.100.40 -> ehr-db-server-01

192.168.100.50 -> file-server-01

192.168.100.10 -> attacker-kali

Therefore A1-A4 are generated from user-pc-01, because that is the source IP required by the evaluator.

Install into the repository

Copy this directory to:

D:\MSc-Research\Healthcare-risk-engine\scripts\chapter6\

Result:

scripts/
  chapter6/
    Invoke-Chapter6Scenario.ps1
    Invoke-Chapter6Series.ps1
    README.md

First check Vagrant machine names

From your Vagrant directory:

vagrant status

The runner currently expects:

user-pc-01
admin-pc-01
ehr-app-server-01
attacker-kali

If your Vagrant machine labels differ, edit only the SourceVM values near the top of Invoke-Chapter6Scenario.ps1.

Run one scenario

Example B2-R1:

.\scripts\chapter6\Invoke-Chapter6Scenario.ps1 `
  -ScenarioId B2 `
  -Repetition 1 `
  -VagrantDir "D:\YOUR-VAGRANT-DIRECTORY"

The runner automatically:

records StartUTC;

executes the controlled action on the source VM;

records EndUTC;

runs one fresh live_pipeline.py cycle with --wazuh-size 500 --skip-publish;

validates the exact Zeek flow inside the recorded time window;

validates required Wazuh evidence for A1/A5;

refuses to archive if required evidence is missing;

calls the existing Save-FinalRun;

runs evaluate_chapter6.py --allow-incomplete;

prints the run-level prediction.

Run repetitions

After the first repetition of a new scenario is accepted:

.\scripts\chapter6\Invoke-Chapter6Series.ps1 `
  -ScenarioId B2 `
  -From 2 `
  -To 5 `
  -VagrantDir "D:\YOUR-VAGRANT-DIRECTORY"

Existing completed runs

The runner refuses to overwrite an existing evaluation/chapter6/final/<RunID> by default.

Use -Overwrite on the single-scenario runner only when you intentionally want to replace an invalid run:

.\scripts\chapter6\Invoke-Chapter6Scenario.ps1 `
  -ScenarioId A1 `
  -Repetition 1 `
  -VagrantDir "D:\YOUR-VAGRANT-DIRECTORY" `
  -Overwrite

Do not overwrite already validated A4, A5, U1, or other accepted evidence merely to standardize the execution method.

Scenario actions

The automated actions are intentionally minimal and lab-scoped:

B1: TCP access from EHR app to PostgreSQL.

B2: TCP access from admin workstation to EHR app SSH.

A1: controlled invalid SSH-user attempts to the DB host; Wazuh + Zeek are required.

A2: direct workstation access to PostgreSQL.

A3: workstation access to EHR app SSH.

A4: workstation access to SMB/file server.

A5: sudo activity on EHR app followed by PostgreSQL TCP access; Wazuh + Zeek correlation is required.

U1: temporary 192.168.101.60/32 source alias, bound TCP access to PostgreSQL, then automatic alias cleanup.

Scientific-integrity rule

The script validates whether evidence exists, but it does not force or rewrite classifications. If an accepted run is classified differently from ExpectedClass, keep the result and analyze it rather than modifying thresholds after observing the output.