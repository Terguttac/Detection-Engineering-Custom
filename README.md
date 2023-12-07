# Detection Engineering

# Purpose
This repo builds upon the scripts written throughout Anthony Isherwood's [Detection Engineering](https://academy.tcm-sec.com/courses/2137578) course. The scripts and automations have been adapted to run locally, using `inotifywait` to monitor the detection folders. The validation script runs upon detecting a change, and if validated, the alert is synced to Elastic.

# Summary
 The bash command watches for file changes in both the **validated** and **failed** directories. Once detected, the validation script will be run against the file and responds accordingly. 

- If a detection is altered and no longer valid, the script moves it to the *failed* directory. 

- If a detection in the *failed* directory is modified and passes validation it is moved to the *validated* directory.

- If a detection is altered **and** validated, it is synced to Elastic.

---
If validation fails, the script can retrieve the last valid detection. This option is enabled by default but can be disabled by setting `getBKUP = False` in the `custom_validation.py` script.

Retrieved detections are placed in the *validated* directory, prepended with `BKUP_`, and are automatically removed when the failed detection is corrected.

---


# Setup & Usage
- Set environment variables for `ELASTIC_URL` and `API_KEY`.
- Set an environment variable for `GH_URL` to the path of the github repo. For example: `https://raw.githubusercontent.com/Terguttac/Detection-Engineering-Custom/main/` 
- Run `monitor_detections.sh`.

---

# Recently Created Detections
## This Month
| Alert | Date | Author | Risk Score | Severity | Tactic | MITRE Links |
| --- | --- | --- | :---: | --- | --- | --- |
|[Potential Zipped Exfiltration](https://raw.githubusercontent.com/Terguttac/Detection-Engineering-Custom/main/detections/validated/zipped_exfiltration.toml)|2023/12/15|Terguttac|65|medium|Collection|[T1074](https://attack.mitre.org/techniques/T1074) [T1074.001](https://attack.mitre.org/techniques/T1074/001)|
## Last Month
| Alert | Date | Author | Risk Score | Severity | Tactic | MITRE Links |
| --- | --- | --- | :---: | --- | --- | --- |
|[Potential MSFVenom PowerShell Payload Observed](https://raw.githubusercontent.com/Terguttac/Detection-Engineering-Custom/main/detections/validated/potential_msfvenom_powershell_payload_observed.toml)|2023/11/15|Terguttac|85|high|Execution|[T1059](https://attack.mitre.org/techniques/T1059) [T1059.001](https://attack.mitre.org/techniques/T1059/001)|
|[Suspicious file added to Registry run key (ps1)](https://raw.githubusercontent.com/Terguttac/Detection-Engineering-Custom/main/detections/validated/suspicious_ps1_file_added_to_run_key.toml)|2023/11/15|Terguttac|85|high|Persistence|[T1547](https://attack.mitre.org/techniques/T1547) [T1547.001](https://attack.mitre.org/techniques/T1547/001)|
|[Powershell execution via a bat file](https://raw.githubusercontent.com/Terguttac/Detection-Engineering-Custom/main/detections/validated/powershell_execution_via_bat.toml)|2023/11/15|Terguttac|55|medium|Execution|[T1059](https://attack.mitre.org/techniques/T1059) [T1059.001](https://attack.mitre.org/techniques/T1059/001)|
|[Powershell Invoke-WebReqeuest Downloading .BAT file](https://raw.githubusercontent.com/Terguttac/Detection-Engineering-Custom/main/detections/validated/powershell_invoke_webrequest_downloads_bat.toml)|2023/11/15|Terguttac|50|medium|Execution|[T1059](https://attack.mitre.org/techniques/T1059) [T1059.001](https://attack.mitre.org/techniques/T1059/001)|
|[Excessive Web Traffic](https://raw.githubusercontent.com/Terguttac/Detection-Engineering-Custom/main/detections/validated/excessive_web_traffic.toml)|2023/11/14|Terguttac|25|low|Discovery|[T1046](https://attack.mitre.org/techniques/T1046) |
|[Web Scanner Activity - Nmap and Nikto](https://raw.githubusercontent.com/Terguttac/Detection-Engineering-Custom/main/detections/validated/web_scanner_activity_nmap_nikto.toml)|2023/11/15|Terguttac|35|low|Discovery|[T1046](https://attack.mitre.org/techniques/T1046) |
## Two Months Ago
| Alert | Date | Author | Risk Score | Severity | Tactic | MITRE Links |
| --- | --- | --- | :---: | --- | --- | --- |
|[Bat files observed in HTTP traffic on unusual port](https://raw.githubusercontent.com/Terguttac/Detection-Engineering-Custom/main/detections/validated/bat_files_in_http.toml)|2023/10/15|Terguttac|30|low|Execution|[T1059](https://attack.mitre.org/techniques/T1059) [T1059.003](https://attack.mitre.org/techniques/T1059/003)|
