# NetDetect: Intelligent & Context-Aware Network Threat Detector

NetDetect is an advanced network threat analysis tool designed to move beyond static, rule-based detection. It functions as an **Intelligent, Self-Learning Behavioral Detector** by establishing a baseline of normal network activity and identifying statistically significant anomalies.

This approach allows NetDetect to be highly accurate, adaptive to different network environments, and capable of detecting unknown or zero-day threats that traditional methods might miss.

## ✨ Key Features

* **🧠 Adaptive Intelligence:** Automatically learns a baseline of normal network traffic and uses statistical methods (mean, standard deviation) to detect anomalies. This minimizes false positives and eliminates the need for manual threshold tuning.
* **🎯 High-Precision Rules:** Includes accurate, context-aware rules for known threats like Unsolicited ARP Replies to ensure reliable detection.
* **🔗 Incident Correlation Engine:** Correlates individual alerts from the same source IP to provide a high-level "Attack Chain" summary, offering actionable insights instead of just raw logs.
* **⚙️ Easy-to-Use CLI:** Features a simple Command-Line Interface for intuitive operation, allowing users to switch between `learn` and `detect` modes effortlessly.
* **🔧 Flexible Configuration:** Key parameters, such as detection sensitivity, can be easily configured in the `config.ini` file.

## 🗂️ Project Structure

NetDetect/
├── Network_Suspicious.py     # Main application script
├── config.ini                # Configuration file for parameters
├── requirements.txt          # Project dependencies
├── sample/
│   ├── normal_traffic.pcap   # Example file for learn mode
│   └── attack_test.pcap      # Example file for detect mode
└── result/
├── network_baseline.json # Output from learn mode
└── detection_report.txt  # Output from detect mode


## 🚀 How to Use

NetDetect operates via a Command-Line Interface (CLI).

Step 1: Installation


It is recommended to use a virtual environment.

```bash
# Install required libraries
pip install -r requirements.txt


Step 2: Configuration (Optional)
You can adjust the detection sensitivity in the config.ini file. A lower value makes the detector more sensitive.

Ini, TOML

# config.ini
[DetectionParameters]
sensitivity = 3.0


Step 3: Create a Traffic Baseline (Learn Mode)
This mode "teaches" the tool what your normal network traffic looks like. Use a clean .pcap file containing only normal traffic for this step.

Run the following command in your terminal:

Bash

python Network_Suspicious.py learn --pcap /path/to/normal_traffic.pcap
This will create a network_baseline.json file, which stores the learned profile of your network.

Step 4: Detect Suspicious Activity (Detect Mode)
Once a baseline exists, you can analyze any .pcap file to find suspicious activities.

Run the following command:

Bash

python Network_Suspicious.py detect --pcap /path/to/test_traffic.pcap
If any suspicious activities are found, a summary report will be saved to result/detection_report.txt.

🔬 Methodology
NetDetect employs a hybrid approach for robust threat detection:

Statistical Anomaly Detection: The core of NetDetect is its ability to create a dynamic profile of normal network behavior. It calculates the mean and standard deviation of various traffic metrics (e.g., packet counts per interval) and flags any activity that deviates significantly from this learned norm.

Context-Aware Heuristics: For well-known attack vectors, the tool uses precise, context-aware rules to minimize false positives, such as identifying unsolicited ARP replies instead of simple IP-MAC mapping conflicts.

🛣️ Future Work
Machine Learning Integration: Implement advanced ML models (e.g., Isolation Forest) for more complex anomaly detection.

Real-time Analysis: Add support for analyzing live traffic directly from a network interface.

Web Dashboard: Develop a web-based UI for intuitive visualization and reporting.