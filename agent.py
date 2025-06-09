# agent.py
import paramiko
from scp import SCPClient
import time
import datetime
import os
import logging
import configparser
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS
import subprocess # For calling anomaly_detector.py
import sys # To get python executable path
import pandas as pd # For reading anomaly CSV

# Prometheus Client
from prometheus_client import start_http_server, Counter, Gauge, Histogram, Info

# --- Configuration ---
CONFIG_FILE = 'config.ini.txt'
LOG_FILE = 'agent.log'

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# --- Prometheus Metrics Definitions ---
# (Define these globally so they can be accessed from anywhere)

# Agent Info
AGENT_INFO = Info('network_agent_info', 'Information about the network monitoring agent')

# Cycle Metrics
CYCLES_COMPLETED = Counter('network_agent_cycles_completed_total', 'Total number of capture cycles completed')
CYCLES_FAILED = Counter('network_agent_cycles_failed_total', 'Total number of capture cycles failed')
LAST_CYCLE_SUCCESS_TIMESTAMP = Gauge('network_agent_last_cycle_success_timestamp_seconds', 'Timestamp of the last successful cycle')
OPERATION_ERRORS = Counter('network_agent_operation_errors_total', 'Total errors during agent operations', ['operation_type']) # e.g., ssh, tcpdump, download, analysis

# PCAP Metrics
LAST_PCAP_FILE_SIZE_BYTES = Gauge('network_agent_last_pcap_file_size_bytes', 'Size of the last processed PCAP file in bytes')
REMOTE_TCPDUMP_DURATION_SECONDS = Histogram('network_agent_remote_tcpdump_duration_seconds', 'Duration of remote tcpdump execution')
DOWNLOAD_DURATION_SECONDS = Histogram('network_agent_download_duration_seconds', 'Duration of PCAP file download')

# Scapy Analysis Metrics
SCAPY_ANALYSIS_DURATION_SECONDS = Histogram('network_agent_scapy_analysis_duration_seconds', 'Duration of Scapy analysis')
SCAPY_PACKET_STATS = Gauge('network_agent_scapy_packet_stats', 'Packet statistics from Scapy analysis', ['type']) # total, ip, tcp, udp, icmp, dns_queries
SCAPY_TOP_SOURCE_IPS = Gauge('network_agent_scapy_top_source_ips_packets', 'Packet count for top source IPs from Scapy analysis', ['source_ip'])

# ML Anomaly Detection Metrics
ML_ANALYSIS_DURATION_SECONDS = Histogram('network_agent_ml_analysis_duration_seconds', 'Duration of ML anomaly detection script')
ML_ANOMALIES_DETECTED = Gauge('network_agent_ml_anomalies_detected_count', 'Number of anomalies detected by ML model in the last scan')
ML_SCRIPT_RUN_SUCCESS = Gauge('network_agent_ml_script_run_success', 'Indicates if the ML script ran successfully (1) or failed (0)')

# Deep Scan Shell Script Metrics
DEEP_SCAN_DURATION_SECONDS = Histogram('network_agent_deep_scan_duration_seconds', 'Duration of the deep_anomaly_scan.sh script')
DEEP_SCAN_RUN_SUCCESS = Gauge('network_agent_deep_scan_run_success', 'Indicates if the deep_anomaly_scan.sh ran successfully (1) or failed (0)')


# --- Helper Functions ---
def load_config():
    parser = configparser.ConfigParser()
    if not os.path.exists(CONFIG_FILE):
        logging.error(f"Configuration file {CONFIG_FILE} not found.")
        raise FileNotFoundError(f"Configuration file {CONFIG_FILE} not found.")
    parser.read(CONFIG_FILE)
    if 'prometheus' not in parser:
        logging.warning("Prometheus section not found in config, using default port 8000.")
        # Add a default prometheus section if it doesn't exist for easier startup
        parser['prometheus'] = {'exporter_port': '8000'}
    return parser

def create_ssh_client(hostname, port, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        logging.info(f"Connecting to {username}@{hostname}:{port}...")
        client.connect(hostname, port=port, username=username, password=password, timeout=10)
        logging.info("Successfully connected.")
        return client
    except paramiko.AuthenticationException:
        logging.error("Authentication failed. Please check credentials.")
        OPERATION_ERRORS.labels(operation_type='ssh_auth').inc()
        raise
    except Exception as e:
        logging.error(f"Could not connect to SSH server: {e}")
        OPERATION_ERRORS.labels(operation_type='ssh_connect').inc()
        raise

@REMOTE_TCPDUMP_DURATION_SECONDS.time()
def run_remote_tcpdump(client, interface, count, remote_file_path):
    # This is the corrected line. It builds the command from the arguments.
    command = f"sudo /usr/bin/tcpdump -i {interface} -c {count} -w {remote_file_path}"
    logging.info(f"Executing remote command: {command}")
    # ... rest of the function
    stdin, stdout, stderr = client.exec_command(command, get_pty=True) # get_pty for sudo password if needed

    exit_status = stdout.channel.recv_exit_status() # This blocks until command completion

    if exit_status == 0:
        logging.info(f"tcpdump completed successfully on remote server. Output stored in {remote_file_path}")
    else:
        error_message = stderr.read().decode().strip()
        stdout_message = stdout.read().decode().strip()
        logging.error(f"tcpdump failed with exit status {exit_status}.")
        if error_message: logging.error(f"Stderr: {error_message}")
        if stdout_message: logging.error(f"Stdout: {stdout_message}")
        OPERATION_ERRORS.labels(operation_type='remote_tcpdump').inc()
        raise RuntimeError(f"tcpdump failed. Stderr: {error_message}, Stdout: {stdout_message}")

@DOWNLOAD_DURATION_SECONDS.time() # Prometheus: Decorator to time this function
def download_file_sftp(client, remote_path, local_path):
    try:
        with SCPClient(client.get_transport()) as scp:
            logging.info(f"Downloading {remote_path} to {local_path}...")
            scp.get(remote_path, local_path)
            logging.info("File downloaded successfully.")
            if os.path.exists(local_path):
                LAST_PCAP_FILE_SIZE_BYTES.set(os.path.getsize(local_path))
    except Exception as e:
        logging.error(f"Failed to download file {remote_path}: {e}")
        OPERATION_ERRORS.labels(operation_type='sftp_download').inc()
        raise

def delete_remote_file(client, remote_path):
    # Corrected command for deleting a file
    command = "sudo /usr/bin/tcpdump -i br0 -c 200 -w /home/inv-6/remote_capture.pcap"
    logging.info(f"Deleting remote file: {remote_path}")
    stdin, stdout, stderr = client.exec_command(command, get_pty=True)
    exit_status = stdout.channel.recv_exit_status()
    if exit_status == 0:
        logging.info(f"Successfully deleted remote file {remote_path}.")
    else:
        error_message = stderr.read().decode().strip()
        stdout_message = stdout.read().decode().strip()
        logging.warning(f"Could not delete remote file {remote_path}. Exit status: {exit_status}. Error: {error_message}. Stdout: {stdout_message}")
        OPERATION_ERRORS.labels(operation_type='remote_delete').inc() # This is a warning, but can be tracked

@SCAPY_ANALYSIS_DURATION_SECONDS.time() # Prometheus: Decorator to time this function
def analyze_pcap_scapy(pcap_file_path):
    """Performs basic Scapy analysis and updates Prometheus metrics."""
    logging.info(f"--- Starting Scapy Analysis for {pcap_file_path} ---")
    try:
        packets = rdpcap(pcap_file_path)
        total_packets = len(packets)
        logging.info(f"Total packets captured: {total_packets}")
        SCAPY_PACKET_STATS.labels(type='total').set(total_packets)

        ip_packets = 0
        tcp_packets = 0
        udp_packets = 0
        icmp_packets = 0
        dns_queries = 0
        source_ips = {}

        for packet in packets:
            if IP in packet:
                ip_packets += 1
                src_ip = packet[IP].src
                source_ips[src_ip] = source_ips.get(src_ip, 0) + 1
                if TCP in packet:
                    tcp_packets += 1
                    if packet.haslayer(DNS) and packet[DNS].qr == 0:
                        dns_queries += 1
                elif UDP in packet:
                    udp_packets += 1
                    if packet.haslayer(DNS) and packet[DNS].qr == 0:
                        dns_queries += 1
                elif ICMP in packet:
                    icmp_packets += 1

        SCAPY_PACKET_STATS.labels(type='ip').set(ip_packets)
        SCAPY_PACKET_STATS.labels(type='tcp').set(tcp_packets)
        SCAPY_PACKET_STATS.labels(type='udp').set(udp_packets)
        SCAPY_PACKET_STATS.labels(type='icmp').set(icmp_packets)
        SCAPY_PACKET_STATS.labels(type='dns_queries').set(dns_queries)

        logging.info(f"  IP Packets: {ip_packets}")
        logging.info(f"  TCP Packets: {tcp_packets}")
        logging.info(f"  UDP Packets: {udp_packets}")
        logging.info(f"  ICMP Packets: {icmp_packets}")
        logging.info(f"  DNS Queries (from TCP/UDP): {dns_queries}")

        if source_ips:
            logging.info("  Top 5 Source IPs by packet count:")
            sorted_ips = sorted(source_ips.items(), key=lambda item: item[1], reverse=True)
            # Clear previous IPs for this metric to avoid stale data if an IP doesn't appear in next scan
            # This is tricky with Gauge and dynamic labels. A better way might be to only set current top IPs
            # or have a separate mechanism to clear old labels. For simplicity, we'll just set them.
            # Consider a different metric type or approach if you need to track *all* IPs ever seen.
            for ip, count in sorted_ips[:5]: # Expose top 5
                logging.info(f"    {ip}: {count} packets")
                SCAPY_TOP_SOURCE_IPS.labels(source_ip=ip).set(count)
    except Exception as e:
        logging.error(f"Error during Scapy analysis of {pcap_file_path}: {e}")
        OPERATION_ERRORS.labels(operation_type='scapy_analysis').inc()

@ML_ANALYSIS_DURATION_SECONDS.time()
def run_ml_anomaly_detection(pcap_file_path, local_pcap_dir, timestamp, contamination_value, anomaly_script_path):
    """Runs the anomaly_detector.py script and updates Prometheus metrics."""
    logging.info("--- Starting ML Anomaly Detection ---")
    anomaly_csv_filename = f"anomaly_data_{timestamp}.csv"
    anomaly_csv_full_path = os.path.join(local_pcap_dir, anomaly_csv_filename)

    if not os.path.isabs(anomaly_script_path):
         script_to_run = os.path.join(os.path.dirname(__file__), anomaly_script_path)
    else:
        script_to_run = anomaly_script_path

    if not os.path.exists(script_to_run):
        logging.error(f"Anomaly detection script '{script_to_run}' not found.")
        ML_SCRIPT_RUN_SUCCESS.set(0)
        OPERATION_ERRORS.labels(operation_type='ml_script_not_found').inc()
        return

    command = [
        sys.executable,
        script_to_run,
        pcap_file_path,
        anomaly_csv_full_path,
        f"--contamination={contamination_value}"
    ]
    logging.info(f"Executing anomaly detection command: {' '.join(command)}")

    try:
        process = subprocess.run(command, check=True, capture_output=True, text=True)
        logging.info("Anomaly detection script executed successfully.")
        ML_SCRIPT_RUN_SUCCESS.set(1)
        if process.stdout: logging.info(f"ML Anomaly detection stdout:\n{process.stdout.strip()}")
        if process.stderr: logging.info(f"ML Anomaly detection stderr:\n{process.stderr.strip()}")
        logging.info(f"Anomaly data CSV written to: {anomaly_csv_full_path}")

        # Read the CSV to count anomalies
        if os.path.exists(anomaly_csv_full_path):
            try:
                df_anomalies = pd.read_csv(anomaly_csv_full_path)
                if 'is_anomaly' in df_anomalies.columns:
                    num_anomalies = df_anomalies['is_anomaly'].sum()
                    ML_ANOMALIES_DETECTED.set(num_anomalies)
                    logging.info(f"Reported {num_anomalies} anomalies to Prometheus.")
                else:
                    logging.warning(f"'is_anomaly' column not found in {anomaly_csv_full_path}. Cannot report anomaly count.")
                    ML_ANOMALIES_DETECTED.set(0) # Or some error value
            except Exception as e_csv:
                logging.error(f"Error reading anomaly CSV {anomaly_csv_full_path}: {e_csv}")
                ML_ANOMALIES_DETECTED.set(0) # Or some error value
                OPERATION_ERRORS.labels(operation_type='ml_csv_read').inc()
        else:
            logging.warning(f"Anomaly CSV {anomaly_csv_full_path} not found after script execution.")
            ML_ANOMALIES_DETECTED.set(0) # No file, no anomalies to report

    except subprocess.CalledProcessError as e:
        logging.error(f"Anomaly detection script failed with exit code {e.returncode}.")
        if e.stdout: logging.error(f"Stdout:\n{e.stdout}")
        if e.stderr: logging.error(f"Stderr:\n{e.stderr}")
        ML_SCRIPT_RUN_SUCCESS.set(0)
        ML_ANOMALIES_DETECTED.set(0) # Or a specific error indicator if desired
        OPERATION_ERRORS.labels(operation_type='ml_script_execution').inc()
    except Exception as e:
        logging.error(f"Error running anomaly detection script: {e}")
        ML_SCRIPT_RUN_SUCCESS.set(0)
        ML_ANOMALIES_DETECTED.set(0)
        OPERATION_ERRORS.labels(operation_type='ml_script_generic').inc()

@DEEP_SCAN_DURATION_SECONDS.time()
def run_deep_scan_shell_script(script_path, pcap_file, output_dir, timestamp):
    """Runs the deep_anomaly_scan.sh script and updates Prometheus metrics."""
    if not (os.path.exists(script_path) and os.path.exists(pcap_file)):
        if not os.path.exists(script_path):
            logging.warning(f"Deep scan shell script not found at {script_path}. Skipping.")
            OPERATION_ERRORS.labels(operation_type='deep_scan_script_not_found').inc()
        if not os.path.exists(pcap_file):
             logging.warning(f"PCAP file {pcap_file} not available for shell script scan.")
        DEEP_SCAN_RUN_SUCCESS.set(0) # Set to 0 if prerequisites not met
        return

    anomaly_report_shell_path = os.path.join(
        output_dir,
        f"anomaly_report_shell_{timestamp}.txt"
    )
    logging.info(f"Running shell script: {script_path} {pcap_file}")
    try:
        process = subprocess.run(
            f"bash {script_path} {pcap_file}", # Explicitly use bash
            shell=True, check=True, capture_output=True, text=True
        )
        with open(anomaly_report_shell_path, 'w') as f_report:
            f_report.write(process.stdout)
        logging.info(f"Shell script anomaly report written to: {anomaly_report_shell_path}")
        if process.stderr:
            logging.warning(f"Shell script stderr:\n{process.stderr}")
        DEEP_SCAN_RUN_SUCCESS.set(1)
    except subprocess.CalledProcessError as e:
        logging.error(f"Shell script {script_path} failed with exit code {e.returncode}.")
        if e.stdout: logging.error(f"Stdout:\n{e.stdout}")
        if e.stderr: logging.error(f"Stderr:\n{e.stderr}")
        DEEP_SCAN_RUN_SUCCESS.set(0)
        OPERATION_ERRORS.labels(operation_type='deep_scan_execution').inc()
    except Exception as e_sh:
        logging.error(f"Error running shell script {script_path}: {e_sh}")
        DEEP_SCAN_RUN_SUCCESS.set(0)
        OPERATION_ERRORS.labels(operation_type='deep_scan_generic').inc()

# --- Main Agent Logic ---
def main():
    try:
        config = load_config()
        ssh_config = config['ssh_server']
        capture_config = config['capture']
        prometheus_config = config['prometheus'] # Load prometheus config

        local_pcap_dir = capture_config.get('local_pcap_dir', './captures')
        ml_contamination = capture_config.getfloat('ml_contamination', 0.05)
        anomaly_script_name = "anomaly_detector.py"
        anomaly_script_path_config = capture_config.get('anomaly_detector_script_path', anomaly_script_name)
        
        if os.path.isabs(anomaly_script_path_config):
            anomaly_detector_script_full_path = anomaly_script_path_config
        else:
            anomaly_detector_script_full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), anomaly_script_path_config)

        if not os.path.exists(local_pcap_dir):
            os.makedirs(local_pcap_dir)
            logging.info(f"Created local capture directory: {local_pcap_dir}")

        # Prometheus: Start HTTP server to expose metrics
        exporter_port = int(prometheus_config.get('exporter_port', 8000))
        start_http_server(exporter_port)
        logging.info(f"Prometheus metrics exporter started on port {exporter_port}")

        # Prometheus: Set agent static info
        AGENT_INFO.info({
            'version': '1.0.0', # Example version
            'config_ssh_host': ssh_config['hostname'],
            'config_capture_interface': capture_config['interface'],
            'config_local_pcap_dir': local_pcap_dir
        })

    except FileNotFoundError:
        logging.critical(f"Configuration file {CONFIG_FILE} missing. Agent cannot start. Exiting.")
        # Not using OPERATION_ERRORS here as prometheus server might not be up.
        return
    except Exception as e:
        logging.critical(f"Failed to initialize agent: {e}", exc_info=True)
        return

    while True:
        ssh_client = None
        cycle_success = False
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            local_pcap_filename = f"capture_{timestamp}.pcap"
            local_pcap_full_path = os.path.join(local_pcap_dir, local_pcap_filename)

            logging.info("--- Starting new capture cycle ---")

            ssh_client = create_ssh_client(
                ssh_config['hostname'],
                int(ssh_config['port']),
                ssh_config['username'],
                ssh_config['password']
            )

            run_remote_tcpdump(
                ssh_client,
                capture_config['interface'],
                capture_config['packet_count'], # Use configured packet_count
                capture_config['remote_pcap_path']
            )

            download_file_sftp(
                ssh_client,
                capture_config['remote_pcap_path'],
                local_pcap_full_path
            )

            delete_remote_file(ssh_client, capture_config['remote_pcap_path'])
            
            if ssh_client:
                ssh_client.close()
                ssh_client = None
                logging.info("SSH connection closed before local analysis.")

            if os.path.exists(local_pcap_full_path):
                analyze_pcap_scapy(local_pcap_full_path)
                run_ml_anomaly_detection(local_pcap_full_path, local_pcap_dir, timestamp, ml_contamination, anomaly_detector_script_full_path)
            else:
                logging.warning(f"PCAP file {local_pcap_full_path} not found for analysis. Skipping analysis.")
                OPERATION_ERRORS.labels(operation_type='pcap_not_found_local').inc()


            deep_scan_script_path = capture_config.get('deep_scan_script_path', '/home/inv-6/packet_monitorning/captures/deep_anomaly_scan.sh')
            run_deep_scan_shell_script(deep_scan_script_path, local_pcap_full_path, local_pcap_dir, timestamp)
            
            cycle_success = True # If we reach here, cycle was mostly successful

        except FileNotFoundError:
            logging.critical("Configuration file missing during run. Agent cannot continue. Exiting.")
            OPERATION_ERRORS.labels(operation_type='config_missing_runtime').inc()
            break
        except paramiko.AuthenticationException: # Already handled in create_ssh_client for metric
            logging.error("SSH Authentication failed. Agent will retry later.")
        except RuntimeError as e:
            logging.error(f"Runtime error during capture cycle: {e}. Agent will retry later.")
            # Specific errors should be caught and instrumented in their respective functions.
            # This is a fallback.
            OPERATION_ERRORS.labels(operation_type='generic_runtime').inc()
        except Exception as e:
            logging.error(f"An unexpected error occurred in capture cycle: {e}", exc_info=True)
            OPERATION_ERRORS.labels(operation_type='unexpected_cycle_exception').inc()
        finally:
            if cycle_success:
                CYCLES_COMPLETED.inc()
                LAST_CYCLE_SUCCESS_TIMESTAMP.set_to_current_time()
            else:
                CYCLES_FAILED.inc()

            if ssh_client:
                ssh_client.close()
                logging.info("SSH connection closed in finally block.")
            
            interval_seconds = int(capture_config.get('interval_seconds', 300))
            logging.info(f"--- Capture cycle finished. Waiting for {interval_seconds} seconds. ---")
            try:
                time.sleep(interval_seconds)
            except KeyboardInterrupt:
                logging.info("Agent stopped by user.")
                break
            except Exception as e_sleep:
                logging.error(f"Error in sleep interval: {e_sleep}. Defaulting to 300 seconds.")
                time.sleep(300)

if __name__ == "__main__":
    main()