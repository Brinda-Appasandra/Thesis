import csv
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict

# Read times from CSV for all metrics
def read_all_times(filepath):
    metrics = {
        'encrypt_time': defaultdict(list),
        'sign_time': defaultdict(list),
        'verify_time': defaultdict(list),
        'decrypt_time': defaultdict(list),
        'total_time': defaultdict(list)
    }

    try:
        with open(filepath, 'r') as file:
            reader = csv.reader(file)
            header = next(reader)
            print(f"Header: {header}")
            for row in reader:
                try:
                    iteration, data_size, encrypt_time, sign_time, verify_time, decrypt_time, total_time = row
                    data_size = float(data_size)
                    metrics['encrypt_time'][data_size].append(float(encrypt_time))
                    metrics['sign_time'][data_size].append(float(sign_time))
                    metrics['verify_time'][data_size].append(float(verify_time))
                    metrics['decrypt_time'][data_size].append(float(decrypt_time))
                    metrics['total_time'][data_size].append(float(total_time))
                except ValueError as e:
                    print(f"Error processing row {row}: {e}")
    except FileNotFoundError as e:
        print(f"File not found: {e}")
    
    return metrics

# Calculate standard deviation for each data size in a metric
def calculate_standard_deviation(data):
    return {data_size: np.std(times) for data_size, times in data.items()}

# Save all standard deviations to a single CSV
def save_all_stddevs(filepath, all_stddevs):
    try:
        with open(filepath, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Metric', 'Data Size', 'Standard Deviation'])
            for metric, stddevs in all_stddevs.items():
                for data_size, std in stddevs.items():
                    writer.writerow([metric, data_size, std])
    except IOError as e:
        print(f"Error writing to file: {e}")

# Plot and save the standard deviation chart for a single metric
def plot_stddev(metric_name, std_devs):
    data_sizes = sorted(std_devs.keys())
    std_values = [std_devs[size] for size in data_sizes]

    plt.figure(figsize=(10, 6))
    plt.plot(data_sizes, std_values, marker='o', linestyle='-', color='b')
    plt.xlabel('Data Size (bytes)')
    plt.ylabel(f'Standard Deviation of {metric_name.replace("_", " ").title()} (seconds)')
    plt.title(f'Standard Deviation of {metric_name.replace("_", " ").title()} vs Data Size for Falcon (AES-128)')
    plt.grid(True)
    plt.xlim(0, max(data_sizes) + 5000)
    plt.xticks(np.arange(0, max(data_sizes) + 5000, step=5000))


    filename = f'{metric_name}_stddev_plot.png'
    plt.savefig(filename)
    print(f"Plot saved as {filename}")
    plt.close()

# Main driver
if __name__ == "__main__":
    input_filepath = 'computation_times.csv'
    output_filepath = 'all_standard_deviations.csv'

    metrics_data = read_all_times(input_filepath)
    all_stddevs = {}

    for metric_name, metric_data in metrics_data.items():
        std_devs = calculate_standard_deviation(metric_data)
        all_stddevs[metric_name] = std_devs
        plot_stddev(metric_name, std_devs)

    save_all_stddevs(output_filepath, all_stddevs)
    print(f"All standard deviations saved to {output_filepath}")
