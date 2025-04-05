import csv
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict

# Read computation times from CSV file
def read_computation_times(filepath):
    data = defaultdict(list)
    try:
        with open(filepath, 'r') as file:
            reader = csv.reader(file)
            header = next(reader)  # Skip header
            print(f"Header: {header}")
            for row in reader:
                try:
                    iteration, data_size, _, _, _, _, total_time = row
                    data_size = float(data_size)
                    total_time = float(total_time)
                    data[data_size].append(total_time)
                except ValueError as e:
                    print(f"Error processing row {row}: {e}")
    except FileNotFoundError as e:
        print(f"File not found: {e}")
    return data

# Calculate standard deviation for each data size
def calculate_standard_deviation(data):
    std_devs = {}
    for data_size, times in data.items():
        std_devs[data_size] = np.std(times)
    return std_devs

# Save standard deviation to CSV file
def save_standard_deviation(filepath, std_devs):
    try:
        with open(filepath, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Data Size', 'Standard Deviation'])
            for data_size, std_dev in std_devs.items():
                writer.writerow([data_size, std_dev])
    except IOError as e:
        print(f"Error writing to file: {e}")

# Plot standard deviation using Matplotlib
def plot_standard_deviation(std_devs):
    data_sizes = sorted(std_devs.keys())
    std_values = [std_devs[size] for size in data_sizes]

    plt.figure(figsize=(10, 6))
    plt.plot(data_sizes, std_values, marker='o', linestyle='-', color='b')
    plt.xlabel('Data Size (bytes)')
    plt.ylabel('Standard Deviation of Total Time (seconds)')
    plt.title('Standard Deviation of Total Time for Different Data Sizes for RSA 2048(aes128)')
    plt.grid(True)

    # Set x-axis range to start from 0 and increment by 5000
    plt.xlim(0, max(data_sizes) + 5000)

    # Set x-ticks with an increment of 5000
    plt.xticks(np.arange(0, max(data_sizes) + 5000, step=5000))

    plt.show()

if __name__ == "__main__":
    input_filepath = 'computation_times.csv'
    output_filepath = 'standard_deviation_times.csv'
    
    data = read_computation_times(input_filepath)
    print(f"Data read: {data}")
    std_devs = calculate_standard_deviation(data)
    print(f"Standard deviations calculated: {std_devs}")
    save_standard_deviation(output_filepath, std_devs)
    plot_standard_deviation(std_devs)
