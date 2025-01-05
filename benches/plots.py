import os
import json
import pandas as pd
import matplotlib.pyplot as plt

# Directory containing Criterion benchmark results
CRITERION_RESULTS_DIR = "target/criterion"

# Initialize a dictionary to store parsed data
data = []

# Traverse Criterion results
for root, dirs, files in os.walk(CRITERION_RESULTS_DIR):
    for file in files:
        if file == "estimates.json":
            with open(os.path.join(root, file)) as f:
                estimates = json.load(f)
                mean_time = estimates["mean"]["point_estimate"]
                benchmark_name = os.path.basename(root)
                
                # Extract number of parties from benchmark name
                if "parties_" in benchmark_name:
                    parts = benchmark_name.split("_")
                    parties = int(parts[-1])
                else:
                    parties = None
                
                # Store data
                data.append({"benchmark": benchmark_name, "parties": parties, "mean_time": mean_time})

# Create a DataFrame
df = pd.DataFrame(data)

# Extract benchmarks and party counts
benchmarks = df["benchmark"].unique()
num_parties = sorted(df["parties"].dropna().unique())

# Save the DataFrame for reference
df.to_csv("benchmark_results.csv", index=False)

# Create plots for each benchmark
for benchmark in benchmarks:
    benchmark_df = df[df["benchmark"] == benchmark]
    plt.figure()
    plt.plot(benchmark_df["parties"], benchmark_df["mean_time"], marker="o", label=benchmark)
    plt.xlabel("Number of Parties")
    plt.ylabel("Mean Time (ns)")
    plt.title(f"Performance of {benchmark}")
    plt.legend()
    plt.grid(True)
    plt.savefig(f"{benchmark}_performance.png")  # Save plot as PNG
    plt.show()
