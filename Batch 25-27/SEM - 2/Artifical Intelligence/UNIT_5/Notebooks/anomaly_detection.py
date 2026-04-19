import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler

# 1. DATASET SIMULATION
# In a real scenario, use: df = pd.read_csv('nsl_kdd_subset.csv')
print("--- Step 1: Preprocessing ---")
data = {
    'protocol_type': ['tcp', 'udp', 'icmp', 'tcp', 'tcp'] * 200,
    'service': ['http', 'smtp', 'dns', 'ftp', 'http'] * 200,
    'flag': ['SF', 'SF', 'S0', 'SF', 'REJ'] * 200,
    'src_bytes': np.random.randint(0, 1000, 1000),
    'dst_bytes': np.random.randint(0, 1000, 1000),
    'duration': np.random.randint(0, 100, 1000)
}
df = pd.DataFrame(data)

# Injecting artificial anomalies (Simulating intrusions with high byte counts)
df.iloc[0:50, 3:6] = df.iloc[0:50, 3:6] * 50 

# Encoding categorical features
le = LabelEncoder()
for col in ['protocol_type', 'service', 'flag']:
    df[col] = le.fit_transform(df[col])

# Scaling features for consistent distance-based isolation
scaler = StandardScaler()
X_scaled = scaler.fit_transform(df)

# 2. FIT ISOLATION FOREST MODEL
print("\n--- Step 2: Training Isolation Forest ---")
# contamination=0.05 assumes roughly 5% of your network traffic is anomalous
model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
model.fit(X_scaled)

# 3. PREDICT ANOMALIES
# Output: 1 for Normal points, -1 for Anomalous points
df['anomaly_prediction'] = model.predict(X_scaled)
df['contamination_score'] = model.decision_function(X_scaled)

print(f"Anomalies detected: {(df['anomaly_prediction'] == -1).sum()}")

# 4. VISUALIZATION
print("\n--- Step 3: Visualizing Results ---")
plt.figure(figsize=(12, 5))

# Plot A: Score Distribution
plt.subplot(1, 2, 1)
sns.histplot(df['contamination_score'], bins=50, kde=True, color='teal')
plt.axvline(x=0, color='r', linestyle='--', label='Anomaly Threshold')
plt.title('Decision Scores (Lower = More Anomalous)')
plt.legend()

# Plot B: Feature Scatter (Detecting Outliers Visually)
plt.subplot(1, 2, 2)
colors = {1: 'blue', -1: 'red'}
plt.scatter(df['src_bytes'], df['dst_bytes'], 
            c=df['anomaly_prediction'].map(colors), alpha=0.5, s=15)
plt.title('Network Traffic Map (Red = Anomaly)')
plt.xlabel('Source Bytes')
plt.ylabel('Destination Bytes')

plt.tight_layout()
plt.show()

print("\nSuccess: Unsupervised Anomaly Detection script finished.")
