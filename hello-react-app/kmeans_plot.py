import numpy as np
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn.datasets import make_blobs
import os

# Generate sample data
np.random.seed(42)
X, y = make_blobs(n_samples=300, centers=4, n_features=2, random_state=42)

# Perform KMeans clustering
kmeans = KMeans(n_clusters=4, random_state=42, n_init=10)
y_pred = kmeans.fit_predict(X)

# Create the plot
plt.figure(figsize=(10, 8))
plt.scatter(X[y_pred == 0, 0], X[y_pred == 0, 1], c='red', label='Cluster 1', s=50)
plt.scatter(X[y_pred == 1, 0], X[y_pred == 1, 1], c='blue', label='Cluster 2', s=50)
plt.scatter(X[y_pred == 2, 0], X[y_pred == 2, 1], c='green', label='Cluster 3', s=50)
plt.scatter(X[y_pred == 3, 0], X[y_pred == 3, 1], c='yellow', label='Cluster 4', s=50)

# Plot cluster centers
plt.scatter(kmeans.cluster_centers_[:, 0], kmeans.cluster_centers_[:, 1], 
            c='black', marker='X', s=300, edgecolors='white', linewidths=2, label='Centroids')

plt.xlabel('Feature 1')
plt.ylabel('Feature 2')
plt.title('KMeans Clustering Results')
plt.legend()
plt.grid(True, alpha=0.3)

# Create public folder if it doesn't exist and save the plot
public_dir = os.path.join(os.path.dirname(__file__), 'public')
os.makedirs(public_dir, exist_ok=True)
plt.savefig(os.path.join(public_dir, 'kmeans_plot.png'), dpi=100, bbox_inches='tight')
print("KMeans plot saved to public/kmeans_plot.png")
plt.close()
