import sys
import numpy as np

print("Python version:", sys.version)
print("NumPy version:", np.__version__)

# Simple test
data = np.random.randn(100)
print("Test numpy array created successfully")
print("Mean:", np.mean(data))
