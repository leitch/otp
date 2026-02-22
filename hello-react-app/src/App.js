import './App.css';

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <h1>KMeans Clustering Visualization</h1>
        <p>Sample data clustered into 4 groups using scikit-learn</p>
        <img 
          src="/kmeans_plot.png" 
          alt="KMeans Clustering Plot" 
          style={{maxWidth: '90%', height: 'auto', marginTop: '20px'}}
        />
        <p style={{marginTop: '20px', fontSize: '14px', color: '#666'}}>
          This visualization shows 300 sample points classified into 4 clusters using the KMeans algorithm.
          Black X markers represent the cluster centroids.
        </p>
      </header>
    </div>
  );
}

export default App;
