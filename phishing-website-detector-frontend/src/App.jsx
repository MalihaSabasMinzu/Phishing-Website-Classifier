
import { useState } from 'react';
import './App.css';
import pasteIcon from './assets/image.png';

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    setError('');
    try {
      // Replace with your backend endpoint
      const response = await fetch('http://localhost:3000/predict-url', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Network response was not ok');
      }
      const data = await response.json();
      setResult({
        webcode: data.webcode_prediction,
        url: data.url_prediction,
        decision: data.final_decision,
        confidence: data.confidence,
        websiteAccessible: data.website_accessible,
        analysisComplete: data.analysis_complete,
        note: data.note,
        websiteError: data.website_error,
      });
    } catch (err) {
      setError('Failed to check the URL. Please try again.');
      console.log(err);
      
    } finally {
      setLoading(false);
    }
  };

  return (
      <div className="container">
        <header className="header">
          <h1>Phishing Website Detector</h1>
        </header>
        <form className="url-form" onSubmit={handleSubmit}>
          <input
            type="url"
            className="url-input"
            placeholder="Enter website URL..."
            value={url}
            onChange={e => setUrl(e.target.value)}
            required
          />
          <button
            type="button"
            className="paste-btn"
            title="Paste URL from clipboard"
            onClick={async () => {
              try {
                const text = await navigator.clipboard.readText();
                setUrl(text);
              } catch {
                setError('Failed to read clipboard.');
              }
            }}
          >
            <img src={pasteIcon} alt="Paste" style={{ width: '24px', height: '24px', objectFit: 'contain' }} />
          </button>
          <button type="submit" className="submit-btn" disabled={loading}>
            {loading ? 'Checking...' : 'Check URL'}
          </button>
        </form>
        <div className="result-section">
          {loading && <div className="loader">Loading...</div>}
          {result && (
            <div className={`result-container`}>
              <div className={`result-card ${result.decision && result.decision.toLowerCase().includes('phishing') ? 'phishing' : 'safe'}`}>
                <div className="result-header">
                  <h3>Analysis Results</h3>
                  {result.confidence && (
                    <span className={`confidence-badge ${result.confidence.toLowerCase().replace('-', '-')}`}>
                      {result.confidence} Confidence
                    </span>
                  )}
                </div>
                <div className="final-decision">{result.decision}</div>
                {result.note && <div className="note">{result.note}</div>}
              </div>
              
              <div className="analysis-details">
                <h4>Analysis Details</h4>
                <div className="detail-row">
                  <span className="detail-label">Website Accessibility:</span>
                  <span className={`status ${result.websiteAccessible ? 'success' : 'warning'}`}>
                    {result.websiteAccessible ? 'Accessible' : 'Not Accessible'}
                  </span>
                </div>
                {result.websiteError && (
                  <div className="detail-row error-detail">
                    <span className="detail-label">Website Error:</span>
                    <div className="error-text">{result.websiteError}</div>
                  </div>
                )}
                <div className="detail-row">
                  <span className="detail-label">Analysis Status:</span>
                  <span className={`status ${result.analysisComplete ? 'complete' : 'partial'}`}>
                    {result.analysisComplete ? 'Complete' : 'Partial'}
                  </span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">Content Analysis:</span>
                  <span className={`prediction ${result.webcode === null ? 'unavailable' : (result.webcode === 1 ? 'phishing' : 'safe')}`}>
                    {result.webcode === null ? 'Unavailable' : (result.webcode === 1 ? 'Phishing' : 'Safe')}
                  </span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">URL Analysis:</span>
                  <span className={`prediction ${result.url === null ? 'unavailable' : (result.url === 1 ? 'phishing' : 'safe')}`}>
                    {result.url === null ? 'Unavailable' : (result.url === 1 ? 'Phishing' : 'Safe')}
                  </span>
                </div>
              </div>
            </div>
          )}
          {error && (
            <div className="error-container">
              <div className="error-header">Analysis Failed</div>
              <div className="error-message">{error}</div>
              <div className="error-suggestions">
                <strong>Suggestions:</strong>
                <ul>
                  <li>Check if the URL is correctly formatted</li>
                  <li>Ensure the website is accessible</li>
                  <li>Try again in a few moments</li>
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>
  );
}

export default App;
