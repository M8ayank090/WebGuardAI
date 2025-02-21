import React, { useState, useEffect } from 'react';
import { LineChart, XAxis, YAxis, CartesianGrid, Tooltip, Line } from 'recharts';
import { AlertCircle, Shield, Activity } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';

const Dashboard = () => {
  const [threatData, setThreatData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [timeRange, setTimeRange] = useState('24h');

  useEffect(() => {
    fetchThreatData();
  }, [timeRange]);

  const fetchThreatData = async () => {
    try {
      const response = await fetch(`/api/analysis/results?timeRange=${timeRange}`);
      const data = await response.json();
      setThreatData(data);
      setLoading(false);
    } catch (err) {
      setError('Failed to fetch threat data');
      setLoading(false);
    }
  };

  const getThreatLevelColor = (level) => {
    const colors = {
      LOW: 'bg-green-100 text-green-800',
      MEDIUM: 'bg-yellow-100 text-yellow-800',
      HIGH: 'bg-orange-100 text-orange-800',
      CRITICAL: 'bg-red-100 text-red-800'
    };
    return colors[level] || 'bg-gray-100 text-gray-800';
  };

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between mb-8">
        <h1 className="text-3xl font-bold">WebGuardAI Dashboard</h1>
        <select
          className="p-2 border rounded-lg"
          value={timeRange}
          onChange={(e) => setTimeRange(e.target.value)}
        >
          <option value="24h">Last 24 Hours</option>
          <option value="7d">Last 7 Days</option>
          <option value="30d">Last 30 Days</option>
        </select>
      </div>

      {error && (
        <Alert variant="destructive" className="mb-6">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="p-6 bg-white rounded-lg shadow">
          <div className="flex items-center gap-4">
            <Shield className="h-8 w-8 text-blue-500" />
            <div>
              <h3 className="text-lg font-medium">Total Scans</h3>
              <p className="text-2xl font-bold">{threatData.totalScans || 0}</p>
            </div>
          </div>
        </div>

        <div className="p-6 bg-white rounded-lg shadow">
          <div className="flex items-center gap-4">
            <AlertCircle className="h-8 w-8 text-red-500" />
            <div>
              <h3 className="text-lg font-medium">Active Threats</h3>
              <p className="text-2xl font-bold">{threatData.activeThreats || 0}</p>
            </div>
          </div>
        </div>

        <div className="p-6 bg-white rounded-lg shadow">
          <div className="flex items-center gap-4">
            <Activity className="h-8 w-8 text-green-500" />
            <div>
              <h3 className="text-lg font-medium">Average Risk Score</h3>
              <p className="text-2xl font-bold">
                {(threatData.averageRiskScore || 0).toFixed(2)}
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white p-6 rounded-lg shadow mb-8">
        <h2 className="text-xl font-bold mb-4">Threat Detection Trend</h2>
        <LineChart width={800} height={300} data={threatData.threatTrend || []}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="timestamp" />
          <YAxis />
          <Tooltip />
          <Line type="monotone" dataKey="threatScore" stroke="#2563eb" />
        </LineChart>
      </div>

      <div className="bg-white p-6 rounded-lg shadow">
        <h2 className="text-xl font-bold mb-4">Recent Detections</h2>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b">
                <th className="p-3 text-left">URL</th>
                <th className="p-3 text-left">Threat Level</th>
                <th className="p-3 text-left">Score</th>
                <th className="p-3 text-left">Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {(threatData.recentDetections || []).map((detection, index) => (
                <tr key={index} className="border-b">
                  <td className="p-3">{detection.url}</td>
                  <td className="p-3">
                    <span className={`px-2 py-1 rounded ${getThreatLevelColor(detection.threatLevel)}`}>
                      {detection.threatLevel}
                    </span>
                  </td>
                  <td className="p-3">{detection.score.toFixed(2)}</td>
                  <td className="p-3">{new Date(detection.timestamp).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
