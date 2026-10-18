const ollamaService = require('../services/ollamaService');
const { getHeapStatistics } = require('node:v8');
const { createTrackRequestCompletion } = require('./trackRequestCompletion');

class PerformanceMonitor {
  constructor() {
    this.requestCounts = new Map();
    this.averageResponseTimes = new Map();
    this.errorRates = new Map();
    this.windowSize = 60000; // 1 minute window
    this.cleanupInterval = 300000; // 5 minutes
    
    // Start cleanup interval
    setInterval(() => this.cleanup(), this.cleanupInterval);
    
    // Monitor system resources
    this.systemStats = {
      activeConnections: 0,
      memoryUsage: process.memoryUsage(),
      heapLimit: getHeapStatistics().heap_size_limit,
      cpuUsage: 0
    };
    
    this.cpuSample = process.cpuUsage();
    this.cpuSampleTime = process.hrtime.bigint();

    // Update system stats every 30 seconds
    setInterval(() => this.updateSystemStats(), 30000);
  }

  // Middleware to track performance
  trackRequest() {
    return createTrackRequestCompletion(this);
  }

  recordMetrics(endpoint, responseTime, isError) {
    const now = Date.now();
    const windowStart = now - this.windowSize;
    
    // Initialize maps if needed
    if (!this.requestCounts.has(endpoint)) {
      this.requestCounts.set(endpoint, []);
      this.averageResponseTimes.set(endpoint, []);
      this.errorRates.set(endpoint, []);
    }
    
    // Add new metrics
    this.requestCounts.get(endpoint).push({ timestamp: now, count: 1 });
    this.averageResponseTimes.get(endpoint).push({ timestamp: now, time: responseTime });
    if (isError) {
      this.errorRates.get(endpoint).push({ timestamp: now, error: 1 });
    }
    
    // Clean old data
    this.cleanOldData(endpoint, windowStart);
  }

  cleanOldData(endpoint, windowStart) {
    const requestData = this.requestCounts.get(endpoint);
    const responseData = this.averageResponseTimes.get(endpoint);
    const errorData = this.errorRates.get(endpoint);
    
    if (requestData) {
      this.requestCounts.set(endpoint, 
        requestData.filter(item => item.timestamp >= windowStart)
      );
    }
    
    if (responseData) {
      this.averageResponseTimes.set(endpoint,
        responseData.filter(item => item.timestamp >= windowStart)
      );
    }
    
    if (errorData) {
      this.errorRates.set(endpoint,
        errorData.filter(item => item.timestamp >= windowStart)
      );
    }
  }

  cleanup() {
    const now = Date.now();
    const windowStart = now - this.windowSize;
    
    // Clean all endpoints
    for (const endpoint of this.requestCounts.keys()) {
      this.cleanOldData(endpoint, windowStart);
    }
    
    // Update Ollama concurrency based on performance
    this.adjustConcurrency();
  }

  adjustConcurrency() {
    const stats = this.getStats();
    const aiEndpoints = Object.keys(stats).filter(endpoint => 
      endpoint.includes('/ai/') || endpoint.includes('/xss/') || endpoint.includes('/prompt')
    );
    
    let totalRequests = 0;
    let avgResponseTime = 0;
    let errorRate = 0;
    
    aiEndpoints.forEach(endpoint => {
      const endpointStats = stats[endpoint];
      totalRequests += endpointStats.requestsPerMinute;
      avgResponseTime += endpointStats.avgResponseTime;
      errorRate += endpointStats.errorRate;
    });
    
    avgResponseTime = avgResponseTime / aiEndpoints.length || 0;
    errorRate = errorRate / aiEndpoints.length || 0;
    
    // Adjust concurrency based on performance
    let newConcurrency = 20; // Default
    
    if (avgResponseTime > 5000) { // If responses are slow (>5s)
      newConcurrency = Math.max(10, Math.floor(newConcurrency * 0.7));
    } else if (avgResponseTime < 2000 && errorRate < 0.05) { // Fast responses, low errors
      newConcurrency = Math.min(50, Math.floor(newConcurrency * 1.2));
    }
    
    // Consider memory usage
    const memUsage = this.systemStats.memoryUsage.heapUsed / this.systemStats.heapLimit;
    if (memUsage > 0.8) { // High memory usage
      newConcurrency = Math.max(5, Math.floor(newConcurrency * 0.5));
    }
    
    // Update Ollama service
    ollamaService.updateConcurrencyLimits(newConcurrency);
  }

  updateSystemStats() {
    this.systemStats.memoryUsage = process.memoryUsage();
    
    this.systemStats.heapLimit = getHeapStatistics().heap_size_limit;
    const cpu = process.cpuUsage();
    const now = process.hrtime.bigint();
    const elapsedMicros = Number(now - this.cpuSampleTime) / 1000;
    const usedMicros = cpu.user - this.cpuSample.user + cpu.system - this.cpuSample.system;
    // Process CPU as a percentage of one core; parallel native workers may
    // legitimately exceed 100%. Timer delay alone is not CPU consumption.
    this.systemStats.cpuUsage = elapsedMicros > 0 ? Math.max(0, usedMicros / elapsedMicros * 100) : 0;
    this.cpuSample = cpu;
    this.cpuSampleTime = now;
  }

  getStats() {
    const stats = {};
    
    for (const [endpoint, requests] of this.requestCounts.entries()) {
      const responses = this.averageResponseTimes.get(endpoint) || [];
      const errors = this.errorRates.get(endpoint) || [];
      
      const requestsPerMinute = requests.length;
      const avgResponseTime = responses.length > 0 ? 
        responses.reduce((sum, item) => sum + item.time, 0) / responses.length : 0;
      const errorRate = errors.length / Math.max(requests.length, 1);
      
      stats[endpoint] = {
        requestsPerMinute,
        avgResponseTime: Math.round(avgResponseTime),
        errorRate: Math.round(errorRate * 100) / 100
      };
    }
    
    return stats;
  }

  getSystemStats() {
    return {
      activeConnections: this.systemStats.activeConnections,
      memoryUsage: {
        used: Math.round(this.systemStats.memoryUsage.heapUsed / 1024 / 1024),
        total: Math.round(this.systemStats.heapLimit / 1024 / 1024),
        allocated: Math.round(this.systemStats.memoryUsage.heapTotal / 1024 / 1024),
        rss: Math.round(this.systemStats.memoryUsage.rss / 1024 / 1024),
        external: Math.round(this.systemStats.memoryUsage.external / 1024 / 1024),
        basis: 'v8-heap-limit',
        percentage: Math.round((this.systemStats.memoryUsage.heapUsed / this.systemStats.heapLimit) * 100)
      },
      cpuUsage: Math.round(this.systemStats.cpuUsage * 100) / 100
    };
  }

  // Get comprehensive monitoring data
  getMonitoringData() {
    return {
      performance: this.getStats(),
      system: this.getSystemStats(),
      ollama: ollamaService.getStats(),
      timestamp: new Date().toISOString()
    };
  }
}

module.exports = new PerformanceMonitor();