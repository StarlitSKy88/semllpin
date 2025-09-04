/**
 * Advanced Query Plan Analyzer for SmellPin Database Performance
 * 
 * Features:
 * - EXPLAIN ANALYZE execution plan analysis
 * - Query performance bottleneck detection
 * - Index usage recommendations
 * - Cost estimation and optimization suggestions
 * - Real-time query performance monitoring
 * - Automated performance alerts
 */

import { Knex } from 'knex';
import { logger } from '../utils/logger';
import { config } from '../config/config';

// Query execution plan node
interface QueryPlanNode {
  nodeType: string;
  relationName?: string;
  indexName?: string;
  totalCost: number;
  planRows: number;
  planWidth: number;
  actualTotalTime?: number;
  actualRows?: number;
  actualLoops?: number;
  bufferHits?: number;
  bufferMisses?: number;
  ioReadTime?: number;
  ioWriteTime?: number;
  plans?: QueryPlanNode[];
}

// Analysis result
interface QueryAnalysis {
  queryHash: string;
  executionTime: number;
  planningTime: number;
  totalCost: number;
  actualRows: number;
  estimatedRows: number;
  rowsAccuracy: number;
  bufferHits: number;
  bufferMisses: number;
  bufferHitRatio: number;
  recommendations: string[];
  bottlenecks: string[];
  indexesUsed: string[];
  indexesMissing: string[];
  queryComplexity: 'low' | 'medium' | 'high' | 'very_high';
  performanceScore: number; // 0-100
}

// Performance thresholds
interface PerformanceThresholds {
  maxExecutionTime: number;     // ms
  minBufferHitRatio: number;    // percentage
  maxRowsDeviation: number;     // percentage
  maxSeqScanRows: number;       // max rows for seq scan
}

// Query pattern analysis
interface QueryPattern {
  pattern: string;
  frequency: number;
  averageTime: number;
  lastSeen: Date;
  optimization: string;
}

class QueryAnalyzerService {
  private static instance: QueryAnalyzerService;
  private queryHistory: Map<string, QueryAnalysis[]> = new Map();
  private queryPatterns: Map<string, QueryPattern> = new Map();
  private performanceThresholds: PerformanceThresholds;
  private analysisCache: Map<string, QueryAnalysis> = new Map();
  private monitoringEnabled: boolean;

  private constructor() {
    this.performanceThresholds = {
      maxExecutionTime: 100,        // 100ms max for LBS queries
      minBufferHitRatio: 95,        // 95% minimum buffer hit ratio
      maxRowsDeviation: 50,         // 50% max deviation between estimated/actual
      maxSeqScanRows: 1000          // Max rows for sequential scan
    };

    this.monitoringEnabled = config.NODE_ENV === 'production' || config.NODE_ENV === 'development';
    
    if (this.monitoringEnabled) {
      this.startMonitoring();
    }
  }

  public static getInstance(): QueryAnalyzerService {
    if (!QueryAnalyzerService.instance) {
      QueryAnalyzerService.instance = new QueryAnalyzerService();
    }
    return QueryAnalyzerService.instance;
  }

  // Analyze query execution plan
  public async analyzeQuery(
    db: Knex,
    sql: string,
    params: any[] = [],
    options: {
      analyze?: boolean;
      buffers?: boolean;
      verbose?: boolean;
      format?: 'text' | 'json';
    } = {}
  ): Promise<QueryAnalysis> {
    const {
      analyze = true,
      buffers = true,
      verbose = true,
      format = 'json'
    } = options;

    if (db.client.config.client !== 'postgresql' && db.client.config.client !== 'pg') {
      throw new Error('Query analysis is only supported for PostgreSQL');
    }

    const queryHash = this.generateQueryHash(sql, params);
    
    // Check cache first
    if (this.analysisCache.has(queryHash)) {
      const cached = this.analysisCache.get(queryHash)!;
      logger.debug(`📋 Using cached query analysis: ${queryHash.slice(0, 8)}`);
      return cached;
    }

    try {
      const startTime = Date.now();
      
      // Build EXPLAIN command
      let explainQuery = 'EXPLAIN';
      if (analyze) explainQuery += ' (ANALYZE true';
      if (buffers) explainQuery += ', BUFFERS true';
      if (verbose) explainQuery += ', VERBOSE true';
      if (format === 'json') explainQuery += ', FORMAT JSON';
      if (analyze) explainQuery += ')';
      
      explainQuery += ` ${sql}`;

      // Execute EXPLAIN
      const result = await db.raw(explainQuery, params);
      const executionTime = Date.now() - startTime;

      // Parse results
      let planData;
      if (format === 'json') {
        planData = result.rows[0]['QUERY PLAN'][0];
      } else {
        // Parse text format (more complex parsing required)
        planData = this.parseTextPlan(result.rows.map((row: Record<string, any>) => row['QUERY PLAN']));
      }

      // Analyze execution plan
      const analysis = this.analyzePlan(planData, queryHash, executionTime);
      
      // Store in cache
      this.analysisCache.set(queryHash, analysis);
      
      // Update query history
      this.updateQueryHistory(queryHash, analysis);
      
      // Update query patterns
      this.updateQueryPatterns(sql, analysis);

      logger.info(`🔍 Query analysis completed: ${analysis.performanceScore}/100 score`);

      return analysis;

    } catch (error) {
      logger.error('❌ Query analysis failed:', error);
      throw error;
    }
  }

  // Generate hash for query identification
  private generateQueryHash(sql: string, params: any[]): string {
    const normalized = this.normalizeQuery(sql);
    const combined = normalized + JSON.stringify(params);
    
    return require('crypto')
      .createHash('md5')
      .update(combined)
      .digest('hex');
  }

  // Normalize query for pattern matching
  private normalizeQuery(sql: string): string {
    return sql
      .replace(/\s+/g, ' ')                    // Normalize whitespace
      .replace(/\$\d+/g, '?')                  // Replace parameter placeholders
      .replace(/IN\s*\([^)]+\)/gi, 'IN (?)')   // Normalize IN clauses
      .replace(/VALUES\s*\([^)]+\)/gi, 'VALUES (?)') // Normalize VALUES
      .trim()
      .toLowerCase();
  }

  // Analyze execution plan data
  private analyzePlan(planData: any, queryHash: string, executionTime: number): QueryAnalysis {
    const plan = planData.Plan || planData;
    
    const analysis: QueryAnalysis = {
      queryHash,
      executionTime,
      planningTime: planData['Planning Time'] || 0,
      totalCost: plan['Total Cost'] || 0,
      actualRows: plan['Actual Rows'] || 0,
      estimatedRows: plan['Plan Rows'] || 0,
      rowsAccuracy: 0,
      bufferHits: planData['Shared Hit Blocks'] || 0,
      bufferMisses: planData['Shared Read Blocks'] || 0,
      bufferHitRatio: 0,
      recommendations: [],
      bottlenecks: [],
      indexesUsed: [],
      indexesMissing: [],
      queryComplexity: 'low',
      performanceScore: 100
    };

    // Calculate derived metrics
    if (analysis.estimatedRows > 0) {
      analysis.rowsAccuracy = Math.abs(1 - (analysis.actualRows / analysis.estimatedRows)) * 100;
    }

    if (analysis.bufferHits + analysis.bufferMisses > 0) {
      analysis.bufferHitRatio = (analysis.bufferHits / (analysis.bufferHits + analysis.bufferMisses)) * 100;
    }

    // Analyze plan nodes recursively
    this.analyzePlanNode(plan, analysis);

    // Calculate complexity and performance score
    analysis.queryComplexity = this.calculateComplexity(plan, analysis);
    analysis.performanceScore = this.calculatePerformanceScore(analysis);

    // Generate recommendations
    this.generateRecommendations(analysis);

    return analysis;
  }

  // Analyze individual plan node
  private analyzePlanNode(node: QueryPlanNode, analysis: QueryAnalysis): void {
    if (!node) return;

    const extendedNode = node as any;
    const nodeType = node.nodeType || extendedNode['Node Type'];
    const relationName = node.relationName || extendedNode['Relation Name'];
    const indexName = node.indexName || extendedNode['Index Name'];
    const actualTime = node.actualTotalTime || extendedNode['Actual Total Time'];
    const actualRows = node.actualRows || extendedNode['Actual Rows'];

    // Track indexes used
    if (indexName && !analysis.indexesUsed.includes(indexName)) {
      analysis.indexesUsed.push(indexName);
    }

    // Identify bottlenecks
    if (actualTime && actualTime > this.performanceThresholds.maxExecutionTime * 0.5) {
      analysis.bottlenecks.push(`${nodeType} on ${relationName || 'unknown'} took ${actualTime}ms`);
    }

    // Sequential scan analysis
    if (nodeType === 'Seq Scan' && actualRows > this.performanceThresholds.maxSeqScanRows) {
      analysis.bottlenecks.push(`Sequential scan on ${relationName} scanned ${actualRows} rows`);
      analysis.indexesMissing.push(`Consider adding index on ${relationName}`);
    }

    // Nested loop analysis
    if (nodeType === 'Nested Loop' && actualRows > 10000) {
      analysis.bottlenecks.push(`Large nested loop with ${actualRows} iterations`);
    }

    // Hash join analysis
    if (nodeType === 'Hash Join' || nodeType === 'Hash') {
      const extendedNode = node as any;
      const workMemUsed = extendedNode['Peak Memory Usage'] || 0;
      if (workMemUsed > 64 * 1024) { // 64MB
        analysis.bottlenecks.push(`Hash operation used ${workMemUsed}KB of memory`);
      }
    }

    // Sort analysis
    if (nodeType === 'Sort') {
      const extendedNode = node as any;
      const sortMethod = extendedNode['Sort Method'] || 'unknown';
      if (typeof sortMethod === 'string' && sortMethod.includes('external')) {
        analysis.bottlenecks.push('Sort spilled to disk (external sort)');
      }
    }

    // Aggregate analysis
    if (nodeType === 'Aggregate' || nodeType === 'GroupAggregate') {
      if (actualRows > 100000) {
        analysis.bottlenecks.push(`Large aggregation with ${actualRows} groups`);
      }
    }

    // Recursively analyze child nodes
    if (node.plans) {
      node.plans.forEach(childNode => this.analyzePlanNode(childNode, analysis));
    }
  }

  // Calculate query complexity
  private calculateComplexity(plan: any, analysis: QueryAnalysis): 'low' | 'medium' | 'high' | 'very_high' {
    let complexityScore = 0;

    // Factor in execution time
    if (analysis.executionTime > 1000) complexityScore += 3;
    else if (analysis.executionTime > 500) complexityScore += 2;
    else if (analysis.executionTime > 100) complexityScore += 1;

    // Factor in number of rows processed
    if (analysis.actualRows > 100000) complexityScore += 3;
    else if (analysis.actualRows > 10000) complexityScore += 2;
    else if (analysis.actualRows > 1000) complexityScore += 1;

    // Factor in plan depth and operations
    const planDepth = this.calculatePlanDepth(plan);
    if (planDepth > 6) complexityScore += 2;
    else if (planDepth > 4) complexityScore += 1;

    // Factor in join operations
    const joinCount = this.countJoinOperations(plan);
    complexityScore += Math.min(joinCount, 3);

    // Return complexity level
    if (complexityScore >= 8) return 'very_high';
    if (complexityScore >= 6) return 'high';
    if (complexityScore >= 3) return 'medium';
    return 'low';
  }

  // Calculate plan depth
  private calculatePlanDepth(node: any): number {
    if (!node || !node.plans) return 1;
    
    let maxDepth = 0;
    for (const childNode of node.plans) {
      maxDepth = Math.max(maxDepth, this.calculatePlanDepth(childNode));
    }
    
    return maxDepth + 1;
  }

  // Count join operations in plan
  private countJoinOperations(node: any): number {
    if (!node) return 0;
    
    let count = 0;
    const nodeType = node['Node Type'] || '';
    
    if (nodeType.includes('Join')) {
      count = 1;
    }
    
    if (node.plans) {
      for (const childNode of node.plans) {
        count += this.countJoinOperations(childNode);
      }
    }
    
    return count;
  }

  // Calculate performance score (0-100)
  private calculatePerformanceScore(analysis: QueryAnalysis): number {
    let score = 100;

    // Execution time penalty
    if (analysis.executionTime > this.performanceThresholds.maxExecutionTime) {
      score -= Math.min(50, (analysis.executionTime - this.performanceThresholds.maxExecutionTime) / 10);
    }

    // Buffer hit ratio penalty
    if (analysis.bufferHitRatio < this.performanceThresholds.minBufferHitRatio) {
      score -= (this.performanceThresholds.minBufferHitRatio - analysis.bufferHitRatio);
    }

    // Row estimation accuracy penalty
    if (analysis.rowsAccuracy > this.performanceThresholds.maxRowsDeviation) {
      score -= Math.min(20, (analysis.rowsAccuracy - this.performanceThresholds.maxRowsDeviation) / 5);
    }

    // Bottlenecks penalty
    score -= analysis.bottlenecks.length * 5;

    // Missing indexes penalty
    score -= analysis.indexesMissing.length * 10;

    return Math.max(0, Math.round(score));
  }

  // Generate optimization recommendations
  private generateRecommendations(analysis: QueryAnalysis): void {
    const recommendations: string[] = [];

    // Execution time recommendations
    if (analysis.executionTime > this.performanceThresholds.maxExecutionTime) {
      recommendations.push(`Query execution time (${analysis.executionTime}ms) exceeds target (${this.performanceThresholds.maxExecutionTime}ms)`);
    }

    // Buffer hit ratio recommendations
    if (analysis.bufferHitRatio < this.performanceThresholds.minBufferHitRatio) {
      recommendations.push(`Buffer hit ratio (${analysis.bufferHitRatio.toFixed(1)}%) is below optimal (${this.performanceThresholds.minBufferHitRatio}%)`);
      recommendations.push('Consider increasing shared_buffers or reducing data set size');
    }

    // Row estimation recommendations
    if (analysis.rowsAccuracy > this.performanceThresholds.maxRowsDeviation) {
      recommendations.push(`Row estimation accuracy is poor (${analysis.rowsAccuracy.toFixed(1)}% deviation)`);
      recommendations.push('Run ANALYZE on affected tables to update statistics');
    }

    // Index recommendations
    if (analysis.indexesMissing.length > 0) {
      recommendations.push('Consider creating indexes for better performance:');
      recommendations.push(...analysis.indexesMissing);
    }

    // Complexity recommendations
    if (analysis.queryComplexity === 'very_high') {
      recommendations.push('Query complexity is very high, consider breaking into smaller queries');
      recommendations.push('Use materialized views for complex aggregations');
    }

    // Geographic query specific recommendations
    if (analysis.indexesUsed.some(idx => idx.includes('gist') || idx.includes('location'))) {
      recommendations.push('Geographic query detected - ensure PostGIS is optimally configured');
      if (analysis.executionTime > 200) {
        recommendations.push('Consider using bounding box pre-filtering for geographic queries');
      }
    }

    analysis.recommendations = recommendations;
  }

  // Parse text format execution plan
  private parseTextPlan(textLines: string[]): any {
    // Simplified text plan parser - in production, you'd want a more robust parser
    const plan = {
      'Node Type': 'Unknown',
      'Total Cost': 0,
      'Actual Total Time': 0,
      'Actual Rows': 0
    };

    for (const line of textLines) {
      if (line.includes('cost=')) {
        const costMatch = line.match(/cost=[\d.]+\.\.([\d.]+)/);
        if (costMatch) {
          plan['Total Cost'] = parseFloat(costMatch[1]);
        }
      }
      
      if (line.includes('actual time=')) {
        const timeMatch = line.match(/actual time=[\d.]+\.\.([\d.]+)/);
        if (timeMatch) {
          plan['Actual Total Time'] = parseFloat(timeMatch[1]);
        }
      }
      
      if (line.includes('rows=')) {
        const rowsMatch = line.match(/rows=([\d]+)/);
        if (rowsMatch) {
          plan['Actual Rows'] = parseInt(rowsMatch[1]);
        }
      }
    }

    return { Plan: plan };
  }

  // Update query history
  private updateQueryHistory(queryHash: string, analysis: QueryAnalysis): void {
    if (!this.queryHistory.has(queryHash)) {
      this.queryHistory.set(queryHash, []);
    }

    const history = this.queryHistory.get(queryHash)!;
    history.push(analysis);

    // Keep only last 10 analyses per query
    if (history.length > 10) {
      history.splice(0, history.length - 10);
    }
  }

  // Update query patterns
  private updateQueryPatterns(sql: string, analysis: QueryAnalysis): void {
    const pattern = this.normalizeQuery(sql);
    
    if (!this.queryPatterns.has(pattern)) {
      this.queryPatterns.set(pattern, {
        pattern,
        frequency: 0,
        averageTime: 0,
        lastSeen: new Date(),
        optimization: ''
      });
    }

    const queryPattern = this.queryPatterns.get(pattern)!;
    queryPattern.frequency++;
    queryPattern.averageTime = 
      (queryPattern.averageTime * (queryPattern.frequency - 1) + analysis.executionTime) / 
      queryPattern.frequency;
    queryPattern.lastSeen = new Date();

    // Generate optimization suggestion
    if (queryPattern.frequency > 10 && queryPattern.averageTime > 100) {
      queryPattern.optimization = 'High frequency, slow query - consider adding to prepared statements and caching';
    }
  }

  // Get query performance summary
  public getPerformanceSummary(): {
    totalQueriesAnalyzed: number;
    averageExecutionTime: number;
    slowQueries: number;
    commonPatterns: QueryPattern[];
    recentBottlenecks: string[];
  } {
    const allAnalyses = Array.from(this.queryHistory.values()).flat();
    const slowThreshold = this.performanceThresholds.maxExecutionTime;

    const summary = {
      totalQueriesAnalyzed: allAnalyses.length,
      averageExecutionTime: allAnalyses.length > 0 ? 
        allAnalyses.reduce((sum, a) => sum + a.executionTime, 0) / allAnalyses.length : 0,
      slowQueries: allAnalyses.filter(a => a.executionTime > slowThreshold).length,
      commonPatterns: Array.from(this.queryPatterns.values())
        .sort((a, b) => b.frequency - a.frequency)
        .slice(0, 10),
      recentBottlenecks: allAnalyses
        .slice(-50)
        .flatMap(a => a.bottlenecks)
        .slice(0, 20)
    };

    return summary;
  }

  // Start performance monitoring
  private startMonitoring(): void {
    setInterval(() => {
      this.performMonitoringCheck();
    }, 60000); // Check every minute

    logger.info('📊 Query performance monitoring started');
  }

  // Perform monitoring check
  private performMonitoringCheck(): void {
    const summary = this.getPerformanceSummary();
    
    // Alert on high average execution time
    if (summary.averageExecutionTime > this.performanceThresholds.maxExecutionTime * 2) {
      logger.warn('⚠️ High average query execution time detected', {
        averageTime: summary.averageExecutionTime,
        threshold: this.performanceThresholds.maxExecutionTime * 2
      });
    }

    // Alert on high percentage of slow queries
    if (summary.totalQueriesAnalyzed > 0) {
      const slowQueryPercentage = (summary.slowQueries / summary.totalQueriesAnalyzed) * 100;
      if (slowQueryPercentage > 20) {
        logger.warn('⚠️ High percentage of slow queries detected', {
          slowQueryPercentage,
          slowQueries: summary.slowQueries,
          totalQueries: summary.totalQueriesAnalyzed
        });
      }
    }
  }

  // Clear analysis cache
  public clearCache(): void {
    this.analysisCache.clear();
    this.queryHistory.clear();
    this.queryPatterns.clear();
    logger.info('🗑️ Query analysis cache cleared');
  }

  // Export analysis report
  public exportReport(): any {
    return {
      performanceSummary: this.getPerformanceSummary(),
      queryPatterns: Array.from(this.queryPatterns.values()),
      recentAnalyses: Array.from(this.queryHistory.entries())
        .map(([hash, analyses]) => ({
          queryHash: hash,
          analysisCount: analyses.length,
          latestAnalysis: analyses[analyses.length - 1]
        })),
      configuration: this.performanceThresholds,
      timestamp: new Date().toISOString()
    };
  }
}

// Export singleton instance
export const queryAnalyzer = QueryAnalyzerService.getInstance();

// Export convenience functions
export const analyzeQuery = queryAnalyzer.analyzeQuery.bind(queryAnalyzer);
export const getPerformanceSummary = queryAnalyzer.getPerformanceSummary.bind(queryAnalyzer);
export const exportAnalysisReport = queryAnalyzer.exportReport.bind(queryAnalyzer);
export const clearAnalysisCache = queryAnalyzer.clearCache.bind(queryAnalyzer);

export default queryAnalyzer;