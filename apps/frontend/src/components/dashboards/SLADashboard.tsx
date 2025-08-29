'use client'

import React, { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { 
  Clock, 
  Target, 
  TrendingUp, 
  TrendingDown, 
  AlertTriangle, 
  CheckCircle,
  BarChart3,
  Calendar,
  Filter
} from 'lucide-react'

interface SLAMetric {
  name: string
  current: number
  target: number
  unit: string
  trend: 'up' | 'down' | 'stable'
  status: 'good' | 'warning' | 'critical'
}

interface IncidentMetrics {
  mttd: SLAMetric // Mean Time to Detection
  mttr: SLAMetric // Mean Time to Response  
  mttc: SLAMetric // Mean Time to Containment
  mttr_resolution: SLAMetric // Mean Time to Resolution
  dwell_time: SLAMetric
  sla_compliance: SLAMetric
}

interface SLADashboardProps {
  timeRange?: string
}

export function SLADashboard({ timeRange = '30d' }: SLADashboardProps) {
  const [metrics, setMetrics] = useState<IncidentMetrics | null>(null)
  const [selectedTimeRange, setSelectedTimeRange] = useState(timeRange)

  useEffect(() => {
    fetchSLAMetrics()
  }, [selectedTimeRange])

  const fetchSLAMetrics = async () => {
    try {
      // Simulate API call
      const mockMetrics: IncidentMetrics = {
        mttd: {
          name: 'Mean Time to Detection',
          current: 18,
          target: 30,
          unit: 'minutes',
          trend: 'down',
          status: 'good'
        },
        mttr: {
          name: 'Mean Time to Response',
          current: 45,
          target: 60,
          unit: 'minutes',
          trend: 'down',
          status: 'good'
        },
        mttc: {
          name: 'Mean Time to Containment',
          current: 120,
          target: 240,
          unit: 'minutes',
          trend: 'up',
          status: 'warning'
        },
        mttr_resolution: {
          name: 'Mean Time to Resolution',
          current: 8.5,
          target: 24,
          unit: 'hours',
          trend: 'stable',
          status: 'good'
        },
        dwell_time: {
          name: 'Average Dwell Time',
          current: 72,
          target: 48,
          unit: 'hours',
          trend: 'up',
          status: 'critical'
        },
        sla_compliance: {
          name: 'SLA Compliance Rate',
          current: 94.5,
          target: 95,
          unit: '%',
          trend: 'down',
          status: 'warning'
        }
      }
      setMetrics(mockMetrics)
    } catch (error) {
      console.error('Failed to fetch SLA metrics:', error)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'good': return 'text-green-600'
      case 'warning': return 'text-yellow-600'
      case 'critical': return 'text-red-600'
      default: return 'text-gray-600'
    }
  }

  const getStatusBadgeVariant = (status: string) => {
    switch (status) {
      case 'good': return 'default'
      case 'warning': return 'default'
      case 'critical': return 'destructive'
      default: return 'outline'
    }
  }

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case 'up': return <TrendingUp className="h-4 w-4 text-red-500" />
      case 'down': return <TrendingDown className="h-4 w-4 text-green-500" />
      case 'stable': return <div className="h-4 w-4 bg-gray-400 rounded-full" />
      default: return null
    }
  }

  const getCompliancePercentage = (current: number, target: number) => {
    return Math.min((current / target) * 100, 100)
  }

  if (!metrics) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>SLA Dashboard</CardTitle>
          <CardDescription>Loading SLA metrics...</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center h-64">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <BarChart3 className="h-5 w-5" />
                SLA Performance Dashboard
              </CardTitle>
              <CardDescription>
                Incident response SLA metrics and performance indicators
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4" />
              <Button
                variant={selectedTimeRange === '7d' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSelectedTimeRange('7d')}
              >
                7 Days
              </Button>
              <Button
                variant={selectedTimeRange === '30d' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSelectedTimeRange('30d')}
              >
                30 Days
              </Button>
              <Button
                variant={selectedTimeRange === '90d' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSelectedTimeRange('90d')}
              >
                90 Days
              </Button>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Key Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {Object.entries(metrics).map(([key, metric]) => (
          <Card key={key}>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium">{metric.name}</CardTitle>
                {getTrendIcon(metric.trend)}
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="flex items-baseline gap-2">
                  <span className={`text-2xl font-bold ${getStatusColor(metric.status)}`}>
                    {metric.current}
                  </span>
                  <span className="text-sm text-muted-foreground">{metric.unit}</span>
                </div>
                
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">
                    Target: {metric.target} {metric.unit}
                  </span>
                  <Badge variant={getStatusBadgeVariant(metric.status)}>
                    {metric.status}
                  </Badge>
                </div>
                
                {/* Progress Bar */}
                <div className="space-y-1">
                  <div className="flex justify-between text-xs text-muted-foreground">
                    <span>Performance</span>
                    <span>{Math.round(getCompliancePercentage(metric.target, metric.current))}%</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div 
                      className={`h-2 rounded-full ${
                        metric.status === 'good' ? 'bg-green-500' :
                        metric.status === 'warning' ? 'bg-yellow-500' : 'bg-red-500'
                      }`}
                      style={{ 
                        width: `${Math.min(getCompliancePercentage(metric.target, metric.current), 100)}%` 
                      }}
                    />
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Detailed Analysis */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* SLA Compliance Overview */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Target className="h-4 w-4" />
              SLA Compliance Overview
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-3 rounded-lg bg-green-50 border border-green-200">
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-4 w-4 text-green-600" />
                  <span className="text-sm font-medium">Met SLA Targets</span>
                </div>
                <span className="text-sm font-bold text-green-600">4/6 metrics</span>
              </div>
              
              <div className="flex items-center justify-between p-3 rounded-lg bg-yellow-50 border border-yellow-200">
                <div className="flex items-center gap-2">
                  <Clock className="h-4 w-4 text-yellow-600" />
                  <span className="text-sm font-medium">At Risk</span>
                </div>
                <span className="text-sm font-bold text-yellow-600">1 metric</span>
              </div>
              
              <div className="flex items-center justify-between p-3 rounded-lg bg-red-50 border border-red-200">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-red-600" />
                  <span className="text-sm font-medium">Missing SLA</span>
                </div>
                <span className="text-sm font-bold text-red-600">1 metric</span>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Recent Incidents Impact */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Calendar className="h-4 w-4" />
              Recent Incidents Impact
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between p-2 border rounded">
                <div>
                  <div className="text-sm font-medium">INC-2023-001</div>
                  <div className="text-xs text-muted-foreground">Phishing Attack</div>
                </div>
                <div className="text-right">
                  <div className="text-sm font-medium">4.2h resolution</div>
                  <Badge variant="default" className="text-xs">Within SLA</Badge>
                </div>
              </div>
              
              <div className="flex items-center justify-between p-2 border rounded">
                <div>
                  <div className="text-sm font-medium">INC-2023-002</div>
                  <div className="text-xs text-muted-foreground">Malware Detection</div>
                </div>
                <div className="text-right">
                  <div className="text-sm font-medium">26.8h resolution</div>
                  <Badge variant="destructive" className="text-xs">SLA Breach</Badge>
                </div>
              </div>
              
              <div className="flex items-center justify-between p-2 border rounded">
                <div>
                  <div className="text-sm font-medium">INC-2023-003</div>
                  <div className="text-xs text-muted-foreground">Data Exfiltration</div>
                </div>
                <div className="text-right">
                  <div className="text-sm font-medium">18.5h resolution</div>
                  <Badge variant="default" className="text-xs">Within SLA</Badge>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Improvement Recommendations */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Performance Improvement Recommendations</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-3">
              <h4 className="font-medium text-sm text-red-600">Critical Issues</h4>
              <div className="space-y-2">
                <div className="p-3 border border-red-200 rounded-lg bg-red-50">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                    <div>
                      <div className="text-sm font-medium">High Dwell Time</div>
                      <div className="text-xs text-muted-foreground">
                        Average dwell time (72h) exceeds target (48h). Consider implementing behavioral analytics for faster detection.
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            
            <div className="space-y-3">
              <h4 className="font-medium text-sm text-yellow-600">Areas for Improvement</h4>
              <div className="space-y-2">
                <div className="p-3 border border-yellow-200 rounded-lg bg-yellow-50">
                  <div className="flex items-start gap-2">
                    <Clock className="h-4 w-4 text-yellow-500 mt-0.5" />
                    <div>
                      <div className="text-sm font-medium">Containment Time</div>
                      <div className="text-xs text-muted-foreground">
                        MTTC trending upward. Review automated containment procedures and staff training.
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="p-3 border border-yellow-200 rounded-lg bg-yellow-50">
                  <div className="flex items-start gap-2">
                    <Target className="h-4 w-4 text-yellow-500 mt-0.5" />
                    <div>
                      <div className="text-sm font-medium">SLA Compliance</div>
                      <div className="text-xs text-muted-foreground">
                        Overall compliance at 94.5%, just below 95% target. Focus on process optimization.
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
