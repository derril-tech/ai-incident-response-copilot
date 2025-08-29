'use client'

import React, { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Slider } from '@/components/ui/slider'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { 
  Play, 
  Pause, 
  SkipBack, 
  SkipForward, 
  ZoomIn, 
  ZoomOut, 
  Filter,
  AlertTriangle,
  Clock,
  Activity
} from 'lucide-react'

interface TimelineEvent {
  id: string
  timestamp: string
  type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  title: string
  description: string
  source: string
  entities: string[]
  metadata?: Record<string, any>
}

interface TimelinePhase {
  name: string
  start_time: string
  end_time: string
  severity: string
  events: TimelineEvent[]
}

interface TimelineData {
  incident_id: string
  events: TimelineEvent[]
  phases: TimelinePhase[]
  anomalies: any[]
  total_events: number
}

interface TimelineViewerProps {
  incidentId: string
  data?: TimelineData
}

export function TimelineViewer({ incidentId, data }: TimelineViewerProps) {
  const [isPlaying, setIsPlaying] = useState(false)
  const [currentTime, setCurrentTime] = useState(0)
  const [zoomLevel, setZoomLevel] = useState(1)
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null)
  const [filterSeverity, setFilterSeverity] = useState<string[]>(['low', 'medium', 'high', 'critical'])
  const [timelineData, setTimelineData] = useState<TimelineData | null>(data || null)

  useEffect(() => {
    if (!data) {
      // Fetch timeline data
      fetchTimelineData()
    }
  }, [incidentId, data])

  const fetchTimelineData = async () => {
    try {
      // Simulate API call
      const mockData: TimelineData = {
        incident_id: incidentId,
        total_events: 25,
        events: [
          {
            id: 'evt_1',
            timestamp: '2023-12-01T10:00:00Z',
            type: 'alert',
            severity: 'high',
            title: 'Suspicious Process Execution',
            description: 'PowerShell process executed with encoded command',
            source: 'EDR',
            entities: ['WS-001', 'user123', 'powershell.exe']
          },
          {
            id: 'evt_2', 
            timestamp: '2023-12-01T10:15:00Z',
            type: 'network',
            severity: 'critical',
            title: 'Outbound Connection to Suspicious IP',
            description: 'Connection established to known malicious IP address',
            source: 'Firewall',
            entities: ['WS-001', '185.159.158.177']
          },
          {
            id: 'evt_3',
            timestamp: '2023-12-01T10:30:00Z',
            type: 'file',
            severity: 'high',
            title: 'Malicious File Detected',
            description: 'File with suspicious hash detected on system',
            source: 'Antivirus',
            entities: ['WS-001', 'malware.exe']
          }
        ],
        phases: [
          {
            name: 'Initial Detection',
            start_time: '2023-12-01T10:00:00Z',
            end_time: '2023-12-01T10:30:00Z',
            severity: 'high',
            events: []
          },
          {
            name: 'Investigation',
            start_time: '2023-12-01T10:30:00Z', 
            end_time: '2023-12-01T12:00:00Z',
            severity: 'medium',
            events: []
          }
        ],
        anomalies: [
          {
            type: 'volume_spike',
            description: 'Unusual event volume detected',
            timestamp: '2023-12-01T10:15:00Z'
          }
        ]
      }
      setTimelineData(mockData)
    } catch (error) {
      console.error('Failed to fetch timeline data:', error)
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500'
      case 'high': return 'bg-orange-500'
      case 'medium': return 'bg-yellow-500'
      case 'low': return 'bg-blue-500'
      default: return 'bg-gray-500'
    }
  }

  const getSeverityBadgeVariant = (severity: string) => {
    switch (severity) {
      case 'critical': return 'destructive'
      case 'high': return 'destructive'
      case 'medium': return 'default'
      case 'low': return 'secondary'
      default: return 'outline'
    }
  }

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString()
  }

  const filteredEvents = timelineData?.events.filter(event => 
    filterSeverity.includes(event.severity)
  ) || []

  if (!timelineData) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Timeline Viewer</CardTitle>
          <CardDescription>Loading timeline data...</CardDescription>
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
      {/* Timeline Controls */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Timeline Viewer - Incident {incidentId}
          </CardTitle>
          <CardDescription>
            Interactive timeline with {timelineData.total_events} events across {timelineData.phases.length} phases
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setIsPlaying(!isPlaying)}
              >
                {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
              </Button>
              <Button variant="outline" size="sm">
                <SkipBack className="h-4 w-4" />
              </Button>
              <Button variant="outline" size="sm">
                <SkipForward className="h-4 w-4" />
              </Button>
              <Separator orientation="vertical" className="h-6" />
              <Button variant="outline" size="sm" onClick={() => setZoomLevel(Math.max(0.5, zoomLevel - 0.5))}>
                <ZoomOut className="h-4 w-4" />
              </Button>
              <span className="text-sm text-muted-foreground">{Math.round(zoomLevel * 100)}%</span>
              <Button variant="outline" size="sm" onClick={() => setZoomLevel(Math.min(3, zoomLevel + 0.5))}>
                <ZoomIn className="h-4 w-4" />
              </Button>
            </div>
            
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4" />
              <span className="text-sm text-muted-foreground">Filter:</span>
              {['critical', 'high', 'medium', 'low'].map(severity => (
                <Badge
                  key={severity}
                  variant={filterSeverity.includes(severity) ? getSeverityBadgeVariant(severity) : 'outline'}
                  className="cursor-pointer"
                  onClick={() => {
                    if (filterSeverity.includes(severity)) {
                      setFilterSeverity(filterSeverity.filter(s => s !== severity))
                    } else {
                      setFilterSeverity([...filterSeverity, severity])
                    }
                  }}
                >
                  {severity}
                </Badge>
              ))}
            </div>
          </div>

          {/* Timeline Scrubber */}
          <div className="mb-6">
            <Slider
              value={[currentTime]}
              onValueChange={(value) => setCurrentTime(value[0])}
              max={100}
              step={1}
              className="w-full"
            />
            <div className="flex justify-between text-xs text-muted-foreground mt-1">
              <span>Start</span>
              <span>Current: {currentTime}%</span>
              <span>End</span>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline Events */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Event Timeline</CardTitle>
              <CardDescription>
                {filteredEvents.length} events shown (filtered by severity)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-96">
                <div className="space-y-4">
                  {filteredEvents.map((event, index) => (
                    <div
                      key={event.id}
                      className={`flex items-start gap-4 p-4 rounded-lg border cursor-pointer transition-colors ${
                        selectedEvent?.id === event.id ? 'bg-accent' : 'hover:bg-muted/50'
                      }`}
                      onClick={() => setSelectedEvent(event)}
                    >
                      <div className="flex flex-col items-center">
                        <div className={`w-3 h-3 rounded-full ${getSeverityColor(event.severity)}`} />
                        {index < filteredEvents.length - 1 && (
                          <div className="w-px h-8 bg-border mt-2" />
                        )}
                      </div>
                      
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge variant={getSeverityBadgeVariant(event.severity)}>
                            {event.severity}
                          </Badge>
                          <Badge variant="outline">{event.type}</Badge>
                          <span className="text-xs text-muted-foreground">
                            {formatTimestamp(event.timestamp)}
                          </span>
                        </div>
                        
                        <h4 className="font-medium text-sm mb-1">{event.title}</h4>
                        <p className="text-xs text-muted-foreground mb-2">{event.description}</p>
                        
                        <div className="flex items-center gap-1 flex-wrap">
                          <span className="text-xs text-muted-foreground">Entities:</span>
                          {event.entities.map(entity => (
                            <Badge key={entity} variant="secondary" className="text-xs">
                              {entity}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </div>

        {/* Event Details & Phases */}
        <div className="space-y-6">
          {/* Selected Event Details */}
          {selectedEvent && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Event Details</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <label className="text-sm font-medium">Title</label>
                  <p className="text-sm text-muted-foreground">{selectedEvent.title}</p>
                </div>
                
                <div>
                  <label className="text-sm font-medium">Description</label>
                  <p className="text-sm text-muted-foreground">{selectedEvent.description}</p>
                </div>
                
                <div>
                  <label className="text-sm font-medium">Source</label>
                  <p className="text-sm text-muted-foreground">{selectedEvent.source}</p>
                </div>
                
                <div>
                  <label className="text-sm font-medium">Timestamp</label>
                  <p className="text-sm text-muted-foreground">
                    {formatTimestamp(selectedEvent.timestamp)}
                  </p>
                </div>
                
                <div>
                  <label className="text-sm font-medium">Severity</label>
                  <Badge variant={getSeverityBadgeVariant(selectedEvent.severity)}>
                    {selectedEvent.severity}
                  </Badge>
                </div>
                
                <div>
                  <label className="text-sm font-medium">Entities</label>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {selectedEvent.entities.map(entity => (
                      <Badge key={entity} variant="secondary" className="text-xs">
                        {entity}
                      </Badge>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Incident Phases */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Clock className="h-4 w-4" />
                Incident Phases
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {timelineData.phases.map((phase, index) => (
                  <div key={index} className="p-3 rounded-lg border">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-medium text-sm">{phase.name}</h4>
                      <Badge variant={getSeverityBadgeVariant(phase.severity)}>
                        {phase.severity}
                      </Badge>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      <div>{formatTimestamp(phase.start_time)}</div>
                      <div>to {formatTimestamp(phase.end_time)}</div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Anomalies */}
          {timelineData.anomalies.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4" />
                  Anomalies Detected
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {timelineData.anomalies.map((anomaly, index) => (
                    <div key={index} className="p-2 rounded bg-yellow-50 border border-yellow-200">
                      <p className="text-sm font-medium">{anomaly.type}</p>
                      <p className="text-xs text-muted-foreground">{anomaly.description}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
