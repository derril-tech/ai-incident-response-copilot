'use client'

import React, { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { 
  FileText, 
  Edit3, 
  MessageSquare, 
  CheckCircle, 
  Clock, 
  User, 
  Download,
  Send,
  Save,
  Eye,
  AlertCircle
} from 'lucide-react'

interface Comment {
  id: string
  author: string
  content: string
  timestamp: string
  resolved: boolean
  section?: string
}

interface ReportSection {
  id: string
  title: string
  content: string
  status: 'draft' | 'review' | 'approved'
  comments: Comment[]
  lastModified: string
  author: string
}

interface Report {
  id: string
  incident_id: string
  title: string
  status: 'draft' | 'review' | 'approved' | 'published'
  created_at: string
  updated_at: string
  sections: ReportSection[]
  metadata: {
    generator: string
    quality_score: number
    review_status: string
  }
}

interface ReportEditorProps {
  reportId: string
  incidentId: string
  report?: Report
}

export function ReportEditor({ reportId, incidentId, report }: ReportEditorProps) {
  const [reportData, setReportData] = useState<Report | null>(report || null)
  const [selectedSection, setSelectedSection] = useState<string | null>(null)
  const [editMode, setEditMode] = useState(false)
  const [newComment, setNewComment] = useState('')
  const [showComments, setShowComments] = useState(true)

  useEffect(() => {
    if (!report) {
      fetchReport()
    }
  }, [reportId, report])

  const fetchReport = async () => {
    try {
      // Simulate API call
      const mockReport: Report = {
        id: reportId,
        incident_id: incidentId,
        title: `Incident Response Report - ${incidentId}`,
        status: 'review',
        created_at: '2023-12-01T14:00:00Z',
        updated_at: '2023-12-01T16:30:00Z',
        metadata: {
          generator: 'CrewAI Multi-Agent System',
          quality_score: 9.2,
          review_status: 'approved'
        },
        sections: [
          {
            id: 'executive_summary',
            title: 'Executive Summary',
            status: 'approved',
            author: 'AI Security Writer',
            lastModified: '2023-12-01T15:00:00Z',
            content: `## Executive Summary

A sophisticated cyber attack was detected and contained within 4 hours on December 1st, 2023. The attacker gained initial access through a spear-phishing email and attempted to exfiltrate sensitive customer data.

### Key Findings:
- Initial access via malicious Excel attachment
- Lateral movement achieved within 30 minutes
- Data exfiltration attempt blocked by DLP controls
- 15 systems affected, ~10,000 customer records at risk

### Business Impact:
- **Severity**: High
- **Estimated Cost**: $250,000 - $500,000
- **Regulatory Impact**: Potential GDPR/CCPA notifications required

### Immediate Actions Taken:
- Systems isolated within 1 hour of detection
- Malicious IPs and domains blocked
- Compromised credentials reset
- External incident response team engaged`,
            comments: [
              {
                id: 'c1',
                author: 'Security Manager',
                content: 'Please add more details about the regulatory timeline requirements.',
                timestamp: '2023-12-01T15:30:00Z',
                resolved: false,
                section: 'executive_summary'
              }
            ]
          },
          {
            id: 'timeline_analysis',
            title: 'Incident Timeline',
            status: 'review',
            author: 'AI Timeline Analyst',
            lastModified: '2023-12-01T15:15:00Z',
            content: `## Incident Timeline

### Phase 1: Initial Compromise (10:00 - 10:30 UTC)
- **10:00**: Spear-phishing email delivered to user@company.com
- **10:05**: User opened malicious Excel attachment
- **10:07**: Macro execution triggered PowerShell download
- **10:10**: First-stage payload executed
- **10:15**: C2 communication established to 185.159.158.177

### Phase 2: Lateral Movement (10:30 - 12:00 UTC)
- **10:30**: Credential harvesting initiated
- **10:45**: Domain controller access attempted
- **11:00**: File server enumeration detected
- **11:30**: Additional workstation compromise

### Phase 3: Data Access (12:00 - 14:00 UTC)
- **12:00**: Customer database access detected
- **12:30**: Data staging for exfiltration
- **13:00**: DLP alert triggered
- **13:15**: Incident response initiated
- **14:00**: Systems contained and isolated`,
            comments: [
              {
                id: 'c2',
                author: 'Forensic Analyst',
                content: 'Timeline looks accurate. Consider adding network flow details.',
                timestamp: '2023-12-01T15:45:00Z',
                resolved: true,
                section: 'timeline_analysis'
              }
            ]
          },
          {
            id: 'technical_analysis',
            title: 'Technical Analysis',
            status: 'draft',
            author: 'AI Forensic Expert',
            lastModified: '2023-12-01T16:00:00Z',
            content: `## Technical Analysis

### Attack Vector
- **Initial Access**: Spear-phishing with malicious Excel attachment
- **Exploit**: CVE-2023-1234 (Office macro execution)
- **Payload**: Multi-stage PowerShell script

### Indicators of Compromise (IOCs)
- **File Hash**: a1b2c3d4e5f6789...
- **IP Address**: 185.159.158.177
- **Domain**: malicious-domain.com
- **Registry Key**: HKEY_CURRENT_USER\\Software\\Microsoft\\...

### MITRE ATT&CK Techniques
- **T1566.001**: Spearphishing Attachment
- **T1059.001**: PowerShell
- **T1071.001**: Web Protocols (C2)
- **T1083**: File and Directory Discovery

### Network Analysis
- Outbound HTTPS connections to C2 infrastructure
- DNS queries to suspicious domains
- Data staging in temp directories`,
            comments: []
          },
          {
            id: 'recommendations',
            title: 'Recommendations',
            status: 'draft',
            author: 'AI Security Writer',
            lastModified: '2023-12-01T16:30:00Z',
            content: `## Recommendations

### Immediate Actions (0-48 hours)
1. **Patch CVE-2023-1234** across all Office installations
2. **Implement PowerShell restrictions** on all workstations
3. **Deploy additional email security** controls

### Short-term Improvements (1-3 months)
1. **Behavioral analysis** for PowerShell execution
2. **Application whitelisting** on critical systems
3. **Automated incident response** playbooks

### Long-term Strategy (3-12 months)
1. **Zero Trust architecture** implementation
2. **Advanced threat hunting** capabilities
3. **Threat intelligence** program establishment`,
            comments: [
              {
                id: 'c3',
                author: 'CISO',
                content: 'Add budget estimates for each recommendation.',
                timestamp: '2023-12-01T16:45:00Z',
                resolved: false,
                section: 'recommendations'
              }
            ]
          }
        ]
      }
      setReportData(mockReport)
      setSelectedSection(mockReport.sections[0].id)
    } catch (error) {
      console.error('Failed to fetch report:', error)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'draft': return 'bg-yellow-500'
      case 'review': return 'bg-blue-500'
      case 'approved': return 'bg-green-500'
      case 'published': return 'bg-purple-500'
      default: return 'bg-gray-500'
    }
  }

  const getStatusVariant = (status: string) => {
    switch (status) {
      case 'draft': return 'default'
      case 'review': return 'default'
      case 'approved': return 'default'
      case 'published': return 'secondary'
      default: return 'outline'
    }
  }

  const selectedSectionData = reportData?.sections.find(s => s.id === selectedSection)
  const unresolvedComments = reportData?.sections.flatMap(s => s.comments.filter(c => !c.resolved)) || []

  if (!reportData) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Report Editor</CardTitle>
          <CardDescription>Loading report...</CardDescription>
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
      {/* Report Header */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <FileText className="h-5 w-5" />
                {reportData.title}
              </CardTitle>
              <CardDescription>
                Report ID: {reportData.id} | Incident: {reportData.incident_id}
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant={getStatusVariant(reportData.status)}>
                {reportData.status}
              </Badge>
              <Badge variant="outline">
                Quality Score: {reportData.metadata.quality_score}/10
              </Badge>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4 text-sm text-muted-foreground">
              <span>Created: {new Date(reportData.created_at).toLocaleString()}</span>
              <span>Updated: {new Date(reportData.updated_at).toLocaleString()}</span>
              <span>Generator: {reportData.metadata.generator}</span>
            </div>
            
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm">
                <Eye className="h-4 w-4 mr-2" />
                Preview
              </Button>
              <Button variant="outline" size="sm">
                <Download className="h-4 w-4 mr-2" />
                Export
              </Button>
              <Button variant="outline" size="sm">
                <Send className="h-4 w-4 mr-2" />
                Submit for Review
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Section Navigation */}
        <div>
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Report Sections</CardTitle>
              {unresolvedComments.length > 0 && (
                <Badge variant="destructive" className="w-fit">
                  {unresolvedComments.length} unresolved comments
                </Badge>
              )}
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {reportData.sections.map((section) => (
                  <Button
                    key={section.id}
                    variant={selectedSection === section.id ? "default" : "ghost"}
                    className="w-full justify-start h-auto p-3"
                    onClick={() => setSelectedSection(section.id)}
                  >
                    <div className="flex items-center justify-between w-full">
                      <div className="text-left">
                        <div className="font-medium text-sm">{section.title}</div>
                        <div className="text-xs text-muted-foreground">
                          by {section.author}
                        </div>
                      </div>
                      <div className="flex flex-col items-end gap-1">
                        <Badge variant={getStatusVariant(section.status)} className="text-xs">
                          {section.status}
                        </Badge>
                        {section.comments.filter(c => !c.resolved).length > 0 && (
                          <Badge variant="destructive" className="text-xs">
                            {section.comments.filter(c => !c.resolved).length}
                          </Badge>
                        )}
                      </div>
                    </div>
                  </Button>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Content Editor */}
        <div className="lg:col-span-2">
          {selectedSectionData && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-base">{selectedSectionData.title}</CardTitle>
                    <CardDescription>
                      Last modified: {new Date(selectedSectionData.lastModified).toLocaleString()}
                    </CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={getStatusVariant(selectedSectionData.status)}>
                      {selectedSectionData.status}
                    </Badge>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setEditMode(!editMode)}
                    >
                      <Edit3 className="h-4 w-4 mr-2" />
                      {editMode ? 'View' : 'Edit'}
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                {editMode ? (
                  <div className="space-y-4">
                    <textarea
                      className="w-full h-96 p-3 border rounded-md font-mono text-sm"
                      value={selectedSectionData.content}
                      onChange={(e) => {
                        // Update content logic here
                      }}
                    />
                    <div className="flex items-center gap-2">
                      <Button size="sm">
                        <Save className="h-4 w-4 mr-2" />
                        Save Changes
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => setEditMode(false)}>
                        Cancel
                      </Button>
                    </div>
                  </div>
                ) : (
                  <ScrollArea className="h-96">
                    <div className="prose prose-sm max-w-none">
                      <pre className="whitespace-pre-wrap text-sm">
                        {selectedSectionData.content}
                      </pre>
                    </div>
                  </ScrollArea>
                )}
              </CardContent>
            </Card>
          )}
        </div>

        {/* Comments Panel */}
        <div>
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <MessageSquare className="h-4 w-4" />
                Comments
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowComments(!showComments)}
                >
                  {showComments ? 'Hide' : 'Show'}
                </Button>
              </CardTitle>
            </CardHeader>
            {showComments && (
              <CardContent>
                <ScrollArea className="h-64">
                  <div className="space-y-3">
                    {selectedSectionData?.comments.map((comment) => (
                      <div
                        key={comment.id}
                        className={`p-3 rounded-lg border ${
                          comment.resolved ? 'bg-green-50 border-green-200' : 'bg-yellow-50 border-yellow-200'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <User className="h-3 w-3" />
                            <span className="text-xs font-medium">{comment.author}</span>
                          </div>
                          {comment.resolved ? (
                            <CheckCircle className="h-3 w-3 text-green-500" />
                          ) : (
                            <AlertCircle className="h-3 w-3 text-yellow-500" />
                          )}
                        </div>
                        <p className="text-xs text-muted-foreground mb-2">{comment.content}</p>
                        <div className="flex items-center justify-between">
                          <span className="text-xs text-muted-foreground">
                            {new Date(comment.timestamp).toLocaleString()}
                          </span>
                          {!comment.resolved && (
                            <Button variant="outline" size="sm" className="text-xs h-6">
                              Resolve
                            </Button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
                
                <Separator className="my-4" />
                
                <div className="space-y-2">
                  <textarea
                    className="w-full p-2 border rounded text-sm"
                    placeholder="Add a comment..."
                    rows={3}
                    value={newComment}
                    onChange={(e) => setNewComment(e.target.value)}
                  />
                  <Button size="sm" className="w-full">
                    <MessageSquare className="h-4 w-4 mr-2" />
                    Add Comment
                  </Button>
                </div>
              </CardContent>
            )}
          </Card>
        </div>
      </div>
    </div>
  )
}
