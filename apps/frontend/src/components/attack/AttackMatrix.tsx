'use client'

import React, { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { 
  Shield, 
  Target, 
  Eye, 
  Zap, 
  Lock, 
  Network, 
  Database, 
  AlertTriangle,
  CheckCircle,
  XCircle
} from 'lucide-react'

interface AttackTechnique {
  id: string
  name: string
  tactic: string
  description: string
  detected: boolean
  confidence: number
  evidence?: string[]
  mitigations?: string[]
}

interface AttackMatrixProps {
  incidentId: string
  techniques?: AttackTechnique[]
}

const MITRE_TACTICS = [
  { id: 'initial-access', name: 'Initial Access', icon: Target, color: 'bg-red-500' },
  { id: 'execution', name: 'Execution', icon: Zap, color: 'bg-orange-500' },
  { id: 'persistence', name: 'Persistence', icon: Lock, color: 'bg-yellow-500' },
  { id: 'privilege-escalation', name: 'Privilege Escalation', icon: Shield, color: 'bg-green-500' },
  { id: 'defense-evasion', name: 'Defense Evasion', icon: Eye, color: 'bg-blue-500' },
  { id: 'credential-access', name: 'Credential Access', icon: Lock, color: 'bg-indigo-500' },
  { id: 'discovery', name: 'Discovery', icon: Eye, color: 'bg-purple-500' },
  { id: 'lateral-movement', name: 'Lateral Movement', icon: Network, color: 'bg-pink-500' },
  { id: 'collection', name: 'Collection', icon: Database, color: 'bg-cyan-500' },
  { id: 'command-and-control', name: 'Command and Control', icon: Network, color: 'bg-teal-500' },
  { id: 'exfiltration', name: 'Exfiltration', icon: Database, color: 'bg-emerald-500' },
  { id: 'impact', name: 'Impact', icon: AlertTriangle, color: 'bg-red-600' }
]

export function AttackMatrix({ incidentId, techniques = [] }: AttackMatrixProps) {
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null)
  const [selectedTechnique, setSelectedTechnique] = useState<AttackTechnique | null>(null)

  // Mock data if no techniques provided
  const mockTechniques: AttackTechnique[] = [
    {
      id: 'T1566.001',
      name: 'Spearphishing Attachment',
      tactic: 'initial-access',
      description: 'Adversaries may send spearphishing emails with a malicious attachment',
      detected: true,
      confidence: 0.9,
      evidence: ['Malicious Excel file detected', 'Macro execution observed'],
      mitigations: ['Email security controls', 'User awareness training']
    },
    {
      id: 'T1059.001',
      name: 'PowerShell',
      tactic: 'execution',
      description: 'Adversaries may abuse PowerShell commands and scripts',
      detected: true,
      confidence: 0.95,
      evidence: ['Encoded PowerShell command execution', 'Suspicious script behavior'],
      mitigations: ['PowerShell logging', 'Execution policy restrictions']
    },
    {
      id: 'T1055',
      name: 'Process Injection',
      tactic: 'defense-evasion',
      description: 'Adversaries may inject code into processes',
      detected: false,
      confidence: 0.3,
      evidence: [],
      mitigations: ['Process monitoring', 'Behavioral analysis']
    },
    {
      id: 'T1071.001',
      name: 'Web Protocols',
      tactic: 'command-and-control',
      description: 'Adversaries may communicate using application layer protocols',
      detected: true,
      confidence: 0.8,
      evidence: ['HTTPS C2 communication', 'Suspicious domain connections'],
      mitigations: ['Network monitoring', 'Domain blocking']
    }
  ]

  const displayTechniques = techniques.length > 0 ? techniques : mockTechniques

  const getTechniquesByTactic = (tacticId: string) => {
    return displayTechniques.filter(technique => technique.tactic === tacticId)
  }

  const getDetectionStats = () => {
    const detected = displayTechniques.filter(t => t.detected).length
    const total = displayTechniques.length
    return { detected, total, coverage: total > 0 ? (detected / total) * 100 : 0 }
  }

  const stats = getDetectionStats()

  return (
    <div className="space-y-6">
      {/* Header with Stats */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            MITRE ATT&CK Matrix - Incident {incidentId}
          </CardTitle>
          <CardDescription>
            Attack technique coverage and detection analysis
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">{stats.detected}</div>
              <div className="text-sm text-muted-foreground">Techniques Detected</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold">{stats.total}</div>
              <div className="text-sm text-muted-foreground">Total Techniques</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">{Math.round(stats.coverage)}%</div>
              <div className="text-sm text-muted-foreground">Detection Coverage</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-600">
                {MITRE_TACTICS.filter(tactic => getTechniquesByTactic(tactic.id).some(t => t.detected)).length}
              </div>
              <div className="text-sm text-muted-foreground">Tactics Observed</div>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Tactics Grid */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Attack Tactics</CardTitle>
              <CardDescription>
                Click on a tactic to view associated techniques
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                {MITRE_TACTICS.map((tactic) => {
                  const tacticTechniques = getTechniquesByTactic(tactic.id)
                  const detectedCount = tacticTechniques.filter(t => t.detected).length
                  const totalCount = tacticTechniques.length
                  const hasDetections = detectedCount > 0
                  
                  const IconComponent = tactic.icon
                  
                  return (
                    <Button
                      key={tactic.id}
                      variant={selectedTactic === tactic.id ? "default" : "outline"}
                      className={`h-auto p-4 flex flex-col items-center gap-2 relative ${
                        hasDetections ? 'border-red-500 bg-red-50 hover:bg-red-100' : ''
                      }`}
                      onClick={() => setSelectedTactic(selectedTactic === tactic.id ? null : tactic.id)}
                    >
                      <IconComponent className="h-6 w-6" />
                      <div className="text-xs font-medium text-center leading-tight">
                        {tactic.name}
                      </div>
                      {totalCount > 0 && (
                        <Badge 
                          variant={hasDetections ? "destructive" : "secondary"}
                          className="text-xs"
                        >
                          {detectedCount}/{totalCount}
                        </Badge>
                      )}
                      {hasDetections && (
                        <div className="absolute -top-1 -right-1">
                          <AlertTriangle className="h-4 w-4 text-red-500" />
                        </div>
                      )}
                    </Button>
                  )
                })}
              </div>
            </CardContent>
          </Card>

          {/* Techniques for Selected Tactic */}
          {selectedTactic && (
            <Card className="mt-6">
              <CardHeader>
                <CardTitle>
                  {MITRE_TACTICS.find(t => t.id === selectedTactic)?.name} Techniques
                </CardTitle>
                <CardDescription>
                  Techniques observed in this tactic category
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-64">
                  <div className="space-y-3">
                    {getTechniquesByTactic(selectedTactic).map((technique) => (
                      <div
                        key={technique.id}
                        className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                          selectedTechnique?.id === technique.id ? 'bg-accent' : 'hover:bg-muted/50'
                        }`}
                        onClick={() => setSelectedTechnique(technique)}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="text-xs">
                              {technique.id}
                            </Badge>
                            {technique.detected ? (
                              <CheckCircle className="h-4 w-4 text-green-500" />
                            ) : (
                              <XCircle className="h-4 w-4 text-gray-400" />
                            )}
                          </div>
                          <Badge variant={technique.detected ? "destructive" : "secondary"}>
                            {Math.round(technique.confidence * 100)}% confidence
                          </Badge>
                        </div>
                        
                        <h4 className="font-medium text-sm mb-1">{technique.name}</h4>
                        <p className="text-xs text-muted-foreground">{technique.description}</p>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Technique Details */}
        <div>
          {selectedTechnique ? (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Technique Details</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="text-sm font-medium">Technique ID</label>
                  <p className="text-sm text-muted-foreground">{selectedTechnique.id}</p>
                </div>
                
                <div>
                  <label className="text-sm font-medium">Name</label>
                  <p className="text-sm text-muted-foreground">{selectedTechnique.name}</p>
                </div>
                
                <div>
                  <label className="text-sm font-medium">Tactic</label>
                  <Badge variant="outline" className="ml-2">
                    {MITRE_TACTICS.find(t => t.id === selectedTechnique.tactic)?.name}
                  </Badge>
                </div>
                
                <div>
                  <label className="text-sm font-medium">Description</label>
                  <p className="text-sm text-muted-foreground">{selectedTechnique.description}</p>
                </div>
                
                <div>
                  <label className="text-sm font-medium">Detection Status</label>
                  <div className="flex items-center gap-2 mt-1">
                    {selectedTechnique.detected ? (
                      <>
                        <CheckCircle className="h-4 w-4 text-green-500" />
                        <span className="text-sm text-green-600">Detected</span>
                      </>
                    ) : (
                      <>
                        <XCircle className="h-4 w-4 text-gray-400" />
                        <span className="text-sm text-muted-foreground">Not Detected</span>
                      </>
                    )}
                  </div>
                </div>
                
                <div>
                  <label className="text-sm font-medium">Confidence</label>
                  <div className="flex items-center gap-2 mt-1">
                    <div className="flex-1 bg-gray-200 rounded-full h-2">
                      <div 
                        className="bg-blue-500 h-2 rounded-full" 
                        style={{ width: `${selectedTechnique.confidence * 100}%` }}
                      />
                    </div>
                    <span className="text-sm text-muted-foreground">
                      {Math.round(selectedTechnique.confidence * 100)}%
                    </span>
                  </div>
                </div>
                
                {selectedTechnique.evidence && selectedTechnique.evidence.length > 0 && (
                  <div>
                    <label className="text-sm font-medium">Evidence</label>
                    <ul className="mt-1 space-y-1">
                      {selectedTechnique.evidence.map((evidence, index) => (
                        <li key={index} className="text-xs text-muted-foreground flex items-start gap-1">
                          <span className="text-green-500">•</span>
                          {evidence}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                
                {selectedTechnique.mitigations && selectedTechnique.mitigations.length > 0 && (
                  <div>
                    <label className="text-sm font-medium">Recommended Mitigations</label>
                    <ul className="mt-1 space-y-1">
                      {selectedTechnique.mitigations.map((mitigation, index) => (
                        <li key={index} className="text-xs text-muted-foreground flex items-start gap-1">
                          <span className="text-blue-500">•</span>
                          {mitigation}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Technique Details</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground text-center py-8">
                  Select a technique to view detailed information
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
