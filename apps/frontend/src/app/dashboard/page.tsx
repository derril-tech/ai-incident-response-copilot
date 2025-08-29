import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { 
  Shield, 
  AlertTriangle, 
  Clock, 
  CheckCircle, 
  TrendingUp, 
  Users, 
  FileText, 
  Activity,
  Target,
  Zap
} from 'lucide-react'

export default function DashboardPage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-white mb-2">
            AI Incident Response Copilot
          </h1>
          <p className="text-slate-300">
            Comprehensive incident response automation with CrewAI multi-agent orchestration
          </p>
        </div>

        {/* Key Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium text-slate-200">Active Incidents</CardTitle>
                <AlertTriangle className="h-4 w-4 text-red-400" />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">7</div>
              <div className="flex items-center gap-2 mt-2">
                <Badge variant="destructive" className="text-xs">3 Critical</Badge>
                <Badge variant="default" className="text-xs">4 High</Badge>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium text-slate-200">MTTD</CardTitle>
                <Clock className="h-4 w-4 text-blue-400" />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">18m</div>
              <div className="flex items-center gap-1 mt-2">
                <TrendingUp className="h-3 w-3 text-green-400" />
                <span className="text-xs text-green-400">12% improvement</span>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium text-slate-200">SLA Compliance</CardTitle>
                <Target className="h-4 w-4 text-green-400" />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">94.5%</div>
              <div className="text-xs text-slate-400 mt-2">Target: 95%</div>
            </CardContent>
          </Card>

          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium text-slate-200">Reports Generated</CardTitle>
                <FileText className="h-4 w-4 text-purple-400" />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-white">23</div>
              <div className="text-xs text-slate-400 mt-2">This month</div>
            </CardContent>
          </Card>
        </div>

        {/* Main Features Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
          {/* Timeline Analysis */}
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Activity className="h-5 w-5" />
                Timeline Analysis
              </CardTitle>
              <CardDescription className="text-slate-300">
                AI-powered event correlation and timeline reconstruction
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-slate-300">Events Correlated</span>
                  <span className="text-white font-medium">1,247</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-slate-300">Anomalies Detected</span>
                  <span className="text-white font-medium">12</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-slate-300">Entity Links</span>
                  <span className="text-white font-medium">89</span>
                </div>
              </div>
              <Button className="w-full bg-blue-600 hover:bg-blue-700">
                View Timeline
              </Button>
            </CardContent>
          </Card>

          {/* Forensic Analysis */}
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Shield className="h-5 w-5" />
                Forensic Analysis
              </CardTitle>
              <CardDescription className="text-slate-300">
                IOC detection, ATT&CK mapping, and threat analysis
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-slate-300">IOCs Identified</span>
                  <span className="text-white font-medium">34</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-slate-300">ATT&CK Techniques</span>
                  <span className="text-white font-medium">8</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-slate-300">Risk Score</span>
                  <span className="text-red-400 font-medium">7.5/10</span>
                </div>
              </div>
              <Button className="w-full bg-red-600 hover:bg-red-700">
                View Analysis
              </Button>
            </CardContent>
          </Card>

          {/* Report Generation */}
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <FileText className="h-5 w-5" />
                AI Report Generation
              </CardTitle>
              <CardDescription className="text-slate-300">
                CrewAI multi-agent report drafting and review
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-slate-300">Draft Reports</span>
                  <span className="text-white font-medium">5</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-slate-300">Under Review</span>
                  <span className="text-white font-medium">3</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-slate-300">Quality Score</span>
                  <span className="text-green-400 font-medium">9.2/10</span>
                </div>
              </div>
              <Button className="w-full bg-purple-600 hover:bg-purple-700">
                Generate Report
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* Recent Activity & Quick Actions */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Recent Incidents */}
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white">Recent Incidents</CardTitle>
              <CardDescription className="text-slate-300">
                Latest incident response activities
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-700/50">
                  <div>
                    <div className="text-sm font-medium text-white">INC-2023-001</div>
                    <div className="text-xs text-slate-400">Phishing Attack - Contained</div>
                  </div>
                  <Badge variant="default">Resolved</Badge>
                </div>
                
                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-700/50">
                  <div>
                    <div className="text-sm font-medium text-white">INC-2023-002</div>
                    <div className="text-xs text-slate-400">Malware Detection - Active</div>
                  </div>
                  <Badge variant="destructive">Critical</Badge>
                </div>
                
                <div className="flex items-center justify-between p-3 rounded-lg bg-slate-700/50">
                  <div>
                    <div className="text-sm font-medium text-white">INC-2023-003</div>
                    <div className="text-xs text-slate-400">Data Exfiltration - Investigating</div>
                  </div>
                  <Badge variant="default">High</Badge>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Quick Actions */}
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white">Quick Actions</CardTitle>
              <CardDescription className="text-slate-300">
                Common incident response tasks
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-3">
                <Button variant="outline" className="h-auto p-4 flex flex-col items-center gap-2 border-slate-600 text-slate-200 hover:bg-slate-700">
                  <Zap className="h-5 w-5" />
                  <span className="text-xs">Create Incident</span>
                </Button>
                
                <Button variant="outline" className="h-auto p-4 flex flex-col items-center gap-2 border-slate-600 text-slate-200 hover:bg-slate-700">
                  <Activity className="h-5 w-5" />
                  <span className="text-xs">View Timeline</span>
                </Button>
                
                <Button variant="outline" className="h-auto p-4 flex flex-col items-center gap-2 border-slate-600 text-slate-200 hover:bg-slate-700">
                  <Shield className="h-5 w-5" />
                  <span className="text-xs">Run Analysis</span>
                </Button>
                
                <Button variant="outline" className="h-auto p-4 flex flex-col items-center gap-2 border-slate-600 text-slate-200 hover:bg-slate-700">
                  <FileText className="h-5 w-5" />
                  <span className="text-xs">Generate Report</span>
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* System Status */}
        <Card className="bg-slate-800/50 border-slate-700">
          <CardHeader>
            <CardTitle className="text-white">System Status</CardTitle>
            <CardDescription className="text-slate-300">
              AI Incident Response Copilot components health
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="flex items-center justify-between p-3 rounded-lg bg-slate-700/50">
                <div>
                  <div className="text-sm font-medium text-white">Frontend</div>
                  <div className="text-xs text-slate-400">Next.js 14</div>
                </div>
                <CheckCircle className="h-4 w-4 text-green-400" />
              </div>
              
              <div className="flex items-center justify-between p-3 rounded-lg bg-slate-700/50">
                <div>
                  <div className="text-sm font-medium text-white">API Gateway</div>
                  <div className="text-xs text-slate-400">NestJS</div>
                </div>
                <CheckCircle className="h-4 w-4 text-green-400" />
              </div>
              
              <div className="flex items-center justify-between p-3 rounded-lg bg-slate-700/50">
                <div>
                  <div className="text-sm font-medium text-white">Orchestrator</div>
                  <div className="text-xs text-slate-400">CrewAI</div>
                </div>
                <CheckCircle className="h-4 w-4 text-green-400" />
              </div>
              
              <div className="flex items-center justify-between p-3 rounded-lg bg-slate-700/50">
                <div>
                  <div className="text-sm font-medium text-white">Database</div>
                  <div className="text-xs text-slate-400">PostgreSQL</div>
                </div>
                <CheckCircle className="h-4 w-4 text-green-400" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
