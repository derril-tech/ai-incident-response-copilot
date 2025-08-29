import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

export default function Home() {
  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      <div className="container mx-auto px-4 py-16">
        <div className="text-center mb-16">
          <h1 className="text-5xl font-bold text-white mb-6">
            AI Incident Response Copilot
          </h1>
          <p className="text-xl text-slate-300 max-w-3xl mx-auto">
            Automate incident retrospectives with CrewAI multi-agent orchestration. 
            Collect evidence, correlate timelines, and generate comprehensive post-incident reports.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-16">
          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white">Evidence Collection</CardTitle>
              <CardDescription className="text-slate-300">
                Automated artifact collection with SHA-256 hashing and chain-of-custody
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="text-slate-300 space-y-2">
                <li>• SIEM & EDR integration</li>
                <li>• Cloud audit logs</li>
                <li>• WORM storage compliance</li>
              </ul>
            </CardContent>
          </Card>

          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white">Timeline Correlation</CardTitle>
              <CardDescription className="text-slate-300">
                AI-powered event correlation and forensic analysis
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="text-slate-300 space-y-2">
                <li>• IOC mapping</li>
                <li>• ATT&CK framework</li>
                <li>• Anomaly detection</li>
              </ul>
            </CardContent>
          </Card>

          <Card className="bg-slate-800/50 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white">Report Generation</CardTitle>
              <CardDescription className="text-slate-300">
                CrewAI agents generate comprehensive incident reports
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="text-slate-300 space-y-2">
                <li>• Executive summaries</li>
                <li>• Remediation steps</li>
                <li>• Lessons learned</li>
              </ul>
            </CardContent>
          </Card>
        </div>

        <div className="text-center">
          <Button size="lg" className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-3">
            Get Started
          </Button>
        </div>
      </div>
    </main>
  )
}
