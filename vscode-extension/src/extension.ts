import * as vscode from 'vscode';
import { exec } from 'child_process';
import * as path from 'path';

let diagnosticCollection: vscode.DiagnosticCollection;

export function activate(context: vscode.ExtensionContext) {
    console.log('Sentinel Security extension is now active!');
    
    diagnosticCollection = vscode.languages.createDiagnosticCollection('sentinel');
    context.subscriptions.push(diagnosticCollection);
    
    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.analyze', () => analyzeContract())
    );
    
    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.liarDetector', () => runLiarDetector())
    );
    
    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.accessMatrix', () => showAccessMatrix())
    );
    
    // Real-time analysis on save
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((document) => {
            if (document.languageId === 'solidity') {
                const config = vscode.workspace.getConfiguration('sentinel');
                if (config.get('enableRealtime')) {
                    analyzeContract(document);
                }
            }
        })
    );
}

async function analyzeContract(document?: vscode.TextDocument) {
    const editor = vscode.window.activeTextEditor;
    if (!editor && !document) {
        vscode.window.showErrorMessage('No active Solidity file');
        return;
    }
    
    const doc = document || editor!.document;
    const filePath = doc.fileName;
    
    if (!filePath.endsWith('.sol')) {
        return;
    }
    
    vscode.window.showInformationMessage('🛡️ Sentinel: Analyzing contract...');
    
    const config = vscode.workspace.getConfiguration('sentinel');
    const pythonPath = config.get<string>('pythonPath') || 'python3';
    const enginePath = config.get<string>('enginePath') || '';
    
    // Run heuristic scanner
    const scannerPath = path.join(enginePath, 'heuristic_scanner.py');
    const command = `${pythonPath} ${scannerPath} ${filePath}`;
    
    exec(command, (error, stdout, stderr) => {
        if (error && error.code !== 1) {  // Code 1 = findings detected
            vscode.window.showErrorMessage(`Sentinel Error: ${stderr}`);
            return;
        }
        
        // Parse findings and create diagnostics
        const diagnostics = parseFindings(stdout, doc);
        diagnosticCollection.set(doc.uri, diagnostics);
        
        if (diagnostics.length > 0) {
            vscode.window.showWarningMessage(
                `Sentinel found ${diagnostics.length} potential issues`
            );
        } else {
            vscode.window.showInformationMessage('✅ Sentinel: No issues detected');
        }
    });
}

function parseFindings(output: string, document: vscode.TextDocument): vscode.Diagnostic[] {
    const diagnostics: vscode.Diagnostic[] = [];
    
    // Parse heuristic scanner output
    // Format: [SEVERITY] RULE_ID - Description @ file:line
    const findingPattern = /\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+(\w+)\s+-\s+(.+?)\s+@\s+.+?:(\d+)/g;
    
    let match;
    while ((match = findingPattern.exec(output)) !== null) {
        const [, severity, ruleId, description, lineNo] = match;
        
        const line = parseInt(lineNo) - 1;  // VS Code is 0-indexed
        const range = document.lineAt(line).range;
        
        const diagnostic = new vscode.Diagnostic(
            range,
            `${ruleId}: ${description}`,
            severityToVSCode(severity)
        );
        
        diagnostic.source = 'Sentinel';
        diagnostic.code = ruleId;
        
        diagnostics.push(diagnostic);
    }
    
    return diagnostics;
}

function severityToVSCode(severity: string): vscode.DiagnosticSeverity {
    switch (severity) {
        case 'CRITICAL':
        case 'HIGH':
            return vscode.DiagnosticSeverity.Error;
        case 'MEDIUM':
            return vscode.DiagnosticSeverity.Warning;
        case 'LOW':
        case 'INFO':
            return vscode.DiagnosticSeverity.Information;
        default:
            return vscode.DiagnosticSeverity.Hint;
    }
}

async function runLiarDetector() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showErrorMessage('No active Solidity file');
        return;
    }
    
    const filePath = editor.document.fileName;
    const config = vscode.workspace.getConfiguration('sentinel');
    const pythonPath = config.get<string>('pythonPath') || 'python3';
    const enginePath = config.get<string>('enginePath') || '';
    
    const liarPath = path.join(enginePath, 'intent_check.py');
    const command = `${pythonPath} ${liarPath} ${filePath}`;
    
    vscode.window.showInformationMessage('🤥 Running Liar Detector...');
    
    exec(command, (error, stdout, stderr) => {
        // Show results in output panel
        const outputChannel = vscode.window.createOutputChannel('Sentinel Liar Detector');
        outputChannel.clear();
        outputChannel.appendLine(stdout);
        outputChannel.show();
        
        if (stdout.includes('MISMATCH')) {
            vscode.window.showWarningMessage('🤥 Intent mismatches detected! Check Output panel.');
        } else {
            vscode.window.showInformationMessage('✅ Code matches developer intent');
        }
    });
}

async function showAccessMatrix() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showErrorMessage('No active Solidity file');
        return;
    }
    
    const filePath = editor.document.fileName;
    const config = vscode.workspace.getConfiguration('sentinel');
    const pythonPath = config.get<string>('pythonPath') || 'python3';
    const enginePath = config.get<string>('enginePath') || '';
    
    const matrixPath = path.join(enginePath, 'access_matrix.py');
    const command = `${pythonPath} ${matrixPath} ${filePath}`;
    
    vscode.window.showInformationMessage('🛡️ Generating Access Matrix...');
    
    exec(command, (error, stdout, stderr) => {
        // Create webview panel
        const panel = vscode.window.createWebviewPanel(
            'sentinelAccessMatrix',
            'Access Control Matrix',
            vscode.ViewColumn.Two,
            {}
        );
        
        // Format output as HTML table
        const html = formatAccessMatrixHTML(stdout);
        panel.webview.html = html;
    });
}

function formatAccessMatrixHTML(output: string): string {
    const lines = output.split('\n').filter(l => l.includes('|'));
    
    let html = `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: monospace; padding: 20px; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #333; color: white; }
            .public { background-color: #ff000020; }
            .admin { background-color: #00ff0020; }
            .view { background-color: #0000ff20; }
        </style>
    </head>
    <body>
        <h2>🛡️ Access Control Matrix</h2>
        <table>
            <tr>
                <th>Risk Level</th>
                <th>Function</th>
                <th>Visibility</th>
                <th>Access Control</th>
            </tr>
    `;
    
    lines.forEach(line => {
        const parts = line.split('|').map(p => p.trim());
        if (parts.length >= 3) {
            const risk = parts[0];
            const rowClass = risk.includes('PUBLIC') ? 'public' : 
                           risk.includes('ADMIN') ? 'admin' : 'view';
            
            html += `<tr class="${rowClass}">`;
            parts.forEach(part => {
                html += `<td>${part}</td>`;
            });
            html += `</tr>`;
        }
    });
    
    html += `
        </table>
    </body>
    </html>
    `;
    
    return html;
}

export function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
}
