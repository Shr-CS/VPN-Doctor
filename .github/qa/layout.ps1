$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path 'build/VPNDoctor.exe'))
$form = [Activator]::CreateInstance($assembly.GetType('OpenVPNDoctor.MainForm'), $true)
$props = [Reflection.BindingFlags]'Instance,NonPublic'
function Field($name) { $form.GetType().GetField($name, $props).GetValue($form) }
function Pump { for ($i=0; $i -lt 20; $i++) { [Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 50 } }
$form.StartPosition = 'Manual'
$form.Location = [Drawing.Point]::new(0,0)
try {
    $form.Show()
    Pump
    $inputBox = Field 'logInput'
    $reportBox = Field 'report'
    foreach ($size in @([Drawing.Size]::new(900,600), [Drawing.Size]::new(1180,750))) {
        $form.ClientSize = $size
        Pump
        $bounds = $form.RectangleToScreen($form.ClientRectangle)
        $rects = @()
        foreach ($name in @('comboLogs','btnAnalyze','btnImport','btnSelectVpn','btnClear','btnSample','btnRescan','report','logInput')) {
            $item = Field $name
            $rect = $item.RectangleToScreen($item.ClientRectangle)
            if (!$item.Visible -or !$bounds.Contains($rect) -or $rect.Width -lt 20 -or $rect.Height -lt 16) { throw "Clipped control: $name at $rect" }
            foreach ($other in $rects) { if ($rect.IntersectsWith($other)) { throw "Controls overlap at $name" } }
            $rects += $rect
        }
    }
    # Render the built-in sample through the same report generator, without contacting a remote server.
    $sample = $form.GetType().GetField('SAMPLE_LOG', [Reflection.BindingFlags]'Static,NonPublic').GetValue($null)
    $inputBox.Text = $sample
    $engine = $assembly.GetType('OpenVPNDoctor.Engine')
    $result = $engine.GetMethod('Analyze',[type[]]@([string])).Invoke($null,@($sample))
    $reportType = $assembly.GetType('OpenVPNDoctor.HtmlReport')
    $html = $reportType.GetMethod('Render').Invoke($null,@($result,$null,$false))
    [IO.File]::WriteAllText((Join-Path (Resolve-Path build) 'sample-report.html'),$html)
    $reportBox.DocumentText = $html
    Pump
    $bitmap = [Drawing.Bitmap]::new($form.Width,$form.Height)
    $form.DrawToBitmap($bitmap,[Drawing.Rectangle]::new(0,0,$form.Width,$form.Height))
    $bitmap.Save((Join-Path (Resolve-Path build) 'workspace.png'),[Drawing.Imaging.ImageFormat]::Png)
    $bitmap.Dispose()
    Write-Host 'Desktop layout passed at minimum and default sizes.'
} finally { $form.Dispose() }
