# Regenerates src\Sanitization.App\Assets\Sanitization.ico (shield + check mark, multi-size PNG-in-ICO).
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$target = Join-Path $PSScriptRoot '..\src\Sanitization.App\Assets\Sanitization.ico'
$sizes = 256, 64, 48, 32, 16
$pngs = @()
function P([double]$x, [double]$y) { New-Object System.Drawing.PointF ([single]$x), ([single]$y) }
foreach ($s in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap $s, $s
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([System.Drawing.Color]::Transparent)
    $k = $s / 256.0
    [System.Drawing.PointF[]]$pts = @((P (128*$k) (14*$k)), (P (226*$k) (50*$k)), (P (220*$k) (140*$k)), (P (128*$k) (242*$k)), (P (36*$k) (140*$k)), (P (30*$k) (50*$k)))
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddPolygon($pts)
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush (P 0 0), (P 0 $s), ([System.Drawing.Color]::FromArgb(255, 59, 130, 246)), ([System.Drawing.Color]::FromArgb(255, 30, 58, 138))
    $g.FillPath($brush, $path)
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 191, 219, 254)), ([single][Math]::Max(1, 8 * $k))
    $g.DrawPath($pen, $path)
    $chk = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), ([single][Math]::Max(2, 26 * $k))
    $chk.StartCap = 'Round'; $chk.EndCap = 'Round'; $chk.LineJoin = 'Round'
    [System.Drawing.PointF[]]$tick = @((P (78*$k) (128*$k)), (P (114*$k) (164*$k)), (P (180*$k) (92*$k)))
    $g.DrawLines($chk, $tick)
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngs += , $ms.ToArray()
    $g.Dispose(); $bmp.Dispose()
}
$out = New-Object System.IO.MemoryStream
$w = New-Object System.IO.BinaryWriter $out
$w.Write([UInt16]0); $w.Write([UInt16]1); $w.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $b = if ($sizes[$i] -ge 256) { 0 } else { $sizes[$i] }
    $w.Write([byte]$b); $w.Write([byte]$b); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([UInt16]1); $w.Write([UInt16]32); $w.Write([UInt32]$pngs[$i].Length); $w.Write([UInt32]$offset)
    $offset += $pngs[$i].Length
}
foreach ($p in $pngs) { $w.Write($p) }
[IO.File]::WriteAllBytes($target, $out.ToArray())
Write-Host "Icon written: $target"
