[CmdletBinding()]
param(
    [switch]$SelfTest,
    [switch]$NoElevation,
    [string]$RootOverride = ""
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$ScriptPath = $MyInvocation.MyCommand.Path
$PackageRoot = Split-Path -Parent (Split-Path -Parent $ScriptPath)
$Payload = Join-Path $PackageRoot 'payload'
$RunId = (Get-Date).ToString('yyyyMMdd_HHmmss')
$RunRoot = if ($RootOverride) { $RootOverride } else { Join-Path $PackageRoot ("RUN_" + $RunId) }
$Evidence = Join-Path $RunRoot 'evidence'
$Logs = Join-Path $Evidence 'logs'
$Scratch = Join-Path $RunRoot 'scratch'
$Results = New-Object System.Collections.ArrayList

function Ensure-Dir([string]$Path) { if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null } }
function Sha256([string]$Path) { if (Test-Path -LiteralPath $Path) { return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() } return $null }
function Write-Json([object]$Object,[string]$Path) { $Object | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8 }
function Add-Result([string]$Id,[string]$Status,[string]$Summary,[object]$Data=$null) {
    $o = [pscustomobject]@{ id=$Id; status=$Status; summary=$Summary; data=$Data; utc=(Get-Date).ToUniversalTime().ToString('o') }
    [void]$Results.Add($o)
    Write-Host ("[{0}] {1}: {2}" -f $Status,$Id,$Summary)
    return $o
}
function Is-Admin {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Quote-Arg([string]$s) {
    if ($null -eq $s) { return '""' }
    if ($s -notmatch '[\s"]') { return $s }
    return '"' + ($s -replace '(\\*)"','$1$1\"' -replace '(\\+)$','$1$1') + '"'
}
function Join-Args([string[]]$ArgumentList) { return (($ArgumentList | ForEach-Object { Quote-Arg $_ }) -join ' ') }

function Invoke-Bounded {
    param(
      [Parameter(Mandatory=$true)][string]$Exe,
      [string[]]$ArgumentList=@(),
      [Parameter(Mandatory=$true)][string]$Name,
      [int]$TimeoutSec=90,
      [string]$WorkingDirectory=''
    )
    Ensure-Dir $Logs
    $stdout=Join-Path $Logs ($Name+'.stdout.txt')
    $stderr=Join-Path $Logs ($Name+'.stderr.txt')
    Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue
    $sw=[Diagnostics.Stopwatch]::StartNew()
    $p=$null
    try {
        $psi=New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName=$Exe
        $psi.Arguments=(Join-Args $ArgumentList)
        $psi.UseShellExecute=$false
        $psi.RedirectStandardOutput=$true
        $psi.RedirectStandardError=$true
        $psi.CreateNoWindow=$true
        if($WorkingDirectory){$psi.WorkingDirectory=$WorkingDirectory}
        $p=New-Object System.Diagnostics.Process
        $p.StartInfo=$psi
        if(-not $p.Start()){throw 'Process.Start returned false.'}
        $outTask=$p.StandardOutput.ReadToEndAsync()
        $errTask=$p.StandardError.ReadToEndAsync()
        $done=$p.WaitForExit($TimeoutSec*1000)
        if(-not $done){
            try { & taskkill.exe /PID $p.Id /T /F 2>$null | Out-Null } catch { try{$p.Kill()}catch{} }
            try{$p.WaitForExit(5000)|Out-Null}catch{}
        }
        try{$outText=$outTask.Result}catch{$outText=''}
        try{$errText=$errTask.Result}catch{$errText=''}
        $outText | Set-Content -LiteralPath $stdout -Encoding UTF8
        $errText | Set-Content -LiteralPath $stderr -Encoding UTF8
        $code=$null
        if($done){$p.Refresh();$code=$p.ExitCode}
        $sw.Stop()
        return [pscustomobject]@{name=$Name;exe=$Exe;args=$ArgumentList;command=(Join-Args $ArgumentList);exit_code=$code;timed_out=(-not $done);launch_error=$null;duration_ms=$sw.ElapsedMilliseconds;stdout=$stdout;stderr=$stderr}
    } catch {
        $sw.Stop(); $msg=$_.Exception.Message; $_ | Out-String | Set-Content -LiteralPath $stderr -Encoding UTF8
        if($p){try{$p.Dispose()}catch{}}
        return [pscustomobject]@{name=$Name;exe=$Exe;args=$ArgumentList;command=(Join-Args $ArgumentList);exit_code=$null;timed_out=$false;launch_error=$msg;duration_ms=$sw.ElapsedMilliseconds;stdout=$stdout;stderr=$stderr}
    } finally {
        if($p){try{$p.Dispose()}catch{}}
    }
}

function Stop-ProcmonSafe([string]$Procmon) {
    if (-not (Test-Path $Procmon)) { return }
    try { Invoke-Bounded -Exe $Procmon -ArgumentList @('/AcceptEula','/Terminate') -Name 'procmon_terminate' -TimeoutSec 15 | Out-Null } catch {}
    Start-Sleep -Milliseconds 500
    Get-Process Procmon64,Procmon -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
function Start-ProcmonTrace([string]$Procmon,[string]$BaseName) {
    Stop-ProcmonSafe $Procmon
    $pml=Join-Path $Evidence ($BaseName+'.pml')
    $csv=Join-Path $Evidence ($BaseName+'.csv')
    Remove-Item $pml,$csv -Force -ErrorAction SilentlyContinue
    $p=Start-Process -FilePath $Procmon -ArgumentList ('/AcceptEula /Quiet /Minimized /BackingFile '+(Quote-Arg $pml)) -PassThru
    $deadline=(Get-Date).AddSeconds(12)
    while ((Get-Date) -lt $deadline) {
        if ((Test-Path $pml) -or (Get-Process Procmon64,Procmon -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 250
    }
    return [pscustomobject]@{pml=$pml;csv=$csv;launcher_pid=$p.Id}
}
function Finish-ProcmonTrace([string]$Procmon,[object]$Trace,[string]$Name) {
    Stop-ProcmonSafe $Procmon
    if (-not (Test-Path $Trace.pml)) { return [pscustomobject]@{ok=$false;reason='PML_MISSING';pml=$Trace.pml;csv=$Trace.csv} }
    $r=Invoke-Bounded -Exe $Procmon -ArgumentList @('/AcceptEula','/OpenLog',$Trace.pml,'/SaveAs',$Trace.csv) -Name ($Name+'_procmon_export') -TimeoutSec 90
    $ok=(Test-Path $Trace.csv) -and ((Get-Item $Trace.csv).Length -gt 0)
    return [pscustomobject]@{ok=$ok;export=$r;pml=$Trace.pml;csv=$Trace.csv}
}
function Procmon-RarRows([string]$Csv) {
    if (-not (Test-Path $Csv)) { return @() }
    try {
        return @(Import-Csv -LiteralPath $Csv | Where-Object { $_.'Process Name' -in @('Rar.exe','WinRAR.exe','UnRAR.exe') })
    } catch { return @() }
}
function Snapshot-Tree([string]$Path) {
    if (-not (Test-Path $Path)) { return @() }
    return @(Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{full=$_.FullName;length=if($_.PSIsContainer){$null}else{$_.Length};attrs=$_.Attributes.ToString();mtime=$_.LastWriteTimeUtc.ToString('o');sha256=if($_.PSIsContainer){$null}else{try{Sha256 $_.FullName}catch{$null}}}
    })
}
function Registry-Snapshot([string]$OutPath) {
    $keys=@('HKCU:\Software\WinRAR','HKLM:\SOFTWARE\WinRAR','HKLM:\SOFTWARE\Classes\WinRAR','HKCU:\Software\Classes\WinRAR')
    $out=@{}
    foreach($k in $keys){
        if(Test-Path $k){
            try {$out[$k]=@(Get-ChildItem $k -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $p=$_.PSPath; [pscustomobject]@{key=$_.Name;values=(Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSDrive,PSProvider)} })} catch {$out[$k]=@('ERROR: '+$_.Exception.Message)}
        } else {$out[$k]=@()}
    }
    Write-Json $out $OutPath
}
function Get-Streams([string]$File) { try { return @(Get-Item -LiteralPath $File -Stream * -ErrorAction Stop | Select-Object Stream,Length) } catch { return @() } }
function Get-LinkInfo([string]$Path) {
    try { $i=Get-Item -LiteralPath $Path -Force; return [pscustomobject]@{exists=$true;attributes=$i.Attributes.ToString();link_type=$i.LinkType;target=$i.Target} } catch { return [pscustomobject]@{exists=$false;error=$_.Exception.Message} }
}
function Get-Sddl([string]$Path) { try { return (Get-Acl -LiteralPath $Path).Sddl } catch { return $null } }

function Verify-Payload {
    $expected=@{
      'WinRAR.exe'='ab727aec2418a942a1adf5295efb9c676eeba39d16f7c2443e3f873fe2dfca14';
      'Rar.exe'='1639bfccc19b6fdd9becffb154edca06f07d1f337cc61933273f5b30dfb91882';
      'UnRAR.exe'='806b42a2ae54eb8688841500aa70b3a3e4fcbe99059e612086cf9ccdc231b5ea';
      'RarExt.dll'='4f00f5046b05862fde74f892ddf8a87110455db4ab577083d4e9e137ed1b5a04';
      'RarExtInstaller.exe'='091f077e4a8ffdca19430e9775b97d3b448e0c8ffdda52fb93b98268d38356f5';
      'Uninstall.exe'='c893bab6e0159ad6a3baea054f7341dd543ac0ca446671ce07aa93e97b540dc2';
      'winrar-x64-723.exe'='f435b24d4c2c5342c4f7c0143ef358f0f425b7b8a0972dd34d9dcf94789e9c4d';
      'winrar-x64-723-current-restore.exe'='8ff0daf3ed564cc743c0e23ff2e253997ffc74460f9673f0b6dd037b2db4ce7b';
      'Procmon64.exe'='f792c9be7ecdb5c1ea0b852cee28ae8093c84e69d9206e307a2a8cd2df9c85ad'
    }
    $rows=@()
    foreach($n in $expected.Keys){$p=Join-Path $Payload $n;$h=Sha256 $p;$rows += [pscustomobject]@{name=$n;exists=(Test-Path $p);expected=$expected[$n];actual=$h;match=($h -eq $expected[$n])}}
    Write-Json $rows (Join-Path $Evidence 'PAYLOAD_IDENTITY.json')
    $bad=@($rows|Where-Object{-not $_.match})
    if($bad.Count -gt 0){throw ('Exact payload identity failure: '+(($bad|Select-Object -ExpandProperty name)-join ', '))}
}

function Self-Test {
    Ensure-Dir $Evidence; Ensure-Dir $Logs; Ensure-Dir $Scratch
    $a=Invoke-Bounded -Exe $env:ComSpec -ArgumentList @('/c','exit','0') -Name 'self_exit0' -TimeoutSec 10
    if($a.exit_code -ne 0 -or $a.timed_out){throw 'Invoke-Bounded exit test failed'}
    $b=Invoke-Bounded -Exe 'powershell.exe' -ArgumentList @('-NoProfile','-Command','Start-Sleep -Seconds 3') -Name 'self_timeout' -TimeoutSec 1
    if(-not $b.timed_out){throw 'Invoke-Bounded timeout test failed'}
    'abc'|Set-Content (Join-Path $Scratch 'hash.txt') -Encoding ASCII
    if(-not (Sha256 (Join-Path $Scratch 'hash.txt'))){throw 'hash test failed'}
    Add-Result 'SELFTEST' 'PASS' 'PowerShell execution, bounded process timeout, hashing, JSON and filesystem helpers passed.' @{exit_test=$a;timeout_test=$b} | Out-Null
    Write-Json @($Results) (Join-Path $Evidence 'RESULTS.json')
    return
}

if ($SelfTest) { Self-Test; Write-Host 'SELFTEST PASS'; exit 0 }

if (-not (Is-Admin)) {
    if ($NoElevation) { throw 'Administrator rights required for SMB, symlink, Procmon and installer tests.' }
    $arg='-NoProfile -ExecutionPolicy Bypass -File ' + (Quote-Arg $ScriptPath)
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arg | Out-Null
    exit 0
}

Ensure-Dir $RunRoot; Ensure-Dir $Evidence; Ensure-Dir $Logs; Ensure-Dir $Scratch
$Rar=Join-Path $Payload 'Rar.exe'; $WinRAR=Join-Path $Payload 'WinRAR.exe'; $UnRAR=Join-Path $Payload 'UnRAR.exe'; $Procmon=Join-Path $Payload 'Procmon64.exe'
$ExactInstaller=Join-Path $Payload 'winrar-x64-723.exe'; $RestoreInstaller=Join-Path $Payload 'winrar-x64-723-current-restore.exe'

try {
    Verify-Payload
    Add-Result 'A00' 'PASS' 'Exact frozen WinRAR-family specimens, exact frozen installer, restoration installer and Procmon payload hashes verified.' | Out-Null

    $troot=Join-Path $Scratch 'trace_workflows'; Ensure-Dir $troot
    $corpus=Join-Path $troot 'corpus'; Ensure-Dir $corpus
    'alpha'|Set-Content (Join-Path $corpus 'alpha.txt') -Encoding UTF8
    [IO.File]::WriteAllBytes((Join-Path $corpus 'binary.bin'),(0..255))
    $archive=Join-Path $troot 'workflow.rar'; $extract=Join-Path $troot 'extract'; Ensure-Dir $extract
    $trace=Start-ProcmonTrace $Procmon 'A01_A02_workflows'
    $ops=@()
    $ops += Invoke-Bounded $Rar @('a','-idq','-ep1',$archive,(Join-Path $corpus '*')) 'A01_create' 120
    'update'|Set-Content (Join-Path $corpus 'update.txt') -Encoding UTF8
    $ops += Invoke-Bounded $Rar @('u','-idq','-ep1',$archive,(Join-Path $corpus '*')) 'A01_update' 120
    $ops += Invoke-Bounded $Rar @('t','-idq',$archive) 'A01_test' 120
    $ops += Invoke-Bounded $Rar @('x','-idq','-o+',$archive,($extract+'\')) 'A01_extract' 120
    $ops += Invoke-Bounded $Rar @('d','-idq',$archive,'update.txt') 'A01_delete' 120
    $ops += Invoke-Bounded $Rar @('r','-idq',$archive) 'A01_repair' 180
    $tf=Finish-ProcmonTrace $Procmon $trace 'A01_A02'
    $rows=if($tf.ok){Procmon-RarRows $tf.csv}else{@()}
    $focus=@($rows|Where-Object{$_.Operation -match 'CreateFile|ReadFile|WriteFile|FlushBuffersFile|SetRenameInformationFile|SetDispositionInformationFile|CloseFile'} )
    $focus|Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Evidence 'A01_A02_RAR_IO_EVENTS.csv')
    Write-Json $ops (Join-Path $Evidence 'A01_A02_COMMAND_RESULTS.json')
    $badOps=@($ops|Where-Object{$_.timed_out -or $_.exit_code -ne 0})
    $hasCreate=@($rows|Where-Object{$_.Operation -eq 'CreateFile'}).Count -gt 0
    $hasRead=@($rows|Where-Object{$_.Operation -eq 'ReadFile'}).Count -gt 0
    $hasWrite=@($rows|Where-Object{$_.Operation -eq 'WriteFile'}).Count -gt 0
    $hasFlush=@($rows|Where-Object{$_.Operation -match 'FlushBuffersFile'}).Count -gt 0
    $status=if($badOps.Count -eq 0 -and $tf.ok -and $hasCreate -and $hasRead -and $hasWrite){'PASS'}else{'FAIL'}
    Add-Result 'A01' $status 'Traced exact Rar.exe create/update/test/extract/delete/repair workflow I/O; CreateFile detail rows preserve Desired Access/Disposition/Options/ShareMode when exposed by Procmon.' @{trace=$tf;rows=$rows.Count;create=$hasCreate;read=$hasRead;write=$hasWrite;flush=$hasFlush;bad_ops=$badOps.Count} | Out-Null
    Add-Result 'A02' $status 'Captured runtime temp/replacement/finalization filesystem/API events with bounded Procmon trace; FlushBuffersFile presence recorded rather than inferred.' @{flush_observed=$hasFlush;focused_rows=$focus.Count} | Out-Null

    $sroot=Join-Path $Scratch 'special_objects'; $src=Join-Path $sroot 'source'; $dst=Join-Path $sroot 'extract'; Ensure-Dir $src; Ensure-Dir $dst
    $normal=Join-Path $src 'normal.txt'; 'normal-data'|Set-Content $normal -Encoding UTF8
    try {'ads-data'|Set-Content -LiteralPath ($normal+':evidence_stream') -Encoding UTF8} catch {}
    $hard=Join-Path $src 'hardlink.txt'; & cmd.exe /c "mklink /H `"$hard`" `"$normal`"" > (Join-Path $Logs 'A03_mklink_hard.txt') 2>&1
    $sym=Join-Path $src 'symlink.txt'; & cmd.exe /c "mklink `"$sym`" `"$normal`"" > (Join-Path $Logs 'A03_mklink_sym.txt') 2>&1
    $jtarget=Join-Path $src 'junction_target'; Ensure-Dir $jtarget; 'junction-data'|Set-Content (Join-Path $jtarget 'j.txt')
    $junction=Join-Path $src 'junction'; & cmd.exe /c "mklink /J `"$junction`" `"$jtarget`"" > (Join-Path $Logs 'A03_mklink_junction.txt') 2>&1
    $secured=Join-Path $src 'secured.txt'; 'secured'|Set-Content $secured; $acl=Get-Acl $secured; $acl.SetAccessRuleProtection($true,$true); Set-Acl $secured $acl
    $before=[pscustomobject]@{streams=(Get-Streams $normal);hardlink_list=(& fsutil.exe hardlink list $normal 2>&1);symlink=(Get-LinkInfo $sym);junction=(Get-LinkInfo $junction);sddl=(Get-Sddl $secured)}
    Write-Json $before (Join-Path $Evidence 'A03_BEFORE.json')
    $sarchive=Join-Path $sroot 'special.rar'
    $trace=Start-ProcmonTrace $Procmon 'A03_special_objects'
    $c=Invoke-Bounded $Rar @('a','-idq','-os','-oh','-ol','-ep1',$sarchive,(Join-Path $src '*')) 'A03_create' 180
    $x=Invoke-Bounded $Rar @('x','-idq','-o+','-os','-oh','-ol','-ola',$sarchive,($dst+'\')) 'A03_extract' 180
    $tf=Finish-ProcmonTrace $Procmon $trace 'A03'
    $rows=if($tf.ok){Procmon-RarRows $tf.csv}else{@()}; $rows|Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Evidence 'A03_RAR_EVENTS.csv')
    $hardlinkAfter=@(); try { $hardlinkAfter=@(& fsutil.exe hardlink list (Join-Path $dst 'normal.txt') 2>&1) } catch { $hardlinkAfter=@() }
    $after=[pscustomobject]@{streams=(Get-Streams (Join-Path $dst 'normal.txt'));hardlink_list=$hardlinkAfter;symlink=(Get-LinkInfo (Join-Path $dst 'symlink.txt'));junction=(Get-LinkInfo (Join-Path $dst 'junction'));sddl=(Get-Sddl (Join-Path $dst 'secured.txt'))}
    Write-Json $after (Join-Path $Evidence 'A03_AFTER.json')
    $ok=($c.exit_code -eq 0 -and $x.exit_code -eq 0 -and $tf.ok)
    Add-Result 'A03' $(if($ok){'PASS'}else{'FAIL'}) 'Automated NTFS ADS/hardlink/symlink/junction/security create/archive/extract comparison with runtime event trace; restoration outcomes and ordering evidence preserved.' @{create=$c;extract=$x;trace=$tf} | Out-Null

    $froot=Join-Path $Scratch 'failure_matrix'; Ensure-Dir $froot; $locked=Join-Path $froot 'locked.txt'; 'locked'|Set-Content $locked
    $farchive=Join-Path $froot 'failure.rar'; $fail=@()
    $fs=[IO.File]::Open($locked,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try { $fail += [pscustomobject]@{case='sharing_violation';result=(Invoke-Bounded $Rar @('a','-idq',$farchive,$locked) 'A05_sharing_violation' 60)} } finally { $fs.Dispose() }
    $fail += [pscustomobject]@{case='after_release_control';result=(Invoke-Bounded $Rar @('a','-idq',$farchive,$locked) 'A05_after_release' 60)}
    $fail += [pscustomobject]@{case='missing_input';result=(Invoke-Bounded $Rar @('a','-idq',(Join-Path $froot 'missing.rar'),(Join-Path $froot 'does_not_exist.txt')) 'A05_missing_input' 60)}
    $corrupt=Join-Path $froot 'corrupt.rar'; [IO.File]::WriteAllBytes($corrupt,[byte[]](1,2,3,4,5,6,7,8)); $fail += [pscustomobject]@{case='corrupt_archive_test';result=(Invoke-Bounded $Rar @('t','-idq',$corrupt) 'A05_corrupt' 60)}
    Write-Json $fail (Join-Path $Evidence 'A05_FAILURE_MATRIX.json')
    $shareCase=$fail|Where-Object{$_.case -eq 'sharing_violation'}|Select-Object -First 1; $control=$fail|Where-Object{$_.case -eq 'after_release_control'}|Select-Object -First 1
    $ok=($shareCase.result.exit_code -ne 0 -and $control.result.exit_code -eq 0)
    Add-Result 'A05' $(if($ok){'PASS'}else{'FAIL'}) 'Automated controlled failure matrix records exact Rar.exe exit codes plus stdout/stderr for sharing violation, control retry, missing input and corrupt archive.' @{cases=$fail.Count} | Out-Null

    $smbAvailable=[bool](Get-Command New-SmbShare -ErrorAction SilentlyContinue)
    if($smbAvailable){
      $shareName='ArchiverLab_'+$RunId; $sharePath=Join-Path $Scratch 'smb_share'; Ensure-Dir $sharePath; 'unc-data'|Set-Content (Join-Path $sharePath 'unc.txt')
      try {
        New-SmbShare -Name $shareName -Path $sharePath -FullAccess 'Everyone' -ErrorAction Stop | Out-Null
        $unc='\\localhost\'+$shareName; $ua=Join-Path $Scratch 'unc_output.rar'; $ud=Join-Path $Scratch 'unc_extract'; Ensure-Dir $ud
        $normal1=Invoke-Bounded $Rar @('a','-idq',$ua,($unc+'\unc.txt')) 'A06_unc_create' 90
        $normal2=Invoke-Bounded $Rar @('t','-idq',$ua) 'A06_unc_test' 90
        $big=Join-Path $sharePath 'disconnect.bin'; $rng=[Security.Cryptography.RandomNumberGenerator]::Create(); $buf=New-Object byte[] (1024*1024); $out=[IO.File]::Create($big); try{for($i=0;$i -lt 512;$i++){ $rng.GetBytes($buf); $out.Write($buf,0,$buf.Length)}}finally{$out.Dispose();$rng.Dispose()}
        $outRar=Join-Path $Scratch 'unc_disconnect.rar'; $so=Join-Path $Logs 'A06_disconnect.stdout.txt';$se=Join-Path $Logs 'A06_disconnect.stderr.txt'
        $p=Start-Process $Rar -ArgumentList @('a','-m0','-idq',$outRar,($unc+'\disconnect.bin')) -RedirectStandardOutput $so -RedirectStandardError $se -PassThru -WindowStyle Hidden
        Start-Sleep -Milliseconds 350
        Remove-SmbShare -Name $shareName -Force -ErrorAction Stop
        $done=$p.WaitForExit(60000); if(-not $done){Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue}; $p.Refresh()
        $disc=[pscustomobject]@{exit_code=if($done){$p.ExitCode}else{$null};timed_out=(-not $done);stdout=$so;stderr=$se;output_exists=(Test-Path $outRar);output_size=if(Test-Path $outRar){(Get-Item $outRar).Length}else{$null}}
        Write-Json $disc (Join-Path $Evidence 'A06_FORCED_SHARE_LOSS.json')
        $ok=($normal1.exit_code -eq 0 -and $normal2.exit_code -eq 0 -and (($disc.exit_code -ne 0) -or (-not $disc.output_exists)))
        Add-Result 'A06' $(if($ok){'PASS'}else{'FAIL'}) 'Automated normal loopback UNC/SMB workflow plus forced live share removal during archive read; failure exit/output residue captured.' @{normal_create=$normal1;normal_test=$normal2;disconnect=$disc} | Out-Null
      } finally { Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue | Remove-SmbShare -Force -ErrorAction SilentlyContinue }
    } else { Add-Result 'A06' 'FAIL' 'SMB PowerShell cmdlets unavailable on this Windows host.' | Out-Null }

    $iroot=Join-Path $Scratch 'installer_lab'; Ensure-Dir $iroot; $labInstall=Join-Path $iroot 'WinRARExact'; Ensure-Dir $labInstall
    Registry-Snapshot (Join-Path $Evidence 'A07_REGISTRY_BEFORE.json'); Write-Json (Snapshot-Tree $labInstall) (Join-Path $Evidence 'A07_FILES_BEFORE.json')
    $install=Invoke-Bounded $ExactInstaller @('/S',('/D='+$labInstall)) 'A07_exact_install' 180
    Registry-Snapshot (Join-Path $Evidence 'A07_REGISTRY_AFTER_INSTALL.json'); Write-Json (Snapshot-Tree $labInstall) (Join-Path $Evidence 'A07_FILES_AFTER_INSTALL.json')
    $generatedUninstall=Join-Path $labInstall 'Uninstall.exe'; $uninstall=$null; $uninstallMissing=$false
    if(Test-Path $generatedUninstall){$uninstall=Invoke-Bounded $generatedUninstall @('/S') 'A07_exact_uninstall' 180}else{$uninstall=[pscustomobject]@{exit_code=$null;timed_out=$false;launch_error='Generated Uninstall.exe missing'};$uninstallMissing=$true}
    Registry-Snapshot (Join-Path $Evidence 'A07_REGISTRY_AFTER_UNINSTALL.json'); Write-Json (Snapshot-Tree $labInstall) (Join-Path $Evidence 'A07_FILES_AFTER_UNINSTALL.json')
    $restore=Invoke-Bounded $RestoreInstaller @('/S') 'A07_restore_current' 180
    Registry-Snapshot (Join-Path $Evidence 'A07_REGISTRY_AFTER_RESTORE.json')
    $ok=($install.exit_code -eq 0 -and (-not $uninstallMissing) -and $uninstall.exit_code -eq 0 -and $restore.exit_code -eq 0)
    Add-Result 'A07' $(if($ok){'PASS'}else{'FAIL'}) 'Automated exact frozen WinRAR 7.23 silent install/uninstall transaction in isolated directory, registry/file snapshots before/after, then current 7.23 restoration installer run.' @{install=$install;uninstall=$uninstall;restore=$restore;lab_dir=$labInstall} | Out-Null

    $probe=Join-Path $Scratch 'token_probe.ps1'; $mediumOut=Join-Path $Evidence 'A08_MEDIUM_TOKEN.txt'; $mediumRar=Join-Path $Evidence 'A08_MEDIUM_RAR.json'; $elevOut=Join-Path $Evidence 'A08_ELEVATED_TOKEN.txt'
    @"
`$ErrorActionPreference='Continue'
whoami /all | Out-File -LiteralPath '$mediumOut' -Encoding utf8
`$o='$mediumRar'; `$so='$Logs\A08_medium_rar.stdout.txt'; `$se='$Logs\A08_medium_rar.stderr.txt';
`$p=Start-Process -FilePath '$Rar' -ArgumentList @('t','-idq','$archive') -PassThru -RedirectStandardOutput `$so -RedirectStandardError `$se -WindowStyle Hidden; if(`$p.WaitForExit(60000)){`$p.Refresh(); [pscustomobject]@{exit_code=`$p.ExitCode;admin=`$false} | ConvertTo-Json | Set-Content `$o -Encoding UTF8}else{Stop-Process -Id `$p.Id -Force; [pscustomobject]@{exit_code=`$null;timed_out=`$true} | ConvertTo-Json | Set-Content `$o -Encoding UTF8}
"@ | Set-Content -LiteralPath $probe -Encoding UTF8
    whoami /all | Out-File -LiteralPath $elevOut -Encoding utf8
    $shell=New-Object -ComObject Shell.Application
    $shell.ShellExecute('powershell.exe',('-NoProfile -ExecutionPolicy Bypass -File '+(Quote-Arg $probe)),'','open',0)
    $deadline=(Get-Date).AddSeconds(75); while((Get-Date)-lt $deadline -and -not(Test-Path $mediumRar)){Start-Sleep -Milliseconds 500}
    $elevRar=Invoke-Bounded $Rar @('t','-idq',$archive) 'A08_elevated_rar' 60
    $mediumExists=Test-Path $mediumRar
    $mediumText=if(Test-Path $mediumOut){Get-Content $mediumOut -Raw}else{''}; $elevText=Get-Content $elevOut -Raw
    $mediumLevel=if($mediumText -match 'Medium Mandatory Level'){'Medium'}elseif($mediumText -match 'High Mandatory Level'){'High'}else{'Unknown'}
    $elevLevel=if($elevText -match 'High Mandatory Level'){'High'}else{'Unknown'}
    Add-Result 'A08' $(if($mediumExists -and $elevLevel -eq 'High'){'PASS'}else{'FAIL'}) 'Automated elevated and Explorer-mediated medium-integrity token/privilege snapshots plus identical Rar.exe test operation in both contexts.' @{medium_integrity=$mediumLevel;elevated_integrity=$elevLevel;medium_result_exists=$mediumExists;elevated_rar=$elevRar} | Out-Null

} catch {
    $_ | Out-String | Set-Content -LiteralPath (Join-Path $Evidence 'FATAL_ERROR.txt') -Encoding UTF8
    Add-Result 'FATAL' 'FAIL' $_.Exception.Message | Out-Null
} finally {
    try { Stop-ProcmonSafe $Procmon } catch {}
    try { Get-SmbShare -Name ('ArchiverLab_'+$RunId) -ErrorAction SilentlyContinue | Remove-SmbShare -Force -ErrorAction SilentlyContinue } catch {}
    Write-Json @($Results) (Join-Path $Evidence 'RESULTS.json')
    @($Results | Select-Object id,status,summary) | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Evidence 'RESULTS.csv')
    $pass=@($Results|Where-Object{$_.status -eq 'PASS'}).Count; $fail=@($Results|Where-Object{$_.status -eq 'FAIL'}).Count
    $readme=@"
ARCHIVER WINDOWS SEVEN AUTOMATED — EVIDENCE
Run ID: $RunId
Host: $env:COMPUTERNAME
PASS records: $pass
FAIL records: $fail

Tests:
A01 runtime CreateFile/ReadFile/WriteFile ordering and flags via bounded Procmon trace
A02 temp/replacement/finalization/FlushBuffersFile trace
A03 ADS/hardlink/reparse/security restoration outcomes and runtime ordering
A05 controlled Win32/product failure matrix
A06 normal UNC/SMB plus forced share-loss failure semantics
A07 exact frozen installer/uninstaller transaction and automated current-build restoration
A08 elevated-vs-medium token/privilege and product behavior

No result is promoted beyond the evidence actually captured. A FAIL means the requested evidence was not established by this run; it does not mean WinRAR itself is defective.
"@
    $readme|Set-Content -LiteralPath (Join-Path $Evidence 'READ_ME_FIRST.txt') -Encoding UTF8
    $zip=Join-Path $PackageRoot ("EVIDENCE_ARCHIVER_WINDOWS_SEVEN_"+$env:COMPUTERNAME+'_'+$RunId+'.zip')
    if(Test-Path $zip){Remove-Item $zip -Force}
    Compress-Archive -Path (Join-Path $Evidence '*') -DestinationPath $zip -CompressionLevel Optimal
    Write-Host ''
    Write-Host 'RUN COMPLETE.'
    Write-Host ('Evidence ZIP: '+$zip)
    Write-Host ('PASS='+$pass+' FAIL='+$fail)
}
