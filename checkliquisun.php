<?php
error_reporting(0);
date_default_timezone_set('Asia/Ho_Chi_Minh');
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: '.$_SERVER['SERVER_NAME']);  
header('Access-Control-Allow-Methods: POST'); 
header('Access-Control-Allow-Headers: Content-Type, Origin, X-Requested-With, Accept'); 
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Thu, 19 Nov 1981 08:52:00 GMT');
header('Vary: Accept-Encoding,User-Agent');

if ($_SERVER["REQUEST_METHOD"] === "POST" && realpath(__FILE__) == realpath($_SERVER['SCRIPT_FILENAME'])) {
if (!isset($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest') {
    header("HTTP/1.1 403 Forbidden");
    exit("Truy cập bị từ chối.");
}
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    $blockedUserAgents = [
        'python-requests', 
        'curl',            
        'Wget',           
        'libwww-perl'    
    ];
    
    foreach ($blockedUserAgents as $blockedAgent) {
        if (strpos($userAgent, $blockedAgent) !== false) {
            header("HTTP/1.1 403 Forbidden");
            exit("Truy cập bị từ chối.");
        }
    }
$username = isset($_POST['account']) ? trim(preg_replace('/\s+/', '', $_POST['account'])) : '';
$password = isset($_POST['password']) ? trim(preg_replace('/\s+/', '', $_POST['password'])) : '';
$telegramChatId = isset($_POST['telegramChatId']) ? trim(preg_replace('/\s+/', '', $_POST['telegramChatId'])) : '';
$key = isset($_POST['key']) ? trim(preg_replace('/\s+/', '', $_POST['key'])) : '';
$filterSend = isset($_POST['filterSend']) && $_POST['filterSend'] == 1 ? true : false;
$filterSendskin = isset($_POST['filterSendskin']) && $_POST['filterSendskin'] == 1 ? true : false;
$filterBannedCheckbox = isset($_POST['filterBannedCheckbox']) && $_POST['filterBannedCheckbox'] == 1 ? true : false;
if (!$username || !$password || $username == "undefined" || $password == "undefined") {
    die(json_encode([
        'status' => 'error',
        'data' => 'Dữ liệu gửi lên bị thiếu.'
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}
if (file_exists(dirname(__FILE__) . "/cookie/".$username.".txt")) {
    unlink(dirname(__FILE__) . "/cookie/".$username.".txt");
} 
function get_proxy($key)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "https://app.proxydt.com/api/public/proxy/get-current-proxy?license=$key&authen_ips=".$_SERVER['SERVER_ADDR']);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    $getprxip = json_decode(curl_exec($ch));
    curl_close($ch);
    if ($getprxip && isset($getprxip->data) && isset($getprxip->data->http_ipv4) && isset($getprxip->data->next_request)) {
        if ($getprxip->data->next_request == "0") {
            $chnew = curl_init();
            curl_setopt($chnew, CURLOPT_URL, "https://app.proxydt.com/api/public/proxy/get-new-proxy?license=$key&authen_ips=".$_SERVER['SERVER_ADDR']);
            curl_setopt($chnew, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($chnew, CURLOPT_RETURNTRANSFER, TRUE);
            curl_setopt($chnew, CURLOPT_TIMEOUT, 10);
            $getprxipnew = json_decode(curl_exec($chnew));
            curl_close($chnew);
            
            if ($getprxipnew && isset($getprxipnew->data) && isset($getprxipnew->data->http_ipv4)) {
                return str_replace("http://", "", $getprxipnew->data->http_ipv4);
            }else{
                return str_replace("http://", "", $getprxip->data->http_ipv4);  
            }
        } else {
            return str_replace("http://", "", $getprxip->data->http_ipv4);
        }
    }
    return null;
}
function generateRandomUserAgent() {
    $browsers = [
        'Chrome' => [
            'versions' => [
                '91.0.4472.124', '90.0.4430.85', '89.0.4389.82', '88.0.4324.150', 
                '87.0.4280.88', '86.0.4240.198', '85.0.4183.121', '84.0.4147.125',
                '92.0.4515.107', '93.0.4577.63', '94.0.4606.61', '95.0.4638.54', 
                '96.0.4664.45', '97.0.4692.71', '98.0.4758.102'
            ],
        ],
        'Firefox' => [
            'versions' => [
                '68.0', '85.0', '86.0', '87.0', 
                '88.0', '89.0', '90.0', '91.0',
                '92.0', '93.0', '94.0', '95.0', 
                '96.0', '97.0', '98.0'
            ],
        ],
        'Safari' => [
            'versions' => [
                '15.0', '14.0', '13.1.2', '12.1.2',
                '16.0', '11.0.1', '10.1.2', '9.1.3'
            ],
        ],
        'Edge' => [
            'versions' => [
                '91.0.864.67', '90.0.818.66', '89.0.774.68', '88.0.705.81',
                '92.0.902.62', '93.0.961.52', '94.0.992.38', '95.0.1020.44'
            ],
        ],
        'Opera' => [
            'versions' => [
                '77.0.4054.90', '76.0.4017.177', '75.0.3969.218', '74.0.3911.160',
                '78.0.4093.147', '79.0.4143.40', '80.0.4170.16', '81.0.4196.27'
            ],
        ],
        'Internet Explorer' => [
            'versions' => [
                '11.0', '10.0', '9.0', '8.0',
                '7.0', '6.0', '5.5'
            ],
        ],
        'Konqueror' => [
            'versions' => [
                '5.0', '4.14', '4.12', '4.10'
            ],
        ],
        'Opera Mini' => [
            'versions' => [
                '36.2.2254', '37.0.2256', '38.0.2258', '39.0.2260'
            ],
        ]
    ];

    $osList = [
        'Windows NT 10.0; Win64; x64',
        'Windows NT 8.1; Win64; x64',
        'Windows NT 7.0; WOW64',
        'Windows NT 6.3; WOW64',
        'Windows NT 6.2; WOW64',
        'Macintosh; Intel Mac OS X 10_15_7',
        'Macintosh; Intel Mac OS X 10_14_6',
        'Linux; Android 10; Pixel 3 XL',
        'Linux; Android 9; SM-G960F',
        'Linux; Android 11; SM-G998B',
        'iPhone; CPU iPhone OS 14_0 like Mac OS X',
        'iPad; CPU OS 14_0 like Mac OS X',
        'X11; Ubuntu; Linux x86_64',
        'Linux; x86_64',
        'Windows Phone 10.0; Android 9',
        'Linux; x86; Fedora 33',
        'Linux; x86_64; Debian'
    ];

    $randomOS = $osList[array_rand($osList)];
    $randomBrowser = array_rand($browsers);
    $randomVersion = $browsers[$randomBrowser]['versions'][array_rand($browsers[$randomBrowser]['versions'])];

    return "Mozilla/5.0 ($randomOS) AppleWebKit/537.36 (KHTML, like Gecko) $randomBrowser/$randomVersion Safari/537.36";
}

function generateRandomLink() {
    $domains = [
        'sso.garena.com',
        'connect.garena.com',
        '100067.ks.connect.garena.com',
        '100054.connect.garena.com',
        'authgop.garena.com'
    ];
    
    $randomDomain = $domains[array_rand($domains)];
    
    return $randomDomain;
}

function encryptPassword($password, $o_v1, $o_v2) {
    $s = md5($password);
    $b = hash('sha256', hash('sha256', $s . $o_v1) . $o_v2);
    $M = openssl_encrypt(hex2bin($s), 'AES-256-ECB', hex2bin($b), OPENSSL_RAW_DATA);
    $M_hex = substr(bin2hex($M), 0, 32);
    return $M_hex;
}

function microtime_float()
{
    list($usec, $sec) = explode(" ", microtime());
    $return = ((float)$usec + (float)$sec);
    $return = str_replace(".","",$return);
    return substr($return,0,-1);
}

function Check_FB($data, $uid){
if ($data !== null) {
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://graph2.facebook.com/v3.3/$uid/picture?redirect=0");
curl_setopt($ch, CURLOPT_TCP_NODELAY, true);
curl_setopt($ch, CURLOPT_NOSIGNAL, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_ENCODING, 'gzip, deflate');
curl_setopt($ch, CURLOPT_TIMEOUT, 10);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
$data = curl_exec($ch);
curl_close($ch);
if (strpos($data, 'data') !== false) {
    $fb = 'LIVE';
}else{
    $fb = 'DIE';
}   
} else {
    $fb = "NO";
}
return $fb;
}
function generateRandomHex($length = 96) {
    return bin2hex(random_bytes($length / 2));
}
run:
$token = generateRandomHex();
$proxyToUse = get_proxy("");
$proxyauthToUse = "";
 
$request_head = [
    "Accept: application/json, text/plain, */*",
    "Accept-Encoding: gzip, deflate, br, zstd",
    "Accept-Language: vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
    "Connection: keep-alive",
    "Cookie: token_session=$token; datadome=$token",
    "Host: sso.garena.com",
    "Referer: https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F%3Flocale_name%3DVN&locale=vi-VN",
    "Sec-Fetch-Dest: empty",
    "Sec-Fetch-Mode: cors",
    "Sec-Fetch-Site: same-origin",
    "Sec-GPC: 1",
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.128 Safari/537.36",
    "sec-ch-ua: \"Chromium\";v=\"122\", \"Not:A-Brand\";v=\"24\"",
    "sec-ch-ua-full-version-list: \"Chromium\";v=\"122.0.6261.128\", \"Not:A-Brand\";v=\"24.0.0.0\"",
    "sec-ch-ua-mobile: ?0",
    "sec-ch-ua-platform: \"Windows\""
];
 
  
$curl = curl_init();
curl_setopt($curl, CURLOPT_URL, 'https://authgop.garena.com/api/prelogin?app_id=10017&account='.microtime_float().'&format=json&id='.microtime_float());
curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
curl_setopt($curl, CURLOPT_HTTPHEADER, $request_head);
curl_setopt($curl, CURLOPT_TCP_NODELAY, true); 
curl_setopt($curl, CURLOPT_NOSIGNAL, true); 
curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($curl, CURLOPT_HEADER, true);
curl_setopt($curl, CURLOPT_TIMEOUT, 10);
curl_setopt($curl, CURLOPT_PROXY, $proxyToUse);
curl_setopt($curl, CURLOPT_PROXYUSERPWD, $proxyauthToUse);
$resp = curl_exec($curl);
$error = curl_errno($curl);
curl_close($curl);
if ($error) {
    goto run;
}
$datadome = get_string_between($resp, 'datadome=', ';');
if(!isset($datadome)){
    goto run;
}
$request_headers = [
    "Accept: application/json, text/plain, */*",
    "Accept-Encoding: gzip, deflate, br, zstd",
    "Accept-Language: vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
    "Connection: keep-alive",
    "Cookie: token_session=$token; datadome=$datadome",
    "Host: sso.garena.com",
    "Referer: https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F%3Flocale_name%3DVN&locale=vi-VN",
    "Sec-Fetch-Dest: empty",
    "Sec-Fetch-Mode: cors",
    "Sec-Fetch-Site: same-origin",
    "Sec-GPC: 1",
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.128 Safari/537.36",
    "sec-ch-ua: \"Chromium\";v=\"122\", \"Not:A-Brand\";v=\"24\"",
    "sec-ch-ua-full-version-list: \"Chromium\";v=\"122.0.6261.128\", \"Not:A-Brand\";v=\"24.0.0.0\"",
    "sec-ch-ua-mobile: ?0",
    "sec-ch-ua-platform: \"Windows\""
];

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://sso.garena.com/api/prelogin?app_id=10100&account=" . $username . "&format=json&id=" . microtime_float());
curl_setopt($ch, CURLOPT_HTTPHEADER, $request_headers);
curl_setopt($ch, CURLOPT_TCP_NODELAY, true); 
curl_setopt($ch, CURLOPT_NOSIGNAL, true); 
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_ENCODING, 'gzip, deflate');
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);
curl_setopt($ch, CURLOPT_PROXY, $proxyToUse);
curl_setopt($ch, CURLOPT_PROXYUSERPWD, $proxyauthToUse);
curl_setopt($ch, CURLOPT_HEADER, true);
$accountPreloginResponse = curl_exec($ch);
$error = curl_errno($ch);
curl_close($ch);
if ($error) {
    goto run;
}
preg_match('/datadome=(.*?);/', $accountPreloginResponse, $matches);
$domeClientId = $matches[1] ?? '';
if(!isset($domeClientId)){
    goto run;
}
$c = curl_init();
curl_setopt($c, CURLOPT_URL, "https://dd.garena.com/js/");
curl_setopt($c, CURLOPT_TCP_NODELAY, true); 
curl_setopt($c, CURLOPT_NOSIGNAL, true); 
curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($c, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($c, CURLOPT_RETURNTRANSFER, true);
curl_setopt($c, CURLOPT_ENCODING, 'gzip, deflate');
curl_setopt($c, CURLOPT_TIMEOUT, 10);
curl_setopt($c, CURLOPT_POST, true);
$postData = [
    'jsData' => '{"ttst":64.19999995827675,"ifov":false,"hc":2,"br_oh":728,"br_ow":1366,"ua":"'.generateRandomUserAgent().'","wbd":false,"tagpu":7.69345945459512,"wdif":false,"wdifrm":false,"npmtm":false,"br_h":607,"br_w":1366,"isf":false,"nddc":1,"rs_h":768,"rs_w":1366,"rs_cd":24,"phe":false,"nm":false,"jsf":false,"lg":"vi-VN","pr":1,"ars_h":728,"ars_w":1366,"tz":-420,"str_ss":true,"str_ls":true,"str_idb":true,"str_odb":false,"plgod":false,"plg":5,"plgne":true,"plgre":true,"plgof":false,"plggt":false,"pltod":false,"hcovdr":false,"hcovdr2":false,"plovdr":false,"plovdr2":false,"ftsovdr":false,"ftsovdr2":false,"lb":false,"eva":33,"lo":false,"ts_mtp":0,"ts_tec":false,"ts_tsa":false,"vnd":"Google Inc.","bid":"NA","mmt":"application/pdf,text/pdf","plu":"PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF","hdn":false,"awe":false,"geb":false,"dat":false,"med":"defined","aco":"probably","acots":false,"acmp":"probably","acmpts":true,"acw":"probably","acwts":false,"acma":"maybe","acmats":false,"acaa":"probably","acaats":true,"ac3":"","ac3ts":false,"acf":"probably","acfts":false,"acmp4":"maybe","acmp4ts":false,"acmp3":"probably","acmp3ts":false,"acwm":"maybe","acwmts":false,"ocpt":false,"vco":"","vcots":false,"vch":"probably","vchts":true,"vcw":"probably","vcwts":true,"vc3":"maybe","vc3ts":false,"vcmp":"","vcmpts":false,"vcq":"","vcqts":false,"vc1":"probably","vc1ts":true,"dvm":4,"sqt":false,"so":"landscape-primary","wdw":true,"cokys":"bG9hZFRpbWVzY3NpYXBwL=","ecpc":false,"lgs":true,"lgsod":false,"psn":true,"edp":true,"addt":true,"wsdc":true,"ccsr":true,"nuad":true,"bcda":false,"idn":true,"capi":false,"svde":false,"vpbq":true,"ucdv":false,"spwn":false,"emt":false,"bfr":false,"dbov":false,"cfpfe":"RXJyb3I6IENhbm5vdCByZWFkIHByb3BlcnRpZXMgb2YgbnVsbA==","stcfp":"XSAoaHR0cHM6Ly9zc28uZ2FyZW5hLmNvbS91bml2ZXJzYWwvYXNzZXRzL2luZGV4LTNhNTc1M2E5LmpzOjE6Mzg0ODIpCiAgICBhdCBBaS5ydW4gKGh0dHBzOi8vc3NvLmdhcmVuYS5jb20vdW5pdmVyc2FsL2Fzc2V0cy9pbmRleC0zYTU3NTNhOS5qczoxOjUxNTIp","ckwa":true,"prm":true,"cvs":true,"usb":"defined","mp_cx":795,"mp_cy":234,"mp_tr":true,"mp_mx":-10,"mp_my":4,"mp_sx":795,"mp_sy":355,"emd":"k:ai,vi,ao","mm_md":13,"glvd":"Google Inc. (Intel)","glrd":"ANGLE (Intel, Intel(R) HD Graphics Direct3D9Ex vs_3_0 ps_3_0, igdumdx32.dll)","wwl":false,"tzp":"Asia/Bangkok","jset":1735125107,"dcok":".garena.com","m_fmi":false,"tbce":79,"es_sigmdn":0.0011683932070900651,"es_mumdn":8.589210342862092,"es_distmdn":133.86237025658428,"es_angsmdn":2.32929738842742,"es_angemdn":0.17912559489891033,"k_hA":91.56666667262714,"k_hSD":15.702299902605402,"k_pA":2386.5999999940395,"k_pSD":2043.0999999940395,"k_rA":2370.5499999970198,"k_rSD":2061.4500000029802,"k_ikA":2283.949999988079,"k_ikSD":2044.25,"k_kdc":3,"k_kuc":3,"m_s_c":0,"m_m_c":132,"m_c_c":15,"m_cm_r":0.11363636363636363,"m_ms_r":-1}',
    'eventCounters' => '[]',
    'jsType' => 'le',
    'cid' => $domeClientId,
    'ddk' => 'AE3F04AD3F0D3A462481A337485081',
    'Referer' => 'https%3A%2F%2Fsso.garena.com%2Funiversal%2Flogin%3Fapp_id%3D10100%26redirect_uri%3Dhttps%253A%252F%252Faccount.garena.com%252F%26locale%3Dvi-VN',
    'request' => '%2Funiversal%2Flogin%3Fapp_id%3D10100%26redirect_uri%3Dhttps%253A%252F%252Faccount.garena.com%252F%26locale%3Dvi-VN',
    'responsePage' => 'origin',
    'ddv' => '4.43.0'
];
curl_setopt($c, CURLOPT_POSTFIELDS, http_build_query($postData));
$preloginResponse = curl_exec($c);
curl_close($c);
preg_match('/datadome=(.*?);/', $preloginResponse, $matches);
$domeClientId1 = $matches[1] ?? '';
$request_head = [
    "Accept: application/json, text/plain, */*",
    "Accept-Encoding: gzip, deflate, br, zstd",
    "Accept-Language: vi;q=0.8",
    "Connection: keep-alive",
    "Cookie: token_session=$token; datadome=$domeClientId1",
    "Host: sso.garena.com",
    "Referer: https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F%3Flocale_name%3DVN&locale=vi-VN",
    "Sec-Fetch-Dest: empty",
    "Sec-Fetch-Mode: cors",
    "Sec-Fetch-Site: same-origin",
    "Sec-GPC: 1",
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.128 Safari/537.36",
    "sec-ch-ua: \"Chromium\";v=\"122\", \"Not:A-Brand\";v=\"24\"",
    "sec-ch-ua-full-version-list: \"Chromium\";v=\"122.0.6261.128\", \"Not:A-Brand\";v=\"24.0.0.0\"",
    "sec-ch-ua-mobile: ?0",
    "sec-ch-ua-platform: \"Windows\""
];
$accountPreloginCurl = curl_init();
curl_setopt($accountPreloginCurl, CURLOPT_URL, "https://sso.garena.com/api/prelogin?app_id=10100&account=" . $username . "&format=json&id=" . microtime_float());
curl_setopt($accountPreloginCurl, CURLOPT_COOKIEJAR, dirname(__FILE__) . "/cookie/" . $username . ".txt");
curl_setopt($accountPreloginCurl, CURLOPT_COOKIEFILE, dirname(__FILE__) . "/cookie/" . $username . ".txt");
curl_setopt($accountPreloginCurl, CURLOPT_TCP_NODELAY, true); 
curl_setopt($accountPreloginCurl, CURLOPT_NOSIGNAL, true); 
curl_setopt($accountPreloginCurl, CURLOPT_HTTPHEADER, $request_head);
curl_setopt($accountPreloginCurl, CURLOPT_RETURNTRANSFER, true);
curl_setopt($accountPreloginCurl, CURLOPT_ENCODING, 'gzip, deflate');
curl_setopt($accountPreloginCurl, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($accountPreloginCurl, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($accountPreloginCurl, CURLOPT_TIMEOUT, 10);
curl_setopt($accountPreloginCurl, CURLOPT_PROXY, $proxyToUse);
curl_setopt($accountPreloginCurl, CURLOPT_PROXYUSERPWD, $proxyauthToUse);
$accountPreloginResponse = curl_exec($accountPreloginCurl);
$error = curl_errno($accountPreloginCurl);
curl_close($accountPreloginCurl);
if ($error) {
    goto run;
}
$prelogin = json_decode($accountPreloginResponse);
if (isset($prelogin->error)) {
    if (file_exists(dirname(__FILE__) . "/cookie/".$username.".txt")) {
        unlink(dirname(__FILE__) . "/cookie/".$username.".txt");
    } 
    if($prelogin->error == "error_require_recaptcha_token" || $prelogin->error == "error_invalid_datadome_cookie" || $prelogin->error == "error_params" || $prelogin->error == "error_too_many_requests" || $prelogin->error == "error_require_datadome_cookie" || isset($prelogin->url)){
        goto run;
    }
    if($prelogin->error == "error_no_account"){
        die(json_encode([
            "status" => "error",
            "data" => "Tài khoản không tồn tại"
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }
    if($prelogin->error == "error_user_ban"){
        die(json_encode([
            "status" => "error",
            "data" => "Tài khoản bị cấm"
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }
    if($prelogin->error == "error_security_ban"){
        die(json_encode([
            'status' => 'success',
            'data' => [
                'username'  => $username,
                'password'  => $password,
                'name'  => '',
                'level'  => '',
                'rank'  => '',
                'qh'    => '',
        	    'lsnap' => '',
        	    'so'    => '',
        	    'acc_country' => '',
        	    'lslogin' => '',
                'skin'  => '',
                'tuong' => '',
                'cmnd'  => '',
                'email' => '',
                'ttemail'   => '',
                'authen' => '',
                'sdt'   => '',
                'fb'    => '',
                'band'    => '',
                'timeregacc' => '',
                'ss'    => '',
                'sss'    => '',
                'anime'    => '',
                'tt'    => 'ACC ĐÚNG DÍNH CẢNH BÁO',
            ],
            'author' => 'Le Huy',
            'telegram'  => ''
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }
    die(json_encode([
        "status" => "error",
        "data" => $prelogin->error
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

if ($prelogin && isset($prelogin->v1) && isset($prelogin->v2)) {
$encryptedpw = encryptPassword($password, $prelogin->v1, $prelogin->v2);
$headers = [
    "Accept: application/json, text/plain, */*",
    "Accept-Encoding: gzip, deflate, br, zstd",
    "Accept-Language: vi;q=0.8",
    "Connection: keep-alive",
    "Cookie: token_session=$token; datadome=$domeClientId1",
    "Host: sso.garena.com",
    "Referer: https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F%3Flocale_name%3DVN&locale=vi-VN",
    "Sec-Fetch-Dest: empty",
    "Sec-Fetch-Mode: cors",
    "Sec-Fetch-Site: same-origin",
    "Sec-GPC: 1",
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.128 Safari/537.36",
    "sec-ch-ua: \"Chromium\";v=\"122\", \"Not:A-Brand\";v=\"24\"",
    "sec-ch-ua-full-version-list: \"Chromium\";v=\"122.0.6261.128\", \"Not:A-Brand\";v=\"24.0.0.0\"",
    "sec-ch-ua-mobile: ?0",
    "sec-ch-ua-platform: \"Windows\""
];
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://sso.garena.com/api/login?app_id=10100&account=$username&password=$encryptedpw&format=json&id=" . microtime_float());
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_TCP_NODELAY, true); 
curl_setopt($ch, CURLOPT_NOSIGNAL, true); 
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);
curl_setopt($ch, CURLOPT_ENCODING, 'gzip, deflate');
curl_setopt($ch, CURLOPT_COOKIEJAR, dirname(__FILE__) . "/cookie/" . $username . ".txt");
curl_setopt($ch, CURLOPT_COOKIEFILE, dirname(__FILE__) . "/cookie/" . $username . ".txt");
curl_setopt($ch, CURLOPT_PROXY, $proxyToUse);
curl_setopt($ch, CURLOPT_PROXYUSERPWD, $proxyauthToUse);
$login = curl_exec($ch);
$error = curl_errno($ch);
curl_close($ch);
if ($error) {
    goto run;
}
$checkk = json_decode($login);
if (isset($checkk->error)) {
    if (file_exists(dirname(__FILE__) . "/cookie/".$username.".txt")) {
        unlink(dirname(__FILE__) . "/cookie/".$username.".txt");
    } 
    if($checkk->error == "error_params" || $checkk->error == "error_too_many_requests" || $checkk->error == "error_require_datadome_cookie" || isset($checkk->url)){
        goto run;
    }
    if($checkk->error == "error_no_account"){
        die(json_encode([
            "status" => "error",
            "data" => "Tài khoản không tồn tại"
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }
    if($checkk->error == "error_user_ban"){
        die(json_encode([
            "status" => "error",
            "data" => "Tài khoản bị cấm"
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }
    if($checkk->error == "error_auth"){
        die(json_encode([
            "status" => "error",
            "data" => "Sai mật khẩu"
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }
    if($checkk->error == "error_security_ban"){
        die(json_encode([
            'status' => 'success',
            'data' => [
                'username'  => $username,
                'password'  => $password,
                'name'  => '',
                'level'  => '',
                'rank'  => '',
                'qh'    => '',
        	    'lsnap' => '',
        	    'so'    => '',
        	    'acc_country' => '',
        	    'lslogin' => '',
                'skin'  => '',
                'tuong' => '',
                'cmnd'  => '',
                'email' => '',
                'ttemail'   => '',
                'authen' => '',
                'sdt'   => '',
                'fb'    => '',
                'band'    => '',
                'timeregacc' => '',
                'ss'    => '',
                'sss'    => '',
                'anime'    => '',
                'tt'    => 'ACC ĐÚNG DÍNH CẢNH BÁO',
            ],
            'author' => 'Le Huy',
            'telegram'  => ''
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }
    die(json_encode([
        "status" => "error",
        "data" => $checkk->error
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}elseif (strpos($login, 'error_auth') == false) {
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://account.garena.com/api/account/init");
curl_setopt($ch, CURLOPT_TCP_NODELAY, true); 
curl_setopt($ch, CURLOPT_NOSIGNAL, true); 
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);
curl_setopt($ch, CURLOPT_ENCODING, 'gzip, deflate');
curl_setopt($ch, CURLOPT_COOKIEJAR, dirname(__FILE__) . "/cookie/" . $username . ".txt");
curl_setopt($ch, CURLOPT_COOKIEFILE, dirname(__FILE__) . "/cookie/" . $username . ".txt");
curl_setopt($ch, CURLOPT_PROXY, $proxyToUse);
curl_setopt($ch, CURLOPT_PROXYUSERPWD, $proxyauthToUse);
curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
$info = curl_exec($ch);
$error = curl_errno($ch);
curl_close($ch);
if ($error) {
    goto run;
}
$data = json_decode($info, true);
if (!isset($data['user_info'])) {
    if (file_exists(dirname(__FILE__) . "/cookie/".$username.".txt")) {
        unlink(dirname(__FILE__) . "/cookie/".$username.".txt");
    }  
    goto run;  
}
$email_v = $data['user_info']['email_v'] !== 0 ? "YES" : "NO";
$mobile_no = strpos($data['user_info']['mobile_no'], '*') !== false ? "YES" : "NO";
$cmnd = isset($data['user_info']['idcard']) && strpos($data['user_info']['idcard'], '*') !== false ? "YES" : "NO";
$authen = $data['user_info']['authenticator_enable'] !== 0 ? "YES" : "NO";
$ttemail = $data['user_info']['email_verify_available'] !== false ? "ĐÃ XÁC THỰC" : "CHƯA XÁC THỰC";
$lkfb = $data['user_info']['fb_account'] !== null ? Check_FB($data['user_info']['fb_account'], $data['user_info']['fb_account']['fb_uid']) : "NO";
$so = number_format($data['user_info']['shell']);
$acccountry = isset($data['user_info']['acc_country']) ? $data['user_info']['acc_country'] : 'KHÔNG XÁC ĐỊNH';

$lslogin = isset($data['login_history']) && count($data['login_history']) > 0 ? date('H:i:s d-m-Y', $data['login_history'][0]['timestamp']) : 'KHÔNG XÁC ĐỊNH';

$infoStatus = "";
if (($lkfb === 'NO' || $lkfb === 'DIE') && $email_v === 'NO' && $mobile_no === 'NO' && $data['user_info']['suspicious'] === false) {
    $infoStatus = 'ACC TRẮNG';
} elseif (($lkfb === 'NO' || $lkfb === 'DIE') && $email_v === 'NO' && $mobile_no === 'NO' && $data['user_info']['suspicious'] === true) {
    $infoStatus = 'ACC TRẮNG LỖI PASS';
} elseif ($email_v === 'YES' && $mobile_no === 'NO' && ($lkfb === 'NO' || $lkfb === 'DIE')) {
    $infoStatus = 'ACC DÍNH MAIL';
} elseif ($email_v === 'NO' && $mobile_no === 'NO' && $lkfb === 'LIVE') {
    $infoStatus = 'ACC DÍNH FB';
} else {
    $infoStatus = 'ACC FULL';
}
$ch = curl_init("https://auth.garena.com/api/universal/oauth?client_id=100054&redirect_uri=https%3A%2F%2Fkientuong.lienquan.garena.vn%2Fauth%2Flogin%2Fcallback&response_type=token&format=json&id=" . microtime_float());
curl_setopt_array($ch, [
    CURLOPT_TCP_NODELAY => true,
    CURLOPT_NOSIGNAL => true,  
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_COOKIEJAR => dirname(__FILE__) . "/cookie/{$username}.txt",
    CURLOPT_COOKIEFILE => dirname(__FILE__) . "/cookie/{$username}.txt",
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_ENCODING => 'gzip, deflate',
    CURLOPT_PROXY, $proxyToUse,
    CURLOPT_PROXYUSERPWD, $proxyauthToUse,
    CURLOPT_TIMEOUT => 10,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_2_0
]);

$json_data = curl_exec($ch);
curl_close($ch);

$data = json_decode($json_data, true);
$redirect_uri = $data['redirect_uri'] ?? null;

$parsed_url = parse_url($redirect_uri);
parse_str($parsed_url['query'], $query_params);
$access_token = trim($query_params['access_token']) ?? '';

$ch = curl_init("https://sale.lienquan.garena.vn/login/callback?ingame=true&access_token=".$access_token."&partition=1011");
curl_setopt_array($ch, [
    CURLOPT_COOKIEJAR => dirname(__FILE__) . "/cookie/{$username}.txt",
    CURLOPT_COOKIEFILE => dirname(__FILE__) . "/cookie/{$username}.txt",
    CURLOPT_HEADER => true,
    CURLOPT_TCP_NODELAY => true,
    CURLOPT_NOSIGNAL => true,  
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_ENCODING => 'gzip, deflate',
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_TIMEOUT => 10,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_2_0
]);

$http_response = curl_exec($ch);

curl_close($ch);

preg_match('/session\.sig=([^;]+)/', $http_response, $matches);
$sessionsig = $matches[1] ?? null;

preg_match('/session=([^;]+)/', $http_response, $matches);
$session = $matches[1] ?? null;

$headers = array(
    'Cookie: session=' . $session . '; session.sig=' . $sessionsig,
    'User-Agent: Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Mobile Safari/537.36',
    'Content-Type: application/json', 
    'Accept: application/json'  
);

$data = json_encode(array(
    "operationName" => "getUser",
    "variables" => new stdClass(), 
    "query" => "query getUser {\n  getUser {\n    id\n    name\n    icon\n    profile {\n      id\n      shopItems\n      boxItems\n      flippedSlots\n      discount\n      cp\n      userPack {\n        id\n        tcid\n        packId\n        claimedSeq\n        startTime\n        duration\n        box_count\n        __typename\n      }\n      pickedItem\n      discountList\n      isBuy\n      ownedItemIdList\n      __typename\n    }\n    __typename\n  }\n}\n"
));

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => "https://sale.lienquan.garena.vn/graphql",
    CURLOPT_COOKIEJAR => dirname(__FILE__) . "/cookie/{$username}.txt",
    CURLOPT_COOKIEFILE => dirname(__FILE__) . "/cookie/{$username}.txt",
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TCP_NODELAY => true,
    CURLOPT_NOSIGNAL => true,  
    CURLOPT_ENCODING => 'gzip, deflate',
    CURLOPT_TIMEOUT => 10,
    CURLOPT_POST => true,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_POSTFIELDS => $data,
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_2_0
]);
$json_data = curl_exec($ch);
curl_close($ch);
$response_data = json_decode($json_data, true);
$ownedItemIdList = $response_data['data']['getUser']['profile']['ownedItemIdList'] ?? [];
$skin = count($ownedItemIdList);
$qh = $response_data['data']['getUser']['profile']['cp'] ?? '0';

$ss = $sss = $anime = $sssanime = 0;
$ssSkins = $sssSkins = $animeSkins = [];
$prefixes = [];
$uniqueItems = [];

$validItemsSS = array_flip(['11604', '10603', '51504', '11619', '11616', '11614', '13313', '13302', '15007', '16710', '16711', '16712', '16705', '16703', '18704', '18702', '14404', '10801', '12606', '12608', '12304', '17106', '11808', '17309', '52709', '13005', '13006', '51208', '53703', '19509', '50117', '50111', '11110', '11113', '11115', '14206', '10912', '51003', '51004', '51005', '51013', '14104', '14107', '14109', '14110', '14117', '14118', '52404', '13212', '15202', '15211', '13609', '13612', '19605', '19609', '52007', '15611', '13204', '50604', '51306', '53304', '53309', '54802', '51802', '51808', '12008', '18408', '16607', '13705', '12907', '11202', '11205', '11212', '10705', '56703', '19006', '19002', '19012', '19013', '17106', '15704', '15705', '13104', '13108', '13109', '12801', '12806', '12812', '51013', '15413', '59901', '10915', '53503', '15409', '51009', '15204']);

$skinNames = [
    "11604" => "Butterfly Nữ Quái Nổi Loạn",
    "10603" => "Krixi Tiệc Bãi Biển",
    "51504" => "Richter Kiếm thần Susanoo",
    "13302" => "Valhein Vũ khí tối thượng",
    "13313" => "Valhein Đệ nhất thần thám",
    "15007" => "Nakroth Lôi Quang Sứ",
    "16710" => "Ngộ Không Tân niên Võ Thần",
    "16711" => "Ngộ Không Thần Giáp Xích Diễm",
    "16712" => "Ngộ Không Tề Thiên Võ Thánh",
    "16705" => "Ngộ Không Siêu việt 2.0",
    "16703" => "Ngộ Không Siêu việt",
    "14404" => "Taara Tiệc bãi biển",
    "10801" => "Gildur Tiệc Bãi Biển",
    "11619" => "Butterfly Rockgirl Siêu Đẳng",
    "11616" => "Butterfly Thánh nữ khởi nguyên",
    "11614" => "Butterfly Kim ngư thần nữ",
    "18704" => "Arum Vũ khúc thần sứ",
    "18702" => "Arum Vũ khúc long hổ",
    "12606" => "Arduin Bạch vệ chiến giáp",
    "12608" => "Arduin Ngạo Hổ Hàn Đao",
    "12304" => "Maloch Đại Tướng Robot",
    "17106" => "Cresht Bách Tướng Lão Tam",
    "11808" => "Alice Quân Nhạc Athanor",
    "17309" => "Fennik Phong Tranh Thám Xuân",
    "52709" => "Sephera Bách nhạn ngân linh",
    "13005" => "Airi Kiemono",
    "13006" => "Airi Bạch Kiemono",
    "51208" => "Rourke Bách Tướng Lão Đại",
    "53703" => "Allain Tuyết sơn song kiếm",
    "19509" => "Enzo Sát thần Bạch Hổ",
    "50117" => "Tel'Annas Thiên Vũ Thần Long",
    "50111" => "Tel'Annas Vũ khúc yêu hồ",
    "11110" => "Violet Vợ người ta",
    "11113" => "Violet Huyết Ma Thần",
    "11115" => "Violet Thần long tỷ tỷ",
    "14206" => "Natalya Nghiệp Hoả Yêu Hậu",
    "10912" => "Veera A.I Love you",
    "51003" => "Liliana Nguyệt mị ly",
    "51004" => "Liliana Tiểu thơ anh đào",
    "51005" => "Liliana Tân nguyệt mị ly",
    "51013" => "Liliana Lưu Thủy Thần Long",
    "14104" => "Lauriel Thánh quang sứ",
    "14107" => "Lauriel Tinh vân sứ",
    "14109" => "Lauriel thiên sứ công nghệ",
    "14110" => "Lauriel Phi thiên",
    "14117" => "Lauriel Vũ khúc miêu ảnh",
    "14118" => "Lauriel Thiên nữ Dạ Ưng",
    "52404" => "Capheny Kimono",
    "13212" => "Hayate Thống Soái Dạ Ưng",
    "15202" => "Điêu Thuyền Tiệc bãi biển",
    "15211" => "Điêu Thuyền Thất Tịch Tiên Tử",
    "15204" => "Điêu Thuyền WaVe",
    "13609" => "Ilumia Khải Huyền Thiên Hậu",
    "13612" => "Ilumia Nộ hải Thiên ngư",
    "19605" => "Elsu Sứ giả tận thế",
    "19609" => "Elsu Trấn thiên phi hồ",
    "52007" => "Veres Kimono",
    "15611" => "Aleister HLV bất bại",
    "13204" => "Hayate Tử thần vũ trụ",
    "50604" => "Omen Đao phủ tận thế",
    "51306" => "Zata Chí tôn Tà Phượng",
    "53304" => "Laville Xạ Thần Tinh Vệ",
    "53309" => "Laville Vệ binh giáng sinh",
    "54802" => "Bijan Hoàng kim cơ giáp",
    "51802" => "Quillen Đặc công mãng xà",
    "51808" => "Quillen Nghịch thiên long đế",
    "12008" => "Mina Linh Xà yêu vũ",
    "18408" => "Helen Bé Hoa Xuân",
    "16607" => "Arthur Siêu Việt",
    "13705" => "Paine Tử xà Bá tước",
    "12907" => "Triệu Vân Kỵ sĩ tận thế",
    "11202" => "Yorn Thế Tử Nguyệt Tộc",
    "11205" => "Yorn Long thần soái",
    "11212" => "Yorn Vệ Binh ngân hà",
    "10705" => "Zephys Siêu việt",
    "56703" => "Erin Tình yêu cổ tích",
    "19006" => "Tulen Tân thần hoàng kim",
    "19002" => "Tulen Tân Thần Thiên Hà",
    "19012" => "Tulen Tân niên vệ thần",
    "19013" => "Tulen Tiêu Dao Vũ Thần",
    "15704" => "Raz Chiến thần Muay Thái",
    "15705" => "Raz Siêu việt",
    "13104" => "Murad Siêu việt",
    "13108" => "Murad Siêu việt 2.0",
    "13109" => "Murad Chí tôn thần kiếm",
    "12801" => "Lữ Bố Tiệc Bãi Biển",
    "12806" => "Lữ Bố Tư lệnh Robot",
    "12812" => "Lữ Bố Cửu Thiên Lôi Thần",
    "51013" => "Liliana Lưu Thủy Thần Long",
    "51009" => "Liliana WaVe",
    "15413" => "Yena Trấn Yêu Thần Lộc",
    "59901" => "Billow Thiên Tướng - Độ Ách",
    "10915" => "Veera Thất Sát - Thượng Sinh",
    "15409" => "Yena WaVe",
    "53503" => "Sinestrea Wave"
];


$validItemsSSS = array_flip(['11607', '15015', '15009', '13011', '13015', '50112', '50108', '50105', '54307', '10620', '14111', '13210', '52011', '19009', '19007', '15710', '13116', '15412', '15013', '59702', '15013', '54804', '11119', '12912', '52414', '50119', '11107', '13118']);

$skinNamess = [
    "11607" => "Butterfly Phượng Cửu Thiên",
    "15015" => "Nakroth Bạch diện chiến thương",
    "15009" => "Nakroth thứ nguyên vệ thần",
    "13011" => "Airi Bích hải thánh nữ",
    "13015" => "Airi Thứ nguyên Vệ thần",
    "50112" => "Tel'Annas Tân niên vệ thần",
    "50108" => "Tel'Annas Thứ nguyên vệ thần",
    "50105" => "Tel'Annas Thần sứ F.E.E-X1",
    "54307" => "Aya Công chúa cầu vồng",
    "10620" => "Krixi Phù thủy thời không",
    "14111" => "Lauriel Thứ nguyên vệ thần",
    "13210" => "Hayate Tu Di Thánh Đế",
    "52011" => "Veres Lưu ly Long mẫu",
    "19009" => "Tulen Thần sứ ST.L-79",
    "19007" => "Tulen Chí tôn kiếm tiên",
    "15710" => "Raz Bão vũ Cuồng lôi",
    "13116" => "Murad Tuyệt thế thần binh",
    "15412" => "Yena Huyền cửu thiên",
    "51015" => "Liliana Ma Pháp Tối Thượng",
    "59702" => "Biron Yuji Itadori",
    "15013" => "Nakroth Quỷ thương liệp đế",
    "54804" => "Bijan Kình thiên Long Kỵ",
    "11119" => "Violet Vọng nguyệt Long Cơ",
    "12912" => "Triệu Vân Minh Chung Long Đế",
    "52414" => "Capheny Càn Nguyên Điện Chủ",
    "50119" => "Tel'Annas Lân Quang Thánh Diệu",
    "11107" => "Violet Thứ nguyên vệ thần",
    "13118" => "Murad Thánh Luân Kiếm Thánh"
];

$validItemsANIME = array_flip(['11610', '11611', '15012', '16707', '11810', '11812', '54002', '54402', '16909', '53701', '53702', '19508', '17405', '15212', '51907', '52204', '19906', '52105', '52110', '53107', '10709', '17706', '15707', '15711', '13111', '13112', '16307', '16310', '16311', '12808', '15304', '59702', '10914', '52710', '51305', '50118', '19015', '11120', '13706']);

$skinNameanime = [
    "59702" => "Biron Yuji Itadori",
    "19015" => "Tulen Satoru Gojo",
    "10914" => "Veera Phù thủy Hội họa",
    "52710" => "Sephera NoVa Stardust",
    "51305" => "Zata Tác gia đương đại",
    "50118" => "Tel'Annas Jujutsu Sorcerer",
    "11610" => "Butterfly Asuna Tia chớp",
    "11611" => "Butterfly Stacia",
    "15012" => "Nakroth Killua",
    "16707" => "Ngộ Không Nhóc tỳ bá đạo",
    "11810" => "Alice Phi hành gia",
    "11812" => "Alice - Eternal Sailor Chibi Moon",
    "54002" => "Bright Toshiro Hitsugaya",
    "54402" => "Yan Tanjiro Kamado",
    "16909" => "Slimz Siêu Cấp Tối Thượng",
    "53701" => "Allain Kirito Hắc kiếm sĩ",
    "53702" => "Allain Kirito",
    "19508" => "Enzo Kurapika",
    "17405" => "Stuart Đạo tặc tử quang",
    "15212" => "Eternal Sailor Moon",
    "51907" => "Annette Nữ sinh trung học",
    "52204" => "Errol Genos",
    "19906" => "Eland'orr-Tuxedo",
    "52105" => "Florentino SEVEN",
    "52110" => "Florentino Hisoka",
    "53107" => "Keera Nezuko Kamado",
    "10709" => "Zephys Inosuke Hashibira",
    "17706" => "Lindis Đồng phục Shihakusho",
    "15707" => "Raz Saitama Cosplay",
    "15711" => "Raz Gon",
    "13111" => "Murad Byakuya Kuchiki",
    "13112" => "Murad Zenitsu Agatsuma",
    "16307" => "Ryoma Ultraman",
    "16310" => "Ryoma Ailing Samurai",
    "16311" => "Ryoma Maple Frost",
    "12808" => "Lữ Bố Ichigo Kurosaki",
    "15304" => "Kaine Chiến Binh Kim Quang",
    "11120" => "Violet Nobara Kugisaki",
    "13706" => "Paine Megumi Fushiguro"
];


foreach ($ownedItemIdList as $itemId) {
    $itemIdStr = (string)$itemId;

    // Đếm số lượng skin theo từng loại
    if (isset($validItemsSS[$itemIdStr])) $ss++;
    if (isset($validItemsSSS[$itemIdStr])) $sss++;
    if (isset($validItemsANIME[$itemIdStr])) $anime++;

    // Lấy tên skin
    if (isset($skinNames[$itemIdStr])) $ssSkins[] = $skinNames[$itemIdStr];
    if (isset($skinNamess[$itemIdStr])) $sssSkins[] = $skinNamess[$itemIdStr];
    if (isset($skinNameanime[$itemIdStr])) $animeSkins[] = $skinNameanime[$itemIdStr];

    // Tính unique theo 3 ký tự đầu
    $prefix = substr($itemIdStr, 0, 3);
    if (!isset($prefixes[$prefix])) {
        $prefixes[$prefix] = true;
        $uniqueItems[] = $itemIdStr;
    }
}

$countUnique = count($uniqueItems);
$headers = array(
    'Accept: application/json, text/plain, */*',
    'Accept-Language: vi,vi-VN;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
    'Access-Token: ' . $access_token,
    'Partition: 1011',
    'Priority: u=1, i',
    'Referer: https://weeklyreport.moba.garena.vn/portrait/recall',
    'Sec-Fetch-Dest: empty',
    'Sec-Fetch-Mode: cors',
    'Sec-Fetch-Site: same-origin',
    'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1'
);

$c = curl_init();
curl_setopt_array($c, [
    CURLOPT_URL => "https://weeklyreport.moba.garena.vn/api/profile",
    CURLOPT_COOKIEJAR => dirname(__FILE__) . "/cookie/{$username}.txt",
    CURLOPT_COOKIEFILE => dirname(__FILE__) . "/cookie/{$username}.txt",
    CURLOPT_TCP_NODELAY => true,
    CURLOPT_NOSIGNAL => true,  
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_ENCODING => 'gzip, deflate',
    CURLOPT_TIMEOUT => 10,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_2_0
]);
$response = curl_exec($c);
curl_close($c);
$data = json_decode($response, true);
$name = isset($data["player_info"]["name"]) ? $data["player_info"]["name"] : 'KHÔNG TỒN TẠI';
$idrank = isset($data["player_info"]["rank"]) ? $data["player_info"]["rank"] : null;
$rankconfig = isset($data["rank_config"]) ? $data["rank_config"] : [];
$rankName = 'KHÔNG XÁC ĐỊNH';
$tcid = isset($data['player_info']['player_uid']) ? explode("_", $data['player_info']['player_uid'])[0] : null;
if (array_key_exists($idrank, $rankconfig)) {
    $rankName = $rankconfig[$idrank]['name'];
}

$ch = curl_init($redirect_uri);
curl_setopt_array($ch, [
    CURLOPT_COOKIEJAR => dirname(__FILE__) . "/cookie/{$username}.txt",
    CURLOPT_COOKIEFILE => dirname(__FILE__) . "/cookie/{$username}.txt",
    CURLOPT_HEADER => true,
    CURLOPT_TCP_NODELAY => true,
    CURLOPT_NOSIGNAL => true,  
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_ENCODING => 'gzip, deflate',
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_TIMEOUT => 10,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_2_0
]);

$http_response = curl_exec($ch);

curl_close($ch);

preg_match('/session\.sig=([^;]+)/', $http_response, $matches);
$sessionsig = $matches[1] ?? null;

preg_match('/session=([^;]+)/', $http_response, $matches);
$session = $matches[1] ?? null;

$head = array(
    'Cookie: session=' . $session . '; session.sig=' . $sessionsig,
    'User-Agent: Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Mobile Safari/537.36',
    'Content-Type: application/json', 
    'Accept: application/json'  
);

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => "https://kientuong.lienquan.garena.vn/api/player/get",
    CURLOPT_COOKIEJAR => dirname(__FILE__) . "/cookie/{$username}.txt",
    CURLOPT_COOKIEFILE => dirname(__FILE__) . "/cookie/{$username}.txt",
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TCP_NODELAY => true,
    CURLOPT_NOSIGNAL => true,  
    CURLOPT_ENCODING => 'gzip, deflate',
    CURLOPT_TIMEOUT => 10,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_HTTPHEADER => $head,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_2_0
]);
$json_data = curl_exec($ch);
curl_close($ch);
$data = json_decode($json_data, true);
$level = isset($data['player']['level']) ? $data['player']['level'] : '0';
$timeregacc = isset($data['player']['registerTime']) ? date('H:i:s d-m-Y', $data['player']['registerTime']) : 'KHÔNG XÁC ĐỊNH';
if(isset($data['player']['banInfo'])){
    $band = "YES";    
}else{
    $band = "NO";  
}
$lsnap = _check_ls_Nap($username);
if (file_exists(dirname(__FILE__) . "/cookie/".$username.".txt")) {
    unlink(dirname(__FILE__) . "/cookie/".$username.".txt");
}      

die(json_encode([
    'status' => 'success',
    'data' => [
        'username'  => $username,
        'password'  => $password,
        'name'  => $name,
        'level'  => $level,
        'rank'  => $rankName,
        'qh'    => $qh,
	    'lsnap' => $lsnap,
	    'so'    => $so,
	    'acc_country' => $acccountry,
	    'lslogin' => $lslogin,
        'skin'  => $skin,
        'tuong' => $countUnique,
        'cmnd'  => $cmnd,
        'email' => $email_v,
        'ttemail'   => $ttemail,
        'authen' => $authen,
        'sdt'   => $mobile_no,
        'fb'    => $lkfb,
        'band'    => $band,
        'timeregacc' => $timeregacc,
        'ss'    => $ss,
        'listskinss' => !empty($ssSkins) ? implode(', ', $ssSkins) : 'NO SS',
        'sss'   => $sss,
        'listskinsss' => !empty($sssSkins) ? implode(', ', $sssSkins) : 'NO SSS',
        'anime' => $anime,
        'listskinanime' => !empty($animeSkins) ? implode(', ', $animeSkins) : 'NO ANIME',
        'tt'    => $infoStatus,
    ],
    'author' => 'Le Huy',
    'telegram'  => ''
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}
}else{
    goto run;
}
}else{
    http_response_code(403);
}

function _check_ls_Nap($tk){
$a = 0;
$b = 0;
$ls = 0;
$tep = '/cookie/'.$tk.'.txt';
$check1  = curl("https://auth.garena.com/oauth/token/grant", 'client_id=10017&redirect_uri=https%3A%2F%2Fnapthe.vn%2Fapp&response_type=token&platform=1&locale=vi-VN&theme=mshop_iframe_white&format=json&id=1654048860433&app_id=10017', '', dirname(__FILE__) . $tep, dirname(__FILE__) . $tep);
$check  = curl("https://napthe.vn/api/auth/inspect_token", '{"token":"'.json_decode($check1[0], true) ["access_token"].'"}', '', dirname(__FILE__) . $tep, dirname(__FILE__) . $tep);
$check2  = curl("https://napthe.vn/api/shop/history?app_id=100054&start_ts=".strtotime("-60 days")."&end_ts=".strtotime("now")."&region=VN&language=vi&limit=20&offset=0", '', '', dirname(__FILE__) . $tep, dirname(__FILE__) . $tep,array('Cookie: '.get_string_between($check[0],'Set-Cookie:',';').''));
if (stristr($check2[1],'display_id')){
$data = json_decode($check2[1],true);
while (isset($data["items"][$a++]["point_amount"])) {
    $ls += $data["items"][$b++]["point_amount"];
}
}else{
$ls = 'NO';
}
return $ls;
}

function curl($url,$post = false,$ref = '', $cookie = false,$cookies = false,$header = false,$headers = false,$follow = false,$proxy = false)
{
global $key,$u,$p;
    $ch=curl_init($url);
    if($ref != '') {
        curl_setopt($ch, CURLOPT_REFERER, $ref);
    }
    if($cookie){
    curl_setopt($ch, CURLOPT_COOKIE, $cookie);
    }
    if($cookies)
    {
    curl_setopt($ch, CURLOPT_COOKIEJAR, $cookies);
    curl_setopt($ch, CURLOPT_COOKIEFILE, $cookies);
    }
    if($post){
    curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
    curl_setopt($ch, CURLOPT_POST, 1);
    }
    if($follow) curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    if($header)     curl_setopt($ch, CURLOPT_HEADER, 1);
    if($headers)        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_ENCODING, '');
    
    
    //curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($ch, CURLOPT_TIMEOUT, 15);

        //curl_setopt($ch, CURLINFO_HEADER_OUT, true);
    $result[0] = curl_exec($ch);
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $result[1] = substr($result[0], $header_size);
    curl_close($ch);
    return $result;

}
function get_string_between($string, $start, $end){
    $string = ' ' . $string;
    $ini = strpos($string, $start);
    if ($ini == 0) return '';
    $ini += strlen($start);
    $len = strpos($string, $end, $ini) - $ini;
    return substr($string, $ini, $len);
}
?>