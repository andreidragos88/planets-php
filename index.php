<?php
$method = $_SERVER['REQUEST_METHOD'];
if ($method == "OPTIONS") {
header('Access-Control-Allow-Origin: *');
header("Access-Control-Allow-Headers: X-API-KEY, Origin, X-Requested-With, Content-Type, Accept, Access-Control-Request-Method,Access-Control-Request-Headers, Authorization");
header("HTTP/1.1 200 OK");
die();
}
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: *");
header("Access-Control-Allow-Methods: *");
header('Content-type: application/json');
//header('Access-Control-Allow-Credentials', 'true');

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

$requestBody = file_get_contents('php://input');
$_POST = json_decode($requestBody,true);

$request = explode ("/", substr ($_SERVER ['REQUEST_URI'], 1));
if (!isset($request[2]))
	$request[2] = 'index';
$db = json_decode(file_get_contents("db.json"),true);
$response = [
	'status' => 0,
	'message' => '',
	'result' => []
];

switch ($request[1]) {
	case 'users':
		switch ($request[2]) {
			case 'token':
				$httpCode = 401;
				$response['status'] = $httpCode;
				foreach ($db['users'] as $key => $value) {
					if ($value['username'] == $_POST['username'] && $value['password'] == $_POST['password']) {
						$response['result']['token'] = $value['token'];
						$httpCode = 200;
						$response['status'] = $httpCode;
						break;
					}
				}
				break;
			
			case 'is-captain':
				$httpCode = 401;
				$response['status'] = $httpCode;
				if (isCaptain()) {
					$httpCode = 200;
					$response['status'] = $httpCode;
				}

				break;
			default:
				# code...
				break;
		}
		break;
	
	case 'planets':
		if (getBearerToken() == null) {
			$httpCode = 401;
			$response['status'] = $httpCode;
		} else {
			switch ($request[2]) {
				case is_numeric($request[2]):
					if (isCaptain() === false) {
						$httpCode = 403;
						$response['status'] = $httpCode;
						break;
					}
					if ($_SERVER['REQUEST_METHOD'] == "POST") {
						foreach ($db['planets'] as $key => $value) {
							if ($value['id'] == $request[2]) {
								$db['planets'][$key]['status'] = $_POST['status'];
								$db['planets'][$key]['description'] = $_POST['description'];
								file_put_contents('db.json', json_encode($db));
								$httpCode = 200;
								$response['status'] = $httpCode;
								break;
							}
						}

					}

					if ($_SERVER['REQUEST_METHOD'] == "GET") {
						$httpCode = 404;
						foreach ($db['planets'] as $key => $value) {
							if ($value['id'] == $request[2]) {
								$response['result'] = $value;
								$httpCode = 200;
								$response['status'] = $httpCode;
								break;
							}
						}
					}
					break;

				case 'index':
					$httpCode = 200;
					$isCaptain = isCaptain();
					$response['status'] = $httpCode;
					$response['result'] = array('editable' => $isCaptain, 'planets' => $db['planets']);
					break;
				
				default:
					# code...
					break;
			}
		}
	default:
		# code...
		break;
}

http_response_code($httpCode);
echo json_encode($response);


/** 
 * Get header Authorization
 * */
function getAuthorizationHeader(){
    $headers = null;
    if (isset($_SERVER['Authorization'])) {
        $headers = trim($_SERVER["Authorization"]);
    }
    else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
        $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
    } elseif (function_exists('apache_request_headers')) {
        $requestHeaders = apache_request_headers();
        // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
        $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
        //print_r($requestHeaders);
        if (isset($requestHeaders['Authorization'])) {
            $headers = trim($requestHeaders['Authorization']);
        }
    }
    return $headers;
}

/**
 * get access token from header
 * */
function getBearerToken() {
    $headers = getAuthorizationHeader();
    // HEADER: Get the access token from the header
    if (!empty($headers)) {
        if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
            return $matches[1];
        }
    }
    return null;
}

function isCaptain() {
	global $db;

	$token = getBearerToken();
	if ($token != null) {
		foreach ($db['users'] as $key => $value) {
			if ($value['token'] == $token && $value['type'] == 2) {
				return true;
			}
		}
	}
	return false;
}
?>