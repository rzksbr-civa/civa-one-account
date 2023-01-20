<?php
declare(strict_types=1);

namespace CIVA\SSO;

class SSO
{
    protected $config;
    private $apiKey;
    private $apiSecret;
    protected $cipher;
    private $passphrase;
    protected $error;
    protected $warning;

    public function __construct($apiKey, $secret, $config = [])
    {
        $this->apiKey = $apiKey;
        $this->apiSecret = $secret;
        $this->config = (object) array_merge([
            'ignore_warning' => false,
            'ignore_device' => true,
            'ignore_ip' => true,
            'ignore_token' => false,
            'debug' => false,
        ], $config);
        $this->cipher = 'aes-128-cbc';
        $this->passphrase = 'accounts.civa.tech';
    }

    public function setConfig($config, $value = '')
    {
        if (is_array($config)) {
            $this->config = (object) array_merge((array) $this->config, $config);
        } else {
            $this->config->$config = $value;
        }
    }

    protected function request($uri, $params = [], $data = [], $token = '')
    {
        $curl = curl_init();
        if ($this->config->debug) {
            $params['debug'] = true;
        }

        $url = "https://accounts.civa.tech/{$uri}/?" . http_build_query($params);

        $meta = json_encode([
            'refresh_token' => $_COOKIE['SSO_REFRESH_TOKEN'] ?? null,
        ]);

        $defaultPost = [
            'meta' => $this->encrypt($meta),
            'data' => $this->encrypt(json_encode($data)),
        ];
        
        $options =  [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 0,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => $defaultPost,
            CURLOPT_USERAGENT => $_SERVER['HTTP_USER_AGENT'] ?? '',
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $token,
            ],
        ];
        
        curl_setopt_array($curl, $options);

        $response = curl_exec($curl);

        if ($this->config->debug) {
            echo $response;
            exit;
        }

        if (curl_errno($curl)) {
            curl_close($curl);
            throw new \Exception(curl_error($curl));
        } else {
            curl_close($curl);
            try{
                $response = json_decode($response);
                if ($response->refresh_token) {
                    setcookie('SSO_REFRESH_TOKEN', $response->refresh_token, strtotime('+1day'));
                }
                if(isset($response->data)){
                    $dec_data = $this->decrypt($response->data);
                    $response->data = json_decode($dec_data);
                }
                return $response;
            }
            catch(\Exception $e){
                throw new \Exception($e->getMessage());
            }
        }
    }

    public function verify($token)
    {
        try {
            $response = $this->request('sso-verify', [], ['action' => 'login'], $token);
            if (isset($response->error)) {
                $this->error = $response->error;
            } elseif (isset($response->warning)) {
                $this->warning = $response->warning;
                if ($this->config->ignore_warning == false) { {
                        if (
                            ($response->warning == 'DEVICE MISMATCH' && $this->config->ignore_device == false) ||
                            ($response->warning == 'IP MISMATCH' && $this->config->ignore_ip == false) ||
                            ($response->warning == 'TOKEN MISMATCH' && $this->config->ignore_token == false)
                        ) {
                            $this->error = 'ACTIVE LOGIN FOUND, BUT ' . $response->warning;
                        }
                    }
                }
            }
            if (!$this->error && isset($response->data)) {
                return $response->data;
            } else {
                throw new \Exception($this->error);
            }
        } catch (\Exception $e) {
            throw new \Exception($e->getMessage());
        }
    }

    public function url()
    {
        $params['tok'] = $this->encrypt($this->passphrase . '|' . time());
        $params['key'] = $this->apiKey;
        $params['ts'] = time();
        return 'https://accounts.civa.tech/login-project?' . http_build_query($params);
    }

    protected function encrypt($plainText)
    {
        if (!function_exists('openssl_encrypt')) {
            throw new \Exception('openssl not found');
        }
        if (in_array($this->cipher, openssl_get_cipher_methods())) {
            $ivlen = openssl_cipher_iv_length($this->cipher);
            $iv = substr(hash('sha256', $this->apiSecret), 0, $ivlen);
            $encryptedText = openssl_encrypt($plainText, $this->cipher, $this->apiSecret, OPENSSL_RAW_DATA, $iv);
            return base64_encode($encryptedText);
        } else {
            throw new \Exception('cipher not found');
        }
    }

    protected function decrypt($encryptedText)
    {
        if (!function_exists('openssl_decrypt')) {
            throw new \Exception('openssl not found');
        }
        if (in_array($this->cipher, openssl_get_cipher_methods())) {
            $ivlen = openssl_cipher_iv_length($this->cipher);
            $iv = substr(hash('sha256', $this->apiSecret), 0, $ivlen);
            $decryptedText = openssl_decrypt(base64_decode($encryptedText), $this->cipher, $this->apiSecret, OPENSSL_RAW_DATA, $iv);
            return $decryptedText;
        } else {
            throw new \Exception('cipher not found');
        }
    }

    public function emit($event, array $data)
    {
        if (in_array($event, ['user.created', 'user.removed'])) {
            $params['tok'] = $this->encrypt($this->passphrase . '|' . time());
            $params['key'] = $this->apiKey;
            $params['ts'] = time();
            $event = base64_encode($event);
            return $this->request("webhook/{$event}", $params, $data);
        } else {
            throw new \Exception('Invalid event');
        }
    }

    public function validateRequest()
    {
        if (isset($_GET['tok'], $_GET['ts'])) {
            try {
                $token = $this->decrypt($_GET['tok']);
                $data = false;
                if (isset($_POST['data']) && $_POST['data']) {
                    $data = $this->decrypt($_POST['data']);
                    $data = @json_decode($data);
                }
                list($phrase, $timestamp) = explode('|', $token);
                $timeDiff = time() - $timestamp;
                if ($timeDiff < 300) {
                    if ($_GET['ts'] == $timestamp && $this->passphrase == $phrase) {
                        return $data;
                    }
                }
            } catch (\Exception $e) {
                return false;
            }
        }
        return false;
    }

    public function listenEvent()
    {
        try {
            $event = $_GET['event'] ?? false;
            if (!$event) {
                return false;
            }
            if ($data = $this->validateRequest()) {
                return (object) ['data' => (object) $data, 'event' => $event];
            }
            return false;
        } catch (\Exception $e) {
            return false;
        }
    }
}
