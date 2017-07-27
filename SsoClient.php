<?php

/* 
 * This client is designed to simplify interactions between brokers and the SSO. 
 * 
 * If you require further help, or wish to report a bug fix, please email support@irap.org
 * 
 */

namespace iRAP\SsoClient;

require_once __DIR__ . '/bootstrap.php';

class SsoClient
{
 
    private $m_broker_id;
    private $m_broker_secret;
    private $m_logged_in;
    
    /**
     * Create the SSO client object by supplying the broker id and broker secret.
     * 
     * @param type $broker_id
     * @param type $broker_secret
     */
    public function __construct($broker_id, $broker_secret)
    {
        $this->m_broker_id = $broker_id;
        $this->m_broker_secret = $broker_secret;
        $this->m_logged_in = false;
    }
    
    /**
     * This method should be called when a user needs to login via the SSO. The browser will be
     * redirected to the SSO, and then returned to this method once the login is complete. The
     * method will check the response details and, if valid, will return an object containing the
     * user details, for the developer to save into a session.
     * 
     * @param array $returnData - an array of data to be returned back to the client
     * @return object - an object containing the details of the user who has successfully logged in
     */
    public function login($returnData = null)
    {
        $get = filter_input_array(INPUT_GET);
    
        if (isset($get['user_data']))
        {
            $decodedUserJsonData = urldecode($get['user_data']);
            $userDataArray = json_decode($decodedUserJsonData, true);

            if (!$this->checkRequiredLoginParams($userDataArray))
            {
                $this->redirectToSSO($returnData);
            }
        }
        else 
        {
            $this->redirectToSSO($returnData);
        }

        if ($this->isValidSignature($userDataArray))
        {
            $session_id = $this->generateSessionId($userDataArray['user_id']);
            
            $response = new SsoObject(
                $session_id, 
                $userDataArray['user_id'], 
                $userDataArray['expires'], 
                $userDataArray['user_name'], 
                $userDataArray['user_email'],
                json_decode(urldecode($userDataArray['return_data']), true)
            );     
            
            $this->m_logged_in = true;
        }
        else
        {
            # Invalid request (hack?), redirect the user back to sign in.
            $response = new \stdClass();
            $response->status = 'Error';
            $response->code = '401';
            $response->error = 'Invalid signature returned by the SSO';
        }
        
        return $response;
    }
    
    /**
     * This method redirects the browser to the logout page on the SSO, to trigger a logout. The
     * developer should destroy the user's local session, before they call this method.
     */
    public function logout()
    {
        $params = array('broker_id' => $this->m_broker_id);
        
        if (defined('\iRAP\SsoClient\IRAP_SSO_URL'))
        {
            $url = \iRAP\SsoClient\IRAP_SSO_URL;
        }
        else
        {
            $url = \iRAP\SsoClient\IRAP_SSO_LIVE_URL;
        }
        
        header("Location: " . $url . "/logout?" . http_build_query($params));
        die();
    }
    
    /**
     * Method is called as a web hook, that needs to be accessible from the SSO. When the user
     * logs out of their account on the SSO, a message is sent to all brokers, instructing them to
     * kill the session. This method validates that request and returns an object containing the 
     * expected session id of the session to destroy. It is up to the developer to handle the
     * destruction of the session itself.
     * 
     * @return \stdClass
     * @throws type
     * @throws \Exception
     */
    public function logoutWebhook()
    {
        try
        {
            $get = filter_input_array(INPUT_GET);
            
            if (isset($get['data']))
            {
                $decodedUserJsonData = urldecode($get['data']);
                $dataArray = json_decode($decodedUserJsonData, true);

                if (!$this->checkRequiredLogoutParams($dataArray))
                {
                    print_r($dataArray);
                    throw new \Exception("Missing required parameter");
                }

                if (!$this->checkRequestExpiry($dataArray['time']))
                {
                    throw new \Exception("Request is out of date.");
                }

                # Check the signature is valid (so we know request actually came from sso.irap.org)
                if ($this->isValidSignature($dataArray))
                {
                    $session_id = $this->generateSessionId($dataArray['user_id']);
                    
                    $response = new \stdClass();
                    $response->session_id = $session_id;
                    $response->user_id = $dataArray['user_id'];
                    
                    $responseArray = array(
                        "result"  => "success",
                        "message" => "User session identified"
                    );
                    
                }
                else
                {
                    # Invalid request (hack?), redirect the user back to sign in.
                    throw new \Exception("Invalid signature.");
                }
            }
            else 
            {
                throw new \Exception("Missing required data parameter");
            }
            
        }
        catch (\Exception $e)
        {
            $responseArray = array(
                "result"  => "error",
                "message" => $e->getMessage()
            );
        }

        print json_encode($responseArray);
        
        if (isset($response))
        {
            return $response;
        }
    }
    
    /**
     * Returns true if login was successful or false if not.
     * 
     * @return boolean
     */
    public function loginSuccessful()
    {
        return $this->m_logged_in;
    }
    
    /**
     * Alias of login, used to handle the keep awake requests, but identical in form.
     * 
     * @param array $returnData - an array of data to be returned back to the client
     * @return SsoObject
     */
    public function renewSSOSession($returnData = null)
    {
        return $this->login($returnData);
    }
    
    /**
     * This method redirects the browser to the SSO. It is called by the login() method when valid
     * login credentials are not found and by the user when keeping the SSO session alive.
     * 
     * @param array $returnData - an array of data to be returned back to the client
     * 
     */
    private function redirectToSSO($returnData = null)
    {
        $params = array('broker_id' => $this->m_broker_id);
        
        if (defined('\iRAP\SsoClient\IRAP_SSO_URL'))
        {
            $url = \iRAP\SsoClient\IRAP_SSO_URL;
        }
        else
        {
            $url = \iRAP\SsoClient\IRAP_SSO_LIVE_URL;
        }
        
        if (is_array($returnData))
        {
            $jsonData = json_encode($returnData, JSON_UNESCAPED_SLASHES);
            $urlData = urlencode($jsonData);
            $params['return_data'] = $urlData;
        }
        
        header("Location: " . $url . "?" . http_build_query($params));
        die();
    }
    
    /**
     * Checks the parameters received from the SSO against a list of expected params, stored in the
     * packages defines.php file. If a parameter is missing, it will return false. Otherwise it will
     * return true.
     * 
     * @param array $params
     * @return boolean
     */
    private function checkRequiredLoginParams($params)
    {
        $passed = true;
        
        foreach (\iRAP\SsoClient\Settings::EXPECTED_SSO_LOGIN_PARAMS as $expectedParam)
        {
            
            if (!isset($params[$expectedParam]))
            {
                $passed = false;
                break;
            }
            
        }
        
        return $passed;
    }
    
    /**
     * Checks the parameters received from the SSO against a list of expected params, stored in the
     * packages defines.php file. If a parameter is missing, it will return false. Otherwise it will
     * return true.
     * 
     * @param array $params
     * @return boolean
     */
    private function checkRequiredLogoutParams($params)
    {
        $passed = true;
        
        foreach (\iRAP\SsoClient\Settings::EXPECTED_SSO_LOGOUT_PARAMS as $expectedParam)
        {
            
            if (!isset($params[$expectedParam]))
            {
                $passed = false;
                break;
            }
            
        }
        
        return $passed;
    }
    
    /**
     * Checks the timestamp returned from the SSO, to ensure that the request has been made recently
     * enough to be valid. This is to guard against replay attacks. The acceptable age of the
     * request can be found in the defines
     * 
     * @param timestamp $timestamp
     * @return boolean
     */
    private function checkRequestExpiry($timestamp)
    {
        $passed = true;
        date_default_timezone_set('UTC'); 

        if (microtime($get_as_float=true) - $timestamp > \iRAP\SsoClient\IRAP_SSO_REQUEST_MAX_AGE)
        {
            $passed = false;
        }
        
        return $passed;
    }
    
    /**
     * Check whether the user details sent to us came from
     * the SSO service without being modified.
     * @param $dataArray - array of name/value pairs in the received data
     */
    private function isValidSignature($dataArray)
    {
        if (!isset($dataArray['signature']))
        {
            throw new Exception("Missing signature");
        }

        $recievedSignature = $dataArray['signature'];
        unset($dataArray['signature']);
        ksort($dataArray);
        $jsonString = json_encode($dataArray);
        $generatedSignature = hash_hmac('sha256', $jsonString, $this->m_broker_secret);

        return ($generatedSignature === $recievedSignature);
    }
    
    /**
     * Generate a session ID to use for a given user_id. We need to do this so
     * that we can figure out which file to destroy (to destroy the session) for
     * the appropriate user when we get a logout request for a specific user ID.
     * @param int $user_id - the ID of the user we are generating a session ID for.
     */
    private function generateSessionId($user_id)
    {
        return hash_hmac('sha256', $user_id, $this->m_broker_secret);
    }
}