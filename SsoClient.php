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
    }
    
    
    public function login()
    {
        $get = filter_input_array(INPUT_GET);
    
        if (isset($get['user_data']))
        {
            $decodedUserJsonData = urldecode($get['user_data']);
            $userDataArray = json_decode($decodedUserJsonData, true);

            if (!$this->checkRequiredLoginParams($userDataArray))
            {
                $response = $this->redirectToSSO();
            }
        }
        else 
        {
            $response = $this->redirectToSSO();
        }

        if ($this->isValidSignature($userDataArray))
        {
            $response = new \stdClass();
            $response->session_id = $this->generateSessionId($userDataArray['user_id']);
            $response->user_id = $userDataArray['user_id'];
            
            if (is_string($userDataArray['user_name']) && $userDataArray['user_name'] !== '')
            {
                $response->user_name = $userDataArray['user_name'];
            }
            
            if (is_string($userDataArray['user_email']) && $userDataArray['user_email'] !== '')
            {
                $response->user_email = $userDataArray['user_email'];
            }
            
            if (is_int($userDataArray['expires']) && $userDataArray['expires'] !== '')
            {
                $response->sso_expiry = $userDataArray['expires'];
            }
            
        }
        else
        {
            # Invalid request (hack?), redirect the user back to sign in.
            $response = $this->redirectToSSO();
        }
        
        return $response;
    }
    
    public function logout()
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
                    throw \Exception("Missing required parameter");
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
    
    
    private function redirectToSSO()
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
        
        header("Location: " . $url . "?" . http_build_query($params));
        die();
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