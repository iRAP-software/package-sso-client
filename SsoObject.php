<?php

/* 
 * Object returned by the SSO login process
 */

class SsoObject
{
    private $m_session_id;
    private $m_user_id;
    private $m_sso_expiry;
    private $m_user_name;
    private $m_user_email;
    
    public function __construct($session_id, $user_id, $sso_expiry, $user_name = null, $user_email = null)
    {
        $this->m_session_id = $session_id;
        $this->m_user_id = $user_id;

        if (is_string($user_name) && $user_name !== '')
        {
            $this->m_user_name = $user_name;
        }

        if (is_string($user_email) && $user_email !== '')
        {
            $this->m_user_email = $user_email;
        }

        if (is_int($sso_expiry))
        {
            $this->m_sso_expiry = $sso_expiry;
        }
    }
    
    public function get_session_id()    { return $this->m_session_id; }
    public function get_user_id()       { return $this->m_user_id; }
    public function get_sso_expiry()    { return $this->m_sso_expiry; }
    public function get_user_name()     { return $this->m_user_name; }
    public function get_user_email()    { return $this->m_user_email; }
    
}