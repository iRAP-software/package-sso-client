<?php

/* 
 * List of defines to use in the ViDA SDK
 */
namespace iRAP\SsoClient;

# URL for the live SSO
define(__NAMESPACE__ . '\IRAP_SSO_LIVE_URL', 'https://sso.irap.org');

# Acceptable age for logout requests
define(__NAMESPACE__ . '\IRAP_SSO_REQUEST_MAX_AGE', 3);

class Settings 
{
    # This requires PHP 5.6+
    # When we move over to PHP 7, we will be able to put this array in a define and
    # remove the Settings class.
    const EXPECTED_SSO_LOGIN_PARAMS = array(
        'user_id',
        'signature'
    );
    
    # This requires PHP 5.6+
    # When we move over to PHP 7, we will be able to put this array in a define and
    # remove the Settings class.
    const EXPECTED_SSO_LOGOUT_PARAMS = array(
        'user_id',
        'signature'
    );
}



