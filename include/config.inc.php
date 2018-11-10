<?php

function credentials(&$config)
{
	$password["Cert-IST - External Root CA"] = "xxxxxx";
	$password["Cert-IST - Legacy Root CA"] = "xxxxxx";

	if (!empty($config['common']))
		$config['capassword'] = $password[$config['common']];
}

?>
