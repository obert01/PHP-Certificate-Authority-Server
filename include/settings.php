<?PHP

// Global variable that states if we are in batch mode or not
// In batch mode, the various functions don't display their progress
$batch_mode = 0;

function update_config() {
  $config['certstore_path']="/var/www/certstore/";
  // Just define here the default CA that will be displayed if none is selected
  if (empty($_SESSION['my_ca']))
    $_SESSION['my_ca'] = "Cert-IST - External Root CA";
  
  // if the session isnt configured for the config area, create a blank config array inside the session before importing the session variables into the
  // config array
  if (!isset($_SESSION['config'])) {
    $_SESSION['config']=array();
  }

  if (isset($_SESSION['my_ca']) )
    $config['ca_path'] = $config['certstore_path'].$_SESSION['my_ca']."/";
  else
    $config['ca_path'] = $config['certstore_path'].'not_defined';

  $config['req_path']=$config['ca_path'].'req/';
  $config['key_path']=$config['ca_path'].'keys/';
  $config['cert_path']=$config['ca_path'].'certs/';
  $config['crl_path']=$config['ca_path'].'crl/';
  $config['ssh_pubkey_path']=$config['ca_path'].'sshpub/';
  $config['csr_upload_path']=$config['ca_path'].'csr_upload/';
  $config['newcert_path']=$config['ca_path'].'newcerts/';
  $config['config'] = $config['ca_path']."openssl.conf";
  $config['cacert'] = $config['ca_path'] . "cacert.pem";
  $config['cakey'] = $config['ca_path'] . "cacert.key";
  $config['cacrl'] = $config['crl_path'] . "crl.pem";
  $config['index'] = $config['ca_path'] . "index.txt";
  $config['serial'] = $config['ca_path'] . "serial";
  $config['blank_dn']=array(
    'CN'=>"Common Name",
    'emailAddress'=>"Email Address",
    'OU'=>"Organizational Unit",
    'O'=>"Organization",
    'C'=>"Country",
  );
  $config['convert_dn']=array(
    'CN'=>"commonName",
    'emailAddress'=>"emailAddress",
    'OU'=>"organizationalUnitName",
    'O'=>"organizationName",
    'L'=>"localityName",
    'ST'=>"stateOrProvinceName",
    'C'=>"countryName"
  );
  $config['v3_req_properties'] = array(
      "client_cert" => "basicConstraints = critical,CA:FALSE\nkeyUsage = critical,nonRepudiation,digitalSignature,keyEncipherment\nextendedKeyUsage = critical,clientAuth,emailProtection",
      "server_cert" => "basicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature, keyEncipherment\nextendedKeyUsage = critical,serverAuth",
      "msdc_cert" => "basicConstraints = critical,CA:FALSE\nkeyUsage = critical,nonRepudiation, digitalSignature, keyEncipherment\nextendedKeyUsage = critical,clientAuth,serverAuth",
      "ca_cert" => "basicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign, cRLSign",
      "subca_cert" => "basicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign, cRLSign",
      "8021x_client_cert" => "basicConstraints = critical,CA:FALSE\nextendedKeyUsage = 1.3.6.1.5.5.7.3.2",
      "8021x_server_cert" => "basicConstraints = critical,CA:FALSE\nextendedKeyUsage = 1.3.6.1.5.5.7.3.1");
  if (is_file($config['cacert']) ) {
    $data = openssl_x509_parse(file_get_contents($config['cacert']));
    if (isset($data['subject']['CN'])) {$config['common'] = $data['subject']['CN'];}
    if (isset($data['subject']['OU'])) {$config['orgunit'] = $data['subject']['OU'];}
    if (isset($data['subject']['O'])) {$config['orgName'] = $data['subject']['O'];}
    if (isset($data['subject']['emailAddress'])) {$config['contact'] = $data['subject']['emailAddress'];}
    if (isset($data['subject']['L'])) {$config['city'] = $data['subject']['L'];}
    if (isset($data['subject']['ST'])) {$config['state'] = $data['subject']['ST'];}
    if (isset($data['subject']['C'])) {$config['country'] = $data['subject']['C'];}
  }
  include_once("config.inc.php");
  credentials($config);
  return $config;
}

?>
