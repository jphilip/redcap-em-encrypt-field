<?php
/**
* REDCap External Module: EncryptField
* Action tag to encrypt text fields is @ENCRYPT_FIELD.
* The form holding the tagged field also has to be neabled in the module's project options
 * An RSA public key also has to be uploaded in the module's project options
* Decryption is not done by REDCap at the moment, but R functions are provided to decrypt data
* @author Jacques Philip, Center for Alaska Native Health Research, University of Alaska Fairbanks
*/

namespace CANHR\EncryptFieldExternalModule;

use ExternalModules\AbstractExternalModule;
use ExternalModules\ExternalModules;
use REDCap;
use Records;

class EncryptFieldExternalModule extends AbstractExternalModule
{
    private $pub_key = '';
    private $encrypted_str = "Please load private key to decrypt data";

    public function __construct()
    {
        parent::__construct();
    }

    private function EncryptField($data)
    {
        if ($this->pub_key === '') {
            $this->pub_key = $this->getProjectSetting('public-key');
        }

        $sealed = $e = null;
        $iv = openssl_random_pseudo_bytes(32);
        openssl_seal($data, $sealed, $e, array( $this->pub_key ), 'AES-256-CBC', $iv);

        $payload = base64_encode($sealed);
        $token = base64_encode($e[0]);
        $iv = base64_encode($iv);

        $j = new \stdClass();
        $j->payload = $payload;
        $j->token = $token;
        $j->iv = $iv;
        $json = json_encode($j, JSON_UNESCAPED_SLASHES);
        return($json);
    }

    private function DecryptField($data, $priv_key)
    {
        $sealed = json_decode($data);

        $token = base64_decode($sealed->token);
        $payload = base64_decode($sealed->payload);
        $iv = base64_decode($sealed->iv);
        $unsealed = null;
        $pkeyid = openssl_get_privatekey($priv_key);
        $result = openssl_open($payload, $unsealed, $token, $pkeyid, 'AES-256-CBC', $iv);
        // free the private key from memory ( although it stays in Apcu cache until it times out. )
        openssl_free_key($pkeyid);
        return($result ? $unsealed : false);
    }

    public function TestPrivateKey($priv_key)
    {
        $plain = 'Test data to encrypt';
        $enc = $this->EncryptField($plain);
        return $this->DecryptField($enc, $priv_key) === $plain;
    }

    public function redcap_data_entry_form($project_id, $record, $instrument, $event_id, $group_id, $repeat_instance)
    {
        if (!$this->getProjectSetting('enable-decryption')) {
            return;
        }

        if (!$this->CheckEncForm($instrument)) {
            return;
        }

        $fields = \REDCap::getDataDictionary('array', false, true, $instrument);

        $enc_fields = array();
        foreach ($fields as $this_field) {
            if (in_array($this_field['field_type'], array( 'text', 'notes' )) && strpos($this_field['field_annotation'], '@ENCRYPT_FIELD') !== false) {
                $enc_fields[] = $this_field;
            }
        }
        if (count($enc_fields) > 0) {
            $priv_key = false;
            $apcu_key = session_id() . "_" . USERID;
            if (apcu_exists($apcu_key) && $this->TestPrivateKey(apcu_fetch($apcu_key))) {
                $priv_key = apcu_fetch($apcu_key);
                # Extend ttl in apcu
                apcu_store($apcu_key, $priv_key, intval($this->getProjectSetting('private-key-ttl')) * 60);
                $enc_data = Records::getData($project_id, "array", $record, array_column($enc_fields, "field_name"), $event_id, $group_id);
                $enc_data = $enc_data[$record][$event_id];
            }
            
            $js = "<script type='text/javascript'>\n";
            foreach ($enc_fields as $enc_field) {
                if ($priv_key) {
                    $dec_str = json_encode($this->DecryptField($enc_data[$enc_field["field_name"]], $priv_key));
                } else {
                    $dec_str = "'Please load private key to decrypt data'";
                    $js .= "\$('[name=${enc_field["field_name"]}]').prop('readonly', true);\n";
                }
                $js .= "\$('[name=${enc_field["field_name"]}]').val($dec_str);\n";
            }
            $js .= "</script>";
            echo($js);
        }
    }

    private function CheckEncForm($form_name)
    {
        //Check if the current form is set for encryption
        $forms = $this->getProjectSetting('project-form-list');
        if (!is_array($forms) || count($forms) == 0) {
            return false;
        }

        $enc_form = false;
        foreach ($forms as $form) {
            if ($form === $form_name) {
                $enc_form = true;
                break;
            }
        }
        return $enc_form;
    }

    public function redcap_every_page_before_render($project_id)
    {
        if (!(strtoupper($_SERVER['REQUEST_METHOD']) === 'POST')) {
            return;
        }

        if (strtolower(PAGE) === 'surveys/index.php' && isset($_GET['s'])) {
            $hash = $_GET['s'];
            $sql = "select s.*, h.* from redcap_surveys s, redcap_surveys_participants h, redcap_metadata m
                where h.hash = '".db_escape($hash)."' and s.survey_id = h.survey_id and m.project_id = s.project_id 
                and m.form_name = s.form_name and h.event_id is not null limit 1";
            $q = db_query($sql);
            $res = db_fetch_assoc($q);
            if (!$res) {
                return;
            }
            $survey_id = $res['survey_id'];
            $form_name = $res['form_name'];
            $event_id = $res['event_id'];

            if (!$this->CheckEncForm($form_name)) {
                return;
            }

            $fields = \REDCap::getDataDictionary('array', false, true, $form_name);

            foreach ($fields as $this_field) {
                if (in_array($this_field['field_type'], array( 'text', 'notes' )) && strpos($this_field['field_annotation'], '@ENCRYPT_FIELD') !== false) {
                    $_POST[$this_field['field_name']] =  $this->EncryptField($_POST[$this_field['field_name']]);
                }
            }
        } elseif ($this->getProjectSetting('enable-decryption') && strtolower(PAGE) === 'dataentry/index.php') {
            $pid = $_GET["pid"];
            $event_id = $_GET["event_id"];
            $form_name = $_GET["page"];
            $instance = $_GET["instance"];

            if (!$this->CheckEncForm($form_name)) {
                return;
            }

            $fields = \REDCap::getDataDictionary('array', false, true, $form_name);

            foreach ($fields as $this_field) {
                if (in_array($this_field['field_type'], array( 'text', 'notes' )) && strpos($this_field['field_annotation'], '@ENCRYPT_FIELD') !== false) {
                    if ($_POST[$this_field['field_name']] !== $this->encrypted_str) {
                        $_POST[$this_field['field_name']] =  $this->EncryptField($_POST[$this_field['field_name']]);
                    } else {
                        unset($_POST[$this_field['field_name']]);
                    }
                }
            }
        }
    }
}
