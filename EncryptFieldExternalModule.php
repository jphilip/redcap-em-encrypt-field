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

class EncryptFieldExternalModule extends AbstractExternalModule
{
    private $pub_key = "";
    private $encrypted_str = "Encrypted field (cannot be modified)";

    public function __construct()
    {
        parent::__construct();
    }

    public function encrypt_field($data)
    {
        if ($this->pub_key === "") {
            $this->pub_key = $this->getProjectSetting('public-key');
        }

        $sealed = $e = null;
        $iv = openssl_random_pseudo_bytes(32);
        openssl_seal($data, $sealed, $e, array($this->pub_key), "AES-256-CBC", $iv);

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

    public function redcap_data_entry_form($project_id, $record, $instrument, $event_id, $group_id, $repeat_instance)
    {
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
            $js = "<script type='text/javascript'>\n";
            foreach ($enc_fields as $enc_field) {
                $dec_str = "'{$this->encrypted_str}'";
                $js .= "\$('[name=${enc_field["field_name"]}]').prop('readonly', true);\n";
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
        if (strtoupper($_SERVER['REQUEST_METHOD']) == 'POST') {
            // Survey options page om POST
            if (strtolower(PAGE) === "surveys/edit_info.php" && isset($_GET['page'])) {
                if ($_POST["save_and_return"] != "0" && $this->CheckEncForm($_GET['page'])) {
                    $_POST["save_and_return"] = "0";
                    $_POST["save_and_return_code_bypass"] = "0";
                    $_POST["edit_completed_response"] = "0";
                }
                // Survey on POST
            } elseif (strtolower(PAGE) === 'surveys/index.php' && isset($_GET['s'])) {
                $hash = $_GET['s'];
                $sql = "select s.*, h.* from redcap_surveys s, redcap_surveys_participants h, redcap_metadata m
                where h.hash = '".db_escape($hash)."' and s.survey_id = h.survey_id and m.project_id = s.project_id 
                and m.form_name = s.form_name and h.event_id is not null limit 1";
                $q = db_query($sql);
                $res = db_fetch_assoc($q);
                if (!$res) {
                    return;
                }
                $survey_id = $res["survey_id"];
                $form_name = $res["form_name"];
                $event_id = $res["event_id"];
                $save_and_return = $res["save_and_return"];
                if (!$this->CheckEncForm($form_name)) {
                    return;
                }

                $fields = REDCap::getDataDictionary('array', false, true, $form_name);

                foreach ($fields as $this_field) {
                    if (in_array($this_field["field_type"], array("text", "notes")) && strpos($this_field['field_annotation'], "@ENCRYPT_FIELD") !== false) {
                        $_POST[$this_field["field_name"]] =  $this->encrypt_field($_POST[$this_field["field_name"]]);
                    }
                }
                // Data entry form on POST
            } elseif (strtolower(PAGE) === 'dataentry/index.php') {
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
                        unset($_POST[$this_field['field_name']]);
                    }
                }
            }
        }
    }
}
