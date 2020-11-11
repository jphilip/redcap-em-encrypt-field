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
    private $incompatible_options = array("Save and return later", "e-consent framework", "One section per page without hiding back button");

    public function validateSettings($settings)
    {
        if (!isset($_GET["pid"])) {
            return;
        }

        $forms = $settings['project-form-list'];
        if (!is_array($forms) || count($forms) == 0) {
            return null;
        }
       
        $sql = "select s.* from redcap_surveys s where s.project_id = '".db_escape($_GET["pid"])."'";
        $q = db_query($sql);

        $invalid_forms = array();
        while ($survey = db_fetch_assoc($q)) {
            foreach ($forms as $enc_form) {
                if ($enc_form == $survey["form_name"]) {
                    if ($survey["save_and_return"] != "0" || $survey["pdf_auto_archive"] == "2" || ($survey["question_by_section"] == "1" &&  strtolower($survey["hide_back_button"]) != "1")) {
                        $invalid_forms[] = $enc_form;
                    }
                    continue;
                }
            }
        }
        if (!empty($invalid_forms)) {
            return("The encrypt field module is incompatible with the survey options " . implode(", ", $this->incompatible_options) . ".
The following surveys has encryption and some of those options enabled, to use encryption please disable " . implode(", and ", $this->incompatible_options) . " for each of these form:\n"
            . \implode(".\n", $invalid_forms) . ".");
        }
    }

    public function encrypt_field($data)
    {
        if ($this->pub_key === "") {
            $this->pub_key = $this->getProjectSetting('public-key');
        }

        # Concatenate a hash of the data with the data for authentication upon decryption
        $hash = openssl_digest($data, "sha256");
        $hdata = $hash . $data;

        $sealed = $e = null;
        $iv = openssl_random_pseudo_bytes(32);
        openssl_seal($hdata, $sealed, $e, array($this->pub_key), "AES-256-CBC", $iv);

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
            $js = "<script type='text/javascript'>
    // IIFE - Immediately Invoked Function Expression
    (function($, window, document) {
        // The $ is now locally scoped\n";
            foreach ($enc_fields as $enc_field) {
                $dec_str = "'{$this->encrypted_str}'";
                $js .= "        \$('[name=${enc_field["field_name"]}]').prop('readonly', true);\n";
                $js .= "        \$('[name=${enc_field["field_name"]}]').val($dec_str);\n";
            }
            $js .= "    }(window.jQuery, window, document));
    // The global jQuery object is passed as a parameter
</script>\n";
            echo($js);
        }
    }

    private function CheckEncForm($form_name)
    {
        //Check if the current form is set for encryption
        $forms = $this->getProjectSetting('project-form-list');
        return in_array($form_name, $forms);
    }

    public function redcap_every_page_before_render($project_id)
    {
        if (strtoupper($_SERVER['REQUEST_METHOD']) == 'POST') {
            // Survey options page om POST
            if (strtolower(PAGE) === "surveys/edit_info.php" && isset($_GET['page']) && $this->CheckEncForm($_GET['page'])) {
                if ($_POST["save_and_return"] != "0") {
                    $_POST["save_and_return"] = "0";
                    $_POST["save_and_return_code_bypass"] = "0";
                    $_POST["edit_completed_response"] = "0";
                }
                if ($_POST["pdf_auto_archive"] == "2") {
                    $_POST["pdf_auto_archive"] = "0";
                }
                if ($_POST["question_by_section"] != "0" &&  strtolower($_POST["hide_back_button"]) != "on") {
                    $_POST["hide_back_button"] = "on";
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
                $form_name = $_GET["page"];
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
