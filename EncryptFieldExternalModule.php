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

class EncryptFieldExternalModule extends AbstractExternalModule {

  private $pub_key = "";

  public function __construct() {
    parent::__construct();
  }

  function encrypt_field($data) {
    if ($this->pub_key === "") {
      $this->pub_key = $this->getProjectSetting('public-key');
    }

    $sealed = $e = NULL;
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

  function redcap_every_page_before_render ($project_id){
    if (PAGE !== "surveys/index.php") {
      return;
    }

    if ($_SERVER['REQUEST_METHOD'] == "POST" && isset($_GET['s'])) {
      $hash = $_GET['s'];
      $sql = "select s.*, h.* from redcap_surveys s, redcap_surveys_participants h, redcap_metadata m
                where h.hash = '".db_escape($hash)."' and s.survey_id = h.survey_id and m.project_id = s.project_id 
                and m.form_name = s.form_name and h.event_id is not null limit 1";
      $q = db_query($sql);
      $res = db_fetch_assoc($q);
      if (!$res)
        return;
      $survey_id = $res["survey_id"];
      $form_name = $res["form_name"];
      $event_id = $res["event_id"];

      $forms = $this->getProjectSetting('project-form-list');
      if (!is_array($forms) || count($forms) == 0) {
        return;
      }

      $enc_form = false;
      foreach($forms as $form) {
        if ($form === $form_name) {
          $enc_form = true;
          break;
        }
      }

      if (!$enc_form) {
        return;
      }

      $fields = REDCap::getDataDictionary('array', false, true, $form_name);

      foreach ($fields as $this_field) {
        if(in_array($this_field["field_type"], array("text", "notes")) && strpos($this_field['field_annotation'], "@ENCRYPT_FIELD") !== false) {
          $_POST[$this_field["field_name"]] =  $this->encrypt_field($_POST[$this_field["field_name"]]);
        }
      }      
    }
  }

}