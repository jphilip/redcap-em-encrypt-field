<?php
/**
 * REDCap External Module: EncryptField
 * Page to enter a private key which will be keopt in memory for the session
 * @author Jacques Philip, Center for Alaska Native Health Research, University of Alaska Fairbanks
 */

$apcu_key = session_id() . "_" . USERID;
$encryptField = new \CANHR\EncryptFieldExternalModule\EncryptFieldExternalModule();
$ttl = intval($encryptField->getProjectSetting('private-key-ttl')) * 60;

function PrintKeyForm() {
    print('<form method="post" class="darkgreen" style="max-width:650px;padding:20px;">');
    print('<div><label for="key">Paste your decryption key below:</label></div>');
    print('<div><textarea name="key" id="key" cols="60" rows="30"></textarea></div>');
    print('<div style="padding-top:10px;"><button type="submit" class="btn btn-xs btn-rcgreen fs14">Continue</button></div>');
    print('</form>');
}
?>

<h2>Decryption Key Import</h2>
<?php 
if ($_SERVER['REQUEST_METHOD']=='POST') {
    $errors = array();
    if (!isset($_POST['key']) || $_POST['key']==='') {
        $errors[] = "The key cannot be empty";
    }
    else
    {
        if (!$encryptField->TestPrivateKey($_POST['key'])) {
            $errors[] = "Invalid decription key.";
        }
    }

    if (!empty($errors)) {
        $_SESSION["crypt_key_import_error"] = $errors;
        apcu_delete($apcu_key);
        if (isset($_SESSION["crypt_key_import_success"])) {
            unset($_SESSION["crypt_key_import_success"]);
        }
    }        
    else {
        if (isset($_SESSION["crypt_key_import_error"])) {
            unset($_SESSION["crypt_key_import_error"]);
        }
        $_SESSION["crypt_key_import_success"] = 1;
        apcu_store($apcu_key, trim($_POST['key']), $ttl);
    }
    header("Location: " . $encryptField->getUrl("key.php"));        
}
else
{
    if (isset($_SESSION["crypt_key_import_error"])){
        $errors = $_SESSION["crypt_key_import_error"];
        print('<div class="red" style="margin:20px 0;">');
            foreach($errors as $error) {
                print("<p>$error</p>");
            }
        print('</div>');
        unset($_SESSION["crypt_key_import_error"]);
        PrintKeyForm();
    }
    elseif (isset($_SESSION["crypt_key_import_success"])) {
        $ttl_min = round($ttl/60);
        print('<div class="green" style="margin:20px 0;">The decription key was imported. It will be unloaded after ' . $ttl_min .' minutes of incactivity.</div><br/>');
        unset($_SESSION["crypt_key_import_success"]);
    }
    else
    {        
        if (apcu_exists($apcu_key)) {
            print('<p class="green" style="margin:20px 0;">A decription key is currently loaded.</p>');
        }
        else {
            PrintKeyForm();
        }
    }
}

    
