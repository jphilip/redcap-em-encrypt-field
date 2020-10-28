<?php
/**
 * REDCap External Module: EncryptField
 * Page to enter a private key which will be keopt in memory for the session
 * @author Jacques Philip, Center for Alaska Native Health Research, University of Alaska Fairbanks
 */

$apcu_key = session_id() . "_" . USERID;
$encryptField = new \CANHR\EncryptFieldExternalModule\EncryptFieldExternalModule();
$ttl = intval($encryptField->getProjectSetting('private-key-ttl')) * 60;

function PrintKeyForm()
{
    print('<form method="post" enctype="multipart/form-data" class="darkgreen" style="max-width:650px;padding:20px;">');
    print('<div><label for="key">Select a decryption key file to upload:</label></div>');
    print('<div><input type="file" name="key" id="key"  required></div>');
    print('<div style="padding-top:10px;"><button type="submit" class="btn btn-xs btn-rcgreen fs14">Continue</button></div>');
    print('</form>');
}
?>

<h2>Decryption Key Import</h2>
<?php
if (strtoupper($_SERVER['REQUEST_METHOD'])=='POST') {
    $errors = array();
    if (!isset($_FILES['key'])) {
        $errors[] = "Please select a file.";
    } else {
        try {
            $key= trim(file_get_contents($_FILES['key']['tmp_name']));
        } catch (\Throwable $th) {
            //throw $th;
        } finally {
            unlink($_FILES["key"]["tmp_name"]);
        }
        
        if (!$encryptField->TestPrivateKey($key)) {
            $errors[] = "Invalid decryption key.";
        }
    }

    if (!empty($errors)) {
        $_SESSION["crypt_key_import_error"] = $errors;
        apcu_delete($apcu_key);
        if (isset($_SESSION["crypt_key_import_success"])) {
            unset($_SESSION["crypt_key_import_success"]);
        }
    } else {
        if (isset($_SESSION["crypt_key_import_error"])) {
            unset($_SESSION["crypt_key_import_error"]);
        }
        $_SESSION["crypt_key_import_success"] = 1;
        apcu_store($apcu_key, $key, $ttl);
    }
    header("Location: " . $encryptField->getUrl("key.php"));
} else {
    if (isset($_SESSION["crypt_key_import_error"])) {
        $errors = $_SESSION["crypt_key_import_error"];
        print('<div class="red" style="margin:20px 0;">');
        foreach ($errors as $error) {
            print("<p>$error</p>");
        }
        print('</div>');
        unset($_SESSION["crypt_key_import_error"]);
        PrintKeyForm();
    } elseif (isset($_SESSION["crypt_key_import_success"])) {
        $ttl_min = round($ttl/60);
        print('<div class="green" style="margin:20px 0;">The decryption key was imported. It will be unloaded after ' . $ttl_min .' minutes of incactivity.</div><br/>');
        unset($_SESSION["crypt_key_import_success"]);
    } else {
        if (!$encryptField->getProjectSetting('enable-decryption')) {
            print('<p class="red" style="margin:20px 0;">Decryption is not enabled in the module\'s project settings.</p>');
        } elseif (apcu_exists($apcu_key)) {
            print('<p class="green" style="margin:20px 0;">A decryption key is currently loaded.</p>');
        } else {
            PrintKeyForm();
        }
    }
}
