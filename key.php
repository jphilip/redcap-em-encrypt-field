<?php
/**
 * REDCap External Module: EncryptField
 * Page to enter a private key which will be keopt in memory for the session
 * @author Jacques Philip, Center for Alaska Native Health Research, University of Alaska Fairbanks
 */

$ttl = 120;
$apcu_key = session_id() . "_" . USERID;
$encryptField = new \CANHR\EncryptFieldExternalModule\EncryptFieldExternalModule();
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

    if (!empty($errors)) {
        $_SESSION["crypt_key_import_error"] = $errors;
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
    if (apcu_exists($apcu_key)) {
        print('<p class="green" style="margin:20px 0;"> Acpu key: ' . $apcu_key . " has value: " . apcu_fetch($apcu_key) . "</p>");
    }
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
        print('<div class="green" style="margin:20px 0;">The decription key was imported</div><br/>');
        unset($_SESSION["crypt_key_import_success"]);
    }
    else
    {
        PrintKeyForm();
    }
}

    
