<?php

class PasswordReset
{
	var $db             = NULL;
	var $alternateSetup = false;

	function __construct(MySQLi $db) {
		$this->db = $db;
	}

	/**
	 * Verifies that the username has an alternate email setup.
	 * @param $username string The email address which is used to verify access.
	 * @return boolean
	 **/

	function alternateIsSetup($username) {
		$sql = "SELECT 
				    COUNT(mailbox_username)
				FROM
				    postfixadmin.password_reset
				WHERE
				    mailbox_username = ?";

		$stmt = $this->db->prepare($sql);
		$stmt->bind_param("s",$username);
		$stmt->execute();
		$stmt->bind_result($count);
		$stmt->fetch();

		return ($count > 0?true:false);
	}

	function resetPassword() {

	}

	function checkForRequest() {
		if(!isset($_POST['realstEmail'])) return false;

		if(!$this->alternateIsSetup($_POST['realstEmail'])) {
			echo '<div class="alert alert-danger">This email does not have an alternate email setup. You cannot reset your password until you hvae setup an alternate email with the administrator. Contact your administrator and give them an alternate email address you can use to reset your passwords.</div>';
			$this->alternateSetup = false;
		} else {
			$this->alternatesetup = true;
		}

		if($this->alternateSetup) $this->sendNonce();
		return $this->alternatesetup;
	}

	function sendNonce() {
		$nonce    = sha1(microtime());
		$expiry   = microtime(true) + (60*60*2);
		$username = $_GET['realstEmail'];

		$sql = "UPDATE `postfixadmin`.`password_reset` 
				SET 
				    `nonce` = ?,
				    `expiration` = ?,
				    `valid` = 'Y'
				WHERE
				    `mailbox_username` = ?";

		$stmt = $this->db->prepare($sql);
		$stmt->bind_param('sis',$nonce,$expiry,$username);
		$stmt->execute();
		echo "<pre>"; var_dump($stmt); echo "</pre>";

	}

	function showForm() {
		$form = <<<EOF
<h2>Email Password Reset</h2>
<form method="post">
  <div class="form-group">
    <label for="realstEmail">Enter Your Email Address</label>
    <input type="email" class="form-control" name="realstEmail" id="realstEmail" placeholder="Email">
  </div>
  <button type="submit" class="btn btn-default">Reset Password</button>
</form>
EOF;
		echo $form;
	}
}
