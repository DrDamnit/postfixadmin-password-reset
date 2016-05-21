<?php

class PasswordReset
{
	var $db = NULL;

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

	function showForm() {
		$form = <<<EOF
<h2>Email Password Reset</h2>
<form method="GET">
  <div class="form-group">
    <label for="realstEmail">Enter Your Email Address</label>
    <input type="email" class="form-control" id="realstEmail" placeholder="Email">
  </div>
  <button type="submit" class="btn btn-default">Reset Password</button>
</form>
EOF;
		echo $form;
	}
}