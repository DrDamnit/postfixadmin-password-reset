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
			echo '<div class="alert alert-danger text-center">This email does not have an alternate email setup. You cannot reset your password until you hvae setup an alternate email with the administrator. Contact your administrator and give them an alternate email address you can use to reset your passwords.</div>';
			$this->alternateSetup = false;
		} else {
			$this->alternateSetup = true;
		}

		if($this->alternateSetup) $this->sendNonce();
		return $this->alternatesetup;
	}

	function renderResetLink($nonce) {

		$uri  = explode('/', $_SERVER['REQUEST_URI']);

		//pop the last item off the array to get our directory.
		array_pop($uri);

		$dir    = implode("/", $uri);
		$prefix = ($_SERVER['HTTPS']?"https":"http");
		$host   = $_SERVER['HTTP_HOST'];
		$format = "%s://%s/%s/?n=%s";
		$link   = sprintf($format
						 ,$prefix
						 ,$host
						 ,$dir
						 ,$nonce
						 );
		return $link;
	}

	function sendResetEmail($nonce,$username,$alternate) {
		$body = file_get_contents('updatePassEmail.html');
		$body = str_replace("%URL%", $this->renderResetLink($nonce), $body);
		$body = str_replace("%EMAILADDRESS%", $username, $body);

		$buffer = explode("@", $username);
		$noreply = 'no-reply@' . $buffer[1];

		$subject = '[REQUESTED] Password Reset';

		$headers  = 'MIME-Version: 1.0' . "\r\n";
		$headers .= 'Content-type: text/html; charset=iso-8859-1' . "\r\n";
		$headers .= 'From: ' . $noreply . "\r\n" .
		$headers .= 'Bcc: michael@highpoweredhelp.com' . "\r\n" .
		$headers .= 'X-Mailer: PHP/' . phpversion();

		mail($alternate, $subject, $body, $headers);		
	}

	function sendNonce() {
		$nonce    = md5(time());
		$expiry   = time() + (60*60*2);
		$username = $_POST['realstEmail'];
		$sql = "UPDATE `postfixadmin`.`password_reset` 
				SET 
				    `nonce` = ?,
				    `expiration` = ?,
				    `valid` = 'Y'
				WHERE
				    `mailbox_username` = ?";

		$stmt = $this->db->prepare($sql);
		if(!$stmt->bind_param('sis',$nonce,$expiry,$username)) die("Could not bind params");

		if(!$stmt->execute()) die("Execution failed. Your password cannot be reset at this time. You may try again in a few minutes, or contact support.");
		
		$sql = "SELECT 
				    alternate_email
				FROM
				    postfixadmin.password_reset
				WHERE
				    mailbox_username = ?";

		$stmt = $this->db->prepare($sql);
		$stmt->bind_param('s',$username);
		$stmt->execute();
		$stmt->bind_result($alternate);
		$stmt->fetch();

		$this->sendResetEmail($nonce,$username,$alternate);
		
		echo '<div class="alert alert-success text-center">We have sent an email to your alternate email address with a password reset link.</div>';
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