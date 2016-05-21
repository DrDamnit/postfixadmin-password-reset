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

	function updatePassword() {
		$password = pacrypt($_POST['pass1']);

		$sql = "SELECT 
				    mailbox_username
				FROM
				    postfixadmin.password_reset
				WHERE
				    nonce= ?
					AND UNIX_TIMESTAMP() < expiration
			        AND valid = 'Y'";

		$stmt = $this->db->prepare($sql);
		$stmt->bind_param('s',$_GET['n']);
		$stmt->execute();
		$stmt->store_result();
		$stmt->bind_result($username);
		$stmt->fetch();

		if($stmt->num_rows == 0 ) {
			echo '<div class="alert alert-danger">This link is not valid. If you were trying to reset your password, you must restart the process by going to <a href="/reset/">the password reset page.</a>. Remeber, you must complete this reset in 2 hours or the link will expire!</div>';
			return false;
		}
				
		$sql = "UPDATE `postfixadmin`.`mailbox` 
				SET 
				    `password` = ?
				WHERE
				    `username` = ?";

		$stmt = $this->db->prepare($sql);
		$stmt->bind_param('ss',$password,$username);
		if($stmt->execute()) {
			echo '<div class="alert alert-succss">You have successfully changed your password.</div>';
		} else {
			echo '<div class="alert alert-succss">Your password could not be updated. Please call support.</div>';
		}
	}

	function resetPassword() {
		if(!isset($_GET['n'])) return false;
		$form = <<<EOF
<h2>Enter your new password</h2>
<form method="post">
  <div class="form-group">
    <label for="pass1">Password</label>
    <input type="password" class="form-control" id="pass1" name="pass1" placeholder="Password">
  </div>
  <div class="form-group">
    <label for="pass2">Confirm your new password</label>
    <input type="password" class="form-control" id="pass2" name="pass2" placeholder="Password">
  </div>  
  <button type="submit" class="btn btn-default">Reset Password</button>
</form>
EOF;

		//confirm the nonce is good.

		$sql = "SELECT 
				    mailbox_username
				FROM
				    postfixadmin.password_reset
				WHERE
				    nonce= ?
					AND UNIX_TIMESTAMP() < expiration
			        AND valid = 'Y'";

		$stmt = $this->db->prepare($sql);
		$stmt->bind_param('s',$_GET['n']);
		$stmt->execute();
		$stmt->store_result();
		$stmt->bind_result($username);
		$stmt->fetch();

		if($stmt->num_rows == 0 ) {
			echo '<div class="alert alert-danger">This link is not valid. If you were trying to reset your password, you must restart the process by going to <a href="/reset/">the password reset page.</a>. Remeber, you must complete this reset in 2 hours or the link will expire!</div>';
			return false;
		}

		echo $form;
	}


	function confirmAuthority() {
		if(!$this->alternateIsSetup($_POST['realstEmail'])) {
			echo '<div class="alert alert-danger text-center">This email does not have an alternate email setup. You cannot reset your password until you hvae setup an alternate email with the administrator. Contact your administrator and give them an alternate email address you can use to reset your passwords.</div>';
			$this->alternateSetup = false;
		} else {
			$this->alternateSetup = true;
		}

		if($this->alternateSetup) $this->sendNonce();
		return $this->alternatesetup;		
	}

	function routeRequest() {
		if(isset($_POST['realstEmail'])) {

			$this->confirmAuthority();

		} elseif (isset($_POST['pass1'])) {

			$this->updatePassword();

		} elseif (isset($_GET['n'])) {

			$this->resetPassword();


		} else {

			$this->showForm();

		}
	}

	function renderResetLink($nonce) {

		$uri  = explode('/', $_SERVER['REQUEST_URI']);

		//pop the last item off the array to get our directory.
		array_pop($uri);

		$dir    = implode("/", $uri);
		$prefix = ($_SERVER['HTTPS']?"https":"http");
		$host   = $_SERVER['HTTP_HOST'];
		$format = "%s://%s%s/?n=%s";
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
