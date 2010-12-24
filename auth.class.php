<?PHP
/**
 * Authentication class.
 *
 * @author     kaotix
 * @copyright  (c) 2010 kaotix/vibenet-hosting
 */

// This is used by my original project to ensure this file isn't accessed directly. It can be removed safely without causing any problems to this classes functionality
if ( !defined('IN_CORE') ) exit();

class auth extends core {

	/**
	 * @var  object  sql connection identifier
	 */
	var $sql;
	/**
	 * @var  object  core class object reference
	 */
	var $core;
	/**
	 * @var  string  authentication errors
	 */
	var $error = '';
	
	
	/**
	 * Construct function, automatically executed once the class is initialized.
	 *
	 * @param   object	core class object reference
	 */
	function __construct( $core ) {
	
		// SQL Connection Settings
		$sql_host 	= 'host';		// SQL Hostname
		$sql_user 	= 'username';		// SQL Username
		$sql_pass 	= 'password';		// SQL Password
		$sql_db 	= 'database';		// SQL Database
		
		// This is the first call to the 'log' function and requires the 2nd parameter to be TRUE so it starts from the beginning of the file
		$this->log( "Class initialized.", TRUE );
		
		// Connect to the SQL database, note the @ to supress any error messages
		$this->sql = @mysql_connect( $sql_host, $sql_user, $sql_pass );
		if ( $this->sql ) {
			$this->log( "Connected to the database." );
			// Select our database after connection, again note the @ to supress error messages
			$result = @mysql_select_db( $sql_db, $this->sql );
			if ( !$result )
				$this->log( "Error - Unable to connect to select the database [" . mysql_error() . "]" );
			else
				$this->log( "Database selected." );
		} else
			$this->log( "Error - Unable to connect to the database [" . mysql_error() . "]" );
			
	} // end construct
	
	/*function log( $data, $first = FALSE ) {
		if ( $first )
			$fh = fopen( "debug.log", "w" );
		else
			$fh = fopen( "debug.log", "a" );
			
		fwrite( $fh, "[" . date( "h:m:s A" ) . "] " . $data . "\r\n" );
		fclose( $fh );
		
	} // end function log*/
	
	function error( $function, $vars = array(), $err, $errno ) {
		echo "Error in [" . $function . "]<br />";
		
		if ( array_count_values( $vars ) > 0 ) {
			echo "Variables:<br />";
			foreach( $vars as $key => $var ) {
				echo "[" . $key . "][" . $var . "]<br />";
			}
		}
		
		echo "Error message: [" . $errno . "] " . $err . "<br />";
		exit();
		
	} // end function error
	
	/**
	 * Generates a random string and hashes it using SHA1
	 *
	 * @return	string	hash token
	 */
	function generate_token() {
		$this->log( "Generating token." );
		return sha1( mt_rand() );
	} // end function generate_token
	
	
	/**
	 * Retrieves a users salt from the SQL database based on their username
	 *
	 * @param   string	username
	 * @return	string	salt as a hash
	 */
	function get_salt( $username ) {
		$this->log( "Getting users salt [" . $username . "]" );
		$username = mysql_real_escape_string( $username );
		
		$sql = "SELECT `salt` FROM `users` WHERE `username` = '" . $username . "' LIMIT 1";
		$result = mysql_query( $sql, $this->sql );
		
		if ( mysql_num_rows( $result ) == 1 ) {
			$salt = mysql_fetch_assoc( $result );
			$this->log( "Salt retrieved [" . $salt['salt'] . "]" );
			return $salt['salt'];
		} else {
			$this->log( "Unable to find salt in database." );
			return FALSE;
		}
	
	} // end function get_salt
	
	/**
	 * Construct password hash based on username, password and salt.
	 *
	 * @param   string	username
	 * @param	string	password
	 * @param	string	salt
	 * @return	string	SHA1 hash to be used as a password
	 */
	function construct_hash( $username, $password, $salt ) {
		$this->log( "Constructing hash." );
		if ( $salt == '' ) return FALSE;
		$hash = sha1( $username . $salt . $password );
		$this->log( "Hash constructed [" . $hash . "]" );
		// todo: validate hash length - needed?
		return $hash;
	} // end function construct_hash
	
	/**
	 * Compare a given hash to the one stored within the SQL database
	 *
	 * @param   string	username
	 * @param	string	hash
	 * @return	bool	TRUE if given hash matches hash in SQL
	 */
	function check_hash( $username, $hash ) {
		$this->log( "Checking users hash." );
		$username = mysql_real_escape_string( $username );
		$hash = mysql_real_escape_string( $hash );
		
		$sql = "SELECT `password` FROM `users` WHERE `username` = '" . $username . "' AND `password` = '" . $hash . "' LIMIT 1";
		$result = mysql_query( $sql, $this->sql );
		
		if ( mysql_num_rows( $result ) == 1 ) {
			$password = mysql_fetch_assoc( $result );
			if ( $password['password'] == $hash ) {
				$this->log( "Hash matches database." );
				return TRUE;
			} else {
				$this->log( "Hash does not match database." );
				return FALSE;
			}
		} else {
			$this->log( "Unable to find hash in database." );
			return FALSE;
		}
	} // end function check_hash
	
	/**
	 * Creates an authentication hash to be used in the session/cookie (viewable by the end user)
	 * It is constructed of the username + token + salt + ip address (IP address is not something I wish to keep in here in the future)
	 *
	 * @param   string	username
	 * @param	string	salt
	 * @return	string	returns hash on success and FALSE when it fails
	 */
	function generate_auth_hash( $username, $salt ) {
		$this->log( "Generating auth_hash." );
		$username = mysql_real_escape_string( $username );
		$salt = mysql_real_escape_string( $salt );
		
		$sql = "SELECT `token` FROM `users` WHERE `username` = '" . $username . "' LIMIT 1";
		$result = mysql_query( $sql, $this->sql );
		
		if ( mysql_num_rows( $result ) == 1 ) {
			$token = mysql_fetch_assoc( $result );
			if ( $token['token'] != '' ) {
				$ip = $_SERVER['REMOTE_ADDR'];
				if ( $ip == '' ) return FALSE;
				$auth_hash = sha1( $username . $token['token'] . $salt . $ip );
				$this->log( "Auth has generated [" . $auth_hash . "]" );
				return $auth_hash;
			} else return FALSE;
			
		} else {
			return FALSE;
		}
	} // end function generate_auth_hash
	
	/**
	 * Get the auth hash (session/cookie hash) from the SQL database based on the provided username
	 *
	 * @param   string	username
	 * @return	string	returns valid hash on success and FALSE if it cannot find the username
	 */
	function get_auth_hash( $username ) {
		$this->log( "Getting auth_hash from database." );
		$username = mysql_real_escape_string( $username );
		
		$sql = "SELECT `auth_hash` FROM `users` WHERE `username` = '" . $username . "' LIMIT 1";
		$result = mysql_query( $sql, $this->sql );
		
		if ( mysql_num_rows( $result ) == 1 ) {
			$auth_hash = mysql_fetch_assoc( $result );
			if ( $auth_hash['auth_hash'] != '' ) {
				$this->log( "Auth hash returned [" . $auth_hash['auth_hash'] . "]" );
				return $auth_hash['auth_hash'];
			} else return FALSE;
			
		} else {
			return FALSE;
		}
	} // end function get_auth_hash
	
	/**
	 * Combines all the methods of checking the data and logs the user in on the system
	 * It also creates session and cookie data containing the username and auth hash for validation within the SQL database
	 * Additional to the above it also 'rotates' the users password hash and subsequent password salt
	 *
	 * The password hash is rotated due to the fact that we are given the valid password in plain text again which is simply re-hashed
	 * The password is validated first before being rotated - obviously!
	 *
	 * @param   string	username
	 * @param	string	password
	 * @return 	bool	TRUE for a successful login
	 */
	function login( $username, $password ) {
		$this->log( "Logging user in." );
		if ( $username == '' ) return FALSE;
		if ( $password == '' ) return FALSE;
		
		$username = mysql_real_escape_string( $username );
		$password = mysql_real_escape_string( $password );
		
		$salt = $this->get_salt( $username );
		if ( $salt != FALSE || strlen( $salt ) == 40 ) {
			$hash = $this->construct_hash( $username, $password, $salt );
			$result = $this->check_hash( $username, $hash );
			
			// Hash matches, user is authenticated
			if ( $result != FALSE ) {
				// Cookie/session setup
				// updated - 28/11/2010
				// change users salt after a successfull login
				$new_salt = $this->generate_token();
				$new_hash = $this->construct_hash( $username, $password, $new_salt );
				$sql = "UPDATE `users` SET `password` = '" . $new_hash . "', `salt` = '" . $new_salt . "' WHERE `username` = '" . $username . "';";
				$result = mysql_query( $sql, $this->sql );
				// Add auth hash to DB
				$auth_hash = $this->generate_auth_hash( $username, $new_salt );
				//$auth_hash = $this->generate_auth_hash( $username, $salt );
				if ( $auth_hash != FALSE ) {
					$sql = "UPDATE `users` SET `auth_hash` = '" . $auth_hash . "' WHERE `username` = '" . $username . "'";
					$result = mysql_query( $sql, $this->sql );
					
					// Add auth hash to cookie and session
					setcookie( 'username', $username, time()+3600 );
					setcookie( 'auth_hash', $auth_hash, time()+3600 );
					$_SESSION['username'] = $username;
					$_SESSION['auth_hash'] = $auth_hash;
					$this->log( "User has been authenticated." );
					return TRUE;
				} else {
					$this->error = "Unable to generate authentication hash.";
					return FALSE;
				}
				
			// Hash mismatch
			} else {
				$this->log( "Login failed [1]" );
				$this->error = "Password mismatch.";
				return FALSE;
			}
		} else {
			$this->log( "Login failed [2]" );
			$this->error = "Unknown username.";
			return FALSE;
		}
		
	} // end function login
	
	/**
	 * Checks for a valid username and auth hash in the session cookie and validates the stored data in the SQL database
	 * TODO: Add better validation of username/auth hash due to the possibility of people trying SQL injection by simply providing a username/hash with a malicious string
	 *
	 * @return	bool	returns TRUE if the users data has been validated
	 */
	function is_loggedin() {
		$this->log( "Checking if user is logged in." );
		if ( isset( $_COOKIE['username'] ) && $_COOKIE['username'] != '' &&
			isset( $_COOKIE['auth_hash'] ) && $_COOKIE['auth_hash'] != '' ) {
			$username = mysql_real_escape_string( $_COOKIE['username'] );
			$hash = mysql_real_escape_string( $_COOKIE['auth_hash'] );
			$this->log( "Found cookie, checking its details. [" . $username . "][" . $hash . "]" );
			
			$salt = $this->get_salt( $username );
			if ( $salt != FALSE ) {
				$auth_hash = $this->get_auth_hash( $username );
				
				if ( $auth_hash == $hash ) {
					$this->log( "User is logged in." );
					return TRUE;
				} else {
					$this->log( "User is not logged in." );
					return FALSE;
				}
			} else {
				return FALSE;
			}
		} else {
			return FALSE;
		}
		
	} // end function is_loggedin
	
	/**
	 * During a logout, we remove the auth hash from the SQL database to avoid anyone re-using a valid session.
	 * This is not flawless, if the user does not explicitly logout then this function is never called and the auth hash will continue to exist.
	 *
	 * TODO: possibly validate the auth hash before removing it. if a user managed to call this function directly they could log any user out simply by providing a valid username
	 *
	 * @param   string	username
	 * @return	bool	TRUE is the hash was removed
	 */
	function remove_auth_hash( $username ) {
		$this->log( "Removing auth_hash." );
		$username = mysql_real_escape_string( $username );
		$sql = "UPDATE `users` SET `auth_hash` = '' WHERE `username` = '" . $username . "'";
		$result = mysql_query( $sql, $this->sql );
		
		if ( $result )
			return TRUE;
		else
			return FALSE;
	} // end function remove_auth_hash
	
	/**
	 * Adds a new user into the database
	 * This function is *VERY* raw and was only added to be called from a secure page or only in code
	 * It simply generates all the required parts for a new user and adds them into the SQL database
	 *
	 * TODO: valid return on errors
	 *
	 * @param   string	username
	 * @param	string	password
	 * @return	bool	(see above todo) TRUE on successfully adding new user
	 */
	function create_user( $username, $password ) {
		$this->log( "Creating new user." );
		$username = mysql_real_escape_string( $username );
		$password = mysql_real_escape_string( $password );
		
		$token = $this->generate_token();
		$salt = $this->generate_token();
		
		$password = $this->construct_hash( $username, $password, $salt );
		
		$sql = "INSERT INTO `users` (`username`, `password`, `salt`, `token`)
				VALUES ('" . $username . "', '" . $password . "', '" . $salt . "', '" . $token . "')";
		$result = mysql_query( $sql, $this->sql );
		
		if ( !$result ) {
			echo "Error: " . mysql_error() . "<br />";
		} else {
			return TRUE;
		}
		
	} // end function create_user
	
	/**
	 * Part of the password hash rotation, used to update a users salt with a new random hash
	 * Please note that no validation is done on this function and it is to only be called within the flow of a valid password rotation
	 * If something fails during this update, you may render the users password hash useless due to the original salt being destroyed
	 *
	 * @param   string	username
	 * @return	bool	TRUE is salt is successfully updated
	 */
	function insert_salt( $username ) {
		$username = mysql_real_escape_string( $username );
		
		$salt = $this->generate_token();
		
		$sql = "UPDATE `users` SET `salt` = '" . $salt . "' WHERE `username` = '" . $username . "'";
		$result = mysql_query( $sql, $this->sql );
		
		if ( $result )
			return TRUE;
		else
			return FALSE;

	} // end function insert_salt
	
	/**
	 * A crude logout function which doesn't validate any information before removing any of the information
	 * If the username doesn't exist in the cookie this function will fail
	 * There is also no return from this function due to no validation
	 *
	 * @return	none
	 */
	function logout() {
		$this->remove_auth_hash( $_COOKIE['username'] );
		//$this->insert_salt( $_COOKIE['username'] );
		setcookie( 'username', '', time() - 3600 );
		setcookie( 'auth_hash', '', time() - 3600 );
		session_destroy();
		session_unset();
		header( 'Location: index.php' );
	} // end function logout

} // end class auth

?>