<?php
// Circumventing the problem with __FILE__ when the plugin is used
// through a symlink
define('FILE', $_SERVER['SCRIPT_FILENAME']);

include(dirname(FILE)."/../../include/db.php");
include(dirname(FILE)."/../../include/general.php");
include(dirname(FILE)."/../../include/dash_functions.php");
include(dirname(FILE)."/../../include/collections_functions.php");
$api=true;

include(dirname(FILE)."/../../include/authenticate.php");

// required: check that this plugin is available to the user
if (!in_array("api_new_user_lng",$plugins)){
    jsonDie('No access to API');
}

$newuser = getvalescaped("newuser","");


if ($api_new_user_lng['signed']){

// test signature? get query string minus leading ? and skey parameter
$test_query="";
parse_str($_SERVER["QUERY_STRING"],$parsed);
foreach ($parsed as $parsed_parameter=>$value){
    if ($parsed_parameter!="skey"){
        $test_query.=$parsed_parameter.'='.$value."&";
    }
    }
$test_query=rtrim($test_query,"&");

    // get hashkey that should have been used to create a signature.
    $hashkey=md5($api_scramble_key.getval("key",""));

    // generate the signature required to match against given skey to continue
    $keytotest = md5($hashkey.$test_query);

    if ($keytotest <> getval('skey','')){
		/*
		header("HTTP/1.0 403 Forbidden.");
		echo "HTTP/1.0 403 Forbidden. Invalid Signature";
		exit;
		*/
		jsonDie('Invalid signature');
	}
}


// Ruud 05-02-16: create new user and associated "My collection" and return values
if (!empty($newuser)) {
	$userId = new_user($newuser);
	if (!$userId) {
		/* Ruud 09-02-16: add error to json rather than die with 403

		header("HTTP/1.0 403 Forbidden.");
		echo "HTTP/1.0 403 Forbidden. User already exists";
		exit;
		*/
	    $output['error'] = 'User already exists';
	} else {
	    // new_user() automatically creates "My collection" but does not return
	    // id of it... Fetch it now.
		$collectionId = (int)sql_value("select current_collection as value from user where ref='$userId'",0);
		$userGroupId = sql_value("select ref as value from usergroup where `name`='General Users'",0);

		// Emulate team_user_edit.php; add variables to $_POST
		$_POST["password"] = createUserPassword(); // Auto-generate password
		$_POST["usergroup"] = $userGroupId; // General user
		$_POST["approved"] = 1;
		$_POST["username"] = $newuser;
		$_POST["fullname"] = $newuser;

		save_user_lng($userId);

		unset($_POST['fullname'], $_POST['usergroup'], $_POST['approved']);
		$output = $_POST;
		unset($_POST);

		$output["user_id"] = $userId;
		$output["collection_id"] = $collectionId;
		$output['error'] = '';

		$password = sql_value("select password as value from user where ref='".$output['user_id']."'",0);
		$output["authentification_key"] = make_api_key($output["username"],$password);

	}
    header('Content-type: application/json');
	die(json_encode($output));
}


function createUserPassword () {
    return bin2hex(openssl_random_pseudo_bytes(4));
}

// Ruud 09-02-16: added to die with json error rather than 403
function jsonDie($m) {
    header('Content-type: application/json');
    die(json_encode(array('error' => $m)));
}

// Ruud 07-06-16: bug in RS 7.7 prevented creation of users...
function save_user_lng($ref)
    {
    global $lang, $allow_password_email, $home_dash;

    # Save user details, data is taken from the submitted form.
    if(getval('deleteme', '') != '')
        {
        sql_query("DELETE FROM user WHERE ref='$ref'");
        empty_user_dash($ref);
        log_activity(null, LOG_CODE_DELETED, null, 'user', null, $ref);

        return true;
        }
    else
        {
        $current_user_data = get_user($ref);

        // Get submitted values
        $username               = trim(getvalescaped('username', ''));
        $password               = trim(getvalescaped('password', ''));
        $fullname               = trim(getvalescaped('fullname', ''));
        $email                  = trim(getvalescaped('email', ''));
        $expires                = "'" . getvalescaped('account_expires', '') . "'";
        $usergroup              = trim(getvalescaped('usergroup', ''));
        $ip_restrict            = trim(getvalescaped('ip_restrict', ''));
        $search_filter_override = trim(getvalescaped('search_filter_override', ''));
        $comments               = trim(getvalescaped('comments', ''));

        $suggest = getval('suggest', '');

        # Username or e-mail address already exists?
        $c = sql_value("SELECT count(*) value FROM user WHERE ref <> '$ref' AND (username = '" . $username . "' OR email = '" . $email . "')", 0);
        if($c > 0 && $email != '')
            {
            return false;
            }

        // Password checks:
        if($suggest != '')
            {
            $password = make_password();
            }
        elseif($password != $lang['hidden'])
            {
            $message = check_password($password);
            if($message !== true)
                {
                return $message;
                }
            }

        if($expires == "''")
            {
            $expires = 'null';
            }

        $passsql = '';
        if($password != $lang['hidden'])
            {
            # Save password.
            if($suggest == '')
                {
                $password = hash('sha256', md5('RS' . $username . $password));
                }

            $passsql = ",password='" . $password . "',password_last_change=now()";
            }

        // Full name checks
        if('' == $fullname && '' == $suggest)
            {
            return $lang['setup-admin_fullname_error'];
            }

        $additional_sql = hook('additionaluserfieldssave');

        log_activity(null, LOG_CODE_EDITED, $username, 'user', 'username', $ref);
        log_activity(null, LOG_CODE_EDITED, $fullname, 'user', 'fullname', $ref);
        log_activity(null, LOG_CODE_EDITED, $email, 'user', 'email', $ref);

        if(isset($current_user_data['usergroup']) && $current_user_data['usergroup'] != $usergroup)
            {
            log_activity(null, LOG_CODE_EDITED, $usergroup, 'user', 'usergroup', $ref);
            }

        log_activity(null, LOG_CODE_EDITED, $ip_restrict, 'user', 'ip_restrict', $ref, null, '');
        log_activity(null, LOG_CODE_EDITED, $search_filter_override, 'user', 'search_filter_override', $ref, null, '');
        log_activity(null, LOG_CODE_EDITED, $expires, 'user', 'account_expires', $ref);
        log_activity(null, LOG_CODE_EDITED, $comments, 'user', 'comments', $ref);
        log_activity(null, LOG_CODE_EDITED, ((getval('approved', '') == '') ? '0' : '1'), 'user', 'approved', $ref);

        sql_query("update user set
        username='" . $username . "'" . $passsql . ",
        fullname='" . $fullname . "',
        email='" . $email . "',
        usergroup='" . $usergroup . "',
        account_expires=$expires,
        ip_restrict='" . $ip_restrict . "',
        search_filter_override='" . $search_filter_override . "',
        comments='" . $comments . "',
        approved='" . ((getval('approved', '') == "") ? '0' : '1') . "' $additional_sql where ref='$ref'");
        }

        // Add user group dash tiles as soon as we've changed the user group
        if($home_dash)
            {
            // If user group has changed, remove all user dash tiles that were valid for the old user group
            if((isset($current_user_data['usergroup']) && '' != $current_user_data['usergroup']) && $current_user_data['usergroup'] != $usergroup)
                {
                sql_query("DELETE FROM user_dash_tile WHERE user = '{$ref}' AND dash_tile IN (SELECT dash_tile FROM usergroup_dash_tile WHERE usergroup = '{$current_user_data['usergroup']}')");
                }

            build_usergroup_dash($usergroup, $ref);
            }

    if($allow_password_email && getval('emailme', '') != '')
        {
        email_user_welcome(getval('email', ''), getval('username', ''), getval('password', ''), $usergroup);
        }
    elseif(getval('emailresetlink', '') != '')
        {
        email_reset_link($email, true);
        }

	if(getval('approved', '')!='')
		{
		# Clear any user request messages
	    message_remove_related(USER_REQUEST,$ref);
		}

    return true;
    }
