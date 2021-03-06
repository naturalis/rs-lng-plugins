<?php
// Circumventing the problem with __FILE__ when the plugin is used
// through a symlink
//define('FILE', $_SERVER['SCRIPT_FILENAME']);
//define('FILE', exec('pwd'));

include(dirname(__FILE__)."/../../include/db.php");
include(dirname(__FILE__)."/../../include/general.php");
include(dirname(__FILE__)."/../../include/image_processing.php");
include(dirname(__FILE__)."/../../include/resource_functions.php");
include(dirname(__FILE__)."/../../include/collections_functions.php");
include(dirname(__FILE__)."/../../include/search_functions.php");
$api=true;

include(dirname(__FILE__)."/../../include/authenticate.php");

// required: check that this plugin is available to the user
if (!in_array("api_new_user_lng",$plugins)){
    jsonDie('No access to API');
}

hook("additionalapiuploadmethods");

$fileurl=getvalescaped("fileurl","");

if (isset($_FILES['userfile']) || $fileurl!=""){

 $resource_type=getvalescaped("resource_type",1,true);

 // work out status
 if (!(checkperm("c") || checkperm("d"))){ header("HTTP/1.0 403 Forbidden.");
    /*
	echo "HTTP/1.0 403 Forbidden. No upload permissions\n";
	exit;
	*/
    jsonDie('No upload permissions.');
 }
 if (checkperm("XU".$resource_type)){ header("HTTP/1.0 403 Forbidden.");
	/*
	echo "HTTP/1.0 403 Forbidden. Upload to this Resource Type not allowed.";
	exit;
	*/
    jsonDie('Upload to this Resource Type not allowed.');
 }

/*
 * Ruud 05-02-16: override permission check; status should immediately be "active"
 *
 $archive=getvalescaped("archive","");
 if ($archive!="" && checkperm('e'.$archive)){
	$status=$archive;
 }
 else if (checkperm("c")) {$status = 0;} # Else, set status to Active - if the user has the required permission.
 else if (checkperm("d")) {$status = -2;} # Else, set status to Pending Submission.
 */
$status = 0;

 // check required fields
 $required_fields=sql_array("select ref value from resource_type_field where required=1 and (resource_type='$resource_type' or resource_type='0')");

 $missing_fields=false;
 $error_message="";
 foreach ($required_fields as $required_field){
	 $value=getvalescaped("field".$required_field,"");
	 if ($value==''){
		 $fieldname=i18n_get_translated(sql_value("select title value from resource_type_field where ref='$required_field'",""));

         //$options=sql_value("select options value from resource_type_field where ref='$required_field'","");

         $options=array();
         node_field_options_override($options,$required_field);

		 $type=sql_value("select type value from resource_type_field where ref='$required_field'","");

		 if (count($options)!=0 && ($type==3 || $type==2))
            {
            $optionstring="Allowed Values: ".ltrim(implode("\n",$options),",")."\n";
            }
         else
            {
            $optionstring="";
            }

		 $error_message.="$fieldname is required. Use field$required_field=[string] as a parameter. $optionstring\n";
		 $missing_fields=true;
	 }
 }
 if ($missing_fields){header("HTTP/1.0 403 Forbidden.");
    /*
	echo "HTTP/1.0 403 Forbidden. $error_message";
	exit;
	*/
    jsonDie($error_message);
 }

 // create resource
 $ref=hook('apiuploadreplaceref');
 if (!$ref){
	$ref=create_resource(getval("resourcetype",1),$status,$userref);
 }



 $collection=getvalescaped('collection',"",true);
 // Ruud 04-02-16: collection is a required field
 if (empty($collection)) {
    /*
	header("HTTP/1.0 403 Forbidden.");
	echo "HTTP/1.0 403 Forbidden. Collection cannot be empty.\n";
	exit;
	*/
    jsonDie('Collection cannot be empty.');
}

 if (isset($_FILES['userfile'])){
	 $path_parts=pathinfo($_FILES['userfile']['name']);
	 $extension=strtolower($path_parts['extension']);
	 $filepath=get_resource_path($ref,true,"",true,$extension);
	 $result=move_uploaded_file($_FILES['userfile']['tmp_name'], $filepath);
	 $filename=$_FILES['userfile']['name'];
 } else if ($fileurl!=""){
	$path_parts=pathinfo($fileurl);
	$extension=strtolower($path_parts['extension']);
	$extension=explode("?",$extension);
	$extension=$extension[0];
	$filepath=get_resource_path($ref,true,"",true,$extension);
	// use curl to get file
	$source = $fileurl;
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, $source);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,false);
	$data = curl_exec ($ch);
	$error = curl_error($ch);
	curl_close ($ch);
	$filename=explode("?",$fileurl);
	$filename=basename($filename[0]);
	$destination = $storagedir."/tmp/".$filename;
	$file = fopen($destination, "w+");
	fputs($file, $data);
	fclose($file);
	$result=rename($destination, $filepath);
 }
  $wait=sql_query("update resource set file_extension='$extension',preview_extension='jpg',file_modified=now(),has_image=0 where ref='$ref'");
 # Store original filename in field, if set
 global $filename_field;
 if (isset($filename_field))
    {
	$uploadfilename=getvalescaped('filename','');
	if ($uploadfilename!=''){
		// allow specification of uploaded filename to exclude extension, it will be added.
		$filename=$uploadfilename;
		$path_parts=pathinfo($filename);
		if(!isset($path_parts['extension'])){
			$filename=$filename.".".$extension;
		}
	}
    $wait=update_field($ref,$filename_field,$filename);
    }

 // extract metadata
 $wait=extract_exif_comment($ref,$extension);
 $resource=get_resource_data($ref);
 //create previews

 if ($camera_autorotation){
	AutoRotateImage($filepath);
 }





 $wait=create_previews($ref,false,$extension);
 // add resource to collection
 if ($collection!=""){
	 $collection_exists=sql_value("select name value from collection where ref='".escape_check($collection)."'","");
	 if ($collection_exists!=""){
		if(!add_resource_to_collection($ref,$collection)){
		    /*
			header("HTTP/1.0 403 Forbidden.");
			echo "HTTP/1.0 403 Forbidden. Collection is not writable by this user.\n";
			exit;
			*/
		    jsonDie('Collection is not writable by this user.');
		}
	} else {
	    /*
		header("HTTP/1.0 403 Forbidden.");
		echo "HTTP/1.0 403 Forbidden. Collection does not exist.\n";
		exit;
		*/
	    jsonDie('Collection does not exist.');
	}
 }

// make sure non-required fields get written. Note this behavior is somewhat different than in the system since these override extracted data
reset($_POST);reset($_GET);
foreach (array_merge($_GET, $_POST) as $key=>$value) {
if (substr($key,0,5)=="field" && $value!=""){
	$value=getvalescaped($key,"");
	$field=str_replace("field","",$key);
	update_field($ref,$field,$value);
	}
}


 $results=do_search("!list$ref","","relevance",$status);


 $modified_result=hook("modifyapisearchresult");
 if ($modified_result){
	$results=$modified_result;
 }

 // this function in api_core
 $results=refine_api_resource_results($results);


// Ruud 04-02-16: add alt file to response; copied from api_alt_file plugin
foreach ($results as $key => $result) {
	if (isset($result['ref'])) {
		$sizes = get_image_sizes($result['ref'],false,$result["file_extension"]);

		$files = array();
		foreach ($sizes as $i => $size) {
			$files[$i]['name'] = $size['name'];
			$files[$i]['width'] = $size['width'];
			$files[$i]['height'] = $size['height'];
			$files[$i]['extension'] = $size['extension'];
			$files[$i]['src'] = get_resource_path($result['ref'],false,$size['id'],false,$size['extension']);
		}

	    $thumbs = array(
            'small' => 'col',
            'medium' => 'thm',
            'large' => 'pre'
        );

        foreach ($thumbs as $k => $v) {

            $previewpath = get_resource_path($result['ref'], true, $v, false, "jpg", -1, 1, false);
            if (file_exists($previewpath)){
                $previewpath = get_resource_path($result['ref'],false,$v,false,$result["preview_extension"],-1,1,false,$result["file_modified"]);
            } else {
                $previewpath = httpProtocol() . '://' .
                $_SERVER['SERVER_NAME'] . "/gfx/".get_nopreview_icon($result["resource_type"],$result["file_extension"], false);
            }

            $thumbs[$k] = $previewpath;
        }


	}

    $results[$key]['files'] = $files;
    $results[$key]['thumbnails'] = $thumbs;
}


 // return refs
 header('Content-type: application/json');
 if ($collection!=""){
   $result = array('collection' => $collection, 'resource' => $results[0], 'error' => '');
 } else {
   $result = array('resource' => $results[0], 'error' => '');
 }

 echo json_encode($result); // echo json without headers by default

}

 else {echo "no file. Please post via curl with two posts: 'userfile' and 'key' as in <a href=".$baseurl."/plugins/api_upload/readme.txt>ReadMe</a>";}


// Ruud 09-02-16: added to die with json error rather than 403
function jsonDie ($m) {
    header('Content-type: application/json');
    die(json_encode(array('error' => $m)));
}

function httpProtocol() {
    $isSecure = false;
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') {
        $isSecure = true;
    } else if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https' ||
        !empty($_SERVER['HTTP_X_FORWARDED_SSL']) && $_SERVER['HTTP_X_FORWARDED_SSL'] == 'on') {
        $isSecure = true;
    }
    return $isSecure ? 'https' : 'http';
}

