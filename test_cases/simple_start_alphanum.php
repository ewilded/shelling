<?php
# filename: simple_start_alphanum.php
# vulnerable, has to start with an alphanumeric character
#

if(isset($_GET['dir'])&&preg_match('/\w+$/',$_GET['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
}
?>
