<?php
# filename: simple_stop_alphanum.php
# vulnerable, needs to end with an alphanumeric character
#

if(isset($_GET['dir'])&&preg_match('/^\w+/',$_GET['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
}
?>
