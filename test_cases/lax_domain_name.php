<?php
# filename: lax_domain_name.php
# vulnerable as the regex is too lose
# sample exploit: 

if(isset($_GET['dir'])&&preg_match('/^\w+\..*\w+\.\w+$/',$_GET['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
}
?>

