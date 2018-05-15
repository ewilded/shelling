<?php
# filename: no_colon_no_pipe_no_ampersand_no_dollar.php
# vulnerable to newline injection
# sample exploit: 

if(isset($_POST['dir'])&&!preg_match('/&|\||;|\$/',$_POST['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_POST['dir']}");
}
?>
