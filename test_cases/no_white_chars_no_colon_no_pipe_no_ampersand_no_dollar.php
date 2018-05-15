<?php
# filename: no_white_chars_no_colon_no_pipe_no_ampersand_no_dollar.php
# vulnerable to newline injection I guess
# 
if(isset($_POST['dir'])&&!preg_match('/\s+/',$_POST['dir'])&&!preg_match('/&|\||;|\$/',$_POST['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_POST['dir']}");
}
?>
