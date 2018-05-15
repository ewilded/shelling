<?php
# filename: no_white_chars_no_colon_no_pipe_no_ampersand.php
# vulnerable with newline as command separator
# sample exploit:
 
if(isset($_GET['dir'])&&!preg_match('/\s+/',$_GET['dir'])&&!preg_match('/&|\||;/',$_GET['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
}
?>
