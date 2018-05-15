<?php
# filename: no_white_chars_no_colon_no_pipe_no_ampersand_no_quote.php
# vulnerable to ...
# sample exploit: 

if(isset($_GET['dir'])&&!preg_match('/\s+/',$_GET['dir'])&&!preg_match('/&|\||;/',$_GET['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls '{$_GET['dir']}'");
}
?>
