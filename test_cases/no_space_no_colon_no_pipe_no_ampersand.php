<?php
# filename: no_space_no_colon_no_pipe_no_ampersand.php
# vulnerable
# sample exploit: 

if(isset($_GET['dir'])&&!preg_match('/ /',$_GET['dir'])&&!preg_match('/&|\||;/',$_GET['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
}
?>
