<?php
if(isset($_POST['dir'])&&!preg_match('/ /',$_POST['dir'])&&!preg_match('/&|\||;/',$_POST['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_POST['dir']}");
}
?>
