<?php
# filename: no_space.php
# vulnerable (alternative argument separator needs to be applied as space is filtered)
# samle exploit: 

if(isset($_GET['dir'])&&!preg_match('/ /',$_GET['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
}
?>
