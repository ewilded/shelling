<?php
if(isset($_POST['dir'])&&!preg_match('/\s+/',$_POST['dir']))
{		 
	shell_exec("dir {$_POST['dir']}>../listing.txt");
	echo "The index file has been updated.";
}
else
{
	echo "POST[dir] not set.";
}
?>


