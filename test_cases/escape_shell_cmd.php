<?php
	$command = 'dir '.$_POST['dir'];
	$escaped_command = escapeshellcmd($command);  // for some reason our bypass does not work with a direct injection, troubleshooting reuqired :)
	file_put_contents('out.bat',$escaped_command);
	system('out.bat');
?>
