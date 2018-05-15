<?php
# filename: simple_nested_quotes1.php
# vulnerable I guess
# 

if(isset($_GET['dir'])) echo "Dir contents are:\n<br />".shell_exec("ls \"{$_GET['dir']}\"");
?>
