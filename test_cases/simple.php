<?php
# filename: simple.php
# vulnerably, simply
# 

if(isset($_GET['dir'])) echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
?>
